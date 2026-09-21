/*******************************************************************************
 * @file         main.go
 * @brief        Command gcp is Muster's Google Compute Engine scanner: a read-only, one-shot CLI that lists instances across every zone in one project via the Compute Engine REST API and reports them to Muster's POST /api/cloud-report, the same way agen...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command gcp is Muster's Google Compute Engine scanner: a read-only,
// one-shot CLI that lists instances across every zone in one project
// via the Compute Engine REST API and reports them to Muster's
// POST /api/cloud-report, the same way agent/aws does for EC2 and
// agent/azure does for Azure VMs.
//
// Like its siblings, this is stdlib-only -- no Google Cloud SDK,
// because this project's dev environment can't reach proxy.golang.org
// to vendor one. Auth is a service-account JWT-bearer OAuth2 flow
// (RFC 7523): build a signed JWT asserting the service account's
// identity and the scope requested, trade it for a short-lived access
// token, use that as a bearer token against the Compute API. The JWT's
// RS256 signature is produced with nothing but crypto/rsa,
// crypto/sha256, and encoding/pem -- reading the service account JSON
// key file's PEM-encoded private key the same way `gcloud` or any
// client library would, just without the library.
//
//	go run ./agent/gcp -project my-project -key-file service-account.json \
//	    -server http://localhost:8080 -token <master-token>
//
// The service account only needs the "Compute Viewer" role (or
// narrower, compute.instances.list) -- this only ever calls the
// read-only aggregated instance-list endpoint.
//
// Not verified against a live GCP project: this dev environment has no
// GCP credentials and limited outbound access, so the JWT construction,
// RS256 signing, and JSON parsing below is carefully checked against
// Google's published OAuth2 service-account docs and example
// responses, but has not actually been round-tripped against the real
// API. Treat it as a solid first draft to test against a real (or
// sandboxed) project before relying on it.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	project := flag.String("project", "", "GCP project ID to scan (required)")
	keyFile := flag.String("key-file", "", "path to a service account JSON key file (required)")
	server := flag.String("server", "http://localhost:8080", "Muster server base URL to report results to")
	token := flag.String("token", "", "Muster master token (POST /api/cloud-report requires the master token, not a per-host enrollment)")
	dryRun := flag.Bool("dry-run", false, "scan and print results, but don't POST a report")
	flag.Parse()

	if *project == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "-project and -key-file are both required")
		os.Exit(1)
	}

	sa, err := loadServiceAccountKey(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loading service account key:", err)
		os.Exit(1)
	}

	accessToken, err := googleJWTBearerToken(sa, "https://www.googleapis.com/auth/compute.readonly")
	if err != nil {
		fmt.Fprintln(os.Stderr, "getting Google OAuth2 token:", err)
		os.Exit(1)
	}

	instances, err := listInstances(*project, accessToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing instances:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "gcp: found %d instance(s) in project %s\n", len(instances), *project)
	for _, inst := range instances {
		fmt.Printf("%s: type=%s state=%s zone=%s\n", inst.Name, inst.MachineType, inst.Status, inst.Zone)
	}

	if *dryRun || len(instances) == 0 {
		return
	}
	if err := reportInstances(*server, *token, *project, instances); err != nil {
		fmt.Fprintln(os.Stderr, "reporting to Muster:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "gcp: report sent")
}

// --- service account key file -------------------------------------------

type serviceAccountKey struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

func loadServiceAccountKey(path string) (serviceAccountKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return serviceAccountKey{}, err
	}
	var sa serviceAccountKey
	if err := json.Unmarshal(data, &sa); err != nil {
		return serviceAccountKey{}, fmt.Errorf("parsing key file: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return serviceAccountKey{}, fmt.Errorf("key file is missing client_email or private_key -- is this a real service account JSON key?")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return sa, nil
}

func parsePrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("private_key is not valid PEM")
	}
	// Google's service account keys are PKCS#8-encoded ("BEGIN PRIVATE
	// KEY"), not the older PKCS#1 ("BEGIN RSA PRIVATE KEY") -- try
	// PKCS#8 first since that's what every key Google issues today
	// uses, and fall back to PKCS#1 for an older/hand-generated key.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private_key is not an RSA key")
		}
		return rsaKey, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// --- RFC 7523 JWT-bearer OAuth2 flow -------------------------------------

func googleJWTBearerToken(sa serviceAccountKey, scope string) (string, error) {
	key, err := parsePrivateKey(sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	now := time.Now().UTC()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss":   sa.ClientEmail,
		"scope": scope,
		"aud":   sa.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(1 * time.Hour).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64URL(headerJSON) + "." + base64URL(claimsJSON)

	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	req, err := http.NewRequest(http.MethodPost, sa.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || parsed.AccessToken == "" {
		desc := parsed.ErrorDesc
		if desc == "" {
			desc = truncate(string(body), 300)
		}
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, desc)
	}
	return parsed.AccessToken, nil
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- Compute Engine: aggregated instance list ---------------------------

type aggregatedListResponse struct {
	Items map[string]struct {
		Instances []struct {
			Name              string            `json:"name"`
			MachineType       string            `json:"machineType"`
			Status            string            `json:"status"`
			Zone              string            `json:"zone"`
			Labels            map[string]string `json:"labels"`
			NetworkInterfaces []struct {
				NetworkIP     string `json:"networkIP"`
				AccessConfigs []struct {
					NatIP string `json:"natIP"`
				} `json:"accessConfigs"`
			} `json:"networkInterfaces"`
		} `json:"instances"`
	} `json:"items"`
	NextPageToken string `json:"nextPageToken"`
}

type instance struct {
	Name        string
	MachineType string
	Status      string
	Zone        string
	InternalIP  string
	ExternalIP  string
	Labels      map[string]string
}

// lastPathElement extracts the trailing segment of a Compute Engine
// self-link-shaped field (zone and machineType come back as full URLs,
// e.g. ".../zones/us-central1-a" or ".../machineTypes/e2-medium") --
// this project only ever wants the short name.
func lastPathElement(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

func listInstances(project, accessToken string) ([]instance, error) {
	endpoint := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances?maxResults=500", url.PathEscape(project))

	var out []instance
	client := &http.Client{Timeout: 30 * time.Second}
	for endpoint != "" {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Compute Engine returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 500))
		}

		var parsed aggregatedListResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("parsing instance list response: %w", err)
		}
		zoneNames := make([]string, 0, len(parsed.Items))
		for z := range parsed.Items {
			zoneNames = append(zoneNames, z)
		}
		sort.Strings(zoneNames)
		for _, zoneKey := range zoneNames {
			for _, gi := range parsed.Items[zoneKey].Instances {
				var internalIP, externalIP string
				if len(gi.NetworkInterfaces) > 0 {
					internalIP = gi.NetworkInterfaces[0].NetworkIP
					if len(gi.NetworkInterfaces[0].AccessConfigs) > 0 {
						externalIP = gi.NetworkInterfaces[0].AccessConfigs[0].NatIP
					}
				}
				out = append(out, instance{
					Name:        gi.Name,
					MachineType: lastPathElement(gi.MachineType),
					Status:      gi.Status,
					Zone:        lastPathElement(gi.Zone),
					InternalIP:  internalIP,
					ExternalIP:  externalIP,
					Labels:      gi.Labels,
				})
			}
		}

		endpoint = ""
		if parsed.NextPageToken != "" {
			endpoint = fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances?maxResults=500&pageToken=%s",
				url.PathEscape(project), url.QueryEscape(parsed.NextPageToken))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- reporting to Muster ------------------------------------------------

type cloudReportRequest struct {
	Provider  string                `json:"provider"`
	Account   string                `json:"account,omitempty"`
	Instances []cloudInstanceReport `json:"instances"`
}

type cloudInstanceReport struct {
	Host  string                    `json:"host"`
	Facts map[string]map[string]any `json:"facts"`
}

func reportInstances(server, token, project string, instances []instance) error {
	req := cloudReportRequest{Provider: "gcp", Account: project}
	for _, inst := range instances {
		facts := map[string]any{
			"machine_type": inst.MachineType,
			"state":        inst.Status,
			"zone":         inst.Zone,
			"internal_ip":  inst.InternalIP,
			"external_ip":  inst.ExternalIP,
			"labels":       inst.Labels,
		}
		req.Instances = append(req.Instances, cloudInstanceReport{
			Host:  inst.Name,
			Facts: map[string]map[string]any{"cloud_instance": facts},
		})
	}
	return postCloudReport(server, token, req)
}

func postCloudReport(server, token string, req cloudReportRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	target := strings.TrimRight(server, "/") + "/api/cloud-report"
	httpReq, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}
	return nil
}
