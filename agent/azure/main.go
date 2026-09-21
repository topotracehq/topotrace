/*******************************************************************************
 * @file         main.go
 * @brief        Command azure is Muster's Azure VM scanner: a read-only, one-shot CLI that lists virtual machines in one subscription via the Azure Resource Manager REST API and reports them to Muster's POST /api/cloud-report, the same way agent/aws doe...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command azure is Muster's Azure VM scanner: a read-only, one-shot CLI
// that lists virtual machines in one subscription via the Azure
// Resource Manager REST API and reports them to Muster's
// POST /api/cloud-report, the same way agent/aws does for EC2 and
// agent/gcp does for Compute Engine.
//
// Like its AWS and GCP counterparts, this is stdlib-only -- no Azure
// SDK -- because this project's dev environment has no route to
// proxy.golang.org to vendor one. Auth is a standard OAuth2
// client-credentials flow (POST username/password-shaped form data,
// get a bearer token back) using nothing but net/http and
// encoding/json; there's no hand-rolled crypto here the way AWS's
// SigV4 needs, since Azure AD's client-credentials grant is just
// HTTPS + a client secret, not a request-signing scheme.
//
//	go run ./agent/azure -tenant <tenant-id> -client-id <id> -client-secret <secret> \
//	    -subscription <subscription-id> -server http://localhost:8080 -token <master-token>
//
// The service principal only needs the built-in "Reader" role on the
// subscription (or a narrower one scoped to Microsoft.Compute/read) --
// this only ever calls the read-only virtualMachines list endpoint.
//
// Not verified against a live Azure subscription: this dev environment
// has no Azure credentials and limited outbound access, so the OAuth2
// flow and JSON parsing below is carefully checked against Azure's
// published API docs and example responses, but has not actually been
// round-tripped against the real API or AD tenant. Treat it as a solid
// first draft to test against a real (or sandboxed) subscription before
// relying on it.
package main

import (
	"bytes"
	"encoding/json"
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
	tenant := flag.String("tenant", "", "Azure AD tenant ID (required)")
	clientID := flag.String("client-id", "", "service principal (app registration) client ID (required)")
	clientSecret := flag.String("client-secret", "", "service principal client secret (required)")
	subscription := flag.String("subscription", "", "Azure subscription ID to scan (required)")
	server := flag.String("server", "http://localhost:8080", "Muster server base URL to report results to")
	token := flag.String("token", "", "Muster master token (POST /api/cloud-report requires the master token, not a per-host enrollment)")
	dryRun := flag.Bool("dry-run", false, "scan and print results, but don't POST a report")
	flag.Parse()

	if *tenant == "" || *clientID == "" || *clientSecret == "" || *subscription == "" {
		fmt.Fprintln(os.Stderr, "-tenant, -client-id, -client-secret, and -subscription are all required")
		os.Exit(1)
	}

	accessToken, err := azureClientCredentialsToken(*tenant, *clientID, *clientSecret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "getting Azure AD token:", err)
		os.Exit(1)
	}

	vms, err := listVirtualMachines(*subscription, accessToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing virtual machines:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "azure: found %d virtual machine(s) in subscription %s\n", len(vms), *subscription)
	for _, vm := range vms {
		fmt.Printf("%s: size=%s state=%s location=%s\n", vm.Name, vm.VMSize, vm.PowerState, vm.Location)
	}

	if *dryRun || len(vms) == 0 {
		return
	}
	if err := reportVMs(*server, *token, *subscription, vms); err != nil {
		fmt.Fprintln(os.Stderr, "reporting to Muster:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "azure: report sent")
}

// --- Azure AD OAuth2 client-credentials flow ---------------------------

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
	ErrorDesc   string `json:"error_description"`
}

func azureClientCredentialsToken(tenant, clientID, clientSecret string) (string, error) {
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenant))
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "https://management.azure.com/.default")

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
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

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || parsed.AccessToken == "" {
		desc := parsed.ErrorDesc
		if desc == "" {
			desc = truncate(string(body), 300)
		}
		return "", fmt.Errorf("Azure AD returned HTTP %d: %s", resp.StatusCode, desc)
	}
	return parsed.AccessToken, nil
}

// --- Azure Resource Manager: list virtual machines ----------------------

type vmListResponse struct {
	Value []struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		Properties struct {
			VMID              string `json:"vmId"`
			ProvisioningState string `json:"provisioningState"`
			HardwareProfile   struct {
				VMSize string `json:"vmSize"`
			} `json:"hardwareProfile"`
			InstanceView struct {
				Statuses []struct {
					Code string `json:"code"`
				} `json:"statuses"`
			} `json:"instanceView"`
		} `json:"properties"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

type vm struct {
	ID         string
	Name       string
	Location   string
	VMSize     string
	PowerState string
	Tags       map[string]string
}

// listVirtualMachines calls the subscription-wide "list all VMs"
// endpoint (statusOnly=true to get power state without a second
// per-VM InstanceView call) and follows nextLink for pagination.
func listVirtualMachines(subscription, accessToken string) ([]vm, error) {
	endpoint := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?statusOnly=true&api-version=2023-07-01",
		url.PathEscape(subscription),
	)

	var out []vm
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
			return nil, fmt.Errorf("ARM returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 500))
		}

		var parsed vmListResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("parsing virtual machines response: %w", err)
		}
		for _, v := range parsed.Value {
			state := "unknown"
			for _, s := range v.Properties.InstanceView.Statuses {
				if strings.HasPrefix(s.Code, "PowerState/") {
					state = strings.TrimPrefix(s.Code, "PowerState/")
				}
			}
			out = append(out, vm{
				ID:         v.ID,
				Name:       v.Name,
				Location:   v.Location,
				VMSize:     v.Properties.HardwareProfile.VMSize,
				PowerState: state,
				Tags:       v.Tags,
			})
		}
		endpoint = parsed.NextLink
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

func reportVMs(server, token, subscription string, vms []vm) error {
	req := cloudReportRequest{Provider: "azure", Account: subscription}
	for _, v := range vms {
		facts := map[string]any{
			"resource_id": v.ID,
			"vm_size":     v.VMSize,
			"state":       v.PowerState,
			"location":    v.Location,
			"tags":        v.Tags,
		}
		req.Instances = append(req.Instances, cloudInstanceReport{
			Host:  v.Name,
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
