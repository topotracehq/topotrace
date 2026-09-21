/*******************************************************************************
 * @file         main.go
 * @brief        Command aws is TopoTrace's AWS EC2 scanner: a read-only, one-shot CLI that lists running instances in one region via the EC2 API and reports them to TopoTrace's POST /api/cloud-report, the same way an OS agent reports the machine it runs on --...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command aws is TopoTrace's AWS EC2 scanner: a read-only, one-shot CLI
// that lists running instances in one region via the EC2 API and
// reports them to TopoTrace's POST /api/cloud-report, the same way an OS
// agent reports the machine it runs on -- except here, one run can
// report many "hosts" at once (every instance the credential can see).
//
// Deliberately built against nothing but the Go standard library: this
// project's dev environment has no route to proxy.golang.org (its
// module proxy), so vendoring the official AWS SDK wasn't an option --
// and honestly, hand-rolling SigV4 for one API call is a better fit
// for a from-scratch portfolio project than pulling in a dependency
// that does everything anyway. See sigV4Sign below for the actual
// signing algorithm (AWS Signature Version 4), implemented from AWS's
// published spec, not ported from the SDK's source.
//
// Only ever makes a single read-only call (ec2:DescribeInstances) --
// give it a credential scoped to just that permission and it can't do
// anything else in the account.
//
//	go run ./agent/aws -region us-east-1 -server http://localhost:8080 -token <master-token>
//
// Credentials come from -access-key/-secret-key/-session-token, or (if
// those flags are omitted) the standard AWS_ACCESS_KEY_ID /
// AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN environment variables --
// the same two sources the real AWS CLI/SDKs check, without adopting
// their full credential-chain complexity (no shared config file, no
// instance-metadata/IMDS lookup, no SSO).
//
// Not verified against a live AWS account: this dev environment has no
// AWS credentials and (per the module-proxy block above) limited
// outbound access, so the signing and XML-parsing logic below is
// carefully hand-checked against AWS's published SigV4 spec and a
// real DescribeInstances response shape, but has not actually been
// round-tripped against the real API. Treat it as a solid first draft
// to test against a real (or sandboxed) AWS account before relying on
// it.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
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
	region := flag.String("region", "", "AWS region to scan, e.g. us-east-1 (required)")
	accessKey := flag.String("access-key", os.Getenv("AWS_ACCESS_KEY_ID"), "AWS access key ID (default: $AWS_ACCESS_KEY_ID)")
	secretKey := flag.String("secret-key", os.Getenv("AWS_SECRET_ACCESS_KEY"), "AWS secret access key (default: $AWS_SECRET_ACCESS_KEY)")
	sessionToken := flag.String("session-token", os.Getenv("AWS_SESSION_TOKEN"), "AWS session token, for temporary/STS credentials (default: $AWS_SESSION_TOKEN)")
	server := flag.String("server", "http://localhost:8080", "TopoTrace server base URL to report results to")
	token := flag.String("token", "", "TopoTrace master token (POST /api/cloud-report requires the master token, not a per-host enrollment)")
	includeStopped := flag.Bool("include-stopped", false, "also report stopped instances, not just running ones")
	dryRun := flag.Bool("dry-run", false, "scan and print results, but don't POST a report")
	flag.Parse()

	if *region == "" {
		fmt.Fprintln(os.Stderr, "-region is required")
		os.Exit(1)
	}
	if *accessKey == "" || *secretKey == "" {
		fmt.Fprintln(os.Stderr, "AWS credentials required: -access-key/-secret-key, or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY in the environment")
		os.Exit(1)
	}
	creds := awsCreds{accessKey: *accessKey, secretKey: *secretKey, sessionToken: *sessionToken}

	instances, err := describeInstances(*region, creds, *includeStopped)
	if err != nil {
		fmt.Fprintln(os.Stderr, "describing instances:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "aws: found %d instance(s) in %s\n", len(instances), *region)
	for _, inst := range instances {
		fmt.Printf("%s: type=%s state=%s az=%s name=%q\n", inst.InstanceID, inst.InstanceType, inst.State, inst.AvailabilityZone, inst.Name)
	}

	if *dryRun || len(instances) == 0 {
		return
	}
	if err := reportInstances(*server, *token, "aws", instances); err != nil {
		fmt.Fprintln(os.Stderr, "reporting to TopoTrace:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "aws: report sent")
}

type awsCreds struct {
	accessKey    string
	secretKey    string
	sessionToken string
}

// instance is the small, flat slice of a DescribeInstances result this
// scanner actually reports -- not an attempt to mirror every field the
// API returns.
type instance struct {
	InstanceID       string
	InstanceType     string
	State            string
	AvailabilityZone string
	Region           string
	PrivateIP        string
	PublicIP         string
	ImageID          string
	LaunchTime       string
	Name             string
	Tags             map[string]string
}

// --- EC2 DescribeInstances (Query API, XML response) ------------------

type describeInstancesResponse struct {
	XMLName        xml.Name `xml:"DescribeInstancesResponse"`
	ReservationSet struct {
		Items []struct {
			InstancesSet struct {
				Items []xmlInstance `xml:"item"`
			} `xml:"instancesSet"`
		} `xml:"item"`
	} `xml:"reservationSet"`
}

type xmlInstance struct {
	InstanceID       string `xml:"instanceId"`
	InstanceType     string `xml:"instanceType"`
	ImageID          string `xml:"imageId"`
	PrivateIPAddress string `xml:"privateIpAddress"`
	IPAddress        string `xml:"ipAddress"`
	LaunchTime       string `xml:"launchTime"`
	InstanceState    struct {
		Name string `xml:"name"`
	} `xml:"instanceState"`
	Placement struct {
		AvailabilityZone string `xml:"availabilityZone"`
	} `xml:"placement"`
	TagSet struct {
		Items []struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		} `xml:"item"`
	} `xml:"tagSet"`
}

func describeInstances(region string, creds awsCreds, includeStopped bool) ([]instance, error) {
	host := fmt.Sprintf("ec2.%s.amazonaws.com", region)
	endpoint := "https://" + host + "/"

	form := url.Values{}
	form.Set("Action", "DescribeInstances")
	form.Set("Version", "2016-11-15")
	body := form.Encode()

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Host", host)

	if err := sigV4Sign(req, []byte(body), creds, region, "ec2"); err != nil {
		return nil, fmt.Errorf("signing request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EC2 returned HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var parsed describeInstancesResponse
	if err := xml.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parsing DescribeInstances response: %w", err)
	}

	var out []instance
	for _, res := range parsed.ReservationSet.Items {
		for _, xi := range res.InstancesSet.Items {
			state := xi.InstanceState.Name
			if state != "running" && !(includeStopped && state == "stopped") {
				continue
			}
			tags := map[string]string{}
			var name string
			for _, t := range xi.TagSet.Items {
				tags[t.Key] = t.Value
				if t.Key == "Name" {
					name = t.Value
				}
			}
			out = append(out, instance{
				InstanceID:       xi.InstanceID,
				InstanceType:     xi.InstanceType,
				State:            state,
				AvailabilityZone: xi.Placement.AvailabilityZone,
				Region:           region,
				PrivateIP:        xi.PrivateIPAddress,
				PublicIP:         xi.IPAddress,
				ImageID:          xi.ImageID,
				LaunchTime:       xi.LaunchTime,
				Name:             name,
				Tags:             tags,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- AWS Signature Version 4 -------------------------------------------
//
// Implemented directly from AWS's published spec
// (https://docs.aws.amazon.com/general/latest/gr/sigv4-signing-and-authenticating-requests.html),
// not ported from any SDK. Signs req in place by setting its
// X-Amz-Date, (optionally) X-Amz-Security-Token, and Authorization
// headers. body must be exactly the bytes that will be sent -- the
// payload hash is part of what gets signed.
func sigV4Sign(req *http.Request, body []byte, creds awsCreds, region, service string) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if creds.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.sessionToken)
	}

	// Canonical request: method, URI, query string, canonical headers,
	// signed headers, payload hash. Header names are sorted and
	// lower-cased; only the headers we intend to sign are included --
	// keep this list and SignedHeaders in exact sync.
	signedHeaderNames := []string{"content-type", "host", "x-amz-date"}
	if creds.sessionToken != "" {
		signedHeaderNames = append(signedHeaderNames, "x-amz-security-token")
		sort.Strings(signedHeaderNames)
	}
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaderNames {
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(headerValue(req, h)))
		canonicalHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")
	payloadHash := sha256Hex(body)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		req.URL.RawQuery, // already sorted/empty for our one call; AWS requires sorted query params in general
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(creds.secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authHeader)
	return nil
}

func headerValue(req *http.Request, lowerName string) string {
	switch lowerName {
	case "host":
		if req.Header.Get("Host") != "" {
			return req.Header.Get("Host")
		}
		return req.Host
	default:
		// http.Header canonicalizes on Get, so this works regardless of
		// how the header was originally set.
		return req.Header.Get(lowerName)
	}
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// --- reporting to TopoTrace ------------------------------------------------

type cloudReportRequest struct {
	Provider  string                `json:"provider"`
	Account   string                `json:"account,omitempty"`
	Instances []cloudInstanceReport `json:"instances"`
}

type cloudInstanceReport struct {
	Host  string                    `json:"host"`
	Facts map[string]map[string]any `json:"facts"`
}

func reportInstances(server, token, provider string, instances []instance) error {
	req := cloudReportRequest{Provider: provider}
	for _, inst := range instances {
		facts := map[string]any{
			"instance_id":       inst.InstanceID,
			"instance_type":     inst.InstanceType,
			"state":             inst.State,
			"availability_zone": inst.AvailabilityZone,
			"region":            inst.Region,
			"private_ip":        inst.PrivateIP,
			"public_ip":         inst.PublicIP,
			"image_id":          inst.ImageID,
			"launch_time":       inst.LaunchTime,
			"name":              inst.Name,
			"tags":              inst.Tags,
		}
		req.Instances = append(req.Instances, cloudInstanceReport{
			Host:  inst.InstanceID,
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
	url := strings.TrimRight(server, "/") + "/api/cloud-report"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
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
