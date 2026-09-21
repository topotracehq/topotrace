/*******************************************************************************
 * @file         breach.go
 * @brief        Package breach asks Have I Been Pwned (https://haveibeenpwned.com) whether an organization's domain shows up in known credential breaches -- the "are our people's credentials already out there" signal, which no amount of endpoint inventory can answer on its own.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package breach asks Have I Been Pwned (https://haveibeenpwned.com)
// whether an organization's domain shows up in known credential
// breaches -- the "are our people's credentials already out there"
// signal, which no amount of endpoint inventory can answer on its own.
// Stdlib net/http against the documented v3 API, no SDK.
//
// Two lookups, honest about the difference:
//
//   - Breaches(domain): the public, unauthenticated list of breaches OF
//     that domain (sites whose own user database leaked -- "adobe.com
//     was breached in 2013"). Useful when the domain is a vendor you
//     depend on; not about your own users.
//   - BreachedDomain(domain): every email alias on your domain that
//     appears in any breach, with which breaches. This is the one that
//     matters for a fleet and it needs an HIBP API key (paid) whose
//     owner has verified control of the domain; without a key it
//     reports "not configured" rather than pretending.
//
// Neither is verified against a live paid key from this environment;
// the public endpoint was exercised for real.
package breach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const baseURL = "https://haveibeenpwned.com/api/v3"

// ErrNotConfigured is returned by BreachedDomain when the client has no
// API key.
var ErrNotConfigured = errors.New("breach: no HIBP API key configured (set -hibp-api-key or MUSTER_HIBP_API_KEY)")

// Client talks to HIBP.
type Client struct {
	APIKey    string
	UserAgent string // HIBP requires one
	BaseURL   string // defaults to the real API; tests point it at an httptest.Server
	HTTP      *http.Client
}

// New returns a Client (APIKey may be empty for public lookups only).
func New(apiKey string) *Client {
	return &Client{APIKey: apiKey, UserAgent: "muster-fleet-inventory", BaseURL: baseURL, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Configured reports whether account-level lookups are possible.
func (c *Client) Configured() bool { return c != nil && c.APIKey != "" }

// Breach is one HIBP breach record (the fields Muster surfaces).
type Breach struct {
	Name        string   `json:"Name"`
	Title       string   `json:"Title"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	AddedDate   string   `json:"AddedDate"`
	PwnCount    int      `json:"PwnCount"`
	Description string   `json:"Description"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
	IsSensitive bool     `json:"IsSensitive"`
	IsMalware   bool     `json:"IsMalware"`
	IsSpamList  bool     `json:"IsSpamList"`
	LogoPath    string   `json:"LogoPath"`
}

// Breaches lists the public breaches of domain (no key needed).
func (c *Client) Breaches(ctx context.Context, domain string) ([]Breach, error) {
	var out []Breach
	err := c.get(ctx, "/breaches?domain="+url.QueryEscape(domain), &out)
	return out, err
}

// BreachedDomain lists every alias on domain found in a breach, mapped
// to the breach names -- requires an API key that has verified the
// domain. HIBP answers 404 for a domain with no exposed aliases and
// 401/403 for a key that can't see it; both are surfaced as errors the
// caller can read.
func (c *Client) BreachedDomain(ctx context.Context, domain string) (map[string][]string, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	var out map[string][]string
	err := c.get(ctx, "/breacheddomain/"+url.PathEscape(domain), &out)
	if out == nil {
		out = map[string][]string{}
	}
	return out, err
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	base := c.BaseURL
	if base == "" {
		base = baseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("hibp-api-key", c.APIKey)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("breach: calling hibp: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil // HIBP's "nothing found" -- leave v empty
	case resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("breach: hibp rate limit hit -- try again shortly")
	case resp.StatusCode >= 400:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("breach: hibp replied %s: %s", resp.Status, string(snippet))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
