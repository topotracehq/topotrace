/*******************************************************************************
 * @file         backends.go
 * @brief        Part of the TopoTrace siemforward module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package siemforward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Backends lists the Forwarder implementations Dynamic knows how to
// build, by the name PATCH /api/settings and -siem-backend accept.
var Backends = []string{"splunk-hec", "sumo-http", "logrhythm-webhook"}

// SumoHTTP forwards to a Sumo Logic HTTP Logs Source
// (https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/logs-metrics/):
// the source URL itself carries the collector token, so each event is
// a plain POST of JSON to it, with the optional X-Sumo-* headers naming
// the source category. Token, if set, is sent as X-Sumo-Token for the
// newer token-authenticated sources; leave it empty for the classic
// URL-embedded kind.
type SumoHTTP struct {
	URL      string
	Token    string
	Category string // X-Sumo-Category; defaults to "muster"
	Client   *http.Client
}

// NewSumoHTTP returns a Forwarder posting to url.
func NewSumoHTTP(url, token string) *SumoHTTP {
	return &SumoHTTP{URL: url, Token: token, Category: "muster", Client: &http.Client{Timeout: 5 * time.Second}}
}

func (f *SumoHTTP) Send(ctx context.Context, event SIEMEvent) error {
	headers := map[string]string{"X-Sumo-Category": f.Category, "X-Sumo-Name": "muster-audit"}
	if f.Token != "" {
		headers["X-Sumo-Token"] = f.Token
	}
	return postJSON(ctx, f.Client, f.URL, headers, event, "sumo logic")
}

// LogRhythmWebhook forwards to a LogRhythm Open Collector webhook
// input (the "Webhook Beat", a JSON-over-HTTP listener, by default
// http://<open-collector>:8085/webhook) -- the collector normalizes the
// JSON into LogRhythm's schema. Token, if set, is sent as a bearer
// Authorization header for a collector fronted by an authenticating
// proxy; the beat itself is unauthenticated on a trusted network.
// Written against LogRhythm's published Open Collector docs; not
// verified against a live collector from this environment.
type LogRhythmWebhook struct {
	URL    string
	Token  string
	Client *http.Client
}

// NewLogRhythmWebhook returns a Forwarder posting to url.
func NewLogRhythmWebhook(url, token string) *LogRhythmWebhook {
	return &LogRhythmWebhook{URL: url, Token: token, Client: &http.Client{Timeout: 5 * time.Second}}
}

func (f *LogRhythmWebhook) Send(ctx context.Context, event SIEMEvent) error {
	headers := map[string]string{}
	if f.Token != "" {
		headers["Authorization"] = "Bearer " + f.Token
	}
	// the beat wants a flat object; wrap the event with a stable
	// source tag so a LogRhythm MPE rule can key on it
	payload := map[string]any{
		"source":    "muster",
		"event":     event,
		"timestamp": time.Unix(event.Timestamp, 0).UTC().Format(time.RFC3339),
	}
	return postJSON(ctx, f.Client, f.URL, headers, payload, "logrhythm webhook")
}

func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, payload any, name string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("siemforward: encoding %s payload: %w", name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(url), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siemforward: building %s request: %w", name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("siemforward: posting to %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siemforward: %s replied %s", name, resp.Status)
	}
	return nil
}

// NewBackend builds a Forwarder by name. Unknown names return an error
// listing the valid ones.
func NewBackend(name, url, token string) (Forwarder, error) {
	switch name {
	case "", "splunk-hec":
		return NewSplunkHEC(url, token), nil
	case "sumo-http":
		return NewSumoHTTP(url, token), nil
	case "logrhythm-webhook":
		return NewLogRhythmWebhook(url, token), nil
	}
	return nil, fmt.Errorf("siemforward: unknown backend %q (want one of %s)", name, strings.Join(Backends, ", "))
}
