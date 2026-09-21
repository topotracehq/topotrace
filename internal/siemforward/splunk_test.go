/*******************************************************************************
 * @file         splunk_test.go
 * @brief        Tests for the TopoTrace siemforward package.
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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplunkHECSendPayload(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotCT     string
		gotBody   hecPayload
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewSplunkHEC(srv.URL, "my-hec-token")
	evt := SIEMEvent{
		ID:        "audit-1",
		Actor:     "master",
		Action:    "policy-violation",
		Target:    "web01.prod",
		Detail:    `rule "stale" violated`,
		Timestamp: 1700000000,
	}
	if err := f.Send(context.Background(), evt); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/services/collector/event" {
		t.Errorf("path = %q, want /services/collector/event", gotPath)
	}
	if gotAuth != "Splunk my-hec-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Splunk my-hec-token")
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody.Sourcetype != "topotrace" {
		t.Errorf("sourcetype = %q, want topotrace", gotBody.Sourcetype)
	}
	if gotBody.Time != 1700000000 {
		t.Errorf("time = %d, want 1700000000", gotBody.Time)
	}
	if gotBody.Event != evt {
		t.Errorf("event = %+v, want %+v", gotBody.Event, evt)
	}
}

// TestSplunkHECURLTrailingSlash ensures a trailing slash on URL doesn't
// produce a double-slashed request path.
func TestSplunkHECURLTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewSplunkHEC(srv.URL+"/", "tok")
	if err := f.Send(context.Background(), SIEMEvent{}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotPath != "/services/collector/event" {
		t.Errorf("path = %q, want /services/collector/event (no double slash)", gotPath)
	}
}

func TestSplunkHECSendErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	f := NewSplunkHEC(srv.URL, "bad-token")
	if err := f.Send(context.Background(), SIEMEvent{}); err == nil {
		t.Fatal("Send: want error on 401 reply, got nil")
	}
}
