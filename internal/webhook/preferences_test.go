/*******************************************************************************
 * @file         preferences_test.go
 * @brief        Tests for the Muster webhook package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package webhook

import (
	"context"
	"encoding/json"
	"muster/internal/model"
	"muster/internal/store/memstore"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQuietHoursDigestAndRestart(t *testing.T) {
	st, _ := memstore.New("")
	p := Preferences{Timezone: "UTC", QuietEnabled: true, QuietStart: 22, QuietEnd: 7, DigestMinutes: 60}
	data, _ := json.Marshal(p)
	st.PutDocument(context.Background(), model.Document{Kind: PreferencesKind, ID: "global", Data: data})
	now := time.Date(2026, 9, 18, 23, 15, 0, 0, time.UTC)
	calls := 0
	var got Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer server.Close()
	sinks := []Sink{&URLSink{URL: server.URL, Client: server.Client()}}
	d := NewWithSinks(sinks, st, nil)
	d.now = func() time.Time { return now }
	d.Send(Event{Type: "policy_violation", Host: "one", Detail: "first"})
	d.Send(Event{Type: "policy_violation", Host: "two", Detail: "second"})
	snapshot := d.Snapshot()
	if len(snapshot.Pending) != 1 || snapshot.Pending[0].DigestCount != 2 {
		t.Fatal(snapshot)
	}
	d.DeliverDue(context.Background())
	if calls != 0 {
		t.Fatal("sent during quiet hours")
	}
	resumed := NewWithSinks(sinks, st, nil)
	resumed.now = func() time.Time { return now }
	now = time.Date(2026, 9, 19, 7, 0, 0, 0, time.UTC)
	resumed.DeliverDue(context.Background())
	if calls != 1 || got.Type != "digest" {
		t.Fatal(calls, got)
	}
	if len(resumed.Snapshot().Pending) != 0 {
		t.Fatal("digest not removed after delivery")
	}
}
func TestQuietHoursDaylightSavingAndValidation(t *testing.T) {
	p := Preferences{Timezone: "America/Chicago", QuietEnabled: true, QuietStart: 22, QuietEnd: 7}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)
	allowed := p.NextAllowed(at)
	if allowed.UTC().Hour() != 13 || !allowed.After(at) {
		t.Fatal("DST end must resolve to 7am local", allowed)
	}
	p.QuietEnd = p.QuietStart
	if p.Validate() == nil {
		t.Fatal("24h quiet range accepted")
	}
	p.QuietEnabled = false
	p.DigestMinutes = 1
	if p.Validate() == nil {
		t.Fatal("invalid digest interval accepted")
	}
}
