/*******************************************************************************
 * @file         backends_test.go
 * @brief        Tests for the Muster siemforward package.
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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSumoAndLogRhythmPayloads(t *testing.T) {
	var gotHdr http.Header
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	evt := SIEMEvent{ID: "au1", Actor: "master", Action: "create-group", Target: "eng", Timestamp: 1700000000}

	sumo := NewSumoHTTP(srv.URL, "tok")
	sumo.Client = srv.Client()
	if err := sumo.Send(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if gotHdr.Get("X-Sumo-Category") != "muster" || gotHdr.Get("X-Sumo-Token") != "tok" || gotBody["action"] != "create-group" {
		t.Fatalf("sumo: hdr=%v body=%v", gotHdr, gotBody)
	}

	lr := NewLogRhythmWebhook(srv.URL, "bearer-tok")
	lr.Client = srv.Client()
	if err := lr.Send(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if gotHdr.Get("Authorization") != "Bearer bearer-tok" || gotBody["source"] != "muster" || gotBody["event"].(map[string]any)["actor"] != "master" {
		t.Fatalf("logrhythm: hdr=%v body=%v", gotHdr, gotBody)
	}

	d := NewDynamic()
	if err := d.Set("nope", srv.URL, ""); err == nil || d.Configured() {
		t.Fatal("unknown backend must be rejected and leave Dynamic unconfigured")
	}
	if err := d.Set("sumo-http", srv.URL, ""); err != nil || d.Backend() != "sumo-http" {
		t.Fatalf("set sumo: %v %s", err, d.Backend())
	}
	if _, err := NewBackend("logrhythm-webhook", srv.URL, ""); err != nil {
		t.Fatal(err)
	}
}
