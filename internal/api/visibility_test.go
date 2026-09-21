/*******************************************************************************
 * @file         visibility_test.go
 * @brief        Tests for the TopoTrace api package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"topotrace/internal/agenthealth"
	"topotrace/internal/model"
	"topotrace/internal/store/memstore"
)

func TestVisibilityDemoScenariosAndIsolation(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	r := httptest.NewRequest("GET", "/api/visibility?demo=1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("demo must require authentication: %d", w.Code)
	}
	r.Header.Set("Authorization", "Bearer master")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var got visibilityResult
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if !got.Demo || len(got.Agents) != 6 || len(got.Assets) != 4 || len(got.Changes) < 4 {
		t.Fatalf("incomplete demo: %+v", got)
	}
	states := map[string]bool{}
	for _, a := range got.Agents {
		states[a.State] = true
	}
	for _, state := range []string{"healthy", "failing", "late", "missing", "never", "unknown"} {
		if !states[state] {
			t.Errorf("missing scenario %s", state)
		}
	}
	assetStates := map[string]bool{}
	stale := false
	for _, a := range got.Assets {
		assetStates[a.State] = true
		stale = stale || a.Stale
	}
	for _, state := range []string{"managed", "needs_review", "approved", "unauthorized"} {
		if !assetStates[state] {
			t.Errorf("missing asset scenario %s", state)
		}
	}
	if !stale {
		t.Error("missing historical discovery")
	}
	hosts, _ := st.ListHosts(ctx)
	assets, _ := st.ListDiscoveredAssets(ctx)
	audits, _ := st.ListAudit(ctx, "", 0)
	if len(hosts)+len(assets)+len(audits) != 0 {
		t.Fatal("demo mutated live store")
	}
}

func TestVisibilityScopeMatchingAndReview(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st, _ := memstore.New("")
	for _, name := range []string{"allowed", "secret"} {
		st.UpsertHost(ctx, model.Host{Name: name, Platform: "linux", LastCooked: now})
		st.SetHostGroup(ctx, name, name)
		agenthealth.Checkin(ctx, st, name, "tcp", 0, now)
	}
	st.CreateAPIKey(ctx, "scoped", "admin", "allowed", sha256Hex("scoped"))
	st.CreateAPIKey(ctx, "reader", "readonly", "", sha256Hex("reader"))
	st.UpsertFact(ctx, model.Fact{Host: "allowed", Category: "network_interfaces", CookedAt: now, Data: map[string]any{"items": []map[string]any{{"address": "192.0.2.7/24"}}}})
	a, _ := st.UpsertDiscoveredAsset(ctx, model.DiscoveredAsset{Address: "192.0.2.7"})
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/visibility", "/api/agents/health"} {
		w := request("GET", path, "", "scoped")
		if w.Code != 200 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "192.0.2.7") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	read := func() visibilityResult {
		w := request("GET", "/api/visibility", "", "master")
		var out visibilityResult
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return out
	}
	if got := read(); got.Assets[0].State != "managed" || got.Assets[0].MatchedHost != "allowed" {
		t.Fatal(got.Assets)
	}
	st.UpsertFact(ctx, model.Fact{Host: "allowed", Category: "network_interfaces", CookedAt: now.Add(-48 * time.Hour), Data: map[string]any{"items": []map[string]any{{"address": "192.0.2.7/24"}}}})
	if got := read(); got.Assets[0].State != "needs_review" {
		t.Fatal("stale IP must not count as managed", got.Assets)
	}
	path := "/api/discovered-assets/" + a.ID + "/review"
	body := `{"state":"unauthorized","reason":"Unapproved appliance"}`
	if w := request("PUT", path, body, "scoped"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("PUT", path, body, "reader"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("PUT", path, `{"state":"bogus","reason":"x"}`, "master"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request("PUT", path, body, "master"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := read(); got.Assets[0].State != "unauthorized" || got.Assets[0].Review.Reason != "Unapproved appliance" {
		t.Fatal(got.Assets)
	}
	if w := request("PUT", "/api/discovered-assets/missing/review", body, "master"); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
