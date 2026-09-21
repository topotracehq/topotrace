/*******************************************************************************
 * @file         workspace_test.go
 * @brief        Tests for the Muster api package.
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
	"errors"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/store"
	"muster/internal/store/memstore"
	"muster/internal/webhook"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type interruptedRestoreStore struct {
	store.Store
	fail bool
}

func (s *interruptedRestoreStore) PutDocument(ctx context.Context, d model.Document) error {
	if s.fail && d.Kind == operations.GroupKind && d.ID == "second" {
		return errors.New("simulated storage interruption")
	}
	return s.Store.PutDocument(ctx, d)
}
func TestConfigurationRestoreResumesAfterInterruption(t *testing.T) {
	base, _ := memstore.New("")
	st := &interruptedRestoreStore{Store: base, fail: true}
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	b := configBackup{Format: "muster-workspace-config-v1", CreatedAt: time.Now().UTC()}
	for _, id := range []string{"first", "second"} {
		data, _ := json.Marshal(operations.DynamicGroup{ID: id, Name: id})
		b.Documents = append(b.Documents, model.Document{Kind: operations.GroupKind, ID: id, Data: data})
	}
	request := func(path, hash string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"backup": b, "preview_hash": hash})
		r := httptest.NewRequest("POST", path, strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer master")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	hash := func() string {
		w := request("/api/config-backup/preview", "")
		var p struct {
			Hash string `json:"preview_hash"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return p.Hash
	}
	if w := request("/api/config-backup/restore", hash()); w.Code != 500 {
		t.Fatal("interruption not surfaced", w.Code)
	}
	first, ok, _ := st.GetDocument(context.Background(), operations.GroupKind, "first")
	if !ok {
		t.Fatal("first successful write missing")
	}
	st.fail = false
	if w := request("/api/config-backup/restore", hash()); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _, _ := st.GetDocument(context.Background(), operations.GroupKind, "first")
	if !first.UpdatedAt.Equal(after.UpdatedAt) {
		t.Fatal("resume overwrote existing record")
	}
	if _, ok, _ := st.GetDocument(context.Background(), operations.GroupKind, "second"); !ok {
		t.Fatal("resume did not recover missing record")
	}
}

func TestWorkspaceBackupRestoreAndScope(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	st.CreateAPIKey(ctx, "alice", "remediate", "team-a", sha256Hex("alice"))
	st.CreateAPIKey(ctx, "bob", "readonly", "team-a", sha256Hex("bob"))
	st.CreateAPIKey(ctx, "charlie", "admin", "team-b", sha256Hex("charlie"))
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"name":"Team attention","page":"health","filter":"attention","layout":"compact","shared":true}`
	if w := request("POST", "/api/saved-views", body, "alice"); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/api/saved-views", "", "bob"); !strings.Contains(w.Body.String(), "Team attention") {
		t.Fatal(w.Body.String())
	}
	if w := request("GET", "/api/saved-views", "", "charlie"); strings.Contains(w.Body.String(), "Team attention") {
		t.Fatal("cross-group view leak")
	}
	if w := request("POST", "/api/saved-views", body, "bob"); w.Code != 401 {
		t.Fatal("readonly shared write", w.Code)
	}
	for _, path := range []string{"/api/config-backup", "/api/notification-preferences"} {
		if w := request("GET", path, "", "charlie"); w.Code != 403 {
			t.Fatal("scoped admin", w.Code)
		}
	}
	g := operations.DynamicGroup{ID: "g", Name: "Linux"}
	operations.Save(ctx, st, operations.GroupKind, g.ID, g)
	operations.Save(ctx, st, webhook.PreferencesKind, "global", webhook.Preferences{Timezone: "UTC", DigestMinutes: 60})
	// A sensitive/active document must never be exported.
	st.PutDocument(ctx, model.Document{Kind: "notify_queue", ID: "secret", Data: json.RawMessage(`{"token":"should-not-export"}`)})
	w := request("GET", "/api/config-backup", "", "master")
	if w.Code != 200 || strings.Contains(w.Body.String(), "should-not-export") {
		t.Fatal(w.Code, w.Body.String())
	}
	var backup configBackup
	json.Unmarshal(w.Body.Bytes(), &backup)
	st.DeleteDocument(ctx, operations.GroupKind, "g")
	raw, _ := json.Marshal(map[string]any{"backup": backup})
	w = request("POST", "/api/config-backup/preview", string(raw), "master")
	var preview struct {
		Hash   string   `json:"preview_hash"`
		Create []string `json:"create"`
	}
	json.Unmarshal(w.Body.Bytes(), &preview)
	if w.Code != 200 || len(preview.Create) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("POST", "/api/config-backup/restore", string(raw), "master"); w.Code != 409 {
		t.Fatal("restore without preview", w.Code)
	}
	raw, _ = json.Marshal(map[string]any{"backup": backup, "preview_hash": preview.Hash})
	if w := request("POST", "/api/config-backup/restore", string(raw), "master"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	restored, found, err := operations.Load[operations.DynamicGroup](ctx, st, operations.GroupKind, "g")
	if err != nil || !found || restored.Name != "Linux" {
		t.Fatal(restored, found, err)
	}
	if w := request("POST", "/api/config-backup/restore", string(raw), "master"); w.Code != 409 {
		t.Fatal("stale preview accepted", w.Code)
	}
	backup.Documents = append(backup.Documents, model.Document{Kind: "change_plan", ID: "evil", Data: json.RawMessage(`{}`)})
	raw, _ = json.Marshal(map[string]any{"backup": backup})
	if w := request("POST", "/api/config-backup/preview", string(raw), "master"); w.Code != 400 {
		t.Fatal("action import accepted", w.Code)
	}
}
func TestDemoRecoveryAndBrandedReport(t *testing.T) {
	st, _ := memstore.New("")
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	for _, scenario := range []string{"unauthorized", "failed_change", "recovery"} {
		r := httptest.NewRequest("GET", "/api/visibility?demo=1&scenario="+scenario, nil)
		r.Header.Set("Authorization", "Bearer master")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var got visibilityResult
		json.Unmarshal(w.Body.Bytes(), &got)
		if !got.Demo || got.Story == "" {
			t.Fatal("missing demo story")
		}
		if scenario == "recovery" && (got.Before.State != "failed" || got.After.State != "verified") {
			t.Fatal(got.Before, got.After)
		}
	}
	r := httptest.NewRequest("GET", "/api/reports/executive?demo=1", nil)
	r.Header.Set("Authorization", "Bearer master")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for _, text := range []string{"DEMO DATA", "data:image/png;base64,", "Executive summary", "Recommended next steps", "TopoTrace LLC"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Errorf("missing report element %s", text)
		}
	}
	hosts, _ := st.ListHosts(context.Background())
	if len(hosts) != 0 {
		t.Fatal("demo wrote live inventory")
	}
}
func TestPlanAPICannotBypassPreflight(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st, _ := memstore.New("")
	st.UpsertHost(ctx, model.Host{Name: "one", Platform: "linux", LastCooked: now})
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	p := operations.Plan{Name: "restart", Hosts: []string{"one"}, Verb: "restart-service", Arg: "nginx", PilotCount: 1, WindowStart: now, WindowEnd: now.Add(time.Hour), RequirePreflight: false}
	body, _ := json.Marshal(p)
	r := httptest.NewRequest("POST", "/api/change-plans", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer master")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	plans, _ := operations.List[operations.Plan](ctx, st, operations.PlanKind)
	if len(plans) != 0 {
		t.Fatal("blocked plan was saved")
	}
}
