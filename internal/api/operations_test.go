/*******************************************************************************
 * @file         operations_test.go
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
	"muster/internal/model"
	"muster/internal/store/memstore"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkScopeWritesAndAIContext(t *testing.T) {
	ctx := context.Background()
	st, _ := memstore.New("")
	for _, h := range []model.Host{{Name: "one", Platform: "linux", Group: "team-a", LastCooked: time.Now()}, {Name: "secret-host", Platform: "linux", Group: "team-b", LastCooked: time.Now()}} {
		st.UpsertHost(ctx, h)
		st.SetHostGroup(ctx, h.Name, h.Group)
	}
	st.CreateAPIKey(ctx, "a", "remediate", "team-a", sha256Hex("scoped"))
	st.CreateAPIKey(ctx, "r", "readonly", "", sha256Hex("reader"))
	s := &Server{Store: st, AuthToken: "master"}
	handler := s.Handler()
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/work", "", ""); w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := request("GET", "/api/work", "", "scoped")
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret-host") {
		t.Fatal(w.Code, w.Body.String())
	}
	body := `{"id":"host:secret-host","host":"secret-host","owner":"Alice"}`
	if w := request("PUT", "/api/work/assignment", body, "scoped"); w.Code != 404 {
		t.Fatal(w.Code, w.Body.String())
	}
	body = `{"id":"host:one","host":"one","owner":"Alice"}`
	if w := request("PUT", "/api/work/assignment", body, "reader"); w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("PUT", "/api/work/assignment", body, "scoped"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "/api/ask", nil)
	r.Header.Set("Authorization", "Bearer scoped")
	c, err := s.buildAskContext(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "secret-host") || len(c.Hosts) != 1 {
		t.Fatal(string(b))
	}
}
func TestCitationsOnlyLinkSuppliedEvidence(t *testing.T) {
	sources, warnings := citedSources("Firewall [E1]. Other [E999]. Again [E1].", []askSource{{ID: "E1", Host: "one"}})
	if len(sources) != 1 || len(warnings) != 1 {
		t.Fatal(sources, warnings)
	}
	_, warnings = citedSources("No citations", nil)
	if len(warnings) != 1 {
		t.Fatal("missing citation warning")
	}
}
