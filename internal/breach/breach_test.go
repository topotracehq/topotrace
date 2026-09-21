/*******************************************************************************
 * @file         breach_test.go
 * @brief        Tests for the TopoTrace breach package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package breach

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient(t *testing.T) {
	var gotKey, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotUA = r.Header.Get("hibp-api-key"), r.Header.Get("User-Agent")
		switch {
		case strings.HasPrefix(r.URL.Path, "/breaches"):
			w.Write([]byte(`[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165,"DataClasses":["Email addresses","Passwords"],"IsVerified":true}]`))
		case strings.HasPrefix(r.URL.Path, "/breacheddomain/none.example"):
			w.WriteHeader(404)
		case strings.HasPrefix(r.URL.Path, "/breacheddomain/"):
			w.Write([]byte(`{"alice":["Adobe","LinkedIn"],"bob":["Adobe"]}`))
		}
	}))
	defer srv.Close()
	c := New("")
	c.BaseURL = srv.URL

	bs, err := c.Breaches(context.Background(), "adobe.com")
	if err != nil || len(bs) != 1 || bs[0].PwnCount != 152445165 || gotUA == "" {
		t.Fatalf("breaches: %+v err=%v ua=%q", bs, err, gotUA)
	}
	if _, err := c.BreachedDomain(context.Background(), "x.example"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
	c.APIKey = "k"
	m, err := c.BreachedDomain(context.Background(), "corp.example")
	if err != nil || len(m) != 2 || len(m["alice"]) != 2 || gotKey != "k" {
		t.Fatalf("breacheddomain: %+v err=%v key=%q", m, err, gotKey)
	}
	m, err = c.BreachedDomain(context.Background(), "none.example")
	if err != nil || len(m) != 0 {
		t.Fatalf("404 should be empty, not an error: %+v %v", m, err)
	}
}
