/*******************************************************************************
 * @file         browserext_test.go
 * @brief        Tests for the TopoTrace browserext package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package browserext

import "testing"

func TestEvaluateLevels(t *testing.T) {
	exts := []Extension{
		{ID: "safe", Name: "Dark Reader-ish", Permissions: []string{"storage"}, HostPermissions: []string{"https://example.com/*"}, FromWebStore: true, ManifestVersion: 3},
		{ID: "coupon", Name: "Coupon Finder", Permissions: []string{"tabs", "webRequest", "cookies"}, HostPermissions: []string{"<all_urls>"}, FromWebStore: true, ManifestVersion: 3},
		{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "Bad", Permissions: nil, FromWebStore: false, ManifestVersion: 2},
	}
	fs := Evaluate(exts)
	if fs[0].ID != "coupon" && fs[0].ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("riskiest first: %+v", fs)
	}
	byID := map[string]Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	if byID["safe"].Level != "low" || len(byID["safe"].Reasons) != 0 {
		t.Fatalf("safe: %+v", byID["safe"])
	}
	if byID["coupon"].Level != "high" {
		t.Fatalf("coupon should be high: %+v", byID["coupon"])
	}
	if byID["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].Level != "high" || len(byID["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].Reasons) != 3 {
		t.Fatalf("known-bad: %+v", byID["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
	}
	if len(Risky(fs)) != 2 {
		t.Fatalf("expected 2 risky, got %d", len(Risky(fs)))
	}

	trusted := Evaluate([]Extension{{ID: "cjpalhdlnbpafiamejdnhcphjbkeiagm", Name: "uBlock Origin", Permissions: []string{"webRequest", "tabs"}, HostPermissions: []string{"<all_urls>"}, FromWebStore: true, ManifestVersion: 3}})
	if trusted[0].Level != "low" || len(trusted[0].Reasons) != 1 {
		t.Fatalf("trusted extension should be low: %+v", trusted[0])
	}
}

func TestFromFactHandlesBothSliceShapes(t *testing.T) {
	typed := []map[string]any{{"id": "x", "permissions": []string{"tabs"}, "manifest_version": 3}}
	if got := FromFact(typed); len(got) != 1 || got[0].Permissions[0] != "tabs" || got[0].ManifestVersion != 3 {
		t.Fatalf("typed: %+v", got)
	}
	generic := []any{map[string]any{"id": "y", "permissions": []any{"cookies"}, "manifest_version": float64(2), "from_web_store": true}}
	if got := FromFact(generic); len(got) != 1 || got[0].Permissions[0] != "cookies" || got[0].ManifestVersion != 2 || !got[0].FromWebStore {
		t.Fatalf("generic: %+v", got)
	}
}
