/*******************************************************************************
 * @file         browserext_test.go
 * @brief        Tests for the TopoTrace cook package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package cook

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestParseBrowserExtensions(t *testing.T) {
	dir := t.TempDir()
	mv3 := base64.StdEncoding.EncodeToString([]byte(`{"manifest_version":3,"name":"__MSG_appName__","version":"2.3.1","permissions":["tabs","webRequest"],"host_permissions":["<all_urls>"],"update_url":"https://clients2.google.com/service/update2/crx"}`))
	msgs := base64.StdEncoding.EncodeToString([]byte(`{"appName":{"message":"Super Coupon Finder"}}`))
	mv2 := base64.StdEncoding.EncodeToString([]byte(`{"manifest_version":2,"name":"Old Style","version":"1.0","permissions":["storage","https://*.example.com/*"]}`))
	lines := "chrome\tuser/Default\tabc\t2.3.1_0\t" + mv3 + "\t" + msgs + "\n" +
		"edge\tuser/Profile 1\tdef\t1.0_0\t" + mv2 + "\t\n" +
		"garbage line\n"
	if err := os.WriteFile(filepath.Join(dir, "browser_extensions.txt"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	data, ok, err := parseBrowserExtensions(dir)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	items := data["items"].([]map[string]any)
	if data["count"] != 2 || len(items) != 2 {
		t.Fatalf("expected 2 items, got %v", data)
	}
	a := items[0]
	if a["name"] != "Super Coupon Finder" || a["version"] != "2.3.1" || a["manifest_version"] != 3 || !a["from_web_store"].(bool) {
		t.Fatalf("mv3 item: %+v", a)
	}
	if hosts := a["host_permissions"].([]string); len(hosts) != 1 || hosts[0] != "<all_urls>" {
		t.Fatalf("mv3 hosts: %v", hosts)
	}
	b := items[1]
	if b["name"] != "Old Style" || b["from_web_store"].(bool) {
		t.Fatalf("mv2 item: %+v", b)
	}
	if perms := b["permissions"].([]string); len(perms) != 1 || perms[0] != "storage" {
		t.Fatalf("mv2 perms should exclude host patterns: %v", perms)
	}
	if hosts := b["host_permissions"].([]string); len(hosts) != 1 || hosts[0] != "https://*.example.com/*" {
		t.Fatalf("mv2 hosts: %v", hosts)
	}

	if _, ok, _ := parseBrowserExtensions(t.TempDir()); ok {
		t.Fatal("missing file should report ok=false")
	}
}

func TestParseCerts(t *testing.T) {
	dir := t.TempDir()
	lines := "/etc/letsencrypt/live/example.com/cert.pem\tCN = example.com\tC = US, O = Let's Encrypt, CN = R11\t2026-10-01T12:00:00Z\n" +
		"/etc/nginx/ssl/old.crt\tCN=old.internal\tCN=Internal CA\tJan  2 15:04:05 2025 GMT\n"
	os.WriteFile(filepath.Join(dir, "certs.txt"), []byte(lines), 0o644)
	data, ok, err := parseLinuxCerts(dir)
	if err != nil || !ok || data["count"] != 2 {
		t.Fatalf("ok=%v err=%v data=%v", ok, err, data)
	}
	items := data["items"].([]map[string]any)
	if items[1]["not_after"] != "2025-01-02T15:04:05Z" {
		t.Fatalf("openssl date should normalize: %v", items[1]["not_after"])
	}

	win := "\"Thumbprint\",\"Subject\",\"Issuer\",\"NotAfter\"\r\n\"ABC123\",\"CN=WIN-HR01\",\"CN=Corp CA\",\"2026-12-31T00:00:00Z\"\r\n"
	wdir := t.TempDir()
	os.WriteFile(filepath.Join(wdir, "certs.txt"), []byte(win), 0o644)
	wdata, err := cookWinCerts(wdir)
	if err != nil || wdata == nil || wdata["count"] != 1 {
		t.Fatalf("win: err=%v data=%v", err, wdata)
	}
	if wdata["items"].([]map[string]any)[0]["id"] != "ABC123" {
		t.Fatalf("win id: %v", wdata)
	}
}
