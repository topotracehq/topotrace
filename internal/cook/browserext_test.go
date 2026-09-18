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
