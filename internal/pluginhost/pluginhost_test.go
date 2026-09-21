/*******************************************************************************
 * @file         pluginhost_test.go
 * @brief        Tests for the TopoTrace pluginhost package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package pluginhost

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHandshake(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantErr bool
		wantVer int
		wantSk  string
	}{
		{"valid", MagicCookie + "|1|/tmp/x.sock", false, 1, "/tmp/x.sock"},
		{"wrong cookie", "not-the-cookie|1|/tmp/x.sock", true, 0, ""},
		{"bad version", MagicCookie + "|abc|/tmp/x.sock", true, 0, ""},
		{"empty socket", MagicCookie + "|1|", true, 0, ""},
		{"too few fields", MagicCookie + "|1", true, 0, ""},
		{"too many fields", MagicCookie + "|1|/tmp/x.sock|extra", true, 0, ""},
		{"empty line", "", true, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ver, sock, err := parseHandshake(c.line)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none (ver=%d sock=%q)", ver, sock)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ver != c.wantVer || sock != c.wantSk {
				t.Fatalf("got (%d, %q), want (%d, %q)", ver, sock, c.wantVer, c.wantSk)
			}
		})
	}
}

func TestHandshakeLineRoundTrip(t *testing.T) {
	line := HandshakeLine("/tmp/some.sock")
	ver, sock, err := parseHandshake(line)
	if err != nil {
		t.Fatalf("parseHandshake(%q): %v", line, err)
	}
	if ver != ProtocolVersion || sock != "/tmp/some.sock" {
		t.Fatalf("got (%d, %q)", ver, sock)
	}
}

// fakePlugin is an in-process PluginServer used to test the HTTP
// bridge logic (serveHTTP) without going through a real subprocess.
type fakePlugin struct{}

func (fakePlugin) Describe(struct{}, *PluginInfo) error { return nil }

func (fakePlugin) HandleHTTP(req PluginHTTPRequest, reply *PluginHTTPResponse) error {
	reply.Status = http.StatusTeapot
	reply.Headers = map[string][]string{"X-Echo-Path": {req.Path}}
	reply.Body = append([]byte("method="+req.Method+" body="), req.Body...)
	return nil
}

func (fakePlugin) Shutdown(struct{}, *struct{}) error { return nil }

func TestPluginServeHTTP(t *testing.T) {
	p := &Plugin{
		Info: PluginInfo{Name: "fake", MountPrefix: "fake"},
	}
	// Wire up a real client/server pair over an in-memory pipe isn't
	// worth the ceremony here -- exercise serveHTTP's marshaling by
	// calling HandleHTTP directly through the same path production
	// code takes (via net/rpc against a Unix socket) in
	// TestManagerRoundTrip below. Here we just check request
	// translation logic that doesn't require a live client: building
	// PluginHTTPRequest from an *http.Request.
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/fake/widgets?x=1", strings.NewReader("hello"))
	body, err := readAll(req)
	if err != nil {
		t.Fatalf("readAll: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("readAll got %q", body)
	}
	_ = p // p.serveHTTP requires a live RPC client; covered end-to-end below.
}

func TestManagerRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a subprocess plugin binary; skipped in -short")
	}
	dir := t.TempDir()
	pluginBin := filepath.Join(dir, "fakeplugin")
	build := exec.Command("go", "build", "-o", pluginBin, "./testdata/fakeplugin")
	build.Dir = "."
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building fake plugin: %v\n%s", err, out)
	}

	pluginDir := t.TempDir()
	finalBin := filepath.Join(pluginDir, "fakeplugin")
	if err := os.Rename(pluginBin, finalBin); err != nil {
		t.Fatalf("moving plugin binary: %v", err)
	}
	if err := os.Chmod(finalBin, 0755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	mgr := NewManager(pluginDir, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mgr.Load(ctx)

	list := mgr.List()
	if len(list) != 1 {
		t.Fatalf("got %d plugins, want 1", len(list))
	}
	if list[0].Name != "fakeplugin" || list[0].MountPrefix != "fakeplugin" {
		t.Fatalf("unexpected plugin info: %+v", list[0])
	}

	mux := http.NewServeMux()
	mgr.Mount(mux)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/plugins/fakeplugin/echo", "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
	if string(body) != "method=POST body=ping" {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Header.Get("X-Echo-Path"); got != "echo" {
		t.Fatalf("X-Echo-Path = %q, want %q", got, "echo")
	}

	mgr.Shutdown()
}
