/*******************************************************************************
 * @file         main.go
 * @brief        Command ai-governance is TopoTrace's first Commercial-candidate plugin: a governance layer on top of internal/aiagentinv's Community visibility data (AI CLI/agent tools, MCP server configs).
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command ai-governance is TopoTrace's first Commercial-candidate
// plugin: a governance layer on top of internal/aiagentinv's
// Community visibility data (AI CLI/agent tools, MCP server configs).
// The visibility layer scores and shows everything it finds; this
// plugin adds an approved-tools/approved-MCP-commands allowlist and
// reports which findings are actually out of policy.
//
// It's a separate binary the core launches as a subprocess (see
// internal/pluginhost and docs/plugins.md) -- it never links against
// core internals or shares the core's Postgres store.
//
//	go build -o ai-governance ./plugins/ai-governance
//	AI_GOVERNANCE_DATA_DIR=/var/lib/topotrace-plugins/ai-governance \
//	TOPOTRACE_CORE_URL=http://127.0.0.1:8080 \
//	TOPOTRACE_AUTH_TOKEN=<token> \
//	./ai-governance
//
// See plugins/ai-governance/README.md.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"topotrace/internal/pluginhost"
	"topotrace/plugins/ai-governance/governance"
)

const (
	pluginName    = "ai-governance"
	pluginVersion = "0.1.0"
	mountPrefix   = "ai-governance"
)

// impl is the plugin-side RPC implementation, bridging
// pluginhost.PluginHTTPRequest/Response onto a plain net/http.Handler
// built with http.ServeMux -- that's the cleanest way to reuse the
// standard library's routing on this side of the RPC boundary too.
type impl struct {
	handler http.Handler
}

func (impl) Describe(args struct{}, reply *pluginhost.PluginInfo) error {
	*reply = pluginhost.PluginInfo{
		Name:        pluginName,
		Version:     pluginVersion,
		MountPrefix: mountPrefix,
		Description: "AI agent inventory governance: approved-tools/MCP-command allowlist and violation reporting on top of internal/aiagentinv's visibility data. Commercial candidate.",
	}
	return nil
}

func (p impl) HandleHTTP(req pluginhost.PluginHTTPRequest, reply *pluginhost.PluginHTTPResponse) error {
	rr := httptest.NewRecorder()
	httpReq, err := http.NewRequest(req.Method, "/"+req.Path+queryString(req.Query), bytes.NewReader(req.Body))
	if err != nil {
		return err
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	p.handler.ServeHTTP(rr, httpReq)
	reply.Status = rr.Code
	reply.Headers = rr.Header()
	reply.Body = rr.Body.Bytes()
	return nil
}

func (impl) Shutdown(struct{}, *struct{}) error { return nil }

func queryString(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}

func main() {
	dataDir := os.Getenv("AI_GOVERNANCE_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data/ai-governance"
	}
	store, err := governance.NewStore(dataDir)
	if err != nil {
		log.Fatalf("ai-governance: opening policy store: %v", err)
	}

	coreURL := os.Getenv("TOPOTRACE_CORE_URL")
	coreToken := os.Getenv("TOPOTRACE_AUTH_TOKEN")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /policy", func(w http.ResponseWriter, r *http.Request) {
		entries, err := store.List()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policy": entries})
	})
	mux.HandleFunc("POST /policy", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Op    string `json:"op"` // "add" or "remove"
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("decoding request body: %w", err))
			return
		}
		entries, err := store.Apply(body.Op, governance.Entry{Kind: body.Kind, Value: body.Value})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policy": entries})
	})
	mux.HandleFunc("GET /violations", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("missing required ?host= parameter"))
			return
		}
		findings, err := fetchFindings(coreURL, coreToken, host)
		if err != nil {
			writeErr(w, http.StatusBadGateway, fmt.Errorf("fetching findings from core: %w", err))
			return
		}
		allowed, err := store.List()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		violations := governance.Violations(findings, allowed)
		writeJSON(w, http.StatusOK, map[string]any{
			"host":       host,
			"total":      len(findings),
			"violations": violations,
		})
	})

	done, err := pluginhost.ServePlugin(impl{handler: mux})
	if err != nil {
		log.Fatalf("ai-governance: %v", err)
	}
	<-done
}

// fetchFindings calls back into the core's own
// GET /api/hosts/{host}/ai-agents endpoint (internal/aiagentinv's
// visibility data) using the bearer token this plugin was configured
// with. Chosen over having the core push findings into the request
// body because it keeps HandleHTTP's contract generic (a plain HTTP
// bridge, no core-specific payload shape baked into the plugin
// protocol) and lets this plugin be queried for any host on demand,
// not just ones the core happens to have just evaluated.
func fetchFindings(coreURL, token, host string) ([]governance.Finding, error) {
	if coreURL == "" {
		return nil, fmt.Errorf("TOPOTRACE_CORE_URL is not configured")
	}
	req, err := http.NewRequest(http.MethodGet, coreURL+"/api/hosts/"+host+"/ai-agents", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("core returned %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Findings []governance.Finding `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding core response: %w", err)
	}
	return out.Findings, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
