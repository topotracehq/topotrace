/*******************************************************************************
 * @file         server.go
 * @brief        Package api is Muster's read side: a small REST API over whatever the cook pipeline has stored, using only net/http (Go 1.22+'s pattern-based ServeMux is enough for a handful of routes -- no router dependency needed).
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package api is Muster's read side: a small REST API over whatever the
// cook pipeline has stored, using only net/http (Go 1.22+'s pattern-based
// ServeMux is enough for a handful of routes -- no router dependency
// needed).
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"muster/agent"
	"muster/docs"
	"muster/internal/aiquery"
	"muster/internal/allowlist"
	"muster/internal/breach"
	"muster/internal/browserext"
	"muster/internal/certs"
	"muster/internal/compliance"
	"muster/internal/cook"
	"muster/internal/eol"
	"muster/internal/ingest"
	"muster/internal/model"
	"muster/internal/oauth"
	"muster/internal/policy"
	"muster/internal/remediate"
	"muster/internal/settingsstore"
	"muster/internal/siemforward"
	"muster/internal/signals"
	"muster/internal/store"
	"muster/internal/vuln"
	"muster/internal/webhook"
)

type Server struct {
	Store  store.Store
	Logger *slog.Logger

	// AuthToken, when non-empty, is the shared operator secret required
	// (as an "Authorization: Bearer <token>" header) for board writes
	// (PATCH /api/hosts/{host}) and for queuing a remediation action.
	// Left empty, board writes stay open (matching every earlier round's
	// demo-friendly default) but action-queuing is refused outright --
	// see handleQueueAction -- rather than silently left unauthenticated.
	// This should be the same value the ingest daemon was started with
	// (cmd/muster wires both from one -auth-token flag).
	AuthToken string

	// Webhooks, when non-nil, is where notable events (a policy
	// violation, a remediation action queued) get posted. A nil
	// Dispatcher is safe to call Send on -- see internal/webhook -- so
	// this field is simply left unset when no -webhook-url was given.
	Webhooks *webhook.Dispatcher

	// VulnFeed, when non-nil, supplements internal/vuln's static
	// Dataset with live OSV.dev lookups (see internal/vuln.Feed) --
	// left unset when no -vuln-feed flag was given, in which case
	// vulnerability correlation falls back to Dataset alone, same as
	// every earlier round.
	VulnFeed *vuln.Feed

	// Pipeline, when non-nil, is what handleAirgapReport uses to cook a
	// base64-delivered capture the same way the TCP ingest daemon cooks
	// one delivered over the network -- see cmd/muster, which wires the
	// exact same *cook.Pipeline into both the ingest server and this one.
	// Left nil (e.g. in tests that only exercise the read side), the
	// air-gap report endpoint refuses with 503 rather than panicking.
	Pipeline *cook.Pipeline

	// OAuth, when non-nil and Enabled, turns on browser login for the
	// dashboard (GET /api/auth/login, /callback, POST /logout) -- see
	// internal/oauth and docs/security-model.md. Left nil (no -oauth-*
	// flags given), those three endpoints report themselves disabled
	// and requireRole/requireRoleStrict only ever look at bearer
	// tokens, exactly as every earlier round of this project did.
	OAuth *oauth.Config

	// Sessions backs OAuth: the in-memory store of session cookies
	// issued after a successful login. Only ever non-nil alongside
	// OAuth -- cmd/muster constructs one iff -oauth-* flags parsed.
	Sessions *oauth.SessionStore

	// AIQuery is "Ask Muster"'s Anthropic credential/model (see
	// -ai-api-key/-ai-model), held in a mutable ConfigStore so
	// PATCH /api/settings can reconfigure or disable it on a running
	// server with no restart -- handleAsk calls AIQuery.Get() on every
	// request rather than reading a value captured once at startup. A
	// nil AIQuery (as in tests that don't set one) or a zero-value
	// Config within it (Enabled() == false, the default when neither
	// flag/env var is set) means handleAsk answers with a clear "not
	// configured" error instead of ever calling out to the network
	// with no key.
	AIQuery *aiquery.ConfigStore

	// The remaining fields exist purely for GET /api/settings to report
	// on -- cmd/muster wires each straight from the flag it already
	// parses. None of them affect this Server's own behavior; they're
	// plumbed through instead of re-parsed from os.Args so the settings
	// endpoint can't drift from what the process actually started with.

	// StorageBackend is "memstore" or "postgres" -- which store.Store
	// implementation cmd/muster constructed, never the -postgres-dsn
	// value itself.
	StorageBackend string
	// IngestAddr and APIAddr are the -ingest-addr/-api-addr the process
	// was started with.
	IngestAddr string
	APIAddr    string
	// EvaluatorInterval is -evaluator-interval.
	EvaluatorInterval time.Duration
	// VulnFeedInterval is -vuln-feed-interval -- meaningful only when
	// VulnFeed is non-nil (-vuln-feed was set).
	VulnFeedInterval time.Duration
	// SIEMForwarder reports on, and (via PATCH /api/settings) lets an
	// admin live-reconfigure, SIEM forwarding (see internal/siemforward
	// -- Configured()/Backend() report "splunk-hec"/true once
	// SetSplunkHEC has been called, false/"" otherwise; never the HEC
	// token itself). cmd/muster always constructs a non-nil
	// *siemforward.Dynamic and always wraps the Store with it (even
	// when starting with neither -siem-hec-* flag set), so forwarding
	// can be turned on later with no restart. A nil SIEMForwarder (as
	// in tests that don't set one) makes PATCH /api/settings refuse
	// SIEM changes with a clear "not available" error.
	SIEMForwarder *siemforward.Dynamic

	// SettingsOverridePath, when non-empty, is where PATCH
	// /api/settings persists the live edits it accepts (SIEM HEC
	// URL/token, Ask Muster API key/model) via internal/settingsstore,
	// so they survive a process restart. Left empty (e.g. in tests),
	// PATCH /api/settings still updates the live in-memory state, it
	// just won't be there after a restart.
	SettingsOverridePath string

	// Breach is the Have I Been Pwned client (see internal/breach);
	// nil means public lookups only, same as a client with no key.
	Breach *breach.Client
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Register adds the API's routes to an existing mux -- used by cmd/muster
// to serve the API and the web UI (internal/webui) from one HTTP server
// on one port, rather than each owning its own listener.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/hosts", s.handleListHosts)
	mux.HandleFunc("GET /api/hosts/{host}", s.handleGetHost)
	mux.HandleFunc("PATCH /api/hosts/{host}", s.handlePatchHost)
	mux.HandleFunc("GET /api/hosts/{host}/facts/{category}", s.handleGetFact)
	mux.HandleFunc("GET /api/hosts/{host}/changes", s.handleListChanges)
	mux.HandleFunc("GET /api/query", s.handleQuery)
	mux.HandleFunc("POST /api/hosts/{host}/actions", s.handleQueueAction)
	mux.HandleFunc("GET /api/hosts/{host}/actions", s.handleListActions)
	mux.HandleFunc("GET /api/groups", s.handleListGroups)
	mux.HandleFunc("POST /api/groups", s.handleCreateGroup)
	mux.HandleFunc("GET /api/hosts/{host}/posture", s.handleGetPosture)
	mux.HandleFunc("GET /api/hosts/{host}/vulnerabilities", s.handleGetVulnerabilities)
	mux.HandleFunc("GET /api/hosts/{host}/software-violations", s.handleGetSoftwareViolations)
	mux.HandleFunc("GET /api/hosts/{host}/compliance", s.handleGetCompliance)
	mux.HandleFunc("GET /api/compliance/summary", s.handleComplianceSummary)
	mux.HandleFunc("GET /api/compliance/frameworks", s.handleListFrameworks)
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/history", s.handleFleetHistory)
	mux.HandleFunc("GET /api/risk", s.handleFleetRisk)
	mux.HandleFunc("GET /api/hosts/{host}/risk", s.handleHostRisk)
	mux.HandleFunc("GET /api/hosts/{host}/browser-extensions", s.handleHostBrowserExtensions)
	mux.HandleFunc("GET /api/hosts/{host}/sbom", s.handleHostSBOM)
	mux.HandleFunc("GET /api/hosts/{host}/lifecycle", s.handleHostLifecycle)
	mux.HandleFunc("GET /api/software/sprawl", s.handleSprawl)
	mux.HandleFunc("GET /api/hosts/{host}/baseline", s.handleGetBaseline)
	mux.HandleFunc("POST /api/hosts/{host}/baseline", s.handleCaptureBaseline)
	mux.HandleFunc("DELETE /api/hosts/{host}/baseline", s.handleDeleteBaseline)
	mux.HandleFunc("GET /api/drift", s.handleFleetDrift)
	mux.HandleFunc("GET /api/notifications/queue", s.handleNotifyQueue)
	mux.HandleFunc("POST /api/notifications/test", s.handleNotifyTest)
	mux.HandleFunc("GET /api/graph", s.handleGraph)
	mux.HandleFunc("GET /api/bookmarks", s.handleListBookmarks)
	mux.HandleFunc("POST /api/bookmarks", s.handleCreateBookmark)
	mux.HandleFunc("GET /api/bookmarks/{id}/diff", s.handleBookmarkDiff)
	mux.HandleFunc("DELETE /api/bookmarks/{id}", s.handleDeleteBookmark)
	mux.HandleFunc("GET /api/demo/scenarios", s.handleDemoScenarios)
	mux.HandleFunc("POST /api/demo/simulate", s.handleDemoSimulate)
	mux.HandleFunc("GET /api/trust/{host}", s.handleTrust)
	mux.HandleFunc("GET /api/signals", s.handleSignals)
	mux.HandleFunc("GET /api/breaches", s.handleBreaches)
	mux.HandleFunc("GET /api/alerts", s.handleListAlerts)
	mux.HandleFunc("POST /api/alerts/snooze", s.handleSnoozeAlert)
	mux.HandleFunc("GET /api/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /api/approvals/{id}/{decision}", s.handleDecideApproval)
	mux.HandleFunc("GET /api/benchmark", s.handleBenchmark)
	mux.HandleFunc("GET /api/reports/executive", s.handleReportHTML)
	mux.HandleFunc("GET /api/reports/{name}", s.handleReportCSV)
	mux.HandleFunc("GET /api/hosts/{host}/history", s.handleHostHistory)
	mux.HandleFunc("GET /api/audit", s.handleListAudit)
	mux.HandleFunc("GET /api/policies", s.handleListPolicies)
	mux.HandleFunc("POST /api/policies", s.handleCreatePolicy)
	mux.HandleFunc("DELETE /api/policies/{id}", s.handleDeletePolicy)
	mux.HandleFunc("GET /api/software-rules", s.handleListSoftwareRules)
	mux.HandleFunc("POST /api/software-rules", s.handleCreateSoftwareRule)
	mux.HandleFunc("DELETE /api/software-rules/{id}", s.handleDeleteSoftwareRule)
	mux.HandleFunc("GET /api/keys", s.handleListKeys)
	mux.HandleFunc("POST /api/keys", s.handleCreateKey)
	mux.HandleFunc("DELETE /api/keys/{id}", s.handleDeleteKey)
	mux.HandleFunc("GET /api/enrollments", s.handleListEnrollments)
	mux.HandleFunc("POST /api/enrollments", s.handleCreateEnrollment)
	mux.HandleFunc("DELETE /api/enrollments/{id}", s.handleDeleteEnrollment)
	mux.HandleFunc("POST /api/mobile-report", s.handleMobileReport)
	mux.HandleFunc("GET /api/agents/download/{platform}", s.handleDownloadAgent)
	mux.HandleFunc("GET /api/docs", s.handleListDocs)
	mux.HandleFunc("GET /api/docs/{name}", s.handleGetDoc)
	mux.HandleFunc("POST /api/discover-report", s.handleDiscoverReport)
	mux.HandleFunc("GET /api/discovered-assets", s.handleListDiscoveredAssets)
	mux.HandleFunc("DELETE /api/discovered-assets/{id}", s.handleDeleteDiscoveredAsset)
	mux.HandleFunc("POST /api/airgap-report", s.handleAirgapReport)
	mux.HandleFunc("POST /api/cloud-report", s.handleCloudReport)
	mux.HandleFunc("GET /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("GET /api/auth/callback", s.handleAuthCallback)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)
	mux.HandleFunc("POST /api/ask", s.handleAsk)
	mux.HandleFunc("POST /api/ask/draft-policy", s.handleDraftPolicy)
	mux.HandleFunc("POST /api/ask/summary", s.handleExecutiveSummary)
	mux.HandleFunc("GET /api/settings", s.handleSettings)
	mux.HandleFunc("PATCH /api/settings", s.handlePatchSettings)
}

// Handler returns a standalone, logged handler for just the API -- used
// by tests and anything that wants the API on its own mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Register(mux)
	return logMiddleware(s.log(), mux)
}

// handleListDocs is GET /api/docs -- unauthenticated, like the agent
// downloads: documentation isn't sensitive, and gating it behind a
// token would just make the Docs tab useless to someone evaluating
// Muster before they've set one up.
func (s *Server) handleListDocs(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, docs.Index)
}

// handleGetDoc is GET /api/docs/{name} -- serves one embedded markdown
// page's raw source; the web UI renders it client-side.
func (s *Server) handleGetDoc(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, p := range docs.Index {
		if p.Name != name {
			continue
		}
		data, err := docs.Pages.ReadFile(name + ".md")
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "reading doc page")
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write(data)
		return
	}
	s.writeError(w, http.StatusNotFound, "doc page not found")
}

// settingsAuth is the auth-related slice of GET /api/settings --
// presence/mode only, never AuthToken or any OAuth secret.
type settingsAuth struct {
	BearerTokenConfigured bool     `json:"bearer_token_configured"`
	OAuthConfigured       bool     `json:"oauth_configured"`
	OAuthRoleMap          []string `json:"oauth_role_map,omitempty"`
}

// settingsVulnFeed is GET /api/settings's vuln-feed slice.
type settingsVulnFeed struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval,omitempty"`
}

// settingsAskMuster is GET /api/settings's Ask Muster (AI query) slice
// -- never AIQuery.APIKey itself.
type settingsAskMuster struct {
	Configured bool   `json:"configured"`
	Model      string `json:"model,omitempty"`
}

// settingsWebhooks is GET /api/settings's notification slice -- the
// sink names (a generic webhook sink's name includes its URL, which
// is deliberately redacted here to its host), never a token or
// credential.
type settingsWebhooks struct {
	Configured bool     `json:"configured"`
	Count      int      `json:"count"`
	Sinks      []string `json:"sinks,omitempty"`
	Pending    int      `json:"pending"`
	Dead       int      `json:"dead"`
}

// settingsSIEM is GET /api/settings's SIEM-forwarding slice (see
// internal/siemforward) -- never the HEC token itself.
type settingsSIEM struct {
	Configured bool   `json:"configured"`
	Backend    string `json:"backend,omitempty"`
}

// settingsResponse is GET /api/settings's full shape -- see
// handleSettings's doc comment for what this deliberately omits.
type settingsResponse struct {
	StorageBackend    string            `json:"storage_backend"`
	IngestAddr        string            `json:"ingest_addr"`
	APIAddr           string            `json:"api_addr"`
	EvaluatorInterval string            `json:"evaluator_interval"`
	Auth              settingsAuth      `json:"auth"`
	VulnFeed          settingsVulnFeed  `json:"vuln_feed"`
	AskMuster         settingsAskMuster `json:"ask_muster"`
	Webhooks          settingsWebhooks  `json:"webhooks"`
	SIEM              settingsSIEM      `json:"siem"`
}

// handleSettings is GET /api/settings, gated admin (same as managing
// policies or API keys -- this is operator-facing server configuration,
// not fleet data). It exists so "what is this server actually running
// with" has one place to look instead of cross-referencing CLI flags,
// env vars, and process arguments -- see cmd/muster's flag list, which
// is where every value here ultimately comes from.
//
// Deliberately never returns MUSTER_AUTH_TOKEN, MUSTER_POSTGRES_DSN,
// MUSTER_AI_API_KEY, the OAuth client secret, or any webhook/OAuth URL
// -- only whether each is configured, and non-secret metadata (mode,
// counts, intervals, model name, role-map policy) about it.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "admin"); !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, s.settingsSnapshot())
}

// settingsSnapshot builds GET /api/settings's response from the
// server's current live state -- shared by handleSettings and
// handlePatchSettings (whose response reflects whatever it just
// changed) so there's exactly one place that decides what this
// endpoint reports.
func (s *Server) settingsSnapshot() settingsResponse {
	resp := settingsResponse{
		StorageBackend:    s.StorageBackend,
		IngestAddr:        s.IngestAddr,
		APIAddr:           s.APIAddr,
		EvaluatorInterval: s.EvaluatorInterval.String(),
		Auth: settingsAuth{
			BearerTokenConfigured: s.AuthToken != "",
			OAuthConfigured:       s.OAuth != nil && s.OAuth.Enabled,
			OAuthRoleMap:          s.OAuth.RoleMapStrings(),
		},
		VulnFeed: settingsVulnFeed{
			Enabled: s.VulnFeed != nil,
		},
		Webhooks: notifySettings(s.Webhooks),
	}
	if s.VulnFeed != nil {
		resp.VulnFeed.Interval = s.VulnFeedInterval.String()
	}
	if s.AIQuery != nil {
		cfg := s.AIQuery.Get()
		resp.AskMuster = settingsAskMuster{
			Configured: cfg.Enabled(),
			Model:      cfg.Model,
		}
	}
	if s.SIEMForwarder != nil {
		resp.SIEM = settingsSIEM{
			Configured: s.SIEMForwarder.Configured(),
			Backend:    s.SIEMForwarder.Backend(),
		}
	}
	return resp
}

// settingsPatchRequest is PATCH /api/settings's body -- pointer fields
// so "field omitted" (leave alone) is distinguishable from "field set
// to empty string" (which, for these two integrations, isn't a valid
// state on its own -- use the matching *_disable bool instead). Every
// field here is optional; a request must set at least one recognized
// field or it's rejected as a no-op.
//
// SIEM forwarding's URL and token must be provided together (same
// all-or-nothing pairing cmd/muster's own -siem-hec-* flags already
// enforce) since internal/siemforward.Dynamic doesn't expose its
// current URL/token to merge a partial update against -- deliberately,
// since that value is a live secret this endpoint otherwise never
// hands back. Ask Muster's two fields can be set independently: the
// model alone (keeping the existing key) is a common edit, and
// internal/aiquery.ConfigStore's current Config is readable
// server-side for exactly that merge.
type settingsPatchRequest struct {
	SIEMHECURL   *string `json:"siem_hec_url,omitempty"`
	SIEMHECToken *string `json:"siem_hec_token,omitempty"`
	SIEMDisable  bool    `json:"siem_disable,omitempty"`

	AIAPIKey  *string `json:"ai_api_key,omitempty"`
	AIModel   *string `json:"ai_model,omitempty"`
	AIDisable bool    `json:"ai_disable,omitempty"`
}

func strPtrVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// handlePatchSettings is PATCH /api/settings, gated admin -- and
// requireRoleStrict, not the softer requireRole, since (unlike
// GET /api/settings, which only ever reads) this endpoint accepts and
// persists real secrets (a SIEM HEC token, an Anthropic API key) and
// must never run with auth wide open just because -auth-token wasn't
// set. It live-reconfigures internal/siemforward.Dynamic and/or
// internal/aiquery.ConfigStore in memory -- taking effect immediately,
// no restart -- and, when SettingsOverridePath is set, persists the
// change to internal/settingsstore so it survives one. Every accepted
// edit is recorded to the audit trail via Store.RecordAudit (and, if
// SIEM forwarding is itself configured, forwarded from there like any
// other audit entry) -- the detail string never includes a secret
// value, only what changed.
func (s *Server) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req settingsPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var overrides settingsstore.Overrides
	if s.SettingsOverridePath != "" {
		loaded, err := settingsstore.Load(s.SettingsOverridePath)
		if err != nil {
			s.log().Error("loading settings overrides before patch", "err", err)
		} else {
			overrides = loaded
		}
	}

	var actions []string

	switch {
	case req.SIEMDisable:
		if s.SIEMForwarder == nil {
			s.writeError(w, http.StatusServiceUnavailable, "SIEM forwarding is not available on this server")
			return
		}
		s.SIEMForwarder.Disable()
		overrides.SIEMHECURL = ""
		overrides.SIEMHECToken = ""
		actions = append(actions, "siem forwarding disabled")
	case req.SIEMHECURL != nil || req.SIEMHECToken != nil:
		if s.SIEMForwarder == nil {
			s.writeError(w, http.StatusServiceUnavailable, "SIEM forwarding is not available on this server")
			return
		}
		hecURL := strings.TrimSpace(strPtrVal(req.SIEMHECURL))
		hecToken := strings.TrimSpace(strPtrVal(req.SIEMHECToken))
		if hecURL == "" || hecToken == "" {
			s.writeError(w, http.StatusBadRequest, "siem_hec_url and siem_hec_token must both be provided together (or set siem_disable instead)")
			return
		}
		if !strings.HasPrefix(hecURL, "http://") && !strings.HasPrefix(hecURL, "https://") {
			s.writeError(w, http.StatusBadRequest, "siem_hec_url must start with http:// or https://")
			return
		}
		s.SIEMForwarder.SetSplunkHEC(hecURL, hecToken)
		overrides.SIEMHECURL = hecURL
		overrides.SIEMHECToken = hecToken
		actions = append(actions, "siem forwarding configured (splunk-hec)")
	}

	switch {
	case req.AIDisable:
		if s.AIQuery == nil {
			s.writeError(w, http.StatusServiceUnavailable, "Ask Muster is not available on this server")
			return
		}
		s.AIQuery.Set(aiquery.Config{})
		overrides.AIAPIKey = ""
		overrides.AIModel = ""
		actions = append(actions, "ask muster disabled")
	case req.AIAPIKey != nil || req.AIModel != nil:
		if s.AIQuery == nil {
			s.writeError(w, http.StatusServiceUnavailable, "Ask Muster is not available on this server")
			return
		}
		cur := s.AIQuery.Get()
		key := cur.APIKey
		if req.AIAPIKey != nil {
			key = strings.TrimSpace(*req.AIAPIKey)
		}
		newModel := cur.Model
		if req.AIModel != nil {
			newModel = strings.TrimSpace(*req.AIModel)
		}
		if key == "" {
			s.writeError(w, http.StatusBadRequest, "ai_api_key is required to enable Ask Muster (or set ai_disable to turn it off)")
			return
		}
		s.AIQuery.Set(aiquery.Config{APIKey: key, Model: newModel})
		overrides.AIAPIKey = key
		overrides.AIModel = newModel
		actions = append(actions, "ask muster configured")
	}

	if len(actions) == 0 {
		s.writeError(w, http.StatusBadRequest, "no recognized settings fields in request")
		return
	}

	if s.SettingsOverridePath != "" {
		if err := settingsstore.Save(s.SettingsOverridePath, overrides); err != nil {
			s.log().Error("saving settings overrides", "err", err)
		}
	}

	detail := strings.Join(actions, "; ")
	if _, err := s.Store.RecordAudit(r.Context(), actor, "settings_updated", "server", detail); err != nil {
		s.log().Error("recording settings-update audit entry", "err", err)
	}

	s.writeJSON(w, http.StatusOK, s.settingsSnapshot())
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log().Error("encoding response", "err", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

// roleRank orders the three fixed roles a credential can have --
// "readonly" (read everything), "remediate" (readonly plus queue
// actions and make board writes), "admin" (remediate plus manage
// policies and other API keys). No custom/finer-grained roles: the same
// "small, fixed set, not free-form" philosophy as internal/remediate's
// allow-listed verbs.
var roleRank = map[string]int{"readonly": 1, "remediate": 2, "admin": 3}

func roleAllows(have, need string) bool {
	return roleRank[have] >= roleRank[need]
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randomToken generates a fresh 192-bit bearer credential (crypto/rand,
// never math/rand) for a newly created API key. Returned to the caller
// exactly once, in handleCreateKey's response -- Store only ever
// receives sha256Hex of it, never the raw value.
func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requireRole is the auth gate for every endpoint that's open by
// default in demo mode (AuthToken == "") but role-checked once an
// operator turns auth on. When AuthToken is empty, every request passes
// with an implicit "admin" role and actor "anonymous" -- the same
// wide-open default every earlier round of this project has had.
// Otherwise it defers to requireRoleStrict. On failure, it has already
// written the error response; callers just return.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, need string) (actor string, ok bool) {
	if s.AuthToken == "" {
		return "anonymous", true
	}
	return s.requireRoleStrict(w, r, need)
}

// requireRoleStrict is requireRole without the "AuthToken empty means
// wide open" escape hatch -- for endpoints that must never run
// unauthenticated even in demo mode: queuing a remediation action,
// issuing or revoking an API key, or creating/deleting a policy (a
// policy can auto-queue a remediation action, so it carries the same
// risk). Mirrors the original handleQueueAction's two-step "refuse if
// no token is configured at all, then check the token" gate,
// generalized to roles and to named API keys, not just the master
// token. A bearer token (master, or a named API key) is checked
// first; a valid OAuth session cookie (see internal/oauth) is the
// fallback, for a person clicking around the dashboard in a browser
// rather than a script or agent carrying a token -- see
// docs/security-model.md's "OAuth2/OIDC login" section for why the
// two sit alongside each other instead of one replacing the other.
func (s *Server) requireRoleStrict(w http.ResponseWriter, r *http.Request, need string) (actor string, ok bool) {
	if s.AuthToken == "" {
		s.writeError(w, http.StatusServiceUnavailable, "this endpoint requires the server to be started with -auth-token")
		return "", false
	}
	if got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); got != "" {
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.AuthToken)) == 1 {
			return "master", true
		}
		key, found, err := s.Store.FindAPIKeyByHash(r.Context(), sha256Hex(got))
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "checking credential")
			return "", false
		}
		if found && roleAllows(key.Role, need) {
			return key.Name, true
		}
		s.writeError(w, http.StatusUnauthorized, "missing or invalid bearer token, or insufficient role")
		return "", false
	}
	if email, role, ok := s.sessionFromCookie(r); ok {
		if roleAllows(role, need) {
			return email, true
		}
		s.writeError(w, http.StatusForbidden, "logged-in user's role is insufficient for this action")
		return "", false
	}
	s.writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
	return "", false
}

// sessionFromCookie looks up the OAuth session (see internal/oauth)
// named by the request's muster_session cookie, if any. ok is false
// whenever OAuth login isn't configured, the cookie is missing, or the
// session it names doesn't exist or has expired -- callers treat all
// of those the same way: fall through to "no credential."
func (s *Server) sessionFromCookie(r *http.Request) (email, role string, ok bool) {
	if s.Sessions == nil {
		return "", "", false
	}
	c, err := r.Cookie(oauth.SessionCookieName)
	if err != nil || c.Value == "" {
		return "", "", false
	}
	sess, found := s.Sessions.Get(c.Value)
	if !found {
		return "", "", false
	}
	return sess.Email, sess.Role, true
}

// authorizedIngestToken reports whether token may push a report for
// host over the JSON POST /api/mobile-report path -- the mobile
// counterpart to internal/ingest's authorizedUpload, same two-tier
// model: the master token authorizes any host, or a live enrollment
// token authorizes exactly its one assigned host (and gets flipped from
// "pending" to "enrolled" on first successful use, here too). Not
// requireRole/requireRoleStrict: an enrollment token is not an API-key
// role and carries no role at all -- it can only ever push a report for
// its one host, nothing else, so it never needs to pass a role check.
// Open (accepts anything) when AuthToken isn't configured, matching
// every other "wide open in demo mode" default in this file.
func (s *Server) authorizedIngestToken(ctx context.Context, token, host string) bool {
	if s.AuthToken == "" {
		return true
	}
	if token == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.AuthToken)) == 1 {
		return true
	}
	enr, ok, err := s.Store.FindEnrollmentByHash(ctx, sha256Hex(token))
	if err != nil || !ok || enr.Host != host {
		return false
	}
	if enr.Status != "enrolled" {
		if err := s.Store.MarkEnrolled(ctx, enr.ID); err != nil {
			s.log().Error("marking enrollment enrolled", "err", err)
		}
	}
	return true
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMetrics is GET /metrics -- a hand-written Prometheus text
// exposition (no client library needed for three gauges; see the README
// for why that's a deliberate choice, not a missing dependency). Point
// a real Prometheus at it with a scrape_config the same way you'd point
// it at any other exporter; no auth, matching /healthz's own posture --
// exposing host counts isn't a sensitive write path the way remediation
// or board edits are.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		http.Error(w, "# error listing hosts for metrics", http.StatusInternalServerError)
		return
	}

	byPlatform := map[string]int{}
	stale := 0
	now := time.Now().UTC()
	for _, h := range hosts {
		byPlatform[h.Platform]++
		if policy.IsStale(h.LastCooked, now) {
			stale++
		}
	}

	var b strings.Builder
	b.WriteString("# HELP muster_hosts_total Total number of hosts Muster has ever received a report from.\n")
	b.WriteString("# TYPE muster_hosts_total gauge\n")
	fmt.Fprintf(&b, "muster_hosts_total %d\n", len(hosts))

	b.WriteString("# HELP muster_hosts_stale_total Hosts that haven't reported in over the staleness threshold (internal/policy.StaleAfter, 24h).\n")
	b.WriteString("# TYPE muster_hosts_stale_total gauge\n")
	fmt.Fprintf(&b, "muster_hosts_stale_total %d\n", stale)

	b.WriteString("# HELP muster_hosts_by_platform Hosts reporting, broken down by platform.\n")
	b.WriteString("# TYPE muster_hosts_by_platform gauge\n")
	platforms := make([]string, 0, len(byPlatform))
	for p := range byPlatform {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		fmt.Fprintf(&b, "muster_hosts_by_platform{platform=%q} %d\n", p, byPlatform[p])
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}

// handleListHosts is GET /api/hosts, optionally filtered to only stale
// ones with ?stale=true -- server-side enforcement of the same 24h rule
// the board's STALE badge already showed client-side (see
// internal/policy), so "which hosts are stale" is now a real, scriptable
// answer, not something only the browser could compute.
func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	if r.URL.Query().Get("stale") == "true" {
		now := time.Now().UTC()
		filtered := make([]model.Host, 0, len(hosts))
		for _, h := range hosts {
			if policy.IsStale(h.LastCooked, now) {
				filtered = append(filtered, h)
			}
		}
		hosts = filtered
	}
	s.writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	host, ok, err := s.Store.GetHost(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	facts, err := s.Store.ListFacts(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching facts")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"host": host, "facts": facts})
}

// hostPatchRequest is deliberately all-pointer: a field left out of the
// JSON body (nil) is left untouched, distinguishing "don't change tags"
// from "clear tags to []" (an explicit `"tags": []`). The board drag
// sends {"group": "..."}; the tag editor sends {"tags": [...]}; either
// or both together both work in one PATCH.
type hostPatchRequest struct {
	Group *string   `json:"group"`
	Tags  *[]string `json:"tags"`
}

// handlePatchHost is the write side of the Kanban board and its tag
// labels: PATCH /api/hosts/{host} with {"group": "prod"} and/or
// {"tags": ["needs-patching"]}. Only a host that has reported in at
// least once can be assigned a group/tags -- see store.ErrHostNotFound.
func (s *Server) handlePatchHost(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "remediate")
	if !ok {
		return
	}

	name := r.PathValue("host")

	var req hostPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Group == nil && req.Tags == nil {
		s.writeError(w, http.StatusBadRequest, "at least one of group or tags is required")
		return
	}

	var (
		host model.Host
		err  error
	)
	if req.Group != nil {
		host, err = s.Store.SetHostGroup(r.Context(), name, *req.Group)
		if err != nil {
			s.writeHostWriteError(w, err)
			return
		}
	}
	if req.Tags != nil {
		host, err = s.Store.SetHostTags(r.Context(), name, *req.Tags)
		if err != nil {
			s.writeHostWriteError(w, err)
			return
		}
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "patch-host", name, patchAuditDetail(req)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, host)
}

// patchAuditDetail renders a hostPatchRequest's pointer fields as a
// short, readable audit-log line -- fmt's default %v on a pointer would
// just print an address, not the actual value the caller sent.
func patchAuditDetail(req hostPatchRequest) string {
	parts := []string{}
	if req.Group != nil {
		parts = append(parts, fmt.Sprintf("group=%q", *req.Group))
	}
	if req.Tags != nil {
		parts = append(parts, fmt.Sprintf("tags=%v", *req.Tags))
	}
	return strings.Join(parts, " ")
}

func (s *Server) writeHostWriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrHostNotFound) {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	s.writeError(w, http.StatusInternalServerError, "updating host")
}

// handleListChanges answers "what's changed on this host" --
// GET /api/hosts/{host}/changes[?limit=N] (default 50, newest first).
func (s *Server) handleListChanges(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			s.writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}

	changes, err := s.Store.ListChanges(r.Context(), name, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing changes")
		return
	}
	s.writeJSON(w, http.StatusOK, changes)
}

func (s *Server) handleGetFact(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	category := r.PathValue("category")
	fact, ok, err := s.Store.GetFact(r.Context(), name, category)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching fact")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "fact not found")
		return
	}
	s.writeJSON(w, http.StatusOK, fact)
}

// handleQuery answers the use case the original project's own docs call
// out: "which servers are running version X of something" --
// GET /api/query?category=system_summary&field=distribution&contains=Ubuntu
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	q := r.URL.Query()
	category, field := q.Get("category"), q.Get("field")
	if category == "" || field == "" {
		s.writeError(w, http.StatusBadRequest, "category and field are required")
		return
	}
	facts, err := s.Store.Query(r.Context(), category, field, q.Get("contains"))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "querying")
		return
	}
	s.writeJSON(w, http.StatusOK, facts)
}

// actionRequest is the body of POST /api/hosts/{host}/actions --
// {"verb": "restart-service", "arg": "sshd"}. See internal/remediate for
// the fixed set Verb is ever validated against.
type actionRequest struct {
	Verb string `json:"verb"`
	Arg  string `json:"arg"`
}

// handleQueueAction is the only path in the whole system that creates a
// model.Action -- and therefore the only path that can ever cause an
// agent to run anything. It always requires AuthToken to be configured
// (remediation has no "open" mode, unlike board writes) and a valid
// bearer credential, then validates verb/arg against internal/remediate
// before the host's platform is even known to matter, and again against
// that specific host's platform once it is.
func (s *Server) handleQueueAction(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "remediate")
	if !ok {
		return
	}

	name := r.PathValue("host")
	host, ok, err := s.Store.GetHost(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}

	var req actionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := remediate.Validate(host.Platform, req.Verb, req.Arg); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	action, err := s.Store.QueueAction(r.Context(), name, req.Verb, req.Arg)
	if err != nil {
		if errors.Is(err, store.ErrHostNotFound) {
			s.writeError(w, http.StatusNotFound, "host not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "queuing action")
		return
	}
	detail := fmt.Sprintf("queued action %s (%s %s)", action.ID, req.Verb, req.Arg)
	if _, err := s.Store.RecordAudit(r.Context(), actor, "queue-action", name, detail); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	if s.Webhooks != nil {
		go s.Webhooks.Send(webhook.Event{Type: "remediation_executed", Host: name, Detail: detail})
	}
	s.writeJSON(w, http.StatusCreated, action)
}

// handleListActions is read-only history/status -- GET
// /api/hosts/{host}/actions -- gated the same as every other read
// endpoint (requireRole "readonly": open in demo mode, any valid
// credential once auth is on), not the AuthToken-always-required gate
// handleQueueAction itself uses -- what happened is not more sensitive
// than the facts already exposed elsewhere, only creating a new action
// is.
func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	actions, err := s.Store.ListActions(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing actions")
		return
	}
	s.writeJSON(w, http.StatusOK, actions)
}

// handleListGroups is GET /api/groups -- every known board-column name,
// including ones with no host in them yet. Same "readonly" role gate as
// every other read endpoint.
func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	groups, err := s.Store.ListGroups(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing groups")
		return
	}
	s.writeJSON(w, http.StatusOK, groups)
}

// handleCreateGroup is POST /api/groups with {"name": "..."} -- how an
// operator's freshly-typed, still-empty board column survives a reload
// instead of only becoming real once a host is dropped into it. Same
// auth posture as PATCH /api/hosts/{host}: open when AuthToken isn't
// configured, "remediate" role or higher required once it is -- this is
// a board write like that one, not a remediation-style hard requirement.
func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "remediate")
	if !ok {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := s.Store.CreateGroup(r.Context(), name); err != nil {
		s.writeError(w, http.StatusInternalServerError, "creating group")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "create-group", name, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"name": name})
}

// handleGetPosture is GET /api/hosts/{host}/posture -- an on-demand
// compliance score (internal/policy.ComputePosture), never stored,
// always computed fresh from whatever facts are on hand right now.
func (s *Server) handleGetPosture(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	host, ok, err := s.Store.GetHost(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	byCategory, err := s.factsByCategory(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching facts")
		return
	}
	stale := policy.IsStale(host.LastCooked, time.Now().UTC())
	s.writeJSON(w, http.StatusOK, policy.ComputePosture(host.Platform, byCategory, stale))
}

// factsByCategory is a small shared helper: every caller that needs a
// host's facts keyed by category (posture, summary, the evaluator) ends
// up doing this same ListFacts-then-index step.
func (s *Server) factsByCategory(ctx context.Context, host string) (map[string]model.Fact, error) {
	facts, err := s.Store.ListFacts(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		out[f.Category] = f
	}
	return out, nil
}

// handleGetVulnerabilities is GET /api/hosts/{host}/vulnerabilities --
// cross-references the host's installed_software fact against
// internal/vuln's small curated dataset. See that package's doc comment
// for exactly how limited this is: a demonstration of the concept, not
// a live CVE feed.
func (s *Server) handleGetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	fact, ok, err := s.Store.GetFact(r.Context(), name, "installed_software")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching installed_software fact")
		return
	}
	findings := []vuln.Finding{}
	if ok {
		if f := vuln.CheckWithFeed(fact.Data["items"], s.VulnFeed); f != nil {
			findings = f
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"host": name, "findings": findings})
}

// handleGetSoftwareViolations is GET /api/hosts/{host}/software-violations
// -- cross-references the host's installed_software fact against every
// software rule in scope for its board group (internal/allowlist).
func (s *Server) handleGetSoftwareViolations(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	host, ok, err := s.Store.GetHost(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	rules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}
	var inScope []model.SoftwareRule
	for _, rule := range rules {
		if rule.Group == "" || rule.Group == host.Group {
			inScope = append(inScope, rule)
		}
	}
	fact, ok, err := s.Store.GetFact(r.Context(), name, "installed_software")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching installed_software fact")
		return
	}
	violations := []allowlist.Violation{}
	shadowAI := []allowlist.Violation{}
	if ok {
		if v := allowlist.Evaluate(fact.Data["items"], inScope); v != nil {
			violations = v
		}
		if v := allowlist.EvaluateShadowAI(fact.Data["items"], inScope); v != nil {
			shadowAI = v
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"host": name, "violations": violations, "shadow_ai": shadowAI})
}

// complianceInput gathers everything compliance.Input needs for host
// name -- the same facts/posture/vuln/software-violation computation
// handleGetPosture, handleGetVulnerabilities, and
// handleGetSoftwareViolations each already do individually, bundled
// once here so handleGetCompliance and handleComplianceSummary don't
// each repeat it by hand.
func (s *Server) complianceInput(ctx context.Context, host model.Host, softwareRules []model.SoftwareRule) (compliance.Input, error) {
	return signals.Gather(ctx, s.Store, host, softwareRules, s.VulnFeed)
}

// handleGetCompliance is GET /api/hosts/{host}/compliance -- evaluates
// every built-in compliance.Framework against the host's current
// signals, computed fresh on every call (same as posture and
// vulnerabilities -- nothing here is precomputed or cached).
func (s *Server) handleGetCompliance(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	name := r.PathValue("host")
	host, ok, err := s.Store.GetHost(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching host")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "host not found")
		return
	}
	softwareRules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}
	in, err := s.complianceInput(r.Context(), host, softwareRules)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "gathering compliance input")
		return
	}
	s.writeJSON(w, http.StatusOK, compliance.EvaluateAll(in))
}

// handleComplianceSummary is GET /api/compliance/summary -- a
// fleet-wide rollup of the Baseline framework: average score, and how
// many hosts pass every check outright. Only Baseline is rolled up
// today (not every Frameworks entry) since it's the only one that
// exists -- this handler is the natural place to extend once a second
// framework is added.
func (s *Server) handleComplianceSummary(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	softwareRules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}

	// ?framework= selects which built-in framework to roll up (default
	// Baseline) -- the same Input is scored by whichever one is asked
	// for, which is the whole point of frameworks being pluggable.
	framework := compliance.Baseline
	if id := r.URL.Query().Get("framework"); id != "" {
		f, ok := compliance.ByID(id)
		if !ok {
			s.writeError(w, http.StatusBadRequest, "unknown framework "+id+" (see GET /api/compliance/frameworks)")
			return
		}
		framework = f
	}

	type hostScore struct {
		Host  string `json:"host"`
		Score int    `json:"score"`
	}
	type checkStat struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Failing     int    `json:"failing"`
	}
	scores := make([]hostScore, 0, len(hosts))
	scoreSum := 0
	fullyCompliant := 0
	failingByCheck := map[string]*checkStat{}
	var checkOrder []string
	for _, h := range hosts {
		in, err := s.complianceInput(r.Context(), h, softwareRules)
		if err != nil {
			s.log().Error("compliance summary: gathering input", "host", h.Name, "err", err)
			continue
		}
		result := framework.Evaluate(in)
		scores = append(scores, hostScore{Host: h.Name, Score: result.Score})
		scoreSum += result.Score
		if result.Score == 100 {
			fullyCompliant++
		}
		for _, c := range result.Checks {
			st, ok := failingByCheck[c.ID]
			if !ok {
				st = &checkStat{ID: c.ID, Description: c.Description}
				failingByCheck[c.ID] = st
				checkOrder = append(checkOrder, c.ID)
			}
			if !c.Pass {
				st.Failing++
			}
		}
	}
	avg := 0
	if len(scores) > 0 {
		avg = scoreSum / len(scores)
	}
	checks := make([]checkStat, 0, len(checkOrder))
	for _, id := range checkOrder {
		checks = append(checks, *failingByCheck[id])
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"framework":       framework.Name,
		"framework_id":    framework.ID,
		"description":     framework.Description,
		"total_hosts":     len(hosts),
		"average_score":   avg,
		"fully_compliant": fullyCompliant,
		"hosts":           scores,
		"checks":          checks,
	})
}

// handleListFrameworks is GET /api/compliance/frameworks -- the built-in
// frameworks, so a client can offer a selector without hardcoding IDs.
func (s *Server) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	type fw struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Checks      int    `json:"checks"`
	}
	out := make([]fw, 0, len(compliance.Frameworks))
	for _, f := range compliance.Frameworks {
		out = append(out, fw{ID: f.ID, Name: f.Name, Description: f.Description, Checks: len(f.Evaluate(compliance.Input{}).Checks)})
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleSummary is GET /api/summary -- a fleet-wide rollup, the
// aggregate counterpart to the per-host board/detail views: how many
// hosts, by platform, how many stale, average posture score, and how
// many have at least one known-vulnerable package. Computed fresh on
// every call, same as posture -- nothing here is precomputed or cached.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	softwareRules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}

	now := time.Now().UTC()
	byPlatform := map[string]int{}
	staleCount := 0
	scoreSum := 0
	vulnerableHosts := 0
	totalFindings := 0
	shadowAIHosts := 0
	totalShadowAI := 0
	riskyExtHosts := 0
	totalRiskyExt := 0
	eolHosts := 0
	certIssueHosts := 0

	for _, h := range hosts {
		byPlatform[h.Platform]++
		stale := policy.IsStale(h.LastCooked, now)
		if stale {
			staleCount++
		}
		byCategory, err := s.factsByCategory(r.Context(), h.Name)
		if err != nil {
			s.log().Error("summary: fetching facts", "host", h.Name, "err", err)
			continue
		}
		scoreSum += policy.ComputePosture(h.Platform, byCategory, stale).Score
		if sw, ok := byCategory["installed_software"]; ok {
			var inScope []model.SoftwareRule
			for _, rule := range softwareRules {
				if rule.Group == "" || rule.Group == h.Group {
					inScope = append(inScope, rule)
				}
			}
			if shadowAI := allowlist.EvaluateShadowAI(sw.Data["items"], inScope); len(shadowAI) > 0 {
				shadowAIHosts++
				totalShadowAI += len(shadowAI)
			}
			if findings := vuln.CheckWithFeed(sw.Data["items"], s.VulnFeed); len(findings) > 0 {
				vulnerableHosts++
				totalFindings += len(findings)
			}
		}
		if ext, ok := byCategory["browser_extensions"]; ok {
			if risky := browserext.Risky(browserext.Evaluate(browserext.FromFact(ext.Data["items"]))); len(risky) > 0 {
				riskyExtHosts++
				totalRiskyExt += len(risky)
			}
		}
		if sum, ok := byCategory["system_summary"]; ok && eol.Check(sum.Data, now).State == "eol" {
			eolHosts++
		}
		if tc, ok := byCategory["tls_certificates"]; ok && len(certs.Problems(certs.FromFact(tc.Data["items"], now))) > 0 {
			certIssueHosts++
		}
	}

	avgScore := 0
	if len(hosts) > 0 {
		avgScore = scoreSum / len(hosts)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"total_hosts":                  len(hosts),
		"stale_hosts":                  staleCount,
		"by_platform":                  byPlatform,
		"average_posture_score":        avgScore,
		"hosts_with_vulnerabilities":   vulnerableHosts,
		"total_vulnerability_findings": totalFindings,
		"hosts_with_shadow_ai":         shadowAIHosts,
		"total_shadow_ai_findings":     totalShadowAI,
		"hosts_with_risky_extensions":  riskyExtHosts,
		"total_risky_extensions":       totalRiskyExt,
		"hosts_os_eol":                 eolHosts,
		"hosts_with_cert_issues":       certIssueHosts,
	})
}

// askHostContext is one host's compact, LLM-friendly summary -- the
// same signals the compliance/posture/vulnerability/allowlist endpoints
// already compute, flattened into short strings instead of nested
// structures, so the fleet context handed to the model stays small and
// readable rather than a raw dump of every fact category on every host.
type askHostContext struct {
	Name               string   `json:"name"`
	Platform           string   `json:"platform"`
	Group              string   `json:"group,omitempty"`
	Tags               []string `json:"tags,omitempty"`
	Stale              bool     `json:"stale"`
	LastReported       string   `json:"last_reported"`
	PostureScore       int      `json:"posture_score"`
	PostureFindings    []string `json:"posture_findings,omitempty"`
	ComplianceScore    int      `json:"compliance_score"`
	Vulnerabilities    []string `json:"vulnerabilities,omitempty"`
	SoftwareViolations []string `json:"software_violations,omitempty"`
	ShadowAI           []string `json:"shadow_ai_detections,omitempty"`
}

// askContext is the full compact snapshot handed to aiquery.Ask
// alongside the operator's question.
type askContext struct {
	GeneratedAt      time.Time               `json:"generated_at"`
	FleetSummary     map[string]any          `json:"fleet_summary"`
	Hosts            []askHostContext        `json:"hosts"`
	PolicyRules      []model.Rule            `json:"policy_rules"`
	SoftwareRules    []model.SoftwareRule    `json:"software_rules"`
	DiscoveredAssets []model.DiscoveredAsset `json:"discovered_assets"`
}

// buildAskContext gathers everything askContext needs from the Store,
// reusing complianceInput -- the same per-host posture/vulnerability/
// allowlist computation handleGetCompliance and handleComplianceSummary
// already do -- so Ask Muster's answers are grounded in exactly the same
// numbers the rest of the dashboard shows, never a separately computed
// (and possibly inconsistent) view of the same facts.
func (s *Server) buildAskContext(ctx context.Context) (askContext, error) {
	hosts, err := s.Store.ListHosts(ctx)
	if err != nil {
		return askContext{}, fmt.Errorf("listing hosts: %w", err)
	}
	softwareRules, err := s.Store.ListSoftwareRules(ctx)
	if err != nil {
		return askContext{}, fmt.Errorf("listing software rules: %w", err)
	}
	policyRules, err := s.Store.ListRules(ctx)
	if err != nil {
		return askContext{}, fmt.Errorf("listing policy rules: %w", err)
	}
	assets, err := s.Store.ListDiscoveredAssets(ctx)
	if err != nil {
		return askContext{}, fmt.Errorf("listing discovered assets: %w", err)
	}

	now := time.Now().UTC()
	byPlatform := map[string]int{}
	staleCount := 0
	hostCtxs := make([]askHostContext, 0, len(hosts))
	for _, h := range hosts {
		byPlatform[h.Platform]++
		stale := policy.IsStale(h.LastCooked, now)
		if stale {
			staleCount++
		}
		in, err := s.complianceInput(ctx, h, softwareRules)
		if err != nil {
			s.log().Error("ask muster: gathering compliance input", "host", h.Name, "err", err)
			continue
		}
		result := compliance.Baseline.Evaluate(in)
		hc := askHostContext{
			Name: h.Name, Platform: h.Platform, Group: h.Group, Tags: h.Tags,
			Stale: stale, LastReported: h.LastCooked.Format(time.RFC3339),
			PostureScore: in.Posture.Score, PostureFindings: in.Posture.Findings,
			ComplianceScore: result.Score,
		}
		for _, f := range in.VulnFindings {
			hc.Vulnerabilities = append(hc.Vulnerabilities, fmt.Sprintf("%s %s (%s, severity %s): %s", f.Package, f.Version, f.CVE, f.Severity, f.Description))
		}
		for _, v := range in.SoftwareViolations {
			hc.SoftwareViolations = append(hc.SoftwareViolations, fmt.Sprintf("%s %s (%s rule %q)", v.Package, v.Version, v.Kind, v.Rule))
		}
		for _, v := range in.ShadowAIViolations {
			hc.ShadowAI = append(hc.ShadowAI, fmt.Sprintf("%s %s (matched: %s)", v.Package, v.Version, v.Rule))
		}
		hostCtxs = append(hostCtxs, hc)
	}

	return askContext{
		GeneratedAt: now,
		FleetSummary: map[string]any{
			"total_hosts": len(hosts), "stale_hosts": staleCount, "by_platform": byPlatform,
		},
		Hosts:            hostCtxs,
		PolicyRules:      policyRules,
		SoftwareRules:    softwareRules,
		DiscoveredAssets: assets,
	}, nil
}

// truncateForAudit shortens s to at most n runes (appending "..." when
// it does), the same "record it, but don't let one field blow up the
// audit log" discipline internal/webhook's payload and every other
// short audit Detail string in this project already follows.
func truncateForAudit(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// askRequest is the body of POST /api/ask.
type askRequest struct {
	Question string `json:"question"`
}

// handleAsk is POST /api/ask -- "Ask Muster": a natural-language query
// over the fleet data this server already holds, gated at "readonly"
// (the same tier as every other read-only endpoint -- asking a question
// about the fleet isn't a write). Every question and its answer are
// recorded to the audit log via Store.RecordAudit, truncated -- this is
// meant to be a "governed AI" feature with a real audit trail, not a
// generic chatbot bolted on: see internal/aiquery's package doc comment.
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "readonly")
	if !ok {
		return
	}
	if s.AIQuery == nil || !s.AIQuery.Get().Enabled() {
		s.writeError(w, http.StatusServiceUnavailable, aiquery.ErrNotConfigured.Error())
		return
	}
	var req askRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" {
		s.writeError(w, http.StatusBadRequest, "question is required")
		return
	}

	fleetCtx, err := s.buildAskContext(r.Context())
	if err != nil {
		s.log().Error("ask muster: building fleet context", "err", err)
		s.writeError(w, http.StatusInternalServerError, "gathering fleet context")
		return
	}

	answer, err := aiquery.Ask(r.Context(), s.AIQuery.Get(), req.Question, fleetCtx)
	if err != nil {
		s.log().Error("ask muster", "err", err)
		if errors.Is(err, aiquery.ErrNotConfigured) {
			s.writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		s.writeError(w, http.StatusBadGateway, "Ask Muster: "+err.Error())
		return
	}

	detail := fmt.Sprintf("Q: %s | A: %s", truncateForAudit(req.Question, 200), truncateForAudit(answer, 500))
	if _, err := s.Store.RecordAudit(r.Context(), actor, "ask-muster", "", detail); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"answer": answer})
}

// handleListAudit is GET /api/audit[?host=...&limit=N] -- who did what,
// to what, and when. Gated at "admin" (unlike most GETs, which only
// need "readonly") since an audit trail is oversight tooling, not
// day-to-day operational data.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "admin"); !ok {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	entries, err := s.Store.ListAudit(r.Context(), r.URL.Query().Get("host"), limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing audit log")
		return
	}
	s.writeJSON(w, http.StatusOK, entries)
}

// validRuleKinds are the only Kind values internal/evaluator knows how
// to evaluate -- see model.Rule's doc comment.
var validRuleKinds = map[string]bool{
	"stale":                 true,
	"score_below":           true,
	"category_missing":      true,
	"vulnerabilities_found": true,
}

// policyRequest is the body of POST /api/policies.
type policyRequest struct {
	Name             string `json:"name"`
	Group            string `json:"group"`
	Kind             string `json:"kind"`
	Threshold        int    `json:"threshold"`
	Category         string `json:"category"`
	AutoRemediate    string `json:"auto_remediate"`
	AutoRemediateArg string `json:"auto_remediate_arg"`
	RequireApproval  bool   `json:"require_approval"`
}

// handleListPolicies is GET /api/policies -- readable at "readonly",
// same as everything else that's just reporting configuration back.
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	rules, err := s.Store.ListRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing policies")
		return
	}
	s.writeJSON(w, http.StatusOK, rules)
}

// handleCreatePolicy is POST /api/policies -- gated at requireRoleStrict
// "admin" (never open, even in demo mode): a policy with AutoRemediate
// set can queue a remediation action entirely on its own, on a schedule,
// with no human in the loop -- the same risk profile as
// handleQueueAction itself, so it gets the same hard requirement.
func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || !validRuleKinds[req.Kind] {
		s.writeError(w, http.StatusBadRequest, "name is required and kind must be one of: stale, score_below, category_missing, vulnerabilities_found")
		return
	}
	if req.AutoRemediate != "" {
		if _, known := remediate.Verbs[req.AutoRemediate]; !known {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown remediation verb %q", req.AutoRemediate))
			return
		}
	}
	created, err := s.Store.CreateRule(r.Context(), model.Rule{
		Name: req.Name, Group: req.Group, Kind: req.Kind, Threshold: req.Threshold,
		Category: req.Category, AutoRemediate: req.AutoRemediate, AutoRemediateArg: req.AutoRemediateArg,
		RequireApproval: req.RequireApproval,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "creating policy")
		return
	}
	detail := fmt.Sprintf("kind=%s group=%q auto_remediate=%q", created.Kind, created.Group, created.AutoRemediate)
	if _, err := s.Store.RecordAudit(r.Context(), actor, "create-policy", created.Name, detail); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, created)
}

// handleDeletePolicy is DELETE /api/policies/{id} -- same hard "admin,
// always authenticated" gate as creating one.
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DeleteRule(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrRuleNotFound) {
			s.writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting policy")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "delete-policy", id, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// softwareRuleRequest is the body of POST /api/software-rules.
type softwareRuleRequest struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Match string `json:"match"`
}

var validSoftwareRuleKinds = map[string]bool{"deny": true, "allow": true}

// handleListSoftwareRules is GET /api/software-rules -- readable at
// "readonly", same as policies and enrollments.
func (s *Server) handleListSoftwareRules(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	rules, err := s.Store.ListSoftwareRules(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing software rules")
		return
	}
	s.writeJSON(w, http.StatusOK, rules)
}

// handleCreateSoftwareRule is POST /api/software-rules -- gated at
// requireRoleStrict "admin", the same hard gate policies use: an allow
// rule changes what counts as "unauthorized" fleet-wide the moment it
// exists, not something to leave reachable in demo mode.
func (s *Server) handleCreateSoftwareRule(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req softwareRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Match == "" || !validSoftwareRuleKinds[req.Kind] {
		s.writeError(w, http.StatusBadRequest, "name and match are required and kind must be \"deny\" or \"allow\"")
		return
	}
	created, err := s.Store.CreateSoftwareRule(r.Context(), model.SoftwareRule{
		Name: req.Name, Group: req.Group, Kind: req.Kind, Match: req.Match,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "creating software rule")
		return
	}
	detail := fmt.Sprintf("kind=%s group=%q match=%q", created.Kind, created.Group, created.Match)
	if _, err := s.Store.RecordAudit(r.Context(), actor, "create-software-rule", created.Name, detail); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, created)
}

// handleDeleteSoftwareRule is DELETE /api/software-rules/{id} -- same
// hard "admin, always authenticated" gate as creating one.
func (s *Server) handleDeleteSoftwareRule(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DeleteSoftwareRule(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrSoftwareRuleNotFound) {
			s.writeError(w, http.StatusNotFound, "software rule not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting software rule")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "delete-software-rule", id, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// validRoles are the only Role values an API key can carry.
var validRoles = map[string]bool{"readonly": true, "remediate": true, "admin": true}

// keyRequest is the body of POST /api/keys.
type keyRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// handleListKeys is GET /api/keys -- admin-only, always authenticated
// (requireRoleStrict): even just seeing which named keys exist and what
// role each has is administrative information, not day-to-day reporting
// data. TokenHash is never marshaled (model.APIKey's `json:"-"` tag),
// but the endpoint itself is locked down regardless.
func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "admin"); !ok {
		return
	}
	keys, err := s.Store.ListAPIKeys(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing api keys")
		return
	}
	s.writeJSON(w, http.StatusOK, keys)
}

// handleCreateKey is POST /api/keys with {"name": "...", "role": "..."}
// -- issues a fresh 192-bit bearer credential, returned in this one
// response and never again. Only the master -auth-token (or an existing
// "admin"-role key) can create one, which is exactly how the RBAC layer
// bootstraps: the operator who started the server with -auth-token
// mints the first named key, and can mint more admin keys after that if
// they want to stop using the master token day to day.
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req keyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || !validRoles[req.Role] {
		s.writeError(w, http.StatusBadRequest, "name is required and role must be one of: readonly, remediate, admin")
		return
	}
	raw, err := randomToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "generating token")
		return
	}
	created, err := s.Store.CreateAPIKey(r.Context(), req.Name, req.Role, sha256Hex(raw))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "creating api key")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "create-key", created.Name, fmt.Sprintf("role=%s", created.Role)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id": created.ID, "name": created.Name, "role": created.Role,
		"token": raw, "created_at": created.CreatedAt,
	})
}

// handleDeleteKey is DELETE /api/keys/{id} -- revokes a key immediately;
// any request already using it fails its next auth check.
func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DeleteAPIKey(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrAPIKeyNotFound) {
			s.writeError(w, http.StatusNotFound, "api key not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting api key")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "delete-key", id, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// mobileReportRequest is the body of POST /api/mobile-report -- a
// simpler, JSON-over-HTTP alternative to the TCP MUSTER1 protocol for
// agents where a raw socket + tar.gz payload is the wrong shape: the
// Android app (agent/android/), the iOS Shortcuts-based flow
// (agent/ios/README.md), and the ChromeOS extension (agent/chromeos/)
// all use this instead. Facts feed into the
// exact same UpsertHost/UpsertFact path every other agent's report goes
// through, the same way internal/cook.Pipeline.Cook does for the raw
// TCP agents -- change tracking, staleness, posture, and vulnerability
// correlation all just work, no separate mobile-only code path below
// this handler.
type mobileReportRequest struct {
	Host     string                    `json:"host"`
	Platform string                    `json:"platform"` // "android", "ios", or "chromeos"
	Facts    map[string]map[string]any `json:"facts"`    // category -> field -> value, at least one category required
}

// handleMobileReport is POST /api/mobile-report. Authenticated by
// authorizedIngestToken, not requireRole/requireRoleStrict -- see that
// method's doc comment for exactly what credential it accepts.
func (s *Server) handleMobileReport(w http.ResponseWriter, r *http.Request) {
	var req mobileReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" || (req.Platform != "android" && req.Platform != "ios" && req.Platform != "chromeos") {
		s.writeError(w, http.StatusBadRequest, `host is required and platform must be "android", "ios", or "chromeos"`)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !s.authorizedIngestToken(r.Context(), token, req.Host) {
		s.writeError(w, http.StatusUnauthorized, "missing or invalid bearer token for this host")
		return
	}
	if len(req.Facts) == 0 {
		s.writeError(w, http.StatusBadRequest, "facts must include at least one category")
		return
	}

	now := time.Now().UTC()
	if err := s.Store.UpsertHost(r.Context(), model.Host{Name: req.Host, Platform: req.Platform, LastCooked: now}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "upserting host")
		return
	}

	// Sorted for the same reason internal/cook.Pipeline.Cook sorts its
	// category names -- a stable, predictable order in logs/tests, at
	// no real cost given how few categories a mobile report ever has.
	names := make([]string, 0, len(req.Facts))
	for name := range req.Facts {
		names = append(names, name)
	}
	sort.Strings(names)

	var totalChanges int
	for _, name := range names {
		changes, err := s.Store.UpsertFact(r.Context(), model.Fact{
			Host: req.Host, Category: name, Data: req.Facts[name], CookedAt: now,
		})
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("upserting fact %q", name))
			return
		}
		totalChanges += len(changes)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"host": req.Host, "changes": totalChanges})
}

// enrollmentRequest is the body of POST /api/enrollments.
type enrollmentRequest struct {
	Host     string `json:"host"`
	Platform string `json:"platform"`
}

// handleListEnrollments is GET /api/enrollments -- admin-only, same
// treatment as API keys (handleListKeys): even just seeing which hosts
// have a pending or live enrollment token is administrative information,
// not day-to-day reporting data. TokenHash is never marshaled
// (model.Enrollment's `json:"-"` tag), but the endpoint itself is locked
// down regardless.
func (s *Server) handleListEnrollments(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "admin"); !ok {
		return
	}
	enrollments, err := s.Store.ListEnrollments(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing enrollments")
		return
	}
	s.writeJSON(w, http.StatusOK, enrollments)
}

// validHostName mirrors the agent scripts' own assert_safe_token charset
// (agent/ubuntu/muster-agent.sh, agent/windows/muster-agent.ps1) and
// cmd/muster's validAuthToken: letters, digits, '.', '_', '-' only, 1-128
// chars. This isn't cosmetic -- the TCP wire protocol header is
// space-delimited (internal/ingest/protocol.go, parsed with
// strings.Fields), and the generated install command drops the host name
// into a shell/PowerShell command line unquoted, so a host name with a
// space (or any other shell metacharacter) breaks both. Rejecting it here,
// at creation time, is a lot friendlier than the agent script's own
// assert_safe_token failing on a host someone already tried to enroll.
var validHostName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// handleCreateEnrollment is POST /api/enrollments with {"host": "...",
// "platform": "..."} -- issues a fresh 192-bit token scoped to exactly
// that host, returned in this one response and never again (same
// one-time-reveal discipline as handleCreateKey). This is what backs
// the dashboard's Agents page: mint one per host, get back a
// pre-filled install command, watch it flip from "pending" to
// "enrolled" once the real device reports in. Gated the same as
// creating an API key -- issuing any live credential is admin,
// always-authenticated territory, never available in demo mode.
func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req enrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" || req.Platform == "" {
		s.writeError(w, http.StatusBadRequest, "host and platform are required")
		return
	}
	if !validHostName.MatchString(req.Host) {
		s.writeError(w, http.StatusBadRequest, "host name may only contain letters, digits, '.', '_', '-' (no spaces) -- 1-128 characters")
		return
	}
	raw, err := randomToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "generating token")
		return
	}
	created, err := s.Store.CreateEnrollment(r.Context(), req.Host, req.Platform, sha256Hex(raw))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "creating enrollment")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "create-enrollment", created.Host, fmt.Sprintf("platform=%s", created.Platform)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id": created.ID, "host": created.Host, "platform": created.Platform,
		"status": created.Status, "token": raw, "created_at": created.CreatedAt,
	})
}

// handleDeleteEnrollment is DELETE /api/enrollments/{id} -- revokes an
// enrollment token immediately, enrolled or still pending either way.
func (s *Server) handleDeleteEnrollment(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DeleteEnrollment(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrEnrollmentNotFound) {
			s.writeError(w, http.StatusNotFound, "enrollment not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting enrollment")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "delete-enrollment", id, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDownloadAgent is GET /api/agents/download/{platform} -- serves
// the real agent script for platform straight from the compiled binary
// (see the agent package's doc comment): the same file committed at
// agent/ubuntu/muster-agent.sh etc., never a second copy that can drift
// out of sync with it. Unauthenticated, matching /healthz and
// /metrics' posture -- these are public install scripts, nothing
// sensitive about serving them (the enrollment/API token an operator
// pastes alongside one is never embedded in the script itself).
func (s *Server) handleDownloadAgent(w http.ResponseWriter, r *http.Request) {
	platform := r.PathValue("platform")
	entry, ok := agent.ScriptPath[platform]
	if !ok {
		s.writeError(w, http.StatusNotFound, "unknown platform (want one of: linux, windows, macos)")
		return
	}
	data, err := agent.Scripts.ReadFile(entry.Embedded)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "reading agent script")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+entry.Filename+`"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// discoverReportRequest is the body of POST /api/discover-report,
// posted by cmd/discover after a sweep -- a batch of best-effort
// sightings, not a full agent report (see model.DiscoveredAsset's doc
// comment for how this differs from a managed Host).
type discoverReportRequest struct {
	ScannedBy   string                 `json:"scanned_by"`
	ScannedCIDR string                 `json:"scanned_cidr"`
	Assets      []discoveredAssetInput `json:"assets"`
}

type discoveredAssetInput struct {
	Address   string            `json:"address"`
	OpenPorts []int             `json:"open_ports"`
	Banners   map[string]string `json:"banners,omitempty"`
}

// handleDiscoverReport is POST /api/discover-report. Gated at
// "remediate" rather than left wide open like the agent-facing report
// endpoints: unlike a host reporting about itself, a discovery sweep
// reveals what else lives on the network, which is operator-level
// information, not something any enrolled agent should be able to push.
func (s *Server) handleDiscoverReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "remediate")
	if !ok {
		return
	}
	var req discoverReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Assets) == 0 {
		s.writeError(w, http.StatusBadRequest, "assets must include at least one entry")
		return
	}
	saved := make([]model.DiscoveredAsset, 0, len(req.Assets))
	for _, in := range req.Assets {
		if in.Address == "" {
			continue
		}
		_, known, err := s.Store.GetHost(r.Context(), in.Address)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "checking known hosts")
			return
		}
		asset, err := s.Store.UpsertDiscoveredAsset(r.Context(), model.DiscoveredAsset{
			Address:     in.Address,
			OpenPorts:   in.OpenPorts,
			Banners:     in.Banners,
			ScannedBy:   req.ScannedBy,
			ScannedCIDR: req.ScannedCIDR,
			Known:       known,
		})
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "recording discovered asset")
			return
		}
		saved = append(saved, asset)
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "discover-report", req.ScannedCIDR, fmt.Sprintf("%d assets", len(saved))); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"recorded": len(saved), "assets": saved})
}

// handleListDiscoveredAssets is GET /api/discovered-assets -- readonly,
// same tier as every other fleet-visibility list.
func (s *Server) handleListDiscoveredAssets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	assets, err := s.Store.ListDiscoveredAssets(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing discovered assets")
		return
	}
	s.writeJSON(w, http.StatusOK, assets)
}

// handleDeleteDiscoveredAsset is DELETE /api/discovered-assets/{id} --
// e.g. once an operator has onboarded a sighting as a real managed
// Host, or it turns out to be noise. Gated at "remediate", matching the
// report endpoint's tier.
func (s *Server) handleDeleteDiscoveredAsset(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRole(w, r, "remediate")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.DeleteDiscoveredAsset(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrDiscoveredAssetNotFound) {
			s.writeError(w, http.StatusNotFound, "discovered asset not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "deleting discovered asset")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "delete-discovered-asset", id, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// airgapReportRequest is the body of POST /api/airgap-report: the same
// gzip-compressed tar payload the TCP ingest protocol carries as raw
// bytes, base64-encoded so it can travel through channels that aren't a
// direct socket to Muster at all -- pasted as text, carried on removable
// media, or (for small payloads) scanned as a QR code. This is the
// delivery path for agent/airgap/: a host with no network route to the
// Muster server whatsoever, where a human has to move the report by
// hand.
type airgapReportRequest struct {
	Platform   string `json:"platform"`
	Host       string `json:"host"`
	PayloadB64 string `json:"payload_b64"`
}

// handleAirgapReport is POST /api/airgap-report. Authenticated the same
// way as handleMobileReport (authorizedIngestToken: the master token, or
// a live per-host enrollment token) -- this is still one host reporting
// about itself, just over a different transport, so it gets the same
// narrow host-scoped credential rather than a requireRole check. Once
// decoded, the payload is extracted and cooked through the exact same
// ingest.ExtractPayload + cook.Pipeline.Cook path the TCP daemon uses
// for a normal upload -- change tracking, staleness, posture, and
// vulnerability correlation all just work, no separate air-gap-only
// logic below this handler.
func (s *Server) handleAirgapReport(w http.ResponseWriter, r *http.Request) {
	if s.Pipeline == nil {
		s.writeError(w, http.StatusServiceUnavailable, "server has no cook pipeline configured")
		return
	}
	var req airgapReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" || req.Platform == "" || req.PayloadB64 == "" {
		s.writeError(w, http.StatusBadRequest, "platform, host, and payload_b64 are all required")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !s.authorizedIngestToken(r.Context(), token, req.Host) {
		s.writeError(w, http.StatusUnauthorized, "missing or invalid bearer token for this host")
		return
	}

	raw, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "payload_b64 is not valid base64")
		return
	}

	snapshotDir := filepath.Join(s.Pipeline.RawBaseDir, req.Platform, req.Host, time.Now().UTC().Format("20060102T150405Z"))
	if err := ingest.ExtractPayload(bytes.NewReader(raw), int64(len(raw)), snapshotDir); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("extracting payload: %v", err))
		return
	}

	changes, err := s.Pipeline.Cook(r.Context(), req.Platform, req.Host)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("cooking payload: %v", err))
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"host": req.Host, "changes": len(changes)})
}

// cloudReportRequest is the body of POST /api/cloud-report -- a batch
// of compute instances found by one run of a cloud scanner
// (agent/aws, agent/azure, agent/gcp), reported the same way an OS
// agent reports itself: each instance becomes a real model.Host (not a
// DiscoveredAsset -- unlike a network sweep, a cloud API call is
// authoritative about what exists in that account, not a guess from
// probing ports).
type cloudReportRequest struct {
	Provider  string                `json:"provider"` // "aws", "azure", or "gcp" -- advisory, not enforced against a fixed list
	Account   string                `json:"account,omitempty"`
	Instances []cloudInstanceReport `json:"instances"`
}

type cloudInstanceReport struct {
	Host  string                    `json:"host"` // e.g. the instance ID -- i-0abc123..., an Azure resource ID, a GCE instance name
	Facts map[string]map[string]any `json:"facts"`
}

// handleCloudReport is POST /api/cloud-report. Deliberately not gated
// with authorizedIngestToken the way handleMobileReport is: that check
// authorizes exactly one host per token, which fits an agent reporting
// about itself but not a single account-wide scan legitimately covering
// many instances under one credential. This endpoint instead requires
// the server's master token outright (or is wide open in demo mode,
// like everything else when -auth-token isn't set) -- a scanner
// credential is operator-level, not host-level.
func (s *Server) handleCloudReport(w http.ResponseWriter, r *http.Request) {
	if s.AuthToken != "" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.AuthToken)) != 1 {
			s.writeError(w, http.StatusUnauthorized, "missing or invalid bearer token (cloud-report requires the server's master token)")
			return
		}
	}

	var req cloudReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Instances) == 0 {
		s.writeError(w, http.StatusBadRequest, "instances must include at least one entry")
		return
	}

	platform := req.Provider
	if platform == "" {
		platform = "cloud"
	}
	now := time.Now().UTC()
	var totalChanges int
	var reported []string
	for _, inst := range req.Instances {
		if inst.Host == "" || len(inst.Facts) == 0 {
			continue
		}
		if err := s.Store.UpsertHost(r.Context(), model.Host{Name: inst.Host, Platform: platform, LastCooked: now}); err != nil {
			s.writeError(w, http.StatusInternalServerError, "upserting host")
			return
		}
		names := make([]string, 0, len(inst.Facts))
		for name := range inst.Facts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			changes, err := s.Store.UpsertFact(r.Context(), model.Fact{
				Host: inst.Host, Category: name, Data: inst.Facts[name], CookedAt: now,
			})
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("upserting fact %q for %q", name, inst.Host))
				return
			}
			totalChanges += len(changes)
		}
		reported = append(reported, inst.Host)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"hosts_reported": len(reported), "changes": totalChanges})
}

// --- OAuth2/OIDC dashboard login -----------------------------------
//
// See internal/oauth's package doc comment and docs/security-model.md
// for the full design. In short: GET /api/auth/login kicks off an
// authorization-code+PKCE flow by redirecting the browser to the
// identity provider, stashing the CSRF state and PKCE verifier as
// short-lived cookies; GET /api/auth/callback is where the provider
// redirects back to with a code, which gets exchanged for a session
// cookie; POST /api/auth/logout clears that cookie; GET /api/auth/me
// tells the web UI whether OAuth login is configured at all and, if
// the caller has a valid session, who they're logged in as.

const (
	oauthStateCookie    = "muster_oauth_state"
	oauthVerifierCookie = "muster_oauth_verifier"
)

// transientCookie sets a short-lived, HttpOnly cookie used only to
// survive the redirect round-trip to the identity provider and back --
// never sent to a script, never valid for longer than the login
// attempt itself.
func transientCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.OAuth == nil || !s.OAuth.Enabled {
		s.writeError(w, http.StatusServiceUnavailable, "OAuth login is not configured on this server (see the -oauth-* flags)")
		return
	}
	authURL, state, verifier, err := s.OAuth.AuthCodeURL()
	if err != nil {
		s.log().Error("building OAuth authorization URL", "err", err)
		s.writeError(w, http.StatusInternalServerError, "starting OAuth login")
		return
	}
	transientCookie(w, oauthStateCookie, state, 600)
	transientCookie(w, oauthVerifierCookie, verifier, 600)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.OAuth == nil || !s.OAuth.Enabled || s.Sessions == nil {
		s.writeError(w, http.StatusServiceUnavailable, "OAuth login is not configured on this server")
		return
	}
	q := r.URL.Query()
	if idpErr := q.Get("error"); idpErr != "" {
		s.writeError(w, http.StatusBadRequest, "identity provider returned an error: "+idpErr)
		return
	}
	state := q.Get("state")
	code := q.Get("code")
	stateCookie, err := r.Cookie(oauthStateCookie)
	if state == "" || code == "" || err != nil || stateCookie.Value == "" || state != stateCookie.Value {
		s.writeError(w, http.StatusBadRequest, "invalid or expired OAuth state -- start over at /api/auth/login")
		return
	}
	verifier := ""
	if verifierCookie, err := r.Cookie(oauthVerifierCookie); err == nil {
		verifier = verifierCookie.Value
	}
	// Clear the transient cookies now that they've been consumed --
	// one login attempt, one use, whether it succeeds or not below.
	transientCookie(w, oauthStateCookie, "", -1)
	transientCookie(w, oauthVerifierCookie, "", -1)

	email, err := s.OAuth.Exchange(r.Context(), code, verifier)
	if err != nil {
		s.log().Error("OAuth code exchange", "err", err)
		s.writeError(w, http.StatusUnauthorized, "completing OAuth login failed")
		return
	}
	role := s.OAuth.RoleFor(email)
	if role == "" {
		s.writeError(w, http.StatusForbidden, fmt.Sprintf("%s is not authorized -- no matching -oauth-role-map entry", email))
		return
	}
	sessionID := s.Sessions.Create(email, role)
	transientCookie(w, oauth.SessionCookieName, sessionID, int(oauth.SessionTTL.Seconds()))
	if _, err := s.Store.RecordAudit(r.Context(), email, "oauth-login", email, fmt.Sprintf("role=%s", role)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if s.Sessions != nil {
		if c, err := r.Cookie(oauth.SessionCookieName); err == nil {
			s.Sessions.Delete(c.Value)
		}
	}
	transientCookie(w, oauth.SessionCookieName, "", -1)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// handleAuthMe is GET /api/auth/me -- unauthenticated itself (a
// dashboard has to be able to ask "am I logged in?" before it has
// anything to authenticate with), it tells the web UI whether OAuth
// login is even configured (so it knows whether to show a "Sign in"
// control at all) and, if the request carries a valid session cookie,
// who as and with what role.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	oauthEnabled := s.OAuth != nil && s.OAuth.Enabled
	if email, role, ok := s.sessionFromCookie(r); ok {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"email":         email,
			"role":          role,
			"oauth_enabled": oauthEnabled,
		})
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": false,
		"oauth_enabled": oauthEnabled,
	})
}

func logMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
