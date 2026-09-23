/*******************************************************************************
 * @file         settingsstore.go
 * @brief        Package settingsstore persists the settings PATCH /api/settings can change without a restart-time flag/env var: two kinds of field.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package settingsstore persists the settings PATCH /api/settings can
// change without a restart-time flag/env var: two kinds of field.
//
// Some fields -- SIEM forwarding's HEC credentials and Ask TopoTrace's
// API key/model -- are live-reconfigurable: internal/api applies them
// to a running process immediately (internal/siemforward.Dynamic,
// internal/aiquery.ConfigStore) and only writes them here so the same
// value survives a restart, exactly like a -flag/env var would have.
//
// Everything else this package now carries -- listen addresses, the
// evaluator interval, OAuth, the vulnerability feed toggle, and the
// notification sinks -- persists for the *next* restart only: PATCH
// /api/settings validates and saves the value here, but the running
// process keeps behaving as it was started until it's restarted with
// this file present, at which point cmd/topotrace's startup logic uses it
// as a fallback default wherever the matching -flag/env var was left
// unset (flag/env always wins). These fields can't be swapped safely
// into a live process (a new listen address needs a new listener, a
// new OAuth config needs re-validating live sessions, ...) without more
// surgery than a settings-page round is scoped for, so "persist for
// next restart" is the deliberate, documented behavior here, not a gap.
//
// Adding a field here is still a deliberate per-field decision made in
// internal/api's PATCH handler (which of the two categories it falls
// into, and how it's validated), not a default this package encourages.
package settingsstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Overrides is the on-disk shape -- a straight mirror of the fields
// PATCH /api/settings accepts, across both categories described in the
// package doc comment above. Every field is a plain secret-bearing
// string/bool written with 0o600 permissions; unlike GET /api/settings's
// response, this file is deliberately not safe to expose over HTTP or
// log.
type Overrides struct {
	// Live-reconfigurable (see package doc comment): SIEM forwarding.
	SIEMBackend  string `json:"siem_backend,omitempty"` // "splunk-hec" (default), "sumo-http", "logrhythm-webhook"
	SIEMHECURL   string `json:"siem_hec_url,omitempty"`
	SIEMHECToken string `json:"siem_hec_token,omitempty"`

	// Live-reconfigurable: Ask TopoTrace (AI query).
	AIAPIKey  string `json:"ai_api_key,omitempty"`
	AIModel   string `json:"ai_model,omitempty"`
	AIBackend string `json:"ai_backend,omitempty"`  // "anthropic" (default) or "openai-compatible"
	AIBaseURL string `json:"ai_base_url,omitempty"` // OpenAI-compatible server root, e.g. https://router.huggingface.co/v1

	// Live-reconfigurable: the process's slog level -- "debug", "info"
	// (default), "warn", or "error". See internal/api's LogLevel field
	// (a *slog.LevelVar) for how PATCH /api/settings applies this to
	// the running process immediately, with no restart, the same way
	// SIEM forwarding and Ask TopoTrace already work.
	LogLevel string `json:"log_level,omitempty"`

	// Persist-for-next-restart: AD/LDAP dashboard login. All-or-
	// nothing, same as the -ldap-* flags -- see internal/ldap.
	LDAPHost         string `json:"ldap_host,omitempty"`
	LDAPPort         string `json:"ldap_port,omitempty"` // stored as a string so an empty override doesn't look like port 0
	LDAPUseTLS       bool   `json:"ldap_use_tls,omitempty"`
	LDAPBindDN       string `json:"ldap_bind_dn,omitempty"`
	LDAPBindPassword string `json:"ldap_bind_password,omitempty"`
	LDAPUserBaseDN   string `json:"ldap_user_base_dn,omitempty"`
	LDAPUserAttr     string `json:"ldap_user_attr,omitempty"`
	LDAPMailAttr     string `json:"ldap_mail_attr,omitempty"`
	LDAPGroupAttr    string `json:"ldap_group_attr,omitempty"`
	LDAPRoleMap      string `json:"ldap_role_map,omitempty"`

	// Persist-for-next-restart: SAML 2.0 dashboard login. All-or-
	// nothing, same as the -saml-* flags -- see internal/saml.
	SAMLEntityID  string `json:"saml_entity_id,omitempty"`
	SAMLACSURL    string `json:"saml_acs_url,omitempty"`
	SAMLIdPSSOURL string `json:"saml_idp_sso_url,omitempty"`
	SAMLIdPCert   string `json:"saml_idp_cert,omitempty"`
	SAMLRoleMap   string `json:"saml_role_map,omitempty"`

	// Persist-for-next-restart: General/ports.
	IngestAddr        string `json:"ingest_addr,omitempty"`
	APIAddr           string `json:"api_addr,omitempty"`
	EvaluatorInterval string `json:"evaluator_interval,omitempty"`

	// Persist-for-next-restart: OAuth2/OIDC dashboard login. All-or-
	// nothing, same as the -oauth-* flags -- see internal/oauth.
	OAuthClientID     string `json:"oauth_client_id,omitempty"`
	OAuthClientSecret string `json:"oauth_client_secret,omitempty"`
	OAuthAuthURL      string `json:"oauth_auth_url,omitempty"`
	OAuthTokenURL     string `json:"oauth_token_url,omitempty"`
	OAuthUserInfoURL  string `json:"oauth_userinfo_url,omitempty"`
	OAuthRedirectURL  string `json:"oauth_redirect_url,omitempty"`
	OAuthScopes       string `json:"oauth_scopes,omitempty"`
	OAuthRoleMap      string `json:"oauth_role_map,omitempty"`

	// Persist-for-next-restart: vulnerability feed (OSV.dev).
	VulnFeedEnabled  bool   `json:"vuln_feed_enabled,omitempty"`
	VulnFeedInterval string `json:"vuln_feed_interval,omitempty"`

	// Persist-for-next-restart: notification sinks.
	WebhookURLs        string `json:"webhook_urls,omitempty"`
	SlackWebhookURL    string `json:"slack_webhook_url,omitempty"`
	TeamsWebhookURL    string `json:"teams_webhook_url,omitempty"`
	JiraURL            string `json:"jira_url,omitempty"`
	JiraEmail          string `json:"jira_email,omitempty"`
	JiraToken          string `json:"jira_token,omitempty"`
	JiraProject        string `json:"jira_project,omitempty"`
	JiraIssueType      string `json:"jira_issue_type,omitempty"`
	ServiceNowURL      string `json:"servicenow_url,omitempty"`
	ServiceNowUser     string `json:"servicenow_user,omitempty"`
	ServiceNowPassword string `json:"servicenow_password,omitempty"`
}

// Load reads path and decodes it as Overrides. A missing file is not
// an error -- it returns the zero value, exactly like a server that
// has never had its settings edited from the dashboard.
func Load(path string) (Overrides, error) {
	var o Overrides
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return o, nil
		}
		return o, fmt.Errorf("settingsstore: reading %s: %w", path, err)
	}
	if len(data) == 0 {
		return o, nil
	}
	if err := json.Unmarshal(data, &o); err != nil {
		return o, fmt.Errorf("settingsstore: parsing %s: %w", path, err)
	}
	return o, nil
}

// Save writes o to path, atomically (write to a temp file in the same
// directory, then rename over path) and with 0o600 permissions, since
// this file carries secrets in plain text. The temp file is cleaned up
// on any failure before the rename.
func Save(path string, o Overrides) error {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("settingsstore: encoding overrides: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("settingsstore: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".settings-overrides-*.json.tmp")
	if err != nil {
		return fmt.Errorf("settingsstore: creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("settingsstore: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("settingsstore: closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("settingsstore: setting permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("settingsstore: renaming into place: %w", err)
	}
	return nil
}
