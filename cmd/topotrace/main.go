/*******************************************************************************
 * @file         main.go
 * @brief        Command topotrace runs the TopoTrace server: the TCP ingest daemon and the HTTP reporting API, side by side in one process, sharing one store.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Command topotrace runs the TopoTrace server: the TCP ingest daemon and the
// HTTP reporting API, side by side in one process, sharing one store.
//
//	go run ./cmd/topotrace
//
// Flags let you point both at different addresses/paths; defaults are
// tuned for "just run it" local demo use.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"topotrace/internal/aiquery"
	"topotrace/internal/api"
	"topotrace/internal/breach"
	"topotrace/internal/cook"
	"topotrace/internal/evaluator"
	"topotrace/internal/ingest"
	"topotrace/internal/ldap"
	"topotrace/internal/oauth"
	"topotrace/internal/pluginhost"
	"topotrace/internal/saml"
	"topotrace/internal/settingsstore"
	"topotrace/internal/siemforward"
	"topotrace/internal/store"
	"topotrace/internal/store/memstore"
	"topotrace/internal/store/pgstore"
	"topotrace/internal/vuln"
	"topotrace/internal/webhook"
	"topotrace/internal/webui"
)

// validAuthToken matches the same safe-token charset the wire protocol
// already enforces on every other field (internal/ingest.isSafeToken) --
// checked again here, at startup, so a bad -auth-token fails fast with a
// clear message instead of quietly locking every agent out at runtime.
var validAuthToken = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func envIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDurationDefault(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func main() {
	var (
		ingestAddr       = flag.String("ingest-addr", ":9090", "address for the TCP ingest daemon")
		apiAddr          = flag.String("api-addr", ":8080", "address for the HTTP reporting API")
		dataDir          = flag.String("data-dir", "./data", "base directory for raw packets, the memstore snapshot (ignored when -postgres-dsn is set), and settings-overrides.json (PATCH /api/settings's persisted live edits -- used regardless of storage backend)")
		postgresDSN      = flag.String("postgres-dsn", os.Getenv("TOPOTRACE_POSTGRES_DSN"), "Postgres connection string (e.g. postgres://user:pass@host:5432/topotrace?sslmode=disable); if set, facts are stored in Postgres instead of the in-memory/JSON-snapshot store. Also read from TOPOTRACE_POSTGRES_DSN.")
		authToken        = flag.String("auth-token", os.Getenv("TOPOTRACE_AUTH_TOKEN"), "shared secret required from agents (TOPOTRACE1/TOPOTRACE1-RESULT) and for API writes (PATCH /api/hosts, POST .../actions). Letters, digits, '.', '_', '-' only, 1-128 chars. Empty disables auth entirely and leaves remediation actions unavailable. Also read from TOPOTRACE_AUTH_TOKEN. This token always resolves to the 'admin' role, so it can bootstrap named API keys (see -h for the /api/keys endpoints).")
		webhookURLs      = flag.String("webhook-url", os.Getenv("TOPOTRACE_WEBHOOK_URLS"), "comma-separated URLs to POST a small JSON event to on policy violations and remediation (host_new/host_stale/policy_violation/remediation_executed). Empty disables webhooks. Also read from TOPOTRACE_WEBHOOK_URLS.")
		evalInterval     = flag.Duration("evaluator-interval", 5*time.Minute, "how often the background evaluator re-checks every host against every persisted policy rule (posture scoring, auto-remediation). Has no effect until at least one rule exists (POST /api/policies).")
		vulnFeedOn       = flag.Bool("vuln-feed", false, "supplement internal/vuln's static CVE dataset with live lookups from OSV.dev (https://osv.dev, free, no API key) for the packages in vuln.Watchlist. Off by default -- turning it on means this server makes outbound HTTPS requests to api.osv.dev on -vuln-feed-interval.")
		vulnFeedInterval = flag.Duration("vuln-feed-interval", 6*time.Hour, "how often -vuln-feed re-queries OSV.dev. Ignored when -vuln-feed is false.")

		oauthClientID     = flag.String("oauth-client-id", os.Getenv("TOPOTRACE_OAUTH_CLIENT_ID"), "OAuth2 client ID for dashboard login. Leave every -oauth-* flag empty to disable browser login entirely (bearer tokens still work). Also read from TOPOTRACE_OAUTH_CLIENT_ID.")
		oauthClientSecret = flag.String("oauth-client-secret", os.Getenv("TOPOTRACE_OAUTH_CLIENT_SECRET"), "OAuth2 client secret for dashboard login. Also read from TOPOTRACE_OAUTH_CLIENT_SECRET.")
		oauthAuthURL      = flag.String("oauth-auth-url", os.Getenv("TOPOTRACE_OAUTH_AUTH_URL"), "identity provider's authorization endpoint (e.g. https://accounts.google.com/o/oauth2/v2/auth). Also read from TOPOTRACE_OAUTH_AUTH_URL.")
		oauthTokenURL     = flag.String("oauth-token-url", os.Getenv("TOPOTRACE_OAUTH_TOKEN_URL"), "identity provider's token endpoint (e.g. https://oauth2.googleapis.com/token). Also read from TOPOTRACE_OAUTH_TOKEN_URL.")
		oauthUserInfoURL  = flag.String("oauth-userinfo-url", os.Getenv("TOPOTRACE_OAUTH_USERINFO_URL"), "identity provider's OIDC UserInfo endpoint (e.g. https://openidconnect.googleapis.com/v1/userinfo) -- see internal/oauth's doc comment for why this is used instead of parsing an ID token. Also read from TOPOTRACE_OAUTH_USERINFO_URL.")
		oauthRedirectURL  = flag.String("oauth-redirect-url", os.Getenv("TOPOTRACE_OAUTH_REDIRECT_URL"), "this server's own callback URL as registered with the identity provider (e.g. http://localhost:8080/api/auth/callback). Also read from TOPOTRACE_OAUTH_REDIRECT_URL.")
		oauthScopes       = flag.String("oauth-scopes", os.Getenv("TOPOTRACE_OAUTH_SCOPES"), "space-separated OAuth2 scopes to request. Defaults to \"openid email profile\" when empty. Also read from TOPOTRACE_OAUTH_SCOPES.")
		oauthRoleMap      = flag.String("oauth-role-map", os.Getenv("TOPOTRACE_OAUTH_ROLE_MAP"), "comma-separated email/domain-to-role mappings, checked in order, e.g. \"admin@example.com=admin,*@example.com=readonly\". Required (and the whole -oauth-* group required) once any -oauth-* flag is set. Also read from TOPOTRACE_OAUTH_ROLE_MAP.")

		ldapHost         = flag.String("ldap-host", os.Getenv("TOPOTRACE_LDAP_HOST"), "AD/LDAP server hostname for dashboard login (POST /api/auth/ldap-login). Leave every -ldap-* flag empty to disable it entirely. Also read from TOPOTRACE_LDAP_HOST.")
		ldapPort         = flag.Int("ldap-port", 0, "AD/LDAP server port. Defaults to 636 with -ldap-use-tls, else 389.")
		ldapUseTLS       = flag.Bool("ldap-use-tls", true, "connect to the LDAP server over TLS (LDAPS). Set false only for a directory reachable exclusively over a trusted private network.")
		ldapBindDN       = flag.String("ldap-bind-dn", os.Getenv("TOPOTRACE_LDAP_BIND_DN"), "service-account DN used to search the directory for the user logging in (e.g. \"CN=svc-topotrace,OU=Service Accounts,DC=example,DC=com\"). Empty attempts an anonymous bind for the search, which most directories disallow. Also read from TOPOTRACE_LDAP_BIND_DN.")
		ldapBindPassword = flag.String("ldap-bind-password", os.Getenv("TOPOTRACE_LDAP_BIND_PASSWORD"), "password for -ldap-bind-dn. Also read from TOPOTRACE_LDAP_BIND_PASSWORD.")
		ldapUserBaseDN   = flag.String("ldap-user-base-dn", os.Getenv("TOPOTRACE_LDAP_USER_BASE_DN"), "subtree to search for the logging-in user's entry (e.g. \"OU=People,DC=example,DC=com\"). Required once any -ldap-* flag is set. Also read from TOPOTRACE_LDAP_USER_BASE_DN.")
		ldapUserAttr     = flag.String("ldap-user-attr", os.Getenv("TOPOTRACE_LDAP_USER_ATTR"), "attribute holding the login username. Defaults to sAMAccountName (Active Directory); use uid for most generic LDAP/OpenLDAP directories. Also read from TOPOTRACE_LDAP_USER_ATTR.")
		ldapMailAttr     = flag.String("ldap-mail-attr", os.Getenv("TOPOTRACE_LDAP_MAIL_ATTR"), "attribute holding the user's email address. Defaults to mail. Also read from TOPOTRACE_LDAP_MAIL_ATTR.")
		ldapGroupAttr    = flag.String("ldap-group-attr", os.Getenv("TOPOTRACE_LDAP_GROUP_ATTR"), "attribute holding the group DNs a user belongs to, used for -ldap-role-map. Defaults to memberOf (Active Directory-style). Also read from TOPOTRACE_LDAP_GROUP_ATTR.")
		ldapRoleMap      = flag.String("ldap-role-map", os.Getenv("TOPOTRACE_LDAP_ROLE_MAP"), "semicolon-separated group-to-role mappings (semicolon, not comma -- a group DN already contains commas of its own), checked in order, matched against -ldap-group-attr's values by full DN or bare CN, e.g. \"CN=TopoTrace Admins,OU=Groups,DC=example,DC=com=admin;*=readonly\". Required (and the whole -ldap-* group required) once any -ldap-* flag is set. Also read from TOPOTRACE_LDAP_ROLE_MAP.")

		samlEntityID  = flag.String("saml-entity-id", os.Getenv("TOPOTRACE_SAML_ENTITY_ID"), "this server's own SAML SP entity ID (e.g. https://topotrace.example.com/saml/metadata) for SSO dashboard login. Leave every -saml-* flag empty to disable it entirely. Also read from TOPOTRACE_SAML_ENTITY_ID.")
		samlACSURL    = flag.String("saml-acs-url", os.Getenv("TOPOTRACE_SAML_ACS_URL"), "this server's own Assertion Consumer Service URL as registered with the identity provider (e.g. https://topotrace.example.com/api/auth/saml/acs). Also read from TOPOTRACE_SAML_ACS_URL.")
		samlIdPSSOURL = flag.String("saml-idp-sso-url", os.Getenv("TOPOTRACE_SAML_IDP_SSO_URL"), "identity provider's SSO endpoint (HTTP-Redirect binding). Also read from TOPOTRACE_SAML_IDP_SSO_URL.")
		samlIdPCert   = flag.String("saml-idp-cert", os.Getenv("TOPOTRACE_SAML_IDP_CERT"), "identity provider's PEM-encoded signing certificate, used to verify assertion signatures -- see internal/saml's doc comment for this package's signature-verification approach and its documented limitations. Also read from TOPOTRACE_SAML_IDP_CERT.")
		samlRoleMap   = flag.String("saml-role-map", os.Getenv("TOPOTRACE_SAML_ROLE_MAP"), "comma-separated email/domain-to-role mappings, same syntax as -oauth-role-map. Required (and the whole -saml-* group required) once any -saml-* flag is set. Also read from TOPOTRACE_SAML_ROLE_MAP.")

		logLevel = flag.String("log-level", os.Getenv("TOPOTRACE_LOG_LEVEL"), "process log level: debug, info (default), warn, or error. Live-adjustable afterward from the dashboard's Settings page (PATCH /api/settings, log_level) with no restart. Also read from TOPOTRACE_LOG_LEVEL.")

		scimToken = flag.String("scim-token", os.Getenv("TOPOTRACE_SCIM_TOKEN"), "bearer token authorizing SCIM 2.0 provisioning requests (/scim/v2/Users) -- issue this to your identity provider's SCIM app. Empty disables SCIM entirely. Also read from TOPOTRACE_SCIM_TOKEN.")

		mfaRequired  = flag.Bool("mfa-required", os.Getenv("TOPOTRACE_MFA_REQUIRED") == "true", "require TOTP multi-factor authentication for dashboard logins (OAuth/LDAP/SAML) -- see -mfa-roles to scope this to specific roles instead of everyone. Also read from TOPOTRACE_MFA_REQUIRED (\"true\"/\"false\").")
		mfaRoles     = flag.String("mfa-roles", os.Getenv("TOPOTRACE_MFA_ROLES"), "comma-separated roles MFA is required for (e.g. \"admin\"). Empty (with -mfa-required set) means every role. Also read from TOPOTRACE_MFA_ROLES.")
		mfaGraceDays = flag.Int("mfa-grace-days", envIntDefault("TOPOTRACE_MFA_GRACE_DAYS", 3), "days a newly-provisioned account may keep logging in without MFA enrolled yet, measured from when its directory record was first created -- an enrollment window, not a permanent exemption. Also read from TOPOTRACE_MFA_GRACE_DAYS.")
		mfaIssuer    = flag.String("mfa-issuer", os.Getenv("TOPOTRACE_MFA_ISSUER"), "issuer name shown in enrolled authenticator apps (defaults to \"TopoTrace\"). Also read from TOPOTRACE_MFA_ISSUER.")

		sessionIdleTimeout   = flag.Duration("session-idle-timeout", envDurationDefault("TOPOTRACE_SESSION_IDLE_TIMEOUT", 30*time.Minute), "how long a dashboard session may sit idle before it expires, independent of its absolute 12-hour lifetime. 0 disables idle expiry. Also read from TOPOTRACE_SESSION_IDLE_TIMEOUT (a Go duration string, e.g. \"30m\").")
		sessionMaxConcurrent = flag.Int("session-max-concurrent", envIntDefault("TOPOTRACE_SESSION_MAX_CONCURRENT", 5), "maximum concurrent dashboard sessions one account may hold at once -- creating one more evicts that account's oldest. 0 disables the cap. Also read from TOPOTRACE_SESSION_MAX_CONCURRENT.")

		licensedSeats = flag.Int("licensed-seats", envIntDefault("TOPOTRACE_LICENSED_SEATS", 0), "contracted seat count for the license/seat usage dashboard (GET /api/license/usage) -- 0 or unset means usage is still tracked and reported but never flagged as near or over limit. This is reporting only, not an enforced login cap. Also read from TOPOTRACE_LICENSED_SEATS.")

		aiAPIKey  = flag.String("ai-api-key", os.Getenv("TOPOTRACE_AI_API_KEY"), "Anthropic API key for \"Ask TopoTrace\" (POST /api/ask), a natural-language query surface over the fleet data with every question+answer recorded to the audit log. Empty disables the endpoint (it answers with a clear 'not configured' error). Also read from TOPOTRACE_AI_API_KEY.")
		aiModel   = flag.String("ai-model", os.Getenv("TOPOTRACE_AI_MODEL"), "Model id Ask TopoTrace calls. For the anthropic backend, empty uses internal/aiquery's built-in default. For the openai-compatible backend this is required and has no default, since what is served depends on the server (e.g. a Hugging Face model id, or the name your local Ollama reports). Also read from TOPOTRACE_AI_MODEL.")
		aiBackend = flag.String("ai-backend", os.Getenv("TOPOTRACE_AI_BACKEND"), "Which model API Ask TopoTrace speaks: \"anthropic\" (default) or \"openai-compatible\". The latter reaches Hugging Face's Inference Providers router and any self-hosted server that speaks OpenAI chat-completions (LM Studio, Ollama, vLLM, TGI) -- see -ai-base-url. Also read from TOPOTRACE_AI_BACKEND.")
		aiBaseURL = flag.String("ai-base-url", os.Getenv("TOPOTRACE_AI_BASE_URL"), "Root URL of an OpenAI-compatible server, required by -ai-backend openai-compatible. Either the /v1 root or the full /v1/chat/completions URL works, e.g. https://router.huggingface.co/v1 or http://10.0.0.50:11434/v1. Also read from TOPOTRACE_AI_BASE_URL.")

		slackWebhookURL = flag.String("slack-webhook-url", os.Getenv("TOPOTRACE_SLACK_WEBHOOK_URL"), "Slack incoming-webhook URL to post every notable event to (policy/software violations, remediations, resolutions). Also read from TOPOTRACE_SLACK_WEBHOOK_URL.")
		teamsWebhookURL = flag.String("teams-webhook-url", os.Getenv("TOPOTRACE_TEAMS_WEBHOOK_URL"), "Microsoft Teams incoming-webhook / Workflows URL to post every notable event to as an Adaptive Card. Also read from TOPOTRACE_TEAMS_WEBHOOK_URL.")
		jiraURL         = flag.String("jira-url", os.Getenv("TOPOTRACE_JIRA_URL"), "Jira Cloud base URL (e.g. https://yourteam.atlassian.net) to open one issue per policy/software violation or proposed remediation in. Requires -jira-email, -jira-token, -jira-project. Also read from TOPOTRACE_JIRA_URL.")
		jiraEmail       = flag.String("jira-email", os.Getenv("TOPOTRACE_JIRA_EMAIL"), "Atlassian account email for -jira-url (basic auth with the API token). Also read from TOPOTRACE_JIRA_EMAIL.")
		jiraToken       = flag.String("jira-token", os.Getenv("TOPOTRACE_JIRA_TOKEN"), "Atlassian API token for -jira-url. Also read from TOPOTRACE_JIRA_TOKEN.")
		jiraProject     = flag.String("jira-project", os.Getenv("TOPOTRACE_JIRA_PROJECT"), "Jira project key to create issues in (e.g. OPS). Also read from TOPOTRACE_JIRA_PROJECT.")
		jiraIssueType   = flag.String("jira-issue-type", os.Getenv("TOPOTRACE_JIRA_ISSUE_TYPE"), "Jira issue type name (default Task). Also read from TOPOTRACE_JIRA_ISSUE_TYPE.")
		snowURL         = flag.String("servicenow-url", os.Getenv("TOPOTRACE_SERVICENOW_URL"), "ServiceNow instance URL (e.g. https://dev12345.service-now.com) to open one incident per policy/software violation or proposed remediation in. Requires -servicenow-user and -servicenow-password. Also read from TOPOTRACE_SERVICENOW_URL.")
		snowUser        = flag.String("servicenow-user", os.Getenv("TOPOTRACE_SERVICENOW_USER"), "ServiceNow basic-auth user for -servicenow-url. Also read from TOPOTRACE_SERVICENOW_USER.")
		snowPassword    = flag.String("servicenow-password", os.Getenv("TOPOTRACE_SERVICENOW_PASSWORD"), "ServiceNow basic-auth password for -servicenow-url. Also read from TOPOTRACE_SERVICENOW_PASSWORD.")

		pluginDir = flag.String("plugin-dir", os.Getenv("TOPOTRACE_PLUGIN_DIR"), "directory of out-of-process plugin executables to load at startup (internal/pluginhost, docs/plugins.md). Empty (default) disables plugins entirely. Also read from TOPOTRACE_PLUGIN_DIR.")

		publicStatus = flag.Bool("public-status", true, "serve an unauthenticated aggregate-only status page at /status (and /status.json): host count, percent compliant, average scores, open findings, which integrations are on. Never host names or findings. Set false to disable.")
		openWrites   = flag.Bool("sandbox-open-writes", false, "DEMO/SANDBOX ONLY. When -auth-token is empty, let admin-gated write endpoints (approvals, plan promotion, dynamic groups, exceptions, ...) succeed as a simulated write instead of refusing with a config error. Never combine with real data -- with -auth-token empty this leaves every write endpoint open to any caller.")
		hibpAPIKey   = flag.String("hibp-api-key", os.Getenv("TOPOTRACE_HIBP_API_KEY"), "Have I Been Pwned API key for account-level breach exposure lookups (GET /api/breaches?domain=). Without it, only the public breaches-of-a-domain lookup works. Also read from TOPOTRACE_HIBP_API_KEY.")

		siemBackend  = flag.String("siem-backend", os.Getenv("TOPOTRACE_SIEM_BACKEND"), "which SIEM the -siem-hec-* URL/token point at: splunk-hec (default), sumo-http (a Sumo Logic HTTP Logs Source URL, token optional) or logrhythm-webhook (a LogRhythm Open Collector webhook URL, token optional). Also read from TOPOTRACE_SIEM_BACKEND.")
		siemHECURL   = flag.String("siem-hec-url", os.Getenv("TOPOTRACE_SIEM_HEC_URL"), "Splunk HTTP Event Collector base URL (e.g. https://splunk.example.com:8088) to forward every audit-log entry to, via internal/siemforward. Leave both -siem-hec-* flags empty to disable SIEM forwarding entirely. Also read from TOPOTRACE_SIEM_HEC_URL.")
		siemHECToken = flag.String("siem-hec-token", os.Getenv("TOPOTRACE_SIEM_HEC_TOKEN"), "Splunk HEC token, sent as \"Authorization: Splunk <token>\". Required once -siem-hec-url is set. Also read from TOPOTRACE_SIEM_HEC_TOKEN.")
	)
	flag.Parse()

	if *authToken != "" && !validAuthToken.MatchString(*authToken) {
		fmt.Fprintln(os.Stderr, "invalid -auth-token: must be 1-128 chars of letters, digits, '.', '_', '-' only (the same charset the wire protocol already restricts every other token-like field to)")
		os.Exit(1)
	}

	// logLevelVar backs -log-level and PATCH /api/settings's log_level
	// field alike (see api.Server.LogLevel): a *slog.LevelVar embedded
	// in the handler's options, so changing it later re-levels every
	// logger derived from this one immediately, no restart. Applied a
	// second time below, after -log-level has had a chance to pick up
	// a saved dashboard override -- see that block's comment.
	var logLevelVar slog.LevelVar
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &logLevelVar}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rawDir := *dataDir + "/raw"

	// overridesPath is where PATCH /api/settings persists live edits to
	// SIEM forwarding and Ask TopoTrace (see internal/settingsstore) so
	// they survive a restart. Loaded here, once, before either
	// integration is wired up below -- an override only fills in a
	// value whose flag/env var was left empty; an explicit -siem-hec-*
	// / -ai-api-key (or its env var) always wins, so a value pinned at
	// the process level can't be silently overridden by something
	// saved from the dashboard in an earlier run.
	overridesPath := *dataDir + "/settings-overrides.json"
	overrides, err := settingsstore.Load(overridesPath)
	if err != nil {
		logger.Warn("loading settings overrides, starting with none", "path", overridesPath, "err", err)
	}

	// Persist-for-next-restart fallback defaults (see
	// internal/settingsstore's doc comment): for each of these fields,
	// if the flag/env var was left at its built-in zero value, and the
	// override saved from the dashboard has a non-empty value, use the
	// override instead. An explicit -flag or env var always wins --
	// this only fills in what wasn't set at the process level.
	if *ingestAddr == ":9090" && overrides.IngestAddr != "" {
		*ingestAddr = overrides.IngestAddr
	}
	if *apiAddr == ":8080" && overrides.APIAddr != "" {
		*apiAddr = overrides.APIAddr
	}
	if *evalInterval == 5*time.Minute && overrides.EvaluatorInterval != "" {
		if d, err := time.ParseDuration(overrides.EvaluatorInterval); err == nil {
			*evalInterval = d
		}
	}
	// vulnFeedOn is a bool flag: there is no way to distinguish
	// "explicitly set to false" from "never set", so the override is
	// only ever applied as a fallback when the flag is still at its
	// default false. Once the vuln feed is turned on from Settings,
	// turning it back off from Settings works fine (the override
	// simply goes back to false, which is also the flag's default).
	// But a saved "off" override can't be forced back on by a bare
	// -vuln-feed flag with no value -- that's a known, accepted
	// limitation of bool flags, not a bug.
	if !*vulnFeedOn && overrides.VulnFeedEnabled {
		*vulnFeedOn = true
	}
	if *vulnFeedInterval == 6*time.Hour && overrides.VulnFeedInterval != "" {
		if d, err := time.ParseDuration(overrides.VulnFeedInterval); err == nil {
			*vulnFeedInterval = d
		}
	}
	// OAuth is all-or-nothing (internal/oauth.NewConfig enforces this
	// for the flags already): the override group is applied only when
	// every current -oauth-* flag is empty, never partially merged
	// with flag-set fields.
	if *oauthClientID == "" && *oauthClientSecret == "" && *oauthAuthURL == "" && *oauthTokenURL == "" &&
		*oauthUserInfoURL == "" && *oauthRedirectURL == "" && *oauthScopes == "" && *oauthRoleMap == "" &&
		overrides.OAuthClientID != "" {
		*oauthClientID = overrides.OAuthClientID
		*oauthClientSecret = overrides.OAuthClientSecret
		*oauthAuthURL = overrides.OAuthAuthURL
		*oauthTokenURL = overrides.OAuthTokenURL
		*oauthUserInfoURL = overrides.OAuthUserInfoURL
		*oauthRedirectURL = overrides.OAuthRedirectURL
		*oauthScopes = overrides.OAuthScopes
		*oauthRoleMap = overrides.OAuthRoleMap
		logger.Info("OAuth: using settings saved from the dashboard (no -oauth-* flags set)")
	}
	// AD/LDAP -- same all-or-nothing fallback shape as OAuth above.
	if *ldapHost == "" && *ldapBindDN == "" && *ldapBindPassword == "" && *ldapUserBaseDN == "" &&
		*ldapUserAttr == "" && *ldapMailAttr == "" && *ldapGroupAttr == "" && *ldapRoleMap == "" &&
		overrides.LDAPHost != "" {
		*ldapHost = overrides.LDAPHost
		if p, err := strconv.Atoi(overrides.LDAPPort); err == nil {
			*ldapPort = p
		}
		*ldapUseTLS = overrides.LDAPUseTLS
		*ldapBindDN = overrides.LDAPBindDN
		*ldapBindPassword = overrides.LDAPBindPassword
		*ldapUserBaseDN = overrides.LDAPUserBaseDN
		*ldapUserAttr = overrides.LDAPUserAttr
		*ldapMailAttr = overrides.LDAPMailAttr
		*ldapGroupAttr = overrides.LDAPGroupAttr
		*ldapRoleMap = overrides.LDAPRoleMap
		logger.Info("AD/LDAP: using settings saved from the dashboard (no -ldap-* flags set)")
	}
	// SAML -- same all-or-nothing fallback shape as OAuth above.
	if *samlEntityID == "" && *samlACSURL == "" && *samlIdPSSOURL == "" && *samlIdPCert == "" && *samlRoleMap == "" &&
		overrides.SAMLEntityID != "" {
		*samlEntityID = overrides.SAMLEntityID
		*samlACSURL = overrides.SAMLACSURL
		*samlIdPSSOURL = overrides.SAMLIdPSSOURL
		*samlIdPCert = overrides.SAMLIdPCert
		*samlRoleMap = overrides.SAMLRoleMap
		logger.Info("SAML: using settings saved from the dashboard (no -saml-* flags set)")
	}
	// TOTP/MFA -- independent fields, not all-or-nothing (see the PATCH
	// handler's doc comment): each only falls back to its saved
	// override when the matching flag is still at its built-in default.
	if !*mfaRequired && overrides.MFARequired {
		*mfaRequired = true
	}
	if *mfaRoles == "" && overrides.MFARoles != "" {
		*mfaRoles = overrides.MFARoles
	}
	if *mfaGraceDays == 3 && overrides.MFAGraceDays != "" {
		if d, err := strconv.Atoi(overrides.MFAGraceDays); err == nil {
			*mfaGraceDays = d
		}
	}
	if *mfaIssuer == "" && overrides.MFAIssuer != "" {
		*mfaIssuer = overrides.MFAIssuer
	}
	if *logLevel == "" && overrides.LogLevel != "" {
		*logLevel = overrides.LogLevel
	}
	if *logLevel != "" {
		level, err := api.ParseLogLevel(*logLevel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -log-level %q: %v\n", *logLevel, err)
			os.Exit(1)
		}
		logLevelVar.Set(level)
	}
	if *webhookURLs == "" && overrides.WebhookURLs != "" {
		*webhookURLs = overrides.WebhookURLs
	}
	if *slackWebhookURL == "" && overrides.SlackWebhookURL != "" {
		*slackWebhookURL = overrides.SlackWebhookURL
	}
	if *teamsWebhookURL == "" && overrides.TeamsWebhookURL != "" {
		*teamsWebhookURL = overrides.TeamsWebhookURL
	}
	if *jiraURL == "" && overrides.JiraURL != "" {
		*jiraURL = overrides.JiraURL
		*jiraEmail = overrides.JiraEmail
		*jiraToken = overrides.JiraToken
		*jiraProject = overrides.JiraProject
		*jiraIssueType = overrides.JiraIssueType
	}
	if *snowURL == "" && overrides.ServiceNowURL != "" {
		*snowURL = overrides.ServiceNowURL
		*snowUser = overrides.ServiceNowUser
		*snowPassword = overrides.ServiceNowPassword
	}

	var st store.Store
	var storageBackend string
	if *postgresDSN != "" {
		pg, err := pgstore.New(ctx, *postgresDSN)
		if err != nil {
			logger.Error("opening postgres store", "err", err)
			os.Exit(1)
		}
		defer pg.Close()
		st = pg
		storageBackend = "postgres"
		logger.Info("store backend: postgres")
	} else {
		mem, err := memstore.New(*dataDir + "/topotrace.json")
		if err != nil {
			logger.Error("opening memstore", "err", err)
			os.Exit(1)
		}
		st = mem
		storageBackend = "memstore"
		logger.Info("store backend: memstore (in-memory, JSON snapshot)", "path", *dataDir+"/topotrace.json")
	}

	// SIEM forwarding (internal/siemforward) is opt-in and all-or-
	// nothing for the flags/env vars (both -siem-hec-* set, or
	// neither); a value saved later from the dashboard can still turn
	// it on with no restart, which is why siemDynamic is always
	// constructed and always wrapped around st below, even when
	// starting disabled -- see internal/siemforward.Dynamic's doc
	// comment.
	resolvedSIEMURL, resolvedSIEMToken, resolvedSIEMBackend := *siemHECURL, *siemHECToken, *siemBackend
	if resolvedSIEMURL == "" && resolvedSIEMToken == "" && overrides.SIEMHECURL != "" {
		resolvedSIEMURL, resolvedSIEMToken, resolvedSIEMBackend = overrides.SIEMHECURL, overrides.SIEMHECToken, overrides.SIEMBackend
		logger.Info("SIEM forwarding: using settings saved from the dashboard (no -siem-hec-* flag set)")
	}
	if resolvedSIEMBackend == "" {
		resolvedSIEMBackend = "splunk-hec"
	}
	// Splunk HEC needs both URL and token; the other backends carry the
	// credential in the URL and may omit the token.
	if resolvedSIEMBackend == "splunk-hec" && (resolvedSIEMURL == "") != (resolvedSIEMToken == "") {
		fmt.Fprintln(os.Stderr, "siem forwarding partially configured -- splunk-hec needs both -siem-hec-url and -siem-hec-token")
		os.Exit(1)
	}
	siemDynamic := siemforward.NewDynamic()
	if resolvedSIEMURL != "" {
		if err := siemDynamic.Set(resolvedSIEMBackend, resolvedSIEMURL, resolvedSIEMToken); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		logger.Info("SIEM forwarding enabled", "backend", siemDynamic.Backend(), "url", resolvedSIEMURL)
	}
	st = siemforward.WrapStore(st, siemDynamic, logger.With("component", "siemforward"))

	pipeline := &cook.Pipeline{RawBaseDir: rawDir, Store: st}

	ingestSrv := &ingest.Server{
		Addr:       *ingestAddr,
		RawBaseDir: rawDir,
		Pipeline:   pipeline,
		Logger:     logger.With("component", "ingest"),
		Token:      *authToken,
	}

	// One HTTP server, one mux: the JSON API under /api (and /healthz),
	// and the web dashboard (internal/webui, embedded static assets)
	// serving everything else. Same port, so there's exactly one address
	// to open in a browser.
	webHandler, err := webui.Handler()
	if err != nil {
		logger.Error("loading web UI assets", "err", err)
		os.Exit(1)
	}
	// Outbound notifications (internal/webhook): generic webhook URLs
	// plus Slack, Teams, Jira and ServiceNow sinks, all through one
	// durable, store-backed queue with retries -- see that package.
	// Every sink is optional; the Dispatcher is a safe no-op with none.
	var sinks []webhook.Sink
	httpClient := &http.Client{Timeout: 10 * time.Second}
	for _, u := range strings.Split(*webhookURLs, ",") {
		if u = strings.TrimSpace(u); u != "" {
			sinks = append(sinks, &webhook.URLSink{URL: u, Client: httpClient})
		}
	}
	if *slackWebhookURL != "" {
		sinks = append(sinks, &webhook.SlackSink{WebhookURL: *slackWebhookURL, Client: httpClient})
	}
	if *teamsWebhookURL != "" {
		sinks = append(sinks, &webhook.TeamsSink{WebhookURL: *teamsWebhookURL, Client: httpClient})
	}
	if *jiraURL != "" {
		if *jiraEmail == "" || *jiraToken == "" || *jiraProject == "" {
			fmt.Fprintln(os.Stderr, "jira partially configured -- -jira-url needs -jira-email, -jira-token and -jira-project")
			os.Exit(1)
		}
		sinks = append(sinks, &webhook.JiraSink{BaseURL: *jiraURL, Email: *jiraEmail, APIToken: *jiraToken, Project: *jiraProject, IssueType: *jiraIssueType, Events: webhook.TicketEvents, Client: httpClient})
	}
	if *snowURL != "" {
		if *snowUser == "" || *snowPassword == "" {
			fmt.Fprintln(os.Stderr, "servicenow partially configured -- -servicenow-url needs -servicenow-user and -servicenow-password")
			os.Exit(1)
		}
		sinks = append(sinks, &webhook.ServiceNowSink{InstanceURL: *snowURL, User: *snowUser, Password: *snowPassword, Events: webhook.TicketEvents, Client: httpClient})
	}
	hooks := webhook.NewWithSinks(sinks, st, logger.With("component", "notify"))
	if len(sinks) > 0 {
		logger.Info("notification sinks configured", "sinks", hooks.SinkNames())
	}

	var vulnFeed *vuln.Feed
	if *vulnFeedOn {
		vulnFeed = vuln.NewFeed(logger.With("component", "vuln-feed"))
		logger.Info("vuln feed enabled", "source", "osv.dev", "interval", vulnFeedInterval.String(), "watchlist_size", len(vuln.Watchlist))
	}

	// OAuth2/OIDC dashboard login (internal/oauth) is entirely opt-in:
	// NewConfig returns (nil, nil) when every -oauth-* flag is empty,
	// so oauthCfg stays nil and requireRole/requireRoleStrict simply
	// never find a session cookie to check. See docs/security-model.md.
	oauthCfg, err := oauth.NewConfig(*oauthClientID, *oauthClientSecret, *oauthAuthURL, *oauthTokenURL, *oauthUserInfoURL, *oauthRedirectURL, *oauthScopes, *oauthRoleMap)
	if err != nil {
		logger.Error("invalid -oauth-* flags", "err", err)
		os.Exit(1)
	}

	// AD/LDAP dashboard login (internal/ldap) -- same opt-in shape as
	// OAuth above.
	ldapCfg, err := ldap.NewConfig(*ldapHost, *ldapPort, *ldapUseTLS, *ldapBindDN, *ldapBindPassword, *ldapUserBaseDN, *ldapUserAttr, *ldapMailAttr, *ldapGroupAttr, *ldapRoleMap)
	if err != nil {
		logger.Error("invalid -ldap-* flags", "err", err)
		os.Exit(1)
	}
	if ldapCfg != nil {
		logger.Info("AD/LDAP dashboard login enabled", "host", *ldapHost, "user_base_dn", *ldapUserBaseDN)
	}

	// SAML 2.0 SSO dashboard login (internal/saml) -- same opt-in shape
	// as OAuth above.
	samlCfg, err := saml.NewConfig(*samlEntityID, *samlACSURL, *samlIdPSSOURL, *samlIdPCert, *samlRoleMap)
	if err != nil {
		logger.Error("invalid -saml-* flags", "err", err)
		os.Exit(1)
	}
	if samlCfg != nil {
		logger.Info("SAML SSO dashboard login enabled", "idp_sso_url", *samlIdPSSOURL, "entity_id", *samlEntityID)
	}

	var sessions *oauth.SessionStore
	if oauthCfg != nil || ldapCfg != nil || samlCfg != nil {
		sessions = oauth.NewSessionStore()
		sessions.IdleTimeout = *sessionIdleTimeout
		sessions.MaxConcurrent = *sessionMaxConcurrent
	}
	if oauthCfg != nil {
		logger.Info("OAuth dashboard login enabled", "auth_url", *oauthAuthURL)
	}

	mux := http.NewServeMux()

	// Ask TopoTrace (internal/aiquery), like SIEM forwarding above, is
	// opt-in via flag/env var but resolves against a saved dashboard
	// override when the flag was left empty -- see the SIEM block's
	// comment for why flag/env always wins. Held in a ConfigStore (not
	// a plain Config) so PATCH /api/settings can change or disable it
	// on a running server with no restart.
	//
	// "Was it configured by flag?" is now a question about the whole
	// config rather than just the key: the openai-compatible backend is
	// configured by URL and often carries no credential at all (a local
	// Ollama or LM Studio is typically unauthenticated), so testing the
	// key alone would wrongly fall through to the saved override.
	aiCfg := aiquery.Config{APIKey: *aiAPIKey, Model: *aiModel, Backend: *aiBackend, BaseURL: *aiBaseURL}
	if !aiCfg.Enabled() && (overrides.AIAPIKey != "" || overrides.AIBaseURL != "") {
		aiCfg = aiquery.Config{APIKey: overrides.AIAPIKey, Model: overrides.AIModel,
			Backend: overrides.AIBackend, BaseURL: overrides.AIBaseURL}
		logger.Info("Ask TopoTrace: using settings saved from the dashboard (no -ai-api-key / -ai-base-url flag set)")
	}
	aiCfgStore := aiquery.NewConfigStore(aiCfg)
	if aiCfg.Enabled() {
		model := aiCfg.Model
		if model == "" {
			model = "(default)"
		}
		args := []any{"backend", aiCfg.Normalized().Backend, "model", model}
		if aiCfg.BaseURL != "" {
			args = append(args, "base_url", aiCfg.BaseURL)
		}
		logger.Info("Ask TopoTrace (AI query) enabled", args...)
	}
	apiSrv := &api.Server{
		Store: st, Logger: logger.With("component", "api"), AuthToken: *authToken, OpenWrites: *openWrites,
		Webhooks: hooks, VulnFeed: vulnFeed, Pipeline: pipeline, OAuth: oauthCfg, Sessions: sessions,
		LDAP: ldapCfg, SAML: samlCfg, LogLevel: &logLevelVar,
		SCIMToken:   *scimToken,
		MFAEnforced: *mfaRequired, MFAGraceDays: *mfaGraceDays, MFAIssuer: *mfaIssuer,
		LicensedSeats:        *licensedSeats,
		AIQuery:              aiCfgStore,
		StorageBackend:       storageBackend,
		IngestAddr:           *ingestAddr,
		APIAddr:              *apiAddr,
		EvaluatorInterval:    *evalInterval,
		VulnFeedInterval:     *vulnFeedInterval,
		SIEMForwarder:        siemDynamic,
		SettingsOverridePath: overridesPath,
		Breach:               breach.New(*hibpAPIKey),
		PublicStatus:         *publicStatus,
		PluginDir:            *pluginDir,
	}
	if *mfaRoles != "" {
		for _, r := range strings.Split(*mfaRoles, ",") {
			if r = strings.TrimSpace(r); r != "" {
				apiSrv.MFARequiredRoles = append(apiSrv.MFARequiredRoles, r)
			}
		}
	}
	pluginMgr := pluginhost.NewManager(*pluginDir, logger.With("component", "pluginhost"))
	pluginMgr.Load(ctx)
	defer pluginMgr.Shutdown()
	apiSrv.Plugins = pluginMgr

	api.StartedAt = time.Now().UTC()
	apiSrv.Register(mux)
	if *openWrites {
		// The sandbox overlay fires tracking beacons at these two paths
		// purely so Caddy's access log captures them -- there was never a
		// real endpoint behind them, which meant every click/feedback event
		// showed up as a 404 in the browser console and any uptime/error
		// monitoring watching this box. Register them explicitly so they
		// resolve as the no-op they actually are.
		beaconNoop := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
		mux.HandleFunc("/__sandbox_click", beaconNoop)
		mux.HandleFunc("/__sandbox_feedback", beaconNoop)
	}
	mux.Handle("/", webHandler)

	eval := &evaluator.Evaluator{Store: st, Webhooks: hooks, VulnFeed: vulnFeed, Log: logger.With("component", "evaluator"), Interval: *evalInterval}

	httpSrv := &http.Server{Addr: *apiAddr, Handler: httpLogger(logger.With("component", "http"), mux)}

	var wg sync.WaitGroup
	errs := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		eval.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		hooks.Run(ctx)
	}()

	if vulnFeed != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulnFeed.Run(ctx, *vulnFeedInterval)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ingestSrv.ListenAndServe(ctx); err != nil {
			errs <- fmt.Errorf("ingest: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("api listening", "addr", *apiAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("api: %w", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	select {
	case err := <-errs:
		logger.Error("fatal", "err", err)
		stop()
		wg.Wait()
		os.Exit(1)
	case <-ctx.Done():
		wg.Wait()
	}
}

func httpLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
