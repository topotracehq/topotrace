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
	"topotrace/internal/oauth"
	"topotrace/internal/pluginhost"
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

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
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
	var sessions *oauth.SessionStore
	if oauthCfg != nil {
		sessions = oauth.NewSessionStore()
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
		Store: st, Logger: logger.With("component", "api"), AuthToken: *authToken,
		Webhooks: hooks, VulnFeed: vulnFeed, Pipeline: pipeline, OAuth: oauthCfg, Sessions: sessions,
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
	pluginMgr := pluginhost.NewManager(*pluginDir, logger.With("component", "pluginhost"))
	pluginMgr.Load(ctx)
	defer pluginMgr.Shutdown()
	apiSrv.Plugins = pluginMgr

	api.StartedAt = time.Now().UTC()
	apiSrv.Register(mux)
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
