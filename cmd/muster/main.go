// Command muster runs the Muster server: the TCP ingest daemon and the
// HTTP reporting API, side by side in one process, sharing one store.
//
//	go run ./cmd/muster
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

	"muster/internal/aiquery"
	"muster/internal/api"
	"muster/internal/cook"
	"muster/internal/evaluator"
	"muster/internal/ingest"
	"muster/internal/oauth"
	"muster/internal/store"
	"muster/internal/store/memstore"
	"muster/internal/store/pgstore"
	"muster/internal/vuln"
	"muster/internal/webhook"
	"muster/internal/webui"
)

// validAuthToken matches the same safe-token charset the wire protocol
// already enforces on every other field (internal/ingest.isSafeToken) --
// checked again here, at startup, so a bad -auth-token fails fast with a
// clear message instead of quietly locking every agent out at runtime.
var validAuthToken = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func main() {
	var (
		ingestAddr  = flag.String("ingest-addr", ":9090", "address for the TCP ingest daemon")
		apiAddr     = flag.String("api-addr", ":8080", "address for the HTTP reporting API")
		dataDir     = flag.String("data-dir", "./data", "base directory for raw packets and the memstore snapshot (ignored when -postgres-dsn is set)")
		postgresDSN = flag.String("postgres-dsn", os.Getenv("MUSTER_POSTGRES_DSN"), "Postgres connection string (e.g. postgres://user:pass@host:5432/muster?sslmode=disable); if set, facts are stored in Postgres instead of the in-memory/JSON-snapshot store. Also read from MUSTER_POSTGRES_DSN.")
		authToken   = flag.String("auth-token", os.Getenv("MUSTER_AUTH_TOKEN"), "shared secret required from agents (MUSTER1/MUSTER1-RESULT) and for API writes (PATCH /api/hosts, POST .../actions). Letters, digits, '.', '_', '-' only, 1-128 chars. Empty disables auth entirely and leaves remediation actions unavailable. Also read from MUSTER_AUTH_TOKEN. This token always resolves to the 'admin' role, so it can bootstrap named API keys (see -h for the /api/keys endpoints).")
		webhookURLs = flag.String("webhook-url", os.Getenv("MUSTER_WEBHOOK_URLS"), "comma-separated URLs to POST a small JSON event to on policy violations and remediation (host_new/host_stale/policy_violation/remediation_executed). Empty disables webhooks. Also read from MUSTER_WEBHOOK_URLS.")
		evalInterval = flag.Duration("evaluator-interval", 5*time.Minute, "how often the background evaluator re-checks every host against every persisted policy rule (posture scoring, auto-remediation). Has no effect until at least one rule exists (POST /api/policies).")
		vulnFeedOn   = flag.Bool("vuln-feed", false, "supplement internal/vuln's static CVE dataset with live lookups from OSV.dev (https://osv.dev, free, no API key) for the packages in vuln.Watchlist. Off by default -- turning it on means this server makes outbound HTTPS requests to api.osv.dev on -vuln-feed-interval.")
		vulnFeedInterval = flag.Duration("vuln-feed-interval", 6*time.Hour, "how often -vuln-feed re-queries OSV.dev. Ignored when -vuln-feed is false.")

		oauthClientID     = flag.String("oauth-client-id", os.Getenv("MUSTER_OAUTH_CLIENT_ID"), "OAuth2 client ID for dashboard login. Leave every -oauth-* flag empty to disable browser login entirely (bearer tokens still work). Also read from MUSTER_OAUTH_CLIENT_ID.")
		oauthClientSecret = flag.String("oauth-client-secret", os.Getenv("MUSTER_OAUTH_CLIENT_SECRET"), "OAuth2 client secret for dashboard login. Also read from MUSTER_OAUTH_CLIENT_SECRET.")
		oauthAuthURL      = flag.String("oauth-auth-url", os.Getenv("MUSTER_OAUTH_AUTH_URL"), "identity provider's authorization endpoint (e.g. https://accounts.google.com/o/oauth2/v2/auth). Also read from MUSTER_OAUTH_AUTH_URL.")
		oauthTokenURL     = flag.String("oauth-token-url", os.Getenv("MUSTER_OAUTH_TOKEN_URL"), "identity provider's token endpoint (e.g. https://oauth2.googleapis.com/token). Also read from MUSTER_OAUTH_TOKEN_URL.")
		oauthUserInfoURL  = flag.String("oauth-userinfo-url", os.Getenv("MUSTER_OAUTH_USERINFO_URL"), "identity provider's OIDC UserInfo endpoint (e.g. https://openidconnect.googleapis.com/v1/userinfo) -- see internal/oauth's doc comment for why this is used instead of parsing an ID token. Also read from MUSTER_OAUTH_USERINFO_URL.")
		oauthRedirectURL  = flag.String("oauth-redirect-url", os.Getenv("MUSTER_OAUTH_REDIRECT_URL"), "this server's own callback URL as registered with the identity provider (e.g. http://localhost:8080/api/auth/callback). Also read from MUSTER_OAUTH_REDIRECT_URL.")
		oauthScopes       = flag.String("oauth-scopes", os.Getenv("MUSTER_OAUTH_SCOPES"), "space-separated OAuth2 scopes to request. Defaults to \"openid email profile\" when empty. Also read from MUSTER_OAUTH_SCOPES.")
		oauthRoleMap      = flag.String("oauth-role-map", os.Getenv("MUSTER_OAUTH_ROLE_MAP"), "comma-separated email/domain-to-role mappings, checked in order, e.g. \"admin@example.com=admin,*@example.com=readonly\". Required (and the whole -oauth-* group required) once any -oauth-* flag is set. Also read from MUSTER_OAUTH_ROLE_MAP.")

		aiAPIKey = flag.String("ai-api-key", os.Getenv("MUSTER_AI_API_KEY"), "Anthropic API key for \"Ask Muster\" (POST /api/ask), a natural-language query surface over the fleet data with every question+answer recorded to the audit log. Empty disables the endpoint (it answers with a clear 'not configured' error). Also read from MUSTER_AI_API_KEY.")
		aiModel  = flag.String("ai-model", os.Getenv("MUSTER_AI_MODEL"), "Anthropic model id Ask Muster calls (e.g. claude-opus-5). Empty uses internal/aiquery's built-in default. Also read from MUSTER_AI_MODEL.")
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

	var st store.Store
	if *postgresDSN != "" {
		pg, err := pgstore.New(ctx, *postgresDSN)
		if err != nil {
			logger.Error("opening postgres store", "err", err)
			os.Exit(1)
		}
		defer pg.Close()
		st = pg
		logger.Info("store backend: postgres")
	} else {
		mem, err := memstore.New(*dataDir + "/muster.json")
		if err != nil {
			logger.Error("opening memstore", "err", err)
			os.Exit(1)
		}
		st = mem
		logger.Info("store backend: memstore (in-memory, JSON snapshot)", "path", *dataDir+"/muster.json")
	}

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
	var hookURLs []string
	for _, u := range strings.Split(*webhookURLs, ",") {
		if u = strings.TrimSpace(u); u != "" {
			hookURLs = append(hookURLs, u)
		}
	}
	hooks := webhook.New(hookURLs, logger.With("component", "webhook"))
	if len(hookURLs) > 0 {
		logger.Info("webhooks configured", "count", len(hookURLs))
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
	if *aiAPIKey != "" {
		model := *aiModel
		if model == "" {
			model = "(default)"
		}
		logger.Info("Ask Muster (AI query) enabled", "model", model)
	}
	apiSrv := &api.Server{Store: st, Logger: logger.With("component", "api"), AuthToken: *authToken, Webhooks: hooks, VulnFeed: vulnFeed, Pipeline: pipeline, OAuth: oauthCfg, Sessions: sessions, AIQuery: aiquery.Config{APIKey: *aiAPIKey, Model: *aiModel}}
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
