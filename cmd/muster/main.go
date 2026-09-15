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
	"sync"
	"syscall"
	"time"

	"muster/internal/api"
	"muster/internal/cook"
	"muster/internal/ingest"
	"muster/internal/store"
	"muster/internal/store/memstore"
	"muster/internal/store/pgstore"
	"muster/internal/webui"
)

func main() {
	var (
		ingestAddr  = flag.String("ingest-addr", ":9090", "address for the TCP ingest daemon")
		apiAddr     = flag.String("api-addr", ":8080", "address for the HTTP reporting API")
		dataDir     = flag.String("data-dir", "./data", "base directory for raw packets and the memstore snapshot (ignored when -postgres-dsn is set)")
		postgresDSN = flag.String("postgres-dsn", os.Getenv("MUSTER_POSTGRES_DSN"), "Postgres connection string (e.g. postgres://user:pass@host:5432/muster?sslmode=disable); if set, facts are stored in Postgres instead of the in-memory/JSON-snapshot store. Also read from MUSTER_POSTGRES_DSN.")
	)
	flag.Parse()

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
	mux := http.NewServeMux()
	apiSrv := &api.Server{Store: st, Logger: logger.With("component", "api")}
	apiSrv.Register(mux)
	mux.Handle("/", webHandler)

	httpSrv := &http.Server{Addr: *apiAddr, Handler: httpLogger(logger.With("component", "http"), mux)}

	var wg sync.WaitGroup
	errs := make(chan error, 2)

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
