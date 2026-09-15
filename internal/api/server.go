// Package api is Muster's read side: a small REST API over whatever the
// cook pipeline has stored, using only net/http (Go 1.22+'s pattern-based
// ServeMux is enough for a handful of routes -- no router dependency
// needed).
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"muster/internal/model"
	"muster/internal/store"
)

type Server struct {
	Store  store.Store
	Logger *slog.Logger
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
	mux.HandleFunc("GET /api/hosts", s.handleListHosts)
	mux.HandleFunc("GET /api/hosts/{host}", s.handleGetHost)
	mux.HandleFunc("PATCH /api/hosts/{host}", s.handlePatchHost)
	mux.HandleFunc("GET /api/hosts/{host}/facts/{category}", s.handleGetFact)
	mux.HandleFunc("GET /api/hosts/{host}/changes", s.handleListChanges)
	mux.HandleFunc("GET /api/query", s.handleQuery)
}

// Handler returns a standalone, logged handler for just the API -- used
// by tests and anything that wants the API on its own mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Register(mux)
	return logMiddleware(s.log(), mux)
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

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	s.writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
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
	s.writeJSON(w, http.StatusOK, host)
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

func logMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
