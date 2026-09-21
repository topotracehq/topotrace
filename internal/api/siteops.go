/*******************************************************************************
 * @file         siteops.go
 * @brief        Part of the TopoTrace api module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"muster/internal/operations"
	"muster/internal/siteops"
)

func (s *Server) registerSiteOps(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/sites", s.handleSites)
	mux.HandleFunc("POST /api/sites/workers", s.handleCreateWorker)
	mux.HandleFunc("DELETE /api/sites/workers/{id}", s.handleDeleteWorker)
	mux.HandleFunc("POST /api/sites/jobs", s.handleCreateSiteJob)
	mux.HandleFunc("POST /api/sites/jobs/{id}/{decision}", s.handleSiteDecision)
	mux.HandleFunc("PUT /api/sites/assets/{id}", s.handleSiteReview)
	mux.HandleFunc("POST /api/worker/poll", s.handleWorkerPoll)
	mux.HandleFunc("POST /api/worker/results/{id}", s.handleWorkerResult)
}
func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.unscopedAdmin(w, r); !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	workers, e := operations.List[siteops.Worker](r.Context(), s.Store, siteops.WorkerKind)
	if e != nil {
		s.writeError(w, 500, "loading workers")
		return
	}
	for i := range workers {
		workers[i].TokenHash = ""
	}
	jobs, e := operations.List[siteops.Job](r.Context(), s.Store, siteops.JobKind)
	if e != nil {
		s.writeError(w, 500, "loading jobs")
		return
	}
	for i := range jobs {
		if e = s.refreshSiteJob(r, &jobs[i]); e != nil {
			s.writeError(w, 500, "refreshing job")
			return
		}
		jobs[i].Lease = ""
	}
	assets, e := operations.List[siteops.Sighting](r.Context(), s.Store, siteops.SightingKind)
	if e != nil {
		s.writeError(w, 500, "loading assets")
		return
	}
	s.writeJSON(w, 200, map[string]any{"workers": workers, "jobs": jobs, "assets": assets})
}
func (s *Server) handleCreateWorker(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.unscopedAdmin(w, r)
	if !ok {
		return
	}
	var b struct {
		Name string `json:"name"`
	}
	if !s.workflowBody(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Name) == "" || len(b.Name) > 100 {
		s.writeError(w, 400, "name required (100 characters maximum)")
		return
	}
	token, e := randomToken()
	if e != nil {
		s.writeError(w, 500, "generating credential")
		return
	}
	v := siteops.Worker{ID: operations.ID(), Name: b.Name, TokenHash: sha256Hex(token)}
	if e = operations.Save(r.Context(), s.Store, siteops.WorkerKind, v.ID, v); e != nil {
		s.writeError(w, 500, "saving worker")
		return
	}
	s.Store.RecordAudit(r.Context(), actor, "create-site-worker", v.ID, v.Name)
	s.writeJSON(w, 201, map[string]string{"id": v.ID, "token": token, "name": v.Name})
}
func (s *Server) handleDeleteWorker(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.unscopedAdmin(w, r); !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if e := s.Store.DeleteDocument(r.Context(), siteops.WorkerKind, r.PathValue("id")); e != nil {
		s.writeError(w, 500, "revoking worker")
		return
	}
	s.writeJSON(w, 200, map[string]bool{"revoked": true})
}
func (s *Server) handleCreateSiteJob(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.unscopedAdmin(w, r)
	if !ok {
		return
	}
	var j siteops.Job
	if !s.workflowBody(w, r, &j) {
		return
	}
	if e := j.Validate(); e != nil {
		s.writeError(w, 400, e.Error())
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	if _, ok, e := operations.Load[siteops.Worker](r.Context(), s.Store, siteops.WorkerKind, j.WorkerID); e != nil || !ok {
		s.writeError(w, 400, "worker not found")
		return
	}
	j.ID = operations.ID()
	existing, e := operations.List[siteops.Job](r.Context(), s.Store, siteops.JobKind)
	if e != nil {
		s.writeError(w, 500, "checking existing deployments")
		return
	}
	for _, other := range existing {
		if other.Kind != "deploy" {
			continue
		}
		for _, old := range other.Targets {
			if other.Phase == "cancelled" && old.EnrollmentID == "" {
				continue
			}
			for _, target := range j.Targets {
				if old.Host == target.Host || (other.WorkerID == j.WorkerID && old.Address == target.Address) {
					s.writeError(w, 409, "target already belongs to a deployment; review the original job")
					return
				}
			}
		}
	}
	j.CreatedAt = time.Now().UTC()
	j.Phase = "draft"
	j.Detail = ""
	j.Lease = ""
	j.LeaseUntil = time.Time{}
	j.NextRun = time.Time{}
	j.ActiveTarget = 0
	for i := range j.Targets {
		if _, ok, e := s.Store.GetHost(r.Context(), j.Targets[i].Host); e != nil || ok {
			s.writeError(w, 400, "target host already exists or could not be checked; deployment is for new enrollments")
			return
		}
		j.Targets[i] = siteops.Target{Address: j.Targets[i].Address, Host: j.Targets[i].Host, State: "pending"}
	}
	if e := operations.Save(r.Context(), s.Store, siteops.JobKind, j.ID, j); e != nil {
		s.writeError(w, 500, "saving job")
		return
	}
	s.Store.RecordAudit(r.Context(), actor, "draft-site-job", j.ID, j.Name)
	s.writeJSON(w, 201, j)
}
func (s *Server) refreshSiteJob(r *http.Request, j *siteops.Job) error {
	changed := false
	now := time.Now().UTC()
	if j.Lease != "" && now.After(j.LeaseUntil) {
		j.Phase = "uncertain"
		j.Detail = "Worker lease expired; inspect the target before any further installation"
		j.Lease = ""
		changed = true
	}
	for i := range j.Targets {
		t := &j.Targets[i]
		if t.State != "awaiting-report" {
			continue
		}
		enrollments, e := s.Store.ListEnrollments(r.Context())
		if e != nil {
			return e
		}
		for _, en := range enrollments {
			if en.ID == t.EnrollmentID && en.Status == "enrolled" {
				h, ok, e := s.Store.GetHost(r.Context(), t.Host)
				if e != nil {
					return e
				}
				if ok && h.LastCooked.After(t.StartedAt) {
					t.State = "complete"
					t.Detail = "Enrollment and first report verified"
					changed = true
				}
			}
		}
	}
	if j.Phase == "pilot" || j.Phase == "rollout" {
		limit := len(j.Targets)
		if j.Phase == "pilot" {
			limit = j.Pilot
		}
		done := true
		for _, t := range j.Targets[:limit] {
			if t.State != "complete" {
				done = false
			}
		}
		if done {
			if limit == len(j.Targets) {
				j.Phase = "complete"
			} else {
				j.Phase = "pilot-complete"
			}
			changed = true
		}
	}
	if changed {
		return operations.Save(r.Context(), s.Store, siteops.JobKind, j.ID, j)
	}
	return nil
}
func (s *Server) handleSiteDecision(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.unscopedAdmin(w, r)
	if !ok {
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	j, ok, e := operations.Load[siteops.Job](r.Context(), s.Store, siteops.JobKind, r.PathValue("id"))
	if e != nil || !ok {
		s.writeError(w, 404, "job not found")
		return
	}
	if e = s.refreshSiteJob(r, &j); e != nil {
		s.writeError(w, 500, "refreshing job")
		return
	}
	valid := false
	switch r.PathValue("decision") {
	case "preflight":
		if j.Kind == "deploy" && j.Phase == "draft" {
			j.Phase = "preflight"
			valid = true
		}
	case "start":
		if j.Kind == "scan" && j.Phase == "draft" {
			j.Phase = "queued"
			valid = true
		} else if j.Kind == "deploy" && j.Phase == "ready" {
			j.Phase = "pilot"
			valid = true
		}
	case "promote":
		if j.Phase == "pilot-complete" {
			j.Phase = "rollout"
			valid = true
		}
	case "cancel":
		if j.Lease == "" && j.Phase != "complete" {
			j.Phase = "cancelled"
			valid = true
		}
	}
	if !valid {
		s.writeError(w, 409, "decision not allowed in current phase; leased work cannot be cancelled mid-operation")
		return
	}
	if e = operations.Save(r.Context(), s.Store, siteops.JobKind, j.ID, j); e != nil {
		s.writeError(w, 500, "saving decision")
		return
	}
	s.Store.RecordAudit(r.Context(), actor, "site-job-"+r.PathValue("decision"), j.ID, j.Name)
	s.writeJSON(w, 200, j)
}
func (s *Server) handleSiteReview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.unscopedAdmin(w, r); !ok {
		return
	}
	var b struct {
		Review string `json:"review"`
	}
	if !s.workflowBody(w, r, &b) {
		return
	}
	if b.Review != "reviewed" && b.Review != "ignored" && b.Review != "new" {
		s.writeError(w, 400, "invalid review state")
		return
	}
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	a, ok, e := operations.Load[siteops.Sighting](r.Context(), s.Store, siteops.SightingKind, r.PathValue("id"))
	if e != nil || !ok {
		s.writeError(w, 404, "asset not found")
		return
	}
	a.Review = b.Review
	if e = operations.Save(r.Context(), s.Store, siteops.SightingKind, a.ID, a); e != nil {
		s.writeError(w, 500, "saving review")
		return
	}
	s.writeJSON(w, 200, a)
}
func (s *Server) workerAuth(w http.ResponseWriter, r *http.Request) (siteops.Worker, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	hash := sha256Hex(token)
	all, e := operations.List[siteops.Worker](r.Context(), s.Store, siteops.WorkerKind)
	if e != nil {
		s.writeError(w, 500, "loading worker credentials")
		return siteops.Worker{}, false
	}
	for _, v := range all {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(v.TokenHash)) == 1 {
			return v, true
		}
	}
	s.writeError(w, 401, "invalid worker credential")
	return siteops.Worker{}, false
}
func (s *Server) handleWorkerPoll(w http.ResponseWriter, r *http.Request) {
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	worker, ok := s.workerAuth(w, r)
	if !ok {
		return
	}
	worker.LastSeen = time.Now().UTC()
	if e := operations.Save(r.Context(), s.Store, siteops.WorkerKind, worker.ID, worker); e != nil {
		s.writeError(w, 500, "saving heartbeat")
		return
	}
	jobs, e := operations.List[siteops.Job](r.Context(), s.Store, siteops.JobKind)
	if e != nil {
		s.writeError(w, 500, "loading jobs")
		return
	}
	for _, j := range jobs {
		if j.WorkerID != worker.ID {
			continue
		}
		if e = s.refreshSiteJob(r, &j); e != nil {
			s.writeError(w, 500, "refreshing job")
			return
		}
		if j.Lease != "" {
			continue
		}
		task := siteops.Task{}
		dispatch := false
		if j.Kind == "scan" && (j.Phase == "queued" || j.Phase == "scheduled" && !time.Now().Before(j.NextRun)) {
			dispatch = true
		} else if j.Kind == "deploy" && (j.Phase == "preflight" || j.Phase == "pilot" || j.Phase == "rollout") {
			limit := len(j.Targets)
			if j.Phase == "pilot" {
				limit = j.Pilot
			}
			for i := 0; i < limit; i++ {
				t := &j.Targets[i]
				expected := "ready"
				if j.Phase == "preflight" {
					expected = "pending"
				}
				if t.State != expected {
					continue
				}
				j.ActiveTarget = i
				t.StartedAt = time.Now().UTC()
				if j.Phase != "preflight" {
					if _, exists, err := s.Store.GetHost(r.Context(), t.Host); err != nil || exists {
						j.Phase = "failed"
						t.Detail = "Host name already enrolled or unavailable"
						operations.Save(r.Context(), s.Store, siteops.JobKind, j.ID, j)
						break
					}
					raw, err := randomToken()
					if err != nil {
						s.writeError(w, 500, "generating enrollment")
						return
					}
					en, err := s.Store.CreateEnrollment(r.Context(), t.Host, j.Platform, sha256Hex(raw))
					if err != nil {
						s.writeError(w, 500, "creating enrollment")
						return
					}
					t.EnrollmentID = en.ID
					task.Token = raw
				}
				task.Target = *t
				dispatch = true
				break
			}
		}
		if !dispatch {
			continue
		}
		j.Lease = operations.ID()
		j.LeaseUntil = time.Now().Add(30 * time.Minute).UTC()
		task.Job = j
		if e := operations.Save(r.Context(), s.Store, siteops.JobKind, j.ID, j); e != nil {
			s.writeError(w, 500, "leasing job")
			return
		}
		s.writeJSON(w, 200, task)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleWorkerResult(w http.ResponseWriter, r *http.Request) {
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	worker, ok := s.workerAuth(w, r)
	if !ok {
		return
	}
	var b siteops.Result
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&b); err != nil {
		s.writeError(w, 400, "invalid worker result")
		return
	}
	if len(b.Assets) > 4096 {
		s.writeError(w, 400, "too many results")
		return
	}
	j, ok, e := operations.Load[siteops.Job](r.Context(), s.Store, siteops.JobKind, r.PathValue("id"))
	if e != nil || !ok || j.WorkerID != worker.ID {
		s.writeError(w, 404, "job not found")
		return
	}
	if j.Lease == "" || j.Lease != b.Lease || time.Now().After(j.LeaseUntil) {
		s.writeError(w, 409, "lease no longer valid; inspect job before any new installation")
		return
	}
	if j.Kind == "scan" && b.OK {
		p, _ := netip.ParsePrefix(j.CIDR)
		for _, a := range b.Assets {
			ip, e := netip.ParseAddr(a.Address)
			if e != nil || !p.Contains(ip) {
				s.writeError(w, 400, "result outside job range")
				return
			}
			for _, port := range a.Ports {
				found := false
				for _, allowed := range j.Ports {
					if port == allowed {
						found = true
					}
				}
				if !found {
					s.writeError(w, 400, "unexpected port")
					return
				}
			}
		}
		for _, a := range b.Assets {
			a.ID = sha256Hex(worker.ID + "\x00" + a.Address)
			old, found, e := operations.Load[siteops.Sighting](r.Context(), s.Store, siteops.SightingKind, a.ID)
			if e != nil {
				s.writeError(w, 500, "loading sighting")
				return
			}
			a.WorkerID = worker.ID
			a.LastSeen = time.Now().UTC()
			a.FirstSeen = a.LastSeen
			a.Review = "new"
			a.Confidence = "Port observations only; device identity and OS unverified"
			if found {
				a.FirstSeen = old.FirstSeen
				a.Review = old.Review
			}
			if e = operations.Save(r.Context(), s.Store, siteops.SightingKind, a.ID, a); e != nil {
				s.writeError(w, 500, "saving sighting")
				return
			}
		}
	}
	if !b.OK {
		j.Phase = "failed"
		j.Detail = b.Detail
		if len(j.Detail) > 300 {
			j.Detail = "Worker operation failed; inspect local diagnostics"
		}
		if j.Kind == "deploy" {
			j.Targets[j.ActiveTarget].State = "failed"
			j.Targets[j.ActiveTarget].Detail = "Worker operation failed; inspect local worker diagnostics"
		}
	} else if j.Kind == "scan" {
		j.Phase = "complete"
		if j.IntervalHours > 0 {
			j.Phase = "scheduled"
			j.NextRun = time.Now().Add(time.Duration(j.IntervalHours) * time.Hour).UTC()
		}
	} else {
		t := &j.Targets[j.ActiveTarget]
		if j.Phase == "preflight" {
			t.State = "ready"
			t.Detail = "Connectivity, platform and privilege checks passed"
			ready := true
			for _, v := range j.Targets {
				if v.State != "ready" {
					ready = false
				}
			}
			if ready {
				j.Phase = "ready"
			}
		} else {
			t.State = "awaiting-report"
			t.Detail = "Installation command succeeded; waiting for enrollment and first report"
		}
	}
	j.Lease = ""
	if e = operations.Save(r.Context(), s.Store, siteops.JobKind, j.ID, j); e != nil {
		s.writeError(w, 500, "saving result")
		return
	}
	s.writeJSON(w, 200, map[string]bool{"accepted": true})
}
