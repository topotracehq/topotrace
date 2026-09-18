package api

import (
	"context"
	"encoding/json"
	"muster/internal/model"
	"muster/internal/operations"
	"muster/internal/siteops"
	"muster/internal/store/memstore"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeploymentRequiresPilotReportAndCannotReplayLease(t *testing.T) {
	st, _ := memstore.New("")
	s := &Server{Store: st, AuthToken: "master"}
	h := s.Handler()
	call := func(method, path, token string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(b)))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := call("POST", "/api/sites/workers", "master", map[string]string{"name": "Test"})
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var worker map[string]string
	json.Unmarshal(w.Body.Bytes(), &worker)
	if w := call("GET", "/api/sites", worker["token"], nil); w.Code != 401 && w.Code != 403 {
		t.Fatal("worker accessed admin API", w.Code)
	}
	job := siteops.Job{Name: "Pilot", Kind: "deploy", WorkerID: worker["id"], Platform: "linux", Profile: "test", MusterHost: "muster.test", MusterPort: 9090, Pilot: 1, Targets: []siteops.Target{{Address: "192.0.2.1", Host: "one"}, {Address: "192.0.2.2", Host: "two"}}}
	w = call("POST", "/api/sites/jobs", "master", job)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &job)
	decision := func(d string, want int) {
		t.Helper()
		w := call("POST", "/api/sites/jobs/"+job.ID+"/"+d, "master", nil)
		if w.Code != want {
			t.Fatalf("%s: %d %s", d, w.Code, w.Body.String())
		}
	}
	poll := func() siteops.Task {
		t.Helper()
		w := call("POST", "/api/worker/poll", worker["token"], nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var task siteops.Task
		json.Unmarshal(w.Body.Bytes(), &task)
		return task
	}
	submit := func(task siteops.Task, want int) {
		t.Helper()
		w := call("POST", "/api/worker/results/"+task.Job.ID, worker["token"], siteops.Result{Lease: task.Job.Lease, OK: true})
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	decision("start", 409)
	decision("preflight", 200)
	first := poll()
	if first.Token != "" {
		t.Fatal("preflight issued credential")
	}
	submit(first, 200)
	submit(first, 409)
	submit(poll(), 200)
	decision("start", 200)
	first = poll()
	if first.Token == "" || first.Target.Host != "one" {
		t.Fatal("missing pilot enrollment")
	}
	submit(first, 200)
	decision("promote", 409)
	if w := call("POST", "/api/worker/poll", worker["token"], nil); w.Code != 204 {
		t.Fatal("dispatched remainder before report")
	}
	en, ok, e := st.FindEnrollmentByHash(context.Background(), sha256Hex(first.Token))
	if e != nil || !ok {
		t.Fatal("enrollment missing", e)
	}
	if e := st.MarkEnrolled(context.Background(), en.ID); e != nil {
		t.Fatal(e)
	}
	st.UpsertHost(context.Background(), model.Host{Name: "one", Platform: "linux", LastCooked: time.Now().Add(time.Second)})
	decision("promote", 200)
	next := poll()
	if next.Target.Host != "two" {
		t.Fatal("wrong rollout host")
	}
	stored, _, _ := operations.Load[siteops.Job](context.Background(), st, siteops.JobKind, job.ID)
	stored.LeaseUntil = time.Now().Add(-time.Minute)
	operations.Save(context.Background(), st, siteops.JobKind, job.ID, stored)
	call("GET", "/api/sites", "master", nil)
	submit(next, 409)
	if w := call("POST", "/api/worker/poll", worker["token"], nil); w.Code != 204 {
		t.Fatal("replayed expired install")
	}
}
func TestDiscoveryRejectsOutOfRangeResults(t *testing.T) {
	st, _ := memstore.New("")
	s := &Server{Store: st, AuthToken: "master"}
	ctx := context.Background()
	worker := siteops.Worker{ID: "w", TokenHash: sha256Hex("worker")}
	operations.Save(ctx, st, siteops.WorkerKind, worker.ID, worker)
	j := siteops.Job{ID: "j", WorkerID: "w", Kind: "scan", CIDR: "192.0.2.0/24", Ports: []int{22}, Lease: "lease", LeaseUntil: time.Now().Add(time.Minute)}
	operations.Save(ctx, st, siteops.JobKind, j.ID, j)
	b, _ := json.Marshal(siteops.Result{Lease: "lease", OK: true, Assets: []siteops.Sighting{{Address: "198.51.100.1", Ports: []int{22}}}})
	r := httptest.NewRequest("POST", "/api/worker/results/j", strings.NewReader(string(b)))
	r.Header.Set("Authorization", "Bearer worker")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	assets, _ := operations.List[siteops.Sighting](ctx, st, siteops.SightingKind)
	if len(assets) != 0 {
		t.Fatal("stored unapproved asset")
	}
}
