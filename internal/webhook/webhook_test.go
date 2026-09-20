/*******************************************************************************
 * @file         webhook_test.go
 * @brief        Tests for the Muster webhook package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"muster/internal/store/memstore"
)

func TestQueueDeliversRetriesAndDeadLetters(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			http.Error(w, "nope", 500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "always", 503) }))
	defer dead.Close()

	st, _ := memstore.New("")
	d := NewWithSinks([]Sink{
		&URLSink{URL: srv.URL, Client: srv.Client()},
		&URLSink{URL: dead.URL, Client: dead.Client()},
	}, st, nil)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return clock }

	d.Send(Event{Type: "policy_violation", Host: "h1", Detail: "x"})
	if got := d.Snapshot(); len(got.Pending) != 2 {
		t.Fatalf("expected 2 pending, got %+v", got)
	}
	docs, _ := st.ListDocuments(context.Background(), QueueKind)
	if len(docs) != 2 {
		t.Fatalf("queue should be persisted: %d docs", len(docs))
	}

	// attempt 1: both fail
	d.DeliverDue(context.Background())
	snap := d.Snapshot()
	if len(snap.Pending) != 2 || snap.Pending[0].Attempts != 1 || snap.Pending[0].LastError == "" {
		t.Fatalf("after attempt 1: %+v", snap.Pending)
	}
	// not due yet
	d.DeliverDue(context.Background())
	if d.Snapshot().Pending[0].Attempts != 1 {
		t.Fatal("should respect backoff")
	}
	// walk the clock through the backoff schedule until the flaky one lands and the dead one dies
	for i := 0; i < 10; i++ {
		clock = clock.Add(31 * time.Minute)
		d.DeliverDue(context.Background())
	}
	snap = d.Snapshot()
	if len(snap.Pending) != 0 {
		t.Fatalf("expected nothing pending, got %+v", snap.Pending)
	}
	if len(snap.Dead) != 1 || !strings.Contains(snap.Dead[0].Sink, dead.URL) || snap.Dead[0].Attempts != MaxAttempts {
		t.Fatalf("expected one dead delivery after %d attempts, got %+v", MaxAttempts, snap.Dead)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("flaky sink should have been called 3 times, got %d", calls)
	}

	// a fresh dispatcher over the same store resumes the dead letter and nothing pending
	d2 := NewWithSinks([]Sink{&URLSink{URL: dead.URL, Client: dead.Client()}}, st, nil)
	if s2 := d2.Snapshot(); len(s2.Dead) != 1 || len(s2.Pending) != 0 {
		t.Fatalf("resume: %+v", s2)
	}
}

func capture(t *testing.T) (*httptest.Server, *map[string]any, *http.Header) {
	t.Helper()
	var got map[string]any
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(201)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &hdr
}

func TestSinkPayloads(t *testing.T) {
	evt := Event{Type: "policy_violation", Host: "db01", Detail: "rule x: stale", Timestamp: time.Unix(0, 0).UTC()}

	slackSrv, slackGot, _ := capture(t)
	slack := &SlackSink{WebhookURL: slackSrv.URL, Client: slackSrv.Client()}
	if err := slack.Deliver(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if text, _ := (*slackGot)["text"].(string); !strings.Contains(text, "policy violation on db01") || !strings.Contains(text, "rule x: stale") {
		t.Fatalf("slack text: %v", *slackGot)
	}

	teamsSrv, teamsGot, _ := capture(t)
	teams := &TeamsSink{WebhookURL: teamsSrv.URL, Client: teamsSrv.Client()}
	if err := teams.Deliver(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if (*teamsGot)["type"] != "message" || len((*teamsGot)["attachments"].([]any)) != 1 {
		t.Fatalf("teams card: %v", *teamsGot)
	}

	jiraSrv, jiraGot, jiraHdr := capture(t)
	jira := &JiraSink{BaseURL: jiraSrv.URL + "/", Email: "a@b", APIToken: "tok", Project: "OPS", Events: TicketEvents, Client: jiraSrv.Client()}
	if !jira.Accepts("policy_violation") || jira.Accepts("host_new") {
		t.Fatal("ticket sinks should filter event types")
	}
	if err := jira.Deliver(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	fields := (*jiraGot)["fields"].(map[string]any)
	if fields["project"].(map[string]any)["key"] != "OPS" || fields["issuetype"].(map[string]any)["name"] != "Task" || !strings.HasPrefix(jiraHdr.Get("Authorization"), "Basic ") {
		t.Fatalf("jira payload: %v hdr=%v", fields, *jiraHdr)
	}

	snowSrv, snowGot, snowHdr := capture(t)
	snow := &ServiceNowSink{InstanceURL: snowSrv.URL, User: "u", Password: "p", Events: TicketEvents, Client: snowSrv.Client()}
	if err := snow.Deliver(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if (*snowGot)["urgency"] != "2" || !strings.Contains((*snowGot)["short_description"].(string), "db01") || snowHdr.Get("Authorization") == "" {
		t.Fatalf("servicenow payload: %v", *snowGot)
	}

	// a non-2xx reply surfaces as an error with the status
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad token", 401) }))
	defer bad.Close()
	if err := (&SlackSink{WebhookURL: bad.URL, Client: bad.Client()}).Deliver(context.Background(), evt); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}

func TestDeliverNowReportsPerSink(t *testing.T) {
	ok, _, _ := capture(t)
	d := NewWithSinks([]Sink{&URLSink{URL: ok.URL, Client: ok.Client()}, &JiraSink{BaseURL: ok.URL, Project: "X", Events: TicketEvents, Client: ok.Client()}}, nil, nil)
	res := d.DeliverNow(context.Background(), Event{Type: "test", Detail: "hello"})
	if res["webhook:"+ok.URL] != "ok" || !strings.HasPrefix(res["jira:X"], "skipped") {
		t.Fatalf("%v", res)
	}
	var nilD *Dispatcher
	nilD.Send(Event{Type: "test"})
	if nilD.Count() != 0 || len(nilD.Snapshot().Pending) != 0 {
		t.Fatal("nil dispatcher should be a safe no-op")
	}
}
