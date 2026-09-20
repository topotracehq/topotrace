/*******************************************************************************
 * @file         notify.go
 * @brief        Part of the Muster api module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"muster/internal/webhook"
)

// notifySettings summarizes the notification sinks for GET /api/settings
// without exposing a URL's path (a Slack/Teams webhook URL is a secret;
// a generic webhook URL may carry a token in its path).
func notifySettings(d *webhook.Dispatcher) settingsWebhooks {
	out := settingsWebhooks{Configured: d.Count() > 0, Count: d.Count()}
	for _, name := range d.SinkNames() {
		out.Sinks = append(out.Sinks, redactSink(name))
	}
	snap := d.Snapshot()
	out.Pending, out.Dead = len(snap.Pending), len(snap.Dead)
	return out
}

func redactSink(name string) string {
	if strings.HasPrefix(name, "webhook:") {
		if u, err := url.Parse(strings.TrimPrefix(name, "webhook:")); err == nil {
			return "webhook:" + u.Host
		}
		return "webhook"
	}
	return name
}

// handleNotifyQueue is GET /api/notifications/queue -- the durable
// delivery queue: what's still pending (with attempts and last error)
// and what died after MaxAttempts. Admin, since pending events carry
// host names and finding detail.
func (s *Server) handleNotifyQueue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "admin"); !ok {
		return
	}
	snap := s.Webhooks.Snapshot()
	for i := range snap.Sinks {
		snap.Sinks[i] = redactSink(snap.Sinks[i])
	}
	for i := range snap.Pending {
		snap.Pending[i].Sink = redactSink(snap.Pending[i].Sink)
	}
	for i := range snap.Dead {
		snap.Dead[i].Sink = redactSink(snap.Dead[i].Sink)
	}
	s.writeJSON(w, http.StatusOK, snap)
}

// handleNotifyTest is POST /api/notifications/test -- delivers one
// synthetic event to every configured sink synchronously and reports
// each sink's outcome, so an operator can confirm a Slack channel or
// Jira project is wired up without waiting for a real violation. Body
// {"type": "...", "host": "...", "detail": "..."} is optional; defaults
// to a "test" event. Admin, strict: this makes outbound calls on the
// operator's behalf and creates tickets where ticket sinks are set.
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	evt := webhook.Event{Type: "test", Host: "muster", Detail: "Test event from Muster's Settings page -- if you can read this, this sink is wired up.", Timestamp: time.Now().UTC()}
	if r.Body != nil {
		var req struct {
			Type, Host, Detail string
		}
		if json.NewDecoder(r.Body).Decode(&req) == nil {
			if req.Type != "" {
				evt.Type = req.Type
			}
			if req.Host != "" {
				evt.Host = req.Host
			}
			if req.Detail != "" {
				evt.Detail = req.Detail
			}
		}
	}
	if s.Webhooks.Count() == 0 {
		s.writeError(w, http.StatusServiceUnavailable, "no notification sinks configured (see -webhook-url, -slack-webhook-url, -teams-webhook-url, -jira-url, -servicenow-url)")
		return
	}
	results := s.Webhooks.DeliverNow(r.Context(), evt)
	redacted := map[string]string{}
	for k, v := range results {
		redacted[redactSink(k)] = v
	}
	names := make([]string, 0, len(redacted))
	for k := range redacted {
		names = append(names, k)
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "notification-test", evt.Host, "sent a "+evt.Type+" test event to "+strings.Join(names, ", ")); err != nil {
		s.log().Error("notify: recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"event": evt, "results": redacted})
}
