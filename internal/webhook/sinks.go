/*******************************************************************************
 * @file         sinks.go
 * @brief        Part of the TopoTrace webhook module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package webhook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Sink is one place an Event can be delivered: a generic webhook URL, a
// Slack or Teams incoming webhook, a Jira project, a ServiceNow
// instance. Every implementation here is stdlib net/http against the
// service's documented HTTP API -- the same no-SDK stance as
// internal/siemforward and the cloud agents, and for the same reason
// (nothing to vendor, nothing to own). Deliver returns an error on any
// transport failure or non-2xx reply; the Dispatcher's queue decides
// whether and when to retry.
type Sink interface {
	// Name identifies the sink in logs, the queue, and the settings API
	// (e.g. "slack", "jira:OPS", "webhook:https://...").
	Name() string
	// Accepts reports whether this sink wants an event of this type --
	// a ticketing sink shouldn't open an incident for every "host is
	// new" event, but a chat sink can carry all of them.
	Accepts(eventType string) bool
	Deliver(ctx context.Context, evt Event) error
}

// eventFilter is the shared "which event types" helper: an empty list
// means everything.
type eventFilter []string

func (f eventFilter) accepts(t string) bool {
	if len(f) == 0 {
		return true
	}
	for _, x := range f {
		if x == t || x == "*" {
			return true
		}
	}
	return false
}

// postJSON is the one HTTP call every sink makes.
func postJSON(ctx context.Context, client *http.Client, url string, headers map[string]string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("replied %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return nil
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// title/body render an Event for a human -- shared by the chat and
// ticket sinks so the wording is the same everywhere.
func title(evt Event) string {
	label := strings.ReplaceAll(evt.Type, "_", " ")
	if evt.Host != "" {
		return fmt.Sprintf("Muster: %s on %s", label, evt.Host)
	}
	return "Muster: " + label
}

func body(evt Event) string {
	b := evt.Detail
	if b == "" {
		b = "(no detail)"
	}
	return fmt.Sprintf("%s\nHost: %s\nEvent: %s\nAt: %s", b, evt.Host, evt.Type, evt.Timestamp.Format(time.RFC3339))
}

// --- generic webhook (the original behavior) ------------------------

// URLSink POSTs the raw Event JSON to one URL.
type URLSink struct {
	URL    string
	Client *http.Client
}

func (s *URLSink) Name() string        { return "webhook:" + s.URL }
func (s *URLSink) Accepts(string) bool { return true }
func (s *URLSink) Deliver(ctx context.Context, evt Event) error {
	return postJSON(ctx, s.Client, s.URL, nil, evt)
}

// --- Slack ----------------------------------------------------------

// SlackSink posts to a Slack incoming webhook
// (https://api.slack.com/messaging/webhooks): {"text": ...} is the
// whole documented payload, and mrkdwn formatting is on by default.
type SlackSink struct {
	WebhookURL string
	Events     eventFilter
	Client     *http.Client
}

func (s *SlackSink) Name() string          { return "slack" }
func (s *SlackSink) Accepts(t string) bool { return s.Events.accepts(t) }
func (s *SlackSink) Deliver(ctx context.Context, evt Event) error {
	text := fmt.Sprintf("*%s*\n%s", title(evt), evt.Detail)
	return postJSON(ctx, s.Client, s.WebhookURL, nil, map[string]any{"text": text})
}

// --- Microsoft Teams ------------------------------------------------

// TeamsSink posts to a Teams incoming webhook / Workflows URL as an
// Adaptive Card wrapped in the "message" envelope Teams expects
// (https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using).
type TeamsSink struct {
	WebhookURL string
	Events     eventFilter
	Client     *http.Client
}

func (s *TeamsSink) Name() string          { return "teams" }
func (s *TeamsSink) Accepts(t string) bool { return s.Events.accepts(t) }
func (s *TeamsSink) Deliver(ctx context.Context, evt Event) error {
	card := map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []any{
					map[string]any{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title(evt)},
					map[string]any{"type": "TextBlock", "wrap": true, "text": evt.Detail},
					map[string]any{"type": "FactSet", "facts": []any{
						map[string]any{"title": "Host", "value": evt.Host},
						map[string]any{"title": "Event", "value": evt.Type},
						map[string]any{"title": "At", "value": evt.Timestamp.Format(time.RFC3339)},
					}},
				},
			},
		}},
	}
	return postJSON(ctx, s.Client, s.WebhookURL, nil, card)
}

// --- Jira -----------------------------------------------------------

// JiraSink creates one issue per accepted event via Jira Cloud's REST
// API v3 (POST /rest/api/3/issue, basic auth with email + API token --
// https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/).
// Description uses the Atlassian Document Format v3 requires.
type JiraSink struct {
	BaseURL   string // e.g. https://yourteam.atlassian.net
	Email     string
	APIToken  string
	Project   string // project key, e.g. OPS
	IssueType string // e.g. Task; defaults to Task
	Events    eventFilter
	Client    *http.Client
}

func (s *JiraSink) Name() string          { return "jira:" + s.Project }
func (s *JiraSink) Accepts(t string) bool { return s.Events.accepts(t) }
func (s *JiraSink) Deliver(ctx context.Context, evt Event) error {
	issueType := s.IssueType
	if issueType == "" {
		issueType = "Task"
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":   map[string]any{"key": s.Project},
			"issuetype": map[string]any{"name": issueType},
			"summary":   title(evt),
			"labels":    []string{"muster", evt.Type},
			"description": map[string]any{
				"type": "doc", "version": 1,
				"content": []any{map[string]any{
					"type":    "paragraph",
					"content": []any{map[string]any{"type": "text", "text": body(evt)}},
				}},
			},
		},
	}
	url := strings.TrimRight(s.BaseURL, "/") + "/rest/api/3/issue"
	return postJSON(ctx, s.Client, url, map[string]string{"Authorization": basicAuth(s.Email, s.APIToken)}, payload)
}

// --- ServiceNow -----------------------------------------------------

// ServiceNowSink creates one incident per accepted event via the Table
// API (POST /api/now/table/incident, basic auth --
// https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI).
type ServiceNowSink struct {
	InstanceURL string // e.g. https://dev12345.service-now.com
	User        string
	Password    string
	Events      eventFilter
	Client      *http.Client
}

func (s *ServiceNowSink) Name() string          { return "servicenow" }
func (s *ServiceNowSink) Accepts(t string) bool { return s.Events.accepts(t) }
func (s *ServiceNowSink) Deliver(ctx context.Context, evt Event) error {
	payload := map[string]any{
		"short_description": title(evt),
		"description":       body(evt),
		"category":          "security",
		"caller_id":         "muster",
		"urgency":           urgencyFor(evt.Type),
	}
	url := strings.TrimRight(s.InstanceURL, "/") + "/api/now/table/incident"
	return postJSON(ctx, s.Client, url, map[string]string{"Authorization": basicAuth(s.User, s.Password), "Accept": "application/json"}, payload)
}

func urgencyFor(eventType string) string {
	switch eventType {
	case "policy_violation", "software_violation", "remediation_proposed":
		return "2"
	default:
		return "3"
	}
}

// TicketEvents is the default event filter for the ticketing sinks:
// the findings worth a ticket, not the lifecycle noise.
var TicketEvents = eventFilter{"policy_violation", "software_violation", "remediation_proposed"}
