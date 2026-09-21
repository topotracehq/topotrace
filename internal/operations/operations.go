/*******************************************************************************
 * @file         operations.go
 * @brief        Package operations holds operator-owned workflow records, separate from agent facts.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package operations holds operator-owned workflow records, separate from agent facts.
package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/store"
)

// Mu serializes workflow transitions in the single Muster server process.
// Multiple server replicas require a database transaction/lease before dispatch.
var Mu sync.Mutex

const AssignmentKind = "work_assignment"
const ExceptionKind = "work_exception"
const GroupKind = "dynamic_group"
const PlanKind = "change_plan"

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Save(ctx context.Context, st store.Store, kind, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return st.PutDocument(ctx, model.Document{Kind: kind, ID: id, Data: b})
}
func Load[T any](ctx context.Context, st store.Store, kind, id string) (T, bool, error) {
	var v T
	d, ok, err := st.GetDocument(ctx, kind, id)
	if err != nil || !ok {
		return v, ok, err
	}
	err = json.Unmarshal(d.Data, &v)
	return v, true, err
}
func List[T any](ctx context.Context, st store.Store, kind string) ([]T, error) {
	docs, err := st.ListDocuments(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := make([]T, 0, len(docs))
	for _, d := range docs {
		var v T
		if err := json.Unmarshal(d.Data, &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

type Assignment struct {
	ID          string     `json:"id"`
	Host        string     `json:"host"`
	Owner       string     `json:"owner"`
	Team        string     `json:"team"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	EscalateTo  string     `json:"escalate_to"`
	EscalatedAt *time.Time `json:"escalated_at,omitempty"`
	UpdatedBy   string     `json:"updated_by"`
}

func (a Assignment) Overdue(now time.Time) bool { return a.DueAt != nil && now.After(*a.DueAt) }

type Exception struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
}

func ExceptionFor(ctx context.Context, st store.Store, key string, now time.Time) (Exception, bool, error) {
	e, ok, err := Load[Exception](ctx, st, ExceptionKind, key)
	return e, ok && now.Before(e.ExpiresAt), err
}

type Selector struct {
	Platform string `json:"platform"`
	Software string `json:"software"`
	Tag      string `json:"tag"`
	Exposure string `json:"exposure"`
	MinRisk  int    `json:"min_risk"`
}
type DynamicGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Selector Selector `json:"selector"`
}

func (s Selector) Validate() error {
	if s.MinRisk < 0 || s.MinRisk > 100 {
		return fmt.Errorf("minimum risk must be between 0 and 100")
	}
	if s.Exposure != "" && s.Exposure != "internet" && s.Exposure != "internal" {
		return fmt.Errorf("exposure must be internet or internal")
	}
	if len(s.Platform)+len(s.Software)+len(s.Tag) > 500 {
		return fmt.Errorf("selector is too long")
	}
	return nil
}
func (s Selector) Matches(h model.Host, facts map[string]model.Fact, risk int, now time.Time) bool {
	if s.Platform != "" && !strings.EqualFold(s.Platform, h.Platform) || risk < s.MinRisk {
		return false
	}
	tag, exposed := s.Tag == "", false
	for _, t := range h.Tags {
		if strings.EqualFold(t, s.Tag) {
			tag = true
		}
		if t == "exposure:internet" || t == "public" || t == "internet-facing" {
			exposed = true
		}
	}
	if !tag || s.Exposure == "internet" && !exposed || s.Exposure == "internal" && exposed {
		return false
	}
	if s.Software != "" {
		f := facts["installed_software"]
		if policy.IsStale(f.CookedAt, now) {
			return false
		}
		for _, item := range Items(f.Data["items"]) {
			name, _ := item["name"].(string)
			if strings.Contains(strings.ToLower(name), strings.ToLower(s.Software)) {
				return true
			}
		}
		return false
	}
	return true
}
func Items(raw any) []map[string]any {
	if rows, ok := raw.([]map[string]any); ok {
		return rows
	}
	out := []map[string]any{}
	if rows, ok := raw.([]any); ok {
		for _, v := range rows {
			if m, ok := v.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

// MatchesGroup preserves manual board groups and adds dynamic:<id> policy targets.
func MatchesGroup(ctx context.Context, st store.Store, group string, h model.Host, facts map[string]model.Fact, score int, now time.Time) (bool, error) {
	if !strings.HasPrefix(group, "dynamic:") {
		return group == "" || group == h.Group, nil
	}
	g, ok, err := Load[DynamicGroup](ctx, st, GroupKind, strings.TrimPrefix(group, "dynamic:"))
	if err != nil || !ok {
		return false, err
	}
	return g.Selector.Matches(h, facts, score, now), nil
}

type Verification struct {
	ActionID   string     `json:"action_id"`
	Host       string     `json:"host"`
	State      string     `json:"state"`
	Detail     string     `json:"detail"`
	EvidenceAt *time.Time `json:"evidence_at,omitempty"`
}

// Verify requires successful execution AND later, fresh evidence that the service
// is running. Execution success alone never verifies remediation.
func Verify(a model.Action, facts map[string]model.Fact, now time.Time) Verification {
	v := Verification{ActionID: a.ID, Host: a.Host, State: "requested", Detail: "Waiting for the agent to receive the action"}
	if a.Status == "fail" {
		v.State = "failed"
		v.Detail = a.Detail
		return v
	}
	if !a.Delivered {
		if now.Sub(a.QueuedAt) > 24*time.Hour {
			v.State = "timed_out"
			v.Detail = "Agent did not receive the action within 24 hours"
		}
		return v
	}
	v.State = "delivered"
	v.Detail = "Waiting for an execution result"
	if a.Status != "ok" {
		if now.Sub(a.DeliveredAt) > 24*time.Hour {
			v.State = "timed_out"
			v.Detail = "No execution result within 24 hours"
		}
		return v
	}
	v.State = "executed"
	v.Detail = "Execution succeeded; waiting for a newer service report"
	if a.Verb != "restart-service" {
		v.State = "unverifiable"
		v.Detail = "No evidence check exists for this action"
		return v
	}
	f, ok := facts["running_services"]
	if !ok || !f.CookedAt.After(a.ReportedAt) || policy.IsStale(f.CookedAt, now) || f.CookedAt.After(now.Add(5*time.Minute)) {
		if now.Sub(a.ReportedAt) > 24*time.Hour {
			v.State = "timed_out"
			v.Detail = "No fresh post-action evidence within 24 hours"
		}
		return v
	}
	v.EvidenceAt = &f.CookedAt
	for _, row := range Items(f.Data["items"]) {
		name, _ := row["name"].(string)
		if !strings.EqualFold(strings.TrimSuffix(name, ".service"), strings.TrimSuffix(a.Arg, ".service")) {
			continue
		}
		if row["active_state"] == "active" || row["status"] == "Running" {
			v.State = "verified"
			v.Detail = "A newer report confirms the service is running"
		} else {
			v.State = "failed"
			v.Detail = "A newer report shows the service is not running"
		}
		return v
	}
	v.State = "failed"
	v.Detail = "The service is absent from the newer service report"
	return v
}
