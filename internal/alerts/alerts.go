/*******************************************************************************
 * @file         alerts.go
 * @brief        Package alerts is the state the background evaluator keeps between runs so it can stop shouting: which (rule, host) violations are currently open, when each was first seen and last announced, whether an operator has snoozed it, and which...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package alerts is the state the background evaluator keeps between
// runs so it can stop shouting: which (rule, host) violations are
// currently open, when each was first seen and last announced, whether
// an operator has snoozed it, and which auto-remediations are parked
// waiting for a human to approve them.
//
// Without this, every evaluator run (every 5 minutes by default)
// re-recorded the same policy violation to the audit trail and re-fired
// the same webhook -- the alert-fatigue failure mode every SIEM and
// detection product eventually has to solve. With it, a violation is
// announced once when it opens, again every RealertAfter while it stays
// open (unless snoozed), and once more when it clears.
//
// Two model.Document kinds: "alert_state" (one document holding every
// open violation, keyed by rule+host) and "approval" (one document per
// parked action).
package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

const (
	// StateKind is the single-document kind holding open violations.
	StateKind = "alert_state"
	stateID   = "violations"
	// ApprovalKind is the per-action pending-approval document kind.
	ApprovalKind = "approval"
	// RealertAfter is how long an open, un-snoozed violation stays
	// quiet before it's announced again.
	RealertAfter = 24 * time.Hour
)

// Violation is one open (rule, host) finding and its announcement state.
type Violation struct {
	Key          string    `json:"key"`  // "<rule id>|<host>" (policy) or "sw|<rule>|<host>|<package>" (software)
	Kind         string    `json:"kind"` // "policy" or "software"
	RuleID       string    `json:"rule_id,omitempty"`
	RuleName     string    `json:"rule_name"`
	Host         string    `json:"host"`
	Reason       string    `json:"reason"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	LastAlerted  time.Time `json:"last_alerted"`
	Occurrences  int       `json:"occurrences"` // evaluator runs it's been seen in
	SnoozedUntil time.Time `json:"snoozed_until,omitempty"`
	SnoozedBy    string    `json:"snoozed_by,omitempty"`
}

// Snoozed reports whether v is snoozed as of now.
func (v Violation) Snoozed(now time.Time) bool {
	return !v.SnoozedUntil.IsZero() && now.Before(v.SnoozedUntil)
}

// State is every open violation, keyed by Violation.Key.
type State struct {
	Open map[string]Violation `json:"open"`
}

// Load reads the current state (empty, not an error, when none yet).
func Load(ctx context.Context, st store.Store) (State, error) {
	s := State{Open: map[string]Violation{}}
	doc, ok, err := st.GetDocument(ctx, StateKind, stateID)
	if err != nil || !ok {
		return s, err
	}
	if err := json.Unmarshal(doc.Data, &s); err != nil {
		return State{Open: map[string]Violation{}}, err
	}
	if s.Open == nil {
		s.Open = map[string]Violation{}
	}
	return s, nil
}

// Save writes the state back.
func Save(ctx context.Context, st store.Store, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.PutDocument(ctx, model.Document{Kind: StateKind, ID: stateID, Data: data})
}

// Decision is what Observe tells the evaluator to do about a violation
// it just found.
type Decision int

const (
	// Quiet: the violation is known and was announced recently (or is
	// snoozed) -- record nothing, fire nothing.
	Quiet Decision = iota
	// Announce: new, or open long enough to be worth repeating -- record
	// the audit entry and fire the webhook.
	Announce
)

// Observe marks key as seen now and decides whether to announce it.
// Mutates s; the caller Saves once at the end of the run.
func (s *State) Observe(key, kind, ruleID, ruleName, host, reason string, now time.Time) Decision {
	v, open := s.Open[key]
	if !open {
		s.Open[key] = Violation{Key: key, Kind: kind, RuleID: ruleID, RuleName: ruleName, Host: host, Reason: reason,
			FirstSeen: now, LastSeen: now, LastAlerted: now, Occurrences: 1}
		return Announce
	}
	v.LastSeen = now
	v.Occurrences++
	v.Reason = reason
	if v.Snoozed(now) {
		s.Open[key] = v
		return Quiet
	}
	if now.Sub(v.LastAlerted) >= RealertAfter {
		v.LastAlerted = now
		s.Open[key] = v
		return Announce
	}
	s.Open[key] = v
	return Quiet
}

// Resolve closes every open violation not in seen (the set of keys
// this run observed) and returns them, so the caller can announce that
// they cleared. Mutates s.
func (s *State) Resolve(seen map[string]bool) []Violation {
	var closed []Violation
	for key, v := range s.Open {
		if !seen[key] {
			closed = append(closed, v)
			delete(s.Open, key)
		}
	}
	sort.Slice(closed, func(i, j int) bool { return closed[i].Key < closed[j].Key })
	return closed
}

// Snooze quiets key until now+d. Returns false if no such open violation.
func (s *State) Snooze(key, by string, d time.Duration, now time.Time) bool {
	v, ok := s.Open[key]
	if !ok {
		return false
	}
	v.SnoozedUntil = now.Add(d)
	v.SnoozedBy = by
	s.Open[key] = v
	return true
}

// Unsnooze clears a snooze. Returns false if no such open violation.
func (s *State) Unsnooze(key string) bool {
	v, ok := s.Open[key]
	if !ok {
		return false
	}
	v.SnoozedUntil, v.SnoozedBy = time.Time{}, ""
	s.Open[key] = v
	return true
}

// List returns the open violations sorted newest-first-seen.
func (s State) List() []Violation {
	out := make([]Violation, 0, len(s.Open))
	for _, v := range s.Open {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstSeen.Equal(out[j].FirstSeen) {
			return out[i].FirstSeen.After(out[j].FirstSeen)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// PolicyKey and SoftwareKey build Violation keys.
func PolicyKey(ruleID, host string) string { return ruleID + "|" + host }
func SoftwareKey(rule, host, pkg string) string {
	return "sw|" + rule + "|" + host + "|" + pkg
}

// Approval is one auto-remediation parked for a human decision.
type Approval struct {
	ID        string    `json:"id"` // "<rule id>|<host>"
	Host      string    `json:"host"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Verb      string    `json:"verb"`
	Arg       string    `json:"arg,omitempty"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// ProposeApproval parks an action for host under rule, unless one is
// already pending for that (rule, host). Returns whether it was newly
// created.
func ProposeApproval(ctx context.Context, st store.Store, a Approval) (bool, error) {
	a.ID = PolicyKey(a.RuleID, a.Host)
	if _, exists, err := st.GetDocument(ctx, ApprovalKind, a.ID); err != nil {
		return false, err
	} else if exists {
		return false, nil
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	data, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	return true, st.PutDocument(ctx, model.Document{Kind: ApprovalKind, ID: a.ID, Data: data})
}

// ListApprovals returns every pending approval, oldest first.
func ListApprovals(ctx context.Context, st store.Store) ([]Approval, error) {
	docs, err := st.ListDocuments(ctx, ApprovalKind)
	if err != nil {
		return nil, err
	}
	out := make([]Approval, 0, len(docs))
	for _, d := range docs {
		var a Approval
		if json.Unmarshal(d.Data, &a) == nil {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// GetApproval loads one pending approval by ID.
func GetApproval(ctx context.Context, st store.Store, id string) (Approval, bool, error) {
	doc, ok, err := st.GetDocument(ctx, ApprovalKind, id)
	if err != nil || !ok {
		return Approval{}, false, err
	}
	var a Approval
	if err := json.Unmarshal(doc.Data, &a); err != nil {
		return Approval{}, false, fmt.Errorf("alerts: decoding approval %s: %w", id, err)
	}
	return a, true, nil
}

// RemoveApproval deletes a pending approval (after approve or reject).
func RemoveApproval(ctx context.Context, st store.Store, id string) error {
	return st.DeleteDocument(ctx, ApprovalKind, id)
}
