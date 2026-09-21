/*******************************************************************************
 * @file         evaluator.go
 * @brief        Package evaluator runs TopoTrace's background compliance loop: on a fixed interval, it computes each host's posture (internal/policy), evaluates every persisted rule (model.Rule, via internal/store) against it, auto-queues a remediation act...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package evaluator runs TopoTrace's background compliance loop: on a
// fixed interval, it computes each host's posture (internal/policy),
// evaluates every persisted rule (model.Rule, via internal/store)
// against it, auto-queues a remediation action for any violated rule
// that specifies one, records an audit-log entry for anything it does,
// and fires a webhook event for a notable outcome.
//
// This is the "unattended trigger" half of the remediation feature --
// internal/api's handleQueueAction is still the human/scripted path;
// this is the autonomous one, gated behind the exact same allow-list
// (internal/remediate.Validate) either way, so a bad or overly broad
// rule still can't queue anything outside the fixed verb set.
package evaluator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"topotrace/internal/alerts"
	"topotrace/internal/allowlist"
	"topotrace/internal/compliance"
	"topotrace/internal/history"
	"topotrace/internal/model"
	"topotrace/internal/operations"
	"topotrace/internal/policy"
	"topotrace/internal/remediate"
	"topotrace/internal/risk"
	"topotrace/internal/signals"
	"topotrace/internal/store"
	"topotrace/internal/vuln"
	"topotrace/internal/webhook"
)

// Evaluator owns the background loop's dependencies. Webhooks may be
// nil (webhook.Dispatcher.Send is a safe no-op on a nil receiver).
type Evaluator struct {
	Store    store.Store
	Webhooks *webhook.Dispatcher
	VulnFeed *vuln.Feed // nil is fine -- see vuln.CheckWithFeed
	Log      *slog.Logger
	Interval time.Duration
}

// Run blocks, evaluating every host against every persisted rule once
// per Interval (default 5 minutes), until ctx is done. Meant to be
// started with `go evaluator.Run(ctx)` from cmd/topotrace's main.
func (e *Evaluator) Run(ctx context.Context) {
	if e.Interval <= 0 {
		e.Interval = 5 * time.Minute
	}
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		e.runOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Evaluator) log() *slog.Logger {
	if e.Log == nil {
		return slog.Default()
	}
	return e.Log
}

func (e *Evaluator) runOnce(ctx context.Context) {
	operations.Mu.Lock()
	defer operations.Mu.Unlock()
	rules, err := e.Store.ListRules(ctx)
	if err != nil {
		e.log().Error("evaluator: listing rules", "err", err)
		return
	}
	softwareRules, err := e.Store.ListSoftwareRules(ctx)
	if err != nil {
		e.log().Error("evaluator: listing software rules", "err", err)
		return
	}
	// Even with no rules configured there's still work to do each run:
	// recording every host's score-history point (see internal/history)
	// is what makes trend charts and time-to-remediate possible at all.

	hosts, err := e.Store.ListHosts(ctx)
	if err != nil {
		e.log().Error("evaluator: listing hosts", "err", err)
		return
	}

	now := time.Now().UTC()
	state, err := alerts.Load(ctx, e.Store)
	if err != nil {
		e.log().Error("evaluator: loading alert state, starting fresh", "err", err)
	}
	run := &runState{state: &state, seen: map[string]bool{}}
	for _, h := range hosts {
		e.evaluateHost(ctx, h, rules, softwareRules, now, run)
	}
	// Anything open before this run that no host reproduced has cleared:
	// announce that once, then forget it.
	for _, v := range state.Resolve(run.seen) {
		action := "policy-resolved"
		if v.Kind == "software" {
			action = "software-violation-resolved"
		}
		detail := fmt.Sprintf("rule %q no longer violated (open since %s)", v.RuleName, v.FirstSeen.Format(time.RFC3339))
		e.log().Info("evaluator: violation resolved", "host", v.Host, "rule", v.RuleName)
		if _, err := e.Store.RecordAudit(ctx, "system", action, v.Host, detail); err != nil {
			e.log().Error("evaluator: recording audit entry", "err", err)
		}
		if e.Webhooks != nil {
			go e.Webhooks.Send(webhook.Event{Type: "violation_resolved", Host: v.Host, Detail: detail})
		}
	}
	if err := alerts.Save(ctx, e.Store, state); err != nil {
		e.log().Error("evaluator: saving alert state", "err", err)
	}
	if err := operations.AdvancePlans(ctx, e.Store, now); err != nil {
		e.log().Error("advancing scheduled changes", "err", err)
	}
	e.escalateOverdue(ctx, now)
}

// runState carries the alert bookkeeping through one evaluator run.
type runState struct {
	state *alerts.State
	seen  map[string]bool
}

func (e *Evaluator) evaluateHost(ctx context.Context, h model.Host, rules []model.Rule, softwareRules []model.SoftwareRule, now time.Time, run *runState) {
	facts, err := e.Store.ListFacts(ctx, h.Name)
	if err != nil {
		e.log().Error("evaluator: listing facts", "host", h.Name, "err", err)
		return
	}
	byCategory := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byCategory[f.Category] = f
	}
	in := signals.FromFacts(h, byCategory, softwareRules, e.VulnFeed, now)
	stale, posture := in.Stale, in.Posture

	// One score-history point per host per run, computed from the same
	// signals every rule below is judged against.
	comp := compliance.Baseline.Evaluate(in)
	if err := history.Record(ctx, e.Store, h.Name, history.Point{
		At: now, Posture: posture.Score, Compliance: comp.Score, Vulns: len(in.VulnFindings), Stale: stale,
	}); err != nil {
		e.log().Error("evaluator: recording score history", "host", h.Name, "err", err)
	}

	e.evaluateSoftware(ctx, h, softwareRules, byCategory, now, run)

	for _, rule := range rules {
		matches, matchErr := operations.MatchesGroup(ctx, e.Store, rule.Group, h, byCategory, risk.Compute(in).Score, now)
		if matchErr != nil {
			e.log().Error("matching dynamic policy group", "err", matchErr)
			continue
		}
		if !matches {
			continue // rule is scoped to a different board column -- not this host's concern
		}
		violated, reason := e.violates(rule, byCategory, stale, posture)
		if !violated {
			continue
		}

		key := alerts.PolicyKey(rule.ID, h.Name)
		run.seen[key] = true
		exception, accepted, err := operations.ExceptionFor(ctx, e.Store, key, now)
		if err != nil {
			e.log().Error("loading policy exception", "err", err)
			continue
		}
		if accepted {
			continue
		}
		if v, exists := run.state.Open[key]; exists && !exception.ExpiresAt.IsZero() && v.LastAlerted.Before(exception.ExpiresAt) {
			v.LastAlerted = time.Time{}
			run.state.Open[key] = v
		}
		decision := run.state.Observe(key, "policy", rule.ID, rule.Name, h.Name, reason, now)
		if decision == alerts.Announce {
			e.log().Info("evaluator: rule violated", "host", h.Name, "rule", rule.Name, "reason", reason)
			if _, err := e.Store.RecordAudit(ctx, "system", "policy-violation", h.Name, fmt.Sprintf("rule %q: %s", rule.Name, reason)); err != nil {
				e.log().Error("evaluator: recording audit entry", "err", err)
			}
			if e.Webhooks != nil {
				go e.Webhooks.Send(webhook.Event{
					Type:   "policy_violation",
					Host:   h.Name,
					Detail: fmt.Sprintf("rule %q: %s", rule.Name, reason),
				})
			}
		}

		if rule.AutoRemediate == "" {
			continue
		}
		if err := remediate.Validate(h.Platform, rule.AutoRemediate, rule.AutoRemediateArg); err != nil {
			e.log().Warn("evaluator: rule's auto-remediate action isn't valid for this host, skipping", "host", h.Name, "rule", rule.Name, "err", err)
			continue
		}
		if rule.RequireApproval {
			// Change control: propose, don't act. One pending approval
			// per (rule, host), however many runs the violation persists.
			created, err := alerts.ProposeApproval(ctx, e.Store, alerts.Approval{
				Host: h.Name, RuleID: rule.ID, RuleName: rule.Name,
				Verb: rule.AutoRemediate, Arg: rule.AutoRemediateArg, Reason: reason, CreatedAt: now,
			})
			if err != nil {
				e.log().Error("evaluator: proposing approval", "host", h.Name, "rule", rule.Name, "err", err)
			} else if created {
				detail := fmt.Sprintf("rule %q proposed %s %s -- waiting for approval", rule.Name, rule.AutoRemediate, rule.AutoRemediateArg)
				if _, err := e.Store.RecordAudit(ctx, "system", "remediation-proposed", h.Name, detail); err != nil {
					e.log().Error("evaluator: recording audit entry", "err", err)
				}
				if e.Webhooks != nil {
					go e.Webhooks.Send(webhook.Event{Type: "remediation_proposed", Host: h.Name, Detail: detail})
				}
			}
			continue
		}
		if decision != alerts.Announce {
			continue // already queued when the violation was first announced; don't re-queue every run
		}
		action, err := e.Store.QueueAction(ctx, h.Name, rule.AutoRemediate, rule.AutoRemediateArg)
		if err != nil {
			e.log().Error("evaluator: queuing auto-remediation", "host", h.Name, "rule", rule.Name, "err", err)
			continue
		}
		detail := fmt.Sprintf("rule %q auto-queued action %s (%s %s)", rule.Name, action.ID, rule.AutoRemediate, rule.AutoRemediateArg)
		if _, err := e.Store.RecordAudit(ctx, "system", "auto-remediate", h.Name, detail); err != nil {
			e.log().Error("evaluator: recording audit entry", "err", err)
		}
		if e.Webhooks != nil {
			go e.Webhooks.Send(webhook.Event{Type: "remediation_executed", Host: h.Name, Detail: detail})
		}
	}
}

// violates evaluates one rule's fixed Kind against a host's current
// facts/staleness/posture -- deliberately a small switch over a fixed
// set of kinds, not an expression language (same "small allow-list, not
// free-form" philosophy as internal/remediate's Verbs).
func (e *Evaluator) violates(rule model.Rule, facts map[string]model.Fact, stale bool, posture policy.PostureResult) (bool, string) {
	switch rule.Kind {
	case "stale":
		if stale {
			return true, "host is stale"
		}
	case "score_below":
		if posture.Score < rule.Threshold {
			return true, fmt.Sprintf("posture score %d is below threshold %d", posture.Score, rule.Threshold)
		}
	case "category_missing":
		if rule.Category == "" {
			return false, ""
		}
		if _, ok := facts[rule.Category]; !ok {
			return true, fmt.Sprintf("category %q has never been reported", rule.Category)
		}
	case "vulnerabilities_found":
		sw, ok := facts["installed_software"]
		if !ok {
			return false, ""
		}
		findings := vuln.CheckWithFeed(sw.Data["items"], e.VulnFeed)
		if len(findings) > 0 {
			return true, fmt.Sprintf("%d known-vulnerable package(s) found", len(findings))
		}
	}
	return false, ""
}

// evaluateSoftware cross-references host h's installed_software fact
// against softwareRules already scoped to it (group filtering happens
// here, the same "" -means-every-host convention model.Rule uses), and
// records an audit entry + fires a webhook for each violation found --
// the software-allowlist counterpart to violates()'s policy-rule path,
// kept separate since model.SoftwareRule has no AutoRemediate/Threshold
// fields of its own to share a code path with.
func (e *Evaluator) evaluateSoftware(ctx context.Context, h model.Host, softwareRules []model.SoftwareRule, facts map[string]model.Fact, now time.Time, run *runState) {
	if len(softwareRules) == 0 {
		return
	}
	sw, ok := facts["installed_software"]
	if !ok {
		return
	}

	var inScope []model.SoftwareRule
	for _, r := range softwareRules {
		if r.Group == "" || r.Group == h.Group {
			inScope = append(inScope, r)
		}
	}
	if len(inScope) == 0 {
		return
	}

	violations := allowlist.Evaluate(sw.Data["items"], inScope)
	for _, v := range violations {
		var detail string
		if v.Kind == "deny" {
			detail = fmt.Sprintf("denied software %q (rule %q): %s %s", v.Package, v.Rule, v.Package, v.Version)
		} else {
			detail = fmt.Sprintf("unauthorized software not on allowlist: %s %s", v.Package, v.Version)
		}
		key := alerts.SoftwareKey(v.Rule, h.Name, v.Package)
		run.seen[key] = true
		exception, accepted, err := operations.ExceptionFor(ctx, e.Store, key, now)
		if err != nil {
			e.log().Error("loading software exception", "err", err)
			continue
		}
		if accepted {
			continue
		}
		if open, exists := run.state.Open[key]; exists && !exception.ExpiresAt.IsZero() && open.LastAlerted.Before(exception.ExpiresAt) {
			open.LastAlerted = time.Time{}
			run.state.Open[key] = open
		}
		if run.state.Observe(key, "software", "", v.Rule, h.Name, detail, now) != alerts.Announce {
			continue
		}
		e.log().Info("evaluator: software rule violated", "host", h.Name, "detail", detail)
		if _, err := e.Store.RecordAudit(ctx, "system", "software-violation", h.Name, detail); err != nil {
			e.log().Error("evaluator: recording audit entry", "err", err)
		}
		if e.Webhooks != nil {
			go e.Webhooks.Send(webhook.Event{Type: "software_violation", Host: h.Name, Detail: detail})
		}
	}
}
