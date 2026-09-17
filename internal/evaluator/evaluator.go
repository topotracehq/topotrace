// Package evaluator runs Muster's background compliance loop: on a
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

	"muster/internal/allowlist"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/remediate"
	"muster/internal/store"
	"muster/internal/vuln"
	"muster/internal/webhook"
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
// started with `go evaluator.Run(ctx)` from cmd/muster's main.
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
	if len(rules) == 0 && len(softwareRules) == 0 {
		return // nothing configured -- don't even bother fetching hosts/facts
	}

	hosts, err := e.Store.ListHosts(ctx)
	if err != nil {
		e.log().Error("evaluator: listing hosts", "err", err)
		return
	}

	now := time.Now().UTC()
	for _, h := range hosts {
		e.evaluateHost(ctx, h, rules, softwareRules, now)
	}
}

func (e *Evaluator) evaluateHost(ctx context.Context, h model.Host, rules []model.Rule, softwareRules []model.SoftwareRule, now time.Time) {
	facts, err := e.Store.ListFacts(ctx, h.Name)
	if err != nil {
		e.log().Error("evaluator: listing facts", "host", h.Name, "err", err)
		return
	}
	byCategory := make(map[string]model.Fact, len(facts))
	for _, f := range facts {
		byCategory[f.Category] = f
	}
	stale := policy.IsStale(h.LastCooked, now)
	posture := policy.ComputePosture(h.Platform, byCategory, stale)

	e.evaluateSoftware(ctx, h, softwareRules, byCategory)

	for _, rule := range rules {
		if rule.Group != "" && rule.Group != h.Group {
			continue // rule is scoped to a different board column -- not this host's concern
		}
		violated, reason := e.violates(rule, byCategory, stale, posture)
		if !violated {
			continue
		}

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

		if rule.AutoRemediate == "" {
			continue
		}
		if err := remediate.Validate(h.Platform, rule.AutoRemediate, rule.AutoRemediateArg); err != nil {
			e.log().Warn("evaluator: rule's auto-remediate action isn't valid for this host, skipping", "host", h.Name, "rule", rule.Name, "err", err)
			continue
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
func (e *Evaluator) evaluateSoftware(ctx context.Context, h model.Host, softwareRules []model.SoftwareRule, facts map[string]model.Fact) {
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
		e.log().Info("evaluator: software rule violated", "host", h.Name, "detail", detail)
		if _, err := e.Store.RecordAudit(ctx, "system", "software-violation", h.Name, detail); err != nil {
			e.log().Error("evaluator: recording audit entry", "err", err)
		}
		if e.Webhooks != nil {
			go e.Webhooks.Send(webhook.Event{Type: "software_violation", Host: h.Name, Detail: detail})
		}
	}
}
