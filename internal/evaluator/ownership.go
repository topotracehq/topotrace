/*******************************************************************************
 * @file         ownership.go
 * @brief        Part of the TopoTrace evaluator module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package evaluator

import (
	"context"
	"fmt"
	"time"

	"topotrace/internal/compliance"
	"topotrace/internal/operations"
	"topotrace/internal/signals"
	"topotrace/internal/webhook"
)

func (e *Evaluator) escalateOverdue(ctx context.Context, now time.Time) {
	prefs, err := webhook.LoadPreferences(ctx, e.Store)
	if err != nil {
		e.log().Error("loading escalation preferences", "err", err)
		return
	}
	hosts, err := e.Store.ListHosts(ctx)
	if err != nil {
		return
	}
	rules, err := e.Store.ListSoftwareRules(ctx)
	if err != nil {
		return
	}
	inputs := []compliance.Input{}
	for _, h := range hosts {
		in, err := signals.Gather(ctx, e.Store, h, rules, e.VulnFeed)
		if err != nil {
			return
		}
		inputs = append(inputs, in)
	}
	queue, err := operations.Queue(ctx, e.Store, inputs, now)
	if err != nil {
		e.log().Error("building escalation queue", "err", err)
		return
	}
	seen := map[string]bool{}
	for _, item := range queue {
		a := item.Assignment
		if !item.Overdue || a.EscalateTo == "" || seen[a.ID] || a.DueAt == nil || now.Before(a.DueAt.Add(time.Duration(prefs.EscalationDelayHours)*time.Hour)) {
			continue
		}
		if a.EscalatedAt != nil && (prefs.EscalationRepeatHours == 0 || now.Before(a.EscalatedAt.Add(time.Duration(prefs.EscalationRepeatHours)*time.Hour))) {
			continue
		}
		seen[a.ID] = true
		detail := fmt.Sprintf("Overdue work assigned to %s (%s); escalation contact: %s; finding: %s", a.Owner, a.Team, a.EscalateTo, item.Title)
		if _, err := e.Store.RecordAudit(ctx, "system", "work-overdue", a.Host, detail); err != nil {
			e.log().Error("recording escalation", "err", err)
			continue
		}
		a.EscalatedAt = &now
		if err := operations.Save(ctx, e.Store, operations.AssignmentKind, a.ID, a); err != nil {
			e.log().Error("saving escalation", "err", err)
			continue
		}
		if e.Webhooks != nil {
			go e.Webhooks.Send(webhook.Event{Type: "work_overdue", Host: a.Host, Detail: detail})
		}
	}
}
