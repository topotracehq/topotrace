/*******************************************************************************
 * @file         store.go
 * @brief        Part of the Muster siemforward module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package siemforward

import (
	"context"
	"log/slog"
	"time"

	"muster/internal/model"
	"muster/internal/store"
)

// forwardTimeout bounds how long one SIEM delivery attempt is allowed
// to run in its own goroutine -- generous enough for a real network
// round-trip, short enough that a dead SIEM endpoint can't accumulate
// goroutines indefinitely on a busy server.
const forwardTimeout = 5 * time.Second

// auditForwardingStore wraps a store.Store, forwarding every
// successfully recorded audit entry to a Forwarder. Every other method
// is promoted unchanged from the embedded store.Store, so WrapStore is
// a one-line change in cmd/muster with zero changes to any of the
// existing RecordAudit call sites across internal/api and
// internal/evaluator.
type auditForwardingStore struct {
	store.Store
	forwarder Forwarder
	log       *slog.Logger
}

// WrapStore returns st unchanged when fwd is nil (SIEM forwarding
// disabled, the default) -- otherwise a store.Store whose RecordAudit
// also forwards the resulting entry to fwd, fire-and-forget, with its
// own bounded timeout. A failed or slow SIEM delivery is logged, never
// returned to the caller: RecordAudit's own success/failure is
// unaffected, exactly like internal/webhook's Send never affecting the
// event that triggered it.
func WrapStore(st store.Store, fwd Forwarder, log *slog.Logger) store.Store {
	if fwd == nil {
		return st
	}
	if log == nil {
		log = slog.Default()
	}
	return &auditForwardingStore{Store: st, forwarder: fwd, log: log}
}

func (s *auditForwardingStore) RecordAudit(ctx context.Context, actor, action, target, detail string) (model.AuditEntry, error) {
	entry, err := s.Store.RecordAudit(ctx, actor, action, target, detail)
	if err != nil {
		return entry, err
	}
	go s.forward(entry)
	return entry, err
}

// forward runs in its own goroutine (see RecordAudit) on a detached
// context with its own timeout -- never the request context that
// triggered the audit entry, which may already be canceled by the time
// this runs if the HTTP handler has finished responding.
func (s *auditForwardingStore) forward(entry model.AuditEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), forwardTimeout)
	defer cancel()
	evt := SIEMEvent{
		ID:        entry.ID,
		Actor:     entry.Actor,
		Action:    entry.Action,
		Target:    entry.Target,
		Detail:    entry.Detail,
		Timestamp: entry.CreatedAt.Unix(),
	}
	if err := s.forwarder.Send(ctx, evt); err != nil {
		s.log.Warn("siemforward: delivery failed", "action", entry.Action, "target", entry.Target, "err", err)
	}
}
