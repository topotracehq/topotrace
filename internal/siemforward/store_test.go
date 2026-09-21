/*******************************************************************************
 * @file         store_test.go
 * @brief        Tests for the Muster siemforward package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package siemforward

import (
	"context"
	"errors"
	"testing"
	"time"

	"muster/internal/store/memstore"
)

type fakeForwarder struct {
	sent chan SIEMEvent
	err  error
}

func (f *fakeForwarder) Send(ctx context.Context, event SIEMEvent) error {
	f.sent <- event
	return f.err
}

func newTestStore(t *testing.T) *memstore.Store {
	t.Helper()
	st, err := memstore.New("")
	if err != nil {
		t.Fatalf("memstore.New: %v", err)
	}
	return st
}

func TestWrapStoreNilForwarderReturnsSameStore(t *testing.T) {
	st := newTestStore(t)
	wrapped := WrapStore(st, nil, nil)
	if wrapped != st {
		t.Error("WrapStore with a nil Forwarder should return the original store unchanged")
	}
}

func TestWrapStoreForwardsRecordedAudit(t *testing.T) {
	st := newTestStore(t)
	fwd := &fakeForwarder{sent: make(chan SIEMEvent, 1)}
	wrapped := WrapStore(st, fwd, nil)

	entry, err := wrapped.RecordAudit(context.Background(), "master", "create-group", "eng", "detail here")
	if err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	select {
	case got := <-fwd.sent:
		if got.Actor != "master" || got.Action != "create-group" || got.Target != "eng" || got.Detail != "detail here" {
			t.Errorf("forwarded event = %+v, want fields to match the recorded audit entry %+v", got, entry)
		}
		if got.ID != entry.ID {
			t.Errorf("forwarded event ID = %q, want %q", got.ID, entry.ID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RecordAudit to forward the event")
	}
}

func TestWrapStoreForwardFailureDoesNotFailRecordAudit(t *testing.T) {
	st := newTestStore(t)
	fwd := &fakeForwarder{sent: make(chan SIEMEvent, 1), err: errors.New("siem unreachable")}
	wrapped := WrapStore(st, fwd, nil)

	if _, err := wrapped.RecordAudit(context.Background(), "master", "create-group", "eng", ""); err != nil {
		t.Fatalf("RecordAudit should succeed even when the forwarder errors, got: %v", err)
	}
	select {
	case <-fwd.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forward attempt")
	}
}
