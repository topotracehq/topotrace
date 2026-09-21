/*******************************************************************************
 * @file         dynamic.go
 * @brief        Part of the TopoTrace siemforward module.
 * @project      TopoTrace
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
	"sync"
)

// Dynamic is a Forwarder whose backend can be swapped at runtime, so
// PATCH /api/settings can turn SIEM forwarding on, reconfigure it, or
// turn it off on a running server -- no restart, and no re-wrapping of
// the Store. A plain Forwarder built once at startup (SplunkHEC) has no
// way to do this; cmd/muster constructs exactly one Dynamic and always
// passes it to WrapStore, even when starting with neither -siem-hec-*
// flag set, so forwarding can be enabled later purely by calling
// SetSplunkHEC. Send is a safe no-op whenever no backend is configured,
// which is what lets cmd/muster always wrap the Store instead of only
// wrapping it once a forwarder already exists (WrapStore's own
// nil-Forwarder short-circuit still exists and is unrelated to this --
// it's for callers who never want the wrapping overhead at all).
type Dynamic struct {
	mu      sync.RWMutex
	backend Forwarder
	name    string // e.g. "splunk-hec"; "" when unconfigured
}

// NewDynamic returns an unconfigured Dynamic -- Send is a no-op until
// SetSplunkHEC is called.
func NewDynamic() *Dynamic {
	return &Dynamic{}
}

// SetSplunkHEC configures (or reconfigures) d to forward to a Splunk
// HEC endpoint. Safe to call at any time, including while forwarding
// is already active with a different URL or token.
func (d *Dynamic) SetSplunkHEC(url, token string) {
	_ = d.Set("splunk-hec", url, token)
}

// Set configures d with any backend NewBackend knows ("splunk-hec",
// "sumo-http", "logrhythm-webhook"). An unknown name leaves d unchanged
// and returns the error.
func (d *Dynamic) Set(backend, url, token string) error {
	fwd, err := NewBackend(backend, url, token)
	if err != nil {
		return err
	}
	if backend == "" {
		backend = "splunk-hec"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.backend = fwd
	d.name = backend
	return nil
}

// Disable turns off forwarding -- Send becomes a no-op again, same as
// a Dynamic that was never configured.
func (d *Dynamic) Disable() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.backend = nil
	d.name = ""
}

// Configured reports whether a backend is currently set.
func (d *Dynamic) Configured() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.backend != nil
}

// Backend names the active backend ("splunk-hec"), or "" when
// unconfigured.
func (d *Dynamic) Backend() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.name
}

// Send forwards to the currently configured backend, or no-ops (nil
// error) when none is set -- see the Dynamic doc comment.
func (d *Dynamic) Send(ctx context.Context, event SIEMEvent) error {
	d.mu.RLock()
	backend := d.backend
	d.mu.RUnlock()
	if backend == nil {
		return nil
	}
	return backend.Send(ctx, event)
}
