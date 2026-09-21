/*******************************************************************************
 * @file         dynamic_test.go
 * @brief        Tests for the TopoTrace siemforward package.
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
	"testing"
)

func TestDynamicSendNoopWhenUnconfigured(t *testing.T) {
	d := NewDynamic()
	if d.Configured() {
		t.Error("expected a fresh Dynamic to be unconfigured")
	}
	if got := d.Backend(); got != "" {
		t.Errorf("expected empty backend name, got %q", got)
	}
	if err := d.Send(context.Background(), SIEMEvent{Action: "test"}); err != nil {
		t.Errorf("Send on unconfigured Dynamic should no-op, got err: %v", err)
	}
}

func TestDynamicSetSplunkHECThenSend(t *testing.T) {
	var received SIEMEvent
	// Swap in a fake backend after configuring a real one, to confirm
	// SetSplunkHEC actually wires up a usable Forwarder without
	// needing a live HTTP server: Send should attempt a real POST and
	// fail against a bogus URL, proving the backend is really there.
	d := NewDynamic()
	d.SetSplunkHEC("http://127.0.0.1:0", "test-token")
	if !d.Configured() {
		t.Fatal("expected Configured() true after SetSplunkHEC")
	}
	if got := d.Backend(); got != "splunk-hec" {
		t.Errorf("got backend %q, want splunk-hec", got)
	}
	if err := d.Send(context.Background(), SIEMEvent{Action: "test"}); err == nil {
		t.Error("expected Send to fail against an unreachable HEC URL")
	}
	_ = received
}

func TestDynamicDisable(t *testing.T) {
	d := NewDynamic()
	d.SetSplunkHEC("http://127.0.0.1:0", "test-token")
	if !d.Configured() {
		t.Fatal("expected Configured() true after SetSplunkHEC")
	}
	d.Disable()
	if d.Configured() {
		t.Error("expected Configured() false after Disable")
	}
	if got := d.Backend(); got != "" {
		t.Errorf("expected empty backend name after Disable, got %q", got)
	}
	if err := d.Send(context.Background(), SIEMEvent{Action: "test"}); err != nil {
		t.Errorf("Send after Disable should no-op, got err: %v", err)
	}
}
