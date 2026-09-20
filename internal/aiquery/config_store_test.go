/*******************************************************************************
 * @file         config_store_test.go
 * @brief        Tests for the Muster aiquery package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package aiquery

import "testing"

func TestConfigStoreGetSet(t *testing.T) {
	s := NewConfigStore(Config{})
	if s.Get().Enabled() {
		t.Error("expected a zero-value initial Config to be disabled")
	}

	s.Set(Config{APIKey: "sk-ant-test", Model: "test-model"})
	got := s.Get()
	if !got.Enabled() {
		t.Error("expected Enabled() true after Set with a non-empty APIKey")
	}
	if got.Model != "test-model" {
		t.Errorf("got model %q, want test-model", got.Model)
	}

	s.Set(Config{})
	if s.Get().Enabled() {
		t.Error("expected Enabled() false after Set back to the zero value")
	}
}

func TestNewConfigStoreHoldsInitialValue(t *testing.T) {
	s := NewConfigStore(Config{APIKey: "sk-ant-initial"})
	if !s.Get().Enabled() {
		t.Error("expected the initial Config passed to NewConfigStore to be preserved")
	}
}
