/*******************************************************************************
 * @file         settingsstore_test.go
 * @brief        Tests for the Muster settingsstore package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package settingsstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsZeroValue(t *testing.T) {
	o, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if o != (Overrides{}) {
		t.Errorf("expected zero value, got %+v", o)
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings-overrides.json")
	want := Overrides{
		SIEMBackend:  "splunk-hec",
		SIEMHECURL:   "https://splunk.example.com:8088",
		SIEMHECToken: "s3cr3t",
		AIAPIKey:     "sk-ant-test",
		AIModel:      "test-model",
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected 0o600 permissions, got %o", perm)
	}
}

func TestSaveOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings-overrides.json")
	if err := Save(path, Overrides{AIModel: "first"}); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	if err := Save(path, Overrides{AIModel: "second"}); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AIModel != "second" {
		t.Errorf("got model %q, want %q", got.AIModel, "second")
	}
}
