/*******************************************************************************
 * @file         eol_test.go
 * @brief        Tests for the Muster eol package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package eol

import (
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		summary map[string]any
		state   string
	}{
		{map[string]any{"os": "Linux", "distribution": "Ubuntu", "distribution_version": "22.04.4 LTS"}, "supported"},
		{map[string]any{"os": "Linux", "distribution": "Ubuntu", "distribution_version": "20.04.6 LTS"}, "eol"},
		{map[string]any{"os": "Windows", "distribution": "Microsoft Windows 10 Enterprise", "distribution_version": "22H2"}, "eol"},
		{map[string]any{"os": "Windows", "distribution": "Microsoft Windows 11 Pro", "distribution_version": "23H2"}, "supported"},
		{map[string]any{"os": "Windows", "distribution": "Microsoft Windows Server 2016 Standard"}, "ending-soon"},
		{map[string]any{"os": "Darwin", "distribution": "macOS", "distribution_version": "14.5"}, "eol"},
		{map[string]any{"os": "Darwin", "distribution": "macOS", "distribution_version": "15.1"}, "supported"},
		{map[string]any{"os": "Linux", "distribution": "Arch Linux", "distribution_version": "rolling"}, "unknown"},
		{map[string]any{}, "unknown"},
	}
	for _, c := range cases {
		got := Check(c.summary, now)
		if got.State != c.state {
			t.Errorf("%v: got %s (%s), want %s", c.summary, got.State, got.Detail, c.state)
		}
	}
	if st := Check(cases[5].summary, now); !st.Estimated {
		t.Error("macOS should be marked estimated")
	}
}
