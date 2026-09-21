/*******************************************************************************
 * @file         sprawl_test.go
 * @brief        Tests for the TopoTrace sprawl package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package sprawl

import "testing"

func TestRollup(t *testing.T) {
	rep := Rollup(HostSoftware{
		"a": {"Zoom", "Slack", "Visual Studio Code"},
		"b": {"Microsoft Teams", "zoom (64-bit)", "Adobe Acrobat DC"},
		"c": {"nginx", "curl"},
	})
	if rep.TotalHosts != 3 || rep.HostsCovered != 2 {
		t.Fatalf("%+v", rep)
	}
	if rep.Installs[0].Product != "Zoom" || rep.Installs[0].Seats != 2 {
		t.Fatalf("zoom should lead: %+v", rep.Installs)
	}
	if rep.LicensedSeats != 5 { // zoom 2 + slack 1 + teams 1 + acrobat 1; vscode unlicensed
		t.Fatalf("licensed seats: %d", rep.LicensedSeats)
	}
	if len(rep.Overlaps) != 1 || rep.Overlaps[0].Category != "video-conferencing" || len(rep.Overlaps[0].Products) != 2 {
		t.Fatalf("overlaps: %+v", rep.Overlaps)
	}
}
