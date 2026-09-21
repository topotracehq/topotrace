/*******************************************************************************
 * @file         linux_test.go
 * @brief        Tests for the Muster cook package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package cook

import "testing"

func TestCookLinux(t *testing.T) {
	data, err := CookLinux("../../testdata/linux-demo-host")
	if err != nil {
		t.Fatalf("CookLinux: %v", err)
	}

	cases := map[string]any{
		"num_cpus":             2,
		"cpu_model":            "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
		"cpu_vendor":           "GenuineIntel",
		"cpu_speed_mhz":        2500,
		"memory_mb":            31888, // 32654320 kB / 1024, integer division
		"swap_total_mb":        4095,  // 4194300 kB / 1024, integer division
		"swap_free_mb":         4095,
		"os":                   "Linux",
		"kernel_version":       "5.15.0-91-generic",
		"distribution":         "Ubuntu",
		"distribution_version": "22.04.3 LTS (Jammy Jellyfish)",
	}

	for field, want := range cases {
		got, ok := data[field]
		if !ok {
			t.Errorf("field %q missing from parsed data", field)
			continue
		}
		if got != want {
			t.Errorf("field %q = %v (%T), want %v (%T)", field, got, got, want, want)
		}
	}

	if _, ok := data["uptime"]; !ok {
		t.Errorf("field %q missing from parsed data", "uptime")
	}
}

func TestCookLinuxMissingFiles(t *testing.T) {
	// A directory with no capture files at all should still return
	// (empty map, nil error) -- a partial/failed agent collection
	// shouldn't crash the pipeline, just produce fewer facts.
	data, err := CookLinux(t.TempDir())
	if err != nil {
		t.Fatalf("CookLinux on empty dir: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty result, got %v", data)
	}
}
