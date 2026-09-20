/*******************************************************************************
 * @file         windows_test.go
 * @brief        Tests for the Muster cook package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package cook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCookWindows(t *testing.T) {
	data, err := CookWindows("../../testdata/windows-demo-host")
	if err != nil {
		t.Fatalf("CookWindows: %v", err)
	}

	cases := map[string]any{
		"cpu_model":            "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz",
		"cpu_vendor":           "GenuineIntel",
		"cpu_speed_mhz":        2600,
		"num_cpus":             8,
		"num_cores":            4,
		"memory_mb":            16384, // 16777216 KB / 1024
		"memory_free_mb":       6144,  // 6291456 KB / 1024
		"os":                   "Windows",
		"distribution":         "Microsoft Windows Server 2022 Datacenter",
		"distribution_version": "10.0.20348",
		"kernel_version":       "20348",
		"os_architecture":      "64-bit",
		"hostname":             "WIN-DEMO01",
		"domain":               "WORKGROUP",
		"uptime":               "12 days, 4:33:10",
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

	if len(data) != len(cases) {
		t.Errorf("got %d fields, want exactly %d: %v", len(data), len(cases), data)
	}
}

func TestCookWindowsMissingFiles(t *testing.T) {
	// A directory with no capture files at all should still return
	// (empty map, nil error) -- same tolerant behavior as CookLinux.
	data, err := CookWindows(t.TempDir())
	if err != nil {
		t.Fatalf("CookWindows on empty dir: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty result, got %v", data)
	}
}

func TestCookWindowsPartialFiles(t *testing.T) {
	// Only cpu.txt present -- os.txt missing means no "os" field either
	// (CookWindows gates that on os.txt actually existing, not just
	// defaulting to "Windows" unconditionally).
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cpu.txt"), []byte("Name: Test CPU\nNumberOfLogicalProcessors: 2\n"), 0o644); err != nil {
		t.Fatalf("writing cpu.txt: %v", err)
	}

	data, err := CookWindows(dir)
	if err != nil {
		t.Fatalf("CookWindows: %v", err)
	}
	if data["cpu_model"] != "Test CPU" || data["num_cpus"] != 2 {
		t.Errorf("cpu fields not parsed: %v", data)
	}
	if _, ok := data["os"]; ok {
		t.Errorf("expected no \"os\" field when os.txt is absent, got %v", data["os"])
	}
}
