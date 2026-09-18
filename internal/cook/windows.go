/*******************************************************************************
 * @file         windows.go
 * @brief        Windows support for the cook pipeline.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Windows support for the cook pipeline. Muster's own capture-file
// contract for this platform (cpu.txt, memory.txt, os.txt, system.txt --
// see agent/windows/muster-agent.ps1) is a flat "Key: Value" format
// rather than Linux's mix of /proc-style and KEY=VALUE files, because
// that's what a PowerShell agent can produce with a couple of lines per
// file (`"Name: $($cpu.Name)"`) with no quoting/escaping to get wrong --
// simplicity on the producing side mattered more here than matching
// Linux's file format for its own sake.
package cook

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var winKVRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*)\s*:\s*(.*)$`)

// parseWindowsKV reads a flat "Key: Value" capture file (one line per
// fact) into a plain string map. Missing file is tolerated the same way
// the Linux parsers tolerate it -- ok reports whether the file existed.
func parseWindowsKV(path string) (kv map[string]string, ok bool, err error) {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	kv = map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := winKVRe.FindStringSubmatch(scanner.Text()); m != nil {
			kv[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return kv, true, scanner.Err()
}

func kvInt(kv map[string]string, key string, out map[string]any, field string) {
	if v, ok := kv[key]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			out[field] = n
		}
	}
}

func kvString(kv map[string]string, key string, out map[string]any, field string) {
	if v, ok := kv[key]; ok && v != "" {
		out[field] = v
	}
}

// CookWindows reads a Windows raw capture directory and returns a flat
// map of system-summary facts. Missing files are tolerated -- same
// "collect whatever's there" policy as CookLinux.
//
// Field names are deliberately shared with CookLinux's vocabulary where
// a Windows concept maps reasonably cleanly onto a Linux one (os,
// distribution, distribution_version, cpu_model, cpu_vendor,
// cpu_speed_mhz, num_cpus, memory_mb, uptime) -- so the web UI's card
// summary and formatting work unmodified across platforms, no
// per-platform display logic needed. kernel_version maps to the Windows
// OS build number: not literally a kernel version, but the closest
// single-field analog Windows has, and it keeps the field populated
// instead of platform-conditionally absent. A few fields (num_cores,
// memory_free_mb, os_architecture, hostname, domain) have no Linux
// counterpart in this project yet and are simply extra.
func CookWindows(rawDir string) (map[string]any, error) {
	summary := map[string]any{}

	cpu, _, err := parseWindowsKV(filepath.Join(rawDir, "cpu.txt"))
	if err != nil {
		return nil, err
	}
	kvString(cpu, "Name", summary, "cpu_model")
	kvString(cpu, "Manufacturer", summary, "cpu_vendor")
	kvInt(cpu, "MaxClockSpeedMHz", summary, "cpu_speed_mhz")
	kvInt(cpu, "NumberOfLogicalProcessors", summary, "num_cpus")
	kvInt(cpu, "NumberOfCores", summary, "num_cores")

	mem, _, err := parseWindowsKV(filepath.Join(rawDir, "memory.txt"))
	if err != nil {
		return nil, err
	}
	if v, ok := mem["TotalVisibleMemoryKB"]; ok {
		if kb, err := strconv.Atoi(v); err == nil {
			summary["memory_mb"] = kb / 1024
		}
	}
	if v, ok := mem["FreePhysicalMemoryKB"]; ok {
		if kb, err := strconv.Atoi(v); err == nil {
			summary["memory_free_mb"] = kb / 1024
		}
	}

	osInfo, osOK, err := parseWindowsKV(filepath.Join(rawDir, "os.txt"))
	if err != nil {
		return nil, err
	}
	if osOK {
		summary["os"] = "Windows"
		kvString(osInfo, "Caption", summary, "distribution")
		kvString(osInfo, "Version", summary, "distribution_version")
		kvString(osInfo, "BuildNumber", summary, "kernel_version")
		kvString(osInfo, "OSArchitecture", summary, "os_architecture")
	}

	sys, _, err := parseWindowsKV(filepath.Join(rawDir, "system.txt"))
	if err != nil {
		return nil, err
	}
	kvString(sys, "Hostname", summary, "hostname")
	kvString(sys, "Domain", summary, "domain")
	kvString(sys, "Uptime", summary, "uptime")

	return summary, nil
}
