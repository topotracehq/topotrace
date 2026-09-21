/*******************************************************************************
 * @file         linux.go
 * @brief        Package cook turns a raw capture directory (whatever an agent uploaded and the ingest layer unpacked) into structured facts.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package cook turns a raw capture directory (whatever an agent uploaded
// and the ingest layer unpacked) into structured facts. One file per
// platform, same pattern in each: read the plain-text capture files a
// packet directory holds, regex/scan the parts that matter, return a
// map[string]any ready to hand to the store.
//
// The raw capture contract below (cpuinfo.txt, meminfo.txt, uname.txt,
// os-release.txt, uptime.txt) is TopoTrace's own -- designed fresh for this
// project, not copied from any prior system. It intentionally mirrors
// the general shape of "capture a few plain-text command outputs per
// host" that this whole class of inventory tool uses, because that
// approach is genuinely a sound one: cheap for an agent to produce,
// trivial to test against without a real target host, human-readable on
// disk for debugging.
package cook

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	cpuMHzRe    = regexp.MustCompile(`(?i)^cpu MHz\s*:\s*(.+)$`)
	modelNameRe = regexp.MustCompile(`(?i)^model name\s*:\s*(.+)$`)
	vendorIDRe  = regexp.MustCompile(`(?i)^vendor_id\s*:\s*(.+)$`)
	processorRe = regexp.MustCompile(`(?i)^processor\s*:`)

	memTotalRe  = regexp.MustCompile(`(?i)^MemTotal:\s*(\d+)\s*kB`)
	swapTotalRe = regexp.MustCompile(`(?i)^SwapTotal:\s*(\d+)\s*kB`)
	swapFreeRe  = regexp.MustCompile(`(?i)^SwapFree:\s*(\d+)\s*kB`)

	osReleaseKV = regexp.MustCompile(`^([A-Z_]+)=(.*)$`)
)

// CookLinux reads a Linux raw capture directory and returns a flat map of
// system-summary facts. Missing files are tolerated -- whatever's there
// gets parsed, whatever's missing is simply absent from the result --
// since a real agent run can legitimately fail to collect any one piece.
func CookLinux(rawDir string) (map[string]any, error) {
	summary := map[string]any{}

	if err := parseCPUInfo(filepath.Join(rawDir, "cpuinfo.txt"), summary); err != nil {
		return nil, err
	}
	if err := parseMemInfo(filepath.Join(rawDir, "meminfo.txt"), summary); err != nil {
		return nil, err
	}
	if err := parseUname(filepath.Join(rawDir, "uname.txt"), summary); err != nil {
		return nil, err
	}
	if err := parseOSRelease(filepath.Join(rawDir, "os-release.txt"), summary); err != nil {
		return nil, err
	}
	if err := parseUptime(filepath.Join(rawDir, "uptime.txt"), summary); err != nil {
		return nil, err
	}

	return summary, nil
}

func openIfExists(path string) (*os.File, bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cook: opening %s: %w", path, err)
	}
	return f, true, nil
}

func parseCPUInfo(path string, out map[string]any) error {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return err
	}
	defer f.Close()

	numCPUs := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := cpuMHzRe.FindStringSubmatch(line); m != nil {
			if mhz, err := strconv.ParseFloat(strings.TrimSpace(m[1]), 64); err == nil {
				out["cpu_speed_mhz"] = int(mhz)
			}
		}
		if m := modelNameRe.FindStringSubmatch(line); m != nil {
			out["cpu_model"] = strings.TrimSpace(m[1])
		}
		if m := vendorIDRe.FindStringSubmatch(line); m != nil {
			out["cpu_vendor"] = strings.TrimSpace(m[1])
		}
		if processorRe.MatchString(line) {
			numCPUs++
		}
	}
	if numCPUs > 0 {
		out["num_cpus"] = numCPUs
	}
	return scanner.Err()
}

func parseMemInfo(path string, out map[string]any) error {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := memTotalRe.FindStringSubmatch(line); m != nil {
			if kb, err := strconv.Atoi(m[1]); err == nil {
				out["memory_mb"] = kb / 1024
			}
		}
		if m := swapTotalRe.FindStringSubmatch(line); m != nil {
			if kb, err := strconv.Atoi(m[1]); err == nil {
				out["swap_total_mb"] = kb / 1024
			}
		}
		if m := swapFreeRe.FindStringSubmatch(line); m != nil {
			if kb, err := strconv.Atoi(m[1]); err == nil {
				out["swap_free_mb"] = kb / 1024
			}
		}
	}
	return scanner.Err()
}

// parseUname expects the single-line output of `uname -a`, e.g.:
//
//	Linux webhost01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 2023 x86_64 GNU/Linux
func parseUname(path string, out map[string]any) error {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return scanner.Err()
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) >= 3 {
		out["os"] = fields[0]
		out["kernel_version"] = fields[2]
	}
	return scanner.Err()
}

// parseOSRelease expects the standard /etc/os-release KEY=VALUE format
// (quoted values tolerated).
func parseOSRelease(path string, out map[string]any) error {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := osReleaseKV.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		value := strings.Trim(m[2], `"`)
		switch m[1] {
		case "NAME":
			out["distribution"] = value
		case "VERSION":
			out["distribution_version"] = value
		}
	}
	return scanner.Err()
}

func parseUptime(path string, out map[string]any) error {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		out["uptime"] = strings.TrimSpace(scanner.Text())
	}
	return scanner.Err()
}
