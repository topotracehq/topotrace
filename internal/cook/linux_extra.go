/*******************************************************************************
 * @file         linux_extra.go
 * @brief        Linux support for the newer capture categories beyond system_summary: disk usage, installed packages, running services, listening ports, local users, network interfaces, scheduled (cron) tasks, pending package updates, and firewall status.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Linux support for the newer capture categories beyond system_summary:
// disk usage, installed packages, running services, listening ports,
// local users, network interfaces, scheduled (cron) tasks, pending
// package updates, and firewall status. Kept in its own file rather than
// folded into linux.go so the original, already-tested CookLinux stays
// untouched -- this is purely additive.
//
// Every raw capture file here is the plain, unmodified output of one
// standard command agent/ubuntu/muster-agent.sh already knows how to
// run -- no parsing happens on the agent side, same division of labor as
// system_summary's five files.
package cook

import (
	"bufio"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// CookLinuxCategories returns every fact category this package knows how
// to cook from a Linux raw capture directory, keyed by category name.
// system_summary comes from the original, unchanged CookLinux; every
// other category is only present if its raw capture file existed and
// produced at least one recognizable row -- an agent run that couldn't
// collect, say, cron entries (no crontab command, or user has none)
// simply doesn't contribute that category this cook, rather than
// clobbering a previous good value with an empty one.
func CookLinuxCategories(rawDir string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}

	summary, err := CookLinux(rawDir)
	if err != nil {
		return nil, err
	}
	if len(summary) > 0 {
		out["system_summary"] = summary
	}

	type step struct {
		category string
		parse    func(string) (map[string]any, bool, error)
	}
	steps := []step{
		{"disk_usage", parseLinuxDiskUsage},
		{"installed_software", parseLinuxPackages},
		{"running_services", parseLinuxServices},
		{"listening_ports", parseLinuxPorts},
		{"local_users", parseLinuxUsers},
		{"network_interfaces", parseLinuxInterfaces},
		{"scheduled_tasks", parseLinuxCron},
		{"patch_update_status", parseLinuxUpdates},
		{"firewall_av_status", parseLinuxFirewall},
		{"browser_extensions", parseBrowserExtensions},
		{"tls_certificates", parseLinuxCerts},
	}
	for _, st := range steps {
		data, ok, err := st.parse(rawDir)
		if err != nil {
			return nil, err
		}
		if ok && len(data) > 0 {
			out[st.category] = data
		}
	}
	return out, nil
}

// listResult is the uniform shape every "N rows of the same thing"
// category is stored as: {"count": N, "items": [...]}. Kept as a plain
// map[string]any rather than a named struct since model.Fact.Data is
// deliberately opaque JSON, not a fixed schema.
func listResult(items []map[string]any) map[string]any {
	return map[string]any{"count": len(items), "items": items}
}

var dfLineRe = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+(.+)$`)

// parseLinuxDiskUsage expects `df -Pk` output (POSIX format, always in
// 1024-byte blocks, one line per filesystem -- unlike plain `df`, -P
// guarantees a filesystem name never wraps onto its own line).
func parseLinuxDiskUsage(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "df.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	skippedHeader := false
	for scanner.Scan() {
		line := scanner.Text()
		if !skippedHeader {
			skippedHeader = true
			continue // header row: "Filesystem 1024-blocks Used Available Capacity Mounted on"
		}
		m := dfLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		totalKB, _ := strconv.Atoi(m[2])
		usedKB, _ := strconv.Atoi(m[3])
		availKB, _ := strconv.Atoi(m[4])
		usePct, _ := strconv.Atoi(m[5])
		items = append(items, map[string]any{
			"filesystem":   m[1],
			"size_mb":      totalKB / 1024,
			"used_mb":      usedKB / 1024,
			"available_mb": availKB / 1024,
			"use_percent":  usePct,
			"mount":        m[6],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

var dpkgLineRe = regexp.MustCompile(`^ii\s+(\S+)\s+(\S+)\s+(\S+)`)

// parseLinuxPackages expects `dpkg -l` output; only "ii " (installed,
// configured) rows are kept -- everything else in dpkg's status column
// (half-installed, removed-but-not-purged, etc.) isn't "installed
// software" in the sense this category means.
func parseLinuxPackages(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "packages.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := dpkgLineRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		items = append(items, map[string]any{
			"name":         m[1],
			"version":      m[2],
			"architecture": m[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

// parseLinuxServices expects `systemctl list-units --type=service
// --state=running --no-legend --no-pager` output: UNIT LOAD ACTIVE SUB
// DESCRIPTION, whitespace-separated (description may itself contain
// spaces, so only the first four fields are parsed).
func parseLinuxServices(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "services.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		items = append(items, map[string]any{
			"name":         strings.TrimSuffix(fields[0], ".service"),
			"load_state":   fields[1],
			"active_state": fields[2],
			"sub_state":    fields[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

// parseLinuxPorts expects `ss -tln` output (no -p: works without root,
// unlike -p which silently omits the process column for a non-root
// caller anyway): State Recv-Q Send-Q Local-Address:Port Peer-Address:Port.
func parseLinuxPorts(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "ports.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "State") {
			continue // header, when present
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		addr, port := local, ""
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			addr, port = local[:idx], local[idx+1:]
		}
		items = append(items, map[string]any{
			"protocol":      "tcp",
			"state":         fields[0],
			"local_address": addr,
			"port":          port,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

// parseLinuxUsers expects a raw copy of /etc/passwd (colon-separated:
// username:password-placeholder:uid:gid:comment:home:shell).
func parseLinuxUsers(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "users.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		items = append(items, map[string]any{
			"username": fields[0],
			"uid":      uid,
			"home":     fields[5],
			"shell":    fields[6],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

// parseLinuxInterfaces expects `ip -o addr show` output (one line per
// address, `-o` keeping each on a single line): index: name family
// address/prefix ...
func parseLinuxInterfaces(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "interfaces.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		family := fields[2]
		if family != "inet" && family != "inet6" {
			continue
		}
		items = append(items, map[string]any{
			"interface": strings.TrimSuffix(fields[1], ":"),
			"family":    family,
			"address":   fields[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

// parseLinuxCron expects `crontab -l` output for the agent's own user --
// best-effort and often legitimately empty ("no crontab for X" is
// filtered out, not treated as an entry). System-wide /etc/cron.d isn't
// captured here; this is deliberately just what the reporting user's own
// crontab holds.
func parseLinuxCron(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "cron.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "no crontab for") {
			continue
		}
		items = append(items, map[string]any{"entry": line})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

var aptUpgradableRe = regexp.MustCompile(`^(\S+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*(\S+)\]`)

// parseLinuxUpdates expects `apt list --upgradable` output. apt prints a
// "Listing... Done" status line to the same stream on some versions --
// harmless here since it just won't match aptUpgradableRe.
func parseLinuxUpdates(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "updates.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := aptUpgradableRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		items = append(items, map[string]any{
			"package":           strings.SplitN(m[1], "/", 2)[0],
			"available_version": m[2],
			"current_version":   m[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return listResult(items), true, nil
}

// parseLinuxFirewall expects `ufw status` output. Absent on any box
// that doesn't run ufw (many don't -- iptables/nftables directly, or
// firewalld on non-Debian systems, are out of scope for this first
// pass) -- ok reports whether the file existed, but an unrecognized or
// empty result still means "nothing to store," same as the other
// parsers' empty-list case.
func parseLinuxFirewall(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "firewall.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	out := map[string]any{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Status:") {
			out["ufw_status"] = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return out, true, nil
}
