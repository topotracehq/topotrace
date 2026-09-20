/*******************************************************************************
 * @file         windows_extra.go
 * @brief        Windows support for the newer capture categories beyond system_summary: disk usage, installed software, running services, listening ports, local users, network interfaces, scheduled tasks, installed patches, and firewall status.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Windows support for the newer capture categories beyond
// system_summary: disk usage, installed software, running services,
// listening ports, local users, network interfaces, scheduled tasks,
// installed patches, and firewall status. Kept in its own file rather
// than folded into windows.go so the original, already-tested
// CookWindows stays untouched -- this is purely additive.
//
// Unlike system_summary's flat "Key: Value" files, every category here
// is naturally a list of rows (N packages, N services, ...), so the
// agent captures each as CSV (PowerShell's own `ConvertTo-Csv
// -NoTypeInformation`, no hand-rolled quoting to get wrong) instead of
// inventing a second flat-file convention -- encoding/csv parses it
// exactly, headers and all, with no format-specific code here.
package cook

import (
	"encoding/csv"
	"fmt"
	"path/filepath"
	"strconv"
)

// parseWindowsCSV reads a PowerShell `ConvertTo-Csv -NoTypeInformation`
// file into a slice of header-keyed row maps. Tolerates a short row
// (fewer columns than the header) the same way the rest of this package
// tolerates a missing field -- the column is simply absent from that
// row's map.
func parseWindowsCSV(path string) ([]map[string]string, bool, error) {
	f, ok, err := openIfExists(path)
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, true, fmt.Errorf("cook: parsing csv %s: %w", path, err)
	}
	if len(records) < 2 {
		return nil, true, nil // header only, or empty -- zero rows, not an error
	}
	header := records[0]
	rows := make([]map[string]string, 0, len(records)-1)
	for _, rec := range records[1:] {
		row := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, true, nil
}

// CookWindowsCategories returns every fact category this package knows
// how to cook from a Windows raw capture directory, keyed by category
// name. system_summary comes from the original, unchanged CookWindows;
// every other category is only present if its CSV capture file existed
// and produced at least one row.
func CookWindowsCategories(rawDir string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}

	summary, err := CookWindows(rawDir)
	if err != nil {
		return nil, err
	}
	if len(summary) > 0 {
		out["system_summary"] = summary
	}

	if data, err := cookWinDiskUsage(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["disk_usage"] = data
	}
	if data, err := cookWinSoftware(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["installed_software"] = data
	}
	if data, err := cookWinServices(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["running_services"] = data
	}
	if data, err := cookWinPorts(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["listening_ports"] = data
	}
	if data, err := cookWinUsers(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["local_users"] = data
	}
	if data, err := cookWinInterfaces(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["network_interfaces"] = data
	}
	if data, err := cookWinScheduledTasks(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["scheduled_tasks"] = data
	}
	if data, err := cookWinHotfixes(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["patch_update_status"] = data
	}
	if data, err := cookWinFirewall(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["firewall_av_status"] = data
	}
	if data, ok, err := parseBrowserExtensions(rawDir); err != nil {
		return nil, err
	} else if ok && len(data) > 0 {
		out["browser_extensions"] = data
	}
	if data, err := cookWinCerts(rawDir); err != nil {
		return nil, err
	} else if data != nil {
		out["tls_certificates"] = data
	}

	return out, nil
}

func cookWinDiskUsage(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "disks.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		sizeB, _ := strconv.ParseInt(r["Size"], 10, 64)
		freeB, _ := strconv.ParseInt(r["FreeSpace"], 10, 64)
		items = append(items, map[string]any{
			"filesystem":   r["DeviceID"],
			"size_mb":      int(sizeB / (1024 * 1024)),
			"available_mb": int(freeB / (1024 * 1024)),
		})
	}
	return listResult(items), nil
}

func cookWinSoftware(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "software.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		if r["DisplayName"] == "" {
			continue
		}
		items = append(items, map[string]any{
			"name":    r["DisplayName"],
			"version": r["DisplayVersion"],
		})
	}
	return listResult(items), nil
}

func cookWinServices(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "services_running.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{
			"name":         r["Name"],
			"display_name": r["DisplayName"],
			"status":       r["Status"],
		})
	}
	return listResult(items), nil
}

func cookWinPorts(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "ports.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{
			"protocol":      "tcp",
			"local_address": r["LocalAddress"],
			"port":          r["LocalPort"],
		})
	}
	return listResult(items), nil
}

func cookWinUsers(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "users.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{
			"username": r["Name"],
			"enabled":  r["Enabled"],
		})
	}
	return listResult(items), nil
}

func cookWinInterfaces(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "netadapters.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{
			"interface": r["InterfaceAlias"],
			"family":    r["AddressFamily"],
			"address":   r["IPAddress"],
		})
	}
	return listResult(items), nil
}

func cookWinScheduledTasks(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "scheduledtasks.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{
			"name":  r["TaskName"],
			"state": r["State"],
		})
	}
	return listResult(items), nil
}

// cookWinHotfixes reports installed patches (Get-HotFix), not pending
// ones -- Windows Update's actual pending-update list needs the Update
// Session COM API, a materially bigger piece of work than this pass
// covers. Documented here, not glossed over: this category answers "what
// has this host already installed," the same direction Linux's
// patch_update_status answers "what's outstanding" -- an intentional,
// stated asymmetry between the two platforms' first passes, not a bug.
func cookWinHotfixes(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "hotfixes.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		items = append(items, map[string]any{
			"id":           r["HotFixID"],
			"installed_on": r["InstalledOn"],
		})
	}
	return listResult(items), nil
}

func cookWinFirewall(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "firewall.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	out := map[string]any{}
	for _, r := range rows {
		if r["Name"] == "" {
			continue
		}
		out[r["Name"]+"_enabled"] = r["Enabled"]
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
