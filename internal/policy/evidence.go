/*******************************************************************************
 * @file         evidence.go
 * @brief        Part of the TopoTrace policy module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package policy

import (
	"strings"
	"time"

	"muster/internal/model"
)

// Evidence describes collection confidence, not whether a security check passed.
type Evidence struct {
	Category    string     `json:"category"`
	Label       string     `json:"label"`
	State       string     `json:"state"`
	Detail      string     `json:"detail"`
	CollectedAt *time.Time `json:"collected_at,omitempty"`
}

type Coverage struct {
	Percent  int        `json:"percent"`
	Verified int        `json:"verified"`
	Expected int        `json:"expected"`
	Evidence []Evidence `json:"evidence"`
}

// CollectionCoverage measures four useful security evidence categories. Unsupported
// collectors remain explicitly unknown rather than inflating the percentage.
func CollectionCoverage(platform string, facts map[string]model.Fact, now time.Time) Coverage {
	c := Coverage{Expected: 4, Evidence: []Evidence{}}
	for _, spec := range []struct{ category, label string }{
		{"system_summary", "Operating system"}, {"installed_software", "Installed software"},
		{"firewall_av_status", "Firewall status"}, {"patch_update_status", "Pending updates"},
	} {
		e := Evidence{Category: spec.category, Label: spec.label, State: "unknown", Detail: "No usable evidence collected"}
		f, exists := facts[spec.category]
		usable := exists && len(f.Data) > 0
		switch spec.category {
		case "system_summary":
			os, _ := f.Data["os"].(string)
			usable = strings.TrimSpace(os) != ""
		case "installed_software":
			_, usable = asNumber(f.Data["count"])
			_, items := f.Data["items"]
			usable = usable && items
		case "firewall_av_status":
			usable = false
			if platform == "linux" {
				v, _ := f.Data["ufw_status"].(string)
				usable = v == "active" || v == "inactive"
			}
			if platform == "windows" {
				usable = true
				for _, profile := range []string{"Domain_enabled", "Private_enabled", "Public_enabled"} {
					v, _ := f.Data[profile].(string)
					usable = usable && (v == "True" || v == "False")
				}
			}
		case "patch_update_status":
			n, ok := asNumber(f.Data["count"])
			usable = platform == "linux" && ok && n >= 0
			if platform != "linux" {
				e.Detail = "Pending-update collection is not supported on this platform"
			}
		}
		if !f.CookedAt.IsZero() {
			at := f.CookedAt
			e.CollectedAt = &at
		}
		if usable {
			switch {
			case f.CookedAt.IsZero():
				e.Detail = "Collection time is unavailable"
			case f.CookedAt.After(now.Add(5 * time.Minute)):
				e.Detail = "Collection time is in the future; check clock settings"
			case IsStale(f.CookedAt, now):
				e.State = "outdated"
				e.Detail = "Evidence is older than 24 hours"
			default:
				e.State = "verified"
				e.Detail = "Usable evidence collected within 24 hours"
				c.Verified++
			}
		}
		c.Evidence = append(c.Evidence, e)
	}
	c.Percent = c.Verified * 100 / c.Expected
	return c
}

func ComputePostureAt(platform string, facts map[string]model.Fact, stale bool, now time.Time) PostureResult {
	p := ComputePosture(platform, facts, stale)
	p.Coverage = CollectionCoverage(platform, facts, now)
	return p
}
