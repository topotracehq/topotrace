/*******************************************************************************
 * @file         frameworks.go
 * @brief        Part of the Muster compliance module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package compliance

import (
	"fmt"
	"strings"

	"muster/internal/browserext"
)

// The two frameworks below map Muster's real signals onto the language
// of two real standards -- the HIPAA Security Rule and NIST SP 800-53.
// Same honesty note as Baseline, stated again because the names carry
// weight: these are ILLUSTRATIVE mappings of the handful of controls a
// fleet-inventory tool can actually observe evidence for, written so
// the framework abstraction is demonstrably pluggable (three frameworks
// evaluated by one Evaluate, selectable per request), not a certified
// or complete control mapping. A real compliance product would license
// and maintain a reviewed mapping; each check here names the control it
// draws on so a reader can judge the stretch for themselves.

// firewallState reports whether the host's firewall is known to be on,
// known to be off, or unknown (category absent or platform unhandled).
func firewallState(in Input) (on bool, known bool) {
	fw, ok := in.Facts["firewall_av_status"]
	if !ok {
		return false, false
	}
	switch in.Host.Platform {
	case "linux":
		status, _ := fw.Data["ufw_status"].(string)
		if status == "" {
			return false, false
		}
		return status == "active", true
	case "windows":
		seen := false
		for k, v := range fw.Data {
			if !strings.HasSuffix(k, "_enabled") {
				continue
			}
			seen = true
			if s, _ := v.(string); s == "False" {
				return false, true
			}
		}
		return seen, seen
	}
	return false, false
}

// pendingUpdates returns the Linux pending-update count, or -1 when the
// host doesn't report one (Windows reports installed hotfixes instead;
// see internal/policy.ComputePosture's note).
func pendingUpdates(in Input) int {
	if in.Host.Platform != "linux" {
		return -1
	}
	pu, ok := in.Facts["patch_update_status"]
	if !ok {
		return -1
	}
	switch n := pu.Data["count"].(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return -1
}

func hasFact(in Input, category string) bool {
	_, ok := in.Facts[category]
	return ok
}

// HIPAA is an illustrative mapping onto HIPAA Security Rule safeguards
// (45 CFR 164.308 administrative, 164.312 technical).
var HIPAA = Framework{
	ID:          "hipaa",
	Name:        "HIPAA Security Rule (illustrative)",
	Description: "Illustrative mapping of Muster's signals onto HIPAA Security Rule safeguards -- evidence for a handful of controls, not a certified assessment.",
	checks: []check{
		{
			id:          "164.308(a)(1)(ii)(A) risk analysis",
			description: "Host is included in an ongoing, current risk analysis (reported within the staleness window)",
			evaluate: func(in Input) (bool, string) {
				if in.Stale {
					return false, "host is stale -- its current risk is unknown"
				}
				return true, ""
			},
		},
		{
			id:          "164.308(a)(5)(ii)(B) protection from malicious software",
			description: "No known-vulnerable installed packages and no software the organization has denied",
			evaluate: func(in Input) (bool, string) {
				var parts []string
				if len(in.VulnFindings) > 0 {
					parts = append(parts, VulnDetail(in.VulnFindings))
				}
				if n := len(in.SoftwareViolations); n > 0 {
					parts = append(parts, fmt.Sprintf("%d denied software item(s)", n))
				}
				if len(parts) > 0 {
					return false, strings.Join(parts, "; ")
				}
				return true, ""
			},
		},
		{
			id:          "164.308(a)(5)(ii)(A) security reminders / patching",
			description: "No pending OS package updates outstanding (Linux; Windows reports installed hotfixes only)",
			evaluate: func(in Input) (bool, string) {
				if n := pendingUpdates(in); n > 0 {
					return false, fmt.Sprintf("%d pending update(s)", n)
				}
				return true, ""
			},
		},
		{
			id:          "164.312(a)(1) access control (network boundary)",
			description: "Host firewall is active",
			evaluate: func(in Input) (bool, string) {
				if on, known := firewallState(in); known && !on {
					return false, "firewall is inactive"
				}
				return true, ""
			},
		},
		{
			id:          "164.312(b) audit controls",
			description: "Host reports an inventory Muster can audit against (system summary and installed software present)",
			evaluate: func(in Input) (bool, string) {
				if !hasFact(in, "system_summary") || !hasFact(in, "installed_software") {
					return false, "system_summary and/or installed_software never reported"
				}
				return true, ""
			},
		},
		{
			id:          "164.312(e)(1) transmission security (browser layer)",
			description: "No browser extension that can read or alter every site's traffic, and no unsanctioned AI tool that could exfiltrate PHI",
			evaluate: func(in Input) (bool, string) {
				var parts []string
				if n := len(browserext.Risky(in.BrowserExtensions)); n > 0 {
					parts = append(parts, fmt.Sprintf("%d risky browser extension(s)", n))
				}
				if n := len(in.ShadowAIViolations); n > 0 {
					parts = append(parts, fmt.Sprintf("%d unsanctioned AI tool(s)", n))
				}
				if len(parts) > 0 {
					return false, strings.Join(parts, "; ")
				}
				return true, ""
			},
		},
	},
}

// NIST80053 is an illustrative mapping onto a handful of NIST SP 800-53
// Rev. 5 controls.
var NIST80053 = Framework{
	ID:          "nist-800-53",
	Name:        "NIST SP 800-53 (illustrative subset)",
	Description: "Illustrative mapping of Muster's signals onto six NIST SP 800-53 Rev. 5 controls -- not a certified or complete mapping.",
	checks: []check{
		{
			id:          "CM-8 system component inventory",
			description: "Host is present in the inventory and current (not stale)",
			evaluate: func(in Input) (bool, string) {
				if in.Stale {
					return false, "host is stale"
				}
				return true, ""
			},
		},
		{
			id:          "SI-2 flaw remediation",
			description: "No known-vulnerable installed packages and no pending OS updates",
			evaluate: func(in Input) (bool, string) {
				var parts []string
				if len(in.VulnFindings) > 0 {
					parts = append(parts, VulnDetail(in.VulnFindings))
				}
				if n := pendingUpdates(in); n > 0 {
					parts = append(parts, fmt.Sprintf("%d pending update(s)", n))
				}
				if len(parts) > 0 {
					return false, strings.Join(parts, "; ")
				}
				return true, ""
			},
		},
		{
			id:          "CM-7 least functionality",
			description: "No denied or unauthorized software installed",
			evaluate: func(in Input) (bool, string) {
				if n := len(in.SoftwareViolations); n > 0 {
					return false, fmt.Sprintf("%d software violation(s)", n)
				}
				return true, ""
			},
		},
		{
			id:          "SC-7 boundary protection",
			description: "Host firewall is active",
			evaluate: func(in Input) (bool, string) {
				if on, known := firewallState(in); known && !on {
					return false, "firewall is inactive"
				}
				return true, ""
			},
		},
		{
			id:          "CM-11 user-installed software",
			description: "No unsanctioned AI tools and no risky browser extensions installed by users",
			evaluate: func(in Input) (bool, string) {
				var parts []string
				if n := len(in.ShadowAIViolations); n > 0 {
					parts = append(parts, fmt.Sprintf("%d unsanctioned AI tool(s)", n))
				}
				if n := len(browserext.Risky(in.BrowserExtensions)); n > 0 {
					parts = append(parts, fmt.Sprintf("%d risky browser extension(s)", n))
				}
				if len(parts) > 0 {
					return false, strings.Join(parts, "; ")
				}
				return true, ""
			},
		},
		{
			id:          "RA-5 vulnerability monitoring and scanning",
			description: "Posture score of at least 70 (the host is being scored and isn't failing badly)",
			evaluate: func(in Input) (bool, string) {
				if in.Posture.Score < 70 {
					return false, fmt.Sprintf("posture score is %d", in.Posture.Score)
				}
				return true, ""
			},
		},
	},
}
