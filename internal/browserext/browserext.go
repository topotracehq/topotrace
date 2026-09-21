/*******************************************************************************
 * @file         browserext.go
 * @brief        Package browserext evaluates a host's browser_extensions fact (see internal/cook.parseBrowserExtensions) for risk: the browser is where most of an endpoint's sensitive work happens now, and an extension with broad host access plus reques...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package browserext evaluates a host's browser_extensions fact (see
// internal/cook.parseBrowserExtensions) for risk: the browser is where
// most of an endpoint's sensitive work happens now, and an extension
// with broad host access plus request-interception or cookie
// permissions can read every page and credential that passes through
// it -- the same visibility-at-the-browser-layer problem enterprise
// browser products exist to solve. This is the browser-extension
// counterpart to internal/allowlist's Shadow AI detection: a fixed,
// explainable ruleset over what the agent actually observed, not a
// reputation service.
//
// Like the vulnerability dataset and Shadow AI patterns, the known-bad
// ID list is a small, curated illustration (and the entries here are
// documented placeholders, not a claim about any real extension ID);
// a real product would sync it from a maintained feed.
package browserext

import (
	"fmt"
	"sort"
	"strings"
)

// Extension is one installed extension as the cook pipeline stores it.
type Extension struct {
	Browser         string   `json:"browser"`
	Profile         string   `json:"profile"`
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	ManifestVersion int      `json:"manifest_version"`
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`
	FromWebStore    bool     `json:"from_web_store"`
}

// Finding is one evaluated extension with its risk verdict.
type Finding struct {
	Extension
	Level   string   `json:"level"` // "high", "medium", "low"
	Reasons []string `json:"reasons"`
	Score   int      `json:"score"` // 0-100, higher is riskier
}

// sensitivePermissions is what an extension can ask for that lets it
// see or change more than its own UI, with a weight for how much.
var sensitivePermissions = map[string]int{
	"webRequest": 20, "webRequestBlocking": 20, "declarativeNetRequestWithHostAccess": 15,
	"cookies": 20, "debugger": 30, "nativeMessaging": 25, "proxy": 25, "management": 15,
	"history": 10, "tabs": 5, "scripting": 10, "clipboardRead": 15, "downloads": 5,
	"webNavigation": 5, "privacy": 15, "contentSettings": 10, "browsingData": 10,
	"identity": 10, "desktopCapture": 15, "tabCapture": 15, "pageCapture": 15,
}

// KnownBad is the curated deny-list, keyed by extension ID, valued by
// the reason. Illustrative placeholder entries -- see the package doc.
var KnownBad = map[string]string{
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "demo placeholder: listed as data-exfiltrating adware",
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": "demo placeholder: listed as credential-harvesting",
}

// Trusted is the curated allow-list: extensions whose broad permissions
// are the point (an ad blocker has to see every request) and whose
// publisher is well established. A trusted extension is reported with
// its permissions intact but scored "low", with the reason stated, so
// an ad blocker doesn't drown out a sideloaded wallet helper on the
// same host. Illustrative and small, like KnownBad; the real version
// of this is an operator-maintained sanctioned-extensions list.
var Trusted = map[string]string{
	"cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
	"ghbmnnjooekpmoecnnnilnnbdlolhkhi": "Google Docs Offline",
	"nmmhkkegccagdldgiimedpiccmgmieda": "Google Wallet",
	"hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
	"nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
	"aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password",
	"eimadpbcbfnmbkopoojfekhnkhdbieeh": "Dark Reader",
	"gighmmpiobklfepjocnamgkkbiglidom": "AdBlock",
}

// FromFact converts a browser_extensions fact's "items" into Extensions.
func FromFact(items any) []Extension {
	list, ok := items.([]any)
	if !ok {
		if typed, ok2 := items.([]map[string]any); ok2 {
			for _, m := range typed {
				list = append(list, m)
			}
		}
	}
	out := make([]Extension, 0, len(list))
	for _, raw := range list {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		e := Extension{
			Browser: str(m["browser"]), Profile: str(m["profile"]), ID: str(m["id"]),
			Name: str(m["name"]), Version: str(m["version"]),
			Permissions: strs(m["permissions"]), HostPermissions: strs(m["host_permissions"]),
		}
		switch v := m["manifest_version"].(type) {
		case float64:
			e.ManifestVersion = int(v)
		case int:
			e.ManifestVersion = v
		}
		if b, ok := m["from_web_store"].(bool); ok {
			e.FromWebStore = b
		}
		out = append(out, e)
	}
	return out
}

// Evaluate scores every extension. Findings come back riskiest first.
func Evaluate(exts []Extension) []Finding {
	out := make([]Finding, 0, len(exts))
	for _, e := range exts {
		f := Finding{Extension: e}
		if reason, bad := KnownBad[e.ID]; bad {
			f.Score += 60
			f.Reasons = append(f.Reasons, "on the known-bad list: "+reason)
		}
		broad := false
		for _, h := range e.HostPermissions {
			if isBroadHost(h) {
				broad = true
				break
			}
		}
		if broad {
			f.Score += 25
			f.Reasons = append(f.Reasons, "can read and change data on all websites")
		}
		var sens []string
		for _, p := range e.Permissions {
			if w, ok := sensitivePermissions[p]; ok {
				f.Score += w
				sens = append(sens, p)
			}
		}
		if len(sens) > 0 {
			sort.Strings(sens)
			f.Reasons = append(f.Reasons, "sensitive permissions: "+strings.Join(sens, ", "))
		}
		if broad && hasAny(e.Permissions, "webRequest", "webRequestBlocking", "cookies", "scripting") {
			f.Score += 15
			f.Reasons = append(f.Reasons, "broad host access combined with request/cookie/script access")
		}
		if !e.FromWebStore {
			f.Score += 10
			f.Reasons = append(f.Reasons, "not installed from an official web store (sideloaded or unpacked)")
		}
		if e.ManifestVersion > 0 && e.ManifestVersion < 3 {
			f.Score += 5
			f.Reasons = append(f.Reasons, fmt.Sprintf("manifest v%d (deprecated by Chrome)", e.ManifestVersion))
		}
		if f.Score > 100 {
			f.Score = 100
		}
		if name, ok := Trusted[e.ID]; ok {
			if _, bad := KnownBad[e.ID]; !bad {
				f.Score = 5
				f.Reasons = []string{"on the trusted list (" + name + "): broad permissions are expected for what it does"}
			}
		}
		switch {
		case f.Score >= 50:
			f.Level = "high"
		case f.Score >= 20:
			f.Level = "medium"
		default:
			f.Level = "low"
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

// Risky returns only the medium/high findings -- what a compliance
// check or a fleet tile counts.
func Risky(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Level != "low" {
			out = append(out, f)
		}
	}
	return out
}

func isBroadHost(h string) bool {
	h = strings.ToLower(h)
	return h == "<all_urls>" || h == "*://*/*" || h == "http://*/*" || h == "https://*/*" || strings.HasPrefix(h, "*://*/")
}

func hasAny(list []string, wants ...string) bool {
	for _, l := range list {
		for _, w := range wants {
			if l == w {
				return true
			}
		}
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strs(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
