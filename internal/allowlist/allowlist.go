// Package allowlist cross-references a host's installed_software fact
// against operator-defined SoftwareRules -- deny rules (banned
// software) and allow rules (an explicit allowlist, once one exists for
// a scope). Deliberately small and honest, the same spirit as
// internal/vuln's static dataset and internal/policy's posture score:
// exact-or-prefix name matching, no version ranges, no package-manager
// metadata beyond name/version -- see model.SoftwareRule's doc comment
// for the exact semantics.
package allowlist

import (
	"strings"

	"muster/internal/model"
)

// Violation is one installed package that fails a rule in scope.
type Violation struct {
	Rule    string `json:"rule"`
	Kind    string `json:"kind"` // "deny" or "allow"
	Package string `json:"package"`
	Version string `json:"version"`
}

// Evaluate returns every violation of rules (already filtered to this
// host's scope by the caller, the same group-filtering convention
// internal/evaluator applies to model.Rule) against itemsRaw (an
// installed_software fact's Data["items"], as internal/cook produces
// it -- a list of {"name":..., "version":...} maps).
//
// Deny rules always apply. Allow rules only start enforcing once at
// least one exists in rules -- with none, Evaluate never reports an
// "unauthorized software" violation, since there's no allowlist to be
// unauthorized against yet.
func Evaluate(itemsRaw any, rules []model.SoftwareRule) []Violation {
	items := asItems(itemsRaw)
	if len(items) == 0 || len(rules) == 0 {
		return nil
	}

	var denyRules, allowRules []model.SoftwareRule
	for _, r := range rules {
		switch r.Kind {
		case "deny":
			denyRules = append(denyRules, r)
		case "allow":
			allowRules = append(allowRules, r)
		}
	}

	var violations []Violation
	for _, item := range items {
		name, _ := item["name"].(string)
		version, _ := item["version"].(string)
		if name == "" {
			continue
		}

		for _, r := range denyRules {
			if matches(r.Match, name) {
				violations = append(violations, Violation{Rule: r.Name, Kind: "deny", Package: name, Version: version})
				break // one deny hit per package is enough to report
			}
		}

		if len(allowRules) == 0 {
			continue // no allowlist configured for this scope -- "unknown," not "unauthorized"
		}
		allowed := false
		for _, r := range allowRules {
			if matches(r.Match, name) {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, Violation{Rule: "(not on allowlist)", Kind: "allow", Package: name, Version: version})
		}
	}
	return violations
}

// matches reports whether name satisfies pattern -- case-insensitive
// exact match, or a prefix match when pattern ends with "*".
func matches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	name = strings.ToLower(strings.TrimSpace(name))
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// asItems normalizes an installed_software fact's Data["items"] the
// same way internal/vuln.CheckWithFeed does -- []any (memstore, or
// pgstore after a JSONB round trip) or []map[string]any (constructed
// directly, e.g. in tests).
func asItems(itemsRaw any) []map[string]any {
	switch v := itemsRaw.(type) {
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, raw := range v {
			if m, ok := raw.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case []map[string]any:
		return v
	default:
		return nil
	}
}
