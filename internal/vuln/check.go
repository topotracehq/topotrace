package vuln

import (
	"regexp"
	"strconv"
	"strings"
)

// Finding is one installed package whose version matched a Dataset
// entry's vulnerable ceiling.
type Finding struct {
	Package     string `json:"package"`
	Version     string `json:"installed_version"`
	CVE         string `json:"cve"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Check cross-references an installed_software fact's Data["items"]
// (a list of {"name":..., "version":..., "architecture":...} maps, as
// internal/cook produces it) against Dataset, returning one Finding per
// installed package whose version is at or below a known-vulnerable
// ceiling. Equivalent to CheckWithFeed(itemsRaw, nil) -- static Dataset
// only, no live feed.
func Check(itemsRaw any) []Finding {
	return CheckWithFeed(itemsRaw, nil)
}

// CheckWithFeed is Check, but also cross-references against feed's
// live-fetched entries (see Feed) when feed is non-nil. Dataset's
// entries are always included regardless of feed -- the feed only ever
// adds coverage, it never replaces the static dataset, so a nil feed
// (no -vuln-feed configured) or a feed whose OSV queries are all
// currently failing never regresses below what Check alone provides.
func CheckWithFeed(itemsRaw any, feed *Feed) []Finding {
	dataset := Dataset
	if feed != nil {
		dataset = append(append([]Entry{}, Dataset...), feed.Entries()...)
	}

	var rows []any
	switch v := itemsRaw.(type) {
	case []any:
		rows = v
	case []map[string]any:
		rows = make([]any, len(v))
		for i, m := range v {
			rows[i] = m
		}
	default:
		return nil
	}

	var findings []Finding
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := row["name"].(string)
		version, _ := row["version"].(string)
		if name == "" || version == "" {
			continue
		}
		for _, entry := range dataset {
			if !strings.EqualFold(entry.Package, name) {
				continue
			}
			cmp, ok := compareVersions(version, entry.MaxVersion)
			if !ok || cmp > 0 {
				continue // installed is newer than the known-vulnerable ceiling, or not comparable at all
			}
			findings = append(findings, Finding{
				Package:     name,
				Version:     version,
				CVE:         entry.CVE,
				Severity:    entry.Severity,
				Description: entry.Description,
			})
		}
	}
	return findings
}

var leadingVersionRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)

// compareVersions does a best-effort, non-authoritative comparison of
// two version strings' leading numeric dotted segment (e.g. "1.22.6"
// out of the real dpkg version "1.22.6ubuntu6.6") -- this is not a real
// Debian version comparator: epochs beyond a simple "N:" prefix strip,
// "~" prerelease markers, and vendor/build suffixes are all out of
// scope, stated plainly rather than silently mishandled. Returns -1/0/1
// like strings.Compare, or ok=false when either string has no
// comparable leading numeric segment, in which case the caller should
// treat the two as not comparable rather than guess.
func compareVersions(a, b string) (result int, ok bool) {
	av, aok := leadingVersion(a)
	bv, bok := leadingVersion(b)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < len(av) || i < len(bv); i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func leadingVersion(s string) ([]int, bool) {
	if idx := strings.Index(s, ":"); idx >= 0 && idx <= 2 {
		s = s[idx+1:] // strip a Debian epoch prefix like "1:", if present
	}
	m := leadingVersionRe.FindString(s)
	if m == "" {
		return nil, false
	}
	parts := strings.Split(m, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}
