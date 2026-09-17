// Package compliance rolls up Muster's other signals -- staleness,
// posture scoring, vulnerability correlation, and software allow/deny
// lists -- into named "frameworks," each a small, fixed set of pass/
// fail checks, scored as a percentage. This is compliance TRACKING in
// the sense of "did this host pass these checks, and how has that
// changed" -- it is explicitly not a certified mapping to any real
// standard (CIS Benchmarks, SOC 2, PCI DSS, HIPAA, ...), the same
// "small, honest illustration, not a stand-in for a real audit"
// posture internal/vuln's static dataset and internal/policy's score
// already take. A real compliance product licenses and maintains an
// actual control mapping reviewed by someone qualified to do that;
// this is the foundation such a mapping could sit on.
package compliance

import (
	"fmt"

	"muster/internal/allowlist"
	"muster/internal/model"
	"muster/internal/policy"
	"muster/internal/vuln"
)

// CheckResult is one framework check's outcome for a single host.
type CheckResult struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Pass        bool   `json:"pass"`
	Detail      string `json:"detail,omitempty"`
}

// Result is one framework's full evaluation for a single host.
type Result struct {
	Framework   string        `json:"framework"`
	FrameworkID string        `json:"framework_id"`
	Host        string        `json:"host"`
	Score       int           `json:"score"` // percent of checks passed, 0-100
	Checks      []CheckResult `json:"checks"`
}

// Input bundles everything a check might need, computed once per host
// by the caller and reused across every framework -- the same
// "compute facts/posture once, pass it down" shape
// internal/evaluator.evaluateHost already uses for policy rules.
type Input struct {
	Host               model.Host
	Facts              map[string]model.Fact
	Stale              bool
	Posture            policy.PostureResult
	VulnFindings       []vuln.Finding
	SoftwareViolations []allowlist.Violation
}

// check is one named, described test against an Input -- a small,
// fixed function, not a persisted/configurable rule. See Baseline's
// doc comment for why frameworks here are Go code, not stored rows.
type check struct {
	id          string
	description string
	evaluate    func(Input) (bool, string)
}

// Framework is a named, ordered, fixed set of checks.
type Framework struct {
	ID          string
	Name        string
	Description string
	checks      []check
}

// Evaluate runs every check in f against in, returning a Result. A
// framework with zero checks scores 100 -- vacuously true, never
// treated as a failure of the framework definition itself.
func (f Framework) Evaluate(in Input) Result {
	checks := make([]CheckResult, 0, len(f.checks))
	passed := 0
	for _, c := range f.checks {
		ok, detail := c.evaluate(in)
		if ok {
			passed++
		}
		checks = append(checks, CheckResult{ID: c.id, Description: c.description, Pass: ok, Detail: detail})
	}
	score := 100
	if len(checks) > 0 {
		score = passed * 100 / len(checks)
	}
	return Result{Framework: f.Name, FrameworkID: f.ID, Host: in.Host.Name, Score: score, Checks: checks}
}

// Baseline is Muster's one built-in framework: four checks built
// entirely from signals this project already computes for real. Not a
// certified mapping to any named standard -- see the package doc
// comment.
var Baseline = Framework{
	ID:          "baseline",
	Name:        "Muster Baseline",
	Description: "Illustrative checks built from Muster's own signals -- not a certified CIS/SOC2/PCI mapping.",
	checks: []check{
		{
			id:          "reporting",
			description: "Host has reported within the staleness window",
			evaluate: func(in Input) (bool, string) {
				if in.Stale {
					return false, "host is stale"
				}
				return true, ""
			},
		},
		{
			id:          "posture-score",
			description: "Posture score is at least 70",
			evaluate: func(in Input) (bool, string) {
				if in.Posture.Score < 70 {
					return false, fmt.Sprintf("posture score is %d", in.Posture.Score)
				}
				return true, ""
			},
		},
		{
			id:          "no-known-vulnerabilities",
			description: "No known-vulnerable installed packages",
			evaluate: func(in Input) (bool, string) {
				if len(in.VulnFindings) > 0 {
					return false, fmt.Sprintf("%d known-vulnerable package(s)", len(in.VulnFindings))
				}
				return true, ""
			},
		},
		{
			id:          "no-denied-software",
			description: "No denied or unauthorized software installed",
			evaluate: func(in Input) (bool, string) {
				if len(in.SoftwareViolations) > 0 {
					return false, fmt.Sprintf("%d software violation(s)", len(in.SoftwareViolations))
				}
				return true, ""
			},
		},
	},
}

// Frameworks lists every built-in framework -- just Baseline today.
// Kept as a slice, not a single hardcoded value, so the API and
// dashboard stay generic as more are added.
var Frameworks = []Framework{Baseline}

// EvaluateAll runs every Framework in Frameworks against in.
func EvaluateAll(in Input) []Result {
	out := make([]Result, 0, len(Frameworks))
	for _, f := range Frameworks {
		out = append(out, f.Evaluate(in))
	}
	return out
}
