// Package model holds the core data shapes Muster passes between its
// ingest, cook, storage, and API layers.
package model

import "time"

// Host is a single managed system Muster has collected data about.
type Host struct {
	Name       string    `json:"name"`
	Platform   string    `json:"platform"` // "linux", "windows", "aix", ... (agent-reported, lowercase, open-ended on purpose)
	FirstSeen  time.Time `json:"first_seen"`
	LastCooked time.Time `json:"last_cooked"`

	// Group and Tags are operator-assigned metadata, not anything an
	// agent reports -- set via the API/web UI (Store.SetHostGroup,
	// Store.SetHostTags), never touched by UpsertHost/the cook pipeline.
	// Group is single-valued and drives the Kanban board's columns (a
	// card lives in exactly one list, same as Trello); Tags is freeform
	// and multi-valued, for labels shown on a card that don't need their
	// own column ("prod", "needs-patching", whatever an operator wants).
	Group string   `json:"group,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// Fact is one category of parsed, structured data about a host -- e.g.
// "system_summary", "disks", "packages". Data is intentionally
// map[string]any rather than a fixed struct: different categories (and
// different platforms) have different shapes, and the store layer treats
// a Fact as an opaque, queryable JSON document, not a fixed schema.
type Fact struct {
	Host     string         `json:"host"`
	Category string         `json:"category"`
	Data     map[string]any `json:"data"`
	CookedAt time.Time      `json:"cooked_at"`
}

// Change is one recorded difference between a fact's previous value and
// its newly cooked value, for a single field.
type Change struct {
	Host      string    `json:"host"`
	Category  string    `json:"category"`
	Field     string    `json:"field"`
	OldValue  string    `json:"old_value,omitempty"`
	NewValue  string    `json:"new_value,omitempty"`
	Action    string    `json:"action"` // "add", "remove", "update"
	ChangedAt time.Time `json:"changed_at"`
}

// Action is a queued or completed remediation action for a host --
// deliberately not free-form. Verb must be one of the small, fixed set
// internal/remediate knows how to validate and an agent script knows how
// to execute (see internal/remediate/actions.go). Queuing one always
// requires the shared operator token (see internal/api's handleQueueAction),
// and the ingest daemon only ever hands a queued action back to the one
// host it was queued for, over the same token-authenticated channel it
// already verifies packets on -- there is no path from an unauthenticated
// network client to a host actually running a command.
type Action struct {
	ID          string    `json:"id"`
	Host        string    `json:"host"`
	Verb        string    `json:"verb"`
	Arg         string    `json:"arg,omitempty"`
	QueuedAt    time.Time `json:"queued_at"`
	Delivered   bool      `json:"delivered"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
	Status      string    `json:"status,omitempty"` // "" (not yet reported), "ok", or "fail"
	Detail      string    `json:"detail,omitempty"`
	ReportedAt  time.Time `json:"reported_at,omitempty"`
}

// AuditEntry records one authenticated write or remediation event, for
// after-the-fact accountability: who (an API key's Name, "master" for
// the bootstrap -auth-token, or "system" for the background evaluator)
// did what, to what, and when. Append-only, same spirit as Change, but
// covers API actions generally rather than just cooked-fact diffs.
type AuditEntry struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKey is a named, role-scoped credential -- the RBAC layer on top of
// the original single shared -auth-token, which keeps working unchanged
// as a permanent "admin" master credential (see internal/api's
// authorized). Role is one of "admin" (everything the master token can
// do, including managing other keys), "remediate" (read everything,
// queue remediation actions), or "readonly" (read-only). TokenHash is a
// SHA-256 hex digest, never the raw token -- Store implementations must
// never log or expose it, and the raw token itself is only ever shown
// once, at creation time, in the API response (never persisted).
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// Rule is one persisted, optionally group-scoped compliance rule,
// evaluated by internal/evaluator on a schedule against each host's
// current posture (see internal/policy.ComputePosture). Kind selects
// which small, fixed check runs: "stale" (host is currently stale),
// "score_below" (posture score < Threshold), or "category_missing"
// (the named Category has never been reported for this host). There is
// deliberately no arbitrary expression language here -- same "small,
// fixed allow-list, not free-form" philosophy as internal/remediate's
// Verbs. If AutoRemediate is set (to an internal/remediate verb), the
// evaluator queues that action, with AutoRemediateArg, on every host
// that violates this rule; leave it empty for a rule that only reports
// findings without acting on them.
type Rule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Group            string    `json:"group,omitempty"` // "" means every host, regardless of group
	Kind             string    `json:"kind"`
	Threshold        int       `json:"threshold,omitempty"`
	Category         string    `json:"category,omitempty"`
	AutoRemediate    string    `json:"auto_remediate,omitempty"`
	AutoRemediateArg string    `json:"auto_remediate_arg,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// Enrollment is a named, single-host, revocable credential used only to
// self-register an agent -- deliberately narrower than an APIKey (which
// grants a role across the whole API): an enrollment token authenticates
// exactly one host's fact reports (over the TCP MUSTER1 protocol or the
// JSON POST /api/mobile-report path), nothing else -- it can never
// queue a remediation action, read another host's data, or call any
// other endpoint. This is what backs the dashboard's tracked-enrollment
// flow: mint one per host up front, hand the resulting install command
// to whoever's setting up that box, and watch Status flip from
// "pending" to "enrolled" the moment the real device's first report
// arrives.
type Enrollment struct {
	ID         string    `json:"id"`
	Host       string    `json:"host"`
	Platform   string    `json:"platform"` // advisory label for the install/download UI -- not enforced against what the host actually reports
	TokenHash  string    `json:"-"`
	Status     string    `json:"status"` // "pending" or "enrolled"
	CreatedAt  time.Time `json:"created_at"`
	EnrolledAt time.Time `json:"enrolled_at,omitempty"`
}

// SoftwareRule is a named allow- or deny-listed software match, scoped
// like model.Rule ("" Group means every host). Match is a package name,
// case-insensitive, with an optional trailing "*" treated as a prefix
// wildcard (e.g. "docker*") -- deliberately not a full glob/regex
// engine, the same small-surface choice model.Rule's fixed Kind set and
// internal/remediate's fixed verb set both make.
//
// Kind "deny" always applies: any installed_software item matching a
// deny rule in scope is a violation. Kind "allow" only starts
// enforcing once at least one allow rule exists in a given scope -- an
// empty allowlist means "no opinion yet, nothing is unauthorized," not
// "everything is banned" (see internal/allowlist.Evaluate's doc
// comment for the exact semantics, the same "absence is unknown, not
// bad" principle internal/policy.ComputePosture already uses).
type SoftwareRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Group     string    `json:"group,omitempty"` // "" means every host, regardless of group
	Kind      string    `json:"kind"`            // "deny" or "allow"
	Match     string    `json:"match"`
	CreatedAt time.Time `json:"created_at"`
}

// DiscoveredAsset is one host-like thing found on the network by a
// discovery scan (cmd/discover) -- distinct from Host, which represents
// a system that actually runs a Muster agent and reports facts.  A
// DiscoveredAsset means only "something answered on this address during
// a sweep": no facts, no change tracking, no posture score, just enough
// for an operator to see what's on their network that Muster otherwise
// has zero visibility into. Upserted by Address on every report, so
// re-scanning refreshes OpenPorts/Banners/Known/LastSeenAt in place
// rather than piling up duplicate rows for the same address -- the same
// "first-seen is sticky" shape Store.UpsertHost already uses for Host.
type DiscoveredAsset struct {
	ID      string `json:"id"`
	Address string `json:"address"` // IP or hostname the scanner connected to

	OpenPorts []int             `json:"open_ports"`
	Banners   map[string]string `json:"banners,omitempty"` // port number (as a string key) -> best-effort banner grab, only present when one was read

	ScannedBy   string `json:"scanned_by"`             // operator-supplied label for who/what ran the scan
	ScannedCIDR string `json:"scanned_cidr,omitempty"` // the subnet this sighting came from, if run as a sweep rather than a single-address probe

	// Known is true when Address matched an existing Host's name at the
	// time of the most recent report -- a quick "you already manage
	// this one" signal for the discovery dashboard, computed by the API
	// layer at report time, not derived live on every read.
	Known bool `json:"known"`

	DiscoveredAt time.Time `json:"discovered_at"` // first time this address was ever seen, never changes on later reports
	LastSeenAt   time.Time `json:"last_seen_at"`
}
