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
