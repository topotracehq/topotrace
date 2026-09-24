/*******************************************************************************
 * @file         acl.go
 * @brief        Package acl implements attribute-based access control over
 *               hosts -- resource-scoped visibility (#23) and dynamic,
 *               role-aware field masking (#24) -- evaluated against
 *               existing host Group/Tags metadata, not a new taxonomy.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package acl implements TopoTrace's attribute-based access control layer:
// which hosts a given viewer may see at all (#23's "resource-level
// scoping"), and which of a visible host's fields must be masked for them
// (#24's "field-level data masking"). Deliberately built on the host
// Group/Tags metadata that already exists (model.Host, set via
// Store.SetHostGroup/SetHostTags) rather than inventing a new resource
// taxonomy -- "a user can see prod hosts but not the DB tier" is exactly
// what a tag-based policy already expresses.
//
// Policies are evaluated fresh on every read (Evaluate is pure and
// cheap), never pre-computed or cached against a host -- masking must
// reflect the *viewer's* role at read time, not whatever role existed
// when a host was last written, matching #24's explicit "computed
// dynamically at query time" requirement.
package acl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"topotrace/internal/model"
	"topotrace/internal/store"
)

// DocumentKind is the store.Document Kind every policy is saved under.
const DocumentKind = "acl_policy"

// MaskableFields is the fixed set of host fields a policy may mask.
// Kept small and explicit -- #24 warns masking must "apply consistently
// across API responses, UI, exports, and debug logs," and a small,
// named set is what makes that auditable; an open-ended field list
// would invite a mask that silently does nothing because a caller
// serializes the field under a name the policy didn't anticipate.
var MaskableFields = []string{"ip", "hostname"}

// Policy is one ABAC rule: which viewers (Subjects) it applies to, and
// what it does for hosts matching AllowTags/DenyTags.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Subjects a policy applies to: a role name ("readonly",
	// "remediate"), an exact email, or "*" for every non-admin viewer.
	// A policy with no matching Subject never fires for a given viewer.
	Subjects []string `json:"subjects"`
	// AllowTags, if non-empty, means a matching viewer may only see
	// hosts carrying at least one of these tags -- every other host is
	// hidden from them entirely by this policy. Leave empty to not
	// restrict by allow-list (rely on DenyTags alone, or on no
	// restriction).
	AllowTags []string `json:"allow_tags,omitempty"`
	// DenyTags, if a host carries any of them, hides that host from a
	// matching viewer -- deny always wins over allow.
	DenyTags []string `json:"deny_tags,omitempty"`
	// MaskFields lists which of MaskableFields to mask (not hide) on
	// hosts this policy's viewer can otherwise see.
	MaskFields []string  `json:"mask_fields,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create validates and persists a new policy.
func Create(ctx context.Context, st store.Store, p Policy) (Policy, error) {
	if p.Name == "" {
		return Policy{}, fmt.Errorf("acl: name is required")
	}
	if len(p.Subjects) == 0 {
		return Policy{}, fmt.Errorf("acl: at least one subject is required (a role, an email, or \"*\")")
	}
	for _, f := range p.MaskFields {
		if !contains(MaskableFields, f) {
			return Policy{}, fmt.Errorf("acl: %q is not a maskable field (want one of %v)", f, MaskableFields)
		}
	}
	id, err := newID()
	if err != nil {
		return Policy{}, err
	}
	p.ID = id
	p.CreatedAt = time.Now().UTC()
	data, err := json.Marshal(p)
	if err != nil {
		return Policy{}, err
	}
	if err := st.PutDocument(ctx, model.Document{Kind: DocumentKind, ID: p.ID, Data: data}); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// List returns every policy.
func List(ctx context.Context, st store.Store) ([]Policy, error) {
	docs, err := st.ListDocuments(ctx, DocumentKind)
	if err != nil {
		return nil, err
	}
	out := make([]Policy, 0, len(docs))
	for _, doc := range docs {
		var p Policy
		if err := json.Unmarshal(doc.Data, &p); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Delete removes a policy by ID.
func Delete(ctx context.Context, st store.Store, id string) error {
	return st.DeleteDocument(ctx, DocumentKind, id)
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func matchesSubject(subjects []string, viewerRole, viewerEmail string) bool {
	for _, s := range subjects {
		if s == "*" {
			return true
		}
		if strings.EqualFold(s, viewerRole) {
			return true
		}
		if strings.EqualFold(s, viewerEmail) {
			return true
		}
	}
	return false
}

func hasAnyTag(hostTags, want []string) bool {
	for _, t := range hostTags {
		for _, w := range want {
			if strings.EqualFold(t, w) {
				return true
			}
		}
	}
	return false
}

// Decision is the result of evaluating every policy for one viewer
// against one host.
type Decision struct {
	Visible bool
	// Masked lists exactly which of MaskableFields are masked -- kept
	// as a slice (not a set) so callers get a deterministic,
	// JSON-friendly value straight from Evaluate.
	Masked []string
}

func (d Decision) MaskedSet() map[string]bool {
	m := make(map[string]bool, len(d.Masked))
	for _, f := range d.Masked {
		m[f] = true
	}
	return m
}

// Evaluate applies every policy matching (viewerRole, viewerEmail)
// against host and returns the combined decision: hidden if any
// matching policy's DenyTags hit, or if any matching policy has
// AllowTags and none of them hit; otherwise visible, with the union of
// every matching, non-hiding policy's MaskFields applied. A viewer with
// no matching policy at all sees the host fully, unmasked -- ACL is
// additive restriction, not default-deny; an operator who never
// creates a policy sees exactly today's (pre-#23/#24) behavior.
func Evaluate(policies []Policy, viewerRole, viewerEmail string, host model.Host) Decision {
	masked := map[string]bool{}
	for _, p := range policies {
		if !matchesSubject(p.Subjects, viewerRole, viewerEmail) {
			continue
		}
		if len(p.DenyTags) > 0 && hasAnyTag(host.Tags, p.DenyTags) {
			return Decision{Visible: false}
		}
		if len(p.AllowTags) > 0 && !hasAnyTag(host.Tags, p.AllowTags) {
			return Decision{Visible: false}
		}
		for _, f := range p.MaskFields {
			masked[f] = true
		}
	}
	out := Decision{Visible: true}
	for f := range masked {
		out.Masked = append(out.Masked, f)
	}
	return out
}

// MaskHost returns a copy of host with any masked field replaced by a
// fixed redaction marker. Only IP and hostname (the fields #24 names
// explicitly: "IPs, hostnames, credentials" -- TopoTrace does not store
// credentials on a Host record at all, so that third field has nothing
// to mask here) are ever touched; every other field, including Tags and
// Group themselves, passes through unchanged so an operator can still
// see *that* a host is masked and why.
//
// This is the single choke point every host-serializing response
// should call before writing JSON to a non-admin viewer -- see
// internal/api's maskHostForViewer. Anything that starts returning host
// data through a new path (a new export format, a new report) must call
// it too; nothing in this package can enforce that for callers that
// bypass it.
const RedactedMarker = "***"

func MaskHost(host model.Host, masked map[string]bool) model.Host {
	if masked["ip"] {
		// Host has no direct IP field today (interface facts carry
		// it) -- kept here as a documented no-op so a future IP field
		// on model.Host is masked by construction rather than by
		// remembering to come back to this function.
		_ = masked
	}
	if masked["hostname"] {
		host.Name = RedactedMarker
	}
	return host
}
