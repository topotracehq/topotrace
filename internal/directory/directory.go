/*******************************************************************************
 * @file         directory.go
 * @brief        Package directory is TopoTrace's persisted user directory --
 *               the missing piece SCIM provisioning (#22), MFA enrollment
 *               (#26), and org-wide deprovisioning all need, since until now
 *               every login method (OAuth/LDAP/SAML) computed a role live
 *               from the identity provider and never stored anything.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package directory is TopoTrace's persisted user directory. Every login
// method (OAuth, AD/LDAP, SAML) has always computed a role live from the
// identity provider on every login and never stored anything about the
// person logging in -- fine for authentication, but it means there is no
// way to say "this person is deprovisioned, refuse them" faster than the
// IdP itself catching up (which, for a slow HR-to-IdP pipeline, can be
// days). This package adds exactly that: a store.Document-backed record
// per user (kind "user"), keyed by lowercased email, that SCIM (see
// internal/api's /scim/v2/Users handlers) can write to directly, and
// that every login path checks before issuing a session.
//
// Deliberately built on the existing generic Document store rather than
// a new dedicated table -- one user record, always read back by its one
// key (email), is exactly the shape Document exists for (see
// model.Document's doc comment).
package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"topotrace/internal/model"
	"topotrace/internal/store"
)

// DocumentKind is the store.Document Kind every user record is saved
// under.
const DocumentKind = "user"

// User is one person's directory record.
type User struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	// Active false means deprovisioned: every login path must refuse
	// this email regardless of what the identity provider still
	// reports. This is the actual fix for the compliance gap #22
	// describes -- an admin (via SCIM, or the dashboard) flips this
	// the moment someone is offboarded, without waiting on the IdP.
	Active bool `json:"active"`
	// Source records how this record came to exist: "scim" (an
	// external identity system pushed it), "jit" (created
	// automatically on first successful SSO login, see ProvisionJIT),
	// or "manual" (an admin created/edited it by hand). Informational
	// only -- it does not change how the record is enforced.
	Source    string    `json:"source"`
	Groups    []string  `json:"groups,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func docID(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Get returns the directory record for email, if one exists. found is
// false both when the store has genuinely never heard of this email
// and when email is empty -- callers should treat "not found" as "no
// opinion," not "deprovisioned" (see Allowed's doc comment).
func Get(ctx context.Context, st store.Store, email string) (User, bool, error) {
	if email == "" {
		return User{}, false, nil
	}
	doc, found, err := st.GetDocument(ctx, DocumentKind, docID(email))
	if err != nil || !found {
		return User{}, false, err
	}
	var u User
	if err := json.Unmarshal(doc.Data, &u); err != nil {
		return User{}, false, fmt.Errorf("directory: decoding user record for %s: %w", email, err)
	}
	return u, true, nil
}

// List returns every directory record.
func List(ctx context.Context, st store.Store) ([]User, error) {
	docs, err := st.ListDocuments(ctx, DocumentKind)
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(docs))
	for _, doc := range docs {
		var u User
		if err := json.Unmarshal(doc.Data, &u); err != nil {
			continue // a corrupt single record should not fail the whole listing
		}
		out = append(out, u)
	}
	return out, nil
}

// Upsert creates or replaces email's record. CreatedAt is preserved from
// any existing record; UpdatedAt is always stamped now.
func Upsert(ctx context.Context, st store.Store, u User) (User, error) {
	u.Email = docID(u.Email)
	if u.Email == "" {
		return User{}, fmt.Errorf("directory: email is required")
	}
	if existing, found, err := Get(ctx, st, u.Email); err == nil && found {
		u.CreatedAt = existing.CreatedAt
	} else if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	u.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(u)
	if err != nil {
		return User{}, err
	}
	if err := st.PutDocument(ctx, model.Document{Kind: DocumentKind, ID: docID(u.Email), Data: data}); err != nil {
		return User{}, err
	}
	return u, nil
}

// Deactivate flips a user's Active flag to false -- the SCIM DELETE
// handler's underlying operation (see internal/api's doc comment on why
// SCIM DELETE deactivates rather than erases the record: an erased
// record has no Active flag left to enforce). Creates the record first
// if none exists yet, defaulting Role to "readonly" -- deactivating
// someone TopoTrace has never seen still needs to leave a durable
// "refuse this email" marker behind.
func Deactivate(ctx context.Context, st store.Store, email string) (User, error) {
	u, found, err := Get(ctx, st, email)
	if err != nil {
		return User{}, err
	}
	if !found {
		u = User{Email: email, Role: "readonly", Source: "manual"}
	}
	u.Active = false
	return Upsert(ctx, st, u)
}

// ProvisionJIT is called on every successful OAuth/LDAP/SAML login. If
// no directory record exists for email yet, it creates one
// (Source="jit", Active=true) so it shows up in the directory and can
// subsequently be managed (deactivated, role-corrected) like any SCIM-
// provisioned user -- the "alternative for customers without SCIM"
// #22 asks for. If a record already exists, its Role is refreshed to
// whatever the IdP just asserted (keeping the directory's notion of
// role current for customers who never touch SCIM at all) but its
// Active flag and Source are left untouched -- a SCIM-deactivated user
// logging in again through the IdP must not silently reactivate
// themselves.
func ProvisionJIT(ctx context.Context, st store.Store, email, role string) (User, error) {
	existing, found, err := Get(ctx, st, email)
	if err != nil {
		return User{}, err
	}
	if !found {
		return Upsert(ctx, st, User{Email: email, Role: role, Active: true, Source: "jit"})
	}
	existing.Role = role
	return Upsert(ctx, st, existing)
}

// Allowed reports whether email is permitted to log in: true whenever
// there is no directory opinion about them at all (found=false -- the
// common case for any deployment that has not adopted SCIM or hit JIT
// provisioning yet, preserving today's behavior), or when a record
// exists and is Active. False only when a record exists and has been
// explicitly deactivated.
func Allowed(ctx context.Context, st store.Store, email string) (bool, error) {
	u, found, err := Get(ctx, st, email)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	return u.Active, nil
}
