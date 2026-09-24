/*******************************************************************************
 * @file         mfa.go
 * @brief        Package mfa implements TOTP (RFC 6238) multi-factor
 *               authentication -- org-wide MFA enforcement policy (#26) --
 *               dependency-free (crypto/hmac + crypto/sha1, stdlib only),
 *               same convention as internal/oauth/ldap/saml.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package mfa implements TOTP (RFC 6238, itself built on RFC 4226's
// HOTP) for dashboard multi-factor authentication. SHA-1 is used as the
// HMAC hash deliberately, not because it is the strongest option, but
// because it is what nearly every TOTP authenticator app (Google
// Authenticator, Authy, 1Password, ...) still assumes by default when
// no algorithm is specified in the otpauth:// URI -- this trades a
// theoretical cryptographic preference for actually working with the
// apps a real deployment's users already have installed. 30-second
// step, 6-digit codes: the same universal defaults.
//
// Enrollment secrets are stored via the existing store.Document
// mechanism (see internal/directory for the parallel pattern), not a
// new table -- one secret per user, always read back by email.
//
// Like every other auth package in this codebase, this has not been
// tested against a real authenticator app in the environment it was
// built in -- see docs/security-model.md before relying on it.
package mfa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505,G401 -- required for TOTP/RFC 6238 interop with real authenticator apps; not used for anything security-critical on its own
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"topotrace/internal/model"
	"topotrace/internal/store"
)

// DocumentKind is the store.Document Kind every enrollment is saved
// under.
const DocumentKind = "mfa_enrollment"

const (
	stepSeconds = 30
	digits      = 6
)

func timeNowUnix() int64 { return time.Now().Unix() }

// Enrollment is one user's TOTP state.
type Enrollment struct {
	Email string `json:"email"`
	// Secret is base32-encoded (RFC 4648, no padding), the standard
	// otpauth:// wire format.
	Secret string `json:"secret"` // #nosec G101 -- the TOTP seed itself, meant to be persisted; not a hardcoded credential
	// Enabled is false while a secret has been generated (via
	// StartEnrollment) but not yet confirmed with a valid code
	// (Confirm) -- an unconfirmed secret enforces nothing, so a typo'd
	// or abandoned enrollment attempt can never lock a user out.
	Enabled    bool      `json:"enabled"`
	EnrolledAt time.Time `json:"enrolled_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// GenerateSecret returns a new random 20-byte (160-bit) TOTP secret,
// base32-encoded -- RFC 4226's recommended key length.
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ProvisioningURI returns the otpauth:// URI an authenticator app scans
// (as a QR code, generated client-side -- this package only builds the
// URI, never an image) to add this account.
func ProvisioningURI(secret, accountEmail, issuer string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(accountEmail)
	q := url.Values{
		"secret": {secret},
		"issuer": {issuer},
		"period": {"30"},
		"digits": {"6"},
	}
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

func hotp(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("mfa: decoding secret: %w", err)
	}
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

// Validate reports whether code is a valid TOTP code for secret at the
// current time, allowing one step of clock skew in either direction (a
// 90-second effective window) -- generous enough to absorb an
// authenticator device's clock drift without meaningfully weakening the
// 6-digit code's entropy.
func Validate(secret, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	now := time.Now().Unix() / stepSeconds
	counters := make([]uint64, 0, 3)
	for _, c := range []int64{now - 1, now, now + 1} {
		if c < 0 {
			continue // clock is before the Unix epoch step window; nothing to check
		}
		counters = append(counters, uint64(c)) // #nosec G115 -- c is checked non-negative above
	}
	for _, counter := range counters {
		want, err := hotp(secret, counter)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// Get returns email's enrollment, if any.
func Get(ctx context.Context, st store.Store, email string) (Enrollment, bool, error) {
	doc, found, err := st.GetDocument(ctx, DocumentKind, strings.ToLower(email))
	if err != nil || !found {
		return Enrollment{}, false, err
	}
	var e Enrollment
	if err := json.Unmarshal(doc.Data, &e); err != nil {
		return Enrollment{}, false, err
	}
	return e, true, nil
}

// StartEnrollment generates a fresh secret for email and persists it as
// unconfirmed (Enabled=false), replacing any prior unconfirmed attempt.
// Returns the secret and its otpauth:// URI for the caller to display.
func StartEnrollment(ctx context.Context, st store.Store, email, issuer string) (secret, uri string, err error) {
	secret, err = GenerateSecret()
	if err != nil {
		return "", "", err
	}
	e := Enrollment{Email: strings.ToLower(email), Secret: secret, Enabled: false, CreatedAt: time.Now().UTC()}
	data, err := json.Marshal(e)
	if err != nil {
		return "", "", err
	}
	if err := st.PutDocument(ctx, model.Document{Kind: DocumentKind, ID: e.Email, Data: data}); err != nil {
		return "", "", err
	}
	return secret, ProvisioningURI(secret, email, issuer), nil
}

// Confirm validates code against email's pending secret and, on
// success, marks the enrollment Enabled. Returns an error (not a plain
// bool) so callers can distinguish "no enrollment in progress" from
// "wrong code" without a second lookup.
func Confirm(ctx context.Context, st store.Store, email, code string) error {
	e, found, err := Get(ctx, st, email)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("mfa: no enrollment in progress for %s", email)
	}
	if !Validate(e.Secret, code) {
		return fmt.Errorf("mfa: invalid code")
	}
	e.Enabled = true
	e.EnrolledAt = time.Now().UTC()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return st.PutDocument(ctx, model.Document{Kind: DocumentKind, ID: e.Email, Data: data})
}

// Required decides whether policy requires MFA for role. requiredRoles
// empty and enforced=true means "every role"; otherwise role must
// appear in requiredRoles (case-insensitive).
func Required(enforced bool, requiredRoles []string, role string) bool {
	if !enforced {
		return false
	}
	if len(requiredRoles) == 0 {
		return true
	}
	for _, r := range requiredRoles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// nowUnix exists only so mfa_test.go has a single seam to compute
// "current TOTP step" from, matching Validate's own clock source.
func nowUnix() int64 {
	return timeNowUnix()
}
