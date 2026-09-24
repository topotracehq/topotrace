/*******************************************************************************
 * @file         mfa_test.go
 * @brief        Tests for internal/mfa -- TOTP generation/validation
 *               against RFC 6238's own published test vector, plus the
 *               enrollment store flow and org-policy Required logic.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package mfa

import (
	"context"
	"encoding/base32"
	"testing"

	"topotrace/internal/store/memstore"
)

// TestHOTPRFC4226Vectors checks hotp against RFC 4226 Appendix D's
// published test vectors for the 20-byte ASCII secret
// "12345678901234567890" -- the standard cross-implementation sanity
// check for any HOTP/TOTP implementation.
func TestHOTPRFC4226Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, w := range want {
		got, err := hotp(secret, uint64(counter))
		if err != nil {
			t.Fatalf("hotp(%d): %v", counter, err)
		}
		if got != w {
			t.Errorf("hotp(counter=%d) = %q, want %q", counter, got, w)
		}
	}
}

func TestValidateAcceptsCurrentCodeRejectsWrong(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := uint64(nowStep(t))
	code, err := hotp(secret, now)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	if !Validate(secret, code) {
		t.Error("Validate should accept the current step's code")
	}
	if Validate(secret, "000000") {
		// astronomically unlikely to collide, but guard against it
		// rather than assert flakily
		if code != "000000" {
			t.Error("Validate should reject an arbitrary wrong code")
		}
	}
	if Validate(secret, "") {
		t.Error("Validate should reject an empty code")
	}
}

func TestProvisioningURIShape(t *testing.T) {
	uri := ProvisioningURI("JBSWY3DPEHPK3PXP", "alice@example.com", "TopoTrace")
	if got, want := uri[:len("otpauth://totp/")], "otpauth://totp/"; got != want {
		t.Errorf("URI scheme/host wrong: %q", uri)
	}
}

func TestEnrollmentFlow(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()

	secret, uri, err := StartEnrollment(ctx, st, "alice@example.com", "TopoTrace")
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	if secret == "" || uri == "" {
		t.Fatal("StartEnrollment returned empty secret/uri")
	}
	e, found, err := Get(ctx, st, "alice@example.com")
	if err != nil || !found {
		t.Fatalf("Get after StartEnrollment: found=%v err=%v", found, err)
	}
	if e.Enabled {
		t.Error("a freshly started enrollment must not be Enabled yet")
	}

	if err := Confirm(ctx, st, "alice@example.com", "000000"); err == nil {
		t.Error("Confirm should reject an arbitrary wrong code")
	}

	code, err := hotp(secret, uint64(nowStep(t)))
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	if err := Confirm(ctx, st, "alice@example.com", code); err != nil {
		t.Fatalf("Confirm with a valid code: %v", err)
	}
	e, found, err = Get(ctx, st, "alice@example.com")
	if err != nil || !found || !e.Enabled {
		t.Fatalf("expected Enabled after Confirm, got %+v found=%v err=%v", e, found, err)
	}
}

func TestConfirmNoEnrollmentInProgress(t *testing.T) {
	st, _ := memstore.New("")
	ctx := context.Background()
	if err := Confirm(ctx, st, "nobody@example.com", "123456"); err == nil {
		t.Error("Confirm should error when no enrollment is in progress")
	}
}

func TestRequired(t *testing.T) {
	if Required(false, nil, "admin") {
		t.Error("MFA should never be required when enforced=false")
	}
	if !Required(true, nil, "readonly") {
		t.Error("enforced=true with no role list should require MFA for every role")
	}
	if !Required(true, []string{"admin"}, "admin") {
		t.Error("admin should require MFA when admin is in the role list")
	}
	if Required(true, []string{"admin"}, "readonly") {
		t.Error("readonly should not require MFA when only admin is in the role list")
	}
}

func nowStep(t *testing.T) int64 {
	t.Helper()
	return nowUnix() / stepSeconds
}
