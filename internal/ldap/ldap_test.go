/*******************************************************************************
 * @file         ldap_test.go
 * @brief        Tests for internal/ldap's pure logic -- BER round-trips,
 *               filter escaping, config validation, and group-to-role
 *               mapping. No live directory is dialed.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-23
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package ldap

import "testing"

func TestBERIntRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 65535, 65536, 2} {
		enc := berInt(tagInteger, n)
		tag, content, next, err := berReadTLV(enc, 0)
		if err != nil {
			t.Fatalf("berReadTLV(%d): %v", n, err)
		}
		if tag != tagInteger || next != len(enc) {
			t.Fatalf("berReadTLV(%d): unexpected tag/next", n)
		}
		got, err := berReadInt(content)
		if err != nil {
			t.Fatalf("berReadInt(%d): %v", n, err)
		}
		if got != n {
			t.Errorf("round-trip %d, got %d", n, got)
		}
	}
}

func TestBERLongFormLength(t *testing.T) {
	value := make([]byte, 300) // forces long-form length encoding
	enc := berTLV(tagOctetStr, value)
	tag, content, next, err := berReadTLV(enc, 0)
	if err != nil {
		t.Fatalf("berReadTLV: %v", err)
	}
	if tag != tagOctetStr || len(content) != 300 || next != len(enc) {
		t.Fatalf("got tag=%x len=%d next=%d, want tag=%x len=300 next=%d", tag, len(content), next, tagOctetStr, len(enc))
	}
}

func TestEscapeFilterValue(t *testing.T) {
	cases := map[string]string{
		"alice":          "alice",
		"a*b":            `a\2ab`,
		"(evil=*)(uid=*": `\28evil=\2a\29\28uid=\2a`,
		`back\slash`:     `back\5cslash`,
	}
	for in, want := range cases {
		if got := EscapeFilterValue(in); got != want {
			t.Errorf("EscapeFilterValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewConfigAllOrNothing(t *testing.T) {
	if cfg, err := NewConfig("", 0, true, "", "", "", "", "", "", ""); cfg != nil || err != nil {
		t.Errorf("all-empty: got (%v, %v), want (nil, nil)", cfg, err)
	}
	if _, err := NewConfig("dc.example.com", 0, true, "", "", "", "", "", "", ""); err == nil {
		t.Error("host-only: expected error (missing user-base-dn/role-map)")
	}
	cfg, err := NewConfig("dc.example.com", 0, true, "svc", "pw", "OU=People,DC=example,DC=com", "", "", "", "CN=Admins,DC=example,DC=com=admin,*=readonly")
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if cfg.Port != 636 {
		t.Errorf("expected default TLS port 636, got %d", cfg.Port)
	}
	if cfg.UserAttr != "sAMAccountName" || cfg.MailAttr != "mail" || cfg.GroupAttr != "memberOf" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestRoleForGroups(t *testing.T) {
	cfg, err := NewConfig("dc.example.com", 389, false, "", "", "OU=People,DC=example,DC=com", "uid", "", "",
		"CN=Admins,OU=Groups,DC=example,DC=com=admin;CN=Readers,OU=Groups,DC=example,DC=com=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	cases := []struct {
		groups []string
		want   string
	}{
		{[]string{"CN=Admins,OU=Groups,DC=example,DC=com"}, "admin"},
		{[]string{"cn=admins,ou=Groups,dc=example,dc=com"}, "admin"}, // case-insensitive
		{[]string{"CN=Readers,OU=Groups,DC=example,DC=com"}, "readonly"},
		{[]string{"CN=Nobody,OU=Groups,DC=example,DC=com"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := cfg.roleForGroups(c.groups); got != c.want {
			t.Errorf("roleForGroups(%v) = %q, want %q", c.groups, got, c.want)
		}
	}
}

func TestRoleMapStrings(t *testing.T) {
	cfg, err := NewConfig("dc.example.com", 389, false, "", "", "OU=People,DC=example,DC=com", "", "", "", "*=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	got := cfg.RoleMapStrings()
	if len(got) != 1 || got[0] != "*=readonly" {
		t.Errorf("RoleMapStrings() = %v", got)
	}
}
