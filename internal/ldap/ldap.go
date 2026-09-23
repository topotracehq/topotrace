/*******************************************************************************
 * @file         ldap.go
 * @brief        Package ldap implements a minimal, dependency-free LDAPv3
 *               client (bind + search) sufficient to authenticate dashboard
 *               users against Active Directory or a generic LDAP directory
 *               via the standard "service-account bind, search for the
 *               user's DN, then bind as that DN to verify the password"
 *               pattern, plus group-to-role mapping.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-23
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package ldap implements a minimal LDAPv3 client -- simple bind and a
// one-level/subtree search with a single equality filter -- entirely with
// the standard library (net, crypto/tls). Like internal/oauth, this is
// hand-rolled against RFC 4511 rather than vendoring a third-party LDAP
// library, because this project's build environment has no route to
// proxy.golang.org to fetch and vendor one (see internal/oauth's doc
// comment for the fuller explanation). It supports exactly what dashboard
// login needs -- simple bind, and a search with one equalityMatch filter
// built from a caller-controlled attribute name and an escaped user-
// supplied value -- not the general LDAP filter grammar, extended
// operations, paging, or SASL. Treat this as a solid first draft: it has
// been checked against RFC 4511's message encodings but not round-tripped
// against a live Active Directory or OpenLDAP server in this environment;
// test it against your actual directory before relying on it to gate
// anything real. See docs/security-model.md.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// resultSuccess is the LDAPResult resultCode value for a successful bind
// or search (RFC 4511 section 4.1.9).
const resultSuccess = 0

// conn is one short-lived LDAP connection -- opened, used for a service
// bind + search + user bind, then closed. Not pooled: dashboard logins are
// low-frequency enough that a fresh TCP+bind per login is simpler and
// safer than managing a shared connection's bind state across concurrent
// requests.
type conn struct {
	nc        net.Conn
	messageID int
}

func dial(ctx context.Context, host string, port int, useTLS bool, timeout time.Duration) (*conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	var nc net.Conn
	var err error
	if useTLS {
		tlsDialer := tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
		nc, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		nc, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap: connecting to %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		nc.SetDeadline(deadline)
	}
	return &conn{nc: nc}, nil
}

func (c *conn) close() { _ = c.nc.Close() }

func (c *conn) nextID() int {
	c.messageID++
	return c.messageID
}

// send wraps protocolOp in an LDAPMessage and writes it.
func (c *conn) send(protocolOp []byte) error {
	msg := berSeq(tagSequence, berInt(tagInteger, c.nextID()), protocolOp)
	_, err := c.nc.Write(msg)
	return err
}

// readMessage reads one full LDAPMessage from the connection and returns
// its protocolOp tag and content. LDAP has no explicit frame length at
// the transport level beyond the BER length itself, so this reads the
// outer SEQUENCE's header first to learn how many more bytes to read.
func (c *conn) readMessage() (opTag byte, opContent []byte, err error) {
	header := make([]byte, 2)
	if _, err := readFull(c.nc, header); err != nil {
		return 0, nil, fmt.Errorf("ldap: reading message header: %w", err)
	}
	if header[0] != tagSequence {
		return 0, nil, fmt.Errorf("ldap: unexpected top-level tag 0x%02x", header[0])
	}
	var rest []byte
	if header[1]&0x80 == 0 {
		length := int(header[1])
		rest = make([]byte, length)
	} else {
		n := int(header[1] &^ 0x80)
		if n == 0 || n > 4 {
			return 0, nil, fmt.Errorf("ldap: unsupported length form (%d octets)", n)
		}
		lenBytes := make([]byte, n)
		if _, err := readFull(c.nc, lenBytes); err != nil {
			return 0, nil, fmt.Errorf("ldap: reading long-form length: %w", err)
		}
		length := 0
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
		rest = make([]byte, length)
	}
	if _, err := readFull(c.nc, rest); err != nil {
		return 0, nil, fmt.Errorf("ldap: reading message body: %w", err)
	}
	// rest is now: messageID INTEGER TLV, then the protocolOp TLV, then
	// optional controls (ignored).
	_, _, next, err := berReadTLV(rest, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("ldap: parsing message ID: %w", err)
	}
	tag, content, _, err := berReadTLV(rest, next)
	if err != nil {
		return 0, nil, fmt.Errorf("ldap: parsing protocol op: %w", err)
	}
	return tag, content, nil
}

func readFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ldapResult pulls resultCode and diagnosticMessage out of an LDAPResult-
// shaped content (BindResponse, SearchResultDone): SEQUENCE { resultCode
// ENUMERATED, matchedDN OCTET STRING, diagnosticMessage OCTET STRING, ... }.
func ldapResult(content []byte) (code int, diagnostic string, err error) {
	tag, codeBytes, next, err := berReadTLV(content, 0)
	if err != nil || tag != tagEnumerated {
		return 0, "", fmt.Errorf("ldap: malformed result (resultCode): %v", err)
	}
	code, err = berReadInt(codeBytes)
	if err != nil {
		return 0, "", err
	}
	_, _, next, err = berReadTLV(content, next) // matchedDN, discarded
	if err != nil {
		return code, "", nil //nolint:nilerr // resultCode alone is enough if the rest is short
	}
	_, diagBytes, _, err := berReadTLV(content, next)
	if err != nil {
		return code, "", nil //nolint:nilerr
	}
	return code, string(diagBytes), nil
}

// simpleBind performs an LDAPv3 simple bind as dn/password. A resultCode
// other than success (including invalidCredentials, 49) is returned as an
// error -- callers distinguish "bad credentials" from "directory
// unreachable" only by error text, which is fine here since both paths
// end in "reject this login attempt."
func (c *conn) simpleBind(dn, password string) error {
	req := berSeq(tagBindRequest,
		berInt(tagInteger, 3), // version 3
		berString(tagOctetStr, dn),
		berTLV(tagAuthSimple, []byte(password)),
	)
	if err := c.send(req); err != nil {
		return fmt.Errorf("ldap: sending bind request: %w", err)
	}
	tag, content, err := c.readMessage()
	if err != nil {
		return err
	}
	if tag != tagBindResponse {
		return fmt.Errorf("ldap: unexpected response to bind (tag 0x%02x)", tag)
	}
	code, diag, err := ldapResult(content)
	if err != nil {
		return err
	}
	if code != resultSuccess {
		return fmt.Errorf("ldap: bind failed (code %d): %s", code, diag)
	}
	return nil
}

// searchEntry is one SearchResultEntry: its DN and attribute values.
type searchEntry struct {
	DN    string
	Attrs map[string][]string
}

// searchOneEquality runs a subtree search under baseDN with a single
// equalityMatch(attr, value) filter, requesting only wantAttrs, and
// returns every matching entry. value is taken as-is -- callers must
// already have escaped it with EscapeFilterValue if it came from outside
// this package.
func (c *conn) searchOneEquality(baseDN, attr, value string, wantAttrs []string) ([]searchEntry, error) {
	filter := berSeq(tagFilterEqualityMatch,
		berString(tagOctetStr, attr),
		berString(tagOctetStr, value),
	)
	attrsSeq := berTLV(tagSequence, nil)
	if len(wantAttrs) > 0 {
		var parts []byte
		for _, a := range wantAttrs {
			parts = append(parts, berString(tagOctetStr, a)...)
		}
		attrsSeq = berTLV(tagSequence, parts)
	}
	req := berSeq(tagSearchRequest,
		berString(tagOctetStr, baseDN),
		berInt(tagEnumerated, 2), // scope: wholeSubtree
		berInt(tagEnumerated, 0), // derefAliases: neverDerefAliases
		berInt(tagInteger, 0),    // sizeLimit: server default
		berInt(tagInteger, 0),    // timeLimit: server default
		berBool(tagBoolean, false),
		filter,
		attrsSeq,
	)
	if err := c.send(req); err != nil {
		return nil, fmt.Errorf("ldap: sending search request: %w", err)
	}
	var entries []searchEntry
	for {
		tag, content, err := c.readMessage()
		if err != nil {
			return nil, err
		}
		switch tag {
		case tagSearchResultEntry:
			e, err := parseSearchResultEntry(content)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		case tagSearchResultDone:
			code, diag, err := ldapResult(content)
			if err != nil {
				return nil, err
			}
			if code != resultSuccess {
				return nil, fmt.Errorf("ldap: search failed (code %d): %s", code, diag)
			}
			return entries, nil
		default:
			// Unrecognized message (e.g. a referral) -- skip it rather
			// than failing the whole search.
		}
	}
}

func parseSearchResultEntry(content []byte) (searchEntry, error) {
	_, dnBytes, next, err := berReadTLV(content, 0)
	if err != nil {
		return searchEntry{}, fmt.Errorf("ldap: parsing entry DN: %w", err)
	}
	e := searchEntry{DN: string(dnBytes), Attrs: map[string][]string{}}
	_, attrsContent, _, err := berReadTLV(content, next)
	if err != nil {
		return searchEntry{}, fmt.Errorf("ldap: parsing entry attributes: %w", err)
	}
	i := 0
	for i < len(attrsContent) {
		_, pair, ni, err := berReadTLV(attrsContent, i)
		if err != nil {
			return searchEntry{}, fmt.Errorf("ldap: parsing attribute: %w", err)
		}
		_, nameBytes, pj, err := berReadTLV(pair, 0)
		if err != nil {
			return searchEntry{}, fmt.Errorf("ldap: parsing attribute name: %w", err)
		}
		_, valsContent, _, err := berReadTLV(pair, pj)
		if err != nil {
			return searchEntry{}, fmt.Errorf("ldap: parsing attribute values: %w", err)
		}
		var vals []string
		vi := 0
		for vi < len(valsContent) {
			_, v, nvi, err := berReadTLV(valsContent, vi)
			if err != nil {
				return searchEntry{}, fmt.Errorf("ldap: parsing attribute value: %w", err)
			}
			vals = append(vals, string(v))
			vi = nvi
		}
		e.Attrs[string(nameBytes)] = vals
		i = ni
	}
	return e, nil
}

func (c *conn) unbind() {
	msg := berSeq(tagSequence, berInt(tagInteger, c.nextID()), berTLV(tagUnbindRequest, nil))
	_, _ = c.nc.Write(msg) // best-effort; connection is being closed either way
}

// EscapeFilterValue escapes the characters RFC 4515 requires escaping in
// an LDAP filter's AssertionValue (\, *, (, ), and NUL), so a username
// typed into a login form can never be used to inject additional filter
// clauses. Every value this package places into a filter goes through
// this first.
func EscapeFilterValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\5c`)
		case '*':
			b.WriteString(`\2a`)
		case '(':
			b.WriteString(`\28`)
		case ')':
			b.WriteString(`\29`)
		case 0:
			b.WriteString(`\00`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var errNotFound = errors.New("ldap: user not found")
