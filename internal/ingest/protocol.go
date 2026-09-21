/*******************************************************************************
 * @file         protocol.go
 * @brief        Package ingest is Muster's TCP front door: a lightweight, deliberately simple framed protocol agents use to push a captured data packet, and to report back the outcome of a remediation action they were asked to run.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package ingest is Muster's TCP front door: a lightweight, deliberately
// simple framed protocol agents use to push a captured data packet, and
// to report back the outcome of a remediation action they were asked to
// run.
//
// Wire format, one request per connection, one of two shapes:
//
//	MUSTER1 <platform> <host> <token> <payload-bytes>\n
//	<payload-bytes> raw bytes of a gzip-compressed tar archive>
//
//	MUSTER1-RESULT <token> <action-id> <ok|fail> <detail-bytes>\n
//	<detail-bytes> raw bytes of a short plain-text detail message>
//
// <token> is the shared secret configured on the server via -auth-token,
// or the literal sentinel "-" when none is configured/known -- always
// present as a fixed field rather than optional, so parsing either shape
// stays a single strings.Fields call.
//
// The server replies with one line (a MUSTER1 upload may get a second
// line right after, see below) and closes the connection:
//
//	OK <changes>\n     -- packet accepted, cooked, N fields changed since last time
//	OK\n                -- (MUSTER1-RESULT only) result recorded
//	ERR <message>\n    -- rejected; message is safe to log/display, never
//	                      raw internal error text
//
// A MUSTER1 upload's "OK <changes>" line may be followed by one more
// line, delivering a queued remediation action to the host that just
// reported in:
//
//	ACTION <action-id> <verb> <arg>\n
//
// <arg> is "-" when the verb takes none. See internal/remediate for the
// fixed, allow-listed set <verb> can ever be, and internal/api's
// handleQueueAction for the only path that ever creates one.
//
// This is a from-scratch design, not a port of anything -- picked because
// it's the simplest thing that (a) is a real length-prefixed protocol
// worth writing a decoder for by hand, matching the "concurrent TCP
// ingest daemon" pitch, and (b) is trivial for a test client or a real
// future agent in any language to implement: one line of ASCII, then N
// bytes.
package ingest

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

const (
	protocolUpload = "MUSTER1"
	protocolResult = "MUSTER1-RESULT"

	// noToken is the sentinel an agent sends in place of a real token
	// when none is configured, and what the server treats as "presented
	// no credential" when checking against a configured -auth-token.
	noToken = "-"
)

// uploadHeader is a parsed MUSTER1 request line: an agent pushing a
// captured data packet.
type uploadHeader struct {
	Platform string
	Host     string
	Token    string
	Bytes    int64
}

// resultHeader is a parsed MUSTER1-RESULT request line: an agent
// reporting what happened when it executed a remediation action the
// server handed it on an earlier connection.
type resultHeader struct {
	Token    string
	ActionID string
	Status   string // "ok" or "fail"
	Bytes    int64  // length of the plain-text detail payload that follows
}

var (
	// Keep these conservative -- this is a network-facing parser reading
	// attacker-shaped input before any auth check runs. Platform/host
	// feed directly into filesystem paths downstream, so they're
	// restricted to a safe charset here, at the earliest possible point,
	// rather than trusted and sanitized later.
	maxHeaderLine  = 512
	maxPayload     = int64(256 << 20) // 256MB per packet
	maxResultBytes = int64(8 << 10)   // 8KB -- a short log line, not a capture
)

func isSafeToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// readLine reads one line off r, enforcing maxHeaderLine, and returns its
// whitespace-split fields so the caller can dispatch on fields[0] before
// fully parsing either header shape.
func readLine(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}
	if len(line) > maxHeaderLine {
		return nil, fmt.Errorf("header line too long")
	}
	return strings.Fields(line), nil
}

func readUploadHeader(fields []string) (uploadHeader, error) {
	if len(fields) != 5 {
		return uploadHeader{}, fmt.Errorf("malformed upload header: want 5 fields, got %d", len(fields))
	}
	if fields[0] != protocolUpload {
		return uploadHeader{}, fmt.Errorf("unsupported protocol %q", fields[0])
	}
	platform, host, token := strings.ToLower(fields[1]), fields[2], fields[3]
	if !isSafeToken(platform) || !isSafeToken(host) {
		return uploadHeader{}, fmt.Errorf("invalid platform/host")
	}
	if token != noToken && !isSafeToken(token) {
		return uploadHeader{}, fmt.Errorf("invalid token")
	}
	n, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil || n < 0 || n > maxPayload {
		return uploadHeader{}, fmt.Errorf("invalid payload size")
	}
	return uploadHeader{Platform: platform, Host: host, Token: token, Bytes: n}, nil
}

func readResultHeader(fields []string) (resultHeader, error) {
	if len(fields) != 5 {
		return resultHeader{}, fmt.Errorf("malformed result header: want 5 fields, got %d", len(fields))
	}
	if fields[0] != protocolResult {
		return resultHeader{}, fmt.Errorf("unsupported protocol %q", fields[0])
	}
	token, actionID, status := fields[1], fields[2], fields[3]
	if token != noToken && !isSafeToken(token) {
		return resultHeader{}, fmt.Errorf("invalid token")
	}
	if !isSafeToken(actionID) {
		return resultHeader{}, fmt.Errorf("invalid action id")
	}
	if status != "ok" && status != "fail" {
		return resultHeader{}, fmt.Errorf("status must be ok or fail")
	}
	n, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil || n < 0 || n > maxResultBytes {
		return resultHeader{}, fmt.Errorf("invalid detail size")
	}
	return resultHeader{Token: token, ActionID: actionID, Status: status, Bytes: n}, nil
}
