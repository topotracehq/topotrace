/*******************************************************************************
 * @file         ber.go
 * @brief        Minimal BER encode/decode helpers for the handful of ASN.1
 *               shapes internal/ldap needs (LDAPMessage, BindRequest/
 *               Response, SearchRequest/ResultEntry/ResultDone) -- not a
 *               general ASN.1/BER library.
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

import (
	"errors"
	"fmt"
)

// LDAP over TCP always uses definite-length BER (effectively DER for the
// shapes it sends) -- no indefinite-length encoding to worry about, unlike
// general BER. These helpers only cover that subset.

// Universal/constructed tag bytes used throughout.
const (
	tagBoolean    = 0x01
	tagInteger    = 0x02
	tagOctetStr   = 0x04
	tagNull       = 0x05
	tagEnumerated = 0x0A
	tagSequence   = 0x30 // universal, constructed

	// LDAPMessage protocolOp application tags (RFC 4511 section 4.1.1).
	tagBindRequest       = 0x60 // APPLICATION 0, constructed
	tagBindResponse      = 0x61 // APPLICATION 1, constructed
	tagUnbindRequest     = 0x42 // APPLICATION 2, primitive
	tagSearchRequest     = 0x63 // APPLICATION 3, constructed
	tagSearchResultEntry = 0x64 // APPLICATION 4, constructed
	tagSearchResultDone  = 0x65 // APPLICATION 5, constructed

	// Filter choice context tags (RFC 4511 section 4.5.1.7), constructed
	// unless noted.
	tagFilterAnd           = 0xA0
	tagFilterEqualityMatch = 0xA3

	// BindRequest authentication CHOICE: simple [0] OCTET STRING (primitive,
	// context class).
	tagAuthSimple = 0x80
)

func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)} // #nosec G115 -- n < 0x80 here, always fits in a byte
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...) // #nosec G115 -- len(b) is at most 8 (byte-width of an int), always fits in a byte
}

func berTLV(tag byte, value []byte) []byte {
	out := append([]byte{tag}, berLength(len(value))...)
	return append(out, value...)
}

func berInt(tag byte, n int) []byte {
	if n == 0 {
		return berTLV(tag, []byte{0})
	}
	var b []byte
	v := n
	neg := v < 0
	for v != 0 && v != -1 {
		b = append([]byte{byte(v & 0xff)}, b...)
		v >>= 8
	}
	// Ensure the high bit correctly reflects sign (LDAP only ever sends
	// non-negative small integers here -- message IDs, sizes -- so this
	// is a light-touch two's-complement encoder, not a general one).
	if len(b) == 0 || (!neg && b[0]&0x80 != 0) {
		b = append([]byte{0}, b...)
	}
	return berTLV(tag, b)
}

func berString(tag byte, s string) []byte {
	return berTLV(tag, []byte(s))
}

func berBool(tag byte, v bool) []byte {
	if v {
		return berTLV(tag, []byte{0xff})
	}
	return berTLV(tag, []byte{0x00})
}

func berSeq(tag byte, children ...[]byte) []byte {
	var buf []byte
	for _, c := range children {
		buf = append(buf, c...)
	}
	return berTLV(tag, buf)
}

// berReadLength reads a BER length from b starting at offset i, returning
// the decoded length and the offset of the first content byte.
func berReadLength(b []byte, i int) (length, next int, err error) {
	if i >= len(b) {
		return 0, 0, errors.New("ldap: truncated length")
	}
	first := b[i]
	i++
	if first&0x80 == 0 {
		return int(first), i, nil
	}
	n := int(first &^ 0x80)
	if n == 0 || n > 4 {
		return 0, 0, fmt.Errorf("ldap: unsupported length form (%d octets)", n)
	}
	if i+n > len(b) {
		return 0, 0, errors.New("ldap: truncated long-form length")
	}
	length = 0
	for j := 0; j < n; j++ {
		length = length<<8 | int(b[i+j])
	}
	return length, i + n, nil
}

// berReadTLV reads one tag-length-value from b at offset i and returns the
// tag, the content slice, and the offset just past it.
func berReadTLV(b []byte, i int) (tag byte, content []byte, next int, err error) {
	if i >= len(b) {
		return 0, nil, 0, errors.New("ldap: truncated tag")
	}
	tag = b[i]
	length, contentStart, err := berReadLength(b, i+1)
	if err != nil {
		return 0, nil, 0, err
	}
	if contentStart+length > len(b) {
		return 0, nil, 0, errors.New("ldap: truncated content")
	}
	return tag, b[contentStart : contentStart+length], contentStart + length, nil
}

// berReadInt decodes a two's-complement INTEGER/ENUMERATED content.
func berReadInt(content []byte) (int, error) {
	if len(content) == 0 {
		return 0, errors.New("ldap: empty integer")
	}
	n := 0
	neg := content[0]&0x80 != 0
	for _, c := range content {
		n = n<<8 | int(c)
	}
	if neg {
		n -= 1 << (8 * uint(len(content)))
	}
	return n, nil
}
