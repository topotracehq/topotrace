/*******************************************************************************
 * @file         certs.go
 * @brief        Package certs evaluates a host's tls_certificates fact (see internal/cook: server certs from Let's Encrypt/nginx/apache/haproxy dirs on Linux and macOS, the machine Personal store on Windows) for expiry -- the classic silent outage: nobo...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package certs evaluates a host's tls_certificates fact (see
// internal/cook: server certs from Let's Encrypt/nginx/apache/haproxy
// dirs on Linux and macOS, the machine Personal store on Windows) for
// expiry -- the classic silent outage: nobody notices until the day it
// stops working. Expired and expiring-soon certificates become a
// compliance check, a risk factor, a host-page card and a Fleet tile.
package certs

import (
	"fmt"
	"sort"
	"time"
)

// ExpiringSoon is how far ahead of NotAfter a certificate is flagged.
const ExpiringSoon = 30 * 24 * time.Hour

// Cert is one certificate with its verdict.
type Cert struct {
	ID       string    `json:"id"` // path (Linux/macOS) or thumbprint (Windows)
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	State    string    `json:"state"` // "expired", "expiring", "ok", "unknown" (unparseable date)
	Detail   string    `json:"detail"`
}

// FromFact evaluates a tls_certificates fact's "items" as of now,
// worst first (expired, then soonest to expire).
func FromFact(items any, now time.Time) []Cert {
	var list []map[string]any
	switch t := items.(type) {
	case []map[string]any:
		list = t
	case []any:
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				list = append(list, m)
			}
		}
	}
	out := make([]Cert, 0, len(list))
	for _, m := range list {
		c := Cert{ID: str(m["id"]), Subject: str(m["subject"]), Issuer: str(m["issuer"])}
		raw := str(m["not_after"])
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			c.State, c.Detail = "unknown", "unparseable expiry: "+raw
			out = append(out, c)
			continue
		}
		c.NotAfter = t
		c.DaysLeft = int(t.Sub(now).Hours() / 24)
		switch {
		case now.After(t):
			c.State = "expired"
			c.Detail = fmt.Sprintf("%s expired %d days ago (%s)", c.Subject, -c.DaysLeft, t.Format("Jan 2, 2006"))
		case t.Sub(now) <= ExpiringSoon:
			c.State = "expiring"
			c.Detail = fmt.Sprintf("%s expires in %d days (%s)", c.Subject, c.DaysLeft, t.Format("Jan 2, 2006"))
		default:
			c.State = "ok"
			c.Detail = fmt.Sprintf("%s valid until %s (%d days)", c.Subject, t.Format("Jan 2, 2006"), c.DaysLeft)
		}
		out = append(out, c)
	}
	rank := map[string]int{"expired": 0, "expiring": 1, "unknown": 2, "ok": 3}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		return out[i].DaysLeft < out[j].DaysLeft
	})
	return out
}

// Problems returns only expired and expiring certificates.
func Problems(cs []Cert) []Cert {
	var out []Cert
	for _, c := range cs {
		if c.State == "expired" || c.State == "expiring" {
			out = append(out, c)
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
