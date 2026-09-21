/*******************************************************************************
 * @file         certs.go
 * @brief        Part of the TopoTrace cook module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package cook

import (
	"bufio"
	"path/filepath"
	"strings"
	"time"
)

// parseLinuxCerts reads certs.txt from the Linux/macOS agents: one
// tab-separated line per server certificate -- path, subject, issuer,
// notAfter (ISO 8601 UTC). Produces the tls_certificates category in
// the usual {"count", "items"} shape, each item {"id", "subject",
// "issuer", "not_after"}; id is the file path on Linux and the
// thumbprint on Windows (see cookWinCerts) so the same field means
// "the thing that identifies this cert on this host" either way.
func parseLinuxCerts(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "certs.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()
	var items []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		items = append(items, map[string]any{
			"id":        fields[0],
			"subject":   strings.TrimSpace(fields[1]),
			"issuer":    strings.TrimSpace(fields[2]),
			"not_after": normalizeNotAfter(strings.TrimSpace(fields[3])),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	if len(items) == 0 {
		return nil, true, nil
	}
	return listResult(items), true, nil
}

// cookWinCerts reads the Windows agent's certs.txt CSV (Thumbprint,
// Subject, Issuer, NotAfter) into the same tls_certificates shape.
func cookWinCerts(rawDir string) (map[string]any, error) {
	rows, ok, err := parseWindowsCSV(filepath.Join(rawDir, "certs.txt"))
	if err != nil || !ok || len(rows) == 0 {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		if r["Thumbprint"] == "" {
			continue
		}
		items = append(items, map[string]any{
			"id":        r["Thumbprint"],
			"subject":   r["Subject"],
			"issuer":    r["Issuer"],
			"not_after": normalizeNotAfter(r["NotAfter"]),
		})
	}
	if len(items) == 0 {
		return nil, nil
	}
	return listResult(items), nil
}

// normalizeNotAfter accepts ISO 8601 or openssl's "Jan  2 15:04:05 2006
// GMT" and returns RFC 3339 UTC; anything unparseable is passed through
// so the raw value is still visible rather than silently dropped.
func normalizeNotAfter(v string) string {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "Jan _2 15:04:05 2006 MST", "Jan 2 15:04:05 2006 MST", "1/2/2006 3:04:05 PM"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return v
}
