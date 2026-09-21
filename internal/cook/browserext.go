/*******************************************************************************
 * @file         browserext.go
 * @brief        Part of the Muster cook module.
 * @project      Muster
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
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
)

// parseBrowserExtensions reads browser_extensions.txt, the one capture
// file every agent (Linux, macOS, Windows) writes the same way: tab-
// separated browser, user/profile, extension id, version, base64
// manifest.json, base64 English messages.json (may be empty). The
// manifest is parsed here as real JSON -- name, version, permissions,
// host_permissions, manifest_version -- and a localized
// "__MSG_key__" name is resolved through messages.json when present.
// Produces the usual {"count", "items"} list shape under the
// "browser_extensions" category.
func parseBrowserExtensions(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "browser_extensions.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var items []map[string]any
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20) // manifests can be large
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 5 {
			continue
		}
		item := map[string]any{
			"browser": fields[0],
			"profile": fields[1],
			"id":      fields[2],
			"version": fields[3],
		}
		var manifest struct {
			Name            string   `json:"name"`
			Version         string   `json:"version"`
			ManifestVersion int      `json:"manifest_version"`
			Permissions     []any    `json:"permissions"`
			HostPermissions []string `json:"host_permissions"`
			Description     string   `json:"description"`
			UpdateURL       string   `json:"update_url"`
		}
		if raw, err := base64.StdEncoding.DecodeString(fields[4]); err == nil {
			_ = json.Unmarshal(raw, &manifest)
		}
		name := manifest.Name
		if strings.HasPrefix(name, "__MSG_") && len(fields) >= 6 && fields[5] != "" {
			key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
			if raw, err := base64.StdEncoding.DecodeString(fields[5]); err == nil {
				var msgs map[string]struct {
					Message string `json:"message"`
				}
				if json.Unmarshal(raw, &msgs) == nil {
					if m, ok := msgs[key]; ok && m.Message != "" {
						name = m.Message
					}
				}
			}
		}
		if name == "" || strings.HasPrefix(name, "__MSG_") {
			name = fields[2]
		}
		item["name"] = name
		if manifest.Version != "" {
			item["version"] = manifest.Version
		}
		item["manifest_version"] = manifest.ManifestVersion
		// MV2 manifests list host patterns inside "permissions"; MV3
		// splits them into host_permissions. Normalize both into one
		// permissions list plus one host list so the server-side
		// evaluation doesn't care which manifest version it's looking at.
		var perms, hosts []string
		for _, p := range manifest.Permissions {
			if s, ok := p.(string); ok {
				if isHostPattern(s) {
					hosts = append(hosts, s)
				} else {
					perms = append(perms, s)
				}
			}
		}
		hosts = append(hosts, manifest.HostPermissions...)
		item["permissions"] = perms
		item["host_permissions"] = hosts
		item["from_web_store"] = strings.Contains(manifest.UpdateURL, "google.com") || strings.Contains(manifest.UpdateURL, "microsoft.com") || strings.Contains(manifest.UpdateURL, "edge.microsoft")
		items = append(items, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	if len(items) == 0 {
		return nil, true, nil
	}
	return listResult(items), true, nil
}

func isHostPattern(s string) bool {
	return s == "<all_urls>" || strings.Contains(s, "://")
}
