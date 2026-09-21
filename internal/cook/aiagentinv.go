/*******************************************************************************
 * @file         aiagentinv.go
 * @brief        Part of the TopoTrace cook module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package cook

import (
	"bufio"
	"encoding/json"
	"path/filepath"
)

// parseAIAgentInventory reads ai_agent_inventory.txt, a JSON-lines raw
// capture written by agent/ubuntu/muster-agent.sh: one JSON object per
// line, each carrying a "kind" of "tool", "mcp_server", or
// "key_presence" (see the agent script's AI agent inventory section for
// the exact fields). Lines that don't parse are skipped, best-effort,
// same as every other raw-capture parser in this package. Produces the
// "ai_agent_inventory" category as {"tools": [...], "mcp_servers":
// [...], "keys": [...]}.
func parseAIAgentInventory(rawDir string) (map[string]any, bool, error) {
	f, ok, err := openIfExists(filepath.Join(rawDir, "ai_agent_inventory.txt"))
	if err != nil || !ok {
		return nil, ok, err
	}
	defer f.Close()

	var tools, servers, keys []map[string]any
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		switch rec["kind"] {
		case "tool":
			tools = append(tools, rec)
		case "mcp_server":
			servers = append(servers, rec)
		case "key_presence":
			keys = append(keys, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	if len(tools) == 0 && len(servers) == 0 && len(keys) == 0 {
		return nil, true, nil
	}
	return map[string]any{
		"tools":       tools,
		"mcp_servers": servers,
		"keys":        keys,
	}, true, nil
}
