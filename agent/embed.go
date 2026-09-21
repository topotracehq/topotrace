/*******************************************************************************
 * @file         embed.go
 * @brief        Package agent embeds a copy of every real agent script this repo ships, so the web dashboard's Agents/download page (internal/api's handleDownloadAgent) can serve them straight from the compiled binary -- the exact same file a human woul...
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package agent embeds a copy of every real agent script this repo
// ships, so the web dashboard's Agents/download page
// (internal/api's handleDownloadAgent) can serve them straight from the
// compiled binary -- the exact same file a human would `cat` and run by
// hand per each platform's own README, never a second copy that can
// drift out of sync with it. This file has no other logic in it on
// purpose: it exists only to give embed.FS something to attach to.
package agent

import "embed"

//go:embed ubuntu/muster-agent.sh windows/muster-agent.ps1 macos/muster-agent.sh
var Scripts embed.FS

// ScriptPath maps a platform name (as used across the API/web UI --
// "linux", "windows", "macos") to Scripts' embedded path and the
// filename it should be offered for download as. Deliberately a fixed,
// small map, not a directory scan -- the same "small allow-list" spirit
// as everywhere else in this project, and it means a typo in a new
// platform's embed path fails at the one call site that uses this, not
// silently.
var ScriptPath = map[string]struct {
	Embedded string
	Filename string
}{
	"linux":   {Embedded: "ubuntu/muster-agent.sh", Filename: "muster-agent.sh"},
	"windows": {Embedded: "windows/muster-agent.ps1", Filename: "muster-agent.ps1"},
	"macos":   {Embedded: "macos/muster-agent.sh", Filename: "muster-agent.sh"},
}
