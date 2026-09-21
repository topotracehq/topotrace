/*******************************************************************************
 * @file         embed.go
 * @brief        Package docs embeds TopoTrace's in-app documentation pages, so the web dashboard's Docs tab (GET /api/docs, GET /api/docs/{name}) can serve them straight from the compiled binary -- the same "one source of truth, no separate copy that can d...
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package docs embeds TopoTrace's in-app documentation pages, so the web
// dashboard's Docs tab (GET /api/docs, GET /api/docs/{name}) can serve
// them straight from the compiled binary -- the same "one source of
// truth, no separate copy that can drift" reasoning agent/embed.go
// already uses for the downloadable agent scripts.
package docs

import "embed"

//go:embed *.md
var Pages embed.FS

// Index lists every doc page in the order the Docs tab should show
// them, with a short display title -- embed.FS's ReadDir gives file
// names but not a human title or an intentional order, so this is
// maintained by hand alongside the .md files themselves.
var Index = []struct {
	Name  string `json:"name"` // filename without extension, and the URL slug
	Title string `json:"title"`
}{
	{"getting-started", "Getting Started"},
	{"interface", "Dashboard & Navigation"},
	{"fleet-workspace", "Fleet Workspace & Reports"},
	{"site-operations", "Discovery & Remote Deployment"},
	{"workflows", "Work Queue & Governed Changes"},
	{"visibility", "Device Visibility & Demo Walkthrough"},
	{"workspace-tools", "Workspace Tools & Presentation"},
	{"recovery", "Full-server Recovery"},
	{"legal", "Copyright & Responsible Use"},
	{"agents", "Agents & Enrollment"},
	{"api-reference", "API Reference"},
	{"security-model", "Security Model"},
	{"compliance", "Compliance & Software Lists"},
	{"scanner-import", "Scanner Import"},
	{"entity-graph", "Entity Map"},
	{"data-model", "Data Model"},
	{"ask-topotrace", "Ask TopoTrace"},
	{"siem-integration", "SIEM Integration"},
	{"ai-agent-inventory", "AI Agent Inventory"},
}
