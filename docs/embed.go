// Package docs embeds Muster's in-app documentation pages, so the web
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
	{"agents", "Agents & Enrollment"},
	{"api-reference", "API Reference"},
	{"security-model", "Security Model"},
	{"compliance", "Compliance & Software Lists"},
	{"ask-muster", "Ask Muster"},
	{"siem-integration", "SIEM Integration"},
}
