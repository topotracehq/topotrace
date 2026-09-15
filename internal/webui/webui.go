// Package webui serves Muster's web dashboard: a small, dependency-free
// single-page app (plain HTML/CSS/JS, no build step) that talks to the
// REST API in internal/api. Embedded into the binary via embed.FS, so
// `go build` (or the Docker image) produces one self-contained artifact
// with no separate static-asset deploy step -- consistent with the rest
// of the project's "go run and go" ethos.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var embedded embed.FS

// Handler serves the dashboard's static assets (index.html at "/", plus
// style.css, app.js, and the brand images under img/) directly from the
// compiled binary.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		return nil, err
	}
	return http.FileServerFS(sub), nil
}
