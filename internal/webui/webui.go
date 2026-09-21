/*******************************************************************************
 * @file         webui.go
 * @brief        Package webui serves TopoTrace's web dashboard: a small, dependency-free single-page app (plain HTML/CSS/JS, no build step) that talks to the REST API in internal/api.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-14
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package webui serves TopoTrace's web dashboard: a small, dependency-free
// single-page app (plain HTML/CSS/JS, no build step) that talks to the
// REST API in internal/api. Embedded into the binary via embed.FS, so
// `go build` (or the Docker image) produces one self-contained artifact
// with no separate static-asset deploy step -- consistent with the rest
// of the project's "go run and go" ethos.
package webui

import (
	"embed"
	"encoding/base64"
	"io/fs"
	"net/http"
)

//go:embed static
var embedded embed.FS

// ProductLogo keeps the TopoTrace mark available in offline HTML reports.
func ProductLogo() string {
	b, err := embedded.ReadFile("static/img/topotrace-mark.png")
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b)
}

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
