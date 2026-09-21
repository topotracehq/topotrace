/*******************************************************************************
 * @file         plugins.go
 * @brief        Part of the TopoTrace api module.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-21
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import "net/http"

// handleListPlugins is GET /api/plugins -- the name, version, and
// mount point of every currently-loaded out-of-process plugin (see
// internal/pluginhost, docs/plugins.md). Empty when -plugin-dir was
// never configured.
func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, "readonly"); !ok {
		return
	}
	type pluginOut struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		MountPrefix string `json:"mount_prefix"`
		Description string `json:"description"`
	}
	out := []pluginOut{}
	if s.Plugins != nil {
		for _, pi := range s.Plugins.List() {
			out = append(out, pluginOut{
				Name: pi.Name, Version: pi.Version,
				MountPrefix: pi.MountPrefix, Description: pi.Description,
			})
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"plugins": out})
}
