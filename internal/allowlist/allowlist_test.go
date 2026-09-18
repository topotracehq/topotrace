/*******************************************************************************
 * @file         allowlist_test.go
 * @brief        Tests for the Muster allowlist package.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package allowlist

import (
	"testing"

	"muster/internal/model"
)

func TestEvaluateShadowAI(t *testing.T) {
	items := []map[string]any{
		{"name": "ollama", "version": "0.1.32"},
		{"name": "chatgpt-desktop", "version": "0.11.0"},
		{"name": "GitHub Copilot for Visual Studio", "version": "17.8"},
		{"name": "curl", "version": "8.5.0"}, // not an AI tool -- should never be flagged
	}

	violations := EvaluateShadowAI(items, nil)
	if len(violations) != 3 {
		t.Fatalf("want 3 shadow AI violations with no allowlist, got %d: %+v", len(violations), violations)
	}
	for _, v := range violations {
		if v.Kind != "shadow_ai" {
			t.Errorf("violation %+v: want Kind shadow_ai", v)
		}
		if v.Package == "curl" {
			t.Errorf("curl should never be flagged as shadow AI: %+v", v)
		}
	}
}

func TestEvaluateShadowAI_AllowlistSuppresses(t *testing.T) {
	items := []map[string]any{
		{"name": "ollama", "version": "0.1.32"},
		{"name": "GitHub Copilot for Visual Studio", "version": "17.8"},
	}
	allow := []model.SoftwareRule{
		{Name: "Approved: GitHub Copilot", Kind: "allow", Match: "github copilot*"},
	}

	violations := EvaluateShadowAI(items, allow)
	if len(violations) != 1 {
		t.Fatalf("want 1 shadow AI violation once Copilot is allowlisted, got %d: %+v", len(violations), violations)
	}
	if violations[0].Package != "ollama" {
		t.Errorf("want ollama still flagged, got %+v", violations[0])
	}
}

func TestEvaluateShadowAI_NoItems(t *testing.T) {
	if v := EvaluateShadowAI(nil, nil); v != nil {
		t.Errorf("want nil for no items, got %+v", v)
	}
	if v := EvaluateShadowAI([]map[string]any{}, nil); v != nil {
		t.Errorf("want nil for empty items, got %+v", v)
	}
}
