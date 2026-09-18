/*******************************************************************************
 * @file         aiquery.go
 * @brief        Package aiquery is "Ask Muster": a natural-language query surface over the fleet data Muster already collects, backed by the Anthropic Messages API.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package aiquery is "Ask Muster": a natural-language query surface
// over the fleet data Muster already collects, backed by the Anthropic
// Messages API. Deliberately narrow, matching the rest of this
// project's outbound-integration style (internal/vuln's OSV.dev client,
// internal/oauth's token exchange): stdlib net/http only, no SDK, one
// request in, one answer out, no tool use, no conversation state kept
// server-side. The pitch this exists to demonstrate is "governed AI,"
// not "a chatbot bolted on" -- every call is meant to be logged by the
// caller (internal/api's handleAsk, via Store.RecordAudit) so a
// question and its answer are both part of the same audit trail every
// other privileged action in this project already goes through.
package aiquery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultModel is used whenever Config.Model is empty. Kept as a plain
// string, not a typed constant, the same "just pass the id" approach
// the rest of the Anthropic API surface uses.
const defaultModel = "claude-opus-5"

const apiURL = "https://api.anthropic.com/v1/messages"
const anthropicVersion = "2023-06-01"

// Config is the operator-supplied Anthropic credential/model for Ask
// Muster -- see cmd/muster's -ai-api-key flag / MUSTER_AI_API_KEY env
// var. A zero-value Config (empty APIKey) means the feature is
// configured off: Ask returns ErrNotConfigured rather than making a
// request with no credential or panicking on a nil client.
type Config struct {
	APIKey string
	Model  string // defaults to defaultModel when empty
}

// Enabled reports whether cfg carries a usable API key.
func (c Config) Enabled() bool { return c.APIKey != "" }

// ErrNotConfigured is returned by Ask when cfg.APIKey is empty -- the
// caller should surface this as a clear "not configured" error, not a
// generic 500.
var ErrNotConfigured = errors.New("aiquery: no Anthropic API key configured (set -ai-api-key or MUSTER_AI_API_KEY)")

// systemPrompt frames the model's role and, critically, tells it to
// answer only from the supplied fleet context -- the "governed" half of
// "governed AI": Ask Muster is meant to answer questions about this
// fleet's real, current data, not free-associate about security topics
// in general or invent hosts/findings that aren't in the snapshot.
const systemPrompt = `You are "Ask Muster," a governed-AI assistant built into the Muster fleet inventory and compliance-posture platform. You are given a compact JSON snapshot of the operator's real fleet data below (hosts, posture scores, vulnerability findings, software/shadow-AI violations, discovered-but-unmanaged assets, and policy rules) plus a question. Answer using ONLY that snapshot. Be concise and specific -- cite host names, scores, package names, and CVE IDs when relevant. If the snapshot doesn't contain enough information to answer, say so plainly rather than guessing or inventing data. This is a security/compliance tool: every question and answer is recorded to Muster's audit log, so keep answers factual and grounded in the provided context.`

// Ask sends question, plus a compact JSON encoding of fleetContext, to
// the Anthropic Messages API and returns Claude's text answer.
// fleetContext is typically the compact per-host/fleet summary
// internal/api's handleAsk builds from the Store -- this package never
// touches the Store itself, keeping the "build context" and "call the
// model" concerns separate.
func Ask(ctx context.Context, cfg Config, question string, fleetContext any) (string, error) {
	if !cfg.Enabled() {
		return "", ErrNotConfigured
	}
	model := cfg.Model
	if model == "" {
		model = defaultModel
	}

	ctxJSON, err := json.Marshal(fleetContext)
	if err != nil {
		return "", fmt.Errorf("aiquery: encoding fleet context: %w", err)
	}

	userContent := fmt.Sprintf("Fleet context (JSON):\n%s\n\nQuestion: %s", ctxJSON, question)

	reqBody, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userContent},
		},
	})
	if err != nil {
		return "", fmt.Errorf("aiquery: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("aiquery: building request: %w", err)
	}
	req.Header.Set("x-api-key", cfg.APIKey)
	req.Header.Set("anthropic-version", anthropicVersion)
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("aiquery: calling Anthropic API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("aiquery: reading Anthropic response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Error.Message != "" {
			return "", fmt.Errorf("aiquery: Anthropic API error (status %d, %s): %s", resp.StatusCode, apiErr.Error.Type, apiErr.Error.Message)
		}
		return "", fmt.Errorf("aiquery: Anthropic API returned status %d", resp.StatusCode)
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("aiquery: decoding Anthropic response: %w", err)
	}

	var sb strings.Builder
	for _, block := range out.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	answer := strings.TrimSpace(sb.String())
	if answer == "" {
		return "", fmt.Errorf("aiquery: empty response from Anthropic (stop_reason=%s)", out.StopReason)
	}
	return answer, nil
}
