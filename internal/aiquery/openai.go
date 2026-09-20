/*******************************************************************************
 * @file         openai.go
 * @brief        Part of the Muster aiquery module.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

package aiquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// This file implements the OpenAI chat-completions shape, which is the
// one wire format worth supporting beyond Anthropic's: Hugging Face's
// Inference Providers router, LM Studio, Ollama, vLLM and
// text-generation-inference all speak it, so one implementation reaches
// every hosted Hugging Face model and every model an operator runs
// themselves. Only BaseURL changes between them.
//
// Written against the published chat-completions spec with stdlib
// net/http only, the same approach as every other outbound integration
// in this project (internal/siemforward's three SIEM backends,
// internal/webhook's four sinks, internal/vuln's OSV.dev client).

// chatCompletionsPath is appended to a base URL that does not already
// name an endpoint.
const chatCompletionsPath = "/chat/completions"

// minOpenAITokens is the floor this backend applies to any caller's
// token budget. See the comment at its use for why.
const minOpenAITokens = 3072

// endpointFor turns whatever the operator typed into a URL to POST to.
// People reasonably enter any of these, and all of them should work:
//
//	https://router.huggingface.co/v1
//	https://router.huggingface.co/v1/
//	https://router.huggingface.co/v1/chat/completions
//	http://10.0.0.188:11434/v1        (Ollama)
//	http://10.0.0.188:1234/v1         (LM Studio)
//
// Getting this wrong is a 404 with no useful message, which is a
// miserable thing to debug against someone else's server, so it is
// handled here rather than left to the operator to get exactly right.
func endpointFor(baseURL string) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(u, chatCompletionsPath) {
		return u
	}
	return u + chatCompletionsPath
}

// completeOpenAI sends one system+user exchange to an OpenAI-compatible
// chat-completions endpoint and returns the assistant's text.
func completeOpenAI(ctx context.Context, cfg Config, system, user string, maxTokens int) (string, error) {
	model := cfg.Model
	if model == "" {
		// Unlike Anthropic, there is no sensible default model name
		// here: what is served depends entirely on which server BaseURL
		// points at. Say so rather than guessing and getting a 404.
		return "", fmt.Errorf("aiquery: the %s backend needs a model name (set -ai-model, e.g. a Hugging Face model id, or the id your local server reports)", BackendOpenAI)
	}
	if maxTokens <= 0 {
		maxTokens = 1024
	}
	// Reasoning models (Qwen3, DeepSeek-R1 and friends) emit a hidden
	// scratchpad before their visible answer, and it is charged against
	// the same budget. A limit tuned for a non-reasoning model gets
	// consumed entirely by thinking, and the caller gets an empty
	// answer with finish_reason=length. There is no way to know from
	// here which kind of model is on the other end, so the floor is
	// raised for this backend rather than trusting the caller's budget.
	if maxTokens < minOpenAITokens {
		maxTokens = minOpenAITokens
	}
	reqBody, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})
	if err != nil {
		return "", fmt.Errorf("aiquery: encoding request: %w", err)
	}

	endpoint := endpointFor(cfg.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("aiquery: building request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	// A local server is usually unauthenticated, so an empty key is a
	// normal configuration here rather than a mistake. Hugging Face's
	// router wants a fine-grained token with Inference Providers
	// permission, sent the same way.
	if cfg.APIKey != "" {
		req.Header.Set("authorization", "Bearer "+cfg.APIKey)
	}

	// Generous next to Anthropic's 60s: a local model on CPU, or a
	// cold serverless one, is slow in a way a hosted frontier model is
	// not, and timing out on a first real answer reads as "broken."
	client := &http.Client{Timeout: 180 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("aiquery: calling %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("aiquery: reading response from %s: %w", endpoint, err)
	}

	if resp.StatusCode != http.StatusOK {
		// The error shape is consistent enough across these servers to
		// be worth unwrapping: the message is usually the only thing
		// that says what is actually wrong (unknown model, bad token,
		// model still loading).
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
			// Some servers return a bare {"message": ...} or
			// {"detail": ...} instead.
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		if json.Unmarshal(body, &apiErr) == nil {
			for _, msg := range []string{apiErr.Error.Message, apiErr.Message, apiErr.Detail} {
				if msg != "" {
					return "", fmt.Errorf("aiquery: %s returned status %d: %s", endpoint, resp.StatusCode, msg)
				}
			}
		}
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		if snippet == "" {
			return "", fmt.Errorf("aiquery: %s returned status %d", endpoint, resp.StatusCode)
		}
		return "", fmt.Errorf("aiquery: %s returned status %d: %s", endpoint, resp.StatusCode, snippet)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				// A reasoning model's scratchpad. Ollama calls it
				// "reasoning"; vLLM and DeepSeek-compatible servers call
				// it "reasoning_content". Never used as the answer --
				// it is read only so an empty content can be explained
				// instead of reported as a blank mystery.
				Reasoning        string `json:"reasoning"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("aiquery: decoding response from %s: %w", endpoint, err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("aiquery: %s returned no choices", endpoint)
	}
	choice := out.Choices[0]
	answer := strings.TrimSpace(choice.Message.Content)
	if answer != "" {
		return answer, nil
	}

	// An empty answer is almost always a reasoning model that spent its
	// whole token budget thinking. Say that, and say what to do about
	// it: the bare "empty response" this used to return sent the
	// operator looking at the network and the model name, neither of
	// which was the problem.
	reasoning := strings.TrimSpace(choice.Message.Reasoning)
	if reasoning == "" {
		reasoning = strings.TrimSpace(choice.Message.ReasoningContent)
	}
	if reasoning != "" {
		if choice.FinishReason == "length" {
			return "", fmt.Errorf("aiquery: %s (model %q) used its whole %d-token budget on reasoning and never produced an answer. "+
				"Use a non-reasoning build of the model (for Qwen3 on Ollama, the -instruct-2507 tags), or turn thinking off on the server",
				endpoint, model, maxTokens)
		}
		return "", fmt.Errorf("aiquery: %s (model %q) returned only reasoning and no answer (finish_reason=%s)", endpoint, model, choice.FinishReason)
	}
	if choice.FinishReason == "length" {
		return "", fmt.Errorf("aiquery: %s (model %q) hit the %d-token limit before producing any answer", endpoint, model, maxTokens)
	}
	return "", fmt.Errorf("aiquery: empty response from %s (model %q, finish_reason=%s)", endpoint, model, choice.FinishReason)
}
