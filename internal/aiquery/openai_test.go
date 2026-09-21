/*******************************************************************************
 * @file         openai_test.go
 * @brief        Tests for the Muster aiquery package.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-18
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package aiquery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpointForAcceptsWhateverTheOperatorTyped(t *testing.T) {
	want := "https://router.huggingface.co/v1/chat/completions"
	for _, in := range []string{
		"https://router.huggingface.co/v1",
		"https://router.huggingface.co/v1/",
		"  https://router.huggingface.co/v1  ",
		"https://router.huggingface.co/v1/chat/completions",
		"https://router.huggingface.co/v1/chat/completions/",
	} {
		if got := endpointFor(in); got != want {
			t.Errorf("endpointFor(%q) = %q, want %q", in, got, want)
		}
	}
	if got := endpointFor("http://10.0.0.188:11434/v1"); got != "http://10.0.0.188:11434/v1/chat/completions" {
		t.Errorf("local base url: %q", got)
	}
}

// okServer replies with one assistant message and records what it got.
func okServer(t *testing.T, answer string, seen *map[string]any, gotAuth *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("posted to %q, want /v1/chat/completions", r.URL.Path)
		}
		if gotAuth != nil {
			*gotAuth = r.Header.Get("authorization")
		}
		body, _ := io.ReadAll(r.Body)
		if seen != nil {
			_ = json.Unmarshal(body, seen)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"` + answer + `"},"finish_reason":"stop"}]}`))
	}))
}

func TestCompleteOpenAIRoundTrip(t *testing.T) {
	var seen map[string]any
	var auth string
	srv := okServer(t, "three hosts are stale", &seen, &auth)
	defer srv.Close()

	cfg := Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "meta-llama/Llama-3.1-8B-Instruct", APIKey: "hf_test"}
	// Above the reasoning-model floor, so the caller's budget passes
	// through untouched (the floor itself is covered separately).
	got, err := Complete(context.Background(), cfg, "you are a fleet assistant", "which hosts are stale?", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got != "three hosts are stale" {
		t.Fatalf("answer: %q", got)
	}
	if auth != "Bearer hf_test" {
		t.Fatalf("authorization header: %q", auth)
	}
	if seen["model"] != "meta-llama/Llama-3.1-8B-Instruct" {
		t.Fatalf("model: %v", seen["model"])
	}
	if seen["max_tokens"] != float64(4096) {
		t.Fatalf("max_tokens: %v", seen["max_tokens"])
	}
	msgs, ok := seen["messages"].([]any)
	if !ok || len(msgs) != 2 {
		t.Fatalf("messages: %v", seen["messages"])
	}
	// The system prompt is what makes this "governed" rather than a
	// generic chatbot, so it has to survive the translation into the
	// chat-completions shape as a real system message.
	first := msgs[0].(map[string]any)
	if first["role"] != "system" || first["content"] != "you are a fleet assistant" {
		t.Fatalf("system message: %v", first)
	}
	second := msgs[1].(map[string]any)
	if second["role"] != "user" || second["content"] != "which hosts are stale?" {
		t.Fatalf("user message: %v", second)
	}
}

func TestCompleteOpenAIOmitsAuthWhenUnauthenticated(t *testing.T) {
	var auth string
	srv := okServer(t, "ok", nil, &auth)
	defer srv.Close()

	// A local Ollama or LM Studio takes no credential at all. Sending
	// an empty bearer token is a good way to get rejected by servers
	// that do check, so it must be omitted entirely.
	cfg := Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "llama3.1:8b"}
	if _, err := Complete(context.Background(), cfg, "s", "u", 0); err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		t.Fatalf("expected no authorization header, got %q", auth)
	}
}

func TestOpenAIBackendEnablement(t *testing.T) {
	// The OpenAI backend needs a base URL, not a key.
	if (Config{Backend: BackendOpenAI}).Enabled() {
		t.Fatal("no base url should not be enabled")
	}
	if !(Config{Backend: BackendOpenAI, BaseURL: "http://x/v1"}).Enabled() {
		t.Fatal("a base url alone should be enough")
	}
	// Anthropic is unchanged: key required, base url irrelevant.
	if (Config{BaseURL: "http://x/v1"}).Enabled() {
		t.Fatal("anthropic without a key should not be enabled")
	}
	if !(Config{APIKey: "k"}).Enabled() {
		t.Fatal("anthropic with a key should be enabled")
	}
	if (Config{}).Normalized().Backend != BackendAnthropic {
		t.Fatal("an empty backend should normalize to anthropic, so existing configs keep working")
	}
}

func TestCompleteOpenAINeedsAModelName(t *testing.T) {
	// There is no sensible default: what is served depends on the
	// server. A clear error beats a 404 from someone else's box.
	_, err := Complete(context.Background(), Config{Backend: BackendOpenAI, BaseURL: "http://x/v1"}, "s", "u", 0)
	if err == nil || !strings.Contains(err.Error(), "needs a model name") {
		t.Fatalf("err: %v", err)
	}
}

func TestCompleteOpenAISurfacesServerErrors(t *testing.T) {
	cases := []struct {
		name, body, want string
		status           int
	}{
		{"openai shape", `{"error":{"message":"Model not found","type":"invalid_request_error"}}`, "Model not found", 404},
		{"bare message", `{"message":"invalid token"}`, "invalid token", 401},
		{"detail", `{"detail":"model is currently loading"}`, "model is currently loading", 503},
		{"not json", `<html>502 Bad Gateway</html>`, "502 Bad Gateway", 502},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cfg := Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "m"}
			_, err := Complete(context.Background(), cfg, "s", "u", 0)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCompleteOpenAIRejectsEmptyAndMissingChoices(t *testing.T) {
	for _, body := range []string{
		`{"choices":[]}`,
		`{"choices":[{"message":{"content":"   "},"finish_reason":"length"}]}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		cfg := Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "m"}
		if _, err := Complete(context.Background(), cfg, "s", "u", 0); err == nil {
			t.Errorf("body %q should have been an error", body)
		}
		srv.Close()
	}
}

func TestCompleteUnconfiguredIsAClearError(t *testing.T) {
	if _, err := Complete(context.Background(), Config{}, "s", "u", 0); err != ErrNotConfigured {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

// A reasoning model that burns its whole budget thinking is the most
// likely way this backend fails in practice, and the old error ("empty
// response") sent the operator looking at the network instead of the
// model. These pin the diagnosis.
func TestCompleteOpenAIExplainsReasoningOnlyResponses(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{
			"ollama style, budget exhausted",
			`{"choices":[{"message":{"content":"","reasoning":"Let me think about the fleet..."},"finish_reason":"length"}]}`,
			"used its whole",
		},
		{
			"vllm style, budget exhausted",
			`{"choices":[{"message":{"content":"","reasoning_content":"thinking..."},"finish_reason":"length"}]}`,
			"used its whole",
		},
		{
			"reasoning but stopped cleanly",
			`{"choices":[{"message":{"content":"","reasoning":"hmm"},"finish_reason":"stop"}]}`,
			"only reasoning and no answer",
		},
		{
			"no reasoning, just truncated",
			`{"choices":[{"message":{"content":""},"finish_reason":"length"}]}`,
			"token limit before producing any answer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			cfg := Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "qwen3:30b"}
			_, err := Complete(context.Background(), cfg, "s", "u", 0)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			// Whatever the failure, the model name belongs in it: that
			// is the thing the operator will change.
			if err != nil && !strings.Contains(err.Error(), "qwen3:30b") {
				t.Fatalf("error should name the model: %v", err)
			}
		})
	}
}

// Reasoning output must never be passed off as the answer.
func TestCompleteOpenAINeverReturnsReasoningAsTheAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"the real answer","reasoning":"secret scratchpad"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()
	got, err := Complete(context.Background(), Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "m"}, "s", "u", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "the real answer" {
		t.Fatalf("answer = %q, want the content field only", got)
	}
}

// The token floor protects a caller whose budget was tuned for a
// non-reasoning model.
func TestCompleteOpenAIRaisesSmallTokenBudgets(t *testing.T) {
	var seen map[string]any
	srv := okServer(t, "ok", &seen, nil)
	defer srv.Close()
	cfg := Config{Backend: BackendOpenAI, BaseURL: srv.URL + "/v1", Model: "m"}
	if _, err := Complete(context.Background(), cfg, "s", "u", 512); err != nil {
		t.Fatal(err)
	}
	if seen["max_tokens"] != float64(minOpenAITokens) {
		t.Fatalf("max_tokens = %v, want the %d floor", seen["max_tokens"], minOpenAITokens)
	}
	// A caller asking for more than the floor keeps what it asked for.
	if _, err := Complete(context.Background(), cfg, "s", "u", 8000); err != nil {
		t.Fatal(err)
	}
	if seen["max_tokens"] != float64(8000) {
		t.Fatalf("max_tokens = %v, want the caller's 8000", seen["max_tokens"])
	}
}
