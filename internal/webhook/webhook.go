// Package webhook is a minimal outbound event notifier: on a notable
// event (a new host, a host going stale, a policy violation, a
// remediation action executed), POST a small JSON payload to every
// configured URL. One attempt with one retry after a short delay,
// logged either way -- not a durable queue, not exactly-once delivery,
// just "best effort, and tell the operator if it failed twice in a
// row." Same scope philosophy as everything else in this project:
// small, real, and honest about what it isn't.
package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Event is the JSON payload posted to every configured webhook URL.
type Event struct {
	Type      string    `json:"type"` // "host_new", "host_stale", "policy_violation", "remediation_executed", "software_violation"
	Host      string    `json:"host,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Dispatcher posts Events to a fixed set of URLs, configured at
// startup. A nil Dispatcher (or one with no URLs) is safe to call Send
// on -- it's a no-op, so callers never need a "webhooks configured?"
// branch of their own.
type Dispatcher struct {
	urls   []string
	client *http.Client
	log    *slog.Logger
}

// New returns a Dispatcher posting to urls (may be empty/nil).
func New(urls []string, log *slog.Logger) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	return &Dispatcher{
		urls:   urls,
		client: &http.Client{Timeout: 5 * time.Second},
		log:    log,
	}
}

// Count reports how many URLs d posts to -- used by the settings API to
// surface "webhooks configured, N of them" without ever exposing the
// URLs themselves. Safe on a nil Dispatcher, same as Send.
func (d *Dispatcher) Count() int {
	if d == nil {
		return 0
	}
	return len(d.urls)
}

// Send posts evt to every configured URL, one retry each after a short
// delay. Blocks for the duration of every attempt -- callers on a
// latency-sensitive path (an HTTP handler, say) should call this via
// `go dispatcher.Send(evt)` rather than inline. Errors are logged, never
// returned: a webhook endpoint being down must never break whatever
// triggered the event in the first place.
func (d *Dispatcher) Send(evt Event) {
	if d == nil || len(d.urls) == 0 {
		return
	}
	evt.Timestamp = time.Now().UTC()
	body, err := json.Marshal(evt)
	if err != nil {
		d.log.Error("webhook: encoding event", "err", err)
		return
	}
	for _, url := range d.urls {
		d.postOnce(url, body)
	}
}

func (d *Dispatcher) postOnce(url string, body []byte) {
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			break
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := d.client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			lastErr = fmt.Errorf("replied %s", resp.Status)
		}
		if attempt == 1 {
			time.Sleep(2 * time.Second)
		}
	}
	if lastErr != nil {
		d.log.Warn("webhook delivery failed", "url", url, "err", lastErr)
	}
}
