package siemforward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SplunkHEC forwards SIEMEvents to a Splunk HTTP Event Collector
// (https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
// via a plain HTTPS POST to <URL>/services/collector/event, with
// "Authorization: Splunk <Token>" -- the standard HEC "event" wire
// format, hand-rolled against Splunk's published docs the same way
// internal/oauth hand-rolls its OAuth2 exchange: no SDK dependency, and
// simple enough not to need one.
type SplunkHEC struct {
	// URL is the HEC base URL, e.g. https://splunk.example.com:8088.
	// Send appends /services/collector/event; a trailing slash on URL
	// is tolerated.
	URL string
	// Token is the HEC token. Sent only in the Authorization header,
	// never logged or included in any error message.
	Token string
	// Client defaults to a 5-second-timeout *http.Client when nil --
	// SIEM delivery is fire-and-forget from every caller in this
	// codebase, so it must never hang a goroutine indefinitely.
	Client *http.Client
}

// NewSplunkHEC returns a Forwarder posting to url with token.
func NewSplunkHEC(url, token string) *SplunkHEC {
	return &SplunkHEC{
		URL:    url,
		Token:  token,
		Client: &http.Client{Timeout: 5 * time.Second},
	}
}

// hecPayload is Splunk HEC's documented "event" wire format: the raw
// event under "event", plus HEC-level metadata. sourcetype is fixed at
// "muster" -- every event this package ever sends comes from Muster's
// own audit trail, so there's nothing per-event to vary it by.
type hecPayload struct {
	Event      SIEMEvent `json:"event"`
	Sourcetype string    `json:"sourcetype"`
	Time       int64     `json:"time"`
}

// Send posts event to f's HEC endpoint. Returns an error on any
// transport failure or non-2xx reply; it never retries -- callers
// already treat this as fire-and-forget (see WrapStore) and just log
// the error.
func (f *SplunkHEC) Send(ctx context.Context, event SIEMEvent) error {
	payload := hecPayload{
		Event:      event,
		Sourcetype: "muster",
		Time:       event.Timestamp,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("siemforward: encoding HEC payload: %w", err)
	}

	url := strings.TrimRight(f.URL, "/") + "/services/collector/event"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siemforward: building HEC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+f.Token)

	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("siemforward: posting to splunk hec: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siemforward: splunk hec replied %s", resp.Status)
	}
	return nil
}
