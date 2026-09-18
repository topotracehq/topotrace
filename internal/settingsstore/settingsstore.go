// Package settingsstore persists the small, explicit set of settings
// that PATCH /api/settings can change live -- SIEM forwarding's HEC
// credentials and Ask Muster's API key/model -- so a value set from the
// dashboard survives a process restart the same way a -flag/env var
// would have. Deliberately narrow: everything else GET /api/settings
// reports on (storage backend, listen addresses, the auth token,
// OAuth, webhooks, the vuln feed) stays CLI-flag/env-var-only, changed
// only by restarting the process with different flags, exactly like
// every earlier round of this project. Adding a field here is a
// deliberate per-field decision made in internal/api's PATCH handler,
// not a default this package encourages.
package settingsstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Overrides is the on-disk shape -- a straight mirror of the fields
// PATCH /api/settings accepts. Every field is a plain secret-bearing
// string (the HEC token, the AI API key) written with 0o600
// permissions; unlike GET /api/settings's response, this file is
// deliberately not safe to expose over HTTP or log.
type Overrides struct {
	SIEMHECURL   string `json:"siem_hec_url,omitempty"`
	SIEMHECToken string `json:"siem_hec_token,omitempty"`
	AIAPIKey     string `json:"ai_api_key,omitempty"`
	AIModel      string `json:"ai_model,omitempty"`
}

// Load reads path and decodes it as Overrides. A missing file is not
// an error -- it returns the zero value, exactly like a server that
// has never had its settings edited from the dashboard.
func Load(path string) (Overrides, error) {
	var o Overrides
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return o, nil
		}
		return o, fmt.Errorf("settingsstore: reading %s: %w", path, err)
	}
	if len(data) == 0 {
		return o, nil
	}
	if err := json.Unmarshal(data, &o); err != nil {
		return o, fmt.Errorf("settingsstore: parsing %s: %w", path, err)
	}
	return o, nil
}

// Save writes o to path, atomically (write to a temp file in the same
// directory, then rename over path) and with 0o600 permissions, since
// this file carries secrets in plain text. The temp file is cleaned up
// on any failure before the rename.
func Save(path string, o Overrides) error {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("settingsstore: encoding overrides: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("settingsstore: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".settings-overrides-*.json.tmp")
	if err != nil {
		return fmt.Errorf("settingsstore: creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("settingsstore: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("settingsstore: closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("settingsstore: setting permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("settingsstore: renaming into place: %w", err)
	}
	return nil
}
