package aiquery

import "sync"

// ConfigStore holds a Config that can be replaced at runtime, so
// PATCH /api/settings can reconfigure or disable Ask Muster on a
// running server with no restart. cmd/muster constructs exactly one
// ConfigStore (even when starting with no -ai-api-key at all -- its
// zero-value Config just means Enabled() == false, same as before) and
// wires it into api.Server.AIQuery; handleAsk calls Get() on every
// request rather than reading a value captured once at startup.
type ConfigStore struct {
	mu  sync.RWMutex
	cfg Config
}

// NewConfigStore returns a ConfigStore holding the given initial cfg
// (which may be the zero value).
func NewConfigStore(cfg Config) *ConfigStore {
	return &ConfigStore{cfg: cfg}
}

// Get returns the currently configured Config.
func (s *ConfigStore) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Set replaces the current Config. Passing the zero value disables Ask
// Muster, same as never setting -ai-api-key.
func (s *ConfigStore) Set(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}
