/*******************************************************************************
 * @file         oauth.go
 * @brief        Package oauth implements a minimal, dependency-free OAuth2 authorization-code login flow (with PKCE) for Muster's web dashboard, plus an in-memory session store for the cookie that flow leaves behind.
 * @project      Muster
 *
 * @author       Michael McGinnis
 * @date         2026-09-17
 * @version      1.0.0
 *
 * Copyright (c) 2026 McGinnis Technologies, LLC. All rights reserved.
 * Licensed under the MIT License -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package oauth implements a minimal, dependency-free OAuth2
// authorization-code login flow (with PKCE) for Muster's web
// dashboard, plus an in-memory session store for the cookie that flow
// leaves behind.
//
// This is deliberately not a full OIDC client: rather than fetching a
// provider's JWKS and verifying an ID token's signature, it takes the
// access token straight to the standard OIDC UserInfo endpoint and
// trusts whatever email claim comes back over that (HTTPS) connection.
// That's simpler, has no JWT-signature-verification code to get
// subtly wrong, and is still exactly how the "authorization code ->
// access token -> UserInfo" half of OIDC is meant to be used -- every
// mainstream IdP (Google, Okta, Azure AD, GitHub via a compatible
// wrapper, Auth0, ...) exposes a UserInfo-shaped endpoint for this.
//
// Like agent/aws, agent/azure, and agent/gcp, this is stdlib-only --
// no golang.org/x/oauth2, since this dev environment has no route to
// proxy.golang.org to vendor it -- so the authorization-code exchange
// and the couple of JSON shapes involved are hand-rolled against the
// RFC 6749 / OpenID Connect Core specs.
//
// Not verified against a live identity provider: this dev environment
// has no OAuth app registration and limited outbound access, so this
// flow has been carefully checked against the RFC and against Google's,
// Okta's, and Auth0's published examples, but has never actually been
// round-tripped against a real IdP. Treat it as a solid first draft;
// test it against your actual identity provider before relying on it
// to gate anything real. See docs/security-model.md.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SessionCookieName is the cookie that carries a logged-in dashboard
// user's session ID once handleAuthCallback completes. It's a random
// opaque ID, not a JWT or any other self-describing token -- the
// actual email/role live server-side in a SessionStore, so a stolen
// cookie is only as dangerous as a stolen session ID for any other
// cookie-session web app, and a session can be revoked (logout, or
// restarting the server) without needing a token-revocation scheme.
const SessionCookieName = "muster_session"

// SessionTTL is how long a session lasts after login, independent of
// activity (no sliding-expiration bookkeeping to get wrong). Once it
// expires, the dashboard just bounces back through /api/auth/login.
const SessionTTL = 12 * time.Hour

// Config holds one server's OAuth2/OIDC login configuration, built by
// NewConfig from the -oauth-* flags in cmd/muster. A nil *Config (or
// one with Enabled false) means OAuth login is off entirely -- every
// caller in internal/api checks for that before touching it.
type Config struct {
	Enabled bool

	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	RedirectURL  string
	Scopes       string

	roleMap []roleMapping
}

type roleMapping struct {
	// pattern is one of: "*" (catch-all), "*@domain.com" (domain
	// wildcard), or a full lowercased email address (exact match).
	pattern string
	role    string
}

// NewConfig validates and builds an OAuth Config from the raw -oauth-*
// flag values. All of clientID/clientSecret/authURL/tokenURL/
// userInfoURL/redirectURL are required together -- OAuth login is all
// or nothing, there's no partially-configured state. scopes defaults
// to "openid email profile" (the standard OIDC scopes needed to get an
// email claim back from UserInfo) when left empty.
func NewConfig(clientID, clientSecret, authURL, tokenURL, userInfoURL, redirectURL, scopes, roleMap string) (*Config, error) {
	if clientID == "" && clientSecret == "" && authURL == "" && tokenURL == "" && userInfoURL == "" && redirectURL == "" && roleMap == "" {
		// Nothing at all was configured -- OAuth login is simply off,
		// not a misconfiguration. Callers treat this nil, non-error
		// return as "disabled."
		return nil, nil
	}
	var missing []string
	for name, v := range map[string]string{
		"-oauth-client-id":     clientID,
		"-oauth-client-secret": clientSecret,
		"-oauth-auth-url":      authURL,
		"-oauth-token-url":     tokenURL,
		"-oauth-userinfo-url":  userInfoURL,
		"-oauth-redirect-url":  redirectURL,
		"-oauth-role-map":      roleMap,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("oauth: partially configured -- also set %s (OAuth login is all-or-nothing; leave every -oauth-* flag empty to disable it entirely)", strings.Join(missing, ", "))
	}

	mappings, err := parseRoleMap(roleMap)
	if err != nil {
		return nil, err
	}
	if scopes == "" {
		scopes = "openid email profile"
	}
	return &Config{
		Enabled:      true,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		UserInfoURL:  userInfoURL,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		roleMap:      mappings,
	}, nil
}

// parseRoleMap parses "admin@example.com=admin,*@example.com=readonly"
// into an ordered list of mappings. Order matters and is preserved:
// RoleFor checks entries in the order they were written, so an
// operator controls precedence just by listing exact-email overrides
// before a domain wildcard, and a domain wildcard before a bare "*"
// catch-all -- there's no separate "most specific wins" logic to
// reason about.
func parseRoleMap(s string) ([]roleMapping, error) {
	var out []roleMapping
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("oauth: invalid -oauth-role-map entry %q (want pattern=role, e.g. admin@example.com=admin)", part)
		}
		pattern := strings.ToLower(strings.TrimSpace(kv[0]))
		role := strings.TrimSpace(kv[1])
		if role != "readonly" && role != "remediate" && role != "admin" {
			return nil, fmt.Errorf("oauth: invalid role %q in -oauth-role-map entry %q (want readonly, remediate, or admin)", role, part)
		}
		out = append(out, roleMapping{pattern: pattern, role: role})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("oauth: -oauth-role-map must have at least one pattern=role entry")
	}
	return out, nil
}

// RoleFor maps a logged-in user's email to one of Muster's three fixed
// roles per -oauth-role-map, or "" if nothing matched (handleAuthCallback
// treats that as "not authorized," not as a default role -- there's no
// implicit access just for having a login at some IdP).
func (c *Config) RoleFor(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	domain := ""
	if i := strings.IndexByte(email, '@'); i >= 0 {
		domain = email[i:]
	}
	for _, m := range c.roleMap {
		switch {
		case m.pattern == "*":
			return m.role
		case m.pattern == email:
			return m.role
		case strings.HasPrefix(m.pattern, "*") && domain != "" && m.pattern[1:] == domain:
			return m.role
		}
	}
	return ""
}

// RoleMapStrings reconstructs -oauth-role-map's "pattern=role" entries,
// in the order they're checked, for the settings API to display --
// none of this is secret (unlike ClientSecret), just the operator's own
// access-control policy, so it's safe to return as-is. Safe on a nil
// Config.
func (c *Config) RoleMapStrings() []string {
	if c == nil {
		return nil
	}
	out := make([]string, len(c.roleMap))
	for i, m := range c.roleMap {
		out[i] = m.pattern + "=" + m.role
	}
	return out
}

// AuthCodeURL builds the identity provider's authorization-endpoint
// URL for one fresh login attempt, using PKCE (RFC 7636, S256) rather
// than relying on the client secret alone to protect the code exchange
// -- cheap to do, and standard practice even for a confidential client
// like this one. It returns the URL to redirect the browser to, plus
// the state and PKCE verifier the caller (handleAuthLogin) must stash
// as short-lived cookies and hand back to Exchange once the identity
// provider redirects back with a code.
func (c *Config) AuthCodeURL() (authURL, state, verifier string, err error) {
	state, err = randomToken(24)
	if err != nil {
		return "", "", "", err
	}
	verifier, err = randomToken(48)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", c.ClientID)
	v.Set("redirect_uri", c.RedirectURL)
	v.Set("scope", c.Scopes)
	v.Set("state", state)
	v.Set("code_challenge", challenge)
	v.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(c.AuthURL, "?") {
		sep = "&"
	}
	return c.AuthURL + sep + v.Encode(), state, verifier, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type userInfoResponse struct {
	Email string `json:"email"`
}

// Exchange trades an authorization code -- plus the PKCE verifier
// AuthCodeURL generated for this same login attempt -- for an access
// token at the token endpoint, then calls the UserInfo endpoint with
// that access token and returns whatever email claim it reports. See
// the package doc comment for why this stops at UserInfo rather than
// also parsing/verifying an ID token.
func (c *Config) Exchange(ctx context.Context, code, verifier string) (email string, err error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURL)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		desc := tok.ErrorDesc
		if desc == "" {
			desc = tok.Error
		}
		if desc == "" {
			desc = truncate(string(body), 300)
		}
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, desc)
	}

	uReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.UserInfoURL, nil)
	if err != nil {
		return "", err
	}
	uReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uResp, err := client.Do(uReq)
	if err != nil {
		return "", fmt.Errorf("calling userinfo endpoint: %w", err)
	}
	defer uResp.Body.Close()
	uBody, err := io.ReadAll(uResp.Body)
	if err != nil {
		return "", err
	}
	if uResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo endpoint returned HTTP %d: %s", uResp.StatusCode, truncate(string(uBody), 300))
	}

	var info userInfoResponse
	if err := json.Unmarshal(uBody, &info); err != nil {
		return "", fmt.Errorf("parsing userinfo response: %w", err)
	}
	if info.Email == "" {
		return "", fmt.Errorf("userinfo response had no email claim -- check that %q is in -oauth-scopes", "email")
	}
	return info.Email, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Session is what a SessionStore hands back for a valid session
// cookie: the role a dashboard request authenticated this way should
// be checked against, exactly like an API key's role, plus the email
// it came from for audit logging.
type Session struct {
	Email  string
	Role   string
	Expiry time.Time
}

// SessionStore is a small in-memory, mutex-guarded map from session ID
// to Session. It is intentionally not backed by the Store interface
// (memstore/pgstore) -- sessions are short-lived, high-churn, and
// nobody needs them to survive a restart or to be queried outside this
// process, so adding a persistent table for them would be needless
// weight. The trade-off, stated plainly: restarting the server (or
// running more than one replica behind a load balancer) invalidates
// or fails to share sessions, so every logged-in dashboard user simply
// logs in again -- there is no multi-instance deployment story here
// yet. See docs/security-model.md.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

// NewSessionStore returns an empty SessionStore ready to use.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]Session)}
}

// Create starts a new session for email/role and returns its opaque
// session ID (what the caller sets as the SessionCookieName cookie's
// value). Also opportunistically garbage-collects expired sessions --
// see gcLocked -- so this map can't grow unbounded over a long-running
// server's lifetime without a background goroutine to do it.
func (s *SessionStore) Create(email, role string) string {
	id, err := randomToken(32)
	if err != nil {
		// crypto/rand failing at all is effectively unrecoverable for
		// a security-sensitive ID, but a live server handling one
		// dashboard login shouldn't panic over it -- fall back to a
		// time-based ID; worst case this one session is guessable,
		// not that the whole request crashes.
		id = fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.sessions[id] = Session{Email: email, Role: role, Expiry: time.Now().Add(SessionTTL)}
	return id
}

// Get returns the session for id, or ok=false if it doesn't exist or
// has expired (in which case it's also removed).
func (s *SessionStore) Get(id string) (Session, bool) {
	if id == "" {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if time.Now().After(sess.Expiry) {
		delete(s.sessions, id)
		return Session{}, false
	}
	return sess, true
}

// Delete removes a session immediately -- what handleAuthLogout calls.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// gcLocked drops every expired session. Caller must hold s.mu.
func (s *SessionStore) gcLocked() {
	now := time.Now()
	for id, sess := range s.sessions {
		if now.After(sess.Expiry) {
			delete(s.sessions, id)
		}
	}
}
