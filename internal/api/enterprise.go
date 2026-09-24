/*******************************************************************************
 * @file         enterprise.go
 * @brief        HTTP handlers for the enterprise settings gaps filed as
 *               #22-#27 and #32: SCIM provisioning, ABAC host visibility
 *               and field masking, MFA enrollment/enforcement, session
 *               management controls, and the license/seat usage
 *               dashboard. Kept in its own file rather than growing
 *               server.go further -- these features share a lot of
 *               plumbing with each other but very little with the rest
 *               of server.go beyond Server itself.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-24
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"topotrace/internal/acl"
	"topotrace/internal/directory"
	"topotrace/internal/license"
	"topotrace/internal/mfa"
	"topotrace/internal/model"
	"topotrace/internal/oauth"
)

// ---------------------------------------------------------------------
// Shared login-completion path (#22 JIT/deprovisioning check, #26 MFA
// gating) -- every one of handleAuthCallback/handleLDAPLogin/
// handleSAMLACS calls this exactly once, after they've independently
// verified the credential with their own identity provider, instead of
// each reimplementing directory + MFA policy.
// ---------------------------------------------------------------------

// loginOutcome is what completeLogin hands back to its three callers.
type loginOutcome struct {
	SessionID        string
	MFASetupRequired bool // grace-period login with no MFA enrollment yet
}

// completeLogin applies the directory deprovisioning check (#22),
// opportunistically JIT-provisions a directory record, decides whether
// org MFA policy (#26) applies, and issues the session -- a normal one,
// or (if MFA is required and the user is already enrolled) one that
// requires a follow-up POST /api/auth/mfa/verify before it authorizes
// anything else. method is the audit action name ("oauth-login",
// "ldap-login", "saml-login").
func (s *Server) completeLogin(r *http.Request, email, role, method string) (loginOutcome, error) {
	allowed, err := directory.Allowed(r.Context(), s.Store, email)
	if err != nil {
		s.log().Error("checking directory", "email", email, "err", err)
		// Fail closed: a directory the server cannot currently read is
		// not the same thing as "no opinion," because we cannot tell
		// the difference between those two cases from here.
		return loginOutcome{}, fmt.Errorf("login temporarily unavailable")
	}
	if !allowed {
		if _, err := s.Store.RecordAudit(r.Context(), email, method+"-blocked-deprovisioned", email, ""); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
		return loginOutcome{}, fmt.Errorf("this account has been deactivated")
	}
	if _, err := directory.ProvisionJIT(r.Context(), s.Store, email, role); err != nil {
		// JIT provisioning is a convenience, not a gate -- a directory
		// write failure should never block an otherwise-valid login.
		s.log().Error("JIT provisioning", "email", email, "err", err)
	}

	requireMFA := mfa.Required(s.MFAEnforced, s.MFARequiredRoles, role)
	if !requireMFA {
		id := s.Sessions.Create(email, role)
		if _, err := s.Store.RecordAudit(r.Context(), email, method, email, fmt.Sprintf("role=%s", role)); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
		return loginOutcome{SessionID: id}, nil
	}

	enrollment, enrolled, err := mfa.Get(r.Context(), s.Store, email)
	if err != nil {
		s.log().Error("checking MFA enrollment", "email", email, "err", err)
		return loginOutcome{}, fmt.Errorf("login temporarily unavailable")
	}
	if enrolled && enrollment.Enabled {
		id := s.Sessions.CreateRequiringMFA(email, role)
		if _, err := s.Store.RecordAudit(r.Context(), email, method+"-mfa-pending", email, fmt.Sprintf("role=%s", role)); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
		return loginOutcome{SessionID: id}, nil
	}

	// Not enrolled yet. Org policy (#26) gets an enrollment grace
	// window rather than locking everyone out the instant MFA is
	// turned on: within the window, login succeeds normally but flags
	// that setup is still needed; the directory record's CreatedAt is
	// used as the anchor (when this account was first provisioned --
	// JIT or SCIM, either way), not first-login-after-policy-enabled,
	// so the window has one clear, auditable start time regardless of
	// when the admin flips -mfa-required on.
	user, found, derr := directory.Get(r.Context(), s.Store, email)
	graceStart := time.Now()
	if derr == nil && found && !user.CreatedAt.IsZero() {
		graceStart = user.CreatedAt
	}
	if s.MFAGraceDays > 0 && time.Since(graceStart) < time.Duration(s.MFAGraceDays)*24*time.Hour {
		id := s.Sessions.Create(email, role)
		if _, err := s.Store.RecordAudit(r.Context(), email, method+"-mfa-grace", email, fmt.Sprintf("role=%s", role)); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
		return loginOutcome{SessionID: id, MFASetupRequired: true}, nil
	}
	if _, err := s.Store.RecordAudit(r.Context(), email, method+"-mfa-required-blocked", email, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	return loginOutcome{}, fmt.Errorf("multi-factor authentication is required for this account and its enrollment window has passed -- contact an administrator")
}

// ---------------------------------------------------------------------
// MFA endpoints (#26)
// ---------------------------------------------------------------------

// sessionForMFA resolves the caller's session directly (bypassing
// requireRole/requireRoleStrict's normal "MFA-pending sessions don't
// authenticate anything" rule -- see sessionFromCookie) since these are
// exactly the endpoints a pending session must still be able to reach.
func (s *Server) sessionForMFA(r *http.Request) (id string, sess oauth.Session, ok bool) {
	if s.Sessions == nil {
		return "", oauth.Session{}, false
	}
	c, err := r.Cookie(oauth.SessionCookieName)
	if err != nil || c.Value == "" {
		return "", oauth.Session{}, false
	}
	sess, ok = s.Sessions.Get(c.Value)
	return c.Value, sess, ok
}

// handleMFAEnroll is POST /api/auth/mfa/enroll -- generates a new TOTP
// secret for the caller's own account and returns it plus the
// otpauth:// provisioning URI for a QR code. Does not enable MFA by
// itself; handleMFAConfirm does, once the caller proves they actually
// captured the secret.
func (s *Server) handleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.sessionForMFA(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "log in first")
		return
	}
	issuer := s.MFAIssuer
	if issuer == "" {
		issuer = "TopoTrace"
	}
	secret, uri, err := mfa.StartEnrollment(r.Context(), s.Store, sess.Email, issuer)
	if err != nil {
		s.log().Error("starting MFA enrollment", "err", err)
		s.writeError(w, http.StatusInternalServerError, "starting MFA enrollment")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": uri})
}

// handleMFAConfirm is POST /api/auth/mfa/confirm {"code":"123456"} --
// completes enrollment (sets Enabled) and, if the caller's current
// session was created pending MFA, marks it verified in the same call
// so they don't have to separately hit /verify right after enrolling.
func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	id, sess, ok := s.sessionForMFA(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "log in first")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := mfa.Confirm(r.Context(), s.Store, sess.Email, req.Code); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid or expired code")
		return
	}
	s.Sessions.MarkMFAVerified(id)
	if _, err := s.Store.RecordAudit(r.Context(), sess.Email, "mfa-enrolled", sess.Email, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"enrolled": true, "verified": true})
}

// handleMFAVerify is POST /api/auth/mfa/verify {"code":"123456"} -- the
// second step of a login when the account already has MFA enrolled:
// marks the pending session verified once a valid code is presented.
func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	id, sess, ok := s.sessionForMFA(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "log in first")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	enrollment, found, err := mfa.Get(r.Context(), s.Store, sess.Email)
	if err != nil || !found || !enrollment.Enabled {
		s.writeError(w, http.StatusBadRequest, "no MFA enrollment on this account")
		return
	}
	if !mfa.Validate(enrollment.Secret, req.Code) {
		if _, err := s.Store.RecordAudit(r.Context(), sess.Email, "mfa-verify-failed", sess.Email, ""); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
		s.writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.Sessions.MarkMFAVerified(id)
	if _, err := s.Store.RecordAudit(r.Context(), sess.Email, "mfa-verified", sess.Email, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

// ---------------------------------------------------------------------
// Session management endpoints (#27)
// ---------------------------------------------------------------------

// sessionView is what a session admin/self-service endpoint actually
// returns -- deliberately without the session ID (see
// oauth.SessionStore.ListAll's doc comment on why).
type sessionView struct {
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeen    time.Time `json:"last_seen"`
	Expiry      time.Time `json:"expiry"`
	MFAVerified bool      `json:"mfa_verified,omitempty"`
}

func toSessionViews(sessions []oauth.Session) []sessionView {
	out := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionView{
			Email: s.Email, Role: s.Role,
			CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, Expiry: s.Expiry,
			MFAVerified: s.MFAVerified,
		})
	}
	return out
}

// handleListSessions is GET /api/auth/sessions -- admin-only visibility
// into every live dashboard session on this process (#27's "visibility
// into active sessions ... for admins").
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "admin"); !ok {
		return
	}
	if s.Sessions == nil {
		s.writeJSON(w, http.StatusOK, []sessionView{})
		return
	}
	s.writeJSON(w, http.StatusOK, toSessionViews(s.Sessions.ListAll()))
}

// handleListMySessions is GET /api/auth/sessions/mine -- the same
// visibility, scoped to the caller's own account (#27's "... and for
// the user themselves").
func (s *Server) handleListMySessions(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.sessionForMFA(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "log in first")
		return
	}
	s.writeJSON(w, http.StatusOK, toSessionViews(s.Sessions.ListForEmail(sess.Email)))
}

// handleRevokeSessions is POST /api/auth/sessions/revoke
// {"email":"..."} -- admin-only forced logout of every session for one
// user (#27's "forced logout of all sessions on ... admin action";
// also called internally by handleSCIMPatchUser/handleSCIMDeleteUser
// when an account is deactivated).
func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		s.writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	n := 0
	if s.Sessions != nil {
		n = s.Sessions.RevokeAll(req.Email)
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "sessions-revoked", req.Email, fmt.Sprintf("count=%d", n)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// ---------------------------------------------------------------------
// ACL endpoints (#23 resource scoping, #24 field masking)
// ---------------------------------------------------------------------

// viewerRoleEmail resolves the requesting caller's (email, role) for
// ACL evaluation purposes, independent of and read-only with respect to
// requireRole/requireRoleStrict -- those only ever return an actor
// *name* (a key's Name, "master", "anonymous", ...), never a role,
// which ACL masking needs. A viewer who is not authenticated at all, or
// for whom auth is off (AuthToken == ""), is treated as "admin" --
// exactly matching requireRole's own "wide open in demo mode" default,
// so ACL never restricts anything beyond what auth already gates.
func (s *Server) viewerRoleEmail(r *http.Request) (email, role string) {
	if s.AuthToken == "" {
		return "anonymous", "admin"
	}
	if got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); got != "" {
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.AuthToken)) == 1 {
			return "master", "admin"
		}
		if key, found, err := s.Store.FindAPIKeyByHash(r.Context(), sha256Hex(got)); err == nil && found {
			return key.Name, key.Role
		}
		return "", ""
	}
	if email, role, ok := s.sessionFromCookie(r); ok {
		return email, role
	}
	return "", ""
}

// maskHostForViewer applies every ACL policy against host for the
// current request's viewer, returning the (possibly masked) host and
// whether it should be shown at all. When it masks a field for a
// viewer whose role is "admin" (an elevated viewer who could have
// avoided the policy by using a different credential, but didn't), it
// also records an audit entry -- #24's "log when a user with elevated
// access views unmasked data" is really about someone who *could*
// bypass masking; since this function is the only place masking is
// applied, it is also the only correct place to detect that.
func (s *Server) maskHostForViewer(r *http.Request, host model.Host) (model.Host, bool) {
	policies, err := acl.List(r.Context(), s.Store)
	if err != nil || len(policies) == 0 {
		return host, true
	}
	email, role := s.viewerRoleEmail(r)
	decision := acl.Evaluate(policies, role, email, host)
	if !decision.Visible {
		return model.Host{}, false
	}
	if len(decision.Masked) == 0 {
		return host, true
	}
	return acl.MaskHost(host, decision.MaskedSet()), true
}

func (s *Server) handleListACLPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "admin"); !ok {
		return
	}
	policies, err := acl.List(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing ACL policies")
		return
	}
	s.writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleCreateACLPolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	var req acl.Policy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	created, err := acl.Create(r.Context(), s.Store, req)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "create-acl-policy", created.Name, fmt.Sprintf("id=%s", created.ID)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteACLPolicy(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := acl.Delete(r.Context(), s.Store, id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "deleting ACL policy")
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), actor, "delete-acl-policy", id, ""); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// aclPreviewResult is one host as a named subject would see it --
// #23's "permissions should be testable/previewable per-user before
// saving."
type aclPreviewResult struct {
	Host    string   `json:"host"`
	Visible bool     `json:"visible"`
	Masked  []string `json:"masked,omitempty"`
}

// handleACLPreview is POST /api/acl/preview {"role":"readonly"} or
// {"email":"someone@example.com"} -- admin-only, shows exactly what
// that subject would see across every current host, without needing to
// actually log in as them.
func (s *Server) handleACLPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRoleStrict(w, r, "admin"); !ok {
		return
	}
	var req struct {
		Role  string `json:"role"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role == "" && req.Email == "" {
		s.writeError(w, http.StatusBadRequest, "role or email is required")
		return
	}
	policies, err := acl.List(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing ACL policies")
		return
	}
	hosts, err := s.Store.ListHosts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing hosts")
		return
	}
	out := make([]aclPreviewResult, 0, len(hosts))
	for _, h := range hosts {
		decision := acl.Evaluate(policies, req.Role, req.Email, h)
		out = append(out, aclPreviewResult{Host: h.Name, Visible: decision.Visible, Masked: decision.Masked})
	}
	s.writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------
// SCIM 2.0 endpoints (#22)
//
// This implements a practical subset of RFC 7644 sufficient for the
// basic "push a user, push a deactivation" flow every mainstream IdP's
// SCIM app (Okta, Azure AD/Entra ID, OneLogin) supports out of the box
// -- User create/read/list/update/deactivate. It is not a general SCIM
// 2.0 server: no /Groups resource, no filter query language beyond an
// exact userName match, no bulk operations, no PATCH path-expression
// evaluation beyond "replace active" and "replace a TopoTrace-specific
// role extension attribute" (SCIM's core User schema has no notion of
// TopoTrace's three fixed roles, so role is carried as a top-level
// "role" field on the resource -- a deliberate, documented deviation
// from strict schema conformance, not an oversight). Like every other
// identity-provider integration in this codebase, this has not been
// tested against a real IdP's SCIM push in the environment it was
// built in -- see docs/security-model.md before relying on it.
// ---------------------------------------------------------------------

const scimSchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"

// scimUser is deliberately a hand-shaped subset of RFC 7643's User
// resource, not a full implementation of it -- see this section's doc
// comment.
type scimUser struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	UserName string   `json:"userName"`
	Active   bool     `json:"active"`
	// Role is a TopoTrace-specific extension, not part of core SCIM --
	// see this section's doc comment.
	Role   string      `json:"role,omitempty"`
	Meta   scimMeta    `json:"meta"`
	Emails []scimEmail `json:"emails,omitempty"`
}

type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

func toSCIMUser(u directory.User) scimUser {
	return scimUser{
		Schemas: []string{scimSchemaUser}, ID: scimUserID(u.Email),
		UserName: u.Email, Active: u.Active, Role: u.Role,
		Meta:   scimMeta{ResourceType: "User", Created: u.CreatedAt, LastModified: u.UpdatedAt},
		Emails: []scimEmail{{Value: u.Email, Primary: true}},
	}
}

// scimUserID base64url-encodes the email so it is always a valid path
// segment (SCIM IDs must not contain characters like "@" that could be
// ambiguous in a URL, even though most implementations tolerate it) --
// decoded back by scimEmailFromID.
func scimUserID(email string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.ToLower(email)))
}

func scimEmailFromID(id string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// requireSCIMToken is this section's own auth gate, deliberately
// separate from requireRole/requireRoleStrict: a SCIM token is a
// narrow-purpose provisioning credential (create/update/deactivate
// directory records only), not one of the three general API-key roles,
// and should be rotatable independently of them.
func (s *Server) requireSCIMToken(w http.ResponseWriter, r *http.Request) bool {
	if s.SCIMToken == "" {
		s.writeError(w, http.StatusServiceUnavailable, "SCIM provisioning is not configured on this server (see -scim-token)")
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.SCIMToken)) != 1 {
		s.writeError(w, http.StatusUnauthorized, "missing or invalid SCIM bearer token")
		return false
	}
	return true
}

// handleSCIMListUsers is GET /scim/v2/Users -- supports an optional
// exact `filter=userName eq "someone@example.com"` query (the one
// filter form every SCIM client actually sends in practice to check if
// a user already exists before creating them); anything else in
// filter is ignored, matching everyone -- a documented limitation, not
// a silent one.
func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMToken(w, r) {
		return
	}
	users, err := directory.List(r.Context(), s.Store)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing users")
		return
	}
	if f := r.URL.Query().Get("filter"); f != "" {
		if email, ok := parseSCIMUserNameFilter(f); ok {
			filtered := users[:0]
			for _, u := range users {
				if strings.EqualFold(u.Email, email) {
					filtered = append(filtered, u)
				}
			}
			users = filtered
		}
	}
	resources := make([]scimUser, 0, len(users))
	for _, u := range users {
		resources = append(resources, toSCIMUser(u))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"Resources":    resources,
	})
}

func parseSCIMUserNameFilter(filter string) (email string, ok bool) {
	const prefix = "userName eq "
	i := strings.Index(filter, prefix)
	if i == -1 {
		return "", false
	}
	v := strings.TrimSpace(filter[i+len(prefix):])
	v = strings.Trim(v, `"`)
	if v == "" {
		return "", false
	}
	return v, true
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMToken(w, r) {
		return
	}
	email, err := scimEmailFromID(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	u, found, err := directory.Get(r.Context(), s.Store, email)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching user")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "no such user")
		return
	}
	s.writeJSON(w, http.StatusOK, toSCIMUser(u))
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMToken(w, r) {
		return
	}
	var req scimUser
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserName == "" {
		s.writeError(w, http.StatusBadRequest, "userName is required")
		return
	}
	role := req.Role
	if role == "" {
		role = "readonly"
	}
	active := true // SCIM's Active defaults true when the field is absent from a create request
	u, err := directory.Upsert(r.Context(), s.Store, directory.User{
		Email: req.UserName, Role: role, Active: active, Source: "scim",
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.RecordAudit(r.Context(), "scim", "user-provisioned", u.Email, fmt.Sprintf("role=%s source=scim", u.Role)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	s.writeJSON(w, http.StatusCreated, toSCIMUser(u))
}

// scimPatchOp is a minimal subset of RFC 7644's PATCH operation shape --
// only "replace" is supported, with "active" and "role" as the only
// recognized paths (see this section's doc comment).
type scimPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMToken(w, r) {
		return
	}
	email, err := scimEmailFromID(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req struct {
		Operations []scimPatchOp `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	u, found, err := directory.Get(r.Context(), s.Store, email)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetching user")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "no such user")
		return
	}
	deactivated := false
	for _, op := range req.Operations {
		if !strings.EqualFold(op.Op, "replace") {
			continue
		}
		switch strings.ToLower(op.Path) {
		case "active":
			if v, ok := op.Value.(bool); ok {
				u.Active = v
				if !v {
					deactivated = true
				}
			}
		case "role":
			if v, ok := op.Value.(string); ok && v != "" {
				u.Role = v
			}
		}
	}
	updated, err := directory.Upsert(r.Context(), s.Store, u)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if deactivated {
		n := 0
		if s.Sessions != nil {
			n = s.Sessions.RevokeAll(updated.Email)
		}
		if _, err := s.Store.RecordAudit(r.Context(), "scim", "user-deprovisioned", updated.Email, fmt.Sprintf("sessions_revoked=%d", n)); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
	} else {
		if _, err := s.Store.RecordAudit(r.Context(), "scim", "user-updated", updated.Email, fmt.Sprintf("role=%s active=%t", updated.Role, updated.Active)); err != nil {
			s.log().Error("recording audit entry", "err", err)
		}
	}
	s.writeJSON(w, http.StatusOK, toSCIMUser(updated))
}

// handleSCIMDeleteUser is DELETE /scim/v2/Users/{id} -- deliberately
// deactivates rather than erasing the directory record (see
// directory.Deactivate's doc comment): an erased record has nothing
// left to enforce "this email is deprovisioned" with, which would
// silently undo the whole point of #22 the next time this person's IdP
// session lets them through OAuth/LDAP/SAML again.
func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireSCIMToken(w, r) {
		return
	}
	email, err := scimEmailFromID(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if _, err := directory.Deactivate(r.Context(), s.Store, email); err != nil {
		s.writeError(w, http.StatusInternalServerError, "deactivating user")
		return
	}
	n := 0
	if s.Sessions != nil {
		n = s.Sessions.RevokeAll(email)
	}
	if _, err := s.Store.RecordAudit(r.Context(), "scim", "user-deprovisioned", email, fmt.Sprintf("sessions_revoked=%d", n)); err != nil {
		s.log().Error("recording audit entry", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// License and seat usage dashboard (#32) -- an admin view of active
// seats vs licensed seats, a historical usage trend, and an
// approaching-limit warning, all built on the existing user directory
// (#22) rather than a separate seat concept. See internal/license's
// doc comment for why "seat" == "active directory user" here.
// ---------------------------------------------------------------------

// licenseUsageResponse is the GET /api/license/usage payload: today's
// numbers up front, the trend underneath, and a non-empty Alert when
// usage is at or above license.NearLimitThresholdPct of LicensedSeats.
type licenseUsageResponse struct {
	ActiveUsers   int                `json:"active_users"`
	LicensedSeats int                `json:"licensed_seats"`
	UsagePct      float64            `json:"usage_pct"`
	Alert         string             `json:"alert,omitempty"`
	History       []license.Snapshot `json:"history"`
}

// handleLicenseUsage is GET /api/license/usage, admin-only. It records
// today's snapshot on every call (RecordSnapshot overwrites same-day
// entries, so repeated dashboard loads don't pile up duplicate history
// -- see its doc comment) rather than relying on a background job, so
// the trend is always current as of the last time an admin looked at
// it. When usage first crosses the near-limit threshold, it's recorded
// to the audit trail (and, via the existing SIEM export wiring, to
// whatever backend is configured) exactly once per day, not once per
// request that happens to load the dashboard while over the line.
func (s *Server) handleLicenseUsage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireRoleStrict(w, r, "admin")
	if !ok {
		return
	}
	snap, err := license.RecordSnapshot(r.Context(), s.Store, s.LicensedSeats)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "recording usage snapshot")
		return
	}
	if msg := license.AlertMessage(snap.ActiveUsers, snap.LicensedSeats, license.NearLimitThresholdPct); msg != "" {
		if !s.licenseAlertedToday(r.Context(), snap.Date) {
			if _, err := s.Store.RecordAudit(r.Context(), actor, "seat-limit-warning", "license", msg); err != nil {
				s.log().Error("recording audit entry", "err", err)
			}
		}
	}
	hist, err := license.History(r.Context(), s.Store, 90)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "loading usage history")
		return
	}
	s.writeJSON(w, http.StatusOK, licenseUsageResponse{
		ActiveUsers:   snap.ActiveUsers,
		LicensedSeats: snap.LicensedSeats,
		UsagePct:      snap.UsagePct(),
		Alert:         license.AlertMessage(snap.ActiveUsers, snap.LicensedSeats, license.NearLimitThresholdPct),
		History:       hist,
	})
}

// licenseAlertedToday checks the audit trail for a "seat-limit-warning"
// entry already recorded today, so handleLicenseUsage doesn't write a
// fresh audit (and SIEM-forwarded) entry on every single dashboard
// refresh while usage stays over the threshold -- once a day is enough
// to have already made the point. Best-effort: a lookup failure just
// means this call records its own entry rather than blocking the
// response, since the audit trail itself is append-only and a
// once-in-a-while duplicate is far cheaper than silently going quiet.
func (s *Server) licenseAlertedToday(ctx context.Context, today string) bool {
	entries, err := s.Store.ListAudit(ctx, "license", 20)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Action == "seat-limit-warning" && e.CreatedAt.Format("2006-01-02") == today {
			return true
		}
	}
	return false
}
