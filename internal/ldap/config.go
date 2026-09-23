/*******************************************************************************
 * @file         config.go
 * @brief        Config validation, group-to-role mapping, and the
 *               service-bind/search/user-bind Authenticate flow -- the
 *               same shape as internal/oauth.Config, for AD/LDAP.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-23
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Config is a validated AD/LDAP login configuration, the LDAP counterpart
// to oauth.Config. Like OAuth, it's all-or-nothing: NewConfig either
// returns a fully usable Config or an error, never a partially-filled one.
type Config struct {
	Host         string
	Port         int
	UseTLS       bool
	BindDN       string // service account used to search for the user's DN
	BindPassword string
	UserBaseDN   string // subtree to search for user entries, e.g. "ou=People,dc=example,dc=com"
	UserAttr     string // attribute holding the login username, e.g. "sAMAccountName" (AD) or "uid" (generic LDAP)
	MailAttr     string // attribute holding the user's email, defaults to "mail"
	GroupAttr    string // attribute holding group DNs the user belongs to, defaults to "memberOf" (AD-style; see doc comment)

	roleMap []roleMapping
	// RoleMapRaw is the original, unparsed role-map string, kept for
	// display in GET /api/settings (same pattern as
	// oauth.Config.RoleMapStrings, just not re-derived from the parsed
	// form since group DNs/CNs round-trip fine as plain strings).
	RoleMapRaw string

	// DialTimeout bounds each LDAP connection attempt. Defaults to 5s
	// if zero.
	DialTimeout time.Duration
}

type roleMapping struct {
	pattern string // a group CN/DN, or "*" for "anyone who authenticated"
	role    string
}

// NewConfig validates and returns a Config, or (nil, nil) if every
// argument is empty (LDAP login is entirely opt-in). Once any argument is
// non-empty, host, userBaseDN, userAttr, and roleMap are all required --
// same all-or-nothing shape as oauth.NewConfig, for the same reason: a
// half-configured login method is worse than a clearly-disabled one.
func NewConfig(host string, port int, useTLS bool, bindDN, bindPassword, userBaseDN, userAttr, mailAttr, groupAttr, roleMap string) (*Config, error) {
	if host == "" && bindDN == "" && bindPassword == "" && userBaseDN == "" && userAttr == "" && roleMap == "" {
		return nil, nil
	}
	if host == "" {
		return nil, fmt.Errorf("ldap: -ldap-host is required once any -ldap-* flag is set")
	}
	if userBaseDN == "" {
		return nil, fmt.Errorf("ldap: -ldap-user-base-dn is required")
	}
	if userAttr == "" {
		userAttr = "sAMAccountName"
	}
	if mailAttr == "" {
		mailAttr = "mail"
	}
	if groupAttr == "" {
		groupAttr = "memberOf"
	}
	if roleMap == "" {
		return nil, fmt.Errorf("ldap: -ldap-role-map is required (semicolon-separated, e.g. \"CN=TopoTrace Admins,OU=Groups,DC=example,DC=com=admin;*=readonly\")")
	}
	parsed, err := parseRoleMap(roleMap)
	if err != nil {
		return nil, err
	}
	if port == 0 {
		if useTLS {
			port = 636
		} else {
			port = 389
		}
	}
	return &Config{
		Host: host, Port: port, UseTLS: useTLS,
		BindDN: bindDN, BindPassword: bindPassword,
		UserBaseDN: userBaseDN, UserAttr: userAttr, MailAttr: mailAttr, GroupAttr: groupAttr,
		roleMap: parsed, RoleMapRaw: roleMap,
		DialTimeout: 5 * time.Second,
	}, nil
}

// parseRoleMap splits on ";" between entries, not "," -- unlike
// oauth's and saml's role maps (whose patterns are emails/domains, which
// never contain a comma), an LDAP role map's patterns are group DNs,
// which do: "CN=Admins,OU=Groups,DC=example,DC=com" has three commas of
// its own. Splitting on "," would tear a single DN-based entry into
// several malformed ones, so ";" is used as the entry separator here
// instead -- see -ldap-role-map's flag description.
func parseRoleMap(s string) ([]roleMapping, error) {
	var out []roleMapping
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.LastIndex(part, "=")
		if idx <= 0 || idx == len(part)-1 {
			return nil, fmt.Errorf("ldap: malformed -ldap-role-map entry %q (want group-or-*=role)", part)
		}
		out = append(out, roleMapping{pattern: strings.TrimSpace(part[:idx]), role: strings.TrimSpace(part[idx+1:])})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ldap: -ldap-role-map has no entries")
	}
	return out, nil
}

// RoleMapStrings returns the parsed role map as "pattern=role" strings,
// for GET /api/settings -- same purpose as oauth.Config.RoleMapStrings.
func (c *Config) RoleMapStrings() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.roleMap))
	for _, m := range c.roleMap {
		out = append(out, m.pattern+"="+m.role)
	}
	return out
}

// roleForGroups checks each of the user's group values (DNs or CNs,
// whatever GroupAttr's values look like on this directory) against the
// role map in order, first match wins; "*" matches unconditionally.
// Returns "" if nothing matched -- same "no matching entry means denied"
// behavior as oauth.Config.RoleFor.
func (c *Config) roleForGroups(groups []string) string {
	for _, m := range c.roleMap {
		if m.pattern == "*" {
			return m.role
		}
		for _, g := range groups {
			if strings.EqualFold(g, m.pattern) {
				return m.role
			}
			// Also match on a bare CN=... prefix comparison so an
			// operator can write a short CN instead of the full DN a
			// directory actually returns in memberOf.
			if cn, ok := cnOf(g); ok && strings.EqualFold(cn, cnValue(m.pattern)) {
				return m.role
			}
		}
	}
	return ""
}

func cnOf(dn string) (string, bool) {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:], true
		}
	}
	return "", false
}

func cnValue(patternOrDN string) string {
	if cn, ok := cnOf(patternOrDN); ok {
		return cn
	}
	return patternOrDN
}

// Authenticate runs the standard LDAP login pattern: bind as the service
// account (BindDN/BindPassword, or anonymously if both are empty --
// unusual but some directories allow anonymous search), search
// UserBaseDN for a single entry whose UserAttr equals username, then bind
// as that entry's DN with password to verify the credential, and finally
// map its GroupAttr values to a role. Returns the user's email (from
// MailAttr, falling back to username@<nothing found> only if MailAttr is
// entirely absent -- callers should treat an empty email as "directory
// entry has no mail attribute set" and decide how to handle that) and
// role, or an error for any failure -- directory unreachable, user not
// found, bad password, or no matching role -- without distinguishing
// which to the caller beyond the error text, deliberately: a login
// endpoint should never reveal *why* a login failed (that's a user-
// enumeration oracle) beyond "invalid credentials."
func (c *Config) Authenticate(ctx context.Context, username, password string) (email, role string, err error) {
	if username == "" || password == "" {
		return "", "", fmt.Errorf("ldap: username and password are required")
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.DialTimeout)
	defer cancel()
	cn, err := dial(dialCtx, c.Host, c.Port, c.UseTLS, c.DialTimeout)
	if err != nil {
		return "", "", err
	}
	defer func() { cn.unbind(); cn.close() }()

	if c.BindDN != "" {
		if err := cn.simpleBind(c.BindDN, c.BindPassword); err != nil {
			return "", "", fmt.Errorf("ldap: service-account bind: %w", err)
		}
	}

	entries, err := cn.searchOneEquality(c.UserBaseDN, c.UserAttr, EscapeFilterValue(username), []string{c.MailAttr, c.GroupAttr})
	if err != nil {
		return "", "", fmt.Errorf("ldap: searching for user: %w", err)
	}
	if len(entries) == 0 {
		return "", "", errNotFound
	}
	if len(entries) > 1 {
		return "", "", fmt.Errorf("ldap: %d entries matched %s=%s, expected exactly one", len(entries), c.UserAttr, username)
	}
	user := entries[0]

	// Re-bind as the user's own DN with the supplied password -- this is
	// the actual credential check. A fresh connection is used so a
	// failed user bind can never be confused with an already-successful
	// service-account bind's session state.
	userConn, err := dial(ctx, c.Host, c.Port, c.UseTLS, c.DialTimeout)
	if err != nil {
		return "", "", err
	}
	defer func() { userConn.unbind(); userConn.close() }()
	if err := userConn.simpleBind(user.DN, password); err != nil {
		return "", "", fmt.Errorf("ldap: invalid credentials")
	}

	role = c.roleForGroups(user.Attrs[c.GroupAttr])
	if role == "" {
		return "", "", fmt.Errorf("ldap: %s is not authorized -- no matching -ldap-role-map entry for their group membership", username)
	}
	if vals := user.Attrs[c.MailAttr]; len(vals) > 0 {
		email = vals[0]
	} else {
		email = username
	}
	return email, role, nil
}
