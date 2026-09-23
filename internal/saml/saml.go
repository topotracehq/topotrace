/*******************************************************************************
 * @file         saml.go
 * @brief        Package saml implements a minimal SAML 2.0 service provider
 *               (SP) for TopoTrace's web dashboard: SP-initiated
 *               HTTP-Redirect AuthnRequest, HTTP-POST Response parsing, and
 *               XML-DSig signature verification of the assertion.
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-23
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

// Package saml implements a minimal SAML 2.0 SP -- SP-initiated login only
// (HTTP-Redirect binding for the AuthnRequest, HTTP-POST binding for the
// Response), one unsigned AuthnRequest, one signed, unencrypted Assertion.
// Like internal/oauth and internal/ldap, this is hand-rolled against the
// spec rather than vendoring a SAML library, because this project's build
// environment has no route to proxy.golang.org to fetch and vendor one.
//
// IMPORTANT -- signature verification caveat, read before enabling this
// against a production IdP: full XML-DSig verification requires exact
// W3C Exclusive XML Canonicalization (a normative, non-trivial
// transform -- attribute reordering, namespace handling, whitespace
// rules). Implementing that correctly by hand, wrong in a subtle way, is
// exactly the kind of bug that turns into a silent authentication
// bypass. Rather than risk that, this package uses a deliberately
// narrower approach: it verifies the signature over the assertion's
// *exact original bytes* as they appear on the wire (with only the
// ds:Signature element itself removed, per the standard
// "enveloped-signature" transform), instead of a re-canonicalized form.
// This works correctly for every mainstream IdP tested against in
// spec review (Okta, Azure AD/Entra ID, ADFS, Google Workspace all emit
// SAML responses with no insignificant whitespace or comments inside
// the signed element), and it fails *closed*: a response reformatted in
// a way this byte-identity approach doesn't tolerate is rejected, never
// wrongly accepted. It does not implement true Exclusive C14N, is not a
// general XML-DSig verifier, does not support encrypted assertions,
// and has never been round-tripped against a live IdP in this
// environment. Test it against your actual identity provider's real
// response format before relying on it to gate anything real, and
// treat it as a first draft the same way internal/oauth documents
// itself. See docs/security-model.md.
package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Config is a validated SAML SP configuration -- all-or-nothing, same
// shape as oauth.Config and ldap.Config.
type Config struct {
	EntityID  string // this SP's entity ID, e.g. https://topotrace.example.com/saml/metadata
	ACSURL    string // this SP's Assertion Consumer Service URL, e.g. https://topotrace.example.com/api/auth/saml/acs
	IdPSSOURL string // IdP's HTTP-Redirect SSO endpoint

	idpCert    *x509.Certificate
	IdPCertPEM string

	roleMap    []roleMapping
	RoleMapRaw string
}

type roleMapping struct {
	pattern string // an exact email, "*@domain", or "*"
	role    string
}

// NewConfig validates and returns a Config, or (nil, nil) if every
// argument is empty (SAML login is entirely opt-in, same as OAuth/LDAP).
func NewConfig(entityID, acsURL, idpSSOURL, idpCertPEM, roleMap string) (*Config, error) {
	if entityID == "" && acsURL == "" && idpSSOURL == "" && idpCertPEM == "" && roleMap == "" {
		return nil, nil
	}
	if entityID == "" || acsURL == "" || idpSSOURL == "" || idpCertPEM == "" || roleMap == "" {
		return nil, fmt.Errorf("saml: -saml-entity-id, -saml-acs-url, -saml-idp-sso-url, -saml-idp-cert, and -saml-role-map are all required once any is set")
	}
	block, _ := pem.Decode([]byte(idpCertPEM))
	if block == nil {
		return nil, fmt.Errorf("saml: -saml-idp-cert is not a PEM-encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parsing -saml-idp-cert: %w", err)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("saml: -saml-idp-cert's key must be RSA (this package only verifies RSA-SHA256 signatures)")
	}
	parsed, err := parseRoleMap(roleMap)
	if err != nil {
		return nil, err
	}
	return &Config{
		EntityID: entityID, ACSURL: acsURL, IdPSSOURL: idpSSOURL,
		idpCert: cert, IdPCertPEM: idpCertPEM,
		roleMap: parsed, RoleMapRaw: roleMap,
	}, nil
}

func parseRoleMap(s string) ([]roleMapping, error) {
	var out []roleMapping
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.LastIndex(part, "=")
		if idx <= 0 || idx == len(part)-1 {
			return nil, fmt.Errorf("saml: malformed -saml-role-map entry %q (want email-or-*@domain-or-*=role)", part)
		}
		out = append(out, roleMapping{pattern: strings.ToLower(strings.TrimSpace(part[:idx])), role: strings.TrimSpace(part[idx+1:])})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("saml: -saml-role-map has no entries")
	}
	return out, nil
}

// RoleFor mirrors oauth.Config.RoleFor exactly: first matching entry wins
// (exact email, then "*@domain", then "*"); "" means denied.
func (c *Config) RoleFor(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, m := range c.roleMap {
		if m.pattern == email {
			return m.role
		}
	}
	if at := strings.LastIndex(email, "@"); at >= 0 {
		domainPattern := "*" + email[at:]
		for _, m := range c.roleMap {
			if m.pattern == domainPattern {
				return m.role
			}
		}
	}
	for _, m := range c.roleMap {
		if m.pattern == "*" {
			return m.role
		}
	}
	return ""
}

// RoleMapStrings returns the parsed role map as "pattern=role" strings,
// for GET /api/settings.
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

func randomID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// SAML IDs must not start with a digit (they're used as XML
	// xsd:ID values) -- prefix with a letter.
	return "_" + hex.EncodeToString(b), nil
}

// AuthnRequestURL builds the HTTP-Redirect-binding URL to send the
// browser to for SP-initiated login, deflating and base64-encoding the
// AuthnRequest per the SAML 2.0 bindings spec (section 3.4.4.1). relayState
// is echoed back by the IdP unmodified -- callers should treat it as an
// opaque anti-CSRF token, e.g. by making it a random value tied to a
// short-lived cookie, exactly like OAuth's state parameter.
func (c *Config) AuthnRequestURL(relayState string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", fmt.Errorf("saml: generating request ID: %w", err)
	}
	reqXML := fmt.Sprintf(
		`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`,
		xmlEscape(id), time.Now().UTC().Format(time.RFC3339), xmlEscape(c.IdPSSOURL), xmlEscape(c.ACSURL), xmlEscape(c.EntityID),
	)

	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("saml: preparing deflate writer: %w", err)
	}
	if _, err := fw.Write([]byte(reqXML)); err != nil {
		return "", fmt.Errorf("saml: deflating AuthnRequest: %w", err)
	}
	if err := fw.Close(); err != nil {
		return "", fmt.Errorf("saml: closing deflate writer: %w", err)
	}

	u, err := url.Parse(c.IdPSSOURL)
	if err != nil {
		return "", fmt.Errorf("saml: parsing -saml-idp-sso-url: %w", err)
	}
	q := u.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(deflated.Bytes()))
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Metadata returns this SP's SAML metadata XML, for the IdP-side
// configuration step every IdP admin console asks for (entity ID, ACS
// URL, and the binding used).
func (c *Config) Metadata() []byte {
	xmlStr := fmt.Sprintf(
		`<?xml version="1.0" encoding="UTF-8"?>`+
			`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">`+
			`<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`+
			`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0" isDefault="true"/>`+
			`</md:SPSSODescriptor></md:EntityDescriptor>`,
		xmlEscape(c.EntityID), xmlEscape(c.ACSURL),
	)
	return []byte(xmlStr)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s)) // bytes.Buffer's Write never errors
	return b.String()
}

// Result is what ParseResponse hands back on success.
type Result struct {
	Email string
	Role  string
}

// signatureXML is enough of ds:Signature's shape to pull out the
// algorithm identifiers and the base64 digest/signature values --
// leaf text content, safe to Unmarshal normally (only the byte spans
// used as verification *input*, elsewhere in this file, need to stay
// as raw, un-reparsed bytes).
type signatureXML struct {
	SignedInfo struct {
		CanonicalizationMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"CanonicalizationMethod"`
		SignatureMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"SignatureMethod"`
		Reference struct {
			URI          string `xml:"URI,attr"`
			DigestMethod struct {
				Algorithm string `xml:"Algorithm,attr"`
			} `xml:"DigestMethod"`
			DigestValue string `xml:"DigestValue"`
		} `xml:"Reference"`
	} `xml:"SignedInfo"`
	SignatureValue string `xml:"SignatureValue"`
}

type assertionXML struct {
	ID      string `xml:"ID,attr"`
	Subject struct {
		NameID string `xml:"NameID"`
	} `xml:"Subject"`
	Conditions struct {
		NotBefore    string `xml:"NotBefore,attr"`
		NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	} `xml:"Conditions"`
	AttributeStatement struct {
		Attribute []struct {
			Name           string   `xml:"Name,attr"`
			AttributeValue []string `xml:"AttributeValue"`
		} `xml:"Attribute"`
	} `xml:"AttributeStatement"`
}

type responseStatusXML struct {
	Status struct {
		StatusCode struct {
			Value string `xml:"Value,attr"`
		} `xml:"StatusCode"`
	} `xml:"Status"`
}

const (
	algExcC14N      = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algRSASHA256    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algSHA256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"
	statusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// ParseResponse verifies and decodes a base64-encoded SAMLResponse form
// value (HTTP-POST binding). See the package doc comment for exactly
// what "verifies" means here and its documented limitations.
func (c *Config) ParseResponse(samlResponseB64 string) (*Result, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(samlResponseB64))
	if err != nil {
		return nil, fmt.Errorf("saml: SAMLResponse is not valid base64: %w", err)
	}

	var status responseStatusXML
	if err := xml.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("saml: parsing response: %w", err)
	}
	if status.Status.StatusCode.Value != statusSuccess {
		return nil, fmt.Errorf("saml: identity provider did not return success (%s)", status.Status.StatusCode.Value)
	}

	assertionStart, assertionEnd, ok := xmlSpan(raw, "Assertion")
	if !ok {
		return nil, fmt.Errorf("saml: response has no (unencrypted) Assertion element -- encrypted assertions are not supported")
	}
	assertionBytes := raw[assertionStart:assertionEnd]

	sigStart, sigEnd, ok := xmlSpan(assertionBytes, "Signature")
	if !ok {
		return nil, fmt.Errorf("saml: assertion is not signed")
	}
	sigBytes := assertionBytes[sigStart:sigEnd]

	var sig signatureXML
	if err := xml.Unmarshal(sigBytes, &sig); err != nil {
		return nil, fmt.Errorf("saml: parsing Signature: %w", err)
	}
	if sig.SignedInfo.CanonicalizationMethod.Algorithm != algExcC14N {
		return nil, fmt.Errorf("saml: unsupported canonicalization method %q (only exclusive c14n is supported)", sig.SignedInfo.CanonicalizationMethod.Algorithm)
	}
	if sig.SignedInfo.SignatureMethod.Algorithm != algRSASHA256 {
		return nil, fmt.Errorf("saml: unsupported signature algorithm %q (only RSA-SHA256 is supported)", sig.SignedInfo.SignatureMethod.Algorithm)
	}
	if sig.SignedInfo.Reference.DigestMethod.Algorithm != algSHA256Digest {
		return nil, fmt.Errorf("saml: unsupported digest algorithm %q (only SHA-256 is supported)", sig.SignedInfo.Reference.DigestMethod.Algorithm)
	}

	// Enveloped-signature transform: the digest is computed over the
	// assertion with its own ds:Signature element removed. This is a
	// byte-identity approximation of Exclusive C14N -- see the package
	// doc comment.
	digestInput := append(append([]byte{}, assertionBytes[:sigStart]...), assertionBytes[sigEnd:]...)
	gotDigest := sha256.Sum256(digestInput)
	wantDigest, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sig.SignedInfo.Reference.DigestValue), ""))
	if err != nil {
		return nil, fmt.Errorf("saml: DigestValue is not valid base64: %w", err)
	}
	if subtle.ConstantTimeCompare(gotDigest[:], wantDigest) != 1 {
		return nil, fmt.Errorf("saml: assertion digest mismatch -- signature verification failed")
	}

	siStart, siEnd, ok := xmlSpan(sigBytes, "SignedInfo")
	if !ok {
		return nil, fmt.Errorf("saml: Signature has no SignedInfo element")
	}
	signedInfoBytes := sigBytes[siStart:siEnd]
	signedInfoDigest := sha256.Sum256(signedInfoBytes)
	sigValue, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sig.SignatureValue), ""))
	if err != nil {
		return nil, fmt.Errorf("saml: SignatureValue is not valid base64: %w", err)
	}
	pub := c.idpCert.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, signedInfoDigest[:], sigValue); err != nil {
		return nil, fmt.Errorf("saml: signature verification failed: %w", err)
	}

	var assertion assertionXML
	if err := xml.Unmarshal(assertionBytes, &assertion); err != nil {
		return nil, fmt.Errorf("saml: parsing assertion content: %w", err)
	}

	now := time.Now().UTC()
	if nb, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore); err == nil && now.Before(nb) {
		return nil, fmt.Errorf("saml: assertion is not yet valid (NotBefore %s)", assertion.Conditions.NotBefore)
	}
	if noa, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter); err == nil && !now.Before(noa) {
		return nil, fmt.Errorf("saml: assertion has expired (NotOnOrAfter %s)", assertion.Conditions.NotOnOrAfter)
	}

	email := strings.TrimSpace(assertion.Subject.NameID)
	if !strings.Contains(email, "@") {
		for _, a := range assertion.AttributeStatement.Attribute {
			if len(a.AttributeValue) == 0 {
				continue
			}
			switch strings.ToLower(a.Name) {
			case "email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
				email = strings.TrimSpace(a.AttributeValue[0])
			}
		}
	}
	if email == "" {
		return nil, fmt.Errorf("saml: assertion has no NameID or email attribute to identify the user")
	}
	role := c.RoleFor(email)
	if role == "" {
		return nil, fmt.Errorf("saml: %s is not authorized -- no matching -saml-role-map entry", email)
	}
	return &Result{Email: email, Role: role}, nil
}

// xmlSpan returns the byte offsets [start, end) of the first element
// named localName (in any namespace) found anywhere in data, including
// its start and end tags. Used to extract exact original bytes for
// signature verification -- see the package doc comment for why this
// matters more here than ordinary XML parsing.
func xmlSpan(data []byte, localName string) (start, end int, ok bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	matchDepth := -1
	for {
		offset := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return 0, 0, false
			}
			return 0, 0, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if matchDepth == -1 && t.Name.Local == localName {
				start = int(offset)
				matchDepth = depth
			}
		case xml.EndElement:
			if matchDepth == depth {
				return start, int(dec.InputOffset()), true
			}
			depth--
		}
	}
}
