/*******************************************************************************
 * @file         saml_test.go
 * @brief        Tests for internal/saml -- config validation, role mapping,
 *               AuthnRequest generation, and a full signed-response
 *               round-trip against a self-signed test certificate (no live
 *               IdP involved).
 * @project      TopoTrace
 *
 * @author       Michael McGinnis
 * @date         2026-09-23
 * @version      1.0.0
 *
 * Copyright (c) 2026 TopoTrace LLC. All rights reserved.
 * Licensed under the Apache License, Version 2.0 -- see the LICENSE file at the repository root.
 ******************************************************************************/

package saml

import (
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewConfigAllOrNothing(t *testing.T) {
	if cfg, err := NewConfig("", "", "", "", ""); cfg != nil || err != nil {
		t.Errorf("all-empty: got (%v, %v), want (nil, nil)", cfg, err)
	}
	if _, err := NewConfig("https://sp.example.com", "", "", "", ""); err == nil {
		t.Error("partial config: expected error")
	}
}

func TestRoleFor(t *testing.T) {
	pem, _ := testCert(t)
	cfg, err := NewConfig("https://sp.example.com/metadata", "https://sp.example.com/acs", "https://idp.example.com/sso", pem,
		"admin@example.com=admin,*@example.com=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	cases := map[string]string{
		"admin@example.com": "admin",
		"bob@example.com":   "readonly",
		"eve@other.com":     "",
	}
	for email, want := range cases {
		if got := cfg.RoleFor(email); got != want {
			t.Errorf("RoleFor(%q) = %q, want %q", email, got, want)
		}
	}
}

func TestAuthnRequestURL(t *testing.T) {
	pem, _ := testCert(t)
	cfg, err := NewConfig("https://sp.example.com/metadata", "https://sp.example.com/acs", "https://idp.example.com/sso", pem, "*=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	redirectURL, err := cfg.AuthnRequestURL("relay-123")
	if err != nil {
		t.Fatalf("AuthnRequestURL: %v", err)
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parsing redirect URL: %v", err)
	}
	if u.Query().Get("RelayState") != "relay-123" {
		t.Errorf("RelayState = %q, want relay-123", u.Query().Get("RelayState"))
	}
	reqB64 := u.Query().Get("SAMLRequest")
	if reqB64 == "" {
		t.Fatal("missing SAMLRequest")
	}
	deflated, err := base64.StdEncoding.DecodeString(reqB64)
	if err != nil {
		t.Fatalf("base64 decoding SAMLRequest: %v", err)
	}
	fr := flate.NewReader(strings.NewReader(string(deflated)))
	xmlBytes, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("inflating SAMLRequest: %v", err)
	}
	if !strings.Contains(string(xmlBytes), `Destination="https://idp.example.com/sso"`) {
		t.Errorf("AuthnRequest missing expected Destination: %s", xmlBytes)
	}
}

// testCert generates a throwaway self-signed RSA certificate for signing
// test assertions, returning its PEM encoding and the private key.
func testCert(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(certPEM), key
}

// buildSignedResponse assembles a minimal, validly-signed SAML Response
// around the given NameID, computing the digest and RSA-SHA256 signature
// itself -- exercising exactly the same enveloped-signature shape
// ParseResponse expects, without needing a live IdP.
func buildSignedResponse(t *testing.T, key *rsa.PrivateKey, nameID string, notBefore, notOnOrAfter time.Time) string {
	t.Helper()
	assertionID := "_test-assertion-1"
	open := fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">`,
		assertionID, time.Now().UTC().Format(time.RFC3339))
	inner := fmt.Sprintf(
		`<saml2:Subject><saml2:NameID>%s</saml2:NameID></saml2:Subject><saml2:Conditions NotBefore="%s" NotOnOrAfter="%s"></saml2:Conditions>`,
		nameID, notBefore.UTC().Format(time.RFC3339), notOnOrAfter.UTC().Format(time.RFC3339))
	closeTag := `</saml2:Assertion>`

	digestInput := open + inner + closeTag
	digest := sha256.Sum256([]byte(digestInput))
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	signedInfo := fmt.Sprintf(
		`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
			`<ds:CanonicalizationMethod Algorithm="%s"/>`+
			`<ds:SignatureMethod Algorithm="%s"/>`+
			`<ds:Reference URI="#%s"><ds:DigestMethod Algorithm="%s"/><ds:DigestValue>%s</ds:DigestValue></ds:Reference>`+
			`</ds:SignedInfo>`,
		algExcC14N, algRSASHA256, assertionID, algSHA256Digest, digestB64,
	)
	signedInfoDigest := sha256.Sum256([]byte(signedInfo))
	sigValue, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, signedInfoDigest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	signature := fmt.Sprintf(
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%s<ds:SignatureValue>%s</ds:SignatureValue></ds:Signature>`,
		signedInfo, base64.StdEncoding.EncodeToString(sigValue),
	)

	assertion := open + signature + inner + closeTag
	response := fmt.Sprintf(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response>`,
		statusSuccess, assertion,
	)
	return base64.StdEncoding.EncodeToString([]byte(response))
}

func TestParseResponseValidSignature(t *testing.T) {
	certPEM, key := testCert(t)
	cfg, err := NewConfig("https://sp.example.com/metadata", "https://sp.example.com/acs", "https://idp.example.com/sso", certPEM, "alice@example.com=admin")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	resp := buildSignedResponse(t, key, "alice@example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	result, err := cfg.ParseResponse(resp)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if result.Email != "alice@example.com" || result.Role != "admin" {
		t.Errorf("got %+v", result)
	}
}

func TestParseResponseRejectsTamperedAssertion(t *testing.T) {
	certPEM, key := testCert(t)
	cfg, err := NewConfig("https://sp.example.com/metadata", "https://sp.example.com/acs", "https://idp.example.com/sso", certPEM, "*=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	resp := buildSignedResponse(t, key, "alice@example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	raw, _ := base64.StdEncoding.DecodeString(resp)
	// Flip the NameID after signing -- a forged privilege-escalation
	// attempt (e.g. impersonating an admin) must be rejected.
	tampered := strings.Replace(string(raw), "alice@example.com</saml2:NameID>", "mallory@example.com</saml2:NameID>", 1)
	if _, err := cfg.ParseResponse(base64.StdEncoding.EncodeToString([]byte(tampered))); err == nil {
		t.Error("expected signature verification to fail on tampered assertion, got nil error")
	}
}

func TestParseResponseRejectsExpiredAssertion(t *testing.T) {
	certPEM, key := testCert(t)
	cfg, err := NewConfig("https://sp.example.com/metadata", "https://sp.example.com/acs", "https://idp.example.com/sso", certPEM, "*=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	resp := buildSignedResponse(t, key, "alice@example.com", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if _, err := cfg.ParseResponse(resp); err == nil {
		t.Error("expected expired assertion to be rejected, got nil error")
	}
}

func TestParseResponseRejectsWrongSigningKey(t *testing.T) {
	certPEM, _ := testCert(t)
	_, otherKey := testCert(t) // a different keypair than the one in certPEM
	cfg, err := NewConfig("https://sp.example.com/metadata", "https://sp.example.com/acs", "https://idp.example.com/sso", certPEM, "*=readonly")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	resp := buildSignedResponse(t, otherKey, "alice@example.com", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if _, err := cfg.ParseResponse(resp); err == nil {
		t.Error("expected signature from an untrusted key to be rejected, got nil error")
	}
}
