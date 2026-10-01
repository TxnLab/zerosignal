/*
 * Copyright (c) 2026. TxnLab Inc.
 * All Rights reserved.
 */

package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
)

// Everything here runs against the REAL captured Phala quote where a
// quote is needed. A synthetic one agrees with the walk by construction
// — it would be built by the same offsets the walk reads — so it can
// only ever confirm that the code is self-consistent.

func TestPCKPlatformID_ReadsTheCapturedPlatform(t *testing.T) {
	_, quote := loadVectors(t)

	fmspc, ca, err := PCKPlatformID(quote)
	if err != nil {
		t.Fatalf("PCKPlatformID: %v", err)
	}

	// Six bytes, upper-case hex. Anything else means the ASN.1 walk read
	// some other extension's value and produced a plausible-looking
	// query parameter for a platform that is not this one.
	if len(fmspc) != 12 {
		t.Errorf("fmspc = %q (%d chars), want 12 hex characters", fmspc, len(fmspc))
	}
	if _, derr := hex.DecodeString(fmspc); derr != nil {
		t.Errorf("fmspc %q is not hex: %v", fmspc, derr)
	}
	if fmspc != strings.ToUpper(fmspc) {
		t.Errorf("fmspc = %q, want upper-case", fmspc)
	}

	// THE CONCRETE FMSPC, for the same reason the CA type below is pinned
	// concretely: this value SELECTS which TCB info describes this
	// platform, so a walk that landed on some other six-byte extension
	// value produces a well-formed identifier for the wrong hardware and
	// every shape check above still passes. Nothing else in the workspace
	// pinned it — proxy and node both assert only "12 upper-case hex".
	if fmspc != "20A06F000000" {
		t.Errorf("fmspc = %q, want 20A06F000000 — the FMSPC of the captured Phala platform",
			fmspc)
	}

	// THE CONCRETE VALUE, not membership in the two-element set.
	// Membership passes for the answer that fetches a CRL which does not
	// cover this platform's own PCK certificate — a complete,
	// well-formed collateral set that fails at every verifier, and one
	// no structural check can catch because both CRLs parse as DER
	// either way.
	if ca != "platform" {
		t.Errorf("ca = %q, want platform: the capture's PCK issuer is an Intel SGX PCK Platform CA", ca)
	}
}

// THE NUMBER, pinned to a literal. Every Go reference derives from the
// constant — deliberately, so there is one place to change — which means
// widening it to 21 days leaves proto, proxy and node all green while the
// browser twin holds at 14. The godoc claims to mirror
// EMBEDDED_COLLATERAL_MAX_AGE_MS, and the TS side pins its own value the
// same way; this is the half that was missing.
//
// The direction that matters: widening is what lets an operator choose an
// older vintage, so a silent Go-side widening is exactly the drift this
// bound exists to prevent.
func TestEmbeddedCollateralMaxAgeIsFourteenDays(t *testing.T) {
	if EmbeddedCollateralMaxAge != 14*24*time.Hour {
		t.Fatalf("EmbeddedCollateralMaxAge = %v, want 14 days — the client's "+
			"EMBEDDED_COLLATERAL_MAX_AGE_MS pins the same number and the two are "+
			"hand-mirrored, not golden-vectored", EmbeddedCollateralMaxAge)
	}
}

func TestPCKPlatformID_RefusesTruncatedQuotes(t *testing.T) {
	_, full := loadVectors(t)
	// The length fields this walk reads are guest-agent-supplied, so
	// every prefix must refuse rather than panic or return a half-read
	// identifier.
	for _, n := range []int{0, 1, 47, 48, 632, 1000, len(full) - 100} {
		if n < 0 || n > len(full) {
			continue
		}
		if _, _, err := PCKPlatformID(full[:n]); err == nil {
			t.Errorf("PCKPlatformID accepted a %d-byte prefix", n)
		}
	}
}

// testCRLDER mints a real DER CRL stamped with `thisUpdate`.
//
// A REAL ONE, not a hand-rolled byte string, because the code under test
// dates it with x509.ParseRevocationList — the same parser a verifier
// uses. A synthetic blob would have to encode the answer the parser is
// supposed to find, which tests the fixture rather than the code.
func testCRLDER(t *testing.T, thisUpdate time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Intel SGX PCK Platform CA (test)"},
		NotBefore:             thisUpdate.Add(-365 * 24 * time.Hour),
		NotAfter:              thisUpdate.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(30 * 24 * time.Hour),
	}, issuer, key)
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	return crl
}

// completeCollateral builds a usable set. The signed documents have
// DELIBERATELY NON-ALPHABETICAL keys — see
// TestCollateralResponses_KeepsSignedBytesVerbatim.
func completeCollateral(t *testing.T, issued time.Time) *inject.TEECollateral {
	t.Helper()
	return &inject.TEECollateral{
		PCKCRLIssuerChain:     "-----BEGIN CERTIFICATE-----\nAA+BB/CC=\n-----END CERTIFICATE-----\n",
		RootCACRL:             hex.EncodeToString(testCRLDER(t, issued)),
		PCKCRL:                hex.EncodeToString(testCRLDER(t, issued)),
		TCBInfoIssuerChain:    "-----BEGIN CERTIFICATE-----\nDD+EE/FF=\n-----END CERTIFICATE-----\n",
		TCBInfo:               tcbInfoDoc(issued),
		TCBInfoSignature:      "abcd",
		QEIdentityIssuerChain: "-----BEGIN CERTIFICATE-----\nGG+HH/II=\n-----END CERTIFICATE-----\n",
		QEIdentity:            qeIdentityDoc(issued),
		QEIdentitySignature:   "ef01",
	}
}

// Keys out of alphabetical order on purpose: `issueDate` before `id`,
// `tcbLevels` before `nextUpdate`. Intel signs these exact bytes, and
// encoding/json SORTS map keys — so a reassembly that round-tripped the
// document through a map would emit a valid-looking document whose every
// field reads back correctly and whose signature verifies nowhere.
func tcbInfoDoc(issued time.Time) string {
	return `{"version":3,"issueDate":"` + issued.UTC().Format(time.RFC3339) +
		`","id":"TDX","tcbLevels":[],"nextUpdate":"` +
		issued.Add(30*24*time.Hour).UTC().Format(time.RFC3339) +
		`","fmspc":"90C06F000000","pceId":"0000"}`
}

func qeIdentityDoc(issued time.Time) string {
	return `{"version":2,"issueDate":"` + issued.UTC().Format(time.RFC3339) +
		`","id":"TD_QE","tcbLevels":[],"nextUpdate":"` +
		issued.Add(30*24*time.Hour).UTC().Format(time.RFC3339) + `"}`
}

func TestCollateralResponses_KeepsSignedBytesVerbatim(t *testing.T) {
	issued := time.Now().Add(-24 * time.Hour)
	c := completeCollateral(t, issued)

	out, err := CollateralResponses(c)
	if err != nil {
		t.Fatalf("CollateralResponses: %v", err)
	}

	// BYTE COMPARISON AGAINST THE LITERAL, not a field-wise check. A
	// field-wise check passes on an alphabetized re-encoding, which is
	// precisely the failure being guarded — the document would carry
	// every correct value and verify at no verifier on earth.
	wantTCB := `{"tcbInfo":` + c.TCBInfo + `,"signature":"abcd"}`
	if got := string(out[CollateralTCBInfo].Body); got != wantTCB {
		t.Errorf("tcb_info envelope =\n  %s\nwant\n  %s", got, wantTCB)
	}
	wantQE := `{"enclaveIdentity":` + c.QEIdentity + `,"signature":"ef01"}`
	if got := string(out[CollateralQEIdentity].Body); got != wantQE {
		t.Errorf("qe_identity envelope =\n  %s\nwant\n  %s", got, wantQE)
	}

	// And it must still be a document a verifier can read.
	var probe map[string]json.RawMessage
	if uerr := json.Unmarshal(out[CollateralTCBInfo].Body, &probe); uerr != nil {
		t.Fatalf("the reassembled envelope is not JSON: %v", uerr)
	}
	if _, ok := probe["tcbInfo"]; !ok {
		t.Error("the envelope has no tcbInfo member; bodyToRawMessage would refuse it")
	}
}

func TestCollateralResponses_DecodesCRLsToDER(t *testing.T) {
	// A verifier hands the body straight to an X.509 CRL parser, so hex
	// TEXT reaches it as a parse failure indistinguishable from a
	// corrupt revocation list.
	c := completeCollateral(t, time.Now().Add(-time.Hour))
	out, err := CollateralResponses(c)
	if err != nil {
		t.Fatalf("CollateralResponses: %v", err)
	}
	for _, a := range []CollateralArtifact{CollateralPCKCRL, CollateralRootCACRL} {
		body := out[a].Body
		if len(body) == 0 {
			t.Fatalf("%v: empty body", a)
		}
		// DER SEQUENCE. The hex text would start with '3'/'0' as ASCII
		// (0x33/0x30), so this distinguishes them.
		if body[0] != 0x30 {
			t.Errorf("%v: body starts %#x, want a DER SEQUENCE (0x30) — it was not hex-decoded", a, body[0])
		}
	}
}

func TestCollateralResponses_IssuerChainsSurviveTheHeaderRoundTrip(t *testing.T) {
	// The chains are stored DECODED and must be re-encoded to ride a
	// header, because PEM newlines cannot. A consumer that passes the
	// stored value through ships a chain that parses to zero
	// certificates while looking present in its own logs.
	//
	// Asserted as a ROUND TRIP through the decoder a verifier actually
	// uses, not against our own encoder's output — the second is a test
	// of nothing.
	c := completeCollateral(t, time.Now().Add(-time.Hour))
	out, err := CollateralResponses(c)
	if err != nil {
		t.Fatalf("CollateralResponses: %v", err)
	}

	for _, tc := range []struct {
		artifact CollateralArtifact
		want     string
	}{
		{CollateralTCBInfo, c.TCBInfoIssuerChain},
		{CollateralQEIdentity, c.QEIdentityIssuerChain},
		{CollateralPCKCRL, c.PCKCRLIssuerChain},
	} {
		enc := out[tc.artifact].IssuerChain
		if strings.Contains(enc, "\n") {
			t.Errorf("%v: the encoded chain still contains a newline, which cannot ride an HTTP header", tc.artifact)
		}
		back, uerr := url.QueryUnescape(enc)
		if uerr != nil {
			t.Fatalf("%v: QueryUnescape: %v", tc.artifact, uerr)
		}
		if back != tc.want {
			t.Errorf("%v: round trip produced\n  %q\nwant\n  %q", tc.artifact, back, tc.want)
		}
	}

	// The root CA CRL carries no chain: a verifier validates it against
	// the root it already pinned. Emitting one would be inventing a
	// header no PCS sends.
	if out[CollateralRootCACRL].IssuerChain != "" {
		t.Error("root_ca_crl carries an issuer chain; no PCS sends one")
	}
}

// THE DOUBLE-WRAP, which is the failure this file's whole byte-exactness
// argument exists to prevent and which a shape check nearly let through.
//
// SPEC §3e says tcb_info is the signed INNER document, and the node
// produces exactly that. A set that arrives already wrapped must be
// REFUSED rather than wrapped again: {"tcbInfo":{"tcbInfo":{…}}} is valid
// JSON, passes every structural check, and hands go-tdx-guest's
// bodyToRawMessage an inner object Intel never signed — so the failure
// lands as "this node's evidence is bad" for our own encoding mistake.
func TestCollateralResponses_RefusesAnAlreadyWrappedDocument(t *testing.T) {
	issued := time.Now().Add(-time.Hour)
	for name, mutate := range map[string]func(*inject.TEECollateral){
		"tcb info": func(c *inject.TEECollateral) {
			c.TCBInfo = `{"tcbInfo":` + tcbInfoDoc(issued) + `}`
		},
		"qe identity": func(c *inject.TEECollateral) {
			c.QEIdentity = `{"enclaveIdentity":` + qeIdentityDoc(issued) + `}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := completeCollateral(t, issued)
			mutate(c)
			if _, err := CollateralResponses(c); err == nil {
				t.Fatal("a pre-wrapped document was accepted and will be wrapped again")
			}
			// And the freshness gate must agree, or it stays the one check
			// that could have named this and does not.
			if CollateralFreshEnough(c, time.Now(), EmbeddedCollateralMaxAge) {
				t.Error("CollateralFreshEnough accepted a shape CollateralResponses refuses — " +
					"two helpers disagreeing about one field is how a set passes every check")
			}
		})
	}
}

// json.Valid accepts `5`, `null`, `[]` and `"hi"`, each of which builds a
// syntactically perfect envelope carrying no document at all.
func TestCollateralResponses_RefusesADocumentThatIsNotAnObject(t *testing.T) {
	for _, doc := range []string{`5`, `null`, `[]`, `"hi"`, `true`} {
		c := completeCollateral(t, time.Now().Add(-time.Hour))
		c.TCBInfo = doc
		if _, err := CollateralResponses(c); err == nil {
			t.Errorf("TCBInfo = %s was accepted", doc)
		}
	}
}

// The signature is the ONE member of the set nothing else validates: the
// node's splitSigned only tests it for non-emptiness, and both consumers
// hex-decode it. Unchecked, a malformed one reaches the verifier and
// reads as an accusation against the node.
func TestCollateralResponses_RefusesANonHexSignature(t *testing.T) {
	for _, sig := range []string{"zz", "ab ", " ab", "abc", "0x1234"} {
		c := completeCollateral(t, time.Now().Add(-time.Hour))
		c.TCBInfoSignature = sig
		if _, err := CollateralResponses(c); err == nil {
			t.Errorf("TCBInfoSignature = %q was accepted", sig)
		}
	}
}

func TestCollateralResponses_RefusesAPartialSet(t *testing.T) {
	// A partial set is an absent set. Accepting eight of nine fields
	// means one check silently does not run, which is the hole a node
	// with something to hide would engineer.
	full := completeCollateral(t, time.Now().Add(-time.Hour))
	blanks := map[string]func(*inject.TEECollateral){
		"pck_crl_issuer_chain":     func(c *inject.TEECollateral) { c.PCKCRLIssuerChain = "" },
		"root_ca_crl":              func(c *inject.TEECollateral) { c.RootCACRL = "" },
		"pck_crl":                  func(c *inject.TEECollateral) { c.PCKCRL = "" },
		"tcb_info_issuer_chain":    func(c *inject.TEECollateral) { c.TCBInfoIssuerChain = "" },
		"tcb_info":                 func(c *inject.TEECollateral) { c.TCBInfo = "" },
		"tcb_info_signature":       func(c *inject.TEECollateral) { c.TCBInfoSignature = "" },
		"qe_identity_issuer_chain": func(c *inject.TEECollateral) { c.QEIdentityIssuerChain = "" },
		"qe_identity":              func(c *inject.TEECollateral) { c.QEIdentity = "" },
		"qe_identity_signature":    func(c *inject.TEECollateral) { c.QEIdentitySignature = "" },
	}
	for name, blank := range blanks {
		c := *full
		blank(&c)
		if _, err := CollateralResponses(&c); err == nil {
			t.Errorf("a set missing %s was accepted", name)
		}
	}
	if _, err := CollateralResponses(nil); err == nil {
		t.Error("a nil set was accepted")
	}
}

func TestCollateralFreshEnough(t *testing.T) {
	now := time.Now()

	t.Run("accepts a set inside the floor", func(t *testing.T) {
		c := completeCollateral(t, now.Add(-24*time.Hour))
		if !CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
			t.Error("a one-day-old set was refused")
		}
	})

	t.Run("refuses a set past the floor", func(t *testing.T) {
		// Derived from the constant, never a literal: a hardcoded offset
		// passes for any production value.
		c := completeCollateral(t, now.Add(-EmbeddedCollateralMaxAge-time.Hour))
		if CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
			t.Error("a set past EmbeddedCollateralMaxAge was accepted")
		}
	})

	t.Run("brackets the floor from the near side", func(t *testing.T) {
		// Without this, any bound between "one day" and
		// "EmbeddedCollateralMaxAge + 1h" satisfies the pair above while
		// the constant advertises 14 days.
		c := completeCollateral(t, now.Add(-EmbeddedCollateralMaxAge+time.Hour))
		if !CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
			t.Error("a set one hour inside EmbeddedCollateralMaxAge was refused")
		}
	})

	t.Run("checks ALL FOUR documents, not the newest", func(t *testing.T) {
		// The rollback is per-document: fresh TCB info can be paired
		// with an older, still validly signed CRL predating the
		// revocation of this node's own PCK certificate. A check that
		// looked at one document would pass every one of these.
		old := now.Add(-EmbeddedCollateralMaxAge - time.Hour)
		stale := testCRLDER(t, old)

		cases := map[string]func(*inject.TEECollateral){
			"tcb_info":    func(c *inject.TEECollateral) { c.TCBInfo = tcbInfoDoc(old) },
			"qe_identity": func(c *inject.TEECollateral) { c.QEIdentity = qeIdentityDoc(old) },
			"pck_crl":     func(c *inject.TEECollateral) { c.PCKCRL = hex.EncodeToString(stale) },
			"root_ca_crl": func(c *inject.TEECollateral) { c.RootCACRL = hex.EncodeToString(stale) },
		}
		for name, age := range cases {
			c := completeCollateral(t, now.Add(-time.Hour))
			age(c)
			if CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
				t.Errorf("a set whose %s is stale was accepted — the other three documents "+
					"were fresh, so only a per-document check catches this", name)
			}
		}
	})

	t.Run("fails closed on an undated or unparseable document", func(t *testing.T) {
		// What it gates is a convenience, so refusing costs only the
		// outage verdict that would have been reported anyway.
		cases := map[string]func(*inject.TEECollateral){
			"tcb_info has no issueDate": func(c *inject.TEECollateral) {
				c.TCBInfo = `{"id":"TDX","version":3,"tcbLevels":[]}`
			},
			"tcb_info is not JSON": func(c *inject.TEECollateral) { c.TCBInfo = "{not json" },
			"pck_crl is not hex":   func(c *inject.TEECollateral) { c.PCKCRL = "zzzz" },
			"pck_crl is not a CRL": func(c *inject.TEECollateral) { c.PCKCRL = hex.EncodeToString([]byte("hello")) },
		}
		for name, break_ := range cases {
			c := completeCollateral(t, now.Add(-time.Hour))
			break_(c)
			if CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
				t.Errorf("accepted a set where %s", name)
			}
		}
	})

	t.Run("refuses a future issueDate", func(t *testing.T) {
		// now.Sub(future) is NEGATIVE, which compares as fresher than
		// anything real — the same shape that made a fast RTC defeat the
		// proxy's cache bounds.
		c := completeCollateral(t, now.Add(48*time.Hour))
		if CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
			t.Error("a set issued in the future was accepted")
		}
	})

	t.Run("refuses an incomplete set", func(t *testing.T) {
		c := completeCollateral(t, now.Add(-time.Hour))
		c.QEIdentitySignature = ""
		if CollateralFreshEnough(c, now, EmbeddedCollateralMaxAge) {
			t.Error("an incomplete set was called fresh")
		}
	})
}

func TestQEIdentityIssuerCertificates_NamesTheZeroCertificateCase(t *testing.T) {
	// The signature of a chain that was left percent-encoded, which is
	// the single most likely way to build a broken carried set. Every
	// downstream symptom of it is an attestation failure, so the error
	// has to say what actually happened.
	c := completeCollateral(t, time.Now().Add(-time.Hour))
	c.QEIdentityIssuerChain = url.QueryEscape(c.QEIdentityIssuerChain)
	if _, err := QEIdentityIssuerCertificates(c); err == nil {
		t.Fatal("a percent-encoded chain parsed as certificates")
	} else if !strings.Contains(err.Error(), "zero certificates") {
		t.Errorf("err = %v, want it to name the zero-certificate case", err)
	}
}
