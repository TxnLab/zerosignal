/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/google/go-tdx-guest/pcs"
)

const testRootCRLURL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"

// testIssuerChain mints a real two-certificate PEM chain — intermediate
// then root, the order go-tdx-guest's headerToIssuerChain parses — with
// the ROOT carrying cdp as its CRL distribution points.
//
// REAL CERTIFICATES, not a placeholder string, because the root's CRL
// distribution point is the only thing that tells either side which URL
// the root CA CRL answers on. A fixture that could not be parsed would
// have to be replaced by a hardcoded URL on both sides, which is exactly
// the coupling newEmbeddedGetter exists to avoid.
func testIssuerChain(t *testing.T, cdp []string) string {
	t.Helper()
	mint := func(cdp []string) []byte {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Intel SGX (test)"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
			CRLDistributionPoints: cdp,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("certificate: %v", err)
		}
		return der
	}
	var b strings.Builder
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mint(nil)}))
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mint(cdp)}))
	return b.String()
}

func testCollateralCRL(t *testing.T, thisUpdate time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Intel SGX PCK Platform CA (test)"},
		NotBefore:             thisUpdate.Add(-24 * time.Hour),
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
	return hex.EncodeToString(crl)
}

// testCarriedCollateral is a structurally valid set: every document
// parses, every chain decodes, every date is `issued`.
//
// IT IS NOT INTEL-SIGNED and cannot be. The signature check is not what
// these tests are about — see the parity test, which asserts only which
// URLs the library asked for and whether each was answered.
func testCarriedCollateral(t *testing.T, issued time.Time) *inject.TEECollateral {
	t.Helper()
	return &inject.TEECollateral{
		PCKCRLIssuerChain:  testIssuerChain(t, nil),
		RootCACRL:          testCollateralCRL(t, issued),
		PCKCRL:             testCollateralCRL(t, issued),
		TCBInfoIssuerChain: testIssuerChain(t, nil),
		TCBInfo: `{"version":3,"issueDate":"` + issued.UTC().Format(time.RFC3339) +
			`","id":"TDX","nextUpdate":"` + issued.Add(30*24*time.Hour).UTC().Format(time.RFC3339) +
			`","tcbLevels":[]}`,
		TCBInfoSignature:      "abcd",
		QEIdentityIssuerChain: testIssuerChain(t, []string{testRootCRLURL}),
		QEIdentity: `{"version":2,"issueDate":"` + issued.UTC().Format(time.RFC3339) +
			`","id":"TD_QE","nextUpdate":"` + issued.Add(30*24*time.Hour).UTC().Format(time.RFC3339) +
			`","tcbLevels":[]}`,
		QEIdentitySignature: "ef01",
	}
}

// recordingGetter notes every URL a verification asks for, and whether
// the wrapped source answered it.
type recordingGetter struct {
	inner   contextGetter
	asked   []string
	refused []string
}

func (g *recordingGetter) getWithContext(ctx context.Context, url string) (map[string][]string, []byte, error, error) {
	g.asked = append(g.asked, url)
	header, body, stale, err := g.inner.getWithContext(ctx, url)
	if err != nil {
		g.refused = append(g.refused, url)
	}
	return header, body, stale, err
}

// THE TEST THAT DECIDES WHETHER LAYER 3 IS REAL.
//
// newEmbeddedGetter answers as Intel's PCS, so its correctness is
// entirely a question of whether the set of URLs it covers equals the
// set go-tdx-guest asks for — a question no unit test of the getter
// alone can answer, because both halves would be written from the same
// assumption. So this drives the REAL tdxverify.RawTdxQuote against the
// REAL captured quote and reads the request log back.
//
// The verification itself fails: nothing here is Intel-signed. That is
// not a weakness of the test but the reason it is shaped this way —
// obtainCollateral fetches all four artifacts UP FRONT and aborts at the
// first one it cannot parse, long before any signature is checked. So
// "all four were asked for" transitively pins the canonical-MIME header
// names, the hex-to-DER CRL decoding, the envelope reassembly, and the
// CRL-distribution-point lookup: break any one and the sequence stops
// short, by name, right here.
func TestEmbeddedGetter_AnswersEveryURLTheRealVerifierAsks(t *testing.T) {
	quote, _ := loadDstackVectors(t)
	carried := testCarriedCollateral(t, time.Now().Add(-time.Hour))

	inner, err := newEmbeddedGetter(quote, carried)
	if err != nil {
		t.Fatalf("newEmbeddedGetter: %v", err)
	}
	rec := &recordingGetter{inner: inner}

	if _, verr := verifyTDXQuoteChainWith(t.Context(), quote, rec); verr == nil {
		t.Fatal("verification PASSED against collateral no Intel key signed — " +
			"the chain check is not running")
	}

	fmspc, ca, err := attest.PCKPlatformID(quote)
	if err != nil {
		t.Fatalf("PCKPlatformID: %v", err)
	}
	// LOWER-CASE fmspc, because that is what the library builds and this
	// list is a claim about the library, not about us. attest returns
	// the upper-case form Intel documents; the two are pinned against
	// each other by TestEmbeddedGetter_CoversBothFmspcCasings.
	for _, want := range []string{
		pcs.TcbInfoURL(strings.ToLower(fmspc)),
		pcs.QeIdentityURL(),
		pcs.PckCrlURL(ca),
		testRootCRLURL,
	} {
		if !slices.Contains(rec.asked, want) {
			t.Errorf("the verifier never asked for %s\n  asked: %v", want, rec.asked)
		}
	}
	if len(rec.refused) != 0 {
		t.Errorf("the carried set could not answer %v — a URL go-tdx-guest asks for "+
			"that newEmbeddedGetter does not cover reads as an Intel outage", rec.refused)
	}
}

// go-tdx-guest hex-encodes the FMSPC extension itself, producing
// lower-case, while attest.PCKPlatformID returns the upper-case form
// Intel documents and the node publishes. Intel's own API is
// case-insensitive, so NOTHING LIVE FAILS if this regresses — the map
// simply stops answering and the miss is reported as "Intel PCS
// unreachable".
//
// Asserted from both directions on purpose: covering only the casing the
// library happens to use today would pass for a getter that has silently
// become coupled to an implementation detail of a dependency.
func TestEmbeddedGetter_CoversBothFmspcCasings(t *testing.T) {
	quote, _ := loadDstackVectors(t)
	g, err := newEmbeddedGetter(quote, testCarriedCollateral(t, time.Now()))
	if err != nil {
		t.Fatalf("newEmbeddedGetter: %v", err)
	}
	fmspc, _, err := attest.PCKPlatformID(quote)
	if err != nil {
		t.Fatalf("PCKPlatformID: %v", err)
	}
	if fmspc != strings.ToUpper(fmspc) {
		t.Fatalf("attest.PCKPlatformID returned %q — this test's premise is that it is "+
			"upper-case; if that changed deliberately, the getter still needs both", fmspc)
	}
	for _, f := range []string{strings.ToUpper(fmspc), strings.ToLower(fmspc)} {
		if _, body, _, gerr := g.getWithContext(t.Context(), pcs.TcbInfoURL(f)); gerr != nil || len(body) == 0 {
			t.Errorf("fmspc=%s: err=%v body=%d bytes", f, gerr, len(body))
		}
	}
}

// An unanswerable URL must be REFUSED rather than answered with nothing:
// a zero-value response reads to the library as a malformed document,
// which would report a node's evidence as bad for a gap that is ours.
func TestEmbeddedGetter_RefusesAURLTheSetDoesNotCover(t *testing.T) {
	quote, _ := loadDstackVectors(t)
	g, err := newEmbeddedGetter(quote, testCarriedCollateral(t, time.Now()))
	if err != nil {
		t.Fatalf("newEmbeddedGetter: %v", err)
	}
	header, body, _, err := g.getWithContext(t.Context(), "https://example.invalid/tcb")
	if !errors.Is(err, ErrNoUsableCarriedCollateral) {
		t.Fatalf("err = %v, want ErrNoUsableCarriedCollateral", err)
	}
	if header != nil || body != nil {
		t.Errorf("a refusal returned header=%v body=%d bytes, want both nil", header, len(body))
	}
}

// EXACTLY ONE issuer-chain header per response. Emitting all three would
// be inert today — the library indexes one key — and would hand it a
// chain for a document it is not reading the moment that stops being
// true.
func TestEmbeddedGetter_SendsOneIssuerChainHeaderPerArtifact(t *testing.T) {
	quote, _ := loadDstackVectors(t)
	carried := testCarriedCollateral(t, time.Now())
	g, err := newEmbeddedGetter(quote, carried)
	if err != nil {
		t.Fatalf("newEmbeddedGetter: %v", err)
	}
	fmspc, ca, err := attest.PCKPlatformID(quote)
	if err != nil {
		t.Fatalf("PCKPlatformID: %v", err)
	}

	for _, tc := range []struct {
		url  string
		want string
	}{
		{pcs.TcbInfoURL(fmspc), "Tcb-Info-Issuer-Chain"},
		{pcs.QeIdentityURL(), "Sgx-Enclave-Identity-Issuer-Chain"},
		{pcs.PckCrlURL(ca), "Sgx-Pck-Crl-Issuer-Chain"},
		{testRootCRLURL, ""},
	} {
		header, body, _, err := g.getWithContext(t.Context(), tc.url)
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if len(body) == 0 {
			t.Errorf("%s answered with an empty body", tc.url)
		}
		if tc.want == "" {
			if len(header) != 0 {
				t.Errorf("%s carried %v, want no issuer chain: the root CA CRL is "+
					"validated against a root the library has already pinned", tc.url, header)
			}
			continue
		}
		if len(header) != 1 || len(header[tc.want]) != 1 {
			t.Errorf("%s carried %v, want exactly %q", tc.url, header, tc.want)
		}
	}
}

// SPEC §3e's precedence, as a decision table.
//
// THE ROW THAT MATTERS IS ErrStaleCollateralRejected. It looks like an
// outage — it is caused by one — but it means our OWN cached Intel
// document was consulted and refused this quote. Falling through to the
// node's set there would discard a signed statement we hold, of a
// vintage the operator did not choose, in favour of one it did: the
// rollback the precedence rule exists to prevent. §3e's "our cache ->
// the node's copy" step is about our cache having no ANSWER, which
// surfaces as ErrCollateralUnavailable and is the row above.
func TestDstackVerifier_CarriedCollateralIsReachedOnlyByAnOutage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		chainErr    error
		carriedErr  error
		wantCarried bool
		wantTag     string
	}{
		{
			name:        "PCS and our cache both empty, the node's set verifies",
			chainErr:    fmt.Errorf("%w: dial tcp: no route to host", ErrCollateralUnavailable),
			carriedErr:  nil,
			wantCarried: true,
			wantTag:     "",
		},
		{
			name:        "PCS and our cache both empty, the node's set does not verify either",
			chainErr:    fmt.Errorf("%w: dial tcp: no route to host", ErrCollateralUnavailable),
			carriedErr:  errors.New("chain does not root at Intel"),
			wantCarried: true,
			// The OUTAGE tag, not a vendor-chain accusation: the last
			// resort's complaint describes the node's set, and the
			// verification failed first because we could not reach Intel.
			wantTag: FailureCollateralUnreachable,
		},
		{
			name:        "our own stale document refused the quote",
			chainErr:    fmt.Errorf("%w: crl expired", ErrStaleCollateralRejected),
			carriedErr:  nil,
			wantCarried: false,
			wantTag:     FailureCollateralUnreachable,
		},
		{
			name:        "a verification that ran on current collateral and refused",
			chainErr:    errors.New("tdx quote verification: signature mismatch"),
			carriedErr:  nil,
			wantCarried: false,
			wantTag:     FailureVendorChainInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, op, bundle := dstackFixture(t)
			bundle.Collateral = testCarriedCollateral(t, time.Now())
			called := false
			v.VerifyChain = func(context.Context, []byte) error { return tc.chainErr }
			v.VerifyChainCarried = func(context.Context, []byte, *inject.TEECollateral) error {
				called = true
				return tc.carriedErr
			}

			verdict := v.Verify(t.Context(), dstackAdvertisement(), bundle, op)

			if called != tc.wantCarried {
				t.Errorf("carried verifier called = %v, want %v", called, tc.wantCarried)
			}
			if verdict.FailureTag != tc.wantTag {
				t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, tc.wantTag)
			}
			if (verdict.FailureTag == "") != verdict.Pass {
				t.Errorf("Pass = %v alongside FailureTag %q", verdict.Pass, verdict.FailureTag)
			}
		})
	}
}

// The bundle's OWN set is what gets handed to the last resort. Passing
// anything else — a nil, or a set from some other operator — would make
// the fallback verify one node's quote against another's criteria.
func TestDstackVerifier_HandsTheCarriedVerifierTheBundlesOwnSet(t *testing.T) {
	v, op, bundle := dstackFixture(t)
	bundle.Collateral = testCarriedCollateral(t, time.Now())
	var got *inject.TEECollateral
	v.VerifyChain = func(context.Context, []byte) error {
		return fmt.Errorf("%w: down", ErrCollateralUnavailable)
	}
	v.VerifyChainCarried = func(_ context.Context, _ []byte, c *inject.TEECollateral) error {
		got = c
		return nil
	}

	if verdict := v.Verify(t.Context(), dstackAdvertisement(), bundle, op); !verdict.Pass {
		t.Fatalf("verdict = %+v, want Pass", verdict)
	}
	if got != bundle.Collateral {
		t.Fatalf("the carried verifier received %p, want the bundle's own set %p", got, bundle.Collateral)
	}
}

func TestVerifyTDXQuoteChainEmbedded_RefusesAnIncompleteSet(t *testing.T) {
	quote, _ := loadDstackVectors(t)
	partial := testCarriedCollateral(t, time.Now())
	partial.PCKCRL = ""

	// Nil is the ordinary case — a node on a build that never published
	// collateral — and must take the same refusal, not a nil dereference.
	for name, c := range map[string]*inject.TEECollateral{"partial": partial, "absent": nil} {
		t.Run(name, func(t *testing.T) {
			err := VerifyTDXQuoteChainCarried(t.Context(), quote, c)
			if !errors.Is(err, ErrNoUsableCarriedCollateral) {
				t.Fatalf("err = %v, want ErrNoUsableCarriedCollateral", err)
			}
		})
	}
}

// The 14-day floor is what bounds an operator's choice of vintage, so it
// has to refuse from BOTH sides of the boundary or it is a comment.
func TestVerifyTDXQuoteChainEmbedded_BoundsTheCarriedVintage(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	stale := testCarriedCollateral(t, time.Now().Add(-attest.EmbeddedCollateralMaxAge-time.Hour))
	if err := VerifyTDXQuoteChainCarried(t.Context(), quote, stale); !errors.Is(err, ErrNoUsableCarriedCollateral) {
		t.Fatalf("a set older than %v: err = %v, want ErrNoUsableCarriedCollateral",
			attest.EmbeddedCollateralMaxAge, err)
	}

	// Just inside the floor must get PAST the freshness gate and fail on
	// the chain instead. Without this the test above passes for a
	// verifier that refuses every carried set unconditionally.
	fresh := testCarriedCollateral(t, time.Now().Add(-attest.EmbeddedCollateralMaxAge+time.Hour))
	err := VerifyTDXQuoteChainCarried(t.Context(), quote, fresh)
	if err == nil {
		t.Fatal("a set signed by nobody PASSED")
	}
	if errors.Is(err, ErrNoUsableCarriedCollateral) {
		t.Fatalf("a set inside the %v floor was refused as unusable: %v",
			attest.EmbeddedCollateralMaxAge, err)
	}
}
