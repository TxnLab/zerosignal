/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// testOperatorAndPubkey returns an Operator and the string used as the bundle's
// NodePubkey, in lockstep so the verifier's cross-check passes. The TEE
// key-binding target is the node's current ephemeral age recipient — the key
// the proxy actually seals to — which applyEphemeralAdvertisement populates
// (signature-verified, lifetime-capped) earlier in the same refresh pass.
// SigningAddr is set too, since a real operator always has one, but the
// verifier no longer binds to it.
func testOperatorAndPubkey(t *testing.T, id uint64) (Operator, string) {
	t.Helper()
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	recipient := ageID.Recipient().String()
	return Operator{
		ID:                       id,
		SigningAddr:              "SIGNING-ADDR-NOT-THE-BINDING-TARGET",
		EphemeralRecipientPubkey: recipient,
	}, recipient
}

// stubBundleFor returns a well-formed stub-mode evidence bundle bound
// to (nodePubkey, operatorID). Mirrors what a node running tee.mode=stub
// emits via /v1/zs/attestation. Use this to drive the verifier
// happy-path tests; mutate fields after to drive negative cases.
func stubBundleFor(nodePubkey string, operatorID uint64) inject.TEEEvidenceBundle {
	var idBytes [8]byte
	binary.BigEndian.PutUint64(idBytes[:], operatorID)
	h := sha256.New()
	h.Write([]byte(nodePubkey))
	h.Write(idBytes[:])
	return inject.TEEEvidenceBundle{
		Mode:           inject.TEEModeStub,
		NodePubkey:     nodePubkey,
		OperatorID:     operatorID,
		ReportData:     base64.StdEncoding.EncodeToString(h.Sum(nil)),
		GeneratedAt:    time.Now().UTC(),
		RefreshSeconds: 60,
		Stub:           true,
	}
}

func TestBundleVerifier_StubAllowed(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	advertised := inject.TEEAdvertisement{
		Mode:        inject.TEEModeStub,
		AttestedAt:  bundle.GeneratedAt,
		EvidenceURL: "/v1/zs/attestation",
	}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if !verdict.Pass {
		t.Fatalf("Pass = false; FailureTag = %q", verdict.FailureTag)
	}
	if verdict.FailureTag != "" {
		t.Errorf("FailureTag should be empty on pass, got %q", verdict.FailureTag)
	}
	if verdict.VerifierID != VerifierIDBuiltin {
		t.Errorf("VerifierID = %q, want %q", verdict.VerifierID, VerifierIDBuiltin)
	}
	if !verdict.AttestedAt.Equal(bundle.GeneratedAt) {
		t.Errorf("AttestedAt mismatch")
	}
}

func TestBundleVerifier_StubRejectedWhenNotAllowed(t *testing.T) {
	v := &BundleVerifier{AllowStub: false}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with AllowStub=false")
	}
	if verdict.FailureTag != FailureStubNotAllowed {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureStubNotAllowed)
	}
	// Verifier identity and attested-at still populated for telemetry.
	if verdict.VerifierID != VerifierIDBuiltin {
		t.Errorf("VerifierID empty on failed verdict")
	}
}

func TestBundleVerifier_KeyBindingMismatch(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	// Tamper with the binding hash directly.
	bundle.ReportData = base64.StdEncoding.EncodeToString(make([]byte, 32))
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with bad binding")
	}
	if verdict.FailureTag != FailureKeyBindingMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureKeyBindingMismatch)
	}
}

func TestBundleVerifier_KeyBindingMismatch_BadBase64(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	bundle.ReportData = "not-base64!@#"
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with malformed report_data")
	}
	if verdict.FailureTag != FailureKeyBindingMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureKeyBindingMismatch)
	}
}

func TestBundleVerifier_AdvertisementMismatch_Mode(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeNvidiaCCTDX}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with mode mismatch")
	}
	if verdict.FailureTag != FailureAdvertisementMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureAdvertisementMismatch)
	}
}

func TestBundleVerifier_AdvertisementMismatch_OperatorID(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 99) // proxy says 99
	bundle := stubBundleFor(pubkey, 7)         // bundle says 7
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with operator id mismatch")
	}
	if verdict.FailureTag != FailureAdvertisementMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureAdvertisementMismatch)
	}
}

func TestBundleVerifier_NodePubkeyMismatch(t *testing.T) {
	// The bundle binds report_data to one pubkey, but the on-chain
	// operator record has a different pubkey. This is the
	// load-bearing key-binding cross-check: even if the bundle is
	// internally consistent, accepting it would route TEE-required
	// traffic to a key that the attested hardware does not hold.
	v := &BundleVerifier{AllowStub: true}
	op, _ := testOperatorAndPubkey(t, 7)
	otherID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate other identity: %v", err)
	}
	bundle := stubBundleFor(otherID.Recipient().String(), 7)
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with bundle.NodePubkey != the verified ephemeral recipient")
	}
	if verdict.FailureTag != FailureAdvertisementMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureAdvertisementMismatch)
	}
}

func TestBundleVerifier_NoEphemeralRecipientFailsClosed(t *testing.T) {
	// An Operator with no verified ephemeral this cycle (never advertised,
	// expired, or a bad signature) must fail closed instead of computing a
	// binding hash over an empty key — that hash is deterministic, so a
	// hostile bundle could be crafted to match it. Such an operator is
	// unsealable anyway.
	v := &BundleVerifier{AllowStub: true}
	op := Operator{ID: 7, SigningAddr: "SIGNING-ADDR-PRESENT"} // no ephemeral
	bundle := stubBundleFor("age1-does-not-need-to-parse", 7)
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with no verified ephemeral recipient")
	}
	if verdict.FailureTag != FailureKeyBindingMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureKeyBindingMismatch)
	}
}

func TestBundleVerifier_StaleEvidence(t *testing.T) {
	// Bundle older than 2× RefreshSeconds is rejected even when the
	// internal binding is consistent. The node should have returned
	// 503 stale_attestation before the proxy got here, but the proxy
	// independently enforces freshness as defense in depth.
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	bundle.RefreshSeconds = 60
	bundle.GeneratedAt = time.Now().Add(-3 * time.Minute) // > 2*60s
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with stale evidence")
	}
	if verdict.FailureTag != FailureStaleEvidence {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureStaleEvidence)
	}
}

// The freshness window is ABSOLUTE, and the future half is the one a
// one-sided `time.Since(...) > maxAge` misses completely: time.Since of a
// future instant is negative and never exceeds the bound, so a node that
// mints once and stamps a far-future GeneratedAt satisfies the rule forever
// while advertising a compliant cadence. That is a strictly better bypass
// than an old timestamp, and GeneratedAt is operator-authored.
//
// The tolerated-skew case is not decoration: without it this test passes for
// a rule that rejects every timestamp not in the past, which would fail
// honest nodes on ordinary NTP drift.
func TestBundleVerifier_FutureDatedEvidenceIsStale(t *testing.T) {
	cases := []struct {
		name     string
		offset   time.Duration
		wantPass bool
	}{
		{"far future", 100 * 365 * 24 * time.Hour, false},
		{"just past the window", 3 * time.Minute, false},
		{"small forward skew is tolerated", 2 * time.Second, true},
		{"small backward skew is tolerated", -2 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &BundleVerifier{AllowStub: true}
			op, pubkey := testOperatorAndPubkey(t, 7)
			bundle := stubBundleFor(pubkey, 7)
			bundle.RefreshSeconds = 60 // window is 2×60s
			bundle.GeneratedAt = time.Now().Add(tc.offset)
			advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

			verdict := v.Verify(context.Background(), advertised, bundle, op)

			if verdict.Pass != tc.wantPass {
				t.Fatalf("Pass = %v, want %v (tag %q)", verdict.Pass, tc.wantPass, verdict.FailureTag)
			}
			if !tc.wantPass && verdict.FailureTag != FailureStaleEvidence {
				t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureStaleEvidence)
			}
		})
	}
}

// RefreshSeconds is the NODE's own number, so a freshness rule stated
// only in terms of it is a rule the attested party sets for itself.
// Both escapes are one field wide and neither needs a forged byte:
// omitting the field skipped the check outright, and advertising a day
// makes "2× the cadence" two days. EvidenceMaxAgeCeiling closes both.
//
// The tighter-cadence cases are not decoration: without them this test
// passes for an implementation that ignores RefreshSeconds entirely and
// always uses the ceiling, which would be a large loosening for every
// honest node.
func TestBundleVerifier_CeilingBoundsNodeAuthoredCadence(t *testing.T) {
	cases := []struct {
		name           string
		refreshSeconds int
		age            time.Duration
		wantPass       bool
	}{
		{"omitted cadence, far past", 0, 48 * time.Hour, false},
		{"omitted cadence, far future", 0, -48 * time.Hour, false},
		{"omitted cadence, inside the ceiling", 0, 10 * time.Minute, true},
		{"day-long cadence cannot outrun the ceiling", 86400, 2 * time.Hour, false},
		{"day-long cadence, future past the ceiling", 86400, -2 * time.Hour, false},
		// 4 minutes, not 3: at 3 the age sits exactly on the 2×60s
		// window's 3× boundary, so the row rejects only by the
		// microseconds between the test's time.Now() and the verifier's
		// time.Since — it would pass a 2×→3× multiplier mutant on a
		// slow enough machine and pins the multiplier at nothing.
		{"tighter cadence still wins", 60, 4 * time.Minute, false},
		{"tighter cadence, inside its own window", 60, 30 * time.Second, true},
		// The DEFAULT cadence, and the only row describing a behavior
		// change a deployed node can actually feel: at 3600 the window
		// was 2h and is now 80m, so 90m flips from accept to reject.
		// Everything above it uses values no node emits.
		{"default hourly cadence is clamped by the ceiling", 3600, 90 * time.Minute, false},
		{"default hourly cadence, inside the ceiling", 3600, 70 * time.Minute, true},
		// Parity with the TypeScript twin, which pins both directions.
		// A malformed cadence advertises no rule, so it falls back to
		// the ceiling — NOT to rejection. Mutating the `> 0` guard to
		// `!= 0` makes the doubled duration negative, pins maxAge
		// negative, and fails every bundle: the second row catches it,
		// and without the second row the first is satisfied by that
		// mutant too.
		{"negative cadence past the ceiling", -1, 2 * time.Hour, false},
		{"negative cadence falls back to the ceiling, not to rejection", -1, 10 * time.Minute, true},
		// Overflow: the nanosecond product wraps int64 here. Same
		// mutant, reached through arithmetic rather than a sign.
		{"overflowing cadence falls back to the ceiling", 1 << 33, 10 * time.Minute, true},
		{"overflowing cadence past the ceiling", 1 << 33, 2 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &BundleVerifier{AllowStub: true}
			op, pubkey := testOperatorAndPubkey(t, 7)
			bundle := stubBundleFor(pubkey, 7)
			bundle.RefreshSeconds = tc.refreshSeconds
			bundle.GeneratedAt = time.Now().Add(-tc.age)
			advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

			verdict := v.Verify(context.Background(), advertised, bundle, op)

			if verdict.Pass != tc.wantPass {
				t.Fatalf("Pass = %v, want %v (tag %q)", verdict.Pass, tc.wantPass, verdict.FailureTag)
			}
			if !tc.wantPass && verdict.FailureTag != FailureStaleEvidence {
				t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureStaleEvidence)
			}
		})
	}
}

// The ceiling is a hand-written literal on BOTH sides (client/ pins a
// published @txnlab/zs-proto and cannot import ticket's constants),
// so nothing makes the two move together. This is what fires when the
// ephemeral window is retuned: fix the literal here AND
// EVIDENCE_MAX_AGE_CEILING_MS in client/src/operators/tee-verify.ts.
//
// The first assertion is the safety property — the ceiling must never
// reject a bundle the key binding would have accepted, and an accepted
// bundle binds a live ephemeral, so its honest age is at most
// MaxEphemeralLifetime plus the skew that keeps that key live.
// The SAME one-field escape the ceiling closes for refresh_seconds, on
// the other field: omit generated_at and a wrapper like
// `if !bundle.GeneratedAt.IsZero() { … }` skips freshness entirely, with
// no forged byte anywhere. It fails closed today only because a zero
// time.Time yields ~2000 years of skew — an accident of the type, not a
// decision — and the cadence table cannot reach it, since every row
// assigns GeneratedAt outright.
func TestBundleVerifier_AbsentGeneratedAtIsStale(t *testing.T) {
	for _, refreshSeconds := range []int{0, 3600} {
		v := &BundleVerifier{AllowStub: true}
		op, pubkey := testOperatorAndPubkey(t, 7)
		bundle := stubBundleFor(pubkey, 7)
		bundle.RefreshSeconds = refreshSeconds
		bundle.GeneratedAt = time.Time{} // field omitted from the JSON
		advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

		verdict := v.Verify(context.Background(), advertised, bundle, op)

		if verdict.Pass {
			t.Errorf("refresh_seconds=%d: Pass = true with no generated_at", refreshSeconds)
		}
		if verdict.FailureTag != FailureStaleEvidence {
			t.Errorf("refresh_seconds=%d: FailureTag = %q, want %q",
				refreshSeconds, verdict.FailureTag, FailureStaleEvidence)
		}
	}
}

// Tag PRECEDENCE, not the accept/reject bit — which is unchanged if the
// freshness block and the key-binding check swap places. The tags are
// the telemetry handles dashboards index on, so a silent reorder
// relabels a whole class of failures without any suite noticing.
func TestBundleVerifier_StaleEvidenceOutranksKeyBinding(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	bundle := stubBundleFor(pubkey, 7)
	bundle.RefreshSeconds = 60
	bundle.GeneratedAt = time.Now().Add(-3 * time.Minute)
	bundle.ReportData = base64.StdEncoding.EncodeToString([]byte("not the binding hash"))
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("Pass = true with both a stale timestamp and a bad binding")
	}
	if verdict.FailureTag != FailureStaleEvidence {
		t.Errorf("FailureTag = %q, want %q — freshness is checked before the key binding",
			verdict.FailureTag, FailureStaleEvidence)
	}
}

func TestEvidenceMaxAgeCeilingCoversEphemeralWindow(t *testing.T) {
	// ONE relation, asserted twice, so the two can never disagree about
	// what the ceiling is for. Asserting `> lifetime+skew` alongside an
	// independent `== 2*lifetime` encodes two theories: raise
	// DefaultEphemeralSkew past MaxEphemeralLifetime and they become
	// unsatisfiable together, and the failure points at the wrong fix.
	// The LITERAL pin has to come first, and it is not redundant with
	// the derived one below. Rewrite the constant as
	// `2 * ticket.MaxEphemeralLifetime` — the one thing its godoc
	// forbids in prose — and the derived comparison becomes `X != X`,
	// which can never fire. The drift detector would then be perfectly
	// green while a bump to MaxEphemeralLifetime widened the Go ceiling
	// and left the hand-written TypeScript twin at 80m: two verifiers
	// disagreeing on any bundle aged between them, both suites green.
	// Only an independent literal here makes the rest non-tautological.
	if EvidenceMaxAgeCeiling != 80*time.Minute {
		t.Errorf("EvidenceMaxAgeCeiling = %v, want the literal 80m; if this was rewritten as a "+
			"derived expression, put the literal back — see the constant's godoc", EvidenceMaxAgeCeiling)
	}
	want := 2 * ticket.MaxEphemeralLifetime
	if widestHonestAge := ticket.MaxEphemeralLifetime + ticket.DefaultEphemeralSkew; want <= widestHonestAge {
		t.Fatalf("2×MaxEphemeralLifetime = %v no longer exceeds the widest honest evidence age %v; "+
			"the ceiling needs a new derivation, not a bigger literal", want, widestHonestAge)
	}
	if EvidenceMaxAgeCeiling != want {
		t.Errorf("EvidenceMaxAgeCeiling = %v, want %v (2×MaxEphemeralLifetime); "+
			"update this literal AND EVIDENCE_MAX_AGE_CEILING_MS in client/src/operators/tee-verify.ts",
			EvidenceMaxAgeCeiling, want)
	}
}

func TestBundleVerifier_RealEvidenceNotImplemented(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, pubkey := testOperatorAndPubkey(t, 7)
	// Build a non-stub bundle for nvidia-cc-tdx with a valid binding
	// hash (so the verifier reaches the real-evidence branch).
	bundle := stubBundleFor(pubkey, 7)
	bundle.Mode = inject.TEEModeNvidiaCCTDX
	bundle.Stub = false
	bundle.CPUReport = "FAKEBASE64=="
	bundle.GPUEAT = "fake.jwt.sig"
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeNvidiaCCTDX}

	verdict := v.Verify(context.Background(), advertised, bundle, op)

	if verdict.Pass {
		t.Fatalf("real-evidence verifier shouldn't pass yet")
	}
	if verdict.FailureTag != FailureVerifierNotImpl {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureVerifierNotImpl)
	}
}

func TestBundleVerifier_AlwaysPopulatesVerifierID(t *testing.T) {
	// Verdict.VerifierID must be set whether Pass is true or false —
	// dashboards and audit logs index against it.
	v := &BundleVerifier{AllowStub: false}
	cases := []struct {
		name string
		mut  func(*inject.TEEEvidenceBundle, *inject.TEEAdvertisement, *Operator)
	}{
		{"stub_not_allowed", func(b *inject.TEEEvidenceBundle, a *inject.TEEAdvertisement, _ *Operator) {}},
		{"key_binding_mismatch", func(b *inject.TEEEvidenceBundle, _ *inject.TEEAdvertisement, _ *Operator) {
			b.ReportData = base64.StdEncoding.EncodeToString(make([]byte, 32))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op, pubkey := testOperatorAndPubkey(t, 7)
			bundle := stubBundleFor(pubkey, 7)
			advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}
			tc.mut(&bundle, &advertised, &op)
			verdict := v.Verify(context.Background(), advertised, bundle, op)
			if verdict.Pass {
				t.Fatalf("expected failure")
			}
			if verdict.VerifierID != VerifierIDBuiltin {
				t.Errorf("VerifierID empty on failed verdict: %+v", verdict)
			}
		})
	}
}

func TestAttestationClient_FetchHappyPath(t *testing.T) {
	want := stubBundleFor("age1abc", 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/attestation" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", inject.AttestationContentType)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := NewAttestationClient(srv.Client(), 2*time.Second)
	got, err := c.Fetch(context.Background(), srv.URL, "/v1/zs/attestation", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Mode != want.Mode || got.NodePubkey != want.NodePubkey || got.OperatorID != want.OperatorID {
		t.Errorf("bundle round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestAttestationClient_FetchNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewAttestationClient(srv.Client(), 500*time.Millisecond)
	_, err := c.Fetch(context.Background(), srv.URL, "/v1/zs/attestation", nil)
	if err == nil {
		t.Fatal("Fetch should error on 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention 503: %v", err)
	}
}

func TestAttestationClient_FetchEmptyEvidenceURL(t *testing.T) {
	// Empty evidence URL → falls back to /v1/zs/attestation on
	// the operator's BaseURL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/attestation" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(stubBundleFor("age1abc", 7))
	}))
	defer srv.Close()
	c := NewAttestationClient(srv.Client(), 2*time.Second)
	if _, err := c.Fetch(context.Background(), srv.URL, "", nil); err != nil {
		t.Fatalf("empty evidence URL fallback failed: %v", err)
	}
}

func TestAttestationClient_FetchAbsoluteEvidenceURL(t *testing.T) {
	// Absolute URL (different host) is honored verbatim.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stubBundleFor("age1abc", 7))
	}))
	defer srv.Close()
	c := NewAttestationClient(srv.Client(), 2*time.Second)
	if _, err := c.Fetch(context.Background(), "http://operator.example", srv.URL, nil); err != nil {
		t.Fatalf("absolute evidence URL failed: %v", err)
	}
}

func TestJoinAttestationURL(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		evidence string
		want     string
		wantErr  bool
	}{
		{"empty evidence falls back", "https://op.example", "", "https://op.example/v1/zs/attestation", false},
		{"trailing slash stripped", "https://op.example/", "/v1/zs/attestation", "https://op.example/v1/zs/attestation", false},
		{"path normalized", "https://op.example", "v1/zs/attestation", "https://op.example/v1/zs/attestation", false},
		{"absolute http accepted", "https://op.example", "http://other.example/x", "http://other.example/x", false},
		{"absolute https accepted", "https://op.example", "https://other.example/x", "https://other.example/x", false},
		{"empty base errors", "", "/v1/zs/attestation", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := joinAttestationURL(tc.base, tc.evidence)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOperator_IsTEEAttested(t *testing.T) {
	cases := []struct {
		name string
		op   Operator
		want bool
	}{
		{"nil TEE", Operator{}, false},
		{"verified", Operator{TEE: &TEEStatus{Verified: true}}, true},
		{"populated but not verified", Operator{TEE: &TEEStatus{Verified: false, FailureTag: FailureKeyBindingMismatch}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.op.IsTEEAttested(); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// The binding target is the ephemeral sealing recipient, NOT the on-chain
// signing address. This is the property that makes the attestation say
// something about where plaintext actually lands: an operator holding a copy
// of the signing key outside the enclave can sign an advertisement for an
// ephemeral whose private half lives on the plain host, so evidence bound to
// the identity key would pass while the prompt is sealed to a key the host
// can read. Guards against a regression back to op.SigningAddr.
func TestBundleVerifier_BindsEphemeralNotSigningAddr(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, recipient := testOperatorAndPubkey(t, 7)
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	// Evidence bound to the operator's signing address — what the interim
	// implementation produced — must now be rejected.
	signingBound := stubBundleFor(op.SigningAddr, 7)
	if verdict := v.Verify(context.Background(), advertised, signingBound, op); verdict.Pass {
		t.Fatalf("evidence bound to SigningAddr was accepted; binding target regressed")
	}

	// Evidence bound to the verified ephemeral recipient passes.
	ephemeralBound := stubBundleFor(recipient, 7)
	if verdict := v.Verify(context.Background(), advertised, ephemeralBound, op); !verdict.Pass {
		t.Fatalf("evidence bound to the ephemeral recipient rejected: %q", verdict.FailureTag)
	}
}

// A node that rotated its sealing key but has not re-minted evidence yet
// advertises key B while serving a bundle binding key A. That must fail
// closed (operator drops out of Require-TEE routing until the next probe),
// never be accepted as "close enough".
func TestBundleVerifier_RotatedButNotRemintedFailsClosed(t *testing.T) {
	v := &BundleVerifier{AllowStub: true}
	op, _ := testOperatorAndPubkey(t, 7)

	stale, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	bundle := stubBundleFor(stale.Recipient().String(), 7) // pre-rotation key
	advertised := inject.TEEAdvertisement{Mode: inject.TEEModeStub}

	verdict := v.Verify(context.Background(), advertised, bundle, op)
	if verdict.Pass {
		t.Fatalf("evidence bound to a rotated-away key was accepted")
	}
	if verdict.FailureTag != FailureAdvertisementMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureAdvertisementMismatch)
	}
}
