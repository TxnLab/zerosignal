/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/steering"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// signEphemeralAdv signs a ticket.EphemeralAdvertisement for (operatorID,
// nodeID) under priv (the node's on-chain signing key) and returns the
// populated block. signAddr must match what rawKeyBytesSigner is keyed on.
func signEphemeralAdv(t *testing.T, signAddr string, priv ed25519.PrivateKey, operatorID, nodeID uint64, agePubkey string, expiry int64) ticket.EphemeralAdvertisement {
	t.Helper()
	adv := ticket.EphemeralAdvertisement{
		AgePubkey: agePubkey,
		Expiry:    expiry,
		// Signed window 10m (≤ MaxEphemeralLifetime) ending at expiry, so the
		// lifetime cap passes and the expired-block tests still surface
		// ErrEphemeralExpired (not the lifetime sentinel).
		IssuedAt: expiry - 600,
	}
	if err := adv.Sign(context.Background(), rawKeyBytesSigner{addr: signAddr, priv: priv}, signAddr, operatorID, nodeID); err != nil {
		t.Fatalf("sign ephemeral advertisement: %v", err)
	}
	return adv
}

// --- Operator.SealRecipient (mandatory forward secrecy: ephemeral or error) ---

func TestSealRecipient_ReturnsValidEphemeral(t *testing.T) {
	eph := mustX25519(t)
	now := time.Now()
	op := Operator{
		EphemeralRecipient:       eph.Recipient(),
		EphemeralRecipientPubkey: eph.Recipient().String(),
		EphemeralExpiry:          now.Add(10 * time.Minute).Unix(),
	}
	got, err := op.SealRecipient(now)
	if err != nil {
		t.Fatalf("SealRecipient returned an error for a valid, unexpired ephemeral: %v", err)
	}
	if got != op.EphemeralRecipient {
		t.Errorf("SealRecipient returned %v, want the ephemeral recipient", got)
	}
}

func TestSealRecipient_NoEphemeralErrors(t *testing.T) {
	op := Operator{} // no ephemeral set — there is no anchor fallback
	got, err := op.SealRecipient(time.Now())
	if !IsNoEphemeral(err) {
		t.Fatalf("SealRecipient err = %v, want errNoEphemeral when no ephemeral is set", err)
	}
	if got != nil {
		t.Errorf("SealRecipient returned a non-nil recipient %v alongside errNoEphemeral", got)
	}
}

func TestSealRecipient_ExpiredEphemeralErrors(t *testing.T) {
	eph := mustX25519(t)
	now := time.Now()
	op := Operator{
		EphemeralRecipient: eph.Recipient(),
		// Expired a minute ago — the cheap re-check must reject it even
		// though enrich once verified it. No anchor to fall back to.
		EphemeralExpiry: now.Add(-1 * time.Minute).Unix(),
	}
	if _, err := op.SealRecipient(now); !IsNoEphemeral(err) {
		t.Fatalf("SealRecipient err = %v, want errNoEphemeral for an expired ephemeral", err)
	}
}

func mustX25519(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// --- fetcher enrich pass verifies + stores / clears the ephemeral ---

// testEnrichNodeID is the node id the enrich fixtures run under — the signed
// canonical bytes bind (operator_id, node_id), so the signer and the
// operator snapshot must agree on it.
const testEnrichNodeID uint64 = 7

// ephemeralEnrichFixture bundles a fake /v1/zs/details server (whose
// response carries the supplied ephemeral_* block) and the operator the
// enrich pass runs against. The signing key behind op.TicketSigningKey is
// the verifier key, so a block signed with signPriv for op.ID verifies.
type ephemeralEnrichFixture struct {
	source   *ChainOperatorSource
	op       Operator
	signAddr string
	signPriv ed25519.PrivateKey
}

// newEphemeralEnrichFixture mints a signing key, lets the caller sign an
// advertisement against it via signFn, and stands up the details server
// advertising whatever block signFn returns (nil ⇒ no block). There is no
// anchor: an operator with no verified ephemeral simply has no seal target.
func newEphemeralEnrichFixture(t *testing.T, operatorID uint64, signFn func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement) *ephemeralEnrichFixture {
	t.Helper()
	signingAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var adv *ticket.EphemeralAdvertisement
	if signFn != nil {
		adv = signFn(signingAddr, priv)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/details" {
			http.NotFound(w, r)
			return
		}
		details := inject.OperatorDetails{
			Models: []inject.OperatorDetailsModel{
				{ID: "gpt-test", ContextWindow: 8192},
			},
		}
		if adv != nil {
			details.EphemeralAgePubkey = adv.AgePubkey
			details.EphemeralExpiry = adv.Expiry
			details.EphemeralIssuedAt = adv.IssuedAt
			details.EphemeralSig = adv.Sig
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(details)
	}))
	t.Cleanup(srv.Close)

	return &ephemeralEnrichFixture{
		source: &ChainOperatorSource{
			Details:        NewDetailsClient(srv.Client(), 2*time.Second),
			DetailsTimeout: 2 * time.Second,
			Log:            discardLogger(),
		},
		op: Operator{
			ID:               operatorID,
			NodeID:           testEnrichNodeID,
			BaseURL:          srv.URL,
			SigningAddr:      signingAddr,
			TicketSigningKey: pub,
		},
		signAddr: signingAddr,
		signPriv: priv,
	}
}

func TestEnrich_ValidEphemeralStored(t *testing.T) {
	eph := mustX25519(t)
	ephPubkey := eph.Recipient().String()
	var wantExpiry int64

	f := newEphemeralEnrichFixture(t, 42, func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement {
		wantExpiry = time.Now().Add(10 * time.Minute).Unix()
		adv := signEphemeralAdv(t, signAddr, priv, 42, testEnrichNodeID, ephPubkey, wantExpiry)
		return &adv
	})

	ops := []Operator{f.op}
	f.source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.EphemeralRecipient == nil {
		t.Fatal("valid ephemeral advertisement was not stored on the operator")
	}
	if got.EphemeralRecipientPubkey != ephPubkey {
		t.Errorf("EphemeralRecipientPubkey = %q, want %q", got.EphemeralRecipientPubkey, ephPubkey)
	}
	if got.EphemeralExpiry != wantExpiry {
		t.Errorf("EphemeralExpiry = %d, want %d", got.EphemeralExpiry, wantExpiry)
	}
	if got.EphemeralIssuedAt != wantExpiry-600 {
		t.Errorf("EphemeralIssuedAt = %d, want %d", got.EphemeralIssuedAt, wantExpiry-600)
	}
	rcpt, err := got.SealRecipient(time.Now())
	if err != nil || rcpt.(*age.X25519Recipient).String() != ephPubkey {
		t.Errorf("SealRecipient did not return the stored ephemeral recipient (err=%v)", err)
	}
}

// TestReprobeEphemeral_RefreshesStaleOperator covers the dispatch self-heal
// seam: an operator whose cached snapshot lost its ephemeral (the node was down
// at the last scheduled refresh) is re-probed live, and because the node is back
// up serving a valid advertisement, the returned operator can seal again — no
// waiting for the next refresh cycle.
func TestReprobeEphemeral_RefreshesStaleOperator(t *testing.T) {
	eph := mustX25519(t)
	ephPubkey := eph.Recipient().String()
	f := newEphemeralEnrichFixture(t, 42, func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement {
		adv := signEphemeralAdv(t, signAddr, priv, 42, testEnrichNodeID, ephPubkey, time.Now().Add(10*time.Minute).Unix())
		return &adv
	})

	// Stale: the operator carries no cached ephemeral (node was down last cycle).
	stale := f.op
	if _, err := stale.SealRecipient(time.Now()); !IsNoEphemeral(err) {
		t.Fatalf("precondition: stale op should have no seal target, got err=%v", err)
	}

	got := f.source.ReprobeEphemeral(context.Background(), []Operator{stale}, stale)
	rcpt, err := got.SealRecipient(time.Now())
	if err != nil {
		t.Fatalf("after re-probe, SealRecipient failed: %v", err)
	}
	if rcpt.(*age.X25519Recipient).String() != ephPubkey {
		t.Errorf("re-probe sealed to %q, want freshly advertised %q", rcpt.(*age.X25519Recipient).String(), ephPubkey)
	}
}

// TestReprobeEphemeral_StillDownStaysSealless confirms the self-heal fails
// closed: when the node still isn't serving a valid advertisement, the re-probed
// operator has no seal target and the dispatcher will skip it (→ 503).
func TestReprobeEphemeral_StillDownStaysSealless(t *testing.T) {
	// signFn nil ⇒ the details endpoint advertises no ephemeral block.
	f := newEphemeralEnrichFixture(t, 42, nil)
	stale := f.op
	got := f.source.ReprobeEphemeral(context.Background(), []Operator{stale}, stale)
	if _, err := got.SealRecipient(time.Now()); !IsNoEphemeral(err) {
		t.Fatalf("re-probe of a node with no advertisement must stay sealless, got err=%v", err)
	}
}

func TestEnrich_ForgedEphemeralIgnored(t *testing.T) {
	eph := mustX25519(t)
	f := newEphemeralEnrichFixture(t, 42, func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement {
		adv := signEphemeralAdv(t, signAddr, priv, 42, testEnrichNodeID, eph.Recipient().String(), time.Now().Add(10*time.Minute).Unix())
		// Tamper with the signature so it no longer verifies under the key.
		sig := []byte(adv.Sig)
		sig[len(sig)-1] ^= 0x01
		adv.Sig = string(sig)
		return &adv
	})

	// Pre-seed a stale ephemeral on the operator to prove enrich clears it.
	stale := mustX25519(t)
	f.op.EphemeralRecipient = stale.Recipient()
	f.op.EphemeralRecipientPubkey = stale.Recipient().String()
	f.op.EphemeralExpiry = time.Now().Add(time.Hour).Unix()

	ops := []Operator{f.op}
	f.source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.EphemeralRecipient != nil {
		t.Fatal("forged ephemeral advertisement was trusted (and a stale one not cleared)")
	}
	// No anchor: after a forged advertisement the operator has no seal target.
	if _, err := got.SealRecipient(time.Now()); !IsNoEphemeral(err) {
		t.Errorf("after forged advertisement, SealRecipient must fail closed (errNoEphemeral), got %v", err)
	}
}

func TestEnrich_ExpiredEphemeralIgnoredSilently(t *testing.T) {
	eph := mustX25519(t)
	f := newEphemeralEnrichFixture(t, 42, func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement {
		// Genuine signature, but expired well past the skew tolerance.
		adv := signEphemeralAdv(t, signAddr, priv, 42, testEnrichNodeID, eph.Recipient().String(), time.Now().Add(-10*time.Minute).Unix())
		return &adv
	})

	ops := []Operator{f.op}
	f.source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.EphemeralRecipient != nil {
		t.Fatal("expired ephemeral advertisement was stored; want no seal target")
	}
	if _, err := got.SealRecipient(time.Now()); !IsNoEphemeral(err) {
		t.Errorf("SealRecipient must fail closed after an expired ephemeral, got %v", err)
	}
}

// TestApplyEphemeral_RelayStalenessDownranks confirms the soft relay-staleness
// attribution (SPEC § 3f): a hard-valid but stale block fetched VIA A RELAY is
// still stored (it's decryptable, forward-secret) but records a fault against
// the relay; after steering.RelayDownrankThreshold such blocks the relay is downranked,
// and a single fresh block over the same relay resets the streak.
//
// Critically, each iteration first fires RecordRelayOutcome(relayID, true) — the
// forward-failure-streak credit probeDetailsWithRetry emits on every successful
// forward, immediately before applyEphemeralAdvertisement runs. The staleness
// streak MUST survive that same-cycle credit; if the two shared one streak the
// credit would reset it every cycle and the relay would never downrank.
func TestApplyEphemeral_RelayStalenessDownranks(t *testing.T) {
	signingAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	eph := mustX25519(t)
	now := time.Now()

	signAdv := func(issuedAt, expiry int64) inject.OperatorDetails {
		adv := ticket.EphemeralAdvertisement{AgePubkey: eph.Recipient().String(), Expiry: expiry, IssuedAt: issuedAt}
		// (42, 0) matches the op built below — this test's operator carries no
		// node id, and the binding has to agree with it or every Verify fails.
		if serr := adv.Sign(context.Background(), rawKeyBytesSigner{addr: signingAddr, priv: priv}, signingAddr, 42, 0); serr != nil {
			t.Fatalf("sign advertisement: %v", serr)
		}
		return inject.OperatorDetails{
			EphemeralAgePubkey: adv.AgePubkey,
			EphemeralExpiry:    adv.Expiry,
			EphemeralIssuedAt:  adv.IssuedAt,
			EphemeralSig:       adv.Sig,
		}
	}

	// Hard-valid but stale: issued ~22m ago (older than FreshnessTarget 21m),
	// expiry 10m in the future (unexpired), so lifetime ~32m ≤ MaxEphemeralLifetime.
	staleIssued := now.Add(-(ticket.FreshnessTarget + time.Minute)).Unix()
	staleResp := signAdv(staleIssued, now.Add(10*time.Minute).Unix())

	s := &ChainOperatorSource{Log: discardLogger()}
	op := Operator{ID: 42, SigningAddr: signingAddr, TicketSigningKey: pub}
	const relayID = uint64(99)
	hop := &RelayHop{RelayID: relayID}

	for i := 0; i < steering.RelayDownrankThreshold; i++ {
		// Mirror the real enrich flow: the discovery probe credits this relay's
		// forward-failure streak on every successful forward, immediately before
		// applyEphemeralAdvertisement. The staleness signal must survive it.
		s.RecordRelayOutcome(NodeRef{Op: relayID}, true)
		o := op
		s.applyEphemeralAdvertisement(&o, staleResp, hop, discardLogger())
		if o.EphemeralRecipient == nil {
			t.Fatalf("iteration %d: a stale-but-valid block must still be stored (it is decryptable + forward-secret)", i)
		}
	}
	if !s.RelayDownranked(NodeRef{Op: relayID}) {
		t.Errorf("relay serving only stale ephemerals should be downranked after %d (the probe-success credit must not reset the staleness streak)", steering.RelayDownrankThreshold)
	}

	// A directly-fetched stale block (no relay) must NOT attribute to anyone —
	// an honest current key legitimately ages toward advTTL.
	s2 := &ChainOperatorSource{Log: discardLogger()}
	o2 := op
	for i := 0; i < steering.RelayDownrankThreshold+1; i++ {
		s2.applyEphemeralAdvertisement(&o2, staleResp, nil, discardLogger())
	}
	if s2.RelayDownranked(NodeRef{Op: relayID}) {
		t.Error("a directly-fetched (no relay) stale block must not downrank any relay")
	}

	// A fresh block over the same relay credits it, resetting the streak.
	freshResp := signAdv(now.Unix(), now.Add(25*time.Minute).Unix())
	o3 := op
	s.applyEphemeralAdvertisement(&o3, freshResp, hop, discardLogger())
	if s.RelayDownranked(NodeRef{Op: relayID}) {
		t.Error("a fresh block over the relay must reset the staleness streak")
	}
}

// A genuine signature over a recipient that isn't an age key leaves no seal
// target, clears the one an earlier cycle stored, and says so in the log.
func TestApplyEphemeral_UnparseableRecipientClearsAndWarns(t *testing.T) {
	signingAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	adv := ticket.EphemeralAdvertisement{AgePubkey: "age1notarecipient", Expiry: now.Add(10 * time.Minute).Unix(), IssuedAt: now.Unix()}
	if err := adv.Sign(context.Background(), rawKeyBytesSigner{addr: signingAddr, priv: priv}, signingAddr, 42, 0); err != nil {
		t.Fatal(err)
	}
	resp := inject.OperatorDetails{
		EphemeralAgePubkey: adv.AgePubkey,
		EphemeralExpiry:    adv.Expiry,
		EphemeralIssuedAt:  adv.IssuedAt,
		EphemeralSig:       adv.Sig,
	}
	op := Operator{
		ID: 42, SigningAddr: signingAddr, TicketSigningKey: pub,
		EphemeralRecipient: mustX25519(t).Recipient(), EphemeralRecipientPubkey: "age1earlier", EphemeralExpiry: 1, EphemeralIssuedAt: 1,
	}
	var logs bytes.Buffer
	s := &ChainOperatorSource{}
	s.applyEphemeralAdvertisement(&op, resp, nil, slog.New(slog.NewTextHandler(&logs, nil)))

	if op.EphemeralRecipient != nil || op.EphemeralRecipientPubkey != "" || op.EphemeralExpiry != 0 || op.EphemeralIssuedAt != 0 {
		t.Errorf("an unparseable recipient must leave no seal target, got %+v", op)
	}
	if !strings.Contains(logs.String(), "unparseable ephemeral age recipient") {
		t.Errorf("want the unparseable-recipient warning, got %q", logs.String())
	}
}

func TestEnrich_WrongOperatorIDEphemeralIgnored(t *testing.T) {
	eph := mustX25519(t)
	// op being enriched is id 42, but the block is signed for id 9. Verify
	// binds op.ID=42 before recomputing the digest, so the signature fails —
	// a relay/substitution that re-points a block at op 42 is rejected.
	f := newEphemeralEnrichFixture(t, 42, func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement {
		adv := signEphemeralAdv(t, signAddr, priv, 9, testEnrichNodeID, eph.Recipient().String(), time.Now().Add(10*time.Minute).Unix())
		return &adv
	})

	ops := []Operator{f.op}
	f.source.enrich(context.Background(), ops, nil)

	if ops[0].EphemeralRecipient != nil {
		t.Fatal("ephemeral signed for a different operator id was trusted")
	}
}

// TestEnrich_WrongNodeIDEphemeralIgnored is the sibling-node substitution the
// v3 tag closes: the block is signed by the SAME signing key for the SAME
// operator but a different node id. Under a shared per-operator signing key
// this used to validate — sealing traffic to a key this node cannot decrypt.
func TestEnrich_WrongNodeIDEphemeralIgnored(t *testing.T) {
	eph := mustX25519(t)
	f := newEphemeralEnrichFixture(t, 42, func(signAddr string, priv ed25519.PrivateKey) *ticket.EphemeralAdvertisement {
		adv := signEphemeralAdv(t, signAddr, priv, 42, testEnrichNodeID+1, eph.Recipient().String(), time.Now().Add(10*time.Minute).Unix())
		return &adv
	})

	ops := []Operator{f.op}
	f.source.enrich(context.Background(), ops, nil)

	if ops[0].EphemeralRecipient != nil {
		t.Fatal("ephemeral signed for a sibling node id was trusted")
	}
}

// --- reserve seals to the ephemeral recipient (no anchor, no retry) ---

// TestReserve_SealsToEphemeralRecipient confirms that the reserve body is sealed
// to the operator's ephemeral recipient (the on-chain-only identity cannot open
// it) and the chosen recipient is pinned into the returned ReservedTicket.
func TestReserve_SealsToEphemeralRecipient(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	eph := mustX25519(t)
	other := mustX25519(t) // an unrelated identity that must NOT be able to open

	var openedWithEphemeralOnly bool
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		// Opening with an unrelated identity must fail; opening with the
		// ephemeral must succeed — proving the body was sealed to the ephemeral.
		if _, err := wire.OpenReserveRequest(raw, other); err == nil {
			openedWithEphemeralOnly = false
		} else if _, err := wire.OpenReserveRequest(raw, eph); err == nil {
			openedWithEphemeralOnly = true
		} else {
			t.Errorf("node could not open the sealed reserve with the ephemeral identity")
		}
		plaintext, err := wire.OpenReserveRequest(raw, eph)
		if err != nil {
			t.Fatalf("open sealed reserve: %v", err)
		}
		var rr ticket.ReserveRequest
		if err := json.Unmarshal(plaintext, &rr); err != nil {
			t.Fatalf("unmarshal inner: %v", err)
		}
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})

	op := h.operator
	op.EphemeralRecipient = eph.Recipient()
	op.EphemeralRecipientPubkey = eph.Recipient().String()
	op.EphemeralExpiry = time.Now().Add(10 * time.Minute).Unix()

	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	rt, err := c.Reserve(context.Background(), op, sampleReserveReq(), nil)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if !openedWithEphemeralOnly {
		t.Fatal("reserve body was NOT sealed to the ephemeral recipient")
	}
	if rt.SealRecipient == nil {
		t.Fatal("ReservedTicket.SealRecipient is nil; want the ephemeral recipient pinned")
	}
	if rt.SealRecipient.(*age.X25519Recipient).String() != op.EphemeralRecipientPubkey {
		t.Errorf("pinned SealRecipient = %v, want the ephemeral recipient",
			rt.SealRecipient.(*age.X25519Recipient).String())
	}
}

// TestReserve_NoEphemeralSkips confirms that with NO valid ephemeral, Reserve
// returns errNoEphemeral WITHOUT contacting the node (mandatory forward secrecy,
// no anchor fallback) — the signal the dispatcher uses to skip the candidate.
func TestReserve_NoEphemeralSkips(t *testing.T) {
	var contacted bool
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any contact at all is a failure: Reserve must fail closed BEFORE the
		// reserve POST when no valid ephemeral exists.
		contacted = true
		rr := h.decodeReserve(t, r)
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})

	// Strip the harness's default ephemeral so SealRecipient returns
	// errNoEphemeral (there is no anchor fallback).
	op := h.operator
	op.EphemeralRecipient = nil
	op.EphemeralRecipientPubkey = ""
	op.EphemeralExpiry = 0
	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), op, sampleReserveReq(), nil)
	if !IsNoEphemeral(err) {
		t.Fatalf("Reserve err = %v, want errNoEphemeral (no ephemeral)", err)
	}
	if contacted {
		t.Error("reserve contacted the node despite no valid ephemeral; must fail closed before sending")
	}
	// Must NOT be misclassified as busy/size — those are distinct dispatch paths.
	if IsBusy(err) || IsSize(err) {
		t.Errorf("errNoEphemeral misclassified as busy/size: %v", err)
	}
}

// TestReserve_BadEnvelopeSurfaced confirms that a node which can no longer open
// the ephemeral-sealed body (stale ephemeral after a restart/rotation) returns
// 400 bad_reserve_envelope, and the proxy surfaces it as an error — there is no
// anchor to retry to, so a single attempt is made and the dispatcher moves on.
func TestReserve_BadEnvelopeSurfaced(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	eph := mustX25519(t)

	var attempts int
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// The node no longer holds the ephemeral key, so it cannot open a body
		// sealed to it → 400 bad_reserve_envelope, mirroring node handleReserve.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"failed to open sealed reserve request","type":"invalid_request_error","code":"bad_reserve_envelope"}}`))
	})

	op := h.operator
	op.EphemeralRecipient = eph.Recipient() // node no longer holds this
	op.EphemeralRecipientPubkey = eph.Recipient().String()
	op.EphemeralExpiry = time.Now().Add(10 * time.Minute).Unix()

	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	_, err := c.Reserve(context.Background(), op, sampleReserveReq(), nil)
	if err == nil {
		t.Fatal("ephemeral-sealed bad_reserve_envelope must surface as an error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want exactly 1 (no retry-to-anchor — the anchor is gone)", attempts)
	}
	if IsBusy(err) || IsSize(err) {
		t.Errorf("err misclassified as busy/size: %v", err)
	}
}

// TestReserve_DispatchSharesPinnedRecipient is the reserve-half of the
// reserve↔dispatch affinity: the recipient Reserve pins is exactly the one a
// fresh op.SealRecipient(now) chose, so dispatch (which seals to
// rt.SealRecipient) and reserve agree even if op.SealRecipient is re-evaluated
// later.
func TestReserve_DispatchSharesPinnedRecipient(t *testing.T) {
	h := newReserveHarness(t, func(w http.ResponseWriter, r *http.Request) {})
	eph := mustX25519(t)
	other := mustX25519(t)
	h.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		plaintext, err := wire.OpenReserveRequest(raw, eph)
		if err != nil {
			t.Fatalf("open sealed reserve: %v", err)
		}
		var rr ticket.ReserveRequest
		if err := json.Unmarshal(plaintext, &rr); err != nil {
			t.Fatalf("unmarshal inner: %v", err)
		}
		resp := h.issueValidTicket(t, rr)
		writeSealedReserve(t, w, resp, rr.ProxyRecipient)
	})

	op := h.operator
	op.EphemeralRecipient = eph.Recipient()
	op.EphemeralRecipientPubkey = eph.Recipient().String()
	op.EphemeralExpiry = time.Now().Add(10 * time.Minute).Unix()

	c := &HTTPReserveClient{HTTPClient: http.DefaultClient}
	rt, err := c.Reserve(context.Background(), op, sampleReserveReq(), nil)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	// What dispatch would seal to (rt.SealRecipient) must equal what
	// SealRecipient chooses for this operator — the same ephemeral recipient.
	want, werr := op.SealRecipient(time.Now())
	if werr != nil {
		t.Fatalf("SealRecipient: %v", werr)
	}
	if rt.SealRecipient != want {
		t.Errorf("dispatch pin %v != SealRecipient choice %v", rt.SealRecipient, want)
	}
	// Sanity: the pinned recipient really seals to the ephemeral key, not some
	// unrelated identity.
	sealed, err := wire.SealReserveRequest([]byte(`{"x":1}`), rt.SealRecipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.OpenReserveRequest(sealed, eph); err != nil {
		t.Errorf("pinned recipient does not open with the ephemeral identity: %v", err)
	}
	if _, err := wire.OpenReserveRequest(sealed, other); err == nil {
		t.Errorf("pinned recipient unexpectedly opens with an unrelated identity")
	}
}
