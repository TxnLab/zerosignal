/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// fakeRelayRep is an injectable RelayReputation that records reported outcomes
// and answers a fixed downrank set, so tests can observe attribution and drive
// relayHopFor's preference deterministically.
type uuCall struct{ relay, target hayai.NodeRef }

type fakeRelayRep struct {
	mu              sync.Mutex
	outcomes        map[hayai.NodeRef][]bool
	downranked      map[hayai.NodeRef]bool
	upstreamUnreach []uuCall
	forwardedFault  []uuCall
	forwardTimeout  []uuCall
}

func newFakeRelayRep() *fakeRelayRep {
	return &fakeRelayRep{outcomes: map[hayai.NodeRef][]bool{}, downranked: map[hayai.NodeRef]bool{}}
}

func (f *fakeRelayRep) RecordRelayOutcome(relay hayai.NodeRef, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcomes[relay] = append(f.outcomes[relay], ok)
}

// RecordRelayUpstreamUnreachable records the differential path's calls so the
// classify test can assert relay_upstream_unreachable is routed here (and NOT
// to RecordRelayOutcome). The real differential decision (target reachable →
// penalize, else credit) is exercised against ChainOperatorSource in
// proto/go/zs/relay_reputation_test.go.
func (f *fakeRelayRep) RecordRelayUpstreamUnreachable(relay, target hayai.NodeRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upstreamUnreach = append(f.upstreamUnreach, uuCall{relay, target})
}

// RecordRelayForwardedTargetFault records the PENALTY-ONLY differential (a
// marked code-less status) separately from the claim-validating one, so a test
// can assert which of the two a given response took.
func (f *fakeRelayRep) RecordRelayForwardedTargetFault(relay, target hayai.NodeRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forwardedFault = append(f.forwardedFault, uuCall{relay, target})
}

// RecordRelayForwardTimeout records the unattributed-timeout streak's calls
// separately from both differentials, so a test can assert that a gateway
// timeout takes THIS path and specifically not RecordRelayOutcome — the
// distinction the whole third streak exists for. The real differential decision
// (target reachable → penalize, else nothing) is exercised against
// ChainOperatorSource in proto/go/zs/relay_reputation_test.go.
func (f *fakeRelayRep) RecordRelayForwardTimeout(relay, target hayai.NodeRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forwardTimeout = append(f.forwardTimeout, uuCall{relay, target})
}

// RecordRelayStaleEphemeral / RecordRelayFreshEphemeral satisfy the interface.
// They're discovery-path signals (driven from the fetcher's enrich pass, tested
// against the real ChainOperatorSource in proto/go/zs); the dispatch-path
// tests that use this fake never call them, so they're no-ops here.
func (f *fakeRelayRep) RecordRelayStaleEphemeral(relay hayai.NodeRef) {}
func (f *fakeRelayRep) RecordRelayFreshEphemeral(relay hayai.NodeRef) {}

func (f *fakeRelayRep) RelayDownranked(relay hayai.NodeRef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.downranked[relay]
}

func (f *fakeRelayRep) last(relay hayai.NodeRef) (bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.outcomes[relay]
	if len(o) == 0 {
		return false, false
	}
	return o[len(o)-1], true
}

func relayRepServer(t *testing.T, privacy bool, ops []hayai.Operator, rep hayai.RelayReputation) *Server {
	t.Helper()
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	return &Server{client: &client{
		cfg:              &Config{Privacy: privacyMode(privacy), Affinity: hayai.AffinityNone},
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		registryProvider: registry,
		relayRep:         rep,
	}, mux: http.NewServeMux()}
}

func relayOp(id uint64, owner, baseURL string) hayai.Operator {
	return hayai.Operator{
		ID:           id,
		OwnerAddr:    owner,
		BaseURL:      baseURL,
		ProtoVersion: wire.ProtoVersion, // version-compatible relay candidate
		Reachable:    true,
		Models:       []string{"gpt-test"},
	}
}

// markedHeader is a response header set carrying the relay's hop marker — i.e.
// "this relay's handler ran and produced or forwarded this response".
func markedHeader() http.Header {
	h := http.Header{}
	h.Set(wire.RelayHopHeader, wire.RelayHopHeaderValue)
	return h
}

func TestAttributeRelayHop(t *testing.T) {
	// No advertised version ⇒ SetsRelayHopHeader is false ⇒ this hop is
	// treated as pre-9.1, so a missing marker proves nothing about it. That is
	// what keeps every case below on the historical behavior; the marker rules
	// get their own cases via relayProtoVersion.
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}

	cases := []struct {
		name       string
		status     int
		body       string
		header     http.Header
		relayVer   string
		wantOK     bool // expected recorded outcome
		wantRecord bool
	}{
		{"relay_busy hop error → relay down", http.StatusServiceUnavailable,
			`{"error":{"code":"` + protorelay.CodeBusy + `"}}`, nil, "", false, true},
		{"relay_unknown_target hop error → relay down", http.StatusNotFound,
			`{"error":{"code":"` + protorelay.CodeUnknownTarget + `"}}`, nil, "", false, true},
		// The entry guard is `>= 400`, not `> 400`, and three of the seven hop
		// codes live at exactly 400 (relay_bad_target / _bad_path / _bad_method).
		// Without a coded-400 row the boundary is invisible: every other 400 case
		// below expects a CREDIT, which is also what skipping the classify block
		// entirely would produce — so a relay refusing every forward with
		// relay_bad_target would keep a spotless streak and no test would notice.
		{"relay_bad_target hop error at exactly 400 → relay down", http.StatusBadRequest,
			`{"error":{"code":"` + protorelay.CodeBadTarget + `"}}`, nil, "", false, true},
		// relay_upstream_unreachable does NOT go through RecordRelayOutcome — it
		// takes the differential RecordRelayUpstreamUnreachable path, covered by
		// TestAttributeRelayHop_UpstreamUnreachableDifferential below.
		{"target's own error forwarded verbatim → relay up", http.StatusBadRequest,
			`{"error":{"code":"context_length_exceeded"}}`, nil, "", true, true},
		{"sealed 2xx response (non-JSON-error) → relay up", http.StatusOK,
			`{"nonce":"x","ciphertext":"y"}`, nil, "", true, true},
		// Unattributable infrastructure from a PRE-9.1 relay: a transient status
		// carrying no protocol code came from a CDN / ingress / LB, and neither
		// the response nor the relay's generation can say whose. Attributing
		// ANYTHING is a guess; crediting (the old behavior) was the harmful
		// guess, because it let a relay behind a broken gateway keep a spotless
		// streak while dropping every forward it was handed.
		//
		// wantRecord is about RecordRelayOutcome specifically. The timeout rows
		// below also feed the separate, non-attributing forward-timeout streak —
		// asserted in TestAttributeRelayHop_ForwardTimeoutStreak, and deliberately
		// NOT here, so this table keeps testing attribution alone.
		{"HTML 504 from an intermediary → no outcome", http.StatusGatewayTimeout,
			`<html><body>504 Gateway Time-out</body></html>`, nil, "", false, false},
		{"bare 502 with no error code → no record", http.StatusBadGateway, ``, nil, "", false, false},
		{"bare 503 with no error code → no record", http.StatusServiceUnavailable,
			`{"message":"upstream unavailable"}`, nil, "", false, false},
		{"Cloudflare 522 origin timeout → no record", 522, `error code: 522`, nil, "", false, false},
		// A code-less 4xx is a genuine refusal that reached us, not gateway
		// weather — the relay delivered it, so it still earns its credit.
		{"bare 400 with no error code → relay up", http.StatusBadRequest, ``, nil, "", true, true},

		// --- 9.1 hop-marker rules ---
		// The fix: a relay that advertises the marker and didn't stamp it never
		// ran its handler, so its own front door ate the request.
		{"bare 502 (could-not-connect), marking relay, no marker → relay down", http.StatusBadGateway,
			`<html>502</html>`, nil, "9.1", false, true},
		// A gateway TIMEOUT is not proof: the relay is byte-silent for the whole
		// forward window, so it may simply have been waiting on a slow target.
		{"bare 504 (gateway timeout), marking relay, no marker → no outcome", http.StatusGatewayTimeout,
			`<html>504</html>`, nil, "9.1", false, false},
		{"Cloudflare 522, marking relay, no marker → relay down", 522,
			`error code: 522`, nil, "9.1", false, true},
		// A MARKED code-less 5xx is the relay's claim about the target, so it
		// leaves RecordRelayOutcome entirely for the differential path (asserted
		// in TestAttributeRelayHop_MarkedCodelessTakesDifferential).
		{"bare 504, marking relay, marker present → differential, not an outcome",
			http.StatusGatewayTimeout, `<html>504</html>`, markedHeader(), "9.1", false, false},
		// The version gate, from the other side: an un-upgraded relay owes no
		// header, so its absence must stay evidence-free. Getting this backwards
		// would charge the entire current fleet.
		{"bare 502, pre-9.1 relay, no marker → still no record", http.StatusBadGateway,
			`<html>502</html>`, nil, "9.0", false, false},
		// A recognized code outranks the marker in both directions — Classify
		// attributes before NarrowRelayed ever runs.
		{"relay_busy with a marker present → still relay down", http.StatusServiceUnavailable,
			`{"error":{"code":"` + protorelay.CodeBusy + `"}}`, markedHeader(), "9.1", false, true},
		{"target code with no marker from a marking relay → still relay up",
			http.StatusBadRequest, `{"error":{"code":"context_length_exceeded"}}`, nil, "9.1", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := newFakeRelayRep()
			s := relayRepServer(t, true, nil, rep)
			h := tc.header
			if h == nil {
				h = http.Header{}
			}
			hopFor := *hop
			hopFor.RelayProtoVersion = tc.relayVer
			s.attributeRelayHop(context.Background(), &hopFor, tc.status, h, []byte(tc.body))
			got, ok := rep.last(hop.RelayRef())
			if ok != tc.wantRecord {
				t.Fatalf("recorded=%v, want %v", ok, tc.wantRecord)
			}
			if ok && got != tc.wantOK {
				t.Errorf("outcome = %v, want %v", got, tc.wantOK)
			}
		})
	}
}

// A MARKED code-less transient status is the relay saying "I forwarded, and
// this is what the target gave me" — the same shape of claim as
// relay_upstream_unreachable. It must therefore take the same DIFFERENTIAL
// path, not a straight target strike: believing a relay's word about a target
// at face value is exactly what RecordRelayUpstreamUnreachable exists to avoid.
func TestAttributeRelayHop_MarkedCodelessTakesDifferential(t *testing.T) {
	hop := &hayai.RelayHop{
		RelayID: 5, TargetID: 9, BaseURL: "http://relay.example", RelayProtoVersion: "9.1",
	}
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)

	s.attributeRelayHop(context.Background(), hop, http.StatusGatewayTimeout, markedHeader(),
		[]byte(`<html><body>504 Gateway Time-out</body></html>`))

	if _, recorded := rep.last(hop.RelayRef()); recorded {
		t.Error("marked code-less 504 went through RecordRelayOutcome; want a differential path")
	}
	// It must take the PENALTY-ONLY differential, not the claim-validating one.
	// The relay asserted nothing beyond "my handler ran", so it has not earned
	// the credit RecordRelayUpstreamUnreachable can hand out — and that credit
	// would wipe its whole streak on any target restart.
	if len(rep.upstreamUnreach) != 0 {
		t.Errorf("took the claim-validating differential (%d calls); a marker is not a claim", len(rep.upstreamUnreach))
	}
	if len(rep.forwardedFault) != 1 {
		t.Fatalf("RecordRelayForwardedTargetFault calls = %d, want 1", len(rep.forwardedFault))
	}
	if got := rep.forwardedFault[0]; got.relay != hop.RelayRef() || got.target != hop.TargetRef() {
		t.Errorf("differential call = %+v, want {relay:%+v target:%+v}", got, hop.RelayRef(), hop.TargetRef())
	}
}

// TestAttributeRelayHop_UpstreamUnreachableDifferential: a 4xx/5xx
// carrying relay_upstream_unreachable is routed to the differential
// RecordRelayUpstreamUnreachable (with the hop's target id) rather than being
// unconditionally credited via RecordRelayOutcome — so a fork can't dodge the
// streak by always blaming the target.
func TestAttributeRelayHop_UpstreamUnreachableDifferential(t *testing.T) {
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)

	s.attributeRelayHop(context.Background(), hop, http.StatusBadGateway, http.Header{},
		[]byte(`{"error":{"code":"`+protorelay.CodeUpstreamUnreachable+`"}}`))

	if _, recorded := rep.last(hop.RelayRef()); recorded {
		t.Error("upstream_unreachable went through RecordRelayOutcome; want the differential path")
	}
	if len(rep.upstreamUnreach) != 1 {
		t.Fatalf("RecordRelayUpstreamUnreachable calls = %d, want 1", len(rep.upstreamUnreach))
	}
	if got := rep.upstreamUnreach[0]; got.relay != hop.RelayRef() || got.target != hop.TargetRef() {
		t.Errorf("differential call = %+v, want {relay:%+v target:%+v}", got, hop.RelayRef(), hop.TargetRef())
	}
}

func TestAttributeRelayHop_NilHopNoop(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	// Direct route (nil hop): never touches the reputation store.
	s.attributeRelayHop(context.Background(), nil, http.StatusServiceUnavailable, http.Header{}, []byte(`{"error":{"code":"relay_busy"}}`))
	// Same for a transport failure with no response at all, cancelled or not —
	// direct mode has no relay to charge and the target's own backoff owns it.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s.attributeRelayHop(cancelled, nil, transient.TransportFailureStatus, nil, nil)
	s.attributeRelayHop(context.Background(), nil, transient.TransportFailureStatus, nil, nil)
	s.attributeRelayHop(context.Background(), nil, http.StatusGatewayTimeout, http.Header{}, nil)
	s.recordRelayOutcome(nil, false)
	if len(rep.outcomes) != 0 {
		t.Errorf("nil hop recorded outcomes: %v", rep.outcomes)
	}
	if len(rep.forwardTimeout) != 0 {
		t.Errorf("nil hop recorded forward timeouts: %v", rep.forwardTimeout)
	}
}

// TestAttributeRelayHop_ForwardTimeoutStreak covers the one slice of AttrUnknown
// that is remembered. It is not an attribution — nothing here may reach
// RecordRelayOutcome — but a gateway timeout that costs the relay literally
// nothing is what makes a CDN-fronted relay a permanent trap: it keeps a
// spotless streak while killing every byte-silent (non-streaming) forward, so
// routing keeps handing it more.
//
// Each negative case below is a DIFFERENT reason not to record, and collapsing
// any of them into "don't record timeouts" would pass the others.
func TestAttributeRelayHop_ForwardTimeoutStreak(t *testing.T) {
	relayVer := "9.1"
	cases := []struct {
		name     string
		status   int
		body     string
		header   http.Header
		relayVer string
		aborted  bool
		want     bool
	}{
		{"504 from a pre-9.1 relay's gateway", http.StatusGatewayTimeout,
			`<html>504</html>`, nil, "", false, true},
		{"504 from a marking relay that never stamped", http.StatusGatewayTimeout,
			`<html>504</html>`, nil, relayVer, false, true},
		{"408 request timeout", http.StatusRequestTimeout, ``, nil, "", false, true},
		{"Cloudflare 524 origin timeout", 524, `error code: 524`, nil, "", false, true},

		// Already attributed to the relay by NarrowRelayed rule 4 — recording a
		// timeout too would charge the same failure twice, on two streaks with
		// two thresholds.
		{"502 could-not-connect from a marking relay → AttrRelay, not a timeout",
			http.StatusBadGateway, `<html>502</html>`, nil, relayVer, false, false},
		{"Cloudflare 522 → AttrRelay, not a timeout", 522, `error code: 522`, nil, relayVer, false, false},
		// A MARKED 504 is the relay's claim about its target, which is the
		// forwarded-fault differential's business, not this streak's.
		{"marked 504 → target differential, not a timeout", http.StatusGatewayTimeout,
			`<html>504</html>`, markedHeader(), relayVer, false, false},
		// We tore the socket down ourselves. Charging here is the same mistake
		// NarrowRelayed rule 2 exists to prevent, one layer up.
		{"504 while the caller aborted → nothing", http.StatusGatewayTimeout,
			`<html>504</html>`, nil, relayVer, true, false},
		// Rule 3 already says AttrRelay: no response arrived and the socket was
		// the relay's, so this is proof, not a timeout inference.
		{"transport failure → AttrRelay, not a timeout", transient.TransportFailureStatus,
			``, nil, relayVer, false, false},
		// A coded answer names its own hop; nothing is unattributed to infer from.
		{"504 carrying a target error code → not a timeout", http.StatusGatewayTimeout,
			`{"error":{"code":"context_length_exceeded"}}`, nil, relayVer, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := newFakeRelayRep()
			s := relayRepServer(t, true, nil, rep)
			hop := &hayai.RelayHop{
				RelayID: 5, TargetID: 9, BaseURL: "http://relay.example",
				RelayProtoVersion: tc.relayVer,
			}
			ctx := context.Background()
			if tc.aborted {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			h := tc.header
			if h == nil {
				h = http.Header{}
			}
			s.attributeRelayHop(ctx, hop, tc.status, h, []byte(tc.body))

			// `!= 0`, not `== 1`: on a want=false row the exact-1 form is green at
			// zero AND at two-or-more, so it could not see the double-record this
			// table exists to rule out (a status charged to both this streak and
			// the failure streak). The exact count is asserted in the want arm.
			if got := len(rep.forwardTimeout) != 0; got != tc.want {
				t.Fatalf("RecordRelayForwardTimeout calls = %d, want recorded=%v",
					len(rep.forwardTimeout), tc.want)
			}
			if tc.want {
				if got := rep.forwardTimeout[0]; got.relay != hop.RelayRef() || got.target != hop.TargetRef() {
					t.Errorf("timeout call = %+v, want {relay:%+v target:%+v}",
						got, hop.RelayRef(), hop.TargetRef())
				}
				// The streak must stay out of the attribution channel entirely,
				// in BOTH directions: a penalty would double-charge, and a credit
				// would be the spotless-streak bug this fixes.
				if _, recorded := rep.last(hop.RelayRef()); recorded {
					t.Error("a forward timeout also reached RecordRelayOutcome; it must attribute nothing")
				}
			}
		})
	}
}

func TestRecordRelayOutcome_TransportFailure(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	hop := &hayai.RelayHop{RelayID: 11, TargetID: 9, BaseURL: "http://relay.example"}
	s.recordRelayOutcome(hop, false)
	got, ok := rep.last(hop.RelayRef())
	if !ok || got != false {
		t.Fatalf("transport failure recorded = (%v,%v), want (false,true)", got, ok)
	}
}

// A transport failure through a relay charges that relay: we opened the RELAY's
// socket, so nothing about which hop failed to answer is ambiguous. This is the
// floor the caller-abort rule below must not sink through — "never charge on a
// transport failure" would pass that test and lose the only signal that reaches
// an entirely un-upgraded fleet.
func TestAttributeRelayHop_TransportFailureChargesRelay(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}

	s.attributeRelayHop(context.Background(), hop, transient.TransportFailureStatus, nil, nil)

	got, ok := rep.last(hop.RelayRef())
	if !ok {
		t.Fatal("a transport failure through a relay recorded nothing")
	}
	if got {
		t.Error("a transport failure credited the relay")
	}
	if n := len(rep.outcomes[hop.RelayRef()]); n != 1 {
		t.Errorf("recorded %d outcomes, want 1", n)
	}
}

// The payer hanging up mid-generation surfaces as the same
// TransportFailureStatus as a dial failure to a dead relay. The non-streaming
// forward rides the payer's own r.Context() and blocks for the whole
// generation, so this is reachable on every buffered request — and charging
// there benches a healthy relay for a socket the proxy tore down itself. The
// inference-leg twin of
// TestReserveWithTransientRetry_CallerCancellationChargesNoRelay.
func TestAttributeRelayHop_CallerAbortChargesNoRelay(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.attributeRelayHop(ctx, hop, transient.TransportFailureStatus, nil, nil)

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v for a caller-cancelled forward; we tore the socket down, "+
			"not the relay", rep.outcomes)
	}
	if len(rep.upstreamUnreach) != 0 || len(rep.forwardedFault) != 0 {
		t.Errorf("caller abort took a differential path: upstreamUnreach=%v forwardedFault=%v",
			rep.upstreamUnreach, rep.forwardedFault)
	}
}

// A deadline the caller set on itself is as much our own doing as a cancel —
// the docblock's predicate is ctx.Err() != nil, and the TS twin
// (init.signal?.aborted) makes no distinction either. Pinned separately because
// every other abort test drives context.WithCancel, so narrowing the predicate
// to context.Canceled would leave the whole suite green while a payer request
// carrying its own deadline went on charging relays.
func TestAttributeRelayHop_CallerDeadlineChargesNoRelay(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done() // expired, not cancelled: ctx.Err() is context.DeadlineExceeded

	s.attributeRelayHop(ctx, hop, transient.TransportFailureStatus, nil, nil)

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v for a forward our own deadline ended", rep.outcomes)
	}
}

// relayEvidence's nil-context guard is defensive — every production caller
// threads a real context — so nothing else would catch its removal until a
// future caller panicked on the reputation path.
func TestRelayEvidence_NilContextIsNotAnAbort(t *testing.T) {
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}
	// Held in a variable rather than written as a literal nil argument: the
	// point is a caller that forgot to thread one, and staticcheck rightly
	// rejects the literal form (SA1012).
	var missing context.Context
	if got := relayEvidence(missing, hop, nil); got.CallerAborted {
		t.Errorf("nil context read as a caller abort: %+v", got)
	}
}

// The abort rule is about OUR context, not the far end's answer: a real
// response that arrived while the payer was hanging up still says whatever it
// says about the route, but NarrowRelayed refuses to charge anyone off it.
// Asserting the marker case specifically, because it is the one that would
// otherwise charge a relay on evidence a cancelled request makes worthless.
func TestAttributeRelayHop_CallerAbortSuppressesMarkerCharge(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example", RelayProtoVersion: "9.1"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Unmarked code-less 502 from a marking relay: charged as a front-door fault
	// under a live context (TestAttributeRelayHop's 9.1 rows).
	s.attributeRelayHop(ctx, hop, http.StatusBadGateway, http.Header{}, []byte(`<html>502</html>`))

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v for a response that arrived after the caller hung up", rep.outcomes)
	}
}

// The credit branch must never be reachable without a response. Classify
// answers AttrNone for any recognized error code, so a body carrying one at
// TransportFailureStatus walks straight past the three attributed cases — and
// without the structural guard lands on RecordRelayOutcome(true), crediting a
// relay we never reached. The real seams pass a nil body, which is exactly why
// this needs pinning: nothing else would notice the guard being dropped.
func TestAttributeRelayHop_TransportFailureNeverCredits(t *testing.T) {
	rep := newFakeRelayRep()
	s := relayRepServer(t, true, nil, rep)
	hop := &hayai.RelayHop{RelayID: 5, TargetID: 9, BaseURL: "http://relay.example"}

	s.attributeRelayHop(context.Background(), hop, transient.TransportFailureStatus, nil,
		[]byte(`{"error":{"code":"context_length_exceeded"}}`))

	for ref, outcomes := range rep.outcomes {
		for _, ok := range outcomes {
			if ok {
				t.Fatalf("relay %+v credited for a forward that never produced a response", ref)
			}
		}
	}
}

// TestRelayHopFor_DownrankPrefersHealthyRelay: with a healthy relay and a
// downranked relay both eligible for the target, relayHopFor consistently
// picks the healthy one — the downranked relay dropped to the fallback tier.
func TestRelayHopFor_DownrankPrefersHealthyRelay(t *testing.T) {
	rep := newFakeRelayRep()
	rep.downranked[hayai.NodeRef{Op: 3}] = true // relay 3 is the bad forwarder
	ops := []hayai.Operator{
		relayOp(1, "OWNER_TARGET", "http://target.example"),
		relayOp(2, "OWNER_GOOD", "http://good-relay.example"),
		relayOp(3, "OWNER_BAD", "http://bad-relay.example"),
	}
	s := relayRepServer(t, true, ops, rep)
	target := ops[0]

	// The preferred tier holds only relay 2 (relay 3 is downranked → fallback),
	// so the random seed can't pick relay 3. Repeat to defeat the random seed.
	for i := 0; i < 50; i++ {
		hop, err := s.relayHopFor(context.Background(), target, true)
		if err != nil {
			t.Fatalf("relayHopFor: %v", err)
		}
		if hop.RelayID != 2 {
			t.Fatalf("picked relay %d, want the healthy relay 2 (downranked 3 should be deprioritized)", hop.RelayID)
		}
	}
}

// TestRelayHopFor_DownrankNeverHardExcludes: when the ONLY eligible relay is
// downranked, relayHopFor still returns it (soft preference + cold-start
// fallback) rather than failing with ErrNoRelay.
func TestRelayHopFor_DownrankNeverHardExcludes(t *testing.T) {
	rep := newFakeRelayRep()
	rep.downranked[hayai.NodeRef{Op: 2}] = true
	ops := []hayai.Operator{
		relayOp(1, "OWNER_TARGET", "http://target.example"),
		relayOp(2, "OWNER_ONLY", "http://only-relay.example"),
	}
	s := relayRepServer(t, true, ops, rep)
	target := ops[0]

	hop, err := s.relayHopFor(context.Background(), target, true)
	if err != nil {
		t.Fatalf("relayHopFor returned error for a downranked-but-only relay: %v (must fall back, never hard-exclude)", err)
	}
	if hop == nil || hop.RelayID != 2 {
		t.Fatalf("expected fallback to the only relay (2), got %+v", hop)
	}
}

// TestRelayHopFor_PrivacyOff: with the per-request privacy decision off,
// relayHopFor is a no-op (nil hop) regardless of reputation — direct routing.
// usePrivacy is now an explicit parameter (resolved in dispatchHayai from
// config + provider.relay / X-Zs-Relay), not read from config here.
func TestRelayHopFor_PrivacyOff(t *testing.T) {
	ops := []hayai.Operator{
		relayOp(1, "OWNER_TARGET", "http://target.example"),
		relayOp(2, "OWNER_GOOD", "http://good-relay.example"),
	}
	s := relayRepServer(t, true, ops, newFakeRelayRep())
	hop, err := s.relayHopFor(context.Background(), ops[0], false)
	if err != nil || hop != nil {
		t.Fatalf("privacy off: relayHopFor = (%v, %v), want (nil, nil)", hop, err)
	}
}
