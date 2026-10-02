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
	"reflect"
	"sync"
	"testing"
	"time"

	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	prototokenize "github.com/TxnLab/zerosignal/go/tokenize"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// scriptedReserveClient replays a fixed sequence of Reserve outcomes and records
// which relay hop carried each call — the assertion that matters for rotation.
type scriptedReserveClient struct {
	mu      sync.Mutex
	script  []error // one entry per call; nil means success
	callIdx int
	hops    []*hayai.RelayHop       // hop used per call, in order
	ops     []hayai.Operator        // operator used per call, in order
	reqs    []ticket.ReserveRequest // request sent per call, in order
}

func (c *scriptedReserveClient) Reserve(_ context.Context, op hayai.Operator, req ticket.ReserveRequest, hop *hayai.RelayHop) (*hayai.ReservedTicket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hops = append(c.hops, hop)
	c.ops = append(c.ops, op)
	c.reqs = append(c.reqs, req)
	var err error
	if c.callIdx < len(c.script) {
		err = c.script[c.callIdx]
	} else if len(c.script) > 0 {
		// Past the end, keep replaying the last outcome so a test can say
		// "always fails" with a single entry.
		err = c.script[len(c.script)-1]
	}
	c.callIdx++
	if err != nil {
		return nil, err
	}
	return &hayai.ReservedTicket{}, nil
}

func (c *scriptedReserveClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callIdx
}

func (c *scriptedReserveClient) hopAt(i int) *hayai.RelayHop {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.hops) {
		return nil
	}
	return c.hops[i]
}

// gatewayErr is the failure this whole mechanism exists for: a transient status
// with an HTML body, so there is no protocol error code to read.
func gatewayErr(status int) error {
	return &hayai.ReserveHTTPError{Status: status, Message: "<html>gateway error</html>"}
}

func retryServer(t *testing.T, privacy bool, rc hayai.ReserveClient, ops []hayai.Operator) *Server {
	t.Helper()
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	return &Server{
		cfg:              &Config{Privacy: privacyMode(privacy), Affinity: hayai.AffinityNone},
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		mux:              http.NewServeMux(),
		registryProvider: registry,
		reserveClient:    rc,
	}
}

// retryOp builds a reachable, version-compatible operator. Distinct owners
// matter: relay eligibility requires the relay's owner to differ from the
// target's, so same-owner nodes are not eligible hops for each other.
func retryOp(id uint64, owner string) hayai.Operator {
	return hayai.Operator{
		ID:           id,
		NodeID:       1,
		OwnerAddr:    owner,
		BaseURL:      "http://op.example",
		ProtoVersion: wire.ProtoVersion,
		Reachable:    true,
		Models:       []string{"gpt-test"},
	}
}

// retryOpAtVersion is retryOp pinned to a specific advertised proto_version, so
// a test can put the relay pool on either side of wire.RelayHopHeaderMinVersion.
// Pre-floor relays are the un-upgraded fleet: the marker rule can say nothing
// about them, so they are what exercises the rotation differential.
func retryOpAtVersion(id uint64, owner, protoVersion string) hayai.Operator {
	op := retryOp(id, owner)
	op.ProtoVersion = protoVersion
	return op
}

func selOf(ops ...hayai.Operator) []selection.Operator {
	out := make([]selection.Operator, len(ops))
	for i, op := range ops {
		out[i] = op.Selection()
	}
	return out
}

// markedGatewayErr is a code-less transient status that DID carry the relay's
// hop marker — the relay ran and copied the target's status back.
func markedGatewayErr(status int) error {
	return &hayai.ReserveHTTPError{
		Status: status, Message: "<html>gateway error</html>", RelayHopMarked: true,
	}
}

// transportErr is a failure that produced no HTTP response at all. In relayed
// mode the socket we opened was the relay's, so this is unambiguously a relay
// fault regardless of what generation it advertises.
func transportErr() error {
	return &hayai.ReserveHTTPError{
		Status: transient.TransportFailureStatus, Message: "dial tcp: connection refused",
	}
}

// retryServerWithRep is retryServer plus an observable relay-reputation store,
// for the tests that assert WHO got charged rather than just how many attempts
// ran.
func retryServerWithRep(t *testing.T, rc hayai.ReserveClient, ops []hayai.Operator) (*Server, *fakeRelayRep) {
	t.Helper()
	s := retryServer(t, true, rc, ops)
	rep := newFakeRelayRep()
	s.relayRep = rep
	return s, rep
}

// The core fix: a gateway 5xx retries through a DIFFERENT relay, and succeeding
// there means the caller never sees an error. Rotation is what rescues the
// single-candidate case, where there is no other operator to fail over to.
func TestReserveWithTransientRetry_RotatesRelayAndSucceeds(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	relayA := retryOp(2, "OWNER-A")
	relayB := retryOp(3, "OWNER-B")

	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout), nil}}
	s := retryServer(t, true, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}

	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)

	if got.Err != nil {
		t.Fatalf("reserve err = %v, want success on the second attempt", got.Err)
	}
	if rc.calls() != 2 {
		t.Fatalf("reserve calls = %d, want 2 (one failure, one rotated retry)", rc.calls())
	}
	first, second := rc.hopAt(0), rc.hopAt(1)
	if first == nil || second == nil {
		t.Fatal("both attempts should have carried a relay hop under privacy mode")
	}
	if first.RelayRef() == second.RelayRef() {
		t.Errorf("retry reused relay %+v; rotation must pick a different one", first.RelayRef())
	}
	if got.Hop == nil || got.Hop.RelayRef() != second.RelayRef() {
		t.Error("returned Hop must be the one that succeeded — the caller seals the inference to it")
	}
}

// The rotation differential, and the reason it must exist alongside the hop
// marker: for a PRE-9.1 relay the marker rule can say nothing, so blame has to
// come from somewhere else. Relay A answers a code-less 504; a rotation to
// relay B reaches the SAME target successfully; therefore the target was up and
// A's failure was A's own. This is the mechanism the relay-attribution docblock
// claimed existed and did not.
func TestReserveWithTransientRetry_RotationDifferentialBlamesFailedRelay(t *testing.T) {
	const preFloor = "9.0"
	target := retryOpAtVersion(1, "OWNER-TARGET", preFloor)
	relayA := retryOpAtVersion(2, "OWNER-A", preFloor)
	relayB := retryOpAtVersion(3, "OWNER-B", preFloor)

	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout), nil}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)
	if got.Err != nil {
		t.Fatalf("reserve err = %v, want success on the rotated attempt", got.Err)
	}

	failed, succeeded := rc.hopAt(0), rc.hopAt(1)
	outcome, recorded := rep.last(failed.RelayRef())
	if !recorded {
		t.Fatal("the relay that answered the code-less 504 was never charged, " +
			"even though a rotation proved the target was up")
	}
	if outcome {
		t.Error("failed relay was CREDITED; the differential must charge it")
	}
	// Strictly one-sided: the reserve leg never credits, because a success here
	// would clear the streak the inference forward is the authoritative signal for.
	if _, credited := rep.last(succeeded.RelayRef()); credited {
		t.Error("the succeeding relay was recorded; the reserve leg must never credit")
	}
}

// The other half of the differential, and the one that keeps it honest: if
// EVERY relay fails, nothing was proven. The target may be the broken party, so
// charging the relays would let one dead target manufacture a fleet-wide relay
// downrank.
func TestReserveWithTransientRetry_AllRelaysFailRecordsNothing(t *testing.T) {
	const preFloor = "9.0"
	target := retryOpAtVersion(1, "OWNER-TARGET", preFloor)
	relayA := retryOpAtVersion(2, "OWNER-A", preFloor)
	relayB := retryOpAtVersion(3, "OWNER-B", preFloor)

	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)
	if got.Err == nil {
		t.Fatal("expected the final failure to be returned")
	}
	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v with every relay failing; nothing was proven, so nothing may be charged",
			rep.outcomes)
	}
}

// A transport failure needs no version gate and no rotation to attribute: no
// response arrived, and the socket we opened belonged to the RELAY. This is the
// one rule that charges correctly against a fleet where nothing has upgraded.
func TestReserveWithTransientRetry_TransportFailureBlamesRelayWithoutVersionGate(t *testing.T) {
	const preFloor = "9.0"
	target := retryOpAtVersion(1, "OWNER-TARGET", preFloor)
	relayA := retryOpAtVersion(2, "OWNER-A", preFloor)
	relayB := retryOpAtVersion(3, "OWNER-B", preFloor)

	rc := &scriptedReserveClient{script: []error{transportErr()}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)

	if len(rep.outcomes) == 0 {
		t.Fatal("a transport failure through a relay charged nobody; the dialed socket was the relay's")
	}
	for ref, outcomes := range rep.outcomes {
		for _, ok := range outcomes {
			if ok {
				t.Errorf("relay %+v was credited for a transport failure", ref)
			}
		}
	}
}

// A MARKED code-less status means the relay ran and forwarded, so the status is
// the target's. It must not reach RecordRelayOutcome from this leg — believing
// or disbelieving the claim is the differential path's job, on the inference leg.
func TestReserveWithTransientRetry_MarkedResponseLeavesRelayAlone(t *testing.T) {
	target := retryOpAtVersion(1, "OWNER-TARGET", "9.1")
	relayA := retryOpAtVersion(2, "OWNER-A", "9.1")
	relayB := retryOpAtVersion(3, "OWNER-B", "9.1")

	rc := &scriptedReserveClient{script: []error{markedGatewayErr(http.StatusGatewayTimeout)}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v for a MARKED response; the relay demonstrably forwarded, "+
			"so this leg must leave it alone", rep.outcomes)
	}
}

// An unmarked code-less status from a relay that ADVERTISES the marker is
// self-incriminating on the spot — no rotation needed, because a relay of that
// generation would have marked anything its handler produced.
// The timeout carve-out: a relay is byte-silent for the whole forward window,
// so an unmarked gateway TIMEOUT may be it waiting on a slow target rather than
// its own door being shut. Charging here would bench whoever fronts the slowest
// targets.
func TestReserveWithTransientRetry_UnmarkedGatewayTimeoutChargesNobody(t *testing.T) {
	target := retryOpAtVersion(1, "OWNER-TARGET", "9.1")
	relayA := retryOpAtVersion(2, "OWNER-A", "9.1")
	relayB := retryOpAtVersion(3, "OWNER-B", "9.1")

	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v for an unmarked gateway TIMEOUT; the relay may have been "+
			"waiting on a slow target, which is not its fault", rep.outcomes)
	}
}

// Our own cancellation must never cost a relay a strike. Every client.Do error
// surfaces as TransportFailureStatus, so without the guard a payer hitting stop
// charges one relay per candidate across the whole sweep.
func TestReserveWithTransientRetry_CallerCancellationChargesNoRelay(t *testing.T) {
	target := retryOpAtVersion(1, "OWNER-TARGET", "9.1")
	relayA := retryOpAtVersion(2, "OWNER-A", "9.1")
	relayB := retryOpAtVersion(3, "OWNER-B", "9.1")

	rc := &scriptedReserveClient{script: []error{transportErr()}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.reserveWithTransientRetry(ctx, target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v for a caller-cancelled request; we tore the socket down, "+
			"not the relay", rep.outcomes)
	}
}

func TestReserveWithTransientRetry_MarkerlessFailureBlamesRelayImmediately(t *testing.T) {
	target := retryOpAtVersion(1, "OWNER-TARGET", "9.1")
	relayA := retryOpAtVersion(2, "OWNER-A", "9.1")
	relayB := retryOpAtVersion(3, "OWNER-B", "9.1")

	// Every attempt fails, so no rotation differential can fire — the marker
	// rule is the only thing that could charge anyone here. 502 is a
	// front-door shape; a 504 would be an ambiguous gateway TIMEOUT and must NOT
	// charge (TestReserveWithTransientRetry_UnmarkedGatewayTimeoutChargesNobody).
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusBadGateway)}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)

	if len(rep.outcomes) == 0 {
		t.Fatal("a 9.1 relay answered a code-less 502 without its own hop marker and was not charged")
	}
	for ref, outcomes := range rep.outcomes {
		for _, ok := range outcomes {
			if ok {
				t.Errorf("relay %+v was credited for an unmarked code-less 502", ref)
			}
		}
	}
}

// Direct mode has no relay to charge, so none of the above may fire.
func TestReserveWithTransientRetry_DirectModeChargesNoRelay(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusBadGateway), nil}}
	s, rep := retryServerWithRep(t, rc, []hayai.Operator{target})

	s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		nil, nil, false, time.Now().Add(10*time.Second), nil)

	if len(rep.outcomes) != 0 {
		t.Errorf("direct mode recorded relay outcomes %v; there was no relay in the path", rep.outcomes)
	}
}

// A considered refusal is an answer, not weather: retrying it burns budget and
// delays the real error for no chance of a different outcome.
func TestReserveWithTransientRetry_TerminalErrorNotRetried(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	for name, err := range map[string]error{
		"sizing rejection":      &hayai.SizeError{Code: "context_length_exceeded"},
		"busy":                  &hayai.BusyError{RetryAfter: time.Second},
		"payer refusal":         &hayai.PayerRefusalError{Code: "free_quota_exhausted"},
		"coded node 503":        &hayai.ReserveHTTPError{Status: 503, Code: "provider_unavailable"},
		"code-less 400 refusal": &hayai.ReserveHTTPError{Status: 400},
	} {
		t.Run(name, func(t *testing.T) {
			rc := &scriptedReserveClient{script: []error{err}}
			s := retryServer(t, false, rc, []hayai.Operator{target})
			got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
				nil, nil, false, time.Now().Add(10*time.Second), nil)
			if got.Err == nil {
				t.Fatal("expected the error to be surfaced")
			}
			if rc.calls() != 1 {
				t.Errorf("reserve calls = %d, want 1 (no retry on a terminal error)", rc.calls())
			}
		})
	}
}

// Direct mode has no relay to rotate to, but a restarting node's gateway
// recovers on its own, so the attempts still happen — just against the same path.
func TestReserveWithTransientRetry_DirectModeStillRetries(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusBadGateway), nil}}
	s := retryServer(t, false, rc, []hayai.Operator{target})

	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		nil, nil, false, time.Now().Add(10*time.Second), nil)
	if got.Err != nil {
		t.Fatalf("reserve err = %v, want success on the retry", got.Err)
	}
	if rc.calls() != 2 {
		t.Errorf("reserve calls = %d, want 2", rc.calls())
	}
}

// The attempt budget is a hard cap — a permanently-broken gateway must not spin.
func TestReserveWithTransientRetry_BoundedByInnerAttempts(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s := retryServer(t, false, rc, []hayai.Operator{target})

	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		nil, nil, false, time.Now().Add(10*time.Second), nil)
	if got.Err == nil {
		t.Fatal("expected the last failure to be surfaced")
	}
	if rc.calls() != transient.InnerAttempts {
		t.Errorf("reserve calls = %d, want InnerAttempts=%d", rc.calls(), transient.InnerAttempts)
	}
}

// An exhausted deadline stops the retrying even though attempts remain — the
// outer sweep owns the remaining budget, and sleeping past the deadline would
// only delay the error the caller is about to get anyway.
func TestReserveWithTransientRetry_StopsAtDeadline(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s := retryServer(t, false, rc, []hayai.Operator{target})

	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		nil, nil, false, time.Now(), nil) // already expired
	if got.Err == nil {
		t.Fatal("expected the failure to be surfaced")
	}
	if rc.calls() != 1 {
		t.Errorf("reserve calls = %d, want 1 (no budget for a retry)", rc.calls())
	}
}

// A caller that hangs up mid-backoff must stop the loop rather than finish
// paying for round-trips nobody is waiting for.
func TestReserveWithTransientRetry_StopsOnContextCancel(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s := retryServer(t, false, rc, []hayai.Operator{target})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := s.reserveWithTransientRetry(ctx, target, ticket.ReserveRequest{},
		nil, nil, false, time.Now().Add(10*time.Second), nil)
	if got.Err == nil {
		t.Fatal("expected the failure to be surfaced")
	}
	if rc.calls() != 1 {
		t.Errorf("reserve calls = %d, want 1 (cancelled before the retry)", rc.calls())
	}
}

// With only one relay in the pool there is nothing to rotate to. Falling back to
// a direct send would leak the payer's IP for a request that asked to be
// relayed, so the loop stops instead.
func TestReserveWithTransientRetry_NoAlternateRelayStopsRatherThanGoingDirect(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	onlyRelay := retryOp(2, "OWNER-A")

	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s := retryServer(t, true, rc, []hayai.Operator{target, onlyRelay})
	relaySel := selOf(target, onlyRelay)

	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatalf("initial relay pick: %v", err)
	}
	got := s.reserveWithTransientRetry(context.Background(), target, ticket.ReserveRequest{},
		hop, relaySel, true, time.Now().Add(10*time.Second), nil)
	if got.Err == nil {
		t.Fatal("expected the failure to be surfaced")
	}
	if rc.calls() != 1 {
		t.Errorf("reserve calls = %d, want 1 (no alternate relay to rotate to)", rc.calls())
	}
	for i := 0; i < rc.calls(); i++ {
		if rc.hopAt(i) == nil {
			t.Error("an attempt went direct under privacy mode; the relay guarantee must hold")
		}
	}
}

func TestClassifyReserveErr(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantRetry   bool
		wantAttr    transient.Attribution
		wantRetryAt time.Duration
	}{
		{"bare 504", gatewayErr(http.StatusGatewayTimeout), true, transient.AttrUnknown, 0},
		{"transport failure", &hayai.ReserveHTTPError{Message: "connection reset"}, true, transient.AttrUnknown, 0},
		{"gateway 503 with Retry-After", &hayai.ReserveHTTPError{Status: 503, RetryAfter: 7 * time.Second},
			true, transient.AttrUnknown, 7 * time.Second},
		{"coded node error", &hayai.ReserveHTTPError{Status: 503, Code: "provider_unavailable"}, false, transient.AttrNone, 0},
		{"sizing error type", &hayai.SizeError{Code: "context_length_exceeded"}, false, transient.AttrNone, 0},
		{"not a reserve HTTP error", context.Canceled, false, transient.AttrNone, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, hint := classifyReserveErr(context.Background(), tc.err, nil)
			if v.Retryable != tc.wantRetry || v.Attribution != tc.wantAttr {
				t.Errorf("verdict = %+v, want retryable=%v attribution=%v", v, tc.wantRetry, tc.wantAttr)
			}
			if hint != tc.wantRetryAt {
				t.Errorf("retry-after = %v, want %v", hint, tc.wantRetryAt)
			}
		})
	}
}

// fakeTargetBackoff reports a fixed set of nodes as backed off.
type fakeTargetBackoff struct {
	mu        sync.Mutex
	backedOff map[hayai.NodeRef]bool
	recorded  []struct {
		ref hayai.NodeRef
		ok  bool
	}
}

func (f *fakeTargetBackoff) RecordTargetOutcome(target hayai.NodeRef, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, struct {
		ref hayai.NodeRef
		ok  bool
	}{target, ok})
}

func (f *fakeTargetBackoff) TargetBackedOff(target hayai.NodeRef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.backedOff[target]
}

func refs(ops []hayai.Operator) []hayai.NodeRef {
	out := make([]hayai.NodeRef, len(ops))
	for i, op := range ops {
		out[i] = hayai.RefOf(op)
	}
	return out
}

// A backed-off node sinks to the tail but is never dropped — a model only one
// node serves has to stay reachable as a last resort, and the window only lapses
// because live traffic re-probes it.
func TestDemoteBackedOffTargets_DemotesNeverDrops(t *testing.T) {
	a, b, c := retryOp(1, "OWNER-A"), retryOp(2, "OWNER-B"), retryOp(3, "OWNER-C")
	bo := &fakeTargetBackoff{backedOff: map[hayai.NodeRef]bool{hayai.RefOf(a): true}}

	got := demoteBackedOffTargets([]hayai.Operator{a, b, c}, nil, bo)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 — demote must never drop a candidate", len(got))
	}
	want := []hayai.NodeRef{hayai.RefOf(b), hayai.RefOf(c), hayai.RefOf(a)}
	if gotRefs := refs(got); !reflect.DeepEqual(gotRefs, want) {
		t.Errorf("order = %v, want %v (backed-off node last)", gotRefs, want)
	}
}

// The affinity / previous_response_id pin is exempt: when it's present it is the
// ONLY correct route, so a routing preference must not displace a working
// continuation.
func TestDemoteBackedOffTargets_PinnedTargetStaysFirst(t *testing.T) {
	pinned, other := retryOp(1, "OWNER-A"), retryOp(2, "OWNER-B")
	bo := &fakeTargetBackoff{backedOff: map[hayai.NodeRef]bool{hayai.RefOf(pinned): true}}

	got := demoteBackedOffTargets([]hayai.Operator{pinned, other}, &pinned, bo)
	if gotRefs := refs(got); gotRefs[0] != hayai.RefOf(pinned) {
		t.Errorf("order = %v; the pinned target must stay first even when backed off", gotRefs)
	}
}

// Order is untouched when nothing is backed off (and with a nil store, the
// tests' default), so the responsiveness banding underneath it is preserved.
func TestDemoteBackedOffTargets_NoOpWhenNothingBackedOff(t *testing.T) {
	a, b := retryOp(1, "OWNER-A"), retryOp(2, "OWNER-B")
	in := []hayai.Operator{a, b}

	if got := demoteBackedOffTargets(in, nil, &fakeTargetBackoff{}); !reflect.DeepEqual(refs(got), refs(in)) {
		t.Error("order changed with nothing backed off")
	}
	if got := demoteBackedOffTargets(in, nil, nil); !reflect.DeepEqual(refs(got), refs(in)) {
		t.Error("order changed with a nil store")
	}
}

// Whether a retryable reserve failure strikes the target's backoff depends on
// BOTH the attribution and whether a relay was in the path. The privacy
// dimension is the review's proxy-F1 for target-backoff: a code-less gateway 5xx
// is unattributable WITH a relay (someone else's CDN) but IS the node's own
// ingress in direct mode — where the proxy must strike it, exactly as the client
// does. The old test omitted the direct-mode row and enshrined the gap.
func TestShouldRecordTargetFailure(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		usePrivacy bool
		want       bool
	}{
		{"relay_upstream_unreachable strikes target (privacy)", &hayai.ReserveHTTPError{
			Status: 502, Code: protorelay.CodeUpstreamUnreachable}, true, true},
		{"relay_upstream_unreachable strikes target (direct)", &hayai.ReserveHTTPError{
			Status: 502, Code: protorelay.CodeUpstreamUnreachable}, false, true},
		{"code-less 504 is unattributable WITH a relay", gatewayErr(http.StatusGatewayTimeout), true, false},
		{"code-less 504 IS the node's ingress in DIRECT mode", gatewayErr(http.StatusGatewayTimeout), false, true},
		{"transport failure strikes target in direct mode", &hayai.ReserveHTTPError{Status: 0}, false, true},
		{"transport failure unattributable behind a relay", &hayai.ReserveHTTPError{Status: 0}, true, false},
		{"relay hop error never strikes the target (privacy)", &hayai.ReserveHTTPError{
			Status: 503, Code: protorelay.CodeBusy}, true, false},
		{"relay hop error never strikes the target (direct)", &hayai.ReserveHTTPError{
			Status: 503, Code: protorelay.CodeBusy}, false, false},
		{"a coded refusal is not retryable, never strikes", &hayai.ReserveHTTPError{
			Status: 503, Code: "provider_unavailable"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := classifyReserveErr(context.Background(), tc.err, nil)
			if got := shouldRecordTargetFailure(v, tc.usePrivacy); got != tc.want {
				t.Errorf("shouldRecordTargetFailure(attr=%q, usePrivacy=%v) = %v, want %v",
					v.Attribution, tc.usePrivacy, got, tc.want)
			}
		})
	}
}

// TestReserveWithTransientRetry_ResizesAfterReprobe covers the one path where
// the design's "the bound version is chosen per-operator, per attempt" property
// used to break.
//
// A re-probe fires precisely because the node restarted — the single moment its
// advertised proto_version can legitimately have changed under us. Re-issuing
// the request built against the PRE-reprobe operator would ship a v2-sized
// input_count to a node that just came back on 9.1 and measures v1, and the
// rejection lands after escrow.open where there is no failover.
func TestReserveWithTransientRetry_ResizesAfterReprobe(t *testing.T) {
	// Comes back downgraded: 9.2 before, 9.1 after.
	target := retryOpAtVersion(1, "OWNER-TARGET", "9.2")
	healed := retryOpAtVersion(1, "OWNER-TARGET", "9.1")

	rc := &scriptedReserveClient{script: []error{hayai.ErrNoEphemeral, nil}}
	static, err := hayai.NewStaticRegistryProvider([]hayai.Operator{target})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	reg := &healingRegistry{
		StaticRegistryProvider: static,
		heal:                   func(hayai.Operator) (hayai.Operator, bool) { return healed, true },
	}
	s := retryServer(t, false, rc, []hayai.Operator{target})
	s.registryProvider = reg

	// The caller's resize closure, mirroring dispatch: re-derive the bound
	// version from whichever operator we are actually talking to.
	resize := func(o hayai.Operator, r *ticket.ReserveRequest) {
		r.InputBoundVersion = boundVersionFor(o)
	}

	got := s.reserveWithTransientRetry(context.Background(), target,
		ticket.ReserveRequest{InputBoundVersion: boundVersionFor(target)},
		nil, nil, false, time.Now().Add(time.Minute), resize)
	if got.Err != nil {
		t.Fatalf("expected the retry to succeed: %v", got.Err)
	}
	if reg.calls != 1 {
		t.Fatalf("ReprobeEphemeral calls = %d, want 1", reg.calls)
	}
	if rc.calls() != 2 {
		t.Fatalf("reserve calls = %d, want 2 (original + post-reprobe retry)", rc.calls())
	}

	if want := prototokenize.BoundVersion2; rc.reqs[0].InputBoundVersion != want {
		t.Errorf("first attempt sized with v%d, want v%d (the operator advertised 9.2)",
			rc.reqs[0].InputBoundVersion, want)
	}
	if want := prototokenize.BoundVersion1; rc.reqs[1].InputBoundVersion != want {
		t.Errorf("post-reprobe attempt sized with v%d, want v%d — the request was not "+
			"re-sized against the downgraded operator, so a v2 reserve would reach a v1 node",
			rc.reqs[1].InputBoundVersion, want)
	}
}

// TestReserveWithTransientRetry_NilResizeKeepsRequest pins the opt-out: the
// dedicated image routes size max_price from imageprice rather than the token
// bound and pass no resize, so their request must ride through a re-probe
// untouched.
func TestReserveWithTransientRetry_NilResizeKeepsRequest(t *testing.T) {
	target := retryOpAtVersion(1, "OWNER-TARGET", "9.2")
	healed := retryOpAtVersion(1, "OWNER-TARGET", "9.1")

	rc := &scriptedReserveClient{script: []error{hayai.ErrNoEphemeral, nil}}
	static, err := hayai.NewStaticRegistryProvider([]hayai.Operator{target})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	s := retryServer(t, false, rc, []hayai.Operator{target})
	s.registryProvider = &healingRegistry{
		StaticRegistryProvider: static,
		heal:                   func(hayai.Operator) (hayai.Operator, bool) { return healed, true },
	}

	orig := ticket.ReserveRequest{InputCount: 0, ImageN: 2, InputBoundVersion: 0}
	if got := s.reserveWithTransientRetry(context.Background(), target, orig,
		nil, nil, false, time.Now().Add(time.Minute), nil); got.Err != nil {
		t.Fatalf("expected success: %v", got.Err)
	}
	if rc.reqs[1].ImageN != 2 || rc.reqs[1].InputCount != 0 || rc.reqs[1].InputBoundVersion != 0 {
		t.Errorf("image reserve was mutated across the re-probe: %+v", rc.reqs[1])
	}
}
