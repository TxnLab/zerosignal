/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/steering"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// OperatorSource produces the current list of operators the proxy may
// dispatch to. Each Fetch call is a fully independent snapshot: the
// source resolves on-chain operator records and probes each operator's
// /v1/zs/details endpoint. An operator whose details probe fails is
// still returned (with Reachable=false and an empty Models list) so the
// registry can keep trying it — the failure might be transient, and
// dispatch's per-request fallthrough can still make progress.
//
// Errors from Fetch mean "the top-level fetch failed" (chain lookup
// returned an error, or no operators registered yet). Per-operator
// details failures are absorbed into the returned Operator values and
// are NOT surfaced as a top-level error.
type OperatorSource interface {
	Fetch(ctx context.Context) ([]Operator, error)
}

// ChainOperatorSource loads operators from the ZeroSignalEscrow contract on
// Algorand and enriches them with capability data from each operator's
// /v1/zs/details endpoint. It's the production OperatorSource used
// by the proxy; tests should inject a fake OperatorSource instead.
type ChainOperatorSource struct {
	// EscrowAppID is the ZeroSignalEscrow application id — required.
	EscrowAppID uint64

	// OperatorIDs, when non-empty, restricts which operator IDs are
	// loaded. Empty means "fetch every currently-registered operator".
	OperatorIDs []uint64

	// ProxyPayerAddr is the sender for the box-enumeration simulate
	// call that FetchAllOperators issues. Required when OperatorIDs is
	// empty.
	ProxyPayerAddr string

	// Algod is the resolved algod client.
	Algod algod.Client

	// Details is the HTTP probe used for /v1/zs/details. If nil,
	// NewDetailsClient is called with DetailsTimeout.
	Details *DetailsClient

	// DetailsTimeout bounds one per-operator details probe. Zero picks
	// DefaultDetailsFetchTimeout.
	DetailsTimeout time.Duration

	// DetailsConcurrency caps how many per-operator details probes run at
	// once inside a single refresh cycle. Without a bound, a large fleet
	// (~1000 nodes) opens ~1000 simultaneous /v1/zs/details sockets — each
	// relayed in privacy mode — which cannot complete inside the refresh
	// timeout and drops the whole cycle. Zero (or negative) picks
	// DefaultDetailsConcurrency.
	DetailsConcurrency int

	// Attestation is the HTTP probe used for /v1/zs/attestation
	// when the details response advertises tee.mode != none. Nil
	// falls back to a fresh client with DetailsTimeout (the two
	// probes share the per-operator deadline).
	Attestation *AttestationClient

	// TEEVerifier verifies fetched attestation bundles. Nil disables
	// the attestation probe entirely — operators that advertise TEE
	// will keep Operator.TEE == nil and be treated as not-attested,
	// which is the correct behavior when the proxy isn't configured
	// for TEE verification (e.g. a deployment that doesn't yet care
	// about confidential mode).
	TEEVerifier tee.Verifier

	// Log receives refresh diagnostics. Nil is tolerated — output goes
	// to slog.Default() in that case.
	Log *slog.Logger

	// Privacy enables transport-privacy mode for the discovery probes:
	// each per-operator /v1/zs/details and /v1/zs/attestation probe is
	// routed through a relay (≠ the probed operator) so the operator never
	// sees the proxy's IP from background discovery traffic. When no eligible
	// relay exists for an operator, its probe is skipped this cycle rather
	// than sent directly (the privacy contract — never reveal the IP). False
	// = probe operators directly, pre-relay behavior. A cold start, with no node
	// probed yet, is not stuck: buildSelAll seeds each unprobed peer's protocol
	// version so it stays relay-eligible, and with no node known reachable the
	// relay pick draws from every eligible peer. A node with no eligible relay
	// (every other node shares its operator or owner, runs an incompatible
	// protocol, or sits in its /16) is skipped, cold or warm.
	Privacy bool

	// reachMu guards lastReachable.
	reachMu sync.Mutex
	// lastReachable remembers each node's most recent probe outcome across
	// refresh cycles (the per-cycle records start fresh with Reachable=false).
	// In privacy mode it lets the relay-candidate set prefer relays that were
	// reachable last cycle, so a down node stops being chosen as a relay. Keyed
	// by (operator id, node id): an operator runs many nodes with independent
	// reachability (operator/node split), so keying by operator id alone would
	// collapse them to whichever node was probed last. Only meaningful under
	// Privacy; unused otherwise.
	lastReachable map[NodeRef]bool

	// relayRepMu guards relayFailStreak, relayStaleStreak and relayTimeoutStreak.
	relayRepMu sync.Mutex
	// relayFailStreak tracks recent consecutive *forward* failures through each node
	// acting as a relay (incremented from discovery probes and the inference
	// path via RecordRelayOutcome / the differential RecordRelayUpstreamUnreachable;
	// reset by a successful forward). Keyed by the relay's (operator id, node id)
	// NodeRef — a relay is a single node, so one operator's nodes accrue
	// independent streaks. It is a soft per-relay reputation signal DISTINCT from
	// lastReachable / the per-node Reachable bool (which track the node's own
	// target-probe health): a non-compliant 3.0 fork that answers its own
	// /v1/zs/details probe but strips the forwarding path is Reachable=true
	// yet accumulates a failure streak here.
	relayFailStreak map[NodeRef]steering.Evidence
	// relayStaleStreak counts consecutive *stale ephemeral* advertisements a
	// relay node served (a hard-valid block older than ticket.FreshnessTarget —
	// the relay replayed an older key block than the target should have). Keyed by
	// the relay's NodeRef like relayFailStreak. It is SEPARATE from relayFailStreak
	// on purpose: a successful forward of a stale block still credits
	// relayFailStreak (the forward worked), so folding the two would let that
	// same-cycle forward-success credit reset the staleness signal before it ever
	// crosses the downrank threshold. Reset by a fresh block over the same relay
	// (RecordRelayFreshEphemeral).
	relayStaleStreak map[NodeRef]steering.Evidence
	// relayTimeoutStreak counts forwards through a relay node that died with a
	// gateway *timeout* (408/504/524) the shared transient verdict left
	// unattributed. Keyed by the relay's NodeRef like the two above, and SEPARATE
	// from both for a reason specific to what it catches: a front door that kills
	// only byte-silent forwards times out every relayed non-streaming request
	// while streamed forwards (kept alive by the node's SSE keepalive) and
	// millisecond-long reserve round-trips keep succeeding — so the same relay is
	// credited into relayFailStreak constantly. Folding them would let those
	// credits erase this evidence before it ever crossed a threshold. Only decay
	// ages it; no success clears it. See RecordRelayForwardTimeout.
	relayTimeoutStreak map[NodeRef]steering.Evidence
	// relayRepClock overrides the reputation-decay clock in tests; nil = time.Now.
	relayRepClock func() time.Time

	// tgtBackoffMu guards tgtBackoff. Distinct from relayRepMu on purpose: this
	// is the *target*-side signal (the node we dispatch inference to), where
	// relayFailStreak/relayStaleStreak are relay-side.
	tgtBackoffMu sync.Mutex
	// tgtBackoff holds the exponential per-target backoff state — see
	// target_backoff.go. Sparse (an entry exists only after a failure, cleared on
	// success) and self-trimming on read, so it needs no cap.
	tgtBackoff map[NodeRef]steering.Backoff

	// excludeMu guards excludedNodes.
	excludeMu sync.Mutex
	// excludedNodes is the write-once, never-reset set of nodes proven to have
	// handed a fraudulent atomic settle group — see malicious_nodes.go. Unlike
	// every other per-node store in this struct it is DELIBERATELY not
	// self-healing: a node authors both halves of the settle group AND its own
	// signed receipt, so handing a group that contradicts that receipt (a
	// RekeyTo, a non-NoOp OnCompletion, or a value mismatch) is proven
	// misbehaviour, not a transient fault — it must never float back into
	// candidacy this process's lifetime. Keyed by NodeRef (operator/node split)
	// like the rest.
	excludedNodes map[NodeRef]struct{}

	// LatencyStateMax caps the number of live entries kept in each latency EWMA
	// map (relay_latency.go). The pair map is (relay,target)-keyed, so it is the
	// one O(n²)-shaped store as the fleet grows; the cap is a hard backstop on top
	// of the natural 5-minute staleness prune. Zero (or negative) picks
	// DefaultLatencyStateMax. (The reachability/reputation maps below don't take a
	// cap: relayFailStreak/relayStaleStreak/relayTimeoutStreak each hold at most
	// one entry per relay node — cleared on the RelayDownranked read that ages
	// their last unit of evidence out, and for the first two also on success
	// (relayTimeoutStreak deliberately has no success clear, see its own comment)
	// — and lastReachable is one bool per node, so all four are O(n)/sparse, not
	// O(n²). Note the decay sweep is LAZY and per-key, so a relay that leaves the
	// fleet keeps its entry until process exit; that is still bounded by fleet
	// size, which is why no cap is needed.)
	LatencyStateMax int

	// latMu guards the client-observed latency EWMA maps below (RelayLatency,
	// relay_latency.go). Distinct from reachMu / relayRepMu: latency is a separate
	// "how fast" signal, recorded from the same discovery + reserve paths.
	latMu sync.Mutex
	// pairLat / relayLat / targetLat hold the per-(relay,target), per-relay-endpoint,
	// and per-target RTT EWMAs. Sparse; pruned on read once stale. Keyed by NodeRef
	// (operator/node split) like every other reliability store here.
	pairLat   map[pairKey]latStat
	relayLat  map[NodeRef]latStat
	targetLat map[NodeRef]latStat
	// latClock overrides the clock for latency staleness in tests; nil = time.Now.
	latClock func() time.Time

	// signerMu guards signerSpendable.
	signerMu sync.Mutex
	// signerSpendable is the last SUCCESSFUL spendable-ALGO reading per signing
	// address — see signer_balance.go. It outlives the per-cycle Operator values
	// so a failed read keeps the previous verdict instead of reverting to
	// "unknown", which would re-admit a node last seen broke. Pruned to the
	// current fleet every pass, so it is bounded by fleet size.
	signerSpendable map[string]uint64
	// readSpendable overrides the algod account read in tests; nil = algod.
	readSpendable func(ctx context.Context, addr string) (uint64, error)
	// readChain overrides the box walk in tests; nil = readChainNodes. It
	// exists so a test can pin that FetchChain runs the balance pass without
	// hand-encoding escrow's positional box layout.
	readChain func(ctx context.Context) ([]Operator, error)
	// chainClock overrides the day the revenue windows end on in tests; nil =
	// time.Now.
	chainClock func() time.Time
}

// recallReachable returns the last-known reachability for a node (false when
// never probed). Keyed by (operator id, node id) — an operator's nodes have
// independent reachability. Safe for concurrent use.
func (s *ChainOperatorSource) recallReachable(ref NodeRef) bool {
	s.reachMu.Lock()
	defer s.reachMu.Unlock()
	return s.lastReachable[ref]
}

// recordReachable stores a node's probe outcome for the next cycle's
// relay-candidate set. Safe for concurrent use (called from the enrich
// goroutines).
func (s *ChainOperatorSource) recordReachable(ref NodeRef, reachable bool) {
	s.reachMu.Lock()
	defer s.reachMu.Unlock()
	if s.lastReachable == nil {
		s.lastReachable = make(map[NodeRef]bool)
	}
	s.lastReachable[ref] = reachable
}

// Fetch implements OperatorSource. Runs the chain read and the
// per-operator details probes; failed probes keep the operator with
// Reachable=false so the registry can retry on the next cycle.
func (s *ChainOperatorSource) Fetch(ctx context.Context) ([]Operator, error) {
	operators, err := s.FetchChain(ctx)
	if err != nil {
		return nil, err
	}
	s.enrich(ctx, operators, nil) // nil probeSet = probe every node
	return operators, nil
}

// FetchChain reads the on-chain operator + node set WITHOUT probing any
// /v1/zs/details endpoint. Each returned Operator carries its ids, owner,
// signing key, base URL, staging flag, signing-account spendable ALGO, and
// on-chain reliability metrics (LatencyEwmaMs / TokensPerSecEwma), but
// Reachable=false and empty capabilities until a probe lands. The balance
// pass lives here rather than beside the probes because every refresh path —
// the startup Fetch, the unbounded fallback, the bounded split — starts with
// this call. The registry pairs it with EnrichSubset to bound the
// /v1/zs/details fan-out: read the chain, pre-seed last-known capabilities from
// the prior snapshot, pick a bounded probe set, then probe only that subset.
func (s *ChainOperatorSource) FetchChain(ctx context.Context) ([]Operator, error) {
	read := s.readChain
	if read == nil {
		read = s.readChainNodes
	}
	ops, err := read(ctx)
	if err != nil {
		return nil, err
	}
	s.fillSignerBalances(ctx, ops)
	return ops, nil
}

// readChainNodes is FetchChain's box walk: operator records, then one
// Operator per active node.
func (s *ChainOperatorSource) readChainNodes(ctx context.Context) ([]Operator, error) {
	if s.Algod == nil {
		return nil, errors.New("ChainOperatorSource.Algod is nil")
	}
	if s.EscrowAppID == 0 {
		return nil, errors.New("ChainOperatorSource.EscrowAppID is 0")
	}

	records, err := s.fetchRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch operators: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no operators found on chain for escrow app %d", s.EscrowAppID)
	}

	return s.resolveActiveNodes(ctx, records)
}

// EnrichSubset probes the /v1/zs/details (and, where advertised, attestation) of
// only the operators whose NodeRef is in probeSet, updating them in place; a nil
// probeSet probes all (Fetch's behavior). Nodes not in the set are left
// untouched — the caller pre-seeds their last-known capabilities so they stay
// routable/advertised via the carry window. It is the bounded counterpart
// of Fetch's probe pass.
func (s *ChainOperatorSource) EnrichSubset(ctx context.Context, ops []Operator, probeSet map[NodeRef]bool) {
	s.enrich(ctx, ops, probeSet)
}

// resolveActiveNodes turns the fetched operator records into one routable
// Operator per NODE. Evicted operators are skipped (discovery hides them,
// matching the contract's open() guard) — FetchNodesForOperators does that
// filtering and the bounded-concurrent node fetch in one pass, so peak algod
// concurrency stays capped regardless of fleet size. A single malformed node
// (bad age key / non-http base URL) is skipped-and-logged rather than failing
// the whole refresh — one operator's typo must not blank discovery for the
// fleet.
func (s *ChainOperatorSource) resolveActiveNodes(ctx context.Context, records []escrow.OperatorRecord) ([]Operator, error) {
	// Day index for the windowed-revenue reads. The on-chain ring is
	// day-granular, so computing this once for the whole batch costs nothing.
	now := time.Now
	if s.chainClock != nil {
		now = s.chainClock
	}
	currentDay := uint64(now().Unix()) / escrow.SecondsPerDay

	// Index operators by id so each fetched node recovers its owner / nfd / id.
	opByID := make(map[uint64]escrow.OperatorRecord, len(records))
	for _, op := range records {
		opByID[op.ID] = op
	}

	nodes, err := escrow.FetchNodesForOperators(ctx, s.EscrowAppID, records, s.Algod)
	if err != nil {
		return nil, fmt.Errorf("fetch nodes: %w", err)
	}

	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	out := make([]Operator, 0, len(nodes))
	for _, node := range nodes {
		op, ok := opByID[node.OperatorID]
		if !ok {
			// Unreachable — every returned node belongs to an operator in
			// records — but guard against a future fetch loosening.
			continue
		}
		o, err := resolveOperatorNode(op, node, currentDay)
		if err != nil {
			log.Warn("skipping unparseable node record",
				slog.Uint64("operator_id", node.OperatorID),
				slog.Uint64("node_id", node.NodeID),
				slog.Any("err", err))
			continue
		}
		out = append(out, o)
	}
	return out, nil
}

// fetchRecords issues either FetchAllOperators or FetchOperatorsByID
// depending on whether OperatorIDs is populated.
func (s *ChainOperatorSource) fetchRecords(ctx context.Context) ([]escrow.OperatorRecord, error) {
	if len(s.OperatorIDs) > 0 {
		return escrow.FetchOperatorsByID(ctx, s.EscrowAppID, s.OperatorIDs, s.Algod)
	}
	return escrow.FetchAllOperators(ctx, s.EscrowAppID, s.Algod, s.ProxyPayerAddr)
}

// enrich populates Models, ModelCapacities, BuiltinTools, MaxToolIters,
// Reachable, LastRefreshAt, and (when the operator advertises TEE)
// TEE on each operator in place. Probes run concurrently; each is
// bounded by DetailsTimeout (plus the caller's refresh timeout via
// ctx).
func (s *ChainOperatorSource) enrich(ctx context.Context, operators []Operator, probeSet map[NodeRef]bool) {
	client, attestation, log := s.probeDeps()

	// In privacy mode, build the relay-candidate set once from the pre-probe
	// snapshot (so the concurrent probe goroutines don't race on the
	// per-operator fields they mutate).
	//
	// Cold-start bootstrap: relay selection needs each candidate's
	// proto_version, but that's only learned from a details probe — and in
	// privacy mode the probe itself routes through a relay. On a freshly
	// started proxy nobody's version is known, so without help every candidate
	// would be filtered out (version "" → legacy → incompatible) and *every*
	// probe would be skipped — the registry never warms (the observed
	// reachable=0 deadlock). Privacy mode presupposes an all-relay-capable
	// fleet (the post-bump precondition; SPEC § 3f), so we seed an unprobed
	// operator's version with this build's version: probes route through peers
	// we optimistically treat as relay-capable, with **no direct probe ever
	// exposing the proxy IP**. A peer that turns out to be pre-relay 404s the
	// forward and that one probe simply retries next cycle through a different
	// (randomly rotated) peer. Inference/reserve relay selection is unaffected —
	// it runs off the warm snapshot's real versions, never this optimistic seed.
	//
	// We also carry each operator's last-known reachability forward (the fresh
	// records start Reachable=false), so SelectRelay can *prefer* relays that
	// were reachable last cycle — that's what stops a down operator from being
	// chosen as a relay (and connection-refusing every probe routed through it)
	// once we've learned it's down. Cold start: nothing known-reachable yet →
	// SelectRelay falls back to the full eligible set, so probing still
	// bootstraps. A relayed-probe failure is ambiguous (target-down vs
	// relay-down), so this is a self-correcting hint, never a guarantee.
	var selAll []selection.Operator
	if s.Privacy {
		selAll = s.buildSelAll(operators)
	}

	now := time.Now()
	// Bound the probe fan-out: a large fleet must not open a socket per node
	// at once (each probe is also relayed in privacy mode), or the cycle can't
	// finish inside the refresh timeout: every probe the deadline cuts off
	// learns nothing, and the registry stores the cycle anyway. A buffered
	// channel is the semaphore; probeOne handles its own errors, so there's
	// nothing to join beyond completion (hence WaitGroup, not errgroup).
	limit := s.DetailsConcurrency
	if limit <= 0 {
		limit = DefaultDetailsConcurrency
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range operators {
		// Bounded probing: a non-nil probeSet restricts this cycle's probes
		// to the selected nodes; the rest keep their caller-pre-seeded last-known
		// capabilities (carry window). nil = probe all (Fetch / small fleets).
		if probeSet != nil && !probeSet[RefOf(operators[i])] {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			s.probeOne(ctx, client, attestation, selAll, &operators[i], now, log)
		}(i)
	}
	wg.Wait()
}

// probeDeps resolves the per-cycle probe dependencies, falling back to
// freshly-built clients (DetailsTimeout) and slog.Default() when the source
// wasn't configured with explicit ones. Shared by enrich (whole-fleet refresh)
// and ReprobeEphemeral (single-operator self-heal) so both probe identically.
func (s *ChainOperatorSource) probeDeps() (*DetailsClient, *AttestationClient, *slog.Logger) {
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	client := s.Details
	if client == nil {
		client = NewDetailsClient(nil, s.DetailsTimeout)
	}
	attestation := s.Attestation
	if attestation == nil {
		attestation = NewAttestationClient(nil, s.DetailsTimeout)
	}
	return client, attestation, log
}

// buildSelAll snapshots operators into the relay-candidate set used by
// privacy-mode discovery probes. Each candidate's reachability is its
// last-known probe outcome minus any relay downrank — a repeatedly-failing
// forwarder (e.g. a non-compliant fork that answers its own probe but drops
// forwards) drops to SelectRelay's fallback tier, never hard-excluded, so the
// cold-start fallback holds; both signals key by (operator id, node id) so a
// dead node never re-tiers a healthy sibling under the same operator. An
// unprobed candidate's proto_version is seeded so a cold start can still
// bootstrap relayed probes (see enrich's call site for the full rationale).
//
// The seed is wire.BootstrapProtoVersion() — this build's MAJOR with minor
// ZERO — not wire.ProtoVersion. Same major keeps the peer relay-ELIGIBLE
// exactly as before (selection filters on major equality), while minor 0 keeps
// it from claiming any minor-gated CAPABILITY it has never demonstrated.
// Seeding the full version is a live trap: at 9.1 every never-probed relay
// would read as wire.RelayHopHeader-capable and its first code-less 5xx would
// be charged to it for omitting a header nobody had established it could set.
func (s *ChainOperatorSource) buildSelAll(operators []Operator) []selection.Operator {
	selAll := make([]selection.Operator, len(operators))
	for i := range operators {
		sel := operators[i].Selection()
		if sel.ProtoVersion == "" {
			sel.ProtoVersion = wire.BootstrapProtoVersion()
		}
		ref := RefOf(operators[i])
		sel.Reachable = s.recallReachable(ref) && !s.RelayDownranked(ref)
		selAll[i] = sel
	}
	return selAll
}

// probeOne probes a single operator's /v1/zs/details (and, when it advertises
// TEE, its attestation), updating op in place: ephemeral sealing recipient,
// model capabilities, builtin tools, reachability, advertised minimum charge,
// and TEE state. selAll is the relay-candidate set consulted in privacy mode
// (nil in direct mode); now stamps LastRefreshAt. It is the per-operator unit of
// enrich's concurrent refresh, factored out so the dispatch self-heal re-probe
// (ReprobeEphemeral) applies byte-for-byte identical verification + carry-forward
// semantics out of band from the scheduled cycle.
func (s *ChainOperatorSource) probeOne(ctx context.Context, client *DetailsClient, attestation *AttestationClient, selAll []selection.Operator, op *Operator, now time.Time, log *slog.Logger) {
	resp, usedHop, err := s.probeDetailsWithRetry(ctx, client, selAll, *op, log)
	outcome := classifyProbe(err, ctx.Err())
	reachable, record := applyProbeOutcome(op, outcome, now)
	if outcome != probeSucceeded {
		if record {
			s.recordReachable(RefOf(*op), reachable)
		}
		switch outcome {
		case probeNoRelay:
			log.Debug("privacy mode: no eligible relay to probe operator; skipping details probe",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID))
		case probeCancelled:
			log.Debug("operator details probe cancelled",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.Any("err", err))
		case probeHopFailed:
			log.Warn("operator details probe: all relay hops failed this cycle; target status unknown",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.String("base_url", op.BaseURL),
				slog.Any("err", err),
			)
		default:
			log.Warn("operator details probe failed",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.String("base_url", op.BaseURL),
				relayLogAttr(usedHop),
				slog.Any("err", err),
			)
		}
		return
	}

	// resp also carries advertised USD rates and oracle health.
	// USD rates are copied onto each ModelCapacity below so the
	// proxy can publish a pricing surface (e.g. on
	// /v1/zs/operators) without callers having to round-trip
	// each operator's /v1/zs/details. They are informational —
	// the authoritative per-request rate is still the microUSDC
	// value the node signs into the ticket at reserve time (see
	// ticket.Ticket.InputRate/OutputRate). Oracle health is
	// ignored at this seam (it's a node-local concern).

	// Signed ephemeral sealing key (mandatory forward secrecy by
	// key-erasure — SPEC.md § 3c, § 4, § 8). When the operator
	// advertises one, verify it against the on-chain signing key
	// before trusting it; only a signature that validates under THIS
	// operator's chain-resolved id, within the policy lifetime, and
	// still unexpired is stored. Anything else leaves the operator with
	// no seal target (there is no anchor) so dispatch fails closed.
	s.applyEphemeralAdvertisement(op, resp, usedHop, log)
	applyDetailsFields(op, resp)
	if record {
		s.recordReachable(RefOf(*op), reachable)
	}

	// TEE attestation. Operators that don't advertise TEE
	// (resp.TEE == nil) keep Operator.TEE == nil and are
	// treated as not-attested by the routing filter.
	// Operators that do advertise but fail verification
	// also keep TEE populated (with Verified=false) so the
	// dashboard can surface the failure tag — but they're
	// excluded from TEE-required routing same as if they'd
	// never advertised.
	s.probeAttestation(ctx, op, resp, attestation, usedHop, log)
}

// probeOutcome is how one details probe ended, as far as what it says about
// the target. The TS SDK's applyProbeOutcome takes the same five, pinned with
// this side's by testdata/registry_probe_vectors.json.
type probeOutcome string

const (
	probeNoRelay      probeOutcome = "no_relay"
	probeCancelled    probeOutcome = "cancelled"
	probeHopFailed    probeOutcome = "hop_failed"
	probeTargetFailed probeOutcome = "target_failed"
	probeSucceeded    probeOutcome = "succeeded"
)

// classifyProbe sorts probeDetailsWithRetry's error (see its godoc). ctxErr is
// the probe context's error. It outranks a hop error, since a probe cut short
// learned nothing about either hop, but not ErrNoRelay, which is decided before
// any request is sent.
func classifyProbe(err, ctxErr error) probeOutcome {
	var hopErr *RelayHopError
	switch {
	case err == nil:
		return probeSucceeded
	case errors.Is(err, selection.ErrNoRelay):
		return probeNoRelay
	case ctxErr != nil:
		return probeCancelled
	case errors.As(err, &hopErr):
		return probeHopFailed
	default:
		return probeTargetFailed
	}
}

// applyProbeOutcome writes onto op what outcome says about its target, and
// returns the reachability to remember for it when record is set. On success it
// also voids the ephemeral recipient and the TEE verdict, which only this
// probe's own advertisement may set again (applyEphemeralAdvertisement and
// probeAttestation run after it). It is the whole of probeOne's decision, pure
// so the TS SDK can replay it.
func applyProbeOutcome(op *Operator, outcome probeOutcome, now time.Time) (reachable, record bool) {
	switch outcome {
	case probeNoRelay:
		// Privacy on but no eligible relay to probe this operator privately:
		// the probe was skipped rather than reveal our IP with a direct
		// request. We didn't probe, so we don't know; just stamp the attempt.
		op.LastRefreshAt = now
	case probeCancelled:
		// The cycle's deadline, or a re-probe's request went away: nothing was
		// learned about the target. Leave it as-is.
	case probeHopFailed:
		// Every relay hop tried this cycle failed at the HOP — the relay was
		// unreachable, returned a relay-generated code, (>=9.1) answered a
		// code-less transient status without stamping wire.RelayHopHeader,
		// proving its own front door ate the probe, or timed out waiting. In
		// none of those did we reach the target, so its status is unknown.
		// probeDetailsWithRetry already recorded the relays that failed (not
		// the ones our deadline cut off after they accepted the connection),
		// so SelectRelay deprioritizes them next cycle. Reachable and the
		// capability fields stay for the snapshot-merge to carry last-known-good
		// forward.
		op.LastRefreshAt = now
	case probeTargetFailed:
		// The target itself failed: down, an error status the relay forwarded
		// from the target, relay_upstream_unreachable from every relay that
		// worked, a malformed body, or — direct mode — a transport error to the
		// target. The operator stays in the registry so dispatch can still
		// reach it if its reserve endpoint is alive, and the previously-fetched
		// Models stay (the caller's snapshot-merge decides whether to carry
		// last-known-good capabilities forward).
		op.Reachable = false
		op.Probed = true // reached the target; the down result is fresh this cycle
		op.LastRefreshAt = now
		return false, true
	case probeSucceeded:
		clearEphemeral(op)
		op.TEE = nil
		op.Reachable = true
		op.Probed = true
		op.LastRefreshAt = now
		// Advance the carry-window clock: this is the last moment we confirmed
		// the node's capabilities live, so the registry keeps advertising/routing
		// it (via carry-forward) until now-ReachableAsOf passes max_carry_age.
		// Set only on success — a failed probe leaves it pinned at the previous
		// good time so the node ages out of the window on schedule rather than
		// resetting.
		op.ReachableAsOf = now
		// A successful (relayed) probe is unambiguous: the target responded,
		// so it's up. Remember it so SelectRelay prefers it as a relay.
		return true, true
	}
	return false, false
}

// applyDetailsFields copies what a details advertisement says onto op, short
// of the ephemeral recipient and the TEE verdict, which each need a check
// first. The TS SDK mirrors it as detailsFieldsOf, pinned by
// testdata/operator_vectors.json.
func applyDetailsFields(op *Operator, resp inject.OperatorDetails) {
	models := make([]string, 0, len(resp.Models))
	caps := make(map[string]ModelCapacity, len(resp.Models))
	for _, m := range resp.Models {
		models = append(models, m.ID)
		caps[m.ID] = modelCapacityOf(m)
	}
	tools := make([]BuiltinToolDef, len(resp.BuiltinTools))
	for j, t := range resp.BuiltinTools {
		tools[j] = BuiltinToolDef{Type: string(t.Type)}
	}
	op.Models = models
	op.ModelCapacities = caps
	op.BuiltinTools = tools
	op.MaxToolIters = resp.MaxToolIterations
	op.ToolHeadroomPerIteration = resp.ToolHeadroomPerIteration
	op.NodeVersion = resp.Version
	op.ProtoVersion = resp.ProtoVersion
	// The advertised minimum charge (SPEC.md §3a "Minimum charge"). The µALGO
	// fields are 0 when the operator hasn't enabled it or its oracle is
	// unhealthy; the authoritative value is the signed ticket's min_price.
	op.MinChargeOutputTokens = resp.MinChargeOutputTokens
	op.MinChargeAlgoTxns = resp.MinChargeAlgoTxns
	op.MinChargeMicroUSDC = resp.MinChargeMicroUSDC
}

// modelCapacityOf is one advertised model as the registry keeps it.
func modelCapacityOf(m inject.OperatorDetailsModel) ModelCapacity {
	return ModelCapacity{
		ContextWindow:                m.ContextWindow,
		MaxOutputTokens:              m.MaxOutputTokens,
		InputModalities:              m.InputModalities,
		OutputModalities:             m.OutputModalities,
		InputUSDPer1M:                m.InputRateUSDPer1M,
		OutputUSDPer1M:               m.OutputRateUSDPer1M,
		CacheReadUSDPer1M:            m.CacheReadRateUSDPer1M,
		LongContextThresholdTokens:   m.LongContextThresholdTokens,
		LongContextInputUSDPer1M:     m.LongContextInputRateUSDPer1M,
		LongContextOutputUSDPer1M:    m.LongContextOutputRateUSDPer1M,
		LongContextCacheReadUSDPer1M: m.LongContextCacheReadRateUSDPer1M,
		Reasoning:                    m.Reasoning,
		ToolUse:                      m.ToolUse,
		Tags:                         m.Tags,
		Coordinates:                  m.Coordinates,
		WeightsDigest:                m.WeightsDigest,
		WeightsUnverifiable:          m.WeightsUnverifiable,
		Source:                       m.Source,
		CanonicalID:                  m.CanonicalID,
		Retention:                    knownRetention(m.Retention),
		ImageToolRateMicroUSDC:       m.ImageToolRateMicroUSDC,
		ImageEditToolRateMicroUSDC:   m.ImageEditToolRateMicroUSDC,
		ImageToolBaseMicroUSDC:       m.ImageToolBaseMicroUSDC,
		ImageEditToolBaseMicroUSDC:   m.ImageEditToolBaseMicroUSDC,
		ImageRateMicroUSDC:           m.ImageRateMicroUSDC,
		ImageEditRateMicroUSDC:       m.ImageEditRateMicroUSDC,
		ImageDefaultMicroUSDC:        m.ImageDefaultMicroUSDC,
		ImageEditDefaultMicroUSDC:    m.ImageEditDefaultMicroUSDC,
		ImageCapMicroUSDC:            m.ImageCapMicroUSDC,
		ImageEditCapMicroUSDC:        m.ImageEditCapMicroUSDC,
		AdvertisesImageGen:           m.ServesImageGen,
		AdvertisesImageEdit:          m.ServesImageEdit,
		ToolCallRatesMicroUSDC:       m.ToolCallRatesMicroUSDC,
		VendorToolCatchAllMicroUSDC:  m.VendorToolCatchAllMicroUSDC,
		VendorToolCallCap:            m.VendorToolCallCap,
		VendorToolTokensPerCall:      m.VendorToolTokensPerCall,
	}
}

// knownRetention drops a retention tier this build does not recognise, leaving
// "" — which every consumer already reads as UNKNOWN.
//
// The field is NODE-AUTHORED and this value reaches a dashboard, so passing an
// unrecognised string through verbatim lets a node mint its own reassuring
// label and have the proxy render it. A newer node's real tier and an
// operator's invention are indistinguishable from here, and degrading both to
// unknown is the honest reading of either.
//
// inject.IsKnownRetention is the shared definition, so this cannot drift from
// the node that emits the values.
func knownRetention(v string) string {
	if !inject.IsKnownRetention(v) {
		return ""
	}
	return v
}

// ReprobeEphemeral re-probes target's /v1/zs/details live and returns the
// operator with its ephemeral sealing recipient (and the rest of its probed
// state) refreshed. all is the current operator set, used only to build the
// privacy-mode relay-candidate set (a target relays through a peer, never
// itself).
//
// It backs the dispatch self-heal path: a node that just restarted mints its
// ephemeral key before it serves (node-side fail-closed), so the only staleness
// is the proxy's cached snapshot. Rather than skip the candidate and 503
// no_ephemeral_capacity until the next scheduled refresh (up to refresh_interval
// away), the dispatcher re-probes the one candidate out of band and retries the
// reserve against the result. Snapshot write-back is deliberately left to the
// scheduled cycle — this returns a fresh copy for the in-flight request only, so
// it never races the background snapshot swap.
func (s *ChainOperatorSource) ReprobeEphemeral(ctx context.Context, all []Operator, target Operator) Operator {
	client, attestation, log := s.probeDeps()
	var selAll []selection.Operator
	if s.Privacy {
		selAll = s.buildSelAll(all)
	}
	s.probeOne(ctx, client, attestation, selAll, &target, time.Now(), log)
	return target
}

// applyEphemeralAdvertisement verifies the operator's advertised
// anchor-signed ephemeral sealing recipient and, on success, stores the
// parsed recipient + its pubkey + expiry on op so SealRecipient can
// prefer it. It is the proxy half of the forward-secrecy handshake
// (SPEC.md § 3c, § 4, § 8); see ticket.EphemeralAdvertisement.
//
// Trust comes entirely from the on-chain signing key — the advertised
// /v1/zs/details JSON is untrusted, so the three ephemeral_* fields
// are bound back to op.ID at verify time (Verify supplies the
// chain-resolved id, never the wire's). Outcomes:
//
//   - No advertisement (empty pubkey): clear any prior ephemeral and
//     return — the operator isn't offering one this cycle.
//   - Verify nil: parse the recipient and store all three. A later
//     SealRecipient call seals to it (subject to its own expiry re-check).
//   - ErrEphemeralExpired: signature was genuine but stale — clear the
//     fields SILENTLY, leaving no seal target this cycle (there is no
//     on-chain key to fall back to; a stale-but-genuine block is routine
//     near a rotation boundary, not an attack).
//   - Any other error (bad signature / wrong operator id / malformed
//     recipient): clear the fields and log a substitution-attempt
//     diagnostic — a relay or substituting node tried to re-point a
//     sealing key at this operator. Mirrors the neighboring age-key-
//     mismatch warn's attributes (operator_id + relay hop).
//
// The fields are always cleared before the verify branch so a probe that
// no longer advertises a valid ephemeral can never carry a stale one
// forward from a previous cycle's snapshot.
func (s *ChainOperatorSource) applyEphemeralAdvertisement(op *Operator, resp inject.OperatorDetails, usedHop *RelayHop, log *slog.Logger) {
	// Clear first: a failed / absent probe must not leave a stale ephemeral
	// recipient pinned from an earlier cycle.
	clearEphemeral(op)

	v := checkEphemeral(resp, op.TicketSigningKey, time.Now(), op.ID, op.NodeID)
	switch v.Outcome {
	case ephemeralVerified:
		op.EphemeralRecipient = v.Recipient
		op.EphemeralRecipientPubkey = resp.EphemeralAgePubkey
		op.EphemeralExpiry = resp.EphemeralExpiry
		op.EphemeralIssuedAt = resp.EphemeralIssuedAt

		// Soft relay-staleness attribution (SPEC § 3f): a hard-valid block that
		// is older than the freshness target AND arrived via a relay means the
		// relay served a staler key than the node should have — downrank it and
		// prefer a fresher path. Gated on usedHop != nil: a directly-fetched
		// block has no relay to attribute to, and an honest current key
		// legitimately ages toward advTTL (> FreshnessTarget) near a rotation
		// boundary, so this can only ever penalize a relay, never reject the
		// (still decryptable, forward-secret) block. This drives a SEPARATE
		// staleness streak — NOT RecordRelayOutcome — because probeDetailsWithRetry
		// already credited this relay's forward-failure streak for the same
		// successful forward, and reusing one streak would let that credit cancel
		// the staleness signal every cycle. A fresh block clears the staleness
		// streak so a recovered relay isn't penalized.
		if usedHop != nil {
			if v.Stale {
				s.RecordRelayStaleEphemeral(usedHop.RelayRef())
			} else {
				s.RecordRelayFreshEphemeral(usedHop.RelayRef())
			}
		}
	case ephemeralUnparseable:
		// Signature validated but the recipient string isn't a parseable
		// age key — the operator signed a malformed pubkey. Treat as a
		// substitution-grade anomaly; the operator is left with no seal
		// target (no anchor) so dispatch fails closed for it.
		log.Warn("operator advertised an unparseable ephemeral age recipient; no seal target (fail closed)",
			slog.Uint64("operator_id", op.ID),
			slog.Uint64("node_id", op.NodeID),
			relayLogAttr(usedHop),
			slog.Any("err", v.Err),
		)
	case ephemeralRejected:
		// Bad signature / wrong operator id / over-long lifetime: someone tried
		// to substitute or over-extend a sealing recipient for this operator.
		// Surface it; the operator is left with no seal target (no anchor) so
		// dispatch fails closed for it.
		log.Warn("operator ephemeral sealing-key advertisement failed verification; no seal target (fail closed)",
			slog.Uint64("operator_id", op.ID),
			slog.Uint64("node_id", op.NodeID),
			relayLogAttr(usedHop),
			slog.Any("err", v.Err),
		)
	}
	// ephemeralAbsent: the node isn't offering one this cycle.
	// ephemeralExpired: genuine but stale, so no seal target this cycle, and
	// silent, since a stale-but-genuine block is not an attack.
}

func clearEphemeral(op *Operator) {
	op.EphemeralRecipient = nil
	op.EphemeralRecipientPubkey = ""
	op.EphemeralExpiry = 0
	op.EphemeralIssuedAt = 0
}

// ephemeralOutcome is what one probe's ephemeral advertisement leaves a node
// with. The SDK's checkEphemeralAdvertisement returns the same five, pinned by
// testdata/ephemeral_verdict_vectors.json.
type ephemeralOutcome string

const (
	ephemeralAbsent      ephemeralOutcome = "absent"
	ephemeralVerified    ephemeralOutcome = "verified"
	ephemeralExpired     ephemeralOutcome = "expired"
	ephemeralRejected    ephemeralOutcome = "rejected"
	ephemeralUnparseable ephemeralOutcome = "unparseable"
)

type ephemeralVerdict struct {
	Outcome ephemeralOutcome
	// Recipient is set only when Outcome is ephemeralVerified.
	Recipient *age.X25519Recipient
	// Stale is the soft relay-attribution signal (ticket.FreshnessTarget),
	// meaningful only for a verified block.
	Stale bool
	// Err says why a block was rejected or unparseable.
	Err error
}

// checkEphemeral verifies one probe's advertisement against the node's
// chain-resolved identity: applyEphemeralAdvertisement's decision, without
// its writes and logs.
func checkEphemeral(resp inject.OperatorDetails, signingKey ed25519.PublicKey, now time.Time, operatorID, nodeID uint64) ephemeralVerdict {
	if resp.EphemeralAgePubkey == "" {
		return ephemeralVerdict{Outcome: ephemeralAbsent}
	}
	adv := ticket.EphemeralAdvertisement{
		AgePubkey: resp.EphemeralAgePubkey,
		Expiry:    resp.EphemeralExpiry,
		// IssuedAt is required to recompute the signed canonical bytes; without
		// it Verify rejects every block on the lifetime cap (Expiry-0 ≫
		// MaxEphemeralLifetime). A 3.0 node omits it → IssuedAt 0 → correctly
		// rejected (it signed an older layout anyway).
		IssuedAt: resp.EphemeralIssuedAt,
		Sig:      resp.EphemeralSig,
	}
	// The chain-resolved pair goes to Verify rather than riding on adv: the
	// signed canonical bytes bind both, so a sibling node's advertisement
	// (possible under a shared operator signing key) can never validate as
	// this node's.
	err := adv.Verify(signingKey, now, operatorID, nodeID, ticket.DefaultEphemeralSkew)
	switch {
	case err == nil:
		recipient, perr := age.ParseX25519Recipient(resp.EphemeralAgePubkey)
		if perr != nil {
			return ephemeralVerdict{Outcome: ephemeralUnparseable, Err: perr}
		}
		return ephemeralVerdict{Outcome: ephemeralVerified, Recipient: recipient, Stale: adv.Stale(now)}
	case errors.Is(err, ticket.ErrEphemeralExpired):
		return ephemeralVerdict{Outcome: ephemeralExpired}
	default:
		return ephemeralVerdict{Outcome: ephemeralRejected, Err: err}
	}
}

// maxDiscoveryRelayAttempts bounds how many distinct relays a single privacy-
// mode details probe will try before giving up for this cycle. A relay that
// fails the hop, times out, or claims the target is down is excluded and the
// probe rotates to another, so a couple of dead or partitioned relays don't
// make the target look down — but the cap keeps a fleet-wide relay outage from
// turning one probe into len(operators) sequential DetailsTimeout waits.
const maxDiscoveryRelayAttempts = 3

// probeDetailsWithRetry probes target's /v1/zs/details. In direct mode
// (privacy off) it is a single direct GET. In privacy mode it routes through a
// rotating relay and, when a relay *hop* is itself unreachable, marks that
// relay down (so SelectRelay deprioritizes it next cycle), excludes it, and
// retries through a different relay — a dead relay must not be mistaken for a
// dead target. A relay that reports relay_upstream_unreachable is rotated past
// too: one relay's view of the target is not proof the target is down. Its
// claim is scored once the probe resolves (settleClaims). It returns the parsed
// details and the relay hop that was used (nil in direct mode), or an error the
// caller classifies:
//
//   - selection.ErrNoRelay : privacy on, no (remaining) eligible relay
//   - *RelayHopError        : no relay tried this cycle reached the target
//   - any other error       : the target itself failed (down / error status /
//     malformed body / direct-mode transport error), including a
//     *RelayUpstreamUnreachableError when every relay that worked said the
//     target was down
//
// The caller treats the first two as "target reachability unknown — leave
// as-is" and the last as "target down".
func (s *ChainOperatorSource) probeDetailsWithRetry(
	ctx context.Context,
	client *DetailsClient,
	selAll []selection.Operator,
	target Operator,
	log *slog.Logger,
) (inject.OperatorDetails, *RelayHop, error) {
	if !s.Privacy {
		start := time.Now()
		resp, err := client.Fetch(ctx, target.BaseURL, nil)
		if err == nil {
			// Clean direct network-RTT sample to the target (no relay leg).
			s.RecordDirectRTT(RefOf(target), time.Since(start))
		}
		return resp, nil, err
	}

	excluded := make(map[NodeRef]bool)
	var lastHop *RelayHop
	var lastHopErr, lastErr error
	// A working relay's claim that the target is down. It outranks the hop
	// errors at the give-up, since it is the only evidence about the target.
	var upstreamHop *RelayHop
	var upstreamErr error
	var claimers []*RelayHop
	// settleClaims scores the relays that said the target was down, using what
	// this probe saw where it can. Scoring each claim as it came, against the
	// previous cycle's view of the target, would strike every honest relay the
	// probe rotates through when a target that was up has just gone down.
	settleClaims := func(reached bool) {
		for _, c := range claimers {
			switch {
			case reached:
				// Another relay reached the target: the claim was wrong.
				s.RecordRelayOutcome(c.RelayRef(), false)
			case len(claimers) > 1:
				// Working relays agree the target is down.
				s.RecordRelayOutcome(c.RelayRef(), true)
			default:
				// One uncorroborated claim: judge it by our last view.
				s.RecordRelayUpstreamUnreachable(c.RelayRef(), c.TargetRef())
			}
		}
	}
	giveUp := func() (inject.OperatorDetails, *RelayHop, error) {
		settleClaims(false)
		// A cancelled probe ended before the other relays were heard, so a
		// claim it holds is not the verdict that every working relay agreed.
		if upstreamErr != nil && ctx.Err() == nil {
			return inject.OperatorDetails{}, upstreamHop, upstreamErr
		}
		if lastHopErr == nil {
			return inject.OperatorDetails{}, nil, ctx.Err()
		}
		return inject.OperatorDetails{}, nil, lastHopErr
	}
	for attempt := 0; attempt < maxDiscoveryRelayAttempts; attempt++ {
		hop, relayErr := SelectRelayHopWeighted(
			CandidatesExcluding(selAll, excluded),
			target.Selection(),
			RandomRelaySeed(),
			func(relay NodeRef) (float64, bool) { return s.RelayLatencyForTarget(relay, RefOf(target)) },
		)
		if relayErr != nil {
			// No (remaining) eligible relay. If we've already tried a relay,
			// its failure or claim is the more informative signal; otherwise
			// surface ErrNoRelay so the caller logs the benign no-relay skip.
			// Either way we do NOT log a "retrying" line here — there is no
			// different relay to retry through; the caller's warning records
			// the give-up.
			if lastHopErr != nil || upstreamErr != nil {
				return giveUp()
			}
			return inject.OperatorDetails{}, nil, relayErr
		}
		if lastHop != nil {
			// We reach here only after a prior relay hop failed AND a *different*
			// relay was actually selected — so this rotation is real, unlike the
			// give-up path above. relay_operator_id/relay_node_id name the relay
			// we're about to retry through; failed_relay_* name the one that just
			// failed (so the relay ids visibly change across attempts).
			log.Debug("relay failed the details probe; retrying through a different relay",
				slog.Uint64("operator_id", target.ID),
				slog.Uint64("node_id", target.NodeID),
				slog.Uint64("failed_relay_operator_id", lastHop.RelayID),
				slog.Uint64("failed_relay_node_id", lastHop.RelayNodeID),
				relayLogAttr(hop),
				slog.Any("err", lastErr))
		}
		start := time.Now()
		resp, err := client.Fetch(ctx, target.BaseURL, hop)
		if err == nil {
			// The relay forwarded this probe successfully (regardless of what the
			// target returned) — clear its forward-failure streak so a recovered
			// relay returns to the preferred tier, and record the full
			// browser→relay→target→back RTT for latency-weighted relay selection.
			// A 2xx with a bad body earns both too (below); a forwarded error
			// status earns neither, as in the TypeScript SDK.
			s.RecordRelayOutcome(hop.RelayRef(), true)
			s.RecordRelayedRTT(hop.RelayRef(), hop.TargetRef(), time.Since(start))
			settleClaims(true)
			return resp, hop, nil
		}
		var hopErr *RelayHopError
		if errors.As(err, &hopErr) {
			// The relay node, not the target, was unreachable. Deprioritize it for
			// next cycle (both the cross-cycle reachability hint and the per-relay
			// forward-reputation streak) and exclude it from this cycle's retries,
			// then rotate on. All three key by the relay's (operator id, node id):
			// a dead node never tars a healthy sibling under the same operator, and
			// a working sibling stays eligible for the very next attempt.
			//
			// Our own deadline charges nobody; the relay is only skipped for
			// this probe. A cancelled caller ends the probe.
			if !hopErr.CallerAborted {
				s.recordReachable(hop.RelayRef(), false)
				s.RecordRelayOutcome(hop.RelayRef(), false)
			}
			excluded[hop.RelayRef()] = true
			lastHop, lastHopErr, lastErr = hop, err, err
			if ctx.Err() != nil {
				return giveUp()
			}
			continue
		}
		var upErr *RelayUpstreamUnreachableError
		if errors.As(err, &upErr) {
			// The relay works but says the target is down. Try a relay that
			// may reach it. Not a reachability mark: the relay answered us fine.
			claimers = append(claimers, hop)
			excluded[hop.RelayRef()] = true
			lastHop, lastErr = hop, err
			upstreamHop, upstreamErr = hop, err
			continue
		}
		var bodyErr *DetailsBodyError
		if errors.As(err, &bodyErr) {
			// A 2xx the target sent: the relay forwarded it, whatever the body.
			s.RecordRelayOutcome(hop.RelayRef(), true)
			s.RecordRelayedRTT(hop.RelayRef(), hop.TargetRef(), time.Since(start))
		}
		// Target-side failure. Return it with the hop so the caller can name
		// the relay the target was (successfully) reached through.
		settleClaims(true)
		return resp, hop, err
	}
	// Exhausted the attempt budget, every attempt a relay failure.
	return giveUp()
}

// CandidatesExcluding returns ops without the relay nodes whose (operator id,
// node id) are in excluded, leaving ops untouched (a fresh slice) so the shared
// per-cycle snapshot the enrich goroutines read is never mutated. Excluding by
// node, not operator id, lets a retry go through a healthy sibling node of an
// operator whose other node just failed the hop. Returns ops as-is when nothing
// is excluded.
//
// Shared by the two relay-rotation loops: the discovery probe's
// (probeDetailsWithRetry, below) and the dispatch path's transient-failure retry
// (server.reserveWithTransientRetry) — both must rotate by the same rule, or a
// relay the probe has written off keeps being handed live traffic.
func CandidatesExcluding(ops []selection.Operator, excluded map[NodeRef]bool) []selection.Operator {
	if len(excluded) == 0 {
		return ops
	}
	out := make([]selection.Operator, 0, len(ops))
	for _, op := range ops {
		if !excluded[NodeRef{Op: op.ID, Node: op.NodeID}] {
			out = append(out, op)
		}
	}
	return out
}

// relayLogAttr names the relay an outbound probe was tunneled through as its
// (operator_id, node_id) pair, for pairing with the target's operator_id +
// node_id on the same log line. A relay is itself a single node, so it carries
// the same pair as any routing target. The keys are emitted flat as
// relay_operator_id + relay_node_id (slog inlines an empty-key group). A nil hop
// (direct route) yields the zero Attr, which slog drops. (Mirrors the server
// package's relayAttr; kept here so package zs needn't import it.)
func relayLogAttr(hop *RelayHop) slog.Attr {
	if hop == nil {
		return slog.Attr{}
	}
	return slog.Group("",
		slog.Uint64("relay_operator_id", hop.RelayID),
		slog.Uint64("relay_node_id", hop.RelayNodeID))
}

// probeAttestation runs the per-operator attestation probe + verify
// pass. Called from enrich() with the operator already populated
// (Reachable=true, Models/etc. up to date) and the parsed
// /v1/zs/details response.
//
// Failure modes:
//   - resp.TEE == nil → operator does not advertise TEE; op.TEE = nil,
//     return.
//   - TEEVerifier nil (Config.DisableTEE) → no TEE verification;
//     op.TEE = nil (treated as not-attested for routing). This is the
//     correct behavior for deployments that don't care about TEE.
//   - Fetch fails → op.TEE.Verified=false, FailureTag=fetch_failed.
//   - Verify fails → op.TEE.Verified=false, FailureTag from verdict.
//   - All checks pass → op.TEE.Verified=true, FailureTag empty.
//
// Verification failures don't mark the operator unreachable — the
// reserve / dispatch path still works for non-TEE traffic; only
// TEE-required requests filter this operator out.
func (s *ChainOperatorSource) probeAttestation(ctx context.Context, op *Operator, details inject.OperatorDetails, client *AttestationClient, hop *RelayHop, log *slog.Logger) {
	op.TEE = nil
	if details.TEE == nil {
		return
	}
	if s.TEEVerifier == nil {
		return
	}
	advertised := *details.TEE
	bundle, err := client.Fetch(ctx, op.BaseURL, advertised.EvidenceURL, hop)
	if err != nil {
		op.TEE = &TEEStatus{
			Mode:       advertised.Mode,
			AttestedAt: advertised.AttestedAt,
			VerifierID: tee.VerifierIDBuiltin,
			Verified:   false,
			FailureTag: tee.FailureFetchFailed,
		}
		log.Warn("operator attestation probe failed",
			slog.Uint64("operator_id", op.ID),
			slog.Uint64("node_id", op.NodeID),
			relayLogAttr(hop),
			slog.String("base_url", op.BaseURL),
			slog.String("mode", advertised.Mode),
			slog.Any("err", err),
		)
		return
	}
	verdict := s.TEEVerifier.Verify(ctx, advertised, bundle, op.TEENode())
	op.TEE = &TEEStatus{
		Mode:             advertised.Mode,
		AttestedAt:       verdict.AttestedAt,
		VerifierID:       verdict.VerifierID,
		Verified:         verdict.Pass,
		FailureTag:       verdict.FailureTag,
		AttestedModelIDs: verdict.AttestedModelIDs,
	}
	if !verdict.Pass {
		log.Warn("operator attestation verification failed",
			slog.Uint64("operator_id", op.ID),
			slog.Uint64("node_id", op.NodeID),
			relayLogAttr(hop),
			slog.String("mode", advertised.Mode),
			slog.String("failure_tag", verdict.FailureTag),
		)
	}
}

// resolveOperatorNode projects one (operator, node) record pair into a
// routable Operator: identity (operator id, node id, owner, nfd) from
// the operator box; the parsed age recipient, Ed25519 signing key, validated
// base URL, and per-node reliability metrics from the node box. Reachable /
// Models / BuiltinTools are left unset — the enrichment pass populates those
// from the node's /v1/zs/details probe. currentDay drives the windowed
// revenue reads off the node's 30-day ring.
func resolveOperatorNode(op escrow.OperatorRecord, node escrow.NodeRecord, currentDay uint64) (Operator, error) {
	// The on-chain NodeRecord.EncryptionPubKey (the legacy long-lived "anchor"
	// age recipient) is no longer read: mandatory forward secrecy seals only to
	// the node's signed ephemeral recipient, fetched + verified per cycle in
	// applyEphemeralAdvertisement. The field is removed from the contract in a
	// follow-up fresh deploy (W1); until then it is simply ignored here.
	signingKey, err := ticket.DecodeAlgorandAddress(node.SigningAddr)
	if err != nil {
		return Operator{}, fmt.Errorf("operator %d node %d: decode signing addr: %w", op.ID, node.NodeID, err)
	}
	baseURL := strings.TrimRight(node.BaseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return Operator{}, fmt.Errorf("operator %d node %d: base_url %q must start with http:// or https://", op.ID, node.NodeID, baseURL)
	}
	return Operator{
		ID:               op.ID,
		NodeID:           node.NodeID,
		NFDAppID:         op.NFDAppID,
		OwnerAddr:        op.OwnerAddr,
		SigningAddr:      node.SigningAddr,
		TicketSigningKey: signingKey,
		BaseURL:          baseURL,
		Staging:          node.Staging != 0, // on-chain NodeRecord.staging (0=production)
		// Per-node reliability metrics (the operator rollup is the sum across
		// its nodes; the proxy lists nodes, so it surfaces the node's own).
		Metrics: OperatorMetrics{
			LastActivityAt:            node.LastActivityAt,
			TicketsOpened:             node.TicketsOpened,
			TicketsSettled:            node.TicketsSettled,
			TicketsLapsedSettled:      node.TicketsLapsedSettled,
			TicketsRefundedInactive:   node.TicketsRefundedInactive,
			TicketsProtested:          node.TicketsProtested,
			TicketsFrozenDispute:      node.TicketsFrozenDispute,
			TotalRefundedInactiveUsdc: node.TotalRefundedInactiveUsdc,
			TotalProtestedUsdc:        node.TotalProtestedUsdc,
			TotalFrozenDisputeUsdc:    node.TotalFrozenDisputeUsdc,
			LatencyTotalMs:            node.LatencyTotalMs,
			LatencyEwmaMs:             node.LatencyEwmaMs,
			LatencySamples:            node.LatencySamples,
			TokensPerSecEwma:          node.TokensPerSecEwma,
			TotalRevenueGross:         node.TotalRevenueGross,
			Revenue24hUsdc:            node.Revenue24h(currentDay),
			Revenue7dUsdc:             node.Revenue7d(currentDay),
			Revenue30dUsdc:            node.Revenue30d(currentDay),
		},
	}, nil
}
