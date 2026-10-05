/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"crypto/ed25519"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// BuiltinToolDef is the proxy-local mirror of a node's advertised
// built-in tool. The node advertises type-only entries on
// /v1/zs/details (SPEC §3d — name/description/parameters stay
// node-internal), so the mirror carries just the type, which is all the
// proxy needs for capability filtering, dedup, and re-advertising on its
// own aggregate endpoint.
type BuiltinToolDef struct {
	Type string
}

// Operator is a single NODE the proxy can dispatch to — this is the routing
// tier, where "the thing I dispatch to" collapses to one endpoint addressed by
// the (ID, NodeID) pair. It carries every piece of material the proxy needs
// *per-request*: the age recipient to encrypt the request envelope to, the
// Ed25519 public key to verify tickets with, the HTTP base URL where reserve +
// sealed requests are sent, and the set of models the operator will serve.
//
// SPEC.md § 3 "Key material" is authoritative for what the identity fields mean
// and how each rotates — operator id vs node id, the cold OwnerAddr (settle
// payout, rotates via updateOperator) vs the hot SigningAddr (signs tickets on
// the node, rotates independently via updateNode). Don't restate those rules
// here; the split between operator-level and node-level concerns is in the
// workspace AGENTS.md.
//
// TicketSigningKey is the one identity field with no on-chain counterpart: it
// is cached at registry-load time as the ed25519 public key decoded from
// SigningAddr, so Ticket.Verify runs without a decode per request.
type Operator struct {
	ID uint64
	// NodeID is the serving node's id within ID (operator/node split). A
	// proxy.Operator is a single NODE: ID+OwnerAddr+NFDAppID come from the
	// operator box, while NodeID+SigningAddr+BaseURL+Metrics are the node's.
	// The routing primary key is (ID, NodeID); affinity/relay address by both.
	NodeID           uint64
	NFDAppID         uint64 // 0 if unset (operator-level)
	OwnerAddr        string
	SigningAddr      string
	TicketSigningKey ed25519.PublicKey
	BaseURL          string // node root URL; e.g. "http://node.example:9090"
	Models           []string

	// Staging mirrors the node's on-chain NodeRecord.staging flag: a node its
	// operator brought up for testing and wants held out of production target
	// selection. Set from escrow.NodeRecord in resolveOperatorNode (false for a
	// node predating the field) and projected into selection.Operator.Staging by
	// Selection(); SelectTargets then drops it unless the request opts in via
	// Constraints.AllowStaging (proxy: zs.allow_staging / --allow-staging).
	Staging bool

	// SignerSpendableMicroAlgos is SigningAddr's spendable ALGO (amount −
	// min-balance), filled by ChainOperatorSource on every chain read — see
	// signer_balance.go. nil = never read successfully, which routes (fail
	// open). Projected into selection.Operator, where SelectTargets drops a node
	// below selection.MinSignerSpendableMicroAlgos. Treat the pointee as
	// immutable: snapshots share it.
	SignerSpendableMicroAlgos *uint64

	// EphemeralRecipient / EphemeralRecipientPubkey / EphemeralExpiry /
	// EphemeralIssuedAt carry the operator's signed short-lived age recipient
	// (mandatory forward secrecy by key-erasure — SPEC.md § 3c, § 4, § 8). They
	// are populated by the enrich pass ONLY after the advertised block has been
	// verified against the on-chain signing key
	// (ticket.EphemeralAdvertisement.Verify under TicketSigningKey) and found
	// in-policy + unexpired; a forged / wrong-operator / over-long / expired
	// advertisement leaves them at their zero value. There is NO long-lived
	// anchor: when EphemeralRecipient is nil (or EphemeralExpiry has since
	// passed) there is no seal target, so SealRecipient returns errNoEphemeral
	// and the dispatcher skips the candidate (fail closed).
	//
	//   - EphemeralRecipient is the parsed age recipient to seal to.
	//   - EphemeralRecipientPubkey is its canonical age1… string (kept
	//     alongside the parsed form for logging / diagnostics).
	//   - EphemeralExpiry is the advertised unix-seconds expiry. It backs
	//     the cheap re-check in SealRecipient (no re-verify) so a request
	//     never seals to a recipient that has expired since enrich ran.
	//   - EphemeralIssuedAt is the signed mint time (unix seconds), kept for
	//     relay-staleness attribution (ticket.EphemeralAdvertisement.Stale)
	//     and diagnostics.
	EphemeralRecipient       age.Recipient
	EphemeralRecipientPubkey string
	EphemeralExpiry          int64
	EphemeralIssuedAt        int64

	// ModelCapacities is the operator's declared per-model sizing
	// envelope: context window + optional per-model output cap. It's
	// consulted by sizing.Fits before the reserve loop so requests that
	// can't fit are skipped cheaply instead of round-tripping a reserve.
	//
	// A missing entry for (operator, model) is treated as *unbounded* —
	// the sizing filter becomes a no-op. This preserves today's routing
	// behavior for operators that haven't declared capacities yet and
	// makes the rollout incremental. Once capacities are populated, the
	// filter tightens automatically.
	ModelCapacities map[string]ModelCapacity

	// BuiltinTools is the zs built-in tool advertisement the operator
	// publishes on /v1/zs/details. Populated opportunistically at
	// startup by FetchDetails; nil means the proxy couldn't reach the
	// endpoint (older node, network blip) and the operator is assumed
	// to support nothing. Routing treats nil as "don't prefer but don't
	// exclude" — the request may still succeed if the operator in fact
	// runs the tool, or fail with 400 unknown_builtin_tool if it doesn't.
	BuiltinTools []BuiltinToolDef

	// MaxToolIters is the operator's advertised cap on chat→tool→chat
	// iterations. Used to size a tool-carrying reserve's input_count as
	// body_bound + MaxToolIters × ToolHeadroomPerIteration (SPEC §3a), so the
	// escrow covers the input a tool loop accumulates without reserving the
	// whole context window. 0 means unknown (pre-tool node) — no headroom is
	// added, and the node's inference-time budget check backstops the tail.
	MaxToolIters int

	// ToolHeadroomPerIteration is the operator's advertised per-tool-loop-
	// iteration input-token headroom (SPEC §3a), sized from its tools' typical
	// result size. 0 (pre-field node) → the proxy uses a built-in default.
	ToolHeadroomPerIteration uint64

	// NodeVersion is the build id the operator advertises on
	// /v1/zs/details, "<release>+<commit>[-dirty] [<commit-time>]" —
	// e.g. "0.21.0+abc1234 [2026-05-03T12:00:00Z]". Opaque here: never
	// parsed, split, compared for order, or routed on. It is surfaced
	// via the proxy's aggregate /v1/zs/details so dashboards and the
	// TUI can see which builds are deployed, and `collectNodeVersions`
	// dedupes WHOLE strings — which is the reason this side reasons on
	// none of its structure. Two "-dirty" builds of different working
	// trees at one commit render identically and so collapse to one
	// entry; the fleet then reads as more uniform than it is. That is
	// tolerable only because the field is advisory. Empty on operators
	// whose probe hasn't landed yet or whose node pre-dates the field.
	NodeVersion string

	// ProtoVersion is the wire-protocol generation the operator
	// advertises on /v1/zs/details, in "<major>.<minor>" form (see
	// proto/go/wire/version.go and SPEC.md §3c "Protocol version
	// negotiation"). Unlike NodeVersion (build id, informational),
	// this IS parsed: pickCandidates filters operators whose advertised
	// major differs from wire.ProtoVersion. Empty on operators whose
	// probe hasn't landed yet or whose node pre-dates the field; absent
	// values are treated as wire.LegacyProtoVersion for compatibility,
	// so the existing fleet remains routable until the next major bump.
	ProtoVersion string

	// Reachable reports whether the most recent /v1/zs/details probe
	// against this operator succeeded. The registry refresh loop sets
	// it each cycle and logs reachable↔unreachable transitions; dispatch
	// still attempts unreachable operators as a fallback since the
	// reserve endpoint can be up while details is down. Zero value
	// (false) is safe: an operator is treated as unknown until its
	// first probe completes.
	Reachable bool

	// LastRefreshAt records when the registry last probed this operator.
	// Zero time means "never successfully enriched" — the operator was
	// discovered on-chain but its details endpoint has never replied
	// within the probe window.
	LastRefreshAt time.Time

	// Probed reports whether this node's /v1/zs/details endpoint was actually
	// contacted this refresh cycle (a target response arrived — success or a
	// target-side failure). It is a TRANSIENT this-cycle signal: false on a node
	// bounded probing skipped, and false on a node whose probe never reached the
	// target (no eligible relay / all relay hops down). It is NOT carried forward
	// and NOT persisted. The discovery gate keys off it: a node probed this cycle
	// trusts the fresh Reachable result, while a node NOT probed falls back to the
	// carry window (ReachableAsOf) — so a freshly-confirmed-down node drops from
	// discovery promptly, but a fine-but-unprobed node keeps advertising.
	Probed bool

	// ReachableAsOf is the time of the most recent SUCCESSFUL /v1/zs/details
	// probe (i.e. the last moment this node's capabilities were confirmed
	// live). Unlike LastRefreshAt (stamped on every probe attempt) it advances
	// only on success, and unlike Reachable (a this-cycle bool) it is carried
	// forward across cycles for nodes not probed-good this cycle. It is the
	// clock the registry's carry window keys off: the discovery surfaces
	// advertise a node's models while now-ReachableAsOf < max_carry_age, so a
	// node stays routable/advertised across the gaps between probes that bounded
	// probing introduces — and ages out of both discovery and dispatch
	// once its last-good passes the window. Zero means never confirmed live.
	ReachableAsOf time.Time

	// TEE carries the result of the most recent attestation
	// verification for operators that advertise tee.mode != none on
	// /v1/zs/details. nil means either (a) the operator does not
	// advertise TEE, or (b) the attestation probe / verification has
	// not yet completed for this refresh cycle. Routing keys on
	// IsTEEAttested(), which only returns true when the verdict
	// passed; populated-but-failed verdicts are kept for diagnostics
	// (failure tag is logged, surfaced on the operator dashboard) but
	// are treated as not-attested for filtering purposes.
	TEE *TEEStatus

	// Metrics is this NODE's reliability track record, read verbatim from the
	// on-chain NodeRecord at registry-load time (a proxy.Operator is a single
	// node — see the type docblock). The operator-level rollup is the sum
	// across its nodes; the proxy lists nodes, so it surfaces each node's own.
	// Surfaced on /v1/zs/operators so dashboards / clients can rank nodes by
	// success rate, latency, and revenue without a chain round-trip per node.
	// Not consulted by routing today — purely an observability surface — but
	// available if a future selector wants to derank chronically unreliable
	// nodes.
	Metrics OperatorMetrics

	// MinChargeOutputTokens, MinChargeAlgoTxns, and MinChargeMicroUSDC
	// mirror the operator's advertised per-request minimum charge
	// (SPEC.md §3a "Minimum charge"). The floor is the larger of a
	// per-model token component and a flat µALGO component, where
	// outputRateMicroUSDCPer1M is the model's own output rate in
	// microUSDC per 1M tokens (Model.OutputUSDPer1M * 1e6):
	//
	//	tokenFloor_model = ceil(MinChargeOutputTokens *
	//	                        outputRateMicroUSDCPer1M / 1e6)
	//	min_price_model  = max(tokenFloor_model, MinChargeMicroUSDC)
	//
	// MinChargeOutputTokens is the reference output-token count
	// (default 1000; 0 = the token component disabled). MinChargeAlgoTxns
	// is the µALGO-recovery count (0 = that component disabled, today's
	// default). MinChargeMicroUSDC is the current USD value of the µALGO
	// component at the operator's most-recent oracle reading; 0 when it's
	// disabled or the operator's oracle is unhealthy. All populated by
	// FetchDetails from /v1/zs/details; surfaced on /v1/zs/operators.
	// The authoritative per-request value for any given reserve is the
	// signed ticket's min_price.
	MinChargeOutputTokens uint64
	MinChargeAlgoTxns     uint64
	MinChargeMicroUSDC    uint64
}

// OperatorMetrics mirrors the per-NODE reliability tail of the on-chain
// ZeroSignalEscrow.NodeRecord (see proto/SPEC.md §3c "On-chain reliability
// metrics"). (Named OperatorMetrics, not NodeMetrics, for consistency with the
// package's "a proxy.Operator is a single node" convention.) It's re-declared
// here — rather than embedding escrow.NodeRecord — so callers that just read
// the registry don't pull in the proto/escrow package. Populated per node from
// the chain record, so values are current as of the last registry refresh, not
// request time.
//
// All *Usdc amounts are microUSDC; all *Ms latencies are milliseconds.
// Counters are lifetime-monotonic and survive operator key rotation.
type OperatorMetrics struct {
	// LastActivityAt is the unix-seconds timestamp of the operator's
	// most recent ticket-touching state change (open / settle finalize /
	// refund / protest / settle-disagreement freeze). 0 = no activity
	// since registration.
	LastActivityAt uint64

	TicketsOpened           uint64
	TicketsSettled          uint64 // co-signed clean settle — the success counter
	TicketsLapsedSettled    uint64 // force-finalized after payer silence (operator still paid)
	TicketsRefundedInactive uint64 // operator never claimed — operator-side fail
	TicketsProtested        uint64 // frozen via payer protest — tracked neutrally
	TicketsFrozenDispute    uint64 // frozen via settle disagreement — tracked neutrally

	// Dollar value at stake on each failure path.
	TotalRefundedInactiveUsdc uint64 // Σ ticket.maxPrice on refundInactive
	TotalProtestedUsdc        uint64 // Σ amountCharged on protest
	TotalFrozenDisputeUsdc    uint64 // Σ ticket.pendingAmount on settle-disagreement freeze

	LatencyTotalMs uint64 // cumulative co-signed TTFT (the ttftMs settle arg) over TOKEN-output settles only
	LatencyEwmaMs  uint64 // EWMA(N=10) of co-signed TTFT (time-to-first-token)

	// LatencySamples is the count of settlements folded into LatencyTotalMs —
	// the exact denominator for the mean. The contract bumps it inside the same
	// token-output guard as the numerator, so it is deliberately NOT
	// TicketsSettled + TicketsLapsedSettled: those count image / video settles
	// that never contributed a TTFT. 0 = no token settle recorded yet.
	LatencySamples uint64

	// TokensPerSecEwma is the EWMA(N=10) of generation throughput (output
	// tokens / sec) the contract folds per finalized settlement from the
	// decode half of the co-signed timing slot. Sampled only on streamed
	// settles with a decode window and output tokens; 0 = no qualifying
	// sample yet.
	TokensPerSecEwma uint64

	TotalRevenueGross uint64 // Σ amountCharged over finalized settlements

	// Windowed gross revenue, computed from the on-chain 30-day ring at
	// registry-load time. Accurate to within one refresh interval —
	// the ring is day-granular, so a few minutes of staleness on the
	// "current day" cannot move a window.
	Revenue24hUsdc uint64
	Revenue7dUsdc  uint64
	Revenue30dUsdc uint64
}

// LatencyMeanMs returns the mean co-signed TTFT (time-to-first-token) over the
// settles that actually reported one, or 0 when no such sample exists yet.
//
// The denominator is LatencySamples, not the settled population: TTFT is folded
// only on token-output settles, so an operator serving the dedicated image /
// video routes accrues settles that move no numerator. Dividing by those
// understates the mean.
func (m OperatorMetrics) LatencyMeanMs() uint64 {
	if m.LatencySamples == 0 {
		return 0
	}
	return m.LatencyTotalMs / m.LatencySamples
}

// TEEStatus captures the proxy's verdict on an operator's confidential-
// mode attestation. Verified is the routing-relevant bit; everything
// else exists for observability (dashboards, debug logs, alerting).
// FailureTag is empty when Verified is true and one of the canonical
// verifier failure tags otherwise (see proto/TEE.md §4.3 and the tee
// package's Failure* constants for the full list).
type TEEStatus struct {
	Mode       string    // "stub" | "dstack-tdx" | "nvidia-cc-tdx" | "nvidia-cc-snp"
	AttestedAt time.Time // bundle.GeneratedAt of the verified evidence
	VerifierID string    // which verifier decided: "builtin" or "dstack-tdx"
	Verified   bool      // true when the most recent verdict passed
	FailureTag string    // empty when Verified; otherwise the verdict tag

	// AttestedModelIDs is tee.Verdict.AttestedModelIDs from the most recent
	// verdict; nil unless that verdict passed. See tee.Verdict for nil versus
	// empty. Shown on /v1/zs/operators, never used for routing: the list is
	// the catalog at the node's last mint.
	AttestedModelIDs []string
}

// TEENode is what a tee.Verifier checks o's evidence against.
func (o Operator) TEENode() tee.Node {
	return tee.Node{OperatorID: o.ID, NodeID: o.NodeID, EphemeralRecipientPubkey: o.EphemeralRecipientPubkey}
}

// IsTEEAttested reports whether the operator has a current
// successful TEE verdict — the only condition under which a routing
// filter that requires TEE will keep this operator in the candidate
// list. Operators that don't advertise TEE (TEE == nil) and operators
// whose verification failed (TEE.Verified == false) both return false.
func (o Operator) IsTEEAttested() bool {
	return o.TEE != nil && o.TEE.Verified
}

// SealRecipient returns the age recipient an inbound request envelope (reserve
// or inference) must be sealed to: the operator's signed, unexpired ephemeral
// recipient. Mandatory forward secrecy — there is no anchor fallback — so when
// no valid fresh ephemeral exists it returns errNoEphemeral and the caller fails
// closed (skips the candidate), never downgrading to a durable key.
//
// The enrich pass already verified the ephemeral advertisement against the
// on-chain signing key, so this is a cheap re-check — NOT a re-verify: it
// returns the ephemeral only when one is present (EphemeralRecipient != nil)
// AND it has not expired as of now (now < EphemeralExpiry). The expiry re-check
// matters because enrich can run minutes before a request; a recipient that
// lapsed in the interim must not be used (the node may have already zeroed the
// matching identity).
func (o Operator) SealRecipient(now time.Time) (age.Recipient, error) {
	if o.EphemeralRecipient != nil && now.Before(time.Unix(o.EphemeralExpiry, 0)) {
		return o.EphemeralRecipient, nil
	}
	return nil, errNoEphemeral
}

// SupportsBuiltinTool reports whether this operator advertises the
// given zs tool type. An operator with no declared BuiltinTools
// (nil slice) returns false — the capability data is missing and the
// proxy only "prefers" operators that positively advertise.
func (o Operator) SupportsBuiltinTool(toolType string) bool {
	for _, t := range o.BuiltinTools {
		if t.Type == toolType {
			return true
		}
	}
	return false
}

// SupportsAllBuiltinTools is the multi-tool variant: returns true only
// if every tool in `needed` appears in BuiltinTools. Used by dispatch
// to rank candidates.
func (o Operator) SupportsAllBuiltinTools(needed []string) bool {
	if len(needed) == 0 {
		return true
	}
	for _, n := range needed {
		if !o.SupportsBuiltinTool(n) {
			return false
		}
	}
	return true
}

// ModelCapacity declares an operator's capability envelope for one model.
// ContextWindow bounds (input_tokens + max_output_tokens); MaxOutputTokens
// bounds max_output_tokens on its own (when the operator's effective
// output cap is tighter than its context window).
// InputModalities and OutputModalities list content types the model
// accepts/produces (e.g. "text", "image", "audio", "video"). A nil slice
// means the operator didn't declare modalities — treat as text-only for
// filtering, but don't hard-reject requests since the node is the
// authoritative gatekeeper.
//
// InputUSDPer1M / OutputUSDPer1M are the operator's advertised USD/1M
// inference rates copied verbatim from /v1/zs/details. They are
// informational — the *authoritative* per-request rate is the
// microUSDC/1M value the node signs into the ticket at reserve time
// (see ticket.Ticket.InputRate/OutputRate). Surfaced here so the proxy
// can publish a pricing surface for clients to browse before reserving.
// Zero means the operator did not declare a rate.
type ModelCapacity struct {
	ContextWindow    uint64
	MaxOutputTokens  uint64   // 0 = unset, no separate cap beyond ContextWindow
	InputModalities  []string // nil = undeclared
	OutputModalities []string // nil = undeclared
	InputUSDPer1M    float64  // 0 = undeclared
	OutputUSDPer1M   float64  // 0 = undeclared
	// CacheReadUSDPer1M is the operator's advertised discounted USD/1M rate
	// for the cache-read subset of input tokens (details cache_read_rate_usd_per_1m).
	// A *float64: nil = the operator advertised no cache discount (its resolved
	// cache-read rate equals its input rate); a non-nil pointer is a real
	// discount, and a pointed-to 0 means "free cached reads" (the maximum
	// discount — distinct from nil). Advertising surface only; the
	// authoritative per-request cache-read rate is signed into the ticket.
	// AllModelDetails surfaces the lowest advertised discount across operators
	// ("from $X"), like the token rates.
	CacheReadUSDPer1M *float64
	// LongContextThresholdTokens + the three LongContext*USDPer1M rates are the
	// operator's advertised long-context (surcharge) tier copied verbatim from
	// /v1/zs/details (xAI's context-size cliff): a prompt whose input tokens reach
	// the threshold is billed at the high rates for the whole request. Threshold 0
	// (the common case) means the operator advertises no tier. The high
	// input/output rates are *float64 (nil when no tier); the high cache-read rate
	// mirrors CacheReadUSDPer1M's nil-vs-zero semantics for the high tier.
	// Advertising surface only — the authoritative per-request rates are the
	// tier-resolved microUSDC rates signed into the ticket, and per-request
	// verification (verifyReservePrice) feeds these into pricing.Advertised.
	// AllModelDetails takes a display-only cross-operator min ("from $X"), like the
	// token rates.
	LongContextThresholdTokens   uint64
	LongContextInputUSDPer1M     *float64
	LongContextOutputUSDPer1M    *float64
	LongContextCacheReadUSDPer1M *float64
	// Reasoning / ToolUse / Tags are the model capability + label fields
	// copied verbatim from /v1/zs/details. nil = the operator didn't
	// advertise it. AllModelDetails unions these across operators (OR the
	// capability flags, union the lists) for the proxy's aggregate surface.
	Reasoning *inject.ModelReasoning
	ToolUse   *bool
	Tags      []string
	// Coordinates is the model-taxonomy descriptor copied verbatim from the
	// operator's bare /v1/zs/details list (the LEAN config+runner signal —
	// the richer HF-discovered coordinates ride the per-node ?expand deep path
	// and are never aggregated). nil = the operator advertised none.
	// AllModelDetails surfaces a per-field majority across operators (omitting a
	// field when they disagree), never a false consensus. Advisory — never
	// drives selection/pricing/settlement.
	Coordinates *inject.ModelCoordinates
	// WeightsDigest / WeightsUnverifiable are this operator's compact
	// weights-integrity signal copied verbatim from its bare /v1/zs/details
	// list (the HOT pair — the verbose unverifiable-reason rides the per-node
	// ?expand=digest deep path and is never probed here). WeightsDigest is the
	// "sha256:<hex>" of the served weights; WeightsUnverifiable marks a
	// remote/no-local-weights backend. AllModelDetails folds these into a
	// cross-operator consensus + WeightsMismatch flag (≥2 distinct digests).
	// A mismatch is "weights differ", not fraud, and never drives pricing or
	// settlement. It DOES drive one soft routing move: the dispatch path demotes
	// a candidate whose digest contradicts a ≥2-distinct-OWNER peer consensus to
	// the tail of the candidate list — see weights_trust.go for
	// what that catches and what it doesn't. The aggregate above is display
	// only; the demotion is computed per request from per-operator evidence.
	WeightsDigest       string
	WeightsUnverifiable bool
	// Source / CanonicalID are this operator's model IDENTITY keys, copied
	// verbatim from its bare /v1/zs/details list. Source is the declared HF
	// artifact pointer ("hf:org/model[@revision]"); CanonicalID is the frontier
	// whitelist canonical the node emits for a CLOSED-weights model that has no
	// HF repo (grok/gpt/claude/gemini) — present only when Source is empty (see
	// inject.OperatorDetailsModel.CanonicalID). AllModelDetails folds each into a
	// cross-operator CONSENSUS (the single value when the operators that declare
	// one agree, omitted on disagreement), so a consumer of the proxy aggregate
	// can group spellings the same way the client does off per-operator details.
	// Advisory — never drives selection/pricing/settlement.
	Source      string
	CanonicalID string
	// Retention is this operator's upstream data-retention tier for the model,
	// taken from its bare /v1/zs/details list and FILTERED through
	// inject.IsKnownRetention — one of inject.Retention*, or "" for unknown. A
	// value this build does not recognise becomes "": the field is
	// node-authored, so carrying an unrecognised string through would let a node
	// print its own reassuring label into whatever renders this. See
	// inject.OperatorDetailsModel.Retention for the ladder and its trust
	// ceiling; the short version is that the ordering is by EVIDENCE, every tier
	// below tee_attested describes only the destination, and "" means unknown
	// rather than "retains".
	//
	// DISPLAY ONLY, and deliberately NOT aggregated into a cross-operator
	// consensus the way Source / CanonicalID / WeightsDigest are. Those describe
	// the MODEL, so operators serving it should agree and a disagreement is
	// information. This describes each operator's own deployment, so operators
	// SHOULD differ — folding it into a majority would report a property of the
	// fleet as if it were a property of the node you are about to dispatch to,
	// which is the one reading that matters. It also never drives selection: it
	// is node-authored with no peer corroboration, unlike WeightsDigest.
	Retention string
	// ImageToolRateMicroUSDC / ImageEditToolRateMicroUSDC are the per-tool
	// microUSDC billing basis (chat-model zs_image_generation /
	// zs_image_edit): the worst-case microUSDC cost of one image the gen /
	// edit tool may produce (imageRate × Factor(cap)). When non-zero the dispatch
	// loop offers the tool and sets the image-tool budget; the node adds
	// max_n × this cap to MaxPrice additively. Kept SEPARATE from the dedicated
	// ImageRateMicroUSDC so a chat model offering the tools is never selected for
	// the dedicated /v1/images/* routes.
	ImageToolRateMicroUSDC     uint64
	ImageEditToolRateMicroUSDC uint64
	// ImageToolBaseMicroUSDC / ImageEditToolBaseMicroUSDC are the per-tool
	// REPRESENTATIVE price: what one image costs when the model names no
	// size/quality (the operator's rate resolved through its default_size /
	// default_quality). Display only — sizing uses the cap above. A client pairs
	// base→cap into a price range, so an operator that pinned its tool to a tier
	// shows one honest price instead of a range starting at a unit rate nothing
	// is billed at.
	ImageToolBaseMicroUSDC     uint64
	ImageEditToolBaseMicroUSDC uint64
	// ImageRateMicroUSDC / ImageEditRateMicroUSDC are the microUSDC price of one
	// 1024²-standard image on the dedicated gen / edit route. When non-zero, the
	// dispatch loop sizes the reserve as imageprice.CostMicroUSDC(rate, n, size,
	// quality) — exact, size-aware — and the node bills the identical figure.
	ImageRateMicroUSDC     uint64
	ImageEditRateMicroUSDC uint64
	// Dedicated-route display companions to the rates above: the price a caller
	// who sends no size/quality actually pays (the rate resolved through the
	// operator's default_size/default_quality) and the ceiling its
	// max_size/max_quality impose. Both are 0 when the operator declares no such
	// knobs, and Cap is additionally 0 when it declares no cap at all — an
	// uncapped route has no ceiling, since the caller picks the size. Display
	// only: reserve sizing and price ordering stay on the *Rate* base.
	ImageDefaultMicroUSDC     uint64
	ImageEditDefaultMicroUSDC uint64
	ImageCapMicroUSDC         uint64
	ImageEditCapMicroUSDC     uint64
	// AdvertisesImageGen / AdvertisesImageEdit mirror the node's price-
	// independent eligibility flags (details `serves_image_gen` /
	// `serves_image_edit`). They make a deliberately-free rate route (rate == 0,
	// dropped by omitempty) discoverable — a 0 rate is otherwise
	// indistinguishable from a non-image model.
	AdvertisesImageGen  bool
	AdvertisesImageEdit bool

	// Per-call tool pricing (SPEC.md "Per-call tool pricing"), copied verbatim
	// from /v1/zs/details. The node folds a per-call tool-fee headroom into
	// max_price for a tool-pricing model; verifyReservePrice REPRODUCES that
	// headroom from these fields (via pricing.ToolFeeReserveMicroUSDC) so the
	// max_price recompute still reconciles and the advertised-rate / min-charge /
	// cache-read bounds keep running — rather than skipping verification and
	// leaving a payer-overcharge hole.
	//   - ToolCallRatesMicroUSDC: canonical tool name → per-call microUSDC, for
	//     both vendor server-side tools and node zs_ built-ins.
	//   - VendorToolCatchAllMicroUSDC: blanket per-call price for an unnamed
	//     vendor tool (never applies to zs_).
	//   - VendorToolCallCap / VendorToolTokensPerCall: the per-request vendor call
	//     cap and its estimated per-call input-token inflation.
	ToolCallRatesMicroUSDC      map[string]uint64
	VendorToolCatchAllMicroUSDC uint64
	VendorToolCallCap           uint64
	VendorToolTokensPerCall     uint64
}

// MaxZsToolRateMicroUSDC / MaxVendorToolRateMicroUSDC return the priciest
// per-call zs_ / vendor rate advertised for this model (vendor includes the
// catch-all), used to reproduce the node's tool-fee reserve headroom. A zs_-
// prefixed key is a node built-in; any other key is a vendor tool.
func (c ModelCapacity) MaxZsToolRateMicroUSDC() uint64 {
	var max uint64
	for name, r := range c.ToolCallRatesMicroUSDC {
		if isZsToolName(name) && r > max {
			max = r
		}
	}
	return max
}

func (c ModelCapacity) MaxVendorToolRateMicroUSDC() uint64 {
	max := c.VendorToolCatchAllMicroUSDC
	for name, r := range c.ToolCallRatesMicroUSDC {
		if !isZsToolName(name) && r > max {
			max = r
		}
	}
	return max
}

// isZsToolName reports whether a canonical tool name is a node zs_ built-in
// (prefix "zs_"), matching proto tools.IsBuiltinToolType without the import.
func isZsToolName(name string) bool {
	return len(name) >= 3 && name[:3] == "zs_"
}

// ServesImageGen / ServesImageEdit report whether this model serves the
// dedicated /v1/images/{generations,edits} route (the explicit Advertises*
// flag is authoritative; a non-zero rate is the fallback signal). microUSDC
// rate is the only billing basis, so a served route is always rate-priced —
// a 0 rate on a served route means "free", not "no rate".
func (c ModelCapacity) ServesImageGen() bool {
	return c.AdvertisesImageGen || c.ImageRateMicroUSDC > 0
}
func (c ModelCapacity) ServesImageEdit() bool {
	return c.AdvertisesImageEdit || c.ImageEditRateMicroUSDC > 0
}

// ServesModel reports whether this operator's published model list
// includes model. An empty Models list means "serves nothing" — a node
// advertising zero models is not a routing candidate for ANY model, matching
// the node's own /v1/zs/details contract (that list is the exact set of
// reservable models, so an empty list means every reserve would be refused).
//
// This deliberately does NOT wildcard on Reachable. A reachable node with an
// empty catalog — e.g. every model dropped by the node's provenance gate for
// lack of a source, or an upstream that momentarily discovered nothing — used
// to be treated as "serves everything", which made it a tried-then-rejected
// candidate for every model: wasted reserve round-trips plus a misleading
// operators_busy masking the real no_operator (the same class as the earlier
// "max_tokens=20000 → operators_busy" symptom, now closed for the reachable
// case too). The unreachable-empty case was already excluded.
//
// Mirrors github.com/TxnLab/zerosignal/go/selection.Operator.ServesModel
// byte-for-byte; the two must agree or the proxy and client would disagree on
// eligibility.
func (o Operator) ServesModel(model string) bool {
	for _, m := range o.Models {
		if m == model {
			return true
		}
	}
	return false
}

// SignerUnderfunded reports whether this node's signing account is known to be
// below the routing floor. The shared predicate, so discovery and dispatch
// agree with SelectTargets on the boundary.
func (o Operator) SignerUnderfunded() bool {
	return selection.SignerUnderfunded(o.SignerSpendableMicroAlgos)
}

// Selection projects this enriched operator onto the shared, transport-agnostic
// selection.Operator the proto selection policy ranks (SelectTargets /
// SelectRelay). Reliability metrics are intentionally dropped — the policy
// doesn't consult them. Advertised USD rates ARE projected (the policy
// price-sorts candidates by them) along with the dedicated-route image rates
// (the price sort on the image endpoints) and the in-loop image-tool factors
// (the per-model image-tool partition); all stay Go↔TS golden-vector-safe
// because the rates are only ever *compared*, never accumulated.
// ServesModel here and selection.Operator.ServesModel implement the same
// wildcard-when-reachable rule.
func (o Operator) Selection() selection.Operator {
	caps := make(map[string]selection.ModelCapacity, len(o.ModelCapacities))
	for m, c := range o.ModelCapacities {
		// selection.SelectTargets gates the image endpoints on the eligibility
		// flags and ORDERS them by the projected image rates (an image model's
		// token rates are 0, so the token sort can't rank them). The
		// authoritative per-image sizing still reads the rate off this
		// ModelCapacity in dispatch, not off the routing descriptor.
		caps[m] = selection.ModelCapacity{
			ContextWindow:       c.ContextWindow,
			MaxOutputTokens:     c.MaxOutputTokens,
			ServesImageGen:      c.ServesImageGen(),
			ServesImageEdit:     c.ServesImageEdit(),
			OffersImageGenTool:  c.ImageToolRateMicroUSDC > 0,
			OffersImageEditTool: c.ImageEditToolRateMicroUSDC > 0,
			InputUSDPer1M:       c.InputUSDPer1M,
			OutputUSDPer1M:      c.OutputUSDPer1M,
			// DORMANT: this used to let the derive-mode sizing filter raise the
			// proportionate max_output ceiling for reasoning models. There is one
			// ceiling now (selection.DefaultMaxOutputCeiling, the value that raise
			// used), so nothing reads it and no selection outcome depends on it.
			// Still projected because it is a serialized field of the descriptor
			// the golden vectors pin — deprecate, don't remove.
			ReasoningSupported:     c.Reasoning != nil && c.Reasoning.Supported,
			ImageRateMicroUSDC:     c.ImageRateMicroUSDC,
			ImageEditRateMicroUSDC: c.ImageEditRateMicroUSDC,
		}
	}
	tools := make([]string, 0, len(o.BuiltinTools))
	for _, t := range o.BuiltinTools {
		tools = append(tools, t.Type)
	}
	return selection.Operator{
		ID:              o.ID,
		NodeID:          o.NodeID,
		OwnerAddr:       o.OwnerAddr,
		BaseURL:         o.BaseURL,
		ProtoVersion:    o.ProtoVersion,
		Reachable:       o.Reachable,
		TEEAttested:     o.IsTEEAttested(),
		Staging:         o.Staging,
		Models:          o.Models,
		ModelCapacities: caps,
		BuiltinTools:    tools,
		// Shared pointer, never written through — see the field doc.
		SignerSpendableMicroAlgos: o.SignerSpendableMicroAlgos,
	}
}
