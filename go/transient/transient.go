/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package transient classifies a failed request as a retryable infrastructure
// fault or a terminal application-level one, and pins the retry schedule both
// callers pace themselves by. It is pure — status code in, verdict out — so the
// proxy and the client/ chat app treat a flaky CDN identically. Mirrored in
// proto/ts/src/transient and golden-vectored in proto/testdata/transient_vectors.json.
//
// Two entry points, both pure. Classify is the per-response verdict over
// (status, code). NarrowRelayed then refines an unattributed verdict using
// route evidence the response body cannot carry — whether a relay was in the
// path, whether it stamped wire.RelayHopHeader, and whether it is new enough
// that a missing marker means anything. Callers on a relayed path should run
// both; the split keeps Classify's two-argument golden-vector contract intact
// while still putting the narrowing rules under the same cross-language
// vectors, so the Go and TS ports cannot drift on either half.
//
// Why this exists: no zs component ever emits 504. A relaying node answers a
// failed forward with 502 relay_upstream_unreachable (see the relay package's
// code list, all 400/404/502/503) and otherwise copies the target's status
// verbatim. So a 502/503/504 carrying no recognized error code came from
// something OUTSIDE the protocol — an operator's CDN, ingress, or load balancer
// — and is exactly the class that resolves on its own within seconds, most
// visibly while a fleet rolls through a node update. Before this package such a
// response was indistinguishable from a deliberate refusal and got surfaced to
// the user as terminal.
//
// Deliberately NOT part of proto/go/selection: this is a per-response verdict,
// not an eligibility policy, and it feeds stateful app-side stores (relay
// reputation, target backoff) that are vantage-specific and can't be vectored.
// The classifier itself is pure, which is why it can live here at all.
package transient

import (
	"time"

	"github.com/TxnLab/zerosignal/go/relay"
)

// Attribution names which hop a retryable failure should be charged to. It
// drives the caller's reputation bookkeeping, and getting it wrong is worse
// than not recording anything: crediting a relay for its own broken front door
// keeps it in rotation, and charging a target for its relay's front door
// benches a node that is perfectly healthy.
type Attribution string

const (
	// AttrNone accompanies a non-retryable verdict.
	AttrNone Attribution = ""

	// AttrRelay means the relay itself failed and the target provably never saw
	// the request. This is the only attribution safe to retry AFTER escrow has
	// committed: the ticket cannot have been consumed, so re-sending the
	// byte-identical sealed envelope through a different relay can't collide
	// with an inference already running.
	AttrRelay Attribution = "relay"

	// AttrTarget means the target is implicated — either it answered with a
	// transient fault of its own, or a relay claimed it was unreachable. Callers
	// that keep a per-target backoff record it here.
	AttrTarget Attribution = "target"

	// AttrUnknown means the failure came from unattributable infrastructure: a
	// status with no recognized error code, i.e. a CDN / ingress / LB error page
	// rather than anything the protocol generated. Which hop's front door
	// produced it is unknowable FROM THE RESPONSE BODY ALONE, so callers MUST
	// NOT record a bare AttrUnknown against either party — neither credit nor
	// penalty.
	//
	// It is not always the last word, though: a caller holding route evidence
	// the body doesn't carry should run the verdict through NarrowRelayed
	// first, which resolves the common relayed cases (no response at all, or a
	// present/absent wire.RelayHopHeader from a relay new enough to set one).
	// A verdict that is STILL AttrUnknown after that narrowing is the genuinely
	// undecidable residue — let a rotation prove where the fault lies.
	AttrUnknown Attribution = "unknown"
)

// Verdict is the classification of one failed response.
type Verdict struct {
	// Retryable reports whether re-issuing the request could plausibly succeed
	// without the caller changing anything about it.
	Retryable bool `json:"retryable"`

	// Attribution names the hop to charge, and is AttrNone when !Retryable.
	Attribution Attribution `json:"attribution"`
}

// TransportFailureStatus is the status callers pass for a failure that never
// produced an HTTP response at all (dial error, TLS failure, connection reset,
// read timeout). Distinguishing it from a real status matters because the hop
// that failed is often known from context even though the response isn't: in
// relayed mode the caller connected to the relay, not the target, so a
// transport error is unambiguously a relay-hop fault and the caller may narrow
// AttrUnknown to AttrRelay itself.
const TransportFailureStatus = 0

// retryableStatuses are the HTTP statuses that, absent a recognized protocol
// error code, mean "infrastructure between us and the node is unhappy right
// now" rather than "your request was rejected".
//
// The 52x block is Cloudflare's origin-fault vocabulary (521 origin down, 522
// connect timeout, 523 origin unreachable, 524 origin timeout) — precisely what
// a node behind Cloudflare emits while it restarts. Ordinary reverse proxies
// stick to 502/503/504.
var retryableStatuses = map[int]bool{
	TransportFailureStatus: true,
	408:                    true, // Request Timeout
	425:                    true, // Too Early
	429:                    true, // Too Many Requests
	500:                    true, // Internal Server Error
	502:                    true, // Bad Gateway
	503:                    true, // Service Unavailable
	504:                    true, // Gateway Timeout
	520:                    true, // Cloudflare: unknown origin error
	521:                    true, // Cloudflare: origin down
	522:                    true, // Cloudflare: origin connect timeout
	523:                    true, // Cloudflare: origin unreachable
	524:                    true, // Cloudflare: origin response timeout
	525:                    true, // Cloudflare: origin TLS handshake failed
	526:                    true, // Cloudflare: invalid origin certificate
	527:                    true, // Cloudflare: Railgun error
}

// Classify decides whether a failed request is worth retrying, and to whom the
// failure belongs. code is the OpenAI-shaped `error.code` already extracted
// from the response body (empty when the body carried none — an HTML error
// page, an empty body, or a parse failure); taking it pre-extracted keeps this
// package free of net/http and JSON handling so both language ports stay
// trivially identical.
//
// The rules, in order:
//
//  1. A relay-generated hop code is a relay fault; the target never saw it.
//  2. relay_upstream_unreachable is the relay's claim about the TARGET, so it
//     attributes to the target — callers keep whatever differential treatment
//     they already apply to that claim (it is a claim, not an observation).
//  3. Any OTHER non-empty code means the zs stack itself answered and its own
//     per-code semantics own the outcome. Not classified as infrastructure —
//     e.g. context_length_exceeded is terminal, provider_unavailable already
//     fails over. Returning "not retryable" here does NOT stop those flows; it
//     only keeps this package from second-guessing them.
//  4. A transient-shaped status with NO code is infrastructure, unattributable.
//  5. Everything else is terminal.
func Classify(status int, code string) Verdict {
	if relay.IsHopErrorCode(code) {
		return Verdict{Retryable: true, Attribution: AttrRelay}
	}
	if code == relay.CodeUpstreamUnreachable {
		return Verdict{Retryable: true, Attribution: AttrTarget}
	}
	if code != "" {
		return Verdict{}
	}
	if retryableStatuses[status] {
		return Verdict{Retryable: true, Attribution: AttrUnknown}
	}
	return Verdict{}
}

// RelayEvidence is what a caller knows about the hop a failed response came
// back through, beyond the (status, code) pair Classify already saw. Every
// field is a fact the CALLER holds — which route it chose, what the response
// headers carried, what the relay advertised at discovery — not a value
// Classify could have read off the body. Keeping them in a separate struct is
// what lets Classify stay a pure two-argument function over the response, and
// keeps its golden-vector contract stable.
type RelayEvidence struct {
	// Relayed reports that the request rode a relay hop (transport-privacy
	// mode). False for a direct send, where the caller's own direct-mode rules
	// already own an unattributed failure.
	Relayed bool `json:"relayed"`

	// HopMarker reports that the response carried wire.RelayHopHeader — the
	// relay's own handler ran and produced or forwarded this response.
	HopMarker bool `json:"hop_marker"`

	// RelayMarksHops reports that the relay advertises a proto_version at or
	// above wire.RelayHopHeaderMinVersion, so a MISSING HopMarker is evidence
	// rather than an artifact of its age. Callers get this from
	// wire.SetsRelayHopHeader over the version the relay advertised at
	// discovery — never a bootstrap-seeded one (wire.BootstrapProtoVersion).
	RelayMarksHops bool `json:"relay_marks_hops"`

	// CallerAborted reports that the failure was the CALLER's own doing — its
	// context was cancelled, or its own client-side deadline expired — rather
	// than anything the far end did.
	//
	// This exists because a caller-side abort produces the same
	// TransportFailureStatus as a dial failure to a dead relay, and rule 3 would
	// charge the relay for a socket the caller itself tore down. A user hitting stop,
	// or a reserve exceeding the caller's own timeout while the RELAY was
	// legitimately waiting on a slow target, must not cost the relay a strike.
	// The distinction is only visible to the caller (it knows its own
	// ctx/deadline), which is exactly why it belongs in this struct rather than
	// in Classify — and why it is decided in this pure, vectored layer rather
	// than duplicated in each app's recording site, where Go and TS would drift.
	CallerAborted bool `json:"caller_aborted"`
}

// relayFrontDoorStatuses are the statuses that, arriving from a marking relay
// WITHOUT its hop marker, prove the relay's own front door answered us and its
// handler never ran. This is the set rule 4 charges on sight.
//
// It is spelled out member by member rather than derived as "retryableStatuses
// minus the timeouts". The derived form was one subtraction away from being
// wrong in a way nobody would notice: every future addition to
// retryableStatuses would silently join the charge set, and the two subtracted
// sets already disagreed with the prose in SPEC § 10, which enumerated a
// narrower list than the code actually charged. An explicit list is the only
// form where the docs and the behavior can be diffed.
//
// Each member means "the request never reached the zs handler":
//
//	425 — Too Early. A TLS early-data replay refusal at the edge.
//	429 — Too Many Requests. See the note below; this one is a judgment call.
//	500 — the relay's own stack failed ahead of the handler (its ingress, or
//	      our middleware before handleRelay stamps the marker).
//	502 — front door could not reach its origin.
//	503 — front door had no healthy origin. Note a relay's own handler answers
//	      an overload with the CODED relay_busy, which never reaches rule 4.
//	520 — Cloudflare: origin returned something CF could not parse.
//	521 — Cloudflare: origin down.
//	522 — Cloudflare: origin connect timeout — TCP never established. A
//	      timeout by name, but a CONNECT one, so it does prove unreachability.
//	523 — Cloudflare: origin unreachable.
//	525, 526, 527 — Cloudflare: origin TLS / Railgun failures.
//
// 429 is deliberately included even though "come back later" is a capacity
// signal rather than a fault. The alternative is worse: on the discovery path a
// relay's throttle answering 429 would otherwise fall through as a TARGET-side
// failure and bench a node the probe never even reached. The self-reinforcing
// risk (a popular relay accruing strikes for being popular) is bounded — the
// downrank is soft, needs 3 consecutive strikes, and any successful forward
// resets it, so a throttled relay recovers as soon as its load drops.
//
// EXCLUDED, and why — the retryable statuses that mean "took too long" rather
// than "could not connect": 408 (Request Timeout), 504 (Gateway Timeout) and
// 524 (Cloudflare origin response timeout, TCP up but no reply). A relay is
// byte-transparent and writes NOTHING until the target's headers arrive — it
// cannot flush its own hop marker early without committing to a status before
// it knows one. So for the whole forward window it looks idle to its own
// gateway, and a gateway giving up in that window emits one of these with no
// marker attached. From the response alone that is indistinguishable between
// the relay being wedged (accepted the connection, never answered) and the
// relay patiently waiting on a slow TARGET. Charging would bench whoever
// happens to front the slowest targets, so rule 4 abstains and lets the
// caller's rotation differential decide: another relay reaching the same target
// proves the first was wedged; every relay timing out proves the target is slow
// and charges nobody.
//
// TransportFailureStatus is absent on purpose too — rule 3 owns it, and it
// needs no version gate because there is no marker to be missing.
var relayFrontDoorStatuses = map[int]bool{
	425: true,
	429: true,
	500: true,
	502: true,
	503: true,
	520: true,
	521: true,
	522: true,
	523: true,
	525: true,
	526: true,
	527: true,
}

// IsRelayFrontDoorStatus reports whether status, arriving unmarked from a relay
// that advertises wire.RelayHopHeaderMinVersion or newer, proves the relay's
// own front door answered rather than its handler.
//
// Exported for the one caller that must reason about the STATUS while
// deliberately ignoring the body: the discovery probe, which uses
// marker-absence from a marking relay as proof the handler never ran — evidence
// that outranks whatever JSON its front door happened to emit (an Envoy
// upstream_connect_error, or a per-IP throttle answering a coded 429 ahead of
// the handler). That path only picks an error TYPE (rotate vs. blame the
// target), so acting on the stronger signal is safe there; NarrowRelayed cannot
// do the same, because reinterpreting a coded response would mean flipping
// retryability.
//
// Both language ports must agree member-for-member, so this is golden-vectored
// (front_door_cases in proto/testdata/transient_vectors.json) rather than left
// to two hand-maintained lists — the discovery probes are the one place the Go
// and TS sides consume it directly, and they already drifted once.
func IsRelayFrontDoorStatus(status int) bool { return relayFrontDoorStatuses[status] }

// NarrowRelayed refines an AttrUnknown verdict using evidence Classify cannot
// see. Classify answers "what does this response say"; this answers "and what
// does the route it came back through tell me". Any verdict that is already
// attributed — or any non-relayed request — passes through untouched, so this
// is safe to apply unconditionally at a response seam.
//
// The rules, in order:
//
//  1. Not AttrUnknown, or not relayed → unchanged. A coded response already
//     names its hop, and a direct send has no relay to reason about.
//
//  2. CallerAborted → unchanged. Our own cancel/deadline says nothing about
//     either hop, and rule 3 would otherwise charge a relay for a socket we
//     tore down ourselves.
//
//  3. TransportFailureStatus while relayed → AttrRelay. No response arrived at
//     all and the socket the caller opened was the RELAY's, so nothing about
//     which hop failed to answer is ambiguous — once rule 2 has excluded the
//     caller's own doing. No version gate: there is no marker to be missing.
//     This is the one rule that works against an entirely un-upgraded fleet.
//
//  4. No marker but RelayMarksHops, and the status is front-door shaped
//     (relayFrontDoorStatuses — 425/429/500/502/503/520/521/522/523/525/526/
//     527, i.e. "could not connect", NOT the 408/504/524 timeouts) → AttrRelay.
//     A relay at or above RelayHopHeaderMinVersion that had run its handler
//     would have marked the response; it didn't, and the status says its front
//     door answered us. So the request died at the relay's own door.
//
//     Deliberately ordered BEFORE rule 5, so that when both could apply the
//     relay is charged rather than the target.
//
//     Note what this rule does NOT do: it never reinterprets a response that
//     carried a protocol error code, because rule 1 already returned. A coded
//     response from a relay's own front door (an ingress emitting its own JSON,
//     or a throttle that runs ahead of the relay handler) therefore stays
//     wherever Classify put it. That is deliberate — reclassifying a coded
//     response here would mean flipping Retryable, and this function must only
//     ever answer WHO, never WHETHER. A node whose pre-handler middleware needs
//     to be rotated away from must say so with a relay_* code (which Classify
//     already attributes to the relay), not rely on this rule.
//
//  5. HopMarker set → AttrTarget. The relay ran its handler and copied a
//     code-less transient status back, which is the same shape of claim as
//     relay_upstream_unreachable: "I forwarded, and this is what I got".
//     Callers already treat that claim DIFFERENTIALLY rather than at face
//     value, and routing this case to the same attribution puts it in the same
//     already-threat-modeled path. It grants a dishonest relay nothing new: one
//     that wants a healthy target benched can emit relay_upstream_unreachable
//     today and reach AttrTarget directly.
//
//  6. Everything else → unchanged (AttrUnknown). Two shapes land here and both
//     are genuinely undecidable from one response: a pre-floor relay (owes no
//     header), and a gateway TIMEOUT from any relay (it may simply have been
//     waiting on a slow target — see relayFrontDoorStatuses' exclusion note).
//     The caller's rotation differential is what resolves both.
func NarrowRelayed(v Verdict, status int, e RelayEvidence) Verdict {
	if v.Attribution != AttrUnknown || !e.Relayed || e.CallerAborted {
		return v
	}
	if status == TransportFailureStatus {
		return Verdict{Retryable: v.Retryable, Attribution: AttrRelay}
	}
	if e.RelayMarksHops && !e.HopMarker && relayFrontDoorStatuses[status] {
		return Verdict{Retryable: v.Retryable, Attribution: AttrRelay}
	}
	if e.HopMarker {
		return Verdict{Retryable: v.Retryable, Attribution: AttrTarget}
	}
	return v
}

// Retry schedule. The shape is two nested loops: a few fast attempts against
// one candidate (rotating the relay hop each time, which is what actually
// clears a bad front door), then — only if EVERY candidate failed transiently —
// slower whole-list sweeps. A single flaky relay costs a couple of seconds; a
// fleet-wide restart gets ridden out for a minute rather than surfaced.
//
// Both ports read these so a request behaves the same whether it went through
// zs-proxy or the browser app.
const (
	// InnerAttempts is the number of tries against one candidate, including the
	// first. Each retry rotates to a different relay when one is available.
	InnerAttempts = 3

	// Sweeps is the number of passes over the whole candidate list, including
	// the first. Sweeps beyond the first only happen when no candidate committed
	// payment and every failure was retryable.
	Sweeps = 4

	// OverallDeadline caps total wall-clock across all attempts and sweeps. It
	// is a ceiling, not a target — a request that exhausts the candidate list
	// terminally returns immediately.
	OverallDeadline = 60 * time.Second
)

// innerDelays / sweepDelays are the waits BEFORE attempt/sweep i (so index 0 is
// always zero — the first try is immediate). Kept unexported behind accessors
// because an exported slice is mutable by any importer.
var (
	innerDelays = []time.Duration{0, 500 * time.Millisecond, 1500 * time.Millisecond}
	sweepDelays = []time.Duration{0, 4 * time.Second, 12 * time.Second, 30 * time.Second}
)

// InnerDelay returns the wait before the zero-based attempt against a single
// candidate. Out-of-range indices clamp to the last delay, so a caller that
// raises InnerAttempts without extending the table degrades to a constant wait
// rather than panicking.
func InnerDelay(attempt int) time.Duration { return lookup(innerDelays, attempt) }

// SweepDelay returns the wait before the zero-based sweep over the candidate
// list. Sweep 0 is the initial pass and always returns 0.
func SweepDelay(sweep int) time.Duration { return lookup(sweepDelays, sweep) }

func lookup(table []time.Duration, i int) time.Duration {
	if i <= 0 {
		return table[0]
	}
	if i >= len(table) {
		return table[len(table)-1]
	}
	return table[i]
}

// Wait resolves how long to sleep before the next attempt, and whether there is
// budget to make it at all.
//
// scheduled is the table value from InnerDelay / SweepDelay. retryAfter is a
// server-supplied Retry-After (zero when absent) and WINS when longer — a node
// or gateway telling us when it will be ready is better information than a
// fixed table. remaining is what's left of OverallDeadline.
//
// ok is false when the resolved wait would consume the remaining budget, which
// the caller treats as "stop retrying and surface the failure" — retrying right
// at the deadline only delays the error without improving the odds.
func Wait(scheduled, retryAfter, remaining time.Duration) (d time.Duration, ok bool) {
	if remaining <= 0 {
		return 0, false
	}
	d = scheduled
	if retryAfter > d {
		d = retryAfter
	}
	if d >= remaining {
		return 0, false
	}
	return d, true
}
