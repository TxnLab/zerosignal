/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// Transient-failure retry for the reserve leg. The failure this exists for is an
// operator's CDN / ingress / LB answering 502/503/504 with an HTML error page
// while the node behind it restarts — most visibly when a fleet rolls through a
// node update and swaths of the network bounce at once. Such a response carries
// no protocol error code, so before transient.Classify it was indistinguishable
// from a considered refusal and the only recourse was to abandon the operator.
//
// Two loops handle it, and they fix different halves:
//
//   - This file: retry the SAME candidate, rotating to a DIFFERENT relay each
//     time. Rotation is the load-bearing part — when the failing gateway is the
//     relay's, a different relay reaches the same target immediately. It is also
//     the only thing that helps at all when the candidate list has exactly one
//     entry, which is precisely the previous_response_id / strict-affinity case
//     that used to fail outright.
//   - dispatchHayai: sweep the whole candidate list again on a slower schedule,
//     for when every operator is transiently down at once.
//
// Relay reputation on this leg: NO CREDIT, EVER — but a PROVEN fault is
// recorded. The reserve rides the same hop as the imminent inference forward,
// so crediting it would clear the streak the inference leg is the authoritative
// signal for. A proven fault has no such conflict: it IS the signal, and
// withholding it is what let a relay behind a broken gateway stay in rotation
// indefinitely. Two things establish proof here, and neither is a guess:
//
//   - The narrowed verdict names the relay (transient.NarrowRelayed): a
//     transport failure — the socket we opened was the relay's — or, from a
//     relay advertising wire.RelayHopHeaderMinVersion or newer, a code-less
//     transient status with no hop marker, proving its front door answered and
//     its handler never ran.
//   - The rotation differential, for the pre-9.1 fleet the marker rule can't
//     reach: if relay A failed with a still-unattributed verdict and a later
//     rotation reaches the SAME target through relay B successfully, the target
//     was demonstrably up and A's failure was A's. If every relay fails, we
//     learn nothing and record nothing — a whole-target outage must not
//     manufacture a fleet-wide relay downrank.

// transientRetryBudget is the wall-clock ceiling on a whole request's transient
// retrying. Production always uses the shared proto value so the proxy and the
// client/ app ride out an outage for the same duration; s.retryBudget exists
// only so tests can shrink it, since the real schedule sleeps up to a minute.
func (s *client) transientRetryBudget() time.Duration {
	if s.retryBudget > 0 {
		return s.retryBudget
	}
	return transient.OverallDeadline
}

// sweepDelay is the wait before outer sweep i. Production uses the shared
// schedule; s.fastSweeps zeros it so a test can drive the multi-sweep
// terminal-selection path without the real 4s/12s/30s waits.
func (s *client) sweepDelay(sweep int) time.Duration {
	if s.fastSweeps {
		return 0
	}
	return transient.SweepDelay(sweep)
}

// reserveAttempt is the outcome of one candidate's reserve leg after any
// transient retries. Op and Hop are the values that produced the FINAL attempt:
// a stale-ephemeral re-probe can replace Op, and a rotation can replace Hop, and
// the caller must carry both forward — sealing the inference to a pre-rotation
// hop would send it through a relay we just abandoned.
type reserveAttempt struct {
	Ticket  *hayai.ReservedTicket
	Op      hayai.Operator
	Hop     *hayai.RelayHop
	Elapsed time.Duration // successful round-trip duration, for the latency store
	Err     error
}

// shouldRecordTargetFailure decides whether a retryable reserve failure counts
// against the TARGET node's per-request backoff, given whether the request was
// relayed. Mirrors the client's isRelayAttributable inversion
// (client/src/state/conversation/listeners.ts):
//
//   - AttrTarget always counts — the target is directly implicated (its own
//     transient error, or a relay_upstream_unreachable claim about it).
//   - AttrUnknown (a code-less gateway 5xx / transport failure) counts ONLY in
//     direct mode: with no relay in the path the broken gateway is this node's
//     own ingress. With a relay in the path it's unattributable — recording it
//     would bench a healthy node for someone else's CDN.
//   - AttrRelay never counts here (relay reputation owns it).
func shouldRecordTargetFailure(v transient.Verdict, usePrivacy bool) bool {
	switch v.Attribution {
	case transient.AttrTarget:
		return true
	case transient.AttrUnknown:
		return !usePrivacy
	default:
		return false
	}
}

// classifyReserveErr runs the shared verdict over a reserve failure, then
// narrows it with the route evidence the response body couldn't carry. Only
// *hayai.ReserveHTTPError carries the raw status/code/marker needed to
// classify; every other error type (busy, sizing, payer refusal, no-ephemeral)
// is already a considered outcome with its own handling in the dispatch loop,
// so it deliberately returns "not retryable" and lets that handling stand.
//
// hop is the relay this attempt rode (nil in direct mode), and it supplies both
// halves of the evidence gate: the advertised generation that decides whether a
// missing marker means anything, and the fact that a relay was in the path at
// all. The narrowing is what makes a TRANSPORT failure through a relay come
// back AttrRelay — the one attribution that works against a fleet where nothing
// has upgraded to 9.1 yet.
func classifyReserveErr(ctx context.Context, err error, hop *hayai.RelayHop) (transient.Verdict, time.Duration) {
	re, ok := hayai.AsReserveHTTP(err)
	if !ok {
		return transient.Verdict{}, 0
	}
	v := transient.Classify(re.Status, re.Code)
	if hop != nil {
		v = transient.NarrowRelayed(v, re.Status, transient.RelayEvidence{
			Relayed:        true,
			HopMarker:      re.RelayHopMarked,
			RelayMarksHops: wire.SetsRelayHopHeader(hop.RelayProtoVersion),
			CallerAborted:  callerAborted(ctx, re),
		})
	}
	return v, re.RetryAfter
}

// callerAborted reports whether a reserve failure was OUR doing rather than the
// far end's. Both shapes matter and neither is distinguishable from a dial
// failure by status alone — the reserve client reports every client.Do error as
// transient.TransportFailureStatus:
//
//   - the request context was cancelled (the payer's client hung up), and
//   - our own client-side deadline expired (DefaultReserveTimeout).
//
// The second is the subtle one. A relay is byte-transparent: it writes nothing
// until the TARGET answers, so a slow target keeps the relay silent, our
// deadline fires, and without this guard the innocent relay eats the strike —
// once per candidate, across every candidate in the sweep.
func callerAborted(ctx context.Context, re *hayai.ReserveHTTPError) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if re.Status != transient.TransportFailureStatus {
		return false
	}
	if errors.Is(re.Err, context.Canceled) || errors.Is(re.Err, context.DeadlineExceeded) {
		return true
	}
	// net/http surfaces a client-side timeout as an error whose Timeout() is
	// true; a dial refusal to a down relay is NOT a timeout, so this keeps the
	// genuine "relay unreachable" case attributable.
	var nerr net.Error
	return errors.As(re.Err, &nerr) && nerr.Timeout()
}

// sleepCtx waits d, returning false if the context was cancelled first (the
// caller then stops retrying). A non-positive d still checks the context, so a
// caller that hung up during a zero-delay attempt is noticed immediately rather
// than after another doomed round-trip.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// reserveWithTransientRetry issues the reserve against op, retrying an
// infrastructure failure through a different relay each time until the attempt
// budget or the overall deadline runs out.
//
// It absorbs the pre-existing stale-ephemeral self-heal (a node that restarted
// between our last discovery probe and now holds none of the ephemeral keys we
// cached, so it 400s the sealed body): that re-probe runs at most once per
// candidate, tracked across attempts by reprobed, because a node with no live
// ephemeral will keep refusing however many times we ask.
//
// The returned reserveAttempt always describes the final attempt — on success
// Ticket is non-nil, otherwise Err carries the last failure so the dispatch
// loop's existing per-error-type handling still sees the real cause.
func (s *client) reserveWithTransientRetry(
	ctx context.Context,
	op hayai.Operator,
	req ticket.ReserveRequest,
	hop *hayai.RelayHop,
	relaySel []selection.Operator,
	usePrivacy bool,
	deadline time.Time,
	resize func(hayai.Operator, *ticket.ReserveRequest),
) reserveAttempt {
	// Relays already tried for this candidate. Rotation excludes them so a
	// retry genuinely changes the path — retrying through the same broken
	// gateway would just burn the budget.
	var excluded map[hayai.NodeRef]bool
	var retryAfter time.Duration
	var reprobed bool
	var last reserveAttempt
	// Relays that failed this candidate with a verdict still UNATTRIBUTED after
	// narrowing — in practice a code-less gateway 5xx through a pre-9.1 relay,
	// where the marker rule has nothing to go on. Held rather than recorded,
	// because on its own such a failure genuinely doesn't say whose front door
	// broke. If a later rotation reaches the SAME target through a DIFFERENT
	// relay, that ambiguity resolves: the target was up, so these were at
	// fault. If every attempt fails, the slice is discarded untouched.
	var unattributed []*hayai.RelayHop

	for attempt := 0; attempt < transient.InnerAttempts; attempt++ {
		if attempt > 0 {
			d, ok := transient.Wait(transient.InnerDelay(attempt), retryAfter, time.Until(deadline))
			if !ok {
				break
			}
			if !sleepCtx(ctx, d) {
				break
			}
			// Rotate. With no relay in play (privacy off) there is nothing to
			// rotate to and the retry is a straight re-attempt — still worth it,
			// since a restarting node's gateway recovers on its own.
			if usePrivacy && hop != nil {
				if excluded == nil {
					excluded = make(map[hayai.NodeRef]bool, transient.InnerAttempts)
				}
				excluded[hop.RelayRef()] = true
				next, err := s.relayHopForPool(hayai.CandidatesExcluding(relaySel, excluded), op, usePrivacy)
				if err != nil {
					// Every other relay is excluded or ineligible. Stop rather
					// than retry the one we just abandoned, and never fall back
					// to a direct route — that would void the privacy guarantee
					// for a request the caller asked to be relayed.
					break
				}
				s.log.Debug("reserve: transient failure; rotating relay",
					opAttr(op),
					slog.Uint64("failed_relay_operator_id", hop.RelayID),
					slog.Uint64("failed_relay_node_id", hop.RelayNodeID),
					relayAttr(next),
					slog.Int("attempt", attempt+1))
				hop = next
			}
		}

		start := time.Now()
		rt, err := s.reserveClient.Reserve(ctx, op, req, hop)
		if !reprobed && (hayai.IsNoEphemeral(err) || hayai.IsBadReserveEnvelope(err)) {
			// Self-heal a stale forward-secrecy ephemeral. A node mints its
			// ephemeral before it serves and fails closed otherwise, so this is
			// almost always a key our cached snapshot lost while the node was
			// down — typically a restart between scheduled refreshes. Two shapes
			// reach here: IsNoEphemeral (the cached ephemeral already expired, so
			// Reserve refused to seal and never contacted the node) and
			// IsBadReserveEnvelope (still unexpired but defunct — the node
			// rotated or restarted inside the advertised validity window, so it
			// couldn't age-open a body sealed to the old key). Re-probe live and
			// retry once; ok=false (no fresh ephemeral, or a static registry with
			// nothing to re-probe) falls through to the normal handling.
			reprobed = true
			if refreshed, ok := s.registryProvider.ReprobeEphemeral(ctx, op); ok {
				op = refreshed
				// Re-size against the REFRESHED operator before re-sending. A
				// re-probe fires exactly when the node restarted, which is the
				// one moment its advertised proto_version and declared
				// capacities can legitimately have changed — and the reserve's
				// bound version is chosen per-operator. Re-issuing the
				// pre-reprobe request would ship a v2-sized input_count to a
				// node that just downgraded to 9.1 and measures v1, rejecting
				// after escrow.open. Safe to mutate here: Reserve signs the
				// payer signature itself, per call, and input_count is inside
				// that digest, so the retry re-signs the new values.
				if resize != nil {
					resize(op, &req)
				}
				start = time.Now()
				rt, err = s.reserveClient.Reserve(ctx, op, req, hop)
			}
		}

		last = reserveAttempt{Ticket: rt, Op: op, Hop: hop, Elapsed: time.Since(start), Err: err}
		if err == nil {
			// Same target, different relay, success — so the target was up all
			// along and every earlier hop's unattributed failure was its own.
			// This is the differential the relay-attribution docblock
			// CLAIMED existed and did not, and it is the only thing
			// that resolves blame for a relay too old to stamp a hop marker.
			// Deliberately one-sided: relay B is NOT credited here, because a
			// reserve success must not clear the streak the inference forward
			// owns.
			//
			// Charge only ONE relay, the most recent — never the whole held
			// set. The differential's premise is "the target was up, so the
			// failure was the relay's", but the failure this file exists for is
			// explicitly the NON-deterministic one (see the header: a gateway
			// bouncing while the node behind it restarts). A target that 5xxs
			// then recovers inside the ~500ms inner delay produces the same
			// fail-then-succeed shape as a genuinely wedged relay, and during a
			// rolling fleet update that shape is everywhere. Capping at one
			// keeps a single ambiguous episode to a single strike — three
			// consecutive ones, with no intervening successful forward, are
			// still needed to downrank — instead of letting one flap burn a
			// healthy relay's entire budget in a single request.
			if n := len(unattributed); n > 0 {
				bad := unattributed[n-1]
				s.recordRelayOutcome(bad, false)
				s.log.Info("relay proven at fault by rotation differential",
					opAttr(op),
					slog.Uint64("failed_relay_operator_id", bad.RelayID),
					slog.Uint64("failed_relay_node_id", bad.RelayNodeID),
					slog.Int("also_unattributed", n-1),
					relayAttr(hop))
			}
			return last
		}

		v, hint := classifyReserveErr(ctx, err, hop)
		if !v.Retryable {
			return last
		}
		retryAfter = hint
		if usePrivacy && hop != nil {
			switch v.Attribution {
			case transient.AttrRelay:
				// Proven, not guessed: a transport failure to the relay's own
				// socket, or a missing hop marker from a relay that advertises
				// it. Penalty only — see this file's header on why the reserve
				// leg never credits.
				s.recordRelayOutcome(hop, false)
			case transient.AttrUnknown:
				// Undecidable on its own. Hold it; a later rotation that
				// succeeds against this same target settles it above.
				unattributed = append(unattributed, hop)
			}
		}
		s.log.Info("reserve failed with a transient infrastructure error",
			opAttr(op), relayAttr(hop),
			slog.Int("attempt", attempt+1),
			slog.String("attribution", string(v.Attribution)),
			slog.Any("err", err))
	}
	return last
}
