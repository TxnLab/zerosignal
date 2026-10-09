/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"time"

	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
)

// What one candidate's failed reserve means for the dispatch loop, apart from
// its side effects (logging, the backoff store, the terminal-error
// accumulators). The TS SDK mirrors classifyReserveFailure and nextResweep in
// sdk/src/routing/verdict.ts; testdata/dispatch_verdict_vectors.json pins both.

// Reserve-failure outcomes: which branch of the dispatch loop a failure takes.
const (
	outcomeBusy         = "busy"
	outcomeSize         = "size"
	outcomePayerRefusal = "payer_refusal"
	outcomeNoEphemeral  = "no_ephemeral"
	outcomeTransient    = "transient"
	outcomeRefused      = "refused"
)

// reserveFailure is one candidate's failed reserve, decided.
type reserveFailure struct {
	// Outcome names the branch the dispatch loop takes.
	Outcome string
	// Stop ends the whole dispatch: every remaining candidate would refuse the
	// identical request identically (a payer-scoped refusal).
	Stop bool
	// Strike records a failure against the target's dispatch backoff. Only a
	// transient failure this node is answerable for does; see
	// shouldRecordTargetFailure.
	Strike bool
	// Refused is a considered refusal: an answer, not weather, so it ends the
	// weather re-sweep and is sticky evidence for the terminal error.
	Refused bool
	// HardRefused is refused for a reason waiting can't fix, which also vetoes
	// a busy re-sweep.
	HardRefused bool
	// Busy is a 429; BusyResweepable when its code says re-asking can help.
	Busy, BusyResweepable bool
	// Transient is infrastructure weather that keeps the outer sweep eligible.
	Transient bool
	// SizeRejected and EphemeralMissing feed their own accumulators.
	SizeRejected, EphemeralMissing bool
	// Hint is the wait the failure asks for: a busy node's Retry-After capped
	// by nodeRetryHint, a transient failure's raw, a payer refusal's reset.
	Hint time.Duration
	// Attribution is the transient verdict's, for logs; empty otherwise.
	Attribution transient.Attribution
}

// reserveRoute is the route evidence a reserve failure's body can't carry.
type reserveRoute struct {
	// Relayed is true when the reserve rode a relay hop.
	Relayed bool
	// RelayMarksHops is true when that relay's generation sets the hop marker,
	// so a missing marker means something.
	RelayMarksHops bool
	// CallerAborted is true when our own cancellation or deadline ended it.
	CallerAborted bool
}

// reserveRouteFor reads the route evidence for err off the hop it rode.
func reserveRouteFor(ctx context.Context, err error, hop *RelayHop) reserveRoute {
	if hop == nil {
		return reserveRoute{}
	}
	route := reserveRoute{Relayed: true, RelayMarksHops: wire.SetsRelayHopHeader(hop.RelayProtoVersion)}
	if re, ok := AsReserveHTTP(err); ok {
		route.CallerAborted = callerAborted(ctx, re)
	}
	return route
}

// narrowReserveVerdict runs the shared transient verdict over a reserve
// failure, then narrows it with the route evidence.
func narrowReserveVerdict(re *ReserveHTTPError, route reserveRoute) transient.Verdict {
	v := transient.Classify(re.Status, re.Code)
	if route.Relayed {
		v = transient.NarrowRelayed(v, re.Status, transient.RelayEvidence{
			Relayed:        true,
			HopMarker:      re.RelayHopMarked,
			RelayMarksHops: route.RelayMarksHops,
			CallerAborted:  route.CallerAborted,
		})
	}
	return v
}

// classifyReserveFailure decides one candidate's failed reserve, in the order
// the dispatch loop has always tested it:
//
//   - busy (429): a considered refusal, resweepable only when its code says so;
//     never strikes, because a saturated node is healthy.
//   - size: other operators may have larger limits, so the loop keeps going.
//   - payer refusal: the chain said no about this PAYER, so stop.
//   - no ephemeral: this node can't be sealed to right now; skip it.
//   - a transient ReserveHTTPError: weather, which strikes only when the target
//     is answerable for it.
//   - anything else, including a bad_reserve_envelope the self-heal couldn't
//     fix: a hard refusal by this operator, with no strike.
func classifyReserveFailure(err error, route reserveRoute, usePrivacy bool) reserveFailure {
	if be := (*BusyError)(nil); errors.As(err, &be) && be != nil {
		return reserveFailure{
			Outcome: outcomeBusy, Refused: true, Busy: true,
			BusyResweepable: be.Retryable(), Hint: nodeRetryHint(be.RetryAfter),
		}
	}
	if IsSize(err) {
		return reserveFailure{Outcome: outcomeSize, SizeRejected: true}
	}
	if pr, ok := AsPayerRefusal(err); ok {
		return reserveFailure{Outcome: outcomePayerRefusal, Stop: true, Hint: pr.RetryAfter}
	}
	if IsNoEphemeral(err) {
		return reserveFailure{Outcome: outcomeNoEphemeral, EphemeralMissing: true}
	}
	if re, ok := AsReserveHTTP(err); ok {
		if v := narrowReserveVerdict(re, route); v.Retryable {
			return reserveFailure{
				Outcome: outcomeTransient, Transient: true,
				Strike: shouldRecordTargetFailure(v, usePrivacy),
				Hint:   re.RetryAfter, Attribution: v.Attribution,
			}
		}
	}
	return reserveFailure{Outcome: outcomeRefused, Refused: true, HardRefused: true}
}

// sweepOutcome is what one pass over the candidates produced, for deciding
// whether to make another.
type sweepOutcome struct {
	// This sweep's own failures. Busy is a 429 whose code is resweepable;
	// AnyBusy below is any 429 at all.
	Transient, Refused, Busy, HardRefused bool
	// Sticky across the whole request: a size rejection, any 429, a relay gap,
	// a missing tool factor, a missing ephemeral, a price violation.
	SizeRejected, AnyBusy, RelayUnavailable, ToolFactorMissing, EphemeralMissing, PriceRejected bool
	// BusyBudgetLeft is true while busy re-sweeps remain and their deadline
	// hasn't passed.
	BusyBudgetLeft bool
}

// nextResweep decides whether to walk the candidates again, and why. Two
// independent reasons, each with its own disqualifiers:
//
//   - weather: every candidate failed transiently and nothing refused. Blocked
//     by any considered refusal or sticky accumulator, since each is a property
//     of the request or the fleet that waiting doesn't change.
//   - busy: a candidate was at capacity with a resweepable code, and none
//     refused for a reason waiting can't fix. Deliberately narrower: only what
//     outranks busy in the terminal ladder (a hard refusal, a size rejection, a
//     relay gap) may veto it, since the ladder already treats a missing tool
//     factor, ephemeral or price as subordinate to busy.
func nextResweep(o sweepOutcome) resweepReason {
	weatherBlocked := o.HardRefused || o.SizeRejected || o.AnyBusy ||
		o.RelayUnavailable || o.ToolFactorMissing || o.EphemeralMissing || o.PriceRejected
	busyBlocked := o.HardRefused || o.SizeRejected || o.RelayUnavailable
	switch {
	case o.Transient && !o.Refused && !weatherBlocked:
		return resweepWeather
	case o.Busy && !busyBlocked && o.BusyBudgetLeft:
		return resweepBusy
	default:
		return resweepNone
	}
}
