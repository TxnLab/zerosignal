/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package steering

import "time"

// Relay reputation is a soft downrank: a relay over a threshold drops to the
// fallback tier of relay selection and is never excluded, so the cold-start
// fallback to the full eligible set survives.
const (
	// RelayDownrankThreshold is how much standing evidence on the forward-failure
	// or stale-ephemeral streak demotes a relay.
	RelayDownrankThreshold = 3

	// RelayReputationCooldown is the interval over which one unit of evidence on
	// those two streaks ages out. It exceeds the proxy's 5-minute discovery
	// refresh, so probes feed evidence faster than it decays. A demoted relay is
	// not normally selected while a healthy preferred pool exists, so recovery by
	// success alone would make the demotion permanent.
	RelayReputationCooldown = 10 * time.Minute

	// RelayTimeoutDownrankThreshold is higher than RelayDownrankThreshold because
	// the evidence is weaker. A gateway timeout is the one failure the shared
	// verdict (transient.NarrowRelayed) refuses to attribute, so this streak is an
	// inference from repetition, and a relay that honestly fronts slow targets can
	// accrue it. More strikes bound what that mistake costs.
	RelayTimeoutDownrankThreshold = 5

	// RelayTimeoutCooldown is sized by how rarely the evidence arrives, not by how
	// fast it goes stale. The failure streak has a probe feeder; this one has none,
	// because a details GET finishes long before any idle timer. Its only writer is
	// a paid inference that failed, and relay rotation spreads those over the
	// pool, so at the 10-minute cooldown the count would sit at 1 forever. The
	// fault it describes, a misconfigured front door, persists for hours.
	RelayTimeoutCooldown = 60 * time.Minute
)

// IsForwardTimeoutStatus reports whether status is a gateway "took too long"
// answer (408, 504, 524) rather than a "could not connect" one. These are
// exactly the statuses transient.NarrowRelayed leaves unattributed, because a
// relay writes nothing until its target's headers arrive, so one timeout can't
// tell the relay's front door from a slow target. A test pins the set as
// disjoint from transient.IsRelayFrontDoorStatus, so no status is charged on
// two streaks.
func IsForwardTimeoutStatus(status int) bool {
	switch status {
	case 408, 504, 524:
		return true
	default:
		return false
	}
}

// Evidence is one relay's standing count on one streak and the time it is
// aged from. The zero value is "no evidence".
type Evidence struct {
	Count int
	At    time.Time
}

// Decay ages e by one unit per whole cooldown elapsed since At, reporting the
// aged evidence and whether any survives. Evidence that does not survive is
// returned as the zero value.
//
// Decay rather than reset: zeroing on expiry hands a chronically broken relay a
// clean slate every quiet cooldown, so it costs a full threshold of fresh
// failures to re-establish, forever. Aging one unit at a time means a repeat
// offender re-crosses the threshold on its next failure while a recovered relay
// still walks back to zero.
//
// At advances by the windows consumed rather than to now, so the residual
// fraction survives and a second call at the same instant changes nothing:
// callers read reputation once per relay per request, and that must not
// compound. A clock that steps backwards consumes nothing, and neither does a
// cooldown that isn't positive.
func Decay(e Evidence, now time.Time, cooldown time.Duration) (Evidence, bool) {
	if e.At.IsZero() || e.Count <= 0 {
		return Evidence{}, false
	}
	if cooldown <= 0 {
		return e, true
	}
	// Duration division truncates toward zero, so a backwards clock is 0 steps
	// here and never a negative count that would grow the evidence.
	steps := int(now.Sub(e.At) / cooldown)
	if steps <= 0 {
		return e, true
	}
	if e.Count -= steps; e.Count <= 0 {
		return Evidence{}, false
	}
	e.At = e.At.Add(time.Duration(steps) * cooldown)
	return e, true
}

// RelayDownranked reports whether a relay's standing evidence demotes it: the
// forward-failure or stale-ephemeral streak at RelayDownrankThreshold, or the
// timeout streak at RelayTimeoutDownrankThreshold. Pass each streak's count
// after aging it with its own cooldown. A payer with no stale-ephemeral signal
// passes 0.
func RelayDownranked(failures, stale, timeouts int) bool {
	return failures >= RelayDownrankThreshold ||
		stale >= RelayDownrankThreshold ||
		timeouts >= RelayTimeoutDownrankThreshold
}

// Bump ages e and then adds one unit of evidence, dated now.
func Bump(e Evidence, now time.Time, cooldown time.Duration) Evidence {
	aged, _ := Decay(e, now, cooldown)
	return Evidence{Count: aged.Count + 1, At: now}
}
