/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transient

import "github.com/TxnLab/zerosignal/go/relay"

// The five conditions a node reports behind HTTP 429 on the reserve path. The
// node emits them from these constants and both reference payers classify
// them with RetryableBusyCode, the same emitter/classifier split relay's hop
// codes use.
const (
	// BusyCodeNoCapacity: the node's ticket store is momentarily full. A slot
	// frees as in-flight tickets settle, so re-asking can succeed.
	BusyCodeNoCapacity = "no_capacity"

	// BusyCodePayerSlotCap: this payer already holds too many reserves on the
	// node. Each ask is charged to the payer's penalty budget, so a retry loop
	// turns a momentary over-subscription into a real ban.
	BusyCodePayerSlotCap = "payer_slot_cap"

	// BusyCodeRateLimited: a fixed-window token bucket; the answer holds for
	// the rest of the window. A relay's own per-IP throttle also answers with
	// it, ahead of its relay handler, and is indistinguishable here.
	BusyCodeRateLimited = "rate_limited"

	// BusyCodeBanned: the penalty box, lasting a minute to a day. No retry
	// schedule outlives it.
	BusyCodeBanned = "reserve_temporarily_banned"

	// BusyCodeFreeBudgetExhausted: a Solana node's free tier for the UTC day
	// is spent, until 00:00 UTC. Another node may still have budget, so a
	// payer fails over; this node's answer holds for the day.
	BusyCodeFreeBudgetExhausted = "free_budget_exhausted"
)

// RetryableBusyCode reports whether re-asking the same node after a 429
// carrying code can produce a different answer. Only BusyCodeNoCapacity can.
// An absent or unrecognized code fails closed: a node that sent none hasn't
// said which condition it means, and guessing wrong spends penalty strikes.
//
// This is separate from Classify on purpose. Classify leaves every coded
// response to the code's own semantics (rule 3), and callers route a retryable
// Classify verdict into the fleet-restart retry budget; a full queue gets its
// own, much shorter one.
func RetryableBusyCode(code string) bool { return code == BusyCodeNoCapacity }

// RetryableAfterPayment reports whether a failure carrying code may be retried
// after escrow.open has committed: only a relay hop error, the relay's
// assertion that it never forwarded the envelope. The byte-identical sealed
// request may then go out through a different relay. The claim is
// unauthenticated; a relay that lied costs the payer the turn (the resend hits a
// consumed ticket), never a second charge.
//
// It takes the code, not an Attribution. NarrowRelayed also attributes a
// dropped connection to the relay, and a connection that drops after the relay
// forwarded leaves the target possibly mid-generation; a second submission
// would collide with a ticket already consumed (SPEC § 10).
func RetryableAfterPayment(code string) bool { return relay.IsHopErrorCode(code) }
