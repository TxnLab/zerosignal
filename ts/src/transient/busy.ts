/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The four conditions a node reports behind HTTP 429 on the reserve path, and
// which failures may be retried after payment. Mirror of
// proto/go/transient/busy.go, pinned by the code_cases in
// proto/testdata/transient_vectors.json.

import { isHopErrorCode } from '../relay/relay.js'

export const BusyCode = {
    /** The node's ticket store is momentarily full; a slot frees as tickets settle. */
    NoCapacity: 'no_capacity',
    /** This payer holds too many reserves. Each ask costs a penalty strike. */
    PayerSlotCap: 'payer_slot_cap',
    /** A fixed-window token bucket. A relay's own per-IP throttle answers with it too. */
    RateLimited: 'rate_limited',
    /** The penalty box, a minute to a day. */
    Banned: 'reserve_temporarily_banned',
} as const

/**
 * Whether re-asking the same node after a 429 carrying code can produce a
 * different answer: only BusyCode.NoCapacity. An absent or unrecognized code
 * fails closed. Separate from classify, which leaves coded responses to their
 * own semantics, because a full queue gets its own short retry budget rather
 * than the fleet-restart one.
 */
export function retryableBusyCode(code: string | null | undefined): boolean {
    return code === BusyCode.NoCapacity
}

/**
 * Whether a failure carrying code may be retried after escrow.open has
 * committed: only a relay hop error, the relay's unauthenticated assertion
 * that it never forwarded the envelope. Takes the code, not an attribution, because a dropped
 * connection is attributed to the relay too and may have left the target
 * mid-generation.
 */
export function retryableAfterPayment(code: string | null | undefined): boolean {
    return !!code && isHopErrorCode(code)
}
