/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's protocol fee rate, cached off the request path, mirroring
// proto/go/zs feeRateCache.

import type { Clock } from './ports.js'

/** How long a fetched rate is served before a background refresh starts. */
export const FEE_RATE_CACHE_TTL_MS = 60_000
/** Bounds one background read, so a wedged algod cannot hold the refresh. */
export const FEE_RATE_REFRESH_TIMEOUT_MS = 5_000

/**
 * FeeRateCache holds the payer's protocol fee rate in basis points. A read
 * never waits on the chain: a cold or stale cache answers with what it has
 * and starts one background refresh, so the response path is never gated on
 * the global read. One payer pays from one address, so one value serves every
 * request.
 */
export class FeeRateCache {
    readonly #clock: Clock
    #feeBps = 0
    #ok = false
    #fetchedAt = 0
    #refreshing = false

    // Monotonic by default, as Go's time.Since, not Config.clock: a wall
    // clock stepped back would hold a stale rate until it caught up.
    constructor(clock: Clock = () => performance.now()) {
        this.#clock = clock
    }

    /** The cached rate, or null until the first read lands. */
    get(fetch: (signal: AbortSignal) => Promise<number>): number | null {
        const stale = !this.#ok || this.#clock() - this.#fetchedAt > FEE_RATE_CACHE_TTL_MS
        if (stale && !this.#refreshing) {
            this.#refreshing = true
            void this.#refresh(fetch)
        }
        return this.#ok ? this.#feeBps : null
    }

    // Detached and silent, as Go's: the rate feeds a cost breakdown and the
    // admission estimate, and a failure leaves the previous value for the
    // next read to retry.
    async #refresh(fetch: (signal: AbortSignal) => Promise<number>): Promise<void> {
        try {
            const feeBps = await fetch(AbortSignal.timeout(FEE_RATE_REFRESH_TIMEOUT_MS))
            this.#feeBps = feeBps
            this.#ok = true
            this.#fetchedAt = this.#clock()
        } catch {
            // Kept cold or stale; see above.
        } finally {
            this.#refreshing = false
        }
    }
}
