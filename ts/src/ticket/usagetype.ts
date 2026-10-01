/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// UsageType — the unit a Ticket / UsageReceipt direction is priced and
// metered in. Mirrors proto/go/ticket/usagetype.go. Carried as one byte each
// inside the signed canonical bytes (v2). Money is unaffected: amount_charged /
// max_price stay a single microUSDC scalar — UsageType only changes how a
// count is interpreted for sizing and metrics.
export const UsageType = {
    /** Direction (or the aux output slot) unused for this request. */
    None: 0,
    /** count = tokens; rate = microUSDC per 1,000,000 tokens. */
    Tokens: 1,
    /** count = image units; rate = microUSDC for one 1024²-standard image × imageprice.factor. */
    Images: 2,
    /** count = characters; rate = microUSDC per 1,000,000 characters. */
    Characters: 3,
    /** count = whole seconds; rate = microUSDC per second. */
    Seconds: 4,
} as const

export type UsageType = (typeof UsageType)[keyof typeof UsageType]
