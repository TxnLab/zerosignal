/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Contract constants. Mirrors proto/go/escrow, which mirrors
// ZeroSignalEscrow.algo.ts; the golden vectors pin the record sizes and every
// value derived from these.

// Ticket statuses. Only OPEN, FROZEN and PENDING_SETTLE are ever written on
// chain — SETTLED and REFUNDED correspond to the box being deleted.
export const STATUS_OPEN = 1
export const STATUS_SETTLED = 2
export const STATUS_REFUNDED = 3
export const STATUS_FROZEN = 4
export const STATUS_PENDING_SETTLE = 5

// Which side posted the first half of a two-sided settle.
export const PENDING_NONE = 0
export const PENDING_BY_OPERATOR = 1
export const PENDING_BY_PAYER = 2

// EVICTED is a soft tombstone: in-flight tickets still settle, but discovery
// hides the operator and open() reverts.
export const OPERATOR_STATUS_ACTIVE = 1
export const OPERATOR_STATUS_EVICTED = 2

export const NODE_STATUS_ACTIVE = 1

// One value for every rail, so escrow re-exports settle's rather than keeping
// a twin that could drift.
export { BPS_DENOMINATOR } from '../settle/fee.js'
export const REVENUE_BUCKET_COUNT = 30
// Indexed by ticket UsageType: 1=Tokens, 2=Images, 3=Characters, 4=Seconds,
// the rest reserved; slot 0 (None) is unused.
export const OUTPUT_UNITS_LEN = 8
export const SECONDS_PER_DAY = 86_400n
export const BASE_URL_MAX = 248
