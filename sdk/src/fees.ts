/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import type { FeeUnit } from './network.js'

/**
 * algoOnly is v for a field named for ALGO (µALGO fees, the ALGO/USD rate)
 * when fees are in ALGO, and 0 otherwise: those fields never carry another
 * coin's units. Go's algoOnly.
 */
export function algoOnly(u: FeeUnit, v: number): number {
    return u.currency === 'ALGO' ? v : 0
}
