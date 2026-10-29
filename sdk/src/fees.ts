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

/**
 * nativeUsd is the reserve's USD rate for u's coin: each rail's node sends its
 * own coin's rate, and a rate for another coin would price u's fees wrong.
 * Go's nativeUSD.
 */
export function nativeUsd(u: FeeUnit, rates: { algoUsdPrice: number; solUsdPrice?: number }): number {
    switch (u.currency) {
        case 'ALGO':
            return rates.algoUsdPrice
        case 'SOL':
            return rates.solUsdPrice ?? 0
    }
    return 0
}
