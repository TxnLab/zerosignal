/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import type { ClaimFields } from '@txnlab/zs-proto/solana/zsescrow'

import type { SettleArgs } from '../reconcile.js'

/** The claim fields the payer's half carries for a, on Solana. Go's solanaClaimFields. */
export function solanaClaimFields(a: SettleArgs): ClaimFields {
    return {
        amount: a.amountCharged,
        receiptDigest: a.receiptDigest,
        ttftMs: a.ttftMs,
        decodeMs: a.decodeMs,
        inputUnits: a.inputTokens,
        outputUnits: a.outputTokens,
        outputUsageType: a.outputUsageType,
        auxUsageType: a.auxOutputUsageType,
        auxCount: a.auxOutputCount,
    }
}
