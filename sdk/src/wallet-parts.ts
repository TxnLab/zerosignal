/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: what the journal sweep reaches inside the SDK's Wallet, as Go's
// walletChain reads *Wallet's unexported fields.

import type { EscrowChain } from './wallet.js'

/** The escrow access behind one Wallet, and the payer it acts as. */
export interface WalletParts {
    chain: EscrowChain
    payer: string
}

/** Each Wallet's parts, set by its constructor. */
export const walletParts = new WeakMap<object, WalletParts>()
