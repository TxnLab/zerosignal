/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The values a reserve and a settle carry for the wallet, which differ by
// rail (SPEC.md § 3a). Dispatch reads them only to drop a malformed one
// early; the wallet decodes them again to use them. Mirrors Go's
// go/zs/rail.go. An absent rail is Algorand, as an absent Network.rail is.

import { base64 } from '@scure/base'
import { MIN_SIGNER_SPENDABLE_LAMPORTS, MIN_SIGNER_SPENDABLE_MICROALGOS } from '@txnlab/zs-proto/selection'
import { parseTransaction } from '@txnlab/zs-proto/solana'
import { decodeOpenOffer, parseOpenSeq } from '@txnlab/zs-proto/solana/zsescrow'

import { decodeOpenGroup } from './escrow/open.js'
import { decodeSettleGroup } from './escrow/settle.js'
import type { Rail } from './network.js'

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err))

/**
 * checkOpenOffer throws unless presigned, a reserve's presigned_open_txn,
 * decodes as rail's open: Algorand's open group, or Solana's offer
 * transaction.
 */
export function checkOpenOffer(rail: Rail | undefined, presigned: string): void {
    if (rail === 'solana') {
        try {
            parseTransaction(decodeOpenOffer(presigned))
        } catch (err) {
            throw new Error(`decode presigned open offer: ${message(err)}`, { cause: err })
        }
        return
    }
    try {
        decodeOpenGroup(presigned)
    } catch (err) {
        throw new Error(`decode presigned open group: ${message(err)}`, { cause: err })
    }
}

/**
 * checkSettleSlot throws unless slot, the settle-group header or frame,
 * decodes as rail's: Algorand's settle group, or Solana's open_seq.
 */
export function checkSettleSlot(rail: Rail | undefined, slot: string): void {
    if (rail === 'solana') parseOpenSeq(slot)
    else decodeSettleGroup(slot)
}

/**
 * opensOnChain is whether a turn on a ticket at maxPrice opens on chain. A
 * Solana turn at max_price 0 doesn't: the program refuses a zero-price open,
 * so a free Solana turn has no open, no ack and nothing for the watchdog
 * (SPEC.md § 3a "Free turns on Solana").
 */
export function opensOnChain(rail: Rail | undefined, maxPrice: number): boolean {
    return rail !== 'solana' || maxPrice > 0
}

/**
 * requestTicketId is the ticket id a reserve on rail asks the node to issue,
 * or undefined to let the node choose. A Solana payer chooses a fresh random
 * id for every reserve, so it never signs two opens with one id at a node:
 * the node's open_seq it acks is then unable to fit another of its tickets
 * (SPEC.md § 3a "The open and the ack on Solana").
 */
export function requestTicketId(rail: Rail | undefined): string | undefined {
    return rail === 'solana' ? base64.encode(crypto.getRandomValues(new Uint8Array(16))) : undefined
}

/**
 * signerFloorText is the signing-account floor as a no_funded_operator refusal
 * names it, in the rail's own unit. Go's signerFloorText, whose division is
 * an integer one.
 */
export function signerFloorText(rail: Rail | undefined): string {
    return rail === 'solana' ? `${MIN_SIGNER_SPENDABLE_LAMPORTS} lamports` : `${Math.floor(MIN_SIGNER_SPENDABLE_MICROALGOS / 1_000_000)} ALGO`
}
