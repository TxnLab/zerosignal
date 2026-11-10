/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: the journal sweep over a Solana wallet, Go's solanaChain.

import { type SettleArgs, type TicketRecord, solanaClaimArgs, zeroClaimArgs } from '../reconcile.js'
import type { SweepChain, SweptTicket } from '../reconciler.js'
import { decodeTicketId } from '../wallet.js'
import { SOLANA_ENDING_TIMEOUT_MS, type SolanaWallet } from './wallet.js'

/**
 * solanaSweep is the reconciler's SweepChain over w: each call is the payer's
 * own transaction on a ticket known only from its journal row and, where it
 * has one, its ticket account.
 */
export function solanaSweep(w: SolanaWallet): SweepChain {
    const ack = async (what: string, rec: TicketRecord, t: SweptTicket | null, a: SettleArgs, signal: AbortSignal) => {
        const account = t !== null && 'solana' in t ? t.solana : null
        try {
            const { opId, nodeId, ticketId } = ids('ack', rec)
            return (await w.sendAck(account, opId, nodeId, ticketId, a, signal)).signature
        } catch (err) {
            throw new Error(`wallet: ${what}: ${message(err)}`, { cause: err })
        }
    }
    return {
        read: async (rec, signal) => {
            const { opId, nodeId, ticketId } = ids('reconcile', rec)
            const t = await w.readTicket(opId, nodeId, ticketId, signal)
            return t === null ? null : { solana: t }
        },
        refund: (rec, signal) => {
            const { opId, nodeId, ticketId } = ids('refund-inactive', rec)
            return w.refundTicket(opId, nodeId, ticketId, signal)
        },
        lapse: (rec, _t, signal) => {
            const { opId, nodeId, ticketId } = ids('settle-lapsed', rec)
            return w.lapseTicket(opId, nodeId, ticketId, signal)
        },
        resettle: async (rec, t, signal) => {
            if (rec.settle === undefined) throw new Error('wallet: re-settle without a recorded receipt')
            return ack('re-settle', rec, t, rec.settle, signal)
        },
        // The payer's ack at args, which the program answers with a freeze
        // against a node claim that differs from it.
        freeze: (rec, t, args, signal) => ack('freeze', rec, t, args, signal),
        // The payer's ack at the claim's own fields, which the program answers
        // by settling at once.
        accept: async (rec, t, signal) => {
            if (!('solana' in t)) throw new Error('wallet: accept claim: no ticket account read')
            return ack('accept claim', rec, t, zeroClaimArgs(solanaClaimArgs(t.solana.pending)), signal)
        },
        // The program has resolve_frozen.
        freezes: async () => true,
        // A Solana submit waits for its confirmation, and one cut short that
        // landed late would be read as a ticket gone, never counted refunded.
        submitTimeoutMs: SOLANA_ENDING_TIMEOUT_MS,
    }
}

function ids(what: string, rec: TicketRecord): { opId: bigint; nodeId: bigint; ticketId: Uint8Array } {
    try {
        return { ticketId: decodeTicketId(rec.ticketId), opId: BigInt(rec.target.op), nodeId: BigInt(rec.target.node) }
    } catch (err) {
        throw new Error(`solana wallet: ${what}: decode ticket: ${message(err)}`, { cause: err })
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
