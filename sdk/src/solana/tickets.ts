/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A payer's live tickets on the Solana rail, for a host's ticket listing, as
// Algorand's hosts walk the escrow's boxes. The twin of
// FetchSolanaPayerTickets in go/zs solana_payer.go.

import { base64 } from '@scure/base'
import { type PublicKey, publicKeyBytes } from '@txnlab/zs-proto/solana'
import {
    type Deployment,
    TICKET_PAYER_OFFSET,
    type Ticket,
    decodeNode,
    decodeTicket,
    discriminator,
    ticketDeadline,
} from '@txnlab/zs-proto/solana/zsescrow'

import type { SolanaRpc } from './rpc.js'

// Confirmed, as the wallet reads.
const COMMITMENT = 'confirmed'

/** One of a payer's live tickets and the node it is at. Go's SolanaPayerTicket. */
export interface SolanaPayerTicket {
    address: PublicKey
    operatorId: bigint
    nodeId: bigint
    ticket: Ticket
}

/** An account that matched the payer's filter but can't be read as one of its tickets, and why. Go's SolanaUnreadableTicket. */
export interface SolanaUnreadableTicket {
    address: PublicKey
    err: Error
}

/** What one read says about a payer's tickets. Go's SolanaPayerTickets. */
export interface SolanaPayerTickets {
    /** Ordered by deadline, the soonest first. */
    tickets: SolanaPayerTicket[]
    /**
     * Accounts carrying the payer's key where a ticket keeps it that this
     * build can't decode or place. Unlike Algorand's unreadable boxes, they
     * are the payer's: the filter matched its key.
     */
    unreadable: SolanaUnreadableTicket[]
}

/**
 * fetchSolanaPayerTickets lists payer's live tickets: every Ticket account the
 * program holds with payer at TICKET_PAYER_OFFSET, each placed at its node by
 * reading the node's account. A ticket account exists only until its ticket
 * ends, so this is what still holds the payer's USDC and rent. A node read
 * that fails fails the listing, so a flaky RPC doesn't mark tickets
 * unreadable. Go's FetchSolanaPayerTickets.
 */
export async function fetchSolanaPayerTickets(
    rpc: SolanaRpc,
    d: Deployment,
    payer: PublicKey,
    signal?: AbortSignal,
): Promise<SolanaPayerTickets> {
    let accts
    try {
        accts = await rpc.getProgramAccounts(d.program, {
            commitment: COMMITMENT,
            filters: [
                { memcmp: { offset: 0, bytes: discriminator('account', 'Ticket') } },
                { memcmp: { offset: TICKET_PAYER_OFFSET, bytes: publicKeyBytes(payer) } },
            ],
            signal,
        })
    } catch (err) {
        throw new Error(`solana tickets: ${message(err)}`, { cause: err })
    }
    const out: SolanaPayerTickets = { tickets: [], unreadable: [] }
    const nodes = new Map<PublicKey, NodeIds | null>()
    for (const a of accts) {
        let t: Ticket
        try {
            t = decodeTicket(a.account.data)
        } catch (err) {
            out.unreadable.push({ address: a.key, err: err instanceof Error ? err : new Error(String(err)) })
            continue
        }
        let ids = nodes.get(t.node)
        if (ids === undefined) {
            ids = await readNodeIds(rpc, d, t.node, signal)
            nodes.set(t.node, ids)
        }
        let why: string | undefined
        if (ids === null) why = `its node ${t.node} is not a readable node of the program`
        else if (d.ticket(t.node, t.ticketId) !== a.key)
            why = `its stored ticket id ${base64.encode(t.ticketId)} doesn't derive its address`
        if (ids === null || why !== undefined) {
            out.unreadable.push({ address: a.key, err: new Error(why) })
            continue
        }
        out.tickets.push({ address: a.key, operatorId: ids.operator, nodeId: ids.node, ticket: t })
    }
    out.tickets.sort((a, b) => {
        const da = ticketDeadline(a.ticket)
        const db = ticketDeadline(b.ticket)
        if (da !== db) return da < db ? -1 : 1
        return compareBytes(publicKeyBytes(a.address), publicKeyBytes(b.address))
    })
    return out
}

interface NodeIds {
    operator: bigint
    node: bigint
}

// The operator and node id of the node account at key, null when no node of
// the program is there. Go's readNodeIDs.
async function readNodeIds(
    rpc: SolanaRpc,
    d: Deployment,
    key: PublicKey,
    signal: AbortSignal | undefined,
): Promise<NodeIds | null> {
    let acct
    try {
        acct = await rpc.getAccountInfo(key, { commitment: COMMITMENT, signal })
    } catch (err) {
        throw new Error(`solana tickets: read node ${key}: ${message(err)}`, { cause: err })
    }
    if (acct === null || acct.owner !== d.program) return null
    try {
        const n = decodeNode(acct.data)
        return d.node(n.operatorId, n.nodeId) === key ? { operator: n.operatorId, node: n.nodeId } : null
    } catch {
        return null
    }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
        if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1
    }
    return a.length - b.length
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
