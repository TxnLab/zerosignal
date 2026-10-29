/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// fetchSolanaPayerTickets over every account of the shared fixtures, on a
// cluster that applies the filters it is sent: the twin of
// TestFetchSolanaPayerTickets in go/zs solana_payer_test.go.

import { readFileSync } from 'node:fs'

import { base64 } from '@scure/base'
import { encodeBase58, publicKeyBytes } from '@txnlab/zs-proto/solana'
import {
    ACCOUNT_VERSION,
    Deployment,
    TICKET_PAYER_OFFSET,
    decodeNode,
    decodeTicket,
    discriminator,
    ticketDeadline,
} from '@txnlab/zs-proto/solana/zsescrow'
import { describe, expect, it } from 'vitest'

import type { Account, Filter, SolanaRpc } from '../src/solana/rpc.js'
import { fetchSolanaPayerTickets } from '../src/solana/tickets.js'

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/solana_account_vectors.json', import.meta.url), 'utf8'),
) as {
    program_id: string
    accounts: { name: string; address: string; owner: string; data_base64: string }[]
}

const OTHER = '3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG'
const keyOf = (b: number) => encodeBase58(new Uint8Array(32).fill(b))

// Every account of the shared fixtures, keyed by address: five tickets of one
// payer at one node, the node, and the rest. getProgramAccounts applies the
// memcmp filters it is sent, as an RPC does.
function world() {
    const accounts = new Map<string, Account>()
    const named = new Map<string, string>()
    for (const a of vectors.accounts) {
        accounts.set(a.address, { lamports: 1n, owner: a.owner, data: base64.decode(a.data_base64), executable: false })
        named.set(a.name, a.address)
    }
    const d = new Deployment(vectors.program_id, '')
    const filters: Filter[][] = []
    const state = { readErr: undefined as Error | undefined }
    const unused = () => {
        throw new Error('unused')
    }
    const rpc: SolanaRpc = {
        getProgramAccounts: async (program, o) => {
            expect(program).toBe(d.program)
            expect(o?.commitment).toBe('confirmed')
            filters.push(o?.filters ?? [])
            return [...accounts]
                .filter(([, a]) => a.owner === program && (o?.filters ?? []).every((f) => matches(a.data, f)))
                .map(([key, account]) => ({ key, account }))
        },
        getAccountInfo: async (k, o) => {
            expect(o?.commitment).toBe('confirmed')
            if (state.readErr) throw state.readErr
            const a = accounts.get(k)
            return a === undefined ? null : { ...a }
        },
        getMinimumBalanceForRentExemption: unused,
        getBalance: unused,
        getLatestBlockhash: unused,
        sendTransaction: unused,
        getSignatureStatuses: unused,
        getBlockHeight: unused,
        getGenesisHash: unused,
    }
    const payer = decodeTicket(accounts.get(named.get('ticket_open')!)!.data).payer
    return { rpc, d, accounts, named, filters, state, payer }
}

// The ticket account's expires_at, as Go's test has it.
const TICKET_EXPIRES_AT_OFFSET = 123

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!
    return a.length - b.length
}

function matches(data: Uint8Array, f: Filter): boolean {
    if (!('memcmp' in f)) throw new Error(`filter ${JSON.stringify(f)}`)
    const { offset, bytes } = f.memcmp
    return offset + bytes.length <= data.length && bytes.every((b, i) => data[offset + i] === b)
}

describe('fetchSolanaPayerTickets', () => {
    it("lists the payer's tickets at their node, soonest deadline first", async () => {
        const w = world()
        const node = decodeNode(w.accounts.get(w.named.get('node_with_metrics')!)!.data)
        const tickets = ['ticket_open', 'ticket_pending', 'ticket_pending_by_payer', 'ticket_frozen', 'ticket_disputed']
        // Another payer's ticket, which the filter leaves on the cluster.
        const other = w.accounts.get(w.named.get('ticket_open')!)!.data.slice()
        other.set(publicKeyBytes(OTHER), TICKET_PAYER_OFFSET)
        w.accounts.set(keyOf(1), { lamports: 1n, owner: w.d.program, data: other, executable: false })

        const got = await fetchSolanaPayerTickets(w.rpc, w.d, w.payer)
        // The read moves the payer's tickets alone: Tickets, by the
        // discriminator, of this payer, at its offset.
        expect(w.filters).toEqual([
            [
                { memcmp: { offset: 0, bytes: discriminator('account', 'Ticket') } },
                { memcmp: { offset: 131, bytes: publicKeyBytes(w.payer) } },
            ],
        ])
        expect(got.unreadable).toEqual([])
        expect(got.tickets.map((t) => t.address).sort()).toEqual(tickets.map((n) => w.named.get(n)!).sort())
        for (const t of got.tickets) {
            expect([t.operatorId, t.nodeId, t.ticket.payer]).toEqual([node.operatorId, node.nodeId, w.payer])
        }
    })

    // The listing is ordered by deadline, the soonest first, and by address
    // bytes between equal deadlines. The fixtures share one deadline, so this
    // moves them apart.
    it('orders the soonest deadline first', async () => {
        const w = world()
        const base = 1_790_000_000n
        const at: [string, bigint][] = [
            ['ticket_open', 500n],
            ['ticket_pending', 100n],
            ['ticket_pending_by_payer', 300n],
            ['ticket_frozen', 100n],
            ['ticket_disputed', 400n],
        ]
        for (const [n, off] of at) {
            const a = w.accounts.get(w.named.get(n)!)!
            const data = a.data.slice()
            new DataView(data.buffer).setBigInt64(TICKET_EXPIRES_AT_OFFSET, base + off - BigInt(decodeTicket(data).grace), true)
            expect(ticketDeadline(decodeTicket(data))).toBe(base + off)
            w.accounts.set(w.named.get(n)!, { ...a, data })
        }
        const tied = [w.named.get('ticket_pending')!, w.named.get('ticket_frozen')!].sort((x, y) =>
            compareBytes(publicKeyBytes(x), publicKeyBytes(y)),
        )
        const got = await fetchSolanaPayerTickets(w.rpc, w.d, w.payer)
        expect(got.tickets.map((t) => t.address)).toEqual([
            ...tied,
            w.named.get('ticket_pending_by_payer')!,
            w.named.get('ticket_disputed')!,
            w.named.get('ticket_open')!,
        ])
    })

    // What matches the payer's filter but can't be read as one of its tickets
    // is reported, not dropped; a node read that fails fails the listing.
    it('reports the unreadable and fails on a failed node read', async () => {
        const w = world()
        const base = w.accounts.get(w.named.get('ticket_open')!)!.data
        const edit = (off: number, b: Uint8Array) => {
            const data = base.slice()
            data.set(b, off)
            return data
        }
        const [nodeless, moved, newer] = [keyOf(2), keyOf(3), keyOf(4)]
        w.accounts.set(nodeless, {
            lamports: 1n,
            owner: w.d.program,
            data: edit(TICKET_PAYER_OFFSET + 32, new Uint8Array(32).fill(9)),
            executable: false,
        })
        w.accounts.set(moved, { lamports: 1n, owner: w.d.program, data: base, executable: false })
        w.accounts.set(newer, {
            lamports: 1n,
            owner: w.d.program,
            data: edit(8, new Uint8Array([ACCOUNT_VERSION + 1])),
            executable: false,
        })

        // A Node account at a key its ids don't derive: placing the ticket by
        // those ids would list it at another node.
        const [impostorNode, impostor] = [keyOf(5), keyOf(6)]
        w.accounts.set(impostorNode, { ...w.accounts.get(w.named.get('node_with_metrics')!)! })
        w.accounts.set(impostor, {
            lamports: 1n,
            owner: w.d.program,
            data: edit(TICKET_PAYER_OFFSET + 32, publicKeyBytes(impostorNode)),
            executable: false,
        })

        const got = await fetchSolanaPayerTickets(w.rpc, w.d, w.payer)
        const why = new Map(got.unreadable.map((u) => [u.address, u.err.message]))
        expect(why.get(nodeless)).toMatch(/not a readable node/)
        expect(why.get(moved)).toMatch(/doesn't derive its address/)
        expect(why.get(newer)).toMatch(/version/)
        expect(why.get(impostor)).toMatch(/not a readable node/)
        expect([got.tickets.length, got.unreadable.length]).toEqual([5, 4])

        w.state.readErr = new Error('rpc down')
        await expect(fetchSolanaPayerTickets(w.rpc, w.d, w.payer)).rejects.toThrow(/rpc down/)
    })
})
