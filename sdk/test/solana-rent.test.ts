/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Solana rent pool: planRentDeposit against Go's vectors, and
// SolanaRentPool against a cluster whose pool the deposits land in, ported
// from go/zs solana_rent_test.go.

import { readFileSync } from 'node:fs'

import * as ed25519 from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha2.js'
import {
    type Instruction,
    type Transaction,
    compileMessage,
    encodeBase58,
    encodeMessage,
    parseTransaction,
    publicKeyBytes,
    verifySignatures,
} from '@txnlab/zs-proto/solana'
import { Deployment, PROGRAM_ID } from '@txnlab/zs-proto/solana/zsescrow'
import { describe, expect, it } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { MbrDepositUnaffordableError } from '../src/mbr.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS } from '../src/registry/solana.js'
import { TransactionExpiredError } from '../src/solana/confirm.js'
import {
    NoRentPoolError,
    RentDepositUnaffordableError,
    RentDepositUnconfirmedError,
    RentPoolTicketsOpenError,
    RentPoolUnconfirmedError,
    SOLANA_SIGNATURE_FEE,
    SolanaRentPool,
    planRentDeposit,
    readSolanaRentPool,
    rentPoolAvailable,
    rentPoolBackedSlots,
    rentPoolFreeSlots,
    rentPoolGross,
} from '../src/solana/rent.js'
import type { Account, SendOptions, SignatureStatus, SolanaRpc } from '../src/solana/rpc.js'

interface Case {
    slots: string
    ticketRent: string
    poolRent: string
    poolExists: boolean
    lamports: string
    openTickets: string
    spendable: string
    amount: string
    belowTarget: boolean
    unaffordable: boolean
    need: string
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/rent_deposit_plan_vectors.json', import.meta.url), 'utf8')) as {
    signatureFee: string
    cases: Case[]
}

describe('planRentDeposit', () => {
    it('has vectors', () => expect(vectors.cases.length).toBeGreaterThan(200))

    it("charges Go's signature fee", () => expect(SOLANA_SIGNATURE_FEE).toBe(BigInt(vectors.signatureFee)))

    it.each(vectors.cases.map((c, i) => [i, c] as const))('case %i sizes as Go does', (_, c) => {
        const pool = { exists: c.poolExists, lamports: BigInt(c.lamports), openTickets: BigInt(c.openTickets) }
        expect(planRentDeposit(BigInt(c.slots), BigInt(c.ticketRent), BigInt(c.poolRent), pool, BigInt(c.spendable))).toEqual({
            amount: BigInt(c.amount),
            belowTarget: c.belowTarget,
            unaffordable: c.unaffordable,
            need: BigInt(c.need),
        })
    })
})

describe('rentPoolGross', () => {
    it("saturates as Go's does", () => {
        const max = (1n << 64n) - 1n
        expect(rentPoolGross(2n, 0n, { exists: true, lamports: 10n, openTickets: max / 2n + 1n })).toBe(max)
        expect(rentPoolGross(2n, 0n, { exists: true, lamports: 10n, openTickets: 3n })).toBe(16n)
    })
})

const TICKET_RENT = (128n + 291n) * 6_960n
const POOL_RENT = (128n + 82n) * 6_960n

const seed = new Uint8Array(32).fill(7)
const publicKey = ed25519.getPublicKey(seed)
const signer = solanaSigner({ seed, publicKey, address: encodeBase58(publicKey) })
const PAYER = signer.address
const d = new Deployment(PROGRAM_ID, PAYER)
const BLOCKHASH = encodeBase58(new Uint8Array(32).fill(9))

function poolAccount(lamports: bigint, open: bigint): Account {
    const data = new Uint8Array(82)
    data.set(sha256(new TextEncoder().encode('account:RentPool')).slice(0, 8))
    data[8] = 1
    data[9] = 255
    new DataView(data.buffer).setBigUint64(10, open, true)
    data.set(publicKeyBytes(PAYER), 18)
    return { lamports, owner: PROGRAM_ID, data, executable: false }
}

/** A cluster holding the payer and its pool. A deposit it is sent lands at once, as deposit_rent moves it, unless land says otherwise. */
function cluster(balance: bigint, poolAt: Account | null = null, land?: () => SignatureStatus | null) {
    const state = { balance, pool: poolAt, balanceReads: 0, height: 0n }
    const sent: { tx: Transaction; o: SendOptions | undefined }[] = []
    const statuses = new Map<string, SignatureStatus | null>()
    const unused = () => {
        throw new Error('unused')
    }
    const rpc: SolanaRpc = {
        getMinimumBalanceForRentExemption: async (n, o) => {
            expect(o?.commitment).toBe('confirmed')
            return (128n + BigInt(n)) * 6_960n
        },
        getAccountInfo: async (k, o) => {
            expect(k).toBe(d.rentPool(PAYER))
            expect(o?.commitment).toBe('confirmed')
            return state.pool === null ? null : { ...state.pool }
        },
        getBalance: async (k, o) => {
            expect(k).toBe(PAYER)
            expect(o?.commitment).toBe('confirmed')
            return (state.balanceReads++, state.balance)
        },
        getLatestBlockhash: async (o) => {
            expect(o?.commitment).toBe('confirmed')
            return { blockhash: BLOCKHASH, lastValidBlockHeight: 150n }
        },
        sendTransaction: async (raw, o) => {
            const tx = parseTransaction(raw)
            verifySignatures(tx)
            sent.push({ tx, o })
            const data = tx.message.instructions[0]!.data
            const amount = data.length >= 16 ? new DataView(data.buffer, data.byteOffset).getBigUint64(data.length - 8, true) : 0n
            const st = land === undefined ? { slot: 5n, confirmations: 1n, err: null, confirmationStatus: 'confirmed' as const } : land()
            if (st !== null && st.err === null) {
                state.balance -= SOLANA_SIGNATURE_FEE
                if (bytesEqual(data, d.closeRentPool(PAYER).data)) {
                    state.balance += state.pool!.lamports
                    state.pool = null
                } else if (bytesEqual(data.slice(0, 8), d.withdrawRent(PAYER, 0n).data.slice(0, 8))) {
                    state.pool!.lamports -= amount
                    state.balance += amount
                } else {
                    if (state.pool === null || state.pool.owner !== PROGRAM_ID) {
                        state.pool = poolAccount(POOL_RENT, 0n)
                        state.balance -= POOL_RENT
                    }
                    state.pool.lamports += amount
                    state.balance -= amount
                }
            }
            const sig = encodeBase58(tx.signatures[0]!)
            statuses.set(sig, st)
            return sig
        },
        getSignatureStatuses: async (sigs) => [statuses.get(sigs[0]!) ?? null],
        getBlockHeight: async () => (state.height += 100n),
        getProgramAccounts: unused,
        getGenesisHash: unused,
    }
    const pool = new SolanaRentPool({ rpc, deployment: d, signer, confirm: { pollMs: 1, heightCheckMs: 1 } })
    return { rpc, state, sent, pool }
}

describe('SolanaRentPool', () => {
    it('creates the pool on the first deposit', async () => {
        const c = cluster(1_000_000_000n)
        const r = await c.pool.ensureDeposit(3n)
        expect(r.deposited).toBe(3n * TICKET_RENT)
        expect(r.belowTarget).toBe(false)
        expect(c.sent).toHaveLength(1)
        const { tx, o } = c.sent[0]!
        expect(r.signature).toBe(encodeBase58(tx.signatures[0]!))
        // The payer pays its own fee, and the transaction is the builder's instruction and nothing else.
        const want = compileMessage(PAYER, BLOCKHASH, [d.depositRent(PAYER, r.deposited)], 'legacy')
        expect(encodeMessage(tx.message)).toEqual(encodeMessage(want))
        expect(o?.preflightCommitment).toBe('confirmed')
        // The pool now covers the set, so a second pass sends nothing.
        await expect(c.pool.ensureDeposit(3n)).resolves.toEqual({ deposited: 0n, belowTarget: false })
        expect(c.sent).toHaveLength(1)
    })

    it('reads no balance for a pool that covers the set', async () => {
        // Live tickets' rent sits in the tickets: 2 in the pool and 8 out cover 10.
        const c = cluster(0n, poolAccount(POOL_RENT + 2n * TICKET_RENT, 8n))
        await expect(c.pool.ensureDeposit()).resolves.toEqual({ deposited: 0n, belowTarget: false })
        expect(c.state.balanceReads).toBe(0)
        expect(c.sent).toHaveLength(0)
    })

    it('sends nothing it cannot afford', async () => {
        // One lamport short of the pool's rent, a slot and the fee above the reserve.
        const c = cluster(SOLANA_SIGNER_RESERVE_LAMPORTS + POOL_RENT + TICKET_RENT + SOLANA_SIGNATURE_FEE - 1n)
        const err = await c.pool.ensureDeposit(1n).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(RentDepositUnaffordableError)
        // The serving path's branch on Algorand's error takes it too.
        expect(err).toBeInstanceOf(MbrDepositUnaffordableError)
        expect(err).toMatchObject({ backedSlots: 0n, slots: 1n, need: 4_382_840n, spendable: 4_382_839n })
        expect((err as Error).message).toContain('one more slot needs 4382840 lamports (2916240 + 5000 fee + 1461600 pool rent)')
        expect((err as Error).stack).not.toMatch(/ALGO/)
        expect(c.sent).toHaveLength(0)
    })

    it('reports a deposit short of the set', async () => {
        const c = cluster(SOLANA_SIGNER_RESERVE_LAMPORTS + 2n * TICKET_RENT + SOLANA_SIGNATURE_FEE, poolAccount(POOL_RENT, 0n))
        const r = await c.pool.ensureDeposit(10n)
        expect(r).toMatchObject({ deposited: 2n * TICKET_RENT, belowTarget: true })
        expect(r.signature).toBeDefined()
        await expect(c.pool.freeSlots()).resolves.toBe(2n)
    })

    it('plans lamports at the address as no pool', async () => {
        // Exactly a first deposit's cost: the stray lamports don't lower it.
        const c = cluster(SOLANA_SIGNER_RESERVE_LAMPORTS + POOL_RENT + TICKET_RENT + SOLANA_SIGNATURE_FEE, {
            lamports: 5n * TICKET_RENT,
            owner: '11111111111111111111111111111111',
            data: new Uint8Array(),
            executable: false,
        })
        await expect(c.pool.ensureDeposit(1n)).resolves.toMatchObject({ deposited: TICKET_RENT })
    })

    it('has no free slots without a pool', async () => {
        await expect(cluster(0n).pool.freeSlots()).resolves.toBe(0n)
    })

    it('reports a failed landing', async () => {
        const c = cluster(1_000_000_000n, null, () => ({
            slot: 5n,
            confirmations: 1n,
            err: { InstructionError: [0, { Custom: 6053 }] },
            confirmationStatus: 'confirmed',
        }))
        await expect(c.pool.ensureDeposit(1n)).rejects.toThrow(/failed: InstructionError/)
    })

    it('reports an expired deposit', async () => {
        const c = cluster(1_000_000_000n, null, () => null)
        const err = await c.pool.ensureDeposit(1n).catch((e: unknown) => e)
        // What was sent is named beside the cause.
        expect(err).toBeInstanceOf(RentDepositUnconfirmedError)
        expect((err as RentDepositUnconfirmedError).signature).toBe(encodeBase58(c.sent[0]!.tx.signatures[0]!))
        expect((err as Error).cause).toBeInstanceOf(TransactionExpiredError)
    })

    // The last transaction sent is ix alone with the payer as fee payer, preflighted at confirmed.
    function sentAlone(c: ReturnType<typeof cluster>, ix: Instruction) {
        const { tx, o } = c.sent.at(-1)!
        expect(encodeMessage(tx.message)).toEqual(encodeMessage(compileMessage(PAYER, BLOCKHASH, [ix], 'legacy')))
        expect(o?.preflightCommitment).toBe('confirmed')
    }

    it('reads its status', async () => {
        // Three slots' rent in the pool, two more in live tickets, and a few lamports short of a fourth.
        const c = cluster(0n, poolAccount(POOL_RENT + 4n * TICKET_RENT - 1n, 2n))
        const want = {
            exists: true,
            lamports: POOL_RENT + 4n * TICKET_RENT - 1n,
            openTickets: 2n,
            ticketRent: TICKET_RENT,
            poolRent: POOL_RENT,
        }
        const got = await readSolanaRentPool(c.rpc, d, PAYER)
        expect(got).toEqual(want)
        expect([rentPoolAvailable(got), rentPoolFreeSlots(got), rentPoolBackedSlots(got)]).toEqual([
            4n * TICKET_RENT - 1n,
            3n,
            5n,
        ])
        await expect(c.pool.status()).resolves.toEqual(want)

        // A pool holding less than its own rent has nothing to draw.
        c.state.pool = poolAccount(POOL_RENT - 1n, 0n)
        const under = await readSolanaRentPool(c.rpc, d, PAYER)
        expect([rentPoolAvailable(under), rentPoolFreeSlots(under), rentPoolBackedSlots(under)]).toEqual([0n, 0n, 0n])
        // Lamports at the address are no pool.
        c.state.pool = {
            lamports: 5n * TICKET_RENT,
            owner: '11111111111111111111111111111111',
            data: new Uint8Array(),
            executable: false,
        }
        const stray = await readSolanaRentPool(c.rpc, d, PAYER)
        expect([stray.exists, rentPoolAvailable(stray), rentPoolBackedSlots(stray)]).toEqual([false, 0n, 0n])

        // A status no read filled in has no slots, rather than dividing by zero.
        const zero = { exists: true, lamports: 5n * TICKET_RENT, openTickets: 1n, ticketRent: 0n, poolRent: 0n }
        expect([rentPoolFreeSlots(zero), rentPoolBackedSlots(zero)]).toEqual([0n, 0n])
    })

    it('withdraws up to what it holds above its rent', async () => {
        const c = cluster(0n, poolAccount(POOL_RENT + 3n * TICKET_RENT, 1n))
        // More than the pool holds above its rent, or nothing, is refused unsent.
        for (const n of [0n, 3n * TICKET_RENT + 1n]) {
            await expect(c.pool.withdraw(n)).rejects.toThrow(/above its own rent/)
        }
        expect(c.sent).toHaveLength(0)
        // All of it, to the lamport.
        const sig = await c.pool.withdraw(3n * TICKET_RENT)
        expect(sig).toBe(encodeBase58(c.sent[0]!.tx.signatures[0]!))
        sentAlone(c, d.withdrawRent(PAYER, 3n * TICKET_RENT))
        const st = await c.pool.status()
        expect([rentPoolAvailable(st), st.openTickets]).toEqual([0n, 1n])
    })

    it('closes only with no ticket open', async () => {
        const c = cluster(0n, poolAccount(POOL_RENT + 2n * TICKET_RENT, 1n))
        const err = await c.pool.close().catch((e: unknown) => e)
        expect(err).toBeInstanceOf(RentPoolTicketsOpenError)
        expect((err as RentPoolTicketsOpenError).openTickets).toBe(1n)
        expect(c.sent).toHaveLength(0)
        c.state.pool = poolAccount(POOL_RENT + 2n * TICKET_RENT, 0n)
        const r = await c.pool.close()
        expect(r).toEqual({
            signature: encodeBase58(c.sent[0]!.tx.signatures[0]!),
            returned: POOL_RENT + 2n * TICKET_RENT,
        })
        sentAlone(c, d.closeRentPool(PAYER))
        expect(c.state.balance).toBe(POOL_RENT + 2n * TICKET_RENT - SOLANA_SIGNATURE_FEE)
    })

    it('refuses a withdraw or close without a pool', async () => {
        const c = cluster(1_000_000_000n)
        await expect(c.pool.withdraw(1n)).rejects.toBeInstanceOf(NoRentPoolError)
        await expect(c.pool.close()).rejects.toBeInstanceOf(NoRentPoolError)
        expect(c.sent).toHaveLength(0)
    })

    it('reports a failed withdraw and an expired close', async () => {
        let land: SignatureStatus | null = {
            slot: 5n,
            confirmations: 1n,
            err: { InstructionError: [0, { Custom: 6000 }] },
            confirmationStatus: 'confirmed',
        }
        const c = cluster(0n, poolAccount(POOL_RENT + TICKET_RENT, 0n), () => land)
        await expect(c.pool.withdraw(TICKET_RENT)).rejects.toThrow(/withdraw .* failed: InstructionError/)
        land = null
        const err = await c.pool.close().catch((e: unknown) => e)
        expect(err).toBeInstanceOf(RentPoolUnconfirmedError)
        expect(err).not.toBeInstanceOf(RentDepositUnconfirmedError)
        expect((err as RentPoolUnconfirmedError).signature).toBe(encodeBase58(c.sent[1]!.tx.signatures[0]!))
        expect((err as Error).cause).toBeInstanceOf(TransactionExpiredError)
    })
})

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((v, i) => v === b[i])
}
