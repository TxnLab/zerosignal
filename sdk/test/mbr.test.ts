/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import {
    DEPOSIT_OPT_IN_MBR,
    MbrDepositUnaffordableError,
    type MbrPoolChain,
    type PayerDeposit,
    defaults,
    ensureMbrDeposit,
    mbrPoolState,
    planMbrDeposit,
    readMbrPool,
} from '../src/index.js'

type Case = Record<'slots' | 'ticketMbr' | 'quotaDue' | 'algoBalance' | 'openTickets' | 'spendable' | 'minFee' | 'amount' | 'need', string> & {
    optedIn: boolean
    belowTarget: boolean
    unaffordable: boolean
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/deposit_plan_vectors.json', import.meta.url), 'utf8')) as {
    cases: Case[]
}

describe('planMbrDeposit', () => {
    it('has vectors', () => expect(vectors.cases.length).toBeGreaterThan(500))

    it.each(vectors.cases.map((c, i) => [i, c] as const))('case %i sizes as Go does', (_, c) => {
        expect(
            planMbrDeposit({
                slots: BigInt(c.slots),
                ticketMbr: BigInt(c.ticketMbr),
                quotaDue: BigInt(c.quotaDue),
                deposit: { algoBalance: BigInt(c.algoBalance), openTickets: BigInt(c.openTickets) },
                optedIn: c.optedIn,
                spendable: BigInt(c.spendable),
                minFee: BigInt(c.minFee),
            }),
        ).toEqual({ amount: BigInt(c.amount), belowTarget: c.belowTarget, unaffordable: c.unaffordable, need: BigInt(c.need) })
    })
})

const MBR = 115_000n
const FEE = 1_000n

// A chain whose pool the deposits land in, recording what was read and sent.
function fakeChain(init: { deposit?: PayerDeposit; optedIn?: boolean; spendable?: bigint; quotaDue?: bigint; ticketMbr?: bigint }) {
    const state = {
        deposit: init.deposit ?? { algoBalance: 0n, openTickets: 0n },
        optedIn: init.optedIn ?? false,
        spendable: init.spendable ?? 0n,
    }
    const reads: string[] = []
    const deposits: { payer: string; amount: bigint; optIn: boolean }[] = []
    const chain: MbrPoolChain = {
        ticketMbr: async () => (reads.push('ticketMbr'), init.ticketMbr ?? MBR),
        freeQuotaMbrDue: async () => (reads.push('quota'), init.quotaDue ?? 0n),
        readPayerDeposit: async () => (reads.push('deposit'), { ...state.deposit }),
        isPayerOptedIn: async () => (reads.push('optedIn'), state.optedIn),
        spendableMicroAlgos: async () => (reads.push('spendable'), state.spendable),
        minTxnFee: async () => (reads.push('minFee'), FEE),
        depositMbr: async (payer, amount, optIn) => {
            deposits.push({ payer, amount, optIn })
            state.deposit.algoBalance += amount
            state.optedIn = true
            return `TX${deposits.length}`
        },
    }
    return { chain, reads, deposits }
}

describe('ensureMbrDeposit', () => {
    it('reads no further than the pool when it already covers the working set', async () => {
        const f = fakeChain({ deposit: { algoBalance: 10n * MBR, openTickets: 7n }, optedIn: true, spendable: 10n ** 9n })
        expect(await ensureMbrDeposit(f.chain, 'P', 10n)).toEqual({ deposited: 0n, belowTarget: false })
        expect(f.reads).toEqual(['ticketMbr', 'deposit', 'quota'])
        expect(f.deposits).toEqual([])
    })

    it('opts in on a first deposit and funds the whole set, quota term included', async () => {
        const f = fakeChain({ spendable: 10n ** 9n, quotaDue: 22_500n })
        expect(await ensureMbrDeposit(f.chain, 'P', 10n)).toEqual({ txid: 'TX1', deposited: 10n * MBR + 22_500n, belowTarget: false })
        expect(f.deposits).toEqual([{ payer: 'P', amount: 10n * MBR + 22_500n, optIn: true }])
        // And the next pass is a no-op.
        expect(await ensureMbrDeposit(f.chain, 'P', 10n)).toEqual({ deposited: 0n, belowTarget: false })
    })

    // A pool at exactly the working set in whole slots still owes the box term
    // until the payer's first free open; the covered-pool shortcut must count it.
    it('funds the quota term a pool of whole slots still owes', async () => {
        const f = fakeChain({ deposit: { algoBalance: 10n * MBR, openTickets: 0n }, optedIn: true, spendable: 10n ** 9n, quotaDue: 22_500n })
        expect(await ensureMbrDeposit(f.chain, 'P', 10n)).toEqual({ txid: 'TX1', deposited: 22_500n, belowTarget: false })
    })

    it('tops up an opted-in pool without opting in again', async () => {
        const f = fakeChain({ deposit: { algoBalance: 4n * MBR, openTickets: 0n }, optedIn: true, spendable: 10n ** 9n })
        expect(await ensureMbrDeposit(f.chain, 'P', 10n)).toMatchObject({ deposited: 6n * MBR })
        expect(f.deposits[0]?.optIn).toBe(false)
    })

    it('funds the slots a thin wallet affords and says it fell short', async () => {
        const f = fakeChain({ spendable: 2n * MBR + 2n * FEE + DEPOSIT_OPT_IN_MBR + 1_000n })
        expect(await ensureMbrDeposit(f.chain, 'P', 10n)).toEqual({ txid: 'TX1', deposited: 2n * MBR, belowTarget: true })
    })

    it('throws, sending nothing, when the wallet cannot fund a slot', async () => {
        const f = fakeChain({ spendable: MBR + 2n * FEE + DEPOSIT_OPT_IN_MBR - 1n })
        const err = await ensureMbrDeposit(f.chain, 'P', 10n).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(MbrDepositUnaffordableError)
        expect(err).toMatchObject({ backedSlots: 0n, slots: 10n, need: MBR + 2n * FEE + DEPOSIT_OPT_IN_MBR })
        expect(f.deposits).toEqual([])
    })

    // A pool that backs a slot can still serve, which the error says so the
    // caller can tell it from one that can't.
    it('names the slots the pool backs when it cannot add one', async () => {
        const f = fakeChain({ deposit: { algoBalance: 3n * MBR, openTickets: 3n }, optedIn: true, spendable: 5_000n })
        await expect(ensureMbrDeposit(f.chain, 'P', 10n)).rejects.toMatchObject({ backedSlots: 3n, need: MBR + 2n * FEE })
    })

    it('takes the default working set for 0', async () => {
        const f = fakeChain({ spendable: 10n ** 9n })
        expect(await ensureMbrDeposit(f.chain, 'P')).toMatchObject({ deposited: BigInt(defaults.concurrentSlots) * MBR })
    })

    it('refuses to size against an unloaded ticket MBR', async () => {
        await expect(ensureMbrDeposit(fakeChain({ ticketMbr: 0n }).chain, 'P')).rejects.toThrow('ticket MBR not loaded')
    })
})

describe('the pool state', () => {
    it('reserves a slot per live ticket and floors what is available at 0', async () => {
        expect(mbrPoolState(MBR, { algoBalance: 5n * MBR + 7n, openTickets: 2n })).toEqual({
            depositedMicroalgos: 5n * MBR + 7n,
            openTickets: 2n,
            ticketMbrMicroalgos: MBR,
            reservedMicroalgos: 2n * MBR,
            availableMicroalgos: 3n * MBR + 7n,
        })
        expect(mbrPoolState(MBR, { algoBalance: MBR, openTickets: 2n }).availableMicroalgos).toBe(0n)
        const f = fakeChain({ deposit: { algoBalance: 4n * MBR, openTickets: 1n } })
        expect((await readMbrPool(f.chain, 'P')).availableMicroalgos).toBe(3n * MBR)
    })
})
