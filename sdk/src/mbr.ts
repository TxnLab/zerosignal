/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's prepaid ticket-MBR pool: the ALGO in escrow that backs each open
// ticket's box, so open() carries no ALGO leg. Mirrors go/zs/wallet.go's
// EnsureDeposit, planDeposit and FreePoolHeadroom. The chain I/O arrives
// through MbrPoolChain, as Go's arrives through its poolEscrow seam.

import { defaults } from './config.js'

/** PayerDeposit is the payer's pool as the escrow app reports it. */
export interface PayerDeposit {
    /** µALGO on deposit. */
    algoBalance: bigint
    /** Live ticket boxes (open, pending settle, frozen), each reserving one slot. */
    openTickets: bigint
}

/**
 * The account-MBR delta a first deposit's opt-in adds to the payer's own
 * balance: the opt-in base plus six local uints (Go's depositOptInMBR).
 * Recoverable on closeDeposit; never sent to the app.
 */
export const DEPOSIT_OPT_IN_MBR = 100_000n + 6n * 28_500n

const MAX_UINT64 = (1n << 64n) - 1n

/** MbrDepositPlan is one funding pass, as planMbrDeposit sizes it. */
export interface MbrDepositPlan {
    /** µALGO to deposit; 0 when nothing is. */
    amount: bigint
    /** After amount lands, the pool is still short of the working set. */
    belowTarget: boolean
    /** The pool backs no ticket slot and the wallet can't fund one. */
    unaffordable: boolean
    /**
     * What the next useful deposit costs the wallet: the free-quota term a pool
     * backing a slot still lacks, else what the pool's part slot lacks of a
     * whole one; fees and any opt-in
     * included. Set when nothing is deposited for want of ALGO.
     */
    need: bigint
}

export interface MbrDepositInputs {
    /** The working set: concurrent ticket boxes the pool should back. */
    slots: bigint
    /** Box MBR per ticket (mbrForTicket). */
    ticketMbr: bigint
    /** The free-quota box MBR still owed: 0 once the payer has the box. */
    quotaDue: bigint
    deposit: PayerDeposit
    optedIn: boolean
    /** The payer's ALGO above its minimum balance. */
    spendable: bigint
    minFee: bigint
}

/**
 * planMbrDeposit sizes a funding pass, as Go's planDeposit does: as many whole
 * slots as the wallet affords, up to the working set, with the free-quota term
 * on top only if it still fits; with no whole slot affordable, the quota term
 * alone, for a pool that already backs a slot. Sized on the gross balance, so
 * tickets in flight don't read as a gap. Pinned by
 * testdata/deposit_plan_vectors.json. ticketMbr must be non-zero.
 */
export function planMbrDeposit(i: MbrDepositInputs): MbrDepositPlan {
    const none: MbrDepositPlan = { amount: 0n, belowTarget: false, unaffordable: false, need: 0n }
    const bal = i.deposit.algoBalance
    const target = poolTarget(i.slots, i.ticketMbr, i.quotaDue)
    if (bal >= target) return none

    const overhead = 2n * i.minFee + (i.optedIn ? 0n : DEPOSIT_OPT_IN_MBR)
    const net = i.spendable > overhead ? i.spendable - overhead : 0n
    // The next slot costs only what the pool's part slot lacks.
    const need = i.ticketMbr - (bal % i.ticketMbr) + overhead

    const current = bal / i.ticketMbr
    // The pool and the wallet together, so a part slot already in the pool
    // counts toward the next one; saturating as Go's does.
    const reach = bal + net > MAX_UINT64 ? MAX_UINT64 : bal + net
    const affordable = reach / i.ticketMbr
    const targetSlots = affordable < i.slots ? affordable : i.slots
    if (targetSlots <= current) {
        const quota = quotaOnlyShortfall(i.ticketMbr, i.quotaDue, bal)
        if (current >= 1n && quota > 0n) {
            return net >= quota
                ? { ...none, amount: quota, belowTarget: bal + quota < target }
                : { ...none, belowTarget: true, need: quota + overhead }
        }
        return current >= 1n ? { ...none, belowTarget: true, need } : { ...none, unaffordable: true, need }
    }
    let amount = targetSlots * i.ticketMbr - bal
    if (net >= amount + i.quotaDue) amount += i.quotaDue
    return { ...none, amount, belowTarget: bal + amount < target }
}

// slots × ticketMbr + quotaDue, saturating at the uint64 ceiling as Go's
// poolTarget does, so a target past it reads as unaffordable, never as small.
function poolTarget(slots: bigint, ticketMbr: bigint, quotaDue: bigint): bigint {
    const t = slots * ticketMbr + quotaDue
    return t > MAX_UINT64 ? MAX_UINT64 : t
}

// The quota term the pool's sub-slot remainder doesn't already cover.
function quotaOnlyShortfall(ticketMbr: bigint, quotaDue: bigint, balance: bigint): bigint {
    if (quotaDue === 0n || ticketMbr === 0n) return 0n
    const remainder = balance % ticketMbr
    return remainder >= quotaDue ? 0n : quotaDue - remainder
}

/** MbrPoolState is the pool resolved for display and the withdraw controls. */
export interface MbrPoolState {
    /** µALGO on deposit. */
    depositedMicroalgos: bigint
    /** Live ticket boxes. */
    openTickets: bigint
    /** Box MBR each ticket reserves. */
    ticketMbrMicroalgos: bigint
    /** openTickets × ticketMbr: locked until those boxes are deleted. */
    reservedMicroalgos: bigint
    /** deposited − reserved, floored at 0: what a withdraw may take (Go's FreePoolHeadroom). */
    availableMicroalgos: bigint
}

/** mbrPoolState resolves a deposit against the ticket MBR. */
export function mbrPoolState(ticketMbr: bigint, deposit: PayerDeposit): MbrPoolState {
    const reserved = deposit.openTickets * ticketMbr
    return {
        depositedMicroalgos: deposit.algoBalance,
        openTickets: deposit.openTickets,
        ticketMbrMicroalgos: ticketMbr,
        reservedMicroalgos: reserved,
        availableMicroalgos: deposit.algoBalance > reserved ? deposit.algoBalance - reserved : 0n,
    }
}

/**
 * MbrPoolChain is the chain the pool is read and funded through: the escrow
 * app's readonly calls, the payer's account, and the deposit group. Go's
 * poolEscrow.
 */
export interface MbrPoolChain {
    /** Box MBR per ticket (mbrForTicket). */
    ticketMbr(): Promise<bigint>
    /**
     * The free-quota box MBR this payer still owes; 0 once the box exists, or
     * against an app without the quota. Fails open as Go's does: an unreadable
     * box resolves to the full term rather than rejecting, so a flaky read
     * over-funds the pool instead of failing the open.
     */
    freeQuotaMbrDue(payer: string): Promise<bigint>
    readPayerDeposit(payer: string): Promise<PayerDeposit>
    /** Tells "no pool yet" (the deposit opts in) from a drained one. */
    isPayerOptedIn(payer: string): Promise<boolean>
    /** The payer's ALGO above its minimum balance, floored at 0. */
    spendableMicroAlgos(payer: string): Promise<bigint>
    minTxnFee(): Promise<bigint>
    /** Submits the deposit group (payment + depositMbr, OptIn on a first deposit), resolving to its txid. */
    depositMbr(payer: string, amount: bigint, optIn: boolean): Promise<string>
}

/**
 * MbrDepositUnaffordableError: the wallet can't afford the next useful deposit,
 * `need` (Go's ErrDepositUnaffordable). Thrown before anything is signed.
 * backedSlots says whether the pool can still serve: one that backs a slot
 * can, while its tickets settle.
 */
export class MbrDepositUnaffordableError extends Error {
    override readonly name = 'MbrDepositUnaffordableError'

    constructor(
        readonly backedSlots: bigint,
        readonly slots: bigint,
        readonly need: bigint,
        readonly spendable: bigint,
    ) {
        super(
            `insufficient ALGO to fund the prepaid MBR pool: it backs ${backedSlots} of ${slots} slot(s); ` +
                `the next deposit needs ${need} µALGO, have ${spendable} spendable — add ALGO to the wallet`,
        )
    }
}

/** MbrDeposit is what ensureMbrDeposit did. */
export interface MbrDeposit {
    /** The deposit's txid; absent when nothing was deposited. */
    txid?: string
    /** µALGO deposited. */
    deposited: bigint
    /** The pool is still short of the working set after this pass. */
    belowTarget: boolean
}

/**
 * ensureMbrDeposit funds the payer's pool toward `slots` ticket boxes (0: the
 * default working set), opting in on a first deposit. Idempotent: nothing is
 * read past the deposit, and nothing sent, when the pool already covers the
 * set. A wallet that can't reach the set funds what it affords and reports
 * belowTarget; one that can't afford a slot throws MbrDepositUnaffordableError.
 * Go's Wallet.EnsureDeposit, whose ErrDepositBelowTarget is belowTarget here.
 *
 * Not single-flight: two concurrent passes for one payer can each read the
 * pool short and both deposit. A caller that can race serializes its calls.
 */
export async function ensureMbrDeposit(chain: MbrPoolChain, payer: string, slots = 0n): Promise<MbrDeposit> {
    const workingSet = slots > 0n ? slots : BigInt(defaults.concurrentSlots)
    const ticketMbr = await chain.ticketMbr()
    if (ticketMbr <= 0n) throw new Error('mbr: ensure-deposit: ticket MBR not loaded')
    const deposit = await chain.readPayerDeposit(payer)
    const quotaDue = await chain.freeQuotaMbrDue(payer)
    if (deposit.algoBalance >= poolTarget(workingSet, ticketMbr, quotaDue)) {
        return { deposited: 0n, belowTarget: false }
    }
    const optedIn = await chain.isPayerOptedIn(payer)
    const minFee = await chain.minTxnFee()
    const spendable = await chain.spendableMicroAlgos(payer)

    const plan = planMbrDeposit({ slots: workingSet, ticketMbr, quotaDue, deposit, optedIn, spendable, minFee })
    if (plan.amount === 0n) {
        throw new MbrDepositUnaffordableError(deposit.algoBalance / ticketMbr, workingSet, plan.need, spendable)
    }
    const txid = await chain.depositMbr(payer, plan.amount, !optedIn)
    return { txid, deposited: plan.amount, belowTarget: plan.belowTarget }
}

/** readMbrPool reads the payer's pool for display. */
export async function readMbrPool(chain: MbrPoolChain, payer: string): Promise<MbrPoolState> {
    const [deposit, ticketMbr] = await Promise.all([chain.readPayerDeposit(payer), chain.ticketMbr()])
    return mbrPoolState(ticketMbr, deposit)
}
