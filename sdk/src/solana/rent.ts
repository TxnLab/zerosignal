/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's ticket rent pool on the Solana rail, the twin of go/zs
// solana_rent.go: the lamports the zs_escrow program draws each ticket's rent
// from at open, as Algorand's prepaid MBR pool backs each ticket's box
// (mbr.ts). Sized by the same rule, through planPoolDeposit.

import { type PublicKey, compileMessage, encodeTransaction, newTransaction, signTransactionWith } from '@txnlab/zs-proto/solana'
import { type Deployment, RENT_POOL_SIZE, TICKET_SIZE, decodeRentPool } from '@txnlab/zs-proto/solana/zsescrow'

import { defaults } from '../config.js'
import { MbrDepositUnaffordableError } from '../mbr.js'
import { type PoolDepositPlan, planPoolDeposit, poolTarget } from '../pool.js'
import type { SolanaSigner } from '../ports.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS } from '../registry/solana.js'
import { type ConfirmOptions, confirmSignature } from './confirm.js'
import { type SolanaRpc, txErrorName } from './rpc.js'

/** The lamports a fee payer pays for each signature. A deposit carries the payer's alone and sets no priority fee. */
export const SOLANA_SIGNATURE_FEE = 5_000n

const MAX_UINT64 = (1n << 64n) - 1n

// Confirmed, as the registry reads: a payer that just funded its wallet sees
// the lamports in about a second.
const COMMITMENT = 'confirmed'

/** The payer's rent pool as the chain shows it. */
export interface RentPoolReading {
    /**
     * A pool the program owns. Lamports someone sent to the address before
     * the first deposit don't make one: the deposit still creates it, so it is
     * planned as though the address were empty.
     */
    exists: boolean
    /** The pool account's lamports, its own rent included. */
    lamports: bigint
    openTickets: bigint
}

/**
 * What the pool backs counting its live tickets, whose rent sits in the
 * tickets rather than the pool, saturating: the basis planPoolDeposit sizes
 * on, as Algorand's gross algoBalance is.
 */
export function rentPoolGross(ticketRent: bigint, poolRent: bigint, pool: RentPoolReading): bigint {
    if (!pool.exists) return 0n
    const available = pool.lamports > poolRent ? pool.lamports - poolRent : 0n
    const gross = available + pool.openTickets * ticketRent
    return gross > MAX_UINT64 ? MAX_UINT64 : gross
}

/**
 * planRentDeposit sizes a top-up of the rent pool by planMbrDeposit's rule,
 * with a ticket's rent as the slot, as Go's planRentDeposit does. There is no
 * quota term, and the overhead is the deposit's fee plus, on a first deposit,
 * the pool's own rent, which deposit_rent charges the payer on top of the
 * amount. spendable is the payer's lamports above its own reserve. Pinned by
 * testdata/rent_deposit_plan_vectors.json. ticketRent must be non-zero.
 */
export function planRentDeposit(slots: bigint, ticketRent: bigint, poolRent: bigint, pool: RentPoolReading, spendable: bigint): PoolDepositPlan {
    const overhead = SOLANA_SIGNATURE_FEE + (pool.exists ? 0n : poolRent)
    return planPoolDeposit(slots, ticketRent, 0n, rentPoolGross(ticketRent, poolRent, pool), overhead, spendable)
}

/**
 * The wallet can't afford the next useful deposit, `need` lamports (Go's
 * ErrRentDepositUnaffordable). An MbrDepositUnaffordableError, so the serving
 * path takes it as it takes Algorand's. Thrown before anything is signed.
 * breakdown is what `need` is made of, as Go's error spells it.
 */
export class RentDepositUnaffordableError extends MbrDepositUnaffordableError {
    override readonly name = 'RentDepositUnaffordableError'

    constructor(backedSlots: bigint, slots: bigint, need: bigint, spendable: bigint, breakdown: string) {
        super(
            backedSlots,
            slots,
            need,
            spendable,
            `insufficient SOL to fund the ticket rent pool: it backs ${backedSlots} of ${slots} slot(s); ` +
                `one more slot needs ${need} lamports (${breakdown}), have ${spendable} lamports spendable — fund the wallet with more SOL`,
        )
    }
}

/**
 * A deposit sent but not confirmed (Go returns its signature beside the
 * error). Unless the cause is a TransactionExpiredError it may still land: the
 * signature lets the caller look before it sends another.
 */
export class RentDepositUnconfirmedError extends Error {
    override readonly name = 'RentDepositUnconfirmedError'

    constructor(
        readonly signature: string,
        cause: unknown,
    ) {
        super(`solana rent pool: deposit ${signature}: ${cause instanceof Error ? cause.message : String(cause)}`, { cause })
    }
}

/** What ensureDeposit did. */
export interface RentDeposit {
    /** The deposit's signature; absent when nothing was deposited. */
    signature?: string
    /** Lamports deposited. */
    deposited: bigint
    /** The pool is still short of the working set after this pass. */
    belowTarget: boolean
}

export interface SolanaRentPoolOptions {
    rpc: SolanaRpc
    deployment: Deployment
    signer: SolanaSigner
    /** Tunes the wait for a deposit to land; absent polls. */
    confirm?: Omit<ConfirmOptions, 'signal'> | undefined
}

interface PoolState {
    payer: PublicKey
    pool: RentPoolReading
    ticketRent: bigint
    poolRent: bigint
}

/**
 * SolanaRentPool funds the payer's ticket rent pool, as ensureMbrDeposit funds
 * Algorand's prepaid MBR pool. Go's zs.SolanaRentPool.
 */
export class SolanaRentPool {
    readonly #o: SolanaRentPoolOptions

    constructor(o: SolanaRentPoolOptions) {
        this.#o = o
    }

    async #read(signal: AbortSignal | undefined): Promise<PoolState> {
        const { rpc, deployment, signer } = this.#o
        const payer = signer.address
        const opts = { commitment: COMMITMENT, signal } as const
        const ticketRent = await rpc.getMinimumBalanceForRentExemption(TICKET_SIZE, opts)
        if (ticketRent === 0n) throw new Error('solana rent pool: the cluster quotes no ticket rent')
        const poolRent = await rpc.getMinimumBalanceForRentExemption(RENT_POOL_SIZE, opts)
        const acct = await rpc.getAccountInfo(deployment.rentPool(payer), opts)
        let pool: RentPoolReading = { exists: false, lamports: 0n, openTickets: 0n }
        if (acct !== null && acct.owner === deployment.program) {
            pool = { exists: true, lamports: acct.lamports, openTickets: decodeRentPool(acct.data).openTickets }
        }
        return { payer, pool, ticketRent, poolRent }
    }

    /**
     * How many more tickets the pool can fund right now: an open needs one, so
     * the serving path proceeds on a pool short of its working set while this
     * is at least 1.
     */
    async freeSlots(signal?: AbortSignal): Promise<bigint> {
        const s = await this.#read(signal)
        if (!s.pool.exists) return 0n
        const available = s.pool.lamports > s.poolRent ? s.pool.lamports - s.poolRent : 0n
        return available / s.ticketRent
    }

    /**
     * ensureDeposit makes sure the pool is sized for `slots` concurrent tickets
     * (0: the default working set), creating it on the first deposit. It has
     * ensureMbrDeposit's contract: nothing read past the pool and nothing sent
     * when the pool covers the set, belowTarget beside a real deposit that fell
     * short, and RentDepositUnaffordableError before anything is signed. It
     * resolves once the deposit is confirmed; a deposit sent but not confirmed
     * throws RentDepositUnconfirmedError.
     *
     * Not single-flight: two concurrent passes can each read the pool short and
     * both deposit.
     */
    async ensureDeposit(slots = 0n, signal?: AbortSignal): Promise<RentDeposit> {
        const { rpc, deployment, signer } = this.#o
        const workingSet = slots > 0n ? slots : BigInt(defaults.concurrentSlots)
        const s = await this.#read(signal)
        const gross = rentPoolGross(s.ticketRent, s.poolRent, s.pool)
        if (gross >= poolTarget(workingSet, s.ticketRent, 0n)) return { deposited: 0n, belowTarget: false }
        const balance = await rpc.getBalance(s.payer, { commitment: COMMITMENT, signal })
        const spendable = balance < SOLANA_SIGNER_RESERVE_LAMPORTS ? 0n : balance - SOLANA_SIGNER_RESERVE_LAMPORTS

        const plan = planRentDeposit(workingSet, s.ticketRent, s.poolRent, s.pool, spendable)
        if (plan.amount === 0n) {
            const firstDeposit = s.pool.exists ? '' : ` + ${s.poolRent} pool rent`
            const breakdown = `${s.ticketRent - (gross % s.ticketRent)} + ${SOLANA_SIGNATURE_FEE} fee${firstDeposit}`
            throw new RentDepositUnaffordableError(gross / s.ticketRent, workingSet, plan.need, spendable, breakdown)
        }

        const bh = await rpc.getLatestBlockhash({ commitment: COMMITMENT, signal })
        const tx = newTransaction(compileMessage(s.payer, bh.blockhash, [deployment.depositRent(s.payer, plan.amount)], 'legacy'))
        await signTransactionWith(tx, s.payer, signer)
        // Preflight at the commitment the plan read, not the RPC's finalized
        // default, which may not see the lamports the plan counted.
        const signature = await rpc.sendTransaction(encodeTransaction(tx), { preflightCommitment: COMMITMENT, signal })
        let r
        try {
            r = await confirmSignature(rpc, signature, bh.lastValidBlockHeight, COMMITMENT, { ...this.#o.confirm, signal })
        } catch (e) {
            throw new RentDepositUnconfirmedError(signature, e)
        }
        if (r.err !== null) throw new Error(`solana rent pool: deposit ${signature} failed: ${txErrorName(r.err)}`)
        return { signature, deposited: plan.amount, belowTarget: plan.belowTarget }
    }
}
