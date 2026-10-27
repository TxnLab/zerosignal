/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's ticket rent pool on the Solana rail, the twin of go/zs
// solana_rent.go: the lamports the zs_escrow program draws each ticket's rent
// from at open, as Algorand's prepaid MBR pool backs each ticket's box
// (mbr.ts). Sized by the same rule, through planPoolDeposit.

import { type Instruction, type PublicKey, compileMessage, encodeTransaction, newTransaction, signTransactionWith } from '@txnlab/zs-proto/solana'
import { type Deployment, RENT_POOL_SIZE, TICKET_SIZE, decodeRentPool } from '@txnlab/zs-proto/solana/zsescrow'

import { defaults } from '../config.js'
import { MbrDepositUnaffordableError } from '../mbr.js'
import { type PoolDepositPlan, planPoolDeposit, poolTarget } from '../pool.js'
import type { SolanaSigner } from '../ports.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS } from '../registry/solana.js'
import { BelowTargetError } from '../wallet.js'
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
 * A deposit landed but left the pool short of the working set, with no free
 * slot to serve on (Go's ErrRentDepositBelowTarget). A BelowTargetError, so
 * the serving path takes it as it takes Algorand's.
 */
export class RentDepositBelowTargetError extends BelowTargetError {
    override readonly name = 'RentDepositBelowTargetError'

    constructor(deposited: bigint) {
        super(deposited)
        this.message = `wallet: ticket rent pool funded below the configured working set (deposited ${deposited} lamports)`
    }
}

/**
 * A pool transaction sent but not confirmed (Go returns its signature beside
 * the error). Unless the cause is a TransactionExpiredError it may still land:
 * the signature lets the caller look before it sends another.
 */
export class RentPoolUnconfirmedError extends Error {
    override readonly name: string = 'RentPoolUnconfirmedError'

    constructor(
        what: string,
        readonly signature: string,
        cause: unknown,
    ) {
        super(`solana rent pool: ${what} ${signature}: ${message(cause)}`, { cause })
    }
}

/** A deposit sent but not confirmed, as RentPoolUnconfirmedError. */
export class RentDepositUnconfirmedError extends RentPoolUnconfirmedError {
    override readonly name: string = 'RentDepositUnconfirmedError'

    constructor(signature: string, cause: unknown) {
        super('deposit', signature, cause)
    }
}

/** A withdraw or close on a payer with no rent pool. Go's ErrNoRentPool. */
export class NoRentPoolError extends Error {
    override readonly name = 'NoRentPoolError'

    constructor() {
        super('solana rent pool: this payer has no rent pool')
    }
}

/**
 * A close while tickets the pool funded are live: their rent returns to the
 * pool when each ends, and the program refuses the close until then. Go's
 * ErrRentPoolTicketsOpen.
 */
export class RentPoolTicketsOpenError extends Error {
    override readonly name = 'RentPoolTicketsOpenError'

    constructor(readonly openTickets: bigint) {
        super(`solana rent pool: tickets the pool funded are still open: ${openTickets}`)
    }
}

/**
 * A payer's rent pool as the chain shows it, with the cluster's rent figures
 * it is read against. Go's SolanaRentPoolStatus.
 */
export interface SolanaRentPoolStatus extends RentPoolReading {
    /** A ticket's rent exemption, what each open draws; never 0. */
    ticketRent: bigint
    /** The pool account's own rent exemption. */
    poolRent: bigint
}

/**
 * What an open can draw and a withdraw can take: the pool's lamports above
 * its own rent exemption. A live ticket's rent sits in the ticket, not here.
 * Go's SolanaRentPoolStatus.Available.
 */
export function rentPoolAvailable(s: SolanaRentPoolStatus): bigint {
    if (!s.exists) return 0n
    return s.lamports > s.poolRent ? s.lamports - s.poolRent : 0n
}

/** How many more tickets the pool can fund right now. Go's SolanaRentPoolStatus.FreeSlots. */
export function rentPoolFreeSlots(s: SolanaRentPoolStatus): bigint {
    // A zero status (a read that never happened) must not throw RangeError.
    if (s.ticketRent === 0n) return 0n
    return rentPoolAvailable(s) / s.ticketRent
}

/**
 * How many concurrent tickets the pool backs counting the live ones, the
 * figure a working set is compared against. Go's
 * SolanaRentPoolStatus.BackedSlots.
 */
export function rentPoolBackedSlots(s: SolanaRentPoolStatus): bigint {
    if (s.ticketRent === 0n) return 0n
    return rentPoolGross(s.ticketRent, s.poolRent, s) / s.ticketRent
}

/**
 * readSolanaRentPool reads payer's rent pool without a signer, so a host can
 * show it for a wallet it has not unlocked. Go's ReadSolanaRentPool.
 */
export async function readSolanaRentPool(
    rpc: SolanaRpc,
    deployment: Deployment,
    payer: PublicKey,
    signal?: AbortSignal,
): Promise<SolanaRentPoolStatus> {
    const opts = { commitment: COMMITMENT, signal } as const
    let ticketRent, poolRent, acct
    try {
        ticketRent = await rpc.getMinimumBalanceForRentExemption(TICKET_SIZE, opts)
    } catch (err) {
        throw new Error(`solana rent pool: ticket rent: ${message(err)}`, { cause: err })
    }
    if (ticketRent === 0n) throw new Error('solana rent pool: the cluster quotes no ticket rent')
    try {
        poolRent = await rpc.getMinimumBalanceForRentExemption(RENT_POOL_SIZE, opts)
    } catch (err) {
        throw new Error(`solana rent pool: pool rent: ${message(err)}`, { cause: err })
    }
    try {
        acct = await rpc.getAccountInfo(deployment.rentPool(payer), opts)
    } catch (err) {
        throw new Error(`solana rent pool: read pool: ${message(err)}`, { cause: err })
    }
    if (acct === null || acct.owner !== deployment.program)
        return { exists: false, lamports: 0n, openTickets: 0n, ticketRent, poolRent }
    let openTickets
    try {
        openTickets = decodeRentPool(acct.data).openTickets
    } catch (err) {
        throw new Error(`solana rent pool: ${message(err)}`, { cause: err })
    }
    return { exists: true, lamports: acct.lamports, openTickets, ticketRent, poolRent }
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
        const payer = this.#o.signer.address
        const { exists, lamports, openTickets, ticketRent, poolRent } = await this.status(signal)
        return { payer, pool: { exists, lamports, openTickets }, ticketRent, poolRent }
    }

    /** The signer's pool, as readSolanaRentPool reads it. Go's Status. */
    status(signal?: AbortSignal): Promise<SolanaRentPoolStatus> {
        const { rpc, deployment, signer } = this.#o
        return readSolanaRentPool(rpc, deployment, signer.address, signal)
    }

    /**
     * How many more tickets the pool can fund right now: an open needs one, so
     * the serving path proceeds on a pool short of its working set while this
     * is at least 1.
     */
    async freeSlots(signal?: AbortSignal): Promise<bigint> {
        return rentPoolFreeSlots(await this.status(signal))
    }

    /**
     * Takes lamports back from the pool, at most its available, as Algorand's
     * withdrawMbr, and resolves to the signature once the withdraw is
     * confirmed; one sent but not confirmed throws RentPoolUnconfirmedError.
     * Go's Withdraw.
     */
    async withdraw(lamports: bigint, signal?: AbortSignal): Promise<string> {
        const s = await this.status(signal)
        if (!s.exists) throw new NoRentPoolError()
        const available = rentPoolAvailable(s)
        if (lamports <= 0n || lamports > available) {
            throw new Error(
                `solana rent pool: withdraw ${lamports} lamports: the pool holds ${available} above its own rent`,
            )
        }
        const payer = this.#o.signer.address
        return this.#send(payer, 'withdraw', this.#o.deployment.withdrawRent(payer, lamports), signal)
    }

    /**
     * Closes the pool and returns all of it, its own rent included, as
     * Algorand's closeDeposit, resolving to the signature and the lamports it
     * held. It refuses before signing while a ticket the pool funded is open.
     * Go's Close.
     */
    async close(signal?: AbortSignal): Promise<{ signature: string; returned: bigint }> {
        const s = await this.status(signal)
        if (!s.exists) throw new NoRentPoolError()
        if (s.openTickets > 0n) throw new RentPoolTicketsOpenError(s.openTickets)
        const payer = this.#o.signer.address
        const signature = await this.#send(payer, 'close', this.#o.deployment.closeRentPool(payer), signal)
        return { signature, returned: s.lamports }
    }

    // Signs ix as the payer's own transaction, sends it and waits for it to
    // confirm. Go's send.
    async #send(payer: PublicKey, what: string, ix: Instruction, signal: AbortSignal | undefined): Promise<string> {
        const { rpc, signer } = this.#o
        let bh
        try {
            bh = await rpc.getLatestBlockhash({ commitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana rent pool: blockhash: ${message(err)}`, { cause: err })
        }
        const tx = newTransaction(compileMessage(payer, bh.blockhash, [ix], 'legacy'))
        await signTransactionWith(tx, payer, signer)
        let signature
        try {
            // Preflight at the commitment the plan read, not the RPC's
            // finalized default, which may not see the lamports the plan
            // counted.
            signature = await rpc.sendTransaction(encodeTransaction(tx), { preflightCommitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana rent pool: send ${what}: ${message(err)}`, { cause: err })
        }
        let r
        try {
            r = await confirmSignature(rpc, signature, bh.lastValidBlockHeight, COMMITMENT, {
                ...this.#o.confirm,
                signal,
            })
        } catch (e) {
            throw what === 'deposit'
                ? new RentDepositUnconfirmedError(signature, e)
                : new RentPoolUnconfirmedError(what, signature, e)
        }
        if (r.err !== null) throw new Error(`solana rent pool: ${what} ${signature} failed: ${txErrorName(r.err)}`)
        return signature
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
        const { rpc } = this.#o
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

        const signature = await this.#send(s.payer, 'deposit', this.#o.deployment.depositRent(s.payer, plan.amount), signal)
        return { signature, deposited: plan.amount, belowTarget: plan.belowTarget }
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
