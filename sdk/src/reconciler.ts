/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: the payer's sweep over its ticket journal, and the request path's
// journal writes, mirroring proto/go/zs reconcile.go. What the sweep decides
// per ticket is reconcile.ts's decideTicket, or decideSolanaTicket.

import type { TicketRecord as TicketBox } from '@txnlab/zs-proto/escrow'
import type { Ticket as SolanaTicket } from '@txnlab/zs-proto/solana/zsescrow'
import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'

import { settleArgsOf } from './ack.js'
import type { SpendGuard } from './config.js'
import type { ResolvedNetwork } from './network.js'
import { refOf } from './operator.js'
import type { OpenHandle, TicketJournal } from './parts.js'
import { type Clock, type Logger, discardLogger } from './ports.js'
import { withJournalTimeout } from './receipt-check.js'
import {
    type ClaimVerdict,
    DEFAULT_LAPSE_FALLBACK_MS,
    type ReconcileAction,
    SETTLE_PENDING_GRACE_MS,
    type SettleArgs,
    type TicketRecord,
    boxClaimArgs,
    decideSolanaTicket,
    decideTicket,
    judgeClaim,
    judgeSolanaClaim,
    signedArgs,
    zeroClaimArgs,
} from './reconcile.js'
import { idle } from './sleep.js'
import { guardRecords } from './spend-guard.js'
import { decodeTicketId } from './wallet.js'
import { walletParts } from './wallet-parts.js'

/**
 * How often the sweep reads the journal. A stranded ticket's deadline is
 * minutes away, so a minute's lag costs nothing.
 */
export const RECONCILE_INTERVAL_MS = 60_000

/** Bounds the failed submits per ticket per process, so a ticket that can never settle doesn't cost a fee every sweep. */
export const RECONCILE_MAX_FAILURES = 10

/**
 * A ticket as the sweep read it: an Algorand box, or a Solana ticket account.
 * Go's sweptTicket.
 */
export type SweptTicket = { box: TicketBox } | { solana: SolanaTicket }

/**
 * What the sweep does on chain for one ticket, on either rail. boxSweep
 * provides it over a TicketChain, solanaSweep over a SolanaWallet. Go's
 * sweepChain.
 */
export interface SweepChain {
    /** The ticket as it stands, or null once it is gone. */
    read(rec: TicketRecord, signal: AbortSignal): Promise<SweptTicket | null>
    refund(rec: TicketRecord, signal: AbortSignal): Promise<string>
    lapse(rec: TicketRecord, t: SweptTicket | null, signal: AbortSignal): Promise<string>
    resettle(rec: TicketRecord, t: SweptTicket | null, signal: AbortSignal): Promise<string>
    freeze(rec: TicketRecord, t: SweptTicket | null, args: SettleArgs, signal: AbortSignal): Promise<string>
    /** Sends the payer's half at t's own pending claim. Reached only with a ticket read. */
    accept(rec: TicketRecord, t: SweptTicket, signal: AbortSignal): Promise<string>
    freezes(signal: AbortSignal): Promise<boolean>
    /**
     * One submit's budget when it must outlast callTimeoutMs; absent, it is
     * callTimeoutMs. Go's submitTimeout.
     */
    submitTimeoutMs?: number
}

/** boxSweep is the SweepChain over chain, the Algorand escrow's. Go's boxChain. */
export function boxSweep(chain: TicketChain): SweepChain {
    const boxOf = (t: SweptTicket | null) => (t !== null && 'box' in t ? t.box : null)
    return {
        read: async (rec, signal) => {
            const box = await chain.readBox(rec.ticketId, signal)
            return box === null ? null : { box }
        },
        refund: (rec, signal) => chain.refund(rec, signal),
        lapse: (rec, t, signal) => chain.lapse(rec, boxOf(t), signal),
        resettle: (rec, t, signal) => chain.resettle(rec, boxOf(t), signal),
        freeze: (rec, t, args, signal) => chain.freeze(rec, boxOf(t), args, signal),
        accept: async (rec, t, signal) => {
            const box = boxOf(t)
            if (box === null) throw new Error('wallet: accept claim: no box read')
            return chain.accept(rec, box, zeroClaimArgs(boxClaimArgs(box)), signal)
        },
        freezes: (signal) => chain.freezes(signal),
    }
}

function decideSwept(rec: TicketRecord, t: SweptTicket | null, nowMs: number, lapseFallbackMs: number): ReconcileAction {
    if (t !== null && 'solana' in t) return decideSolanaTicket(rec, t.solana, { nowMs }, lapseFallbackMs)
    return decideTicket(rec, t?.box ?? null, { nowMs }, lapseFallbackMs)
}

// The verdict on t's claim against a, 'none' when t is gone. Go's judgeSwept.
function judgeSwept(a: SettleArgs, t: SweptTicket | null): ClaimVerdict {
    if (t !== null && 'solana' in t) return judgeSolanaClaim(a, t.solana)
    return judgeClaim(a, t?.box ?? null)
}

function pendingAmountOf(t: SweptTicket | null): bigint {
    if (t === null) return 0n
    return 'solana' in t ? t.solana.pending.amount : t.box.pendingAmount
}

/** What the sweep does on chain for one Algorand ticket. walletChain provides it; tests fake it. */
export interface TicketChain {
    /** The ticket's box, or null once it is gone. */
    readBox(ticketId: string, signal: AbortSignal): Promise<TicketBox | null>
    refund(rec: TicketRecord, signal: AbortSignal): Promise<string>
    lapse(rec: TicketRecord, box: TicketBox | null, signal: AbortSignal): Promise<string>
    resettle(rec: TicketRecord, box: TicketBox | null, signal: AbortSignal): Promise<string>
    /** Sends the payer's settle at args, against an operator claim on box that takes more. */
    freeze(rec: TicketRecord, box: TicketBox | null, args: SettleArgs, signal: AbortSignal): Promise<string>
    /** Sends the payer's settle at args, the operator's own claim on box, which finalizes the ticket. */
    accept(rec: TicketRecord, box: TicketBox, args: SettleArgs, signal: AbortSignal): Promise<string>
    /**
     * Whether the deployed escrow has resolveFrozen. Without it freeze is never
     * called: the frozen escrow would be locked for good. A rejection reads as
     * false. Go's ticketChain.freezes.
     */
    freezes(signal: AbortSignal): Promise<boolean>
}

/**
 * walletChain is the sweep's TicketChain over the SDK's Wallet: each call acts
 * as the payer on a ticket known only from its journal row and, where it has
 * one, its box. The box's operator owner is the one the contract pays, so it
 * is preferred over none. Undefined for any other wallet.
 */
export function walletChain(wallet: object): TicketChain | undefined {
    const parts = walletParts.get(wallet)
    if (parts === undefined) return undefined
    const { chain, payer } = parts
    const ids = (rec: TicketRecord) => ({
        ticketIdRaw: decodeTicketId(rec.ticketId),
        operatorId: BigInt(rec.target.op),
        nodeId: BigInt(rec.target.node),
    })
    const settleAt = async (what: string, rec: TicketRecord, box: TicketBox | null, args: SettleArgs, outerFeeOnly: boolean, signal: AbortSignal) => {
        const r = await wrap(what, async () =>
            chain.settleStandalone(
                {
                    ...ids(rec),
                    args,
                    maxPrice: rec.maxPrice,
                    payer,
                    operatorOwnerAddr: box?.operatorOwnerAddr ?? '',
                    ...(outerFeeOnly ? { outerFeeOnly } : {}),
                },
                signal,
            ),
        )
        return r.txid
    }
    return {
        readBox: async (ticketId, signal) => chain.readTicketBox(decodeTicketId(ticketId), signal),
        refund: (rec, signal) => wrap('refund-inactive', async () => chain.refundInactive({ ...ids(rec), payer }, signal)),
        lapse: (rec, box, signal) =>
            wrap('settle-lapsed', async () =>
                chain.settleLapsed({ ...ids(rec), operatorOwnerAddr: box?.operatorOwnerAddr ?? '', payer }, signal),
            ),
        resettle: async (rec, box, signal) => {
            const settle = rec.settle
            if (settle === undefined) throw new Error('wallet: re-settle without a recorded receipt')
            return settleAt('re-settle', rec, box, settle, false, signal)
        },
        freeze: (rec, box, args, signal) => settleAt('freeze', rec, box, args, true, signal),
        // The full settle fee, unlike freeze: a matching half finalizes the
        // ticket, and finalization needs the op-up.
        accept: (rec, box, args, signal) => settleAt('accept claim', rec, box, args, false, signal),
        freezes: async (signal) => {
            try {
                return (await chain.config(signal)).resolvesFrozen === true
            } catch {
                return false
            }
        },
    }
}

export interface ReconcilerOptions {
    journal: TicketJournal
    chain: SweepChain
    payer: string
    deployment: ResolvedNetwork
    /** Whether the refund watchdog still drives a ticket, which the sweep then leaves alone. */
    watching: (ticketId: string) => boolean
    /**
     * Learns how each ticket ended, so a reservation a restarted SpendGuard
     * restored frees its headroom then. An argument rather than set later
     * because start sweeps at once, and that first sweep is the one that finds
     * what a restart left behind.
     */
    spend?: SpendGuard | undefined
    /**
     * Hears of each ticket whose box carries an operator claim above the
     * receipt its row records, every sweep that reads one, so the node is
     * barred though the live ack never saw the claim: posted after its read,
     * or after a restart. Go's reconciler.overclaimed.
     */
    overclaimed?: ((rec: TicketRecord) => void) | undefined
    logger?: Logger | undefined
    clock?: Clock | undefined
}

/**
 * Reconciler finishes journaled tickets this process is not watching: those
 * left by an earlier run, and those whose refund watchdog gave up. Each
 * ticket has one driver at a time; a live ticket stays with the watchdog,
 * except for a freeze. The watchdog acts only past the deadline and the live
 * ack reads the box once, so an over-claim the node posts after that read, or
 * after the ack failed, would otherwise lapse.
 */
export class Reconciler {
    interval = RECONCILE_INTERVAL_MS
    callTimeoutMs = 30_000
    lapseFallbackMs = DEFAULT_LAPSE_FALLBACK_MS
    /** Remedies.recoverTicket, for a ticket the sweep gives up on. */
    remedy = ''
    /** Gives back the claim the Client took on the journal, once closed. */
    release: (() => void) | undefined
    /**
     * Set when the journal outlives the Client: close then stops the watchdog
     * before releasing the claim, so the next sweeper owns the rows.
     */
    handOff = false

    readonly #journal: TicketJournal
    readonly #chain: SweepChain
    readonly #payer: string
    readonly #deployment: ResolvedNetwork
    readonly #watching: (ticketId: string) => boolean
    readonly #spend: SpendGuard | undefined
    readonly #overclaimed: ((rec: TicketRecord) => void) | undefined
    readonly #log: Logger
    readonly #clock: Clock
    readonly #failures = new Map<string, number>()
    /** Every chain and journal call's parent: close aborts it, so a wedged algod can't hold close for a call timeout. */
    readonly #stop = new AbortController()
    #done: Promise<void> = Promise.resolve()

    constructor(o: ReconcilerOptions) {
        this.#journal = o.journal
        this.#chain = o.chain
        this.#payer = o.payer
        this.#deployment = o.deployment
        this.#watching = o.watching
        this.#spend = o.spend
        this.#overclaimed = o.overclaimed
        this.#log = o.logger ?? discardLogger
        this.#clock = o.clock ?? Date.now
    }

    /** Sweeps at once, then every interval, until close. */
    start(): void {
        this.#done = (async () => {
            for (;;) {
                const started = Date.now()
                await this.sweep()
                // A ticker's cadence: the next sweep is due interval after this one began.
                if (!(await idle(this.interval - (Date.now() - started), this.#stop.signal))) return
            }
        })()
    }

    /**
     * Stops the loop, aborting any call in flight, and waits for it. Then it
     * runs beforeRelease, if any, and gives up the journal claim: after a sweep
     * can no longer act and before another Client may.
     */
    async close(beforeRelease?: () => Promise<void> | void): Promise<void> {
        this.#stop.abort()
        // A claim never given back bars every later Client from sweeping this
        // journal, so it goes whatever the steps before it threw.
        try {
            await this.#done
            await beforeRelease?.()
        } finally {
            this.release?.()
        }
    }

    #stopped(): boolean {
        return this.#stop.signal.aborted
    }

    /** Acts once on every journaled ticket nobody else is driving. It never rejects: whatever goes wrong is retried next sweep. */
    async sweep(): Promise<void> {
        let recs: TicketRecord[]
        try {
            recs = await this.#bounded(() => this.#journal.list(this.#payer, this.#deployment))
        } catch (err) {
            if (!this.#stopped()) this.#log.warn('ticket reconciler: journal read failed', { err: message(err) })
            return
        }
        // Asked once a sweep: the answer is the deployment's.
        let freezes: boolean | undefined
        const canFreeze = async () => (freezes ??= await this.#bounded((signal) => this.#chain.freezes(signal)).catch(() => false))
        for (const rec of recs) {
            if (this.#stopped()) return
            if (this.#exhausted(rec.ticketId)) continue
            // A watched row is read only when the sweep may act on it: a
            // freeze needs a receipt and an escrow that can resolve one, and a
            // $0 claim's acceptance waits out the settle-pending grace. The
            // watchdog would hold such a claim's pool slot to the deadline.
            // A row time that isn't a number reads as long past, as
            // decideTicket reads it.
            const watched = this.#watching(rec.ticketId)
            const updatedAt = Number.isFinite(rec.updatedAt) ? rec.updatedAt : 0
            if (
                watched &&
                !(signedArgs(rec) !== undefined && (await canFreeze())) &&
                this.#clock() - updatedAt < SETTLE_PENDING_GRACE_MS
            ) {
                continue
            }
            // A row that throws, a box it can't decide say, must not end the
            // sweep loop for the rows after it. It counts as a failed
            // attempt, so a row that always throws is given up on.
            try {
                await this.#reconcile(rec, watched, canFreeze)
            } catch (err) {
                this.#failed(rec, 'reconcile', err)
            }
        }
    }

    #exhausted(ticketId: string): boolean {
        return (this.#failures.get(ticketId) ?? 0) >= RECONCILE_MAX_FAILURES
    }

    // A watched ticket gets a freeze, a $0 claim's acceptance or nothing:
    // every other call is its watchdog's.
    async #reconcile(rec: TicketRecord, watched: boolean, canFreeze: () => Promise<boolean>): Promise<void> {
        let t: SweptTicket | null
        try {
            t = await this.#bounded((signal) => this.#chain.read(rec, signal))
        } catch (err) {
            this.#log.debug('ticket reconciler: ticket read failed; retrying next sweep', { ticket_id: rec.ticketId, err: message(err) })
            return
        }
        let action = decideSwept(rec, t, this.#clock(), this.lapseFallbackMs)
        const signed = signedArgs(rec)
        if (signed !== undefined && this.#overclaimed && judgeSwept(signed, t) === 'overclaims') this.#overclaimed(rec)
        // No freeze, and still no lapse: decideSettlement never lapses an
        // over-claim, which the operator can lapse itself.
        if (action === 'freeze' && !(await canFreeze())) action = 'wait'
        if (watched && action !== 'freeze' && action !== 'acceptZeroClaim') return
        let submit: (signal: AbortSignal) => Promise<string>
        switch (action) {
            case 'wait':
                return
            case 'forget':
                await this.#forget(rec, t)
                return
            case 'refundInactive':
                submit = (signal) => this.#chain.refund(rec, signal)
                break
            case 'settleLapsed':
                submit = (signal) => this.#chain.lapse(rec, t, signal)
                break
            case 'settle':
                submit = (signal) => this.#chain.resettle(rec, t, signal)
                break
            case 'freeze': {
                // The receipt's values, not the box's: settling at the claim's
                // own figure would match it and pay it.
                const args = signedArgs(rec)!
                submit = (signal) => this.#chain.freeze(rec, t, args, signal)
                break
            }
            case 'acceptZeroClaim': {
                // Only a pending claim is accepted, so a ticket was read.
                const read = t!
                submit = (signal) => this.#chain.accept(rec, read, signal)
                break
            }
        }
        let txid: string
        try {
            txid = await this.#bounded(submit, this.#chain.submitTimeoutMs)
        } catch (err) {
            if (this.#stopped()) return // cut off by close, not refused
            this.#failed(rec, action, err)
            return
        }
        // Kept until a later sweep finds the box gone: a submitted call is not
        // a confirmed one.
        if (action === 'freeze') {
            // Warn: the escrow now goes to arbitration rather than settlement,
            // on the operator's doing.
            this.#log.warn("ticket reconciler: operator's settle claim exceeds its signed receipt; submitted the receipt's settle to freeze the ticket", {
                ticket_id: rec.ticketId,
                txid,
                claimed_microusdc: Number(pendingAmountOf(t)),
                receipt_microusdc: Number(signedArgs(rec)?.amountCharged ?? 0n),
            })
            return
        }
        this.#log.info(`ticket reconciler: submitted ${action}`, { ticket_id: rec.ticketId, txid })
        const spend = this.#spend
        if (spend === undefined) return
        // Once algod accepts a refund or a lapse no other outcome is legal: no
        // charge for a refund, the operator's claim for a lapse. A journaled
        // receipt means the request path already counted its charge, so a lapse
        // only drops what reservation is left rather than counting it twice.
        // An accepted $0 claim charges nothing, so it only releases.
        if (action === 'refundInactive' || action === 'acceptZeroClaim' || (action === 'settleLapsed' && rec.settle !== undefined)) {
            guardRecords(this.#log, 'release', rec.ticketId, () => spend.release(rec.ticketId))
        } else if (action === 'settleLapsed') {
            guardRecords(this.#log, 'settle', rec.ticketId, () => spend.settle(rec.ticketId, Number(pendingAmountOf(t))))
        }
    }

    #failed(rec: TicketRecord, action: ReconcileAction | 'reconcile', err: unknown): void {
        const n = (this.#failures.get(rec.ticketId) ?? 0) + 1
        this.#failures.set(rec.ticketId, n)
        if (n >= RECONCILE_MAX_FAILURES) {
            this.#log.warn(`ticket reconciler: ${action} keeps failing; leaving the ticket for the next start`, {
                ticket_id: rec.ticketId,
                attempts: n,
                err: message(err),
                remedy: this.remedy,
            })
            return
        }
        this.#log.debug(`ticket reconciler: ${action} failed; retrying next sweep`, {
            ticket_id: rec.ticketId,
            attempt: n,
            err: message(err),
        })
    }

    async #forget(rec: TicketRecord, t: SweptTicket | null): Promise<void> {
        if (t !== null) {
            // Frozen: only the admin's resolveFrozen can close it, so the
            // escrowed USDC and the MBR slot stay locked until the arbiter acts,
            // and nothing the payer can call applies. The spend reservation is
            // left open: it outlives a resolveFrozen refund until it ages out.
            this.#log.warn('ticket reconciler: ticket is frozen; leaving it to arbitration', { ticket_id: rec.ticketId })
        } else if (rec.settle !== undefined) {
            // Closed, with a verified receipt. The request path settles before
            // it journals the receipt, so the charge is already counted; a
            // reservation still open here survived a crash between the guard's
            // two writes, and settling it again would count the charge twice.
            // With no receipt nothing here says what the ticket cost, so its
            // reservation ages out.
            const spend = this.#spend
            if (spend) guardRecords(this.#log, 'release', rec.ticketId, () => spend.release(rec.ticketId))
        }
        try {
            await this.#bounded(() => this.#journal.delete(rec.ticketId))
        } catch (err) {
            if (!this.#stopped()) this.#log.warn('ticket reconciler: journal delete failed', { ticket_id: rec.ticketId, err: message(err) })
        }
    }

    /**
     * One call under timeoutMs (callTimeoutMs when absent) and close. The
     * journal takes no signal, so its call is abandoned rather than cut off.
     */
    #bounded<T>(call: (signal: AbortSignal) => Promise<T>, timeoutMs?: number): Promise<T> {
        const ms = timeoutMs !== undefined && timeoutMs > 0 ? timeoutMs : this.callTimeoutMs
        const signal = AbortSignal.any([this.#stop.signal, AbortSignal.timeout(ms)])
        if (signal.aborted) return Promise.reject(signal.reason)
        return new Promise<T>((resolve, reject) => {
            const onAbort = () => reject(signal.reason)
            signal.addEventListener('abort', onAbort, { once: true })
            call(signal).then(
                (v) => {
                    signal.removeEventListener('abort', onAbort)
                    resolve(v)
                },
                (e: unknown) => {
                    signal.removeEventListener('abort', onAbort)
                    reject(e)
                },
            )
        })
    }
}

/** What the request path's journal writes read off the Client. */
export interface JournalDeps {
    journal: TicketJournal | undefined
    logger: Logger
    clock: Clock
    deployment: ResolvedNetwork
    /** The wallet's payer address. */
    payer: string
    /** Overrides JOURNAL_TIMEOUT_MS. */
    journalTimeoutMs?: number | undefined
}

// The row journalOpen wrote for each handle, which journalReceipt extends.
const journaled = new WeakMap<OpenHandle, TicketRecord>()

/**
 * journalOpen records a ticket whose escrow just opened, before the request
 * is sent. A failed write is logged, not thrown: the USDC is already locked,
 * and the watchdog still drives the ticket while this process runs.
 */
export async function journalOpen(d: JournalDeps, h: OpenHandle, t: Ticket): Promise<void> {
    if (d.journal === undefined) return
    const now = d.clock()
    const rec: TicketRecord = {
        ticketId: t.ticket_id,
        openTxId: h.appCallTxId,
        escrowAppId: d.deployment.escrowAppId,
        deployment: d.deployment.key,
        target: refOf(h.operator),
        payer: d.payer,
        maxPrice: BigInt(t.max_price),
        expiresAt: t.expires_at * 1000,
        status: 'open',
        createdAt: now,
        updatedAt: now,
    }
    journaled.set(h, rec)
    try {
        await withJournalTimeout(d.journal.put(rec), d.journalTimeoutMs)
    } catch (err) {
        d.logger.warn('ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline', {
            ticket_id: rec.ticketId,
            err: message(err),
        })
    }
}

/**
 * journalReceipt records the values the payer will co-sign for a verified
 * receipt, before the settle is submitted, so a restart mid-submit can still
 * re-fire it. A ticket journalOpen never recorded is left alone. The caller
 * bounds and logs the write.
 */
export async function journalReceipt(d: JournalDeps, h: OpenHandle, receipt: UsageReceipt): Promise<void> {
    const opened = journaled.get(h)
    if (d.journal === undefined || opened === undefined) return
    await d.journal.put({ ...opened, status: 'settle_pending', settle: settleArgsOf(receipt), updatedAt: d.clock() })
}

/**
 * journalSigned records a receipt whose signature verified but that failed a
 * later check, on the row's open status: the payer settles nothing from it,
 * but a sweep holds an operator claim against its amount, after a restart as
 * before one. Go's journalSigned. The caller bounds and logs the write.
 */
export async function journalSigned(d: JournalDeps, h: OpenHandle, receipt: UsageReceipt): Promise<void> {
    const opened = journaled.get(h)
    if (d.journal === undefined || opened === undefined) return
    await d.journal.put({ ...opened, signed: settleArgsOf(receipt), updatedAt: d.clock() })
}

async function wrap<T>(what: string, call: () => Promise<T>): Promise<T> {
    try {
        return await call()
    } catch (err) {
        throw new Error(`wallet: ${what}: ${message(err)}`, { cause: err })
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
