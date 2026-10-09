/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: the payer's sweep over its ticket journal, and the request path's
// journal writes, mirroring proto/go/zs reconcile.go. What the sweep decides
// per ticket is reconcile.ts's decideTicket.

import type { TicketRecord as TicketBox } from '@txnlab/zs-proto/escrow'
import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'

import { settleArgsOf } from './ack.js'
import type { SpendGuard } from './config.js'
import { refOf } from './operator.js'
import type { OpenHandle, TicketJournal } from './parts.js'
import { type Clock, type Logger, discardLogger } from './ports.js'
import { withJournalTimeout } from './receipt-check.js'
import { DEFAULT_LAPSE_FALLBACK_MS, type ReconcileAction, type TicketRecord, decideTicket } from './reconcile.js'
import { idle } from './sleep.js'
import { decodeTicketId } from './wallet.js'
import { walletParts } from './wallet-parts.js'

/**
 * How often the sweep reads the journal. A stranded ticket's deadline is
 * minutes away, so a minute's lag costs nothing.
 */
export const RECONCILE_INTERVAL_MS = 60_000

/** Bounds the failed submits per ticket per process, so a ticket that can never settle doesn't cost a fee every sweep. */
export const RECONCILE_MAX_FAILURES = 10

/** What the sweep does on chain for one ticket. walletChain provides it; tests fake it. */
export interface TicketChain {
    /** The ticket's box, or null once it is gone. */
    readBox(ticketId: string, signal: AbortSignal): Promise<TicketBox | null>
    refund(rec: TicketRecord, signal: AbortSignal): Promise<string>
    lapse(rec: TicketRecord, box: TicketBox | null, signal: AbortSignal): Promise<string>
    resettle(rec: TicketRecord, box: TicketBox | null, signal: AbortSignal): Promise<string>
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
            const r = await wrap('re-settle', async () =>
                chain.settleStandalone(
                    {
                        ...ids(rec),
                        args: settle,
                        maxPrice: rec.maxPrice,
                        payer,
                        operatorOwnerAddr: box?.operatorOwnerAddr ?? '',
                    },
                    signal,
                ),
            )
            return r.txid
        },
    }
}

export interface ReconcilerOptions {
    journal: TicketJournal
    chain: TicketChain
    payer: string
    escrowAppId: bigint
    /** Whether the refund watchdog still drives a ticket, which the sweep then leaves alone. */
    watching: (ticketId: string) => boolean
    /**
     * Learns how each ticket ended, so a reservation a restarted SpendGuard
     * restored frees its headroom then. An argument rather than set later
     * because start sweeps at once, and that first sweep is the one that finds
     * what a restart left behind.
     */
    spend?: SpendGuard | undefined
    logger?: Logger | undefined
    clock?: Clock | undefined
}

/**
 * Reconciler finishes journaled tickets this process is not watching: those
 * left by an earlier run, and those whose refund watchdog gave up. Each
 * ticket has one driver at a time; a live ticket stays with the watchdog.
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
    readonly #chain: TicketChain
    readonly #payer: string
    readonly #appId: bigint
    readonly #watching: (ticketId: string) => boolean
    readonly #spend: SpendGuard | undefined
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
        this.#appId = o.escrowAppId
        this.#watching = o.watching
        this.#spend = o.spend
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
        await this.#done
        await beforeRelease?.()
        this.release?.()
    }

    #stopped(): boolean {
        return this.#stop.signal.aborted
    }

    /** Acts once on every journaled ticket nobody else is driving. It never rejects: whatever goes wrong is retried next sweep. */
    async sweep(): Promise<void> {
        let recs: TicketRecord[]
        try {
            recs = await this.#bounded(() => this.#journal.list(this.#payer, this.#appId))
        } catch (err) {
            if (!this.#stopped()) this.#log.warn('ticket reconciler: journal read failed', { err: message(err) })
            return
        }
        for (const rec of recs) {
            if (this.#stopped()) return
            if (this.#watching(rec.ticketId) || this.#exhausted(rec.ticketId)) continue
            await this.#reconcile(rec)
        }
    }

    #exhausted(ticketId: string): boolean {
        return (this.#failures.get(ticketId) ?? 0) >= RECONCILE_MAX_FAILURES
    }

    async #reconcile(rec: TicketRecord): Promise<void> {
        let box: TicketBox | null
        try {
            box = await this.#bounded((signal) => this.#chain.readBox(rec.ticketId, signal))
        } catch (err) {
            this.#log.debug('ticket reconciler: box read failed; retrying next sweep', { ticket_id: rec.ticketId, err: message(err) })
            return
        }
        const action = decideTicket(rec, box, { nowMs: this.#clock() }, this.lapseFallbackMs)
        let submit: (signal: AbortSignal) => Promise<string>
        switch (action) {
            case 'wait':
                return
            case 'forget':
                await this.#forget(rec, box)
                return
            case 'refundInactive':
                submit = (signal) => this.#chain.refund(rec, signal)
                break
            case 'settleLapsed':
                submit = (signal) => this.#chain.lapse(rec, box, signal)
                break
            case 'settle':
                submit = (signal) => this.#chain.resettle(rec, box, signal)
                break
        }
        let txid: string
        try {
            txid = await this.#bounded(submit)
        } catch (err) {
            if (this.#stopped()) return // cut off by close, not refused
            this.#failed(rec, action, err)
            return
        }
        // Kept until a later sweep finds the box gone: a submitted call is not
        // a confirmed one.
        this.#log.info(`ticket reconciler: submitted ${action}`, { ticket_id: rec.ticketId, txid })
        const spend = this.#spend
        if (spend === undefined) return
        // Once algod accepts a refund or a lapse no other outcome is legal: no
        // charge for a refund, the operator's claim for a lapse. A journaled
        // receipt means the request path already counted its charge, so a lapse
        // only drops what reservation is left rather than counting it twice.
        if (action === 'refundInactive' || (action === 'settleLapsed' && rec.settle !== undefined)) {
            spend.release(rec.ticketId)
        } else if (action === 'settleLapsed') {
            spend.settle(rec.ticketId, Number(box!.pendingAmount))
        }
    }

    #failed(rec: TicketRecord, action: ReconcileAction, err: unknown): void {
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

    async #forget(rec: TicketRecord, box: TicketBox | null): Promise<void> {
        if (box !== null) {
            // Frozen: no contract call accepts it, and the escrowed USDC and the
            // MBR slot stay locked until arbitration. The reservation stays too.
            this.#log.warn('ticket reconciler: ticket is frozen; leaving it to arbitration', { ticket_id: rec.ticketId })
        } else if (rec.settle !== undefined) {
            // Closed, with a verified receipt. The request path settles before
            // it journals the receipt, so the charge is already counted; a
            // reservation still open here survived a crash between the guard's
            // two writes, and settling it again would count the charge twice.
            // With no receipt nothing here says what the ticket cost, so its
            // reservation ages out.
            this.#spend?.release(rec.ticketId)
        }
        try {
            await this.#bounded(() => this.#journal.delete(rec.ticketId))
        } catch (err) {
            if (!this.#stopped()) this.#log.warn('ticket reconciler: journal delete failed', { ticket_id: rec.ticketId, err: message(err) })
        }
    }

    /**
     * One call under callTimeoutMs and close. The journal takes no signal, so
     * its call is abandoned rather than cut off.
     */
    #bounded<T>(call: (signal: AbortSignal) => Promise<T>): Promise<T> {
        const signal = AbortSignal.any([this.#stop.signal, AbortSignal.timeout(this.callTimeoutMs)])
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
    escrowAppId: bigint
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
        escrowAppId: d.escrowAppId,
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
