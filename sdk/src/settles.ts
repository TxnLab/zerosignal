/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The escrow work a turn leaves running after its reply, mirroring proto/go/zs
// dispatch.go's submitAfterResponse, confirmSettled, drain and WaitSettles: a
// buffered turn's ack or protest, submitted once the caller has the response,
// and the watch on an atomic settle until it lands.

import { type SettleSubmit, withJournalTimeout } from './receipt-check.js'
import type { OpenHandle, TicketJournal } from './parts.js'
import type { Clock, Logger } from './ports.js'
import { sleep as sleepFor } from './sleep.js'

/** How long confirmSettled watches a settle; Algorand confirms in seconds. */
export const SETTLE_CONFIRM_TIMEOUT_MS = 20_000
/** How often confirmSettled looks. */
export const SETTLE_CONFIRM_POLL_MS = 1000

// Marks an in-flight key as a confirmation, not a submit, for wait's report.
const CONFIRMING_SUFFIX = ' (confirming)'

export interface SettlesOptions {
    logger: Logger
    /** Where a confirmed atomic settle's row is deleted; without one nothing is watched. */
    journal?: TicketJournal | undefined
    /** Ends every watch: the Client's close. */
    life?: AbortSignal | undefined
    clock?: Clock | undefined
    sleep?: ((ms: number, signal: AbortSignal | undefined) => Promise<boolean>) | undefined
    confirmTimeoutMs?: number | undefined
    confirmPollMs?: number | undefined
    /** Overrides JOURNAL_TIMEOUT_MS for the delete. */
    journalTimeoutMs?: number | undefined
}

/** Settles runs a Client's background escrow work and lets shutdown wait for it. */
export class Settles {
    readonly #o: SettlesOptions
    readonly #running = new Set<Promise<void>>()
    readonly #inFlight = new Set<string>()

    constructor(o: SettlesOptions) {
        this.#o = o
    }

    // go runs f in the background under key, which wait names while it runs.
    #go(key: string, what: string, ticketId: string, f: () => Promise<void>): void {
        this.#inFlight.add(key)
        // Assigned before the body's first await returns, so finally sees it.
        let p: Promise<void> | undefined
        p = (async () => {
            try {
                await f()
            } catch (err) {
                // Nothing awaits it, so a throw would be an unhandled rejection.
                this.#o.logger.error(`escrow settle ${what} failed`, { ticket_id: ticketId, err: errText(err) })
            } finally {
                this.#inFlight.delete(key)
                if (p !== undefined) this.#running.delete(p)
            }
        })()
        this.#running.add(p)
    }

    /**
     * afterResponse runs a turn's submit in the background, so the caller has
     * its whole response without waiting on algod.
     */
    afterResponse(ticketId: string, submit: SettleSubmit | null): void {
        if (submit === null) return
        this.#go(ticketId, 'submit', ticketId, async () => {
            await submit()
        })
    }

    /**
     * confirmSettled watches the atomic settle txId just submitted for
     * ticketId until it lands, then deletes the ticket's journal row. A settle
     * dropped from the pool, one not confirmed by the deadline, or one whose
     * lookups keep failing keeps its row for the reconciler, which re-settles
     * or refunds it. The Client's close ends the watch.
     */
    confirmSettled(ticketId: string, txId: string, handle: OpenHandle): void {
        const o = this.#o
        const journal = o.journal
        const outcome = handle.settleOutcome?.bind(handle)
        if (outcome === undefined || journal === undefined || txId === '') return
        const log = o.logger
        const clock = o.clock ?? Date.now
        const sleep = o.sleep ?? sleepFor
        const timeoutMs = o.confirmTimeoutMs ?? SETTLE_CONFIRM_TIMEOUT_MS
        const pollMs = o.confirmPollMs ?? SETTLE_CONFIRM_POLL_MS
        this.#go(ticketId + CONFIRMING_SUFFIX, 'confirmation', ticketId, async () => {
            const end = clock() + timeoutMs
            let lastErr: unknown
            const notConfirmed = () =>
                log.info('ack-settle not confirmed in time; the ticket reconciler finishes it', {
                    ticket_id: ticketId,
                    txid: txId,
                    last_err: lastErr === undefined ? '' : errText(lastErr),
                })
            for (;;) {
                const remaining = end - clock()
                const bound = AbortSignal.timeout(Math.max(remaining, 0))
                const signal = o.life ? AbortSignal.any([o.life, bound]) : bound
                let out: Awaited<ReturnType<typeof outcome>> | undefined
                try {
                    out = await outcome(txId, signal)
                } catch (err) {
                    lastErr = err
                }
                if (out === 'landed') {
                    try {
                        await withJournalTimeout(journal.delete(ticketId), o.journalTimeoutMs)
                    } catch (err) {
                        log.warn('ticket journal delete failed', { ticket_id: ticketId, err: errText(err) })
                    }
                    log.debug('ack-settle confirmed', { ticket_id: ticketId, txid: txId })
                    return
                }
                if (out === 'dropped') {
                    log.info('ack-settle dropped from the pool; the ticket reconciler finishes it', {
                        ticket_id: ticketId,
                        txid: txId,
                    })
                    return
                }
                // The deadline or the Client's close ends the wait between looks.
                const left = end - clock()
                if (left <= 0 || o.life?.aborted || !(await sleep(Math.min(pollMs, left), o.life)) || end - clock() <= 0) {
                    notConfirmed()
                    return
                }
            }
        })
    }

    /**
     * wait resolves once no background escrow work is running: the submits
     * made after a whole reply, and the watches on atomic settles. Work that
     * starts while it waits is waited for too. When signal aborts first it
     * rejects naming the tickets still being submitted, which die with the
     * process, apart from settles submitted but not yet seen to land, whose
     * journal rows stay for the reconciler.
     */
    async wait(signal?: AbortSignal): Promise<void> {
        while (this.#running.size > 0) {
            if (signal?.aborted) throw this.#unfinished(signal)
            const all = Promise.allSettled([...this.#running])
            if (!signal) {
                await all
                continue
            }
            await new Promise<void>((resolve) => {
                const onAbort = () => resolve()
                signal.addEventListener('abort', onAbort, { once: true })
                void all.then(() => {
                    signal.removeEventListener('abort', onAbort)
                    resolve()
                })
            })
        }
    }

    #unfinished(signal: AbortSignal): Error {
        const submitting: string[] = []
        const confirming: string[] = []
        for (const k of this.#inFlight) {
            if (k.endsWith(CONFIRMING_SUFFIX)) confirming.push(k.slice(0, -CONFIRMING_SUFFIX.length))
            else submitting.push(k)
        }
        submitting.sort()
        confirming.sort()
        let detail = ''
        if (submitting.length > 0) detail += `; tickets still settling: ${submitting.join(', ')}`
        if (confirming.length > 0) {
            detail += `; settles submitted but not yet seen to land, left journaled: ${confirming.join(', ')}`
        }
        return new Error(`${errText(signal.reason)}${detail}`, { cause: signal.reason })
    }
}

function errText(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
