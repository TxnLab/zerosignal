/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal but for the RefundWatchdog type: the payer's recovery of escrow
// whose settlement never arrived, mirroring proto/go/zs refund_watchdog.go.

import { type TicketView, type Verdict, classify } from '@txnlab/zs-proto/settle'

import type { OpenHandle } from './parts.js'
import type { NodeRef } from './types.js'
import { type Clock, type Logger, discardLogger } from './ports.js'
import { idle } from './sleep.js'

/**
 * RefundWatchdog recovers escrowed USDC for tickets whose settlement never
 * arrived. The open group is submitted before the node's admission check
 * runs, so a failure after it (the node refusing the payment, a transport
 * failure mid-request, an operator that dies before settling) leaves max_price
 * locked in the ticket box with nobody driving a settle. Past the deadline
 * D = expires_at + grace anyone may refund a ticket that carries no operator
 * claim (SPEC.md §3a "Settlement windows"). The node keeps nothing for a
 * request it refused, so only the payer knows the ticket was orphaned.
 *
 * At D plus a margin a tracked ticket's box is read. A box gone was settled or
 * lapsed elsewhere; a frozen one is left to arbitration. An operator's pending
 * claim bars refundInactive, so it waits for the node's own settleLapsed and
 * posts one itself only if the node never does. A box whose own deadline is
 * still ahead re-arms to it: the box is authoritative, and the grace track
 * read can have been rotated since. Anything else gets refundInactive. On
 * Solana the read is of the ticket account, which the program closes as
 * Algorand deletes the box, and the calls are the program's refund_inactive
 * and settle_lapsed.
 *
 * State is in memory. A ticket outlives a restart through the journal, whose
 * sweep takes any row the watchdog isn't watching.
 */
export interface RefundWatchdog {
    /**
     * Arms a deferred refund for the ticket behind h, firing at expiresAt
     * (unix seconds) plus the contract's grace and a margin, unless resolve
     * comes first. A handle the SDK's Wallet did not open is not tracked.
     */
    track(h: OpenHandle | null | undefined, expiresAt: number): void
    /**
     * Stops watching a ticket whose settlement finalized or that froze by
     * protest, where refundInactive reverts. An unknown id is a no-op.
     */
    resolve(ticketId: string): void
}

/**
 * What track reads off a handle the SDK's Wallet or SolanaWallet opened, Go's
 * refundSource, which a caller's wallet leaves unset. The wallet decoded the
 * ticket id at open, so track has no undecodable id to refuse.
 */
export interface RefundSource {
    /** The grace an open takes by default, as the wallet read it: the contract's grace global, the program's default_grace. */
    graceSeconds: bigint
    /** The ticket as the rail-neutral view with the amount of its pending claim, or null once it is gone. */
    readTicket(signal: AbortSignal): Promise<{ view: TicketView; pendingAmount: bigint } | null>
    /**
     * When set, bounds each refund or lapse in place of the watchdog's
     * callTimeoutMs, for a rail whose call waits for its outcome. Go's
     * refundSource.callTimeout.
     */
    callTimeoutMs?: number
}

/** Each handle the SDK's wallets opened, set by the wallet. */
export const refundSources = new WeakMap<OpenHandle, RefundSource>()

/** The fire-time read of a tracked ticket's box. */
export interface TicketProbe {
    /** False once the box is gone: settled or lapsed elsewhere. */
    exists: boolean
    /**
     * Which deadline call the contract allows on the box now. arbitrate and
     * settleLapsed are terminal for the refund path, since neither state can
     * return to one refundInactive accepts; wait is the re-arm.
     */
    verdict: Verdict
    /** The box's own deadline D, unix ms. */
    deadlineMs: number
    /**
     * The amount on whichever side's claim the box carries. driveLapse reads
     * it only beside settleLapsed, an operator claim: a payer claim's amount
     * is the payer's own receipt.
     */
    pendingAmount?: bigint
}

type Probe = (signal: AbortSignal) => Promise<TicketProbe>
type Call = (signal: AbortSignal) => Promise<string>

type ProbeResult = { ok: true; res: TicketProbe } | { ok: false; err: unknown }
type CallResult = { ok: true; txid: string } | { ok: false; err: unknown }

/** callOnce's answer once the ticket was resolved or handed off; the loops return on it rather than retry. */
const errCancelled = new Error('refund watchdog: cancelled')

export interface WatchdogOptions {
    logger?: Logger | undefined
    clock?: Clock | undefined
    /** Remedies.recoverTicket. The box outlives this process, so a give-up log naming only the ticket id is a dead end. */
    remedy: string
    /**
     * Hears each ticket a refundInactive was submitted for. Submitted is
     * enough: the contract accepts it only past the deadline and with no
     * operator claim, so no charge can land after it.
     */
    refunded?: ((ticketId: string) => void) | undefined
    /**
     * Hears of each node whose claim on a tracked ticket exceeds the receipt
     * it signed, so the node is barred though the live ack never saw the
     * claim. Go's RefundWatchdog.overclaimed.
     */
    overclaimed?: ((ticketId: string, node: NodeRef) => void) | undefined
}

/** The RefundWatchdog a Client runs. */
export class Watchdog implements RefundWatchdog {
    /** Pads D before the first attempt, so skew against the chain's clock doesn't buy a certain revert. */
    marginMs = 15_000
    /** Spaces the re-attempts after a failed refund or lapse. */
    retryDelayMs = 60_000
    /** Bounds the refundInactive (or settleLapsed) tries per ticket. */
    attempts = 3
    /** Bounds one algod round trip; each probe and each submit gets its own. */
    callTimeoutMs = 30_000
    /**
     * How long past D the watchdog leaves an operator's claim to the node's
     * own driver before posting settleLapsed itself. The node lapses at
     * expires_at plus its own grace (5 minutes by default), which can sit well
     * after D, and retries up to 5 times. Undershooting only spends a fee
     * racing a node that would have succeeded, so this is generous.
     */
    lapseFallbackMs = 10 * 60_000

    readonly #log: Logger
    readonly #clock: Clock
    readonly #remedy: string
    readonly #refunded: ((ticketId: string) => void) | undefined
    readonly #overclaimed: ((ticketId: string, node: NodeRef) => void) | undefined
    #pending = new Map<string, AbortController>()
    /**
     * The amount the node signed for each tracked ticket this process saw a
     * receipt for, and the node that signed it: the one figure an operator
     * claim found on the box later can be held against. Dropped with the
     * ticket's driver.
     */
    readonly #receipts = new Map<string, { amount: bigint; node: NodeRef }>()
    /** Set by handOff: track arms nothing more. */
    #handedOff = false
    /** The per-ticket runs, which handOff waits out. */
    readonly #running = new Set<Promise<void>>()

    constructor(o: WatchdogOptions) {
        this.#log = o.logger ?? discardLogger
        this.#clock = o.clock ?? Date.now
        this.#remedy = o.remedy
        this.#refunded = o.refunded
        this.#overclaimed = o.overclaimed
    }

    track(h: OpenHandle | null | undefined, expiresAt: number): void {
        const src = h ? refundSources.get(h) : undefined
        if (!h || src === undefined) return
        const deadlineMs = expiresAt * 1000 + Number(src.graceSeconds) * 1000 + this.marginMs
        const probe: Probe = async (signal) => {
            const t = await src.readTicket(signal)
            if (t === null) return { exists: false, verdict: 'unknown', deadlineMs: 0 }
            return {
                exists: true,
                verdict: classify(t.view, new Date(this.#clock())),
                deadlineMs: Number(t.view.deadline) * 1000,
                pendingAmount: t.pendingAmount,
            }
        }
        const budget =
            (call: Call): Call =>
            (signal) =>
                call(src.callTimeoutMs === undefined ? signal : AbortSignal.timeout(src.callTimeoutMs))
        this.arm(
            h.ticketId,
            deadlineMs,
            probe,
            budget((signal) => h.refundInactive(signal)),
            budget((signal) => h.settleLapsed(signal)),
        )
    }

    /**
     * Pins the amount node signed for a ticket, so driveLapse can tell a
     * stalled honest claim from one that contradicts the receipt. An untracked
     * ticket records nothing: no driver would read the entry or delete it.
     * track runs at open and resolve only after the ack that follows the
     * receipt, so a live ticket is always still tracked here. Go's
     * recordReceipt.
     */
    recordReceipt(ticketId: string, node: NodeRef, amountCharged: bigint): void {
        if (!this.#pending.has(ticketId)) return
        this.#receipts.set(ticketId, { amount: amountCharged, node })
    }

    /** The amount recordReceipt pinned for ticketId, if any. */
    signedAmount(ticketId: string): bigint | undefined {
        return this.#receipts.get(ticketId)?.amount
    }

    resolve(ticketId: string): void {
        const cancel = this.#pending.get(ticketId)
        if (cancel === undefined) return
        this.#pending.delete(ticketId)
        cancel.abort()
    }

    /**
     * Cancels every armed ticket and arms no more, leaving them to the sweep
     * that next reads a durable journal: both driving one ticket would submit
     * the same refund or lapse, and the loser pays for a revert. A submit
     * already sent finishes first, for up to callTimeoutMs, so the next
     * sweeper reads its outcome rather than racing it.
     */
    async handOff(): Promise<void> {
        this.#handedOff = true
        const pending = this.#pending
        this.#pending = new Map()
        for (const cancel of pending.values()) cancel.abort()
        await Promise.allSettled([...this.#running])
    }

    /** Whether the watchdog is still driving ticketId: armed, and not yet resolved, finished or given up. */
    watching(ticketId: string): boolean {
        return this.#pending.has(ticketId)
    }

    /** track's core, which tests drive with fake closures and short timings. */
    arm(ticketId: string, deadlineMs: number, probe: Probe, refund: Call, lapse: Call): void {
        // A repeat shouldn't happen: ticket ids are single-use.
        if (this.#handedOff || this.#pending.has(ticketId)) return
        const cancel = new AbortController()
        this.#pending.set(ticketId, cancel)
        const run = this.#run(ticketId, deadlineMs, cancel.signal, probe, refund, lapse)
            // The calls and the refunded hook are the host's: a rejection
            // nothing observes would end a Node process.
            .catch((err: unknown) => {
                this.#log.error('refund watchdog: ticket driver failed', { ticket_id: ticketId, err: message(err) })
            })
            .finally(() => {
                this.#running.delete(run)
            })
        this.#running.add(run)
    }

    async #run(ticketId: string, deadlineMs: number, cancel: AbortSignal, probe: Probe, refund: Call, lapse: Call): Promise<void> {
        try {
            if (!(await idle(deadlineMs - this.#clock(), cancel))) return
            for (let attempt = 1; ; attempt++) {
                const p = await this.#probeOnce(cancel, probe)
                if (p.ok) {
                    const res = p.res
                    if (!res.exists) {
                        // The normal outcome for a ticket whose ack failed: the
                        // operator's driver settled or lapsed it.
                        this.#log.debug('refund watchdog: ticket box already gone (settled elsewhere)', { ticket_id: ticketId })
                        return
                    }
                    switch (res.verdict) {
                        case 'arbitrate':
                            this.#log.info('refund watchdog: ticket is frozen (dispute); leaving to arbitration', { ticket_id: ticketId })
                            return
                        case 'settleLapsed':
                            // The operator's claim landed after the payer lost
                            // sight of the ticket. The contract asserts 'ticket not
                            // refundable' on it, so no retry of refundInactive helps.
                            this.#log.info(
                                "refund watchdog: operator has a pending settle claim; refundInactive is not legal — deferring to the node's settleLapsed",
                                { ticket_id: ticketId },
                            )
                            await this.#driveLapse(ticketId, cancel, probe, lapse)
                            return
                        case 'unknown':
                            this.#log.warn(
                                'refund watchdog: unrecognized ticket state, likely a contract newer than these escrow bindings; not attempting refundInactive — upgrade before acting on this ticket',
                                { ticket_id: ticketId },
                            )
                            return
                    }
                    const wait = res.deadlineMs + this.marginMs - this.#clock()
                    if (wait > 0) {
                        // Track's deadline ran early. The box's is immutable once
                        // written, so the re-arm is bounded and costs no attempt.
                        this.#log.debug('refund watchdog: on-chain deadline still ahead; re-arming', {
                            ticket_id: ticketId,
                            deadline: new Date(res.deadlineMs),
                        })
                        attempt--
                        if (!(await idle(wait, cancel))) return
                        continue
                    }
                }
                // Live and past its deadline, or the probe failed: a revert is
                // cheap and the error may be transient.
                const r = await this.#callOnce(cancel, refund)
                if (r.ok) {
                    this.#log.info('refund watchdog: recovered escrowed USDC via refundInactive', { ticket_id: ticketId, txid: r.txid })
                    this.#refunded?.(ticketId)
                    return
                }
                if (r.err === errCancelled) return
                if (attempt >= this.attempts) {
                    this.#log.warn('refund watchdog: refundInactive failed; giving up', {
                        ticket_id: ticketId,
                        remedy: this.#remedy,
                        attempts: attempt,
                        err: message(r.err),
                        probe: probeState(p),
                    })
                    return
                }
                this.#log.debug('refund watchdog: refundInactive attempt failed; retrying', {
                    ticket_id: ticketId,
                    attempt,
                    err: message(r.err),
                })
                if (!(await idle(this.retryDelayMs, cancel))) return
            }
        } finally {
            this.#pending.delete(ticketId)
            this.#receipts.delete(ticketId)
        }
    }

    /**
     * The payer's backstop for an operator's claim, where refundInactive is
     * illegal. The node's own driver normally posts settleLapsed, so this waits
     * out its whole schedule and reads the box again before spending anything:
     * a box gone by then costs one read. One still parked means the node
     * stalled, and nobody else will move it, so the payer posts the
     * permissionless settleLapsed itself. It does so even when the claim takes
     * all of max_price: finalizing frees the payer's pool slot and unblocks
     * closeDeposit, so the ALGO is what's recovered then. The one claim it
     * will not finalize is one above the amount the node signed for the ticket
     * (recordReceipt). Shares the refund path's attempt bound.
     */
    async #driveLapse(ticketId: string, cancel: AbortSignal, probe: Probe, lapse: Call): Promise<void> {
        if (!(await idle(this.lapseFallbackMs, cancel))) return
        for (let attempt = 1; ; attempt++) {
            // No re-arm, unlike the refund loop: classify says settleLapsed only
            // past the box's deadline, which can no longer move.
            const p = await this.#probeOnce(cancel, probe)
            // Read per attempt: the receipt can be pinned while this waits out
            // lapseFallbackMs.
            const receipt = this.#receipts.get(ticketId)
            const signed = receipt?.amount
            if (p.ok) {
                if (!p.res.exists) {
                    this.#log.debug('refund watchdog: operator-pending ticket finalized by the node', { ticket_id: ticketId })
                    return
                }
                if (p.res.verdict === 'arbitrate') {
                    this.#log.info('refund watchdog: ticket froze while awaiting settleLapsed; leaving to arbitration', { ticket_id: ticketId })
                    return
                }
                if (p.res.verdict === 'unknown') {
                    this.#log.warn(
                        'refund watchdog: unrecognized ticket state, likely a contract newer than these escrow bindings; not attempting settleLapsed — upgrade before acting on this ticket',
                        { ticket_id: ticketId },
                    )
                    return
                }
                const claimed = p.res.pendingAmount
                if (p.res.verdict === 'settleLapsed' && signed !== undefined && claimed !== undefined && claimed > signed) {
                    // Refusing is no defense: settleLapsed is permissionless and
                    // pays the operator, who can post it and collect either way.
                    // It keeps the payer from paying the fee for a payout its
                    // own receipt contradicts, and gives the event a warning
                    // instead of a success line. The pool slot stays held until
                    // someone lapses the ticket.
                    this.#log.warn("refund watchdog: operator's settle claim exceeds the receipt it signed; not finalizing it with settleLapsed", {
                        ticket_id: ticketId,
                        claimed_microusdc: Number(claimed),
                        receipt_microusdc: Number(signed),
                        remedy: this.#remedy,
                    })
                    if (receipt !== undefined) this.#overclaimed?.(ticketId, receipt.node)
                    return
                }
            }
            // With a receipt held, a box that can't be read could carry a claim
            // above it, which a blind settleLapsed would pay in full: counted
            // as a failed attempt instead. With none, a revert is cheap and the
            // error may be transient, so the lapse goes ahead.
            const r: CallResult =
                !p.ok && receipt !== undefined
                    ? { ok: false, err: new Error(`box unreadable, so not lapsing a claim the receipt may contradict: ${message(p.err)}`, { cause: p.err }) }
                    : await this.#callOnce(cancel, lapse)
            if (r.ok) {
                this.#log.info('refund watchdog: finalized a stalled operator claim via settleLapsed', { ticket_id: ticketId, txid: r.txid })
                return
            }
            if (r.err === errCancelled) return
            if (attempt >= this.attempts) {
                this.#log.warn('refund watchdog: settleLapsed failed; giving up', {
                    ticket_id: ticketId,
                    remedy: this.#remedy,
                    attempts: attempt,
                    err: message(r.err),
                    probe: probeState(p),
                })
                return
            }
            this.#log.debug('refund watchdog: settleLapsed attempt failed; retrying', {
                ticket_id: ticketId,
                attempt,
                err: message(r.err),
            })
            if (!(await idle(this.retryDelayMs, cancel))) return
        }
    }

    /**
     * One box read under its own timeout, ended early by cancel. Each network
     * call gets a fresh budget: a probe sharing the submit's deadline lets a
     * slow algod spend it all on the read, failing the submit for nothing to do
     * with the ticket exactly when the chain is slow.
     */
    async #probeOnce(cancel: AbortSignal, probe: Probe): Promise<ProbeResult> {
        try {
            return { ok: true, res: await probe(AbortSignal.any([cancel, AbortSignal.timeout(this.callTimeoutMs)])) }
        } catch (err) {
            return { ok: false, err }
        }
    }

    /**
     * One submit under its own timeout. cancel stops it from starting but not
     * once it may have reached algod: handOff waits for its answer instead.
     */
    async #callOnce(cancel: AbortSignal, call: Call): Promise<CallResult> {
        if (cancel.aborted) return { ok: false, err: errCancelled }
        try {
            return { ok: true, txid: await call(AbortSignal.timeout(this.callTimeoutMs)) }
        } catch (err) {
            return { ok: false, err }
        }
    }
}

/**
 * What the last box read told a give-up log. After a failed probe there is no
 * on-chain state to report, which is the common give-up, since probe and
 * submit usually fail for the same reason.
 */
function probeState(p: ProbeResult): Record<string, unknown> {
    if (!p.ok) return { err: message(p.err) }
    return { verdict: p.res.verdict, deadline: new Date(p.res.deadlineMs) }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
