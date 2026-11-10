/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The journal sweep and the request path's journal writes, porting go/zs
// reconcile_test.go, spend_outcome_test.go and the walletChain cases of
// config_gates_test.go. decideTicket itself is pinned by reconcile.test.ts.

import {
    PENDING_BY_OPERATOR,
    STATUS_FROZEN,
    STATUS_OPEN,
    STATUS_PENDING_SETTLE,
    type TicketRecord as TicketBox,
} from '@txnlab/zs-proto/escrow'
import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'
import { describe, expect, it } from 'vitest'

import { settleArgsOf } from '../src/ack.js'
import type { SpendGuard } from '../src/config.js'
import { resolveNetwork } from '../src/network.js'
import { type OpenHandle, type TicketJournal, memoryJournal } from '../src/parts.js'
import type { Signer } from '../src/ports.js'
import {
    RECONCILE_MAX_FAILURES,
    Reconciler,
    type TicketChain,
    boxSweep,
    journalOpen,
    journalReceipt,
    walletChain,
} from '../src/reconciler.js'
import { SETTLE_PENDING_GRACE_MS, type SettleArgs, type TicketRecord } from '../src/reconcile.js'
import { type EscrowChain, Wallet, decodeTicketId } from '../src/wallet.js'
import { recLogger } from './turn-fixtures.js'

const NOW = 1_800_000_000_000
const MIN = 60_000
const HOUR = 60 * MIN
const SKEW = 15_000

/** A ticket box whose deadline is deadlineIn ms from NOW. */
function box(status: number, pendingBy: number, deadlineIn: number): TicketBox {
    return {
        status,
        pendingBy,
        expiresAt: BigInt(Math.floor((NOW + deadlineIn) / 1000)) - 60n,
        settlementGraceSeconds: 60n,
        operatorOwnerAddr: 'OWNER',
        pendingAmount: 0n,
        pendingDigest: new Uint8Array(32),
        pendingTtftMs: 0n,
        pendingDecodeMs: 0n,
        pendingInputCount: 0n,
        pendingOutputCount: 0n,
        pendingOutputUsageType: 0n,
        pendingAuxOutputUsageType: 0n,
        pendingAuxOutputCount: 0n,
    } as unknown as TicketBox
}

const settled: SettleArgs = {
    amountCharged: 7n,
    receiptDigest: new Uint8Array(32).fill(1),
    ttftMs: 2n,
    decodeMs: 3n,
    inputTokens: 4n,
    outputTokens: 5n,
    outputUsageType: 1,
    auxOutputUsageType: 2,
    auxOutputCount: 6n,
}

function openRec(over: Partial<TicketRecord> = {}): TicketRecord {
    return {
        ticketId: 'T',
        openTxId: '',
        escrowAppId: 7n,
        target: { op: 3, node: 4 },
        payer: 'PAYER',
        maxPrice: 99n,
        expiresAt: 0,
        status: 'open',
        createdAt: 0,
        updatedAt: NOW - HOUR,
        ...over,
    }
}

/** A row carrying the payer's receipt, recorded age ago. */
const pendingRec = (age: number, over: Partial<TicketRecord> = {}) =>
    openRec({ status: 'settle_pending', settle: settled, updatedAt: NOW - age, ...over })

/** Answers box reads from boxes and records each submit. */
class FakeChain implements TicketChain {
    boxes = new Map<string, TicketBox | null>()
    readErr: Error | undefined
    callErr: Error | undefined
    calls: string[] = []
    readBox = async (id: string) => {
        if (this.readErr) throw this.readErr
        return this.boxes.get(id) ?? null
    }
    #record = async (call: string) => {
        this.calls.push(call)
        if (this.callErr) throw this.callErr
        return 'TX'
    }
    refund = (rec: TicketRecord) => this.#record(`refund ${rec.ticketId}`)
    /** The box each lapse, re-settle and freeze was handed, in order. */
    handed: (TicketBox | null)[] = []
    lapse = (rec: TicketRecord, box: TicketBox | null) => (this.handed.push(box), this.#record(`lapse ${rec.ticketId}`))
    resettle = (rec: TicketRecord, box: TicketBox | null) => (this.handed.push(box), this.#record(`settle ${rec.ticketId}`))
    /** Each freeze's args, in order. */
    frozeWith: SettleArgs[] = []
    freeze = (rec: TicketRecord, box: TicketBox | null, args: SettleArgs) => {
        this.handed.push(box)
        this.frozeWith.push(args)
        return this.#record(`freeze ${rec.ticketId}`)
    }
    /** Each accept's args, in order. */
    acceptedWith: SettleArgs[] = []
    accept = (rec: TicketRecord, box: TicketBox, args: SettleArgs) => {
        this.handed.push(box)
        this.acceptedWith.push(args)
        return this.#record(`accept ${rec.ticketId}`)
    }
    /** Fakes an escrow without resolveFrozen. */
    noResolveFrozen = false
    freezes = async () => !this.noResolveFrozen
}

// Owns the rows openRec writes, which name only app 7, as a row from before
// rows named their deployment does.
const app7 = resolveNetwork({ network: 'localnet', escrowAppId: 7n })

function testReconciler(journal: TicketJournal, chain: TicketChain, watching: string[] = [], spend?: SpendGuard) {
    const log = recLogger()
    const r = new Reconciler({
        journal,
        chain: boxSweep(chain),
        payer: 'PAYER',
        deployment: app7,
        watching: (id) => watching.includes(id),
        spend,
        logger: log,
        clock: () => NOW,
    })
    return { r, log }
}

async function put(j: TicketJournal, ...recs: TicketRecord[]) {
    for (const r of recs) await j.put(r)
}

const ids = async (j: TicketJournal) => (await j.list('PAYER', app7)).map((r) => r.ticketId)

/** Records each settle and release it hears. */
function outcomeGuard(): SpendGuard & { calls: string[] } {
    const calls: string[] = []
    return {
        calls,
        admit() {},
        reserve() {},
        settle: (id, charged) => void calls.push(`settle ${id} ${charged}`),
        release: (id) => void calls.push(`release ${id}`),
    }
}

describe('Reconciler', () => {
    // It acts on each ticket nobody else drives, forgets the ones whose box is
    // gone, and keeps the ones it submitted for until a later sweep sees them
    // gone.
    it('sweeps the tickets nobody else drives', async () => {
        const j = memoryJournal()
        // The watched ticket sorts first, so skipping it must not end the sweep.
        await put(
            j,
            openRec({ ticketId: 'AWATCHED' }),
            openRec({ ticketId: 'GONE' }),
            openRec({ ticketId: 'STALE' }),
            openRec({ ticketId: 'OTHER', payer: 'SOMEONE' }),
            openRec({ ticketId: 'ELSEWHERE', escrowAppId: 8n }),
        )
        const chain = new FakeChain()
        for (const id of ['STALE', 'AWATCHED', 'OTHER', 'ELSEWHERE']) chain.boxes.set(id, box(STATUS_OPEN, 0, -MIN))
        const { r } = testReconciler(j, chain, ['AWATCHED'])
        await r.sweep()
        expect(chain.calls).toEqual(['refund STALE'])
        expect(await ids(j)).toEqual(['AWATCHED', 'STALE'])

        chain.boxes.set('STALE', null)
        await r.sweep()
        expect(await ids(j)).toEqual(['AWATCHED'])
    })

    // A re-settle for a stranded receipt, and settleLapsed once the lapse
    // fallback has passed.
    for (const [name, rec, b, want] of [
        ['stranded receipt', pendingRec(HOUR), box(STATUS_OPEN, 0, HOUR), ['settle T']],
        ['operator claim past the lapse fallback', openRec(), box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, -11 * MIN), ['lapse T']],
        ['operator claim inside the lapse fallback', openRec(), box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, -9 * MIN), []],
        ['open box inside the window', openRec(), box(STATUS_OPEN, 0, HOUR), []],
    ] as const) {
        it(`submits the verdict's call: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, rec)
            const chain = new FakeChain()
            chain.boxes.set('T', b)
            await testReconciler(j, chain).r.sweep()
            expect(chain.calls).toEqual(want)
            expect(await ids(j)).toEqual(['T'])
        })
    }

    // Each call that names the box gets the one the sweep read: walletChain
    // takes the operator's owner address, which the contract pays, from it.
    for (const [name, rec, b] of [
        ['lapse', openRec(), box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, -11 * MIN)],
        ['re-settle', pendingRec(HOUR), box(STATUS_OPEN, 0, HOUR)],
        [
            'freeze',
            pendingRec(HOUR),
            { ...box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, HOUR), pendingAmount: settled.amountCharged + 1n } as TicketBox,
        ],
    ] as const) {
        it(`hands the chain the box it read: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, rec)
            const chain = new FakeChain()
            chain.boxes.set('T', b)
            await testReconciler(j, chain).r.sweep()
            expect(chain.calls).toHaveLength(1)
            expect(chain.handed).toHaveLength(1)
            expect(chain.handed[0]).toBe(b)
        })
    }

    it('takes lapseFallbackMs from the field', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        const chain = new FakeChain()
        chain.boxes.set('T', box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, -2 * MIN))
        const { r } = testReconciler(j, chain)
        r.lapseFallbackMs = MIN
        await r.sweep()
        expect(chain.calls).toEqual(['lapse T'])
    })

    // A frozen ticket is the admin's and no call the payer can make touches it, so its row
    // goes rather than costing a read every minute forever.
    it('forgets a frozen ticket and submits nothing', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        const chain = new FakeChain()
        chain.boxes.set('T', box(STATUS_FROZEN, 0, -MIN))
        const { r, log } = testReconciler(j, chain)
        await r.sweep()
        expect([await ids(j), chain.calls]).toEqual([[], []])
        expect(log.logged).toContainEqual({ level: 'warn', msg: 'ticket reconciler: ticket is frozen; leaving it to arbitration', attrs: { ticket_id: 'T' } })
    })

    // The open is submitted unconfirmed and the contract takes it until
    // expires_at, so a missing box is final only past the expiry.
    it('keeps a row whose box has not appeared before the ticket expires', async () => {
        const j = memoryJournal()
        await put(j, openRec({ ticketId: 'LIVE', expiresAt: NOW + MIN }), openRec({ ticketId: 'DEAD', expiresAt: NOW - SKEW - 1000 }))
        await testReconciler(j, new FakeChain()).r.sweep()
        expect(await ids(j)).toEqual(['LIVE'])
    })

    it('keeps a ticket whose box cannot be read', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        const chain = new FakeChain()
        chain.readErr = new Error('algod down')
        await testReconciler(j, chain).r.sweep()
        expect([await ids(j), chain.calls]).toEqual([['T'], []])
    })

    it('logs a journal it cannot read, and acts on nothing', async () => {
        const j: TicketJournal = { put: async () => {}, delete: async () => {}, list: () => Promise.reject(new Error('disk gone')) }
        const chain = new FakeChain()
        const { r, log } = testReconciler(j, chain)
        await r.sweep()
        expect(log.logged).toEqual([{ level: 'warn', msg: 'ticket reconciler: journal read failed', attrs: { err: 'disk gone' } }])
    })

    it('logs a row it cannot delete', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        j.delete = () => Promise.reject(new Error('disk gone'))
        const { r, log } = testReconciler(j, new FakeChain())
        await r.sweep()
        expect(log.logged).toContainEqual({ level: 'warn', msg: 'ticket reconciler: journal delete failed', attrs: { ticket_id: 'T', err: 'disk gone' } })
    })

    // A ticket whose submit keeps failing stops costing fees after the cap,
    // for this process, and the give-up line is the payer's lead.
    it('stops submitting for a ticket after RECONCILE_MAX_FAILURES', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        const chain = new FakeChain()
        chain.boxes.set('T', box(STATUS_OPEN, 0, -MIN))
        chain.callErr = new Error('rejected')
        const { r, log } = testReconciler(j, chain)
        r.remedy = 'recover it by hand'
        for (let i = 0; i < RECONCILE_MAX_FAILURES + 3; i++) await r.sweep()
        expect(chain.calls).toHaveLength(RECONCILE_MAX_FAILURES)
        const giveUp = log.logged.filter((l) => l.level === 'warn')
        expect(giveUp).toEqual([
            {
                level: 'warn',
                msg: 'ticket reconciler: refundInactive keeps failing; leaving the ticket for the next start',
                attrs: { ticket_id: 'T', attempts: RECONCILE_MAX_FAILURES, err: 'rejected', remedy: 'recover it by hand' },
            },
        ])
        expect(await ids(j)).toEqual(['T'])

        // An exhausted ticket listed first doesn't stop the sweep reaching a later one.
        await put(j, openRec({ ticketId: 'U', createdAt: NOW }))
        chain.boxes.set('U', box(STATUS_OPEN, 0, -MIN))
        await r.sweep()
        expect(chain.calls.at(-1)).toBe('refund U')
    })

    // The freeze goes out as the payer's settle at the journaled receipt, never
    // the claim's own values, which would match the claim and pay it, and says
    // so at warn. A receipt that failed a check is held against the claim the
    // same way.
    const overclaimBox = (deadlineIn = HOUR) =>
        ({
            ...box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, deadlineIn),
            pendingAmount: settled.amountCharged + 100n,
            pendingDigest: settled.receiptDigest,
        }) as TicketBox
    for (const [name, rec] of [
        ['verified', pendingRec(HOUR)],
        ['failed a check', openRec({ signed: settled })],
    ] as const) {
        it(`freezes an operator claim above the receipt with the receipt: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, rec)
            const chain = new FakeChain()
            chain.boxes.set('T', overclaimBox())
            const { r, log } = testReconciler(j, chain)
            await r.sweep()
            expect([chain.calls, chain.frozeWith]).toEqual([['freeze T'], [settled]])
            expect(log.logged).toEqual([
                {
                    level: 'warn',
                    msg: "ticket reconciler: operator's settle claim exceeds its signed receipt; submitted the receipt's settle to freeze the ticket",
                    attrs: { ticket_id: 'T', txid: 'TX', claimed_microusdc: 107, receipt_microusdc: 7 },
                },
            ])
        })
    }

    // A ticket the watchdog drives is the sweep's for a freeze alone: the
    // watchdog acts only past the deadline, so an over-claim the node posts
    // after the live ack read the box, or after the ack failed, has nobody
    // else to freeze it inside the window.
    for (const [name, rec, b, want] of [
        ['claim above a verified receipt', pendingRec(HOUR), overclaimBox(), ['freeze T']],
        // Inside the settle-pending grace too: the window can close before the
        // grace ends, and an over-claim left to it lapses to the node.
        ['claim above a verified receipt, inside the grace', pendingRec(MIN), overclaimBox(), ['freeze T']],
        ['claim above a receipt that failed a check', openRec({ signed: settled }), overclaimBox(), ['freeze T']],
        ['stranded receipt', pendingRec(HOUR), box(STATUS_OPEN, 0, HOUR), []],
        ['claim above the receipt, past the lapse fallback', pendingRec(HOUR), overclaimBox(-11 * MIN), []],
        ['open past the deadline', pendingRec(HOUR), box(STATUS_OPEN, 0, -MIN), []],
        ['frozen', pendingRec(HOUR), box(STATUS_FROZEN, PENDING_BY_OPERATOR, HOUR), []],
        ['gone', pendingRec(HOUR), null, []],
    ] as const) {
        it(`acts on a watched ticket only to freeze it: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, rec)
            const chain = new FakeChain()
            chain.boxes.set('T', b)
            await testReconciler(j, chain, ['T']).r.sweep()
            expect(chain.calls).toEqual(want)
            expect(await ids(j)).toEqual(['T'])
        })
    }

    // On an escrow without resolveFrozen a freeze would lock the ticket's
    // escrow for good, so the sweep sends none: an unwatched over-claim is
    // left to the operator's lapse, still never lapsed by the payer, and a
    // watched row inside the settle-pending grace, where no $0 claim is
    // accepted either, is not read at all. Go's
    // TestReconciler_SendsNoFreezeWithoutResolveFrozen.
    for (const [name, b, watched] of [
        ['unwatched, inside the window', overclaimBox(), false],
        ['unwatched, past the lapse fallback', overclaimBox(-11 * MIN), false],
        ['watched', overclaimBox(), true],
    ] as const) {
        it(`sends no freeze without resolveFrozen: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, pendingRec(watched ? MIN : HOUR))
            const chain = new FakeChain()
            chain.noResolveFrozen = true
            chain.boxes.set('T', b)
            let reads = 0
            const read = chain.readBox
            chain.readBox = async (id: string) => (reads++, read(id))
            await testReconciler(j, chain, watched ? ['T'] : []).r.sweep()
            expect(chain.calls).toEqual([])
            if (watched) expect(reads).toBe(0)
        })
    }

    // Every sweep that reads an operator claim above the row's receipt bars
    // the node, watched or not, inside the window or past it, and on an escrow
    // without resolveFrozen too. No other claim does. Go's
    // TestReconciler_BarsAnOverclaimingNode.
    for (const [name, b, watched, noResolveFrozen, want] of [
        ['claim above the receipt', overclaimBox(), false, false, true],
        ['claim above the receipt, watched', overclaimBox(), true, false, true],
        ['claim above the receipt, past the lapse fallback', overclaimBox(-11 * MIN), false, false, true],
        ['claim above the receipt, no resolveFrozen', overclaimBox(), false, true, true],
        ['claim matching the receipt', { ...overclaimBox(), pendingAmount: settled.amountCharged } as TicketBox, false, false, false],
        ['claim below the receipt', { ...overclaimBox(), pendingAmount: settled.amountCharged - 1n } as TicketBox, false, false, false],
        ['open', box(STATUS_OPEN, 0, HOUR), false, false, false],
    ] as const) {
        it(`bars a node claiming above its receipt: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, pendingRec(HOUR, { target: { op: 3, node: 4 } }))
            const chain = new FakeChain()
            chain.noResolveFrozen = noResolveFrozen
            chain.boxes.set('T', b)
            const barred: unknown[] = []
            const r = new Reconciler({
                journal: j,
                chain: boxSweep(chain),
                payer: 'PAYER',
                deployment: app7,
                watching: (id) => watched && id === 'T',
                overclaimed: (rec) => void barred.push(rec.target),
                clock: () => NOW,
            })
            await r.sweep()
            expect(barred).toEqual(want ? [{ op: 3, node: 4 }] : [])
        })
    }

    it('never reads a watched row with no receipt inside the settle-pending grace', async () => {
        const j = memoryJournal()
        await put(j, openRec({ updatedAt: NOW - SETTLE_PENDING_GRACE_MS + 1 }))
        const chain = new FakeChain()
        let reads = 0
        chain.readBox = async () => {
            reads++
            return null
        }
        await testReconciler(j, chain, ['T']).r.sweep()
        expect([reads, chain.calls]).toEqual([0, []])
    })

    // A $0 operator claim is accepted at the claim's own values, every one,
    // since the contract freezes a half that differs in any, and whatever
    // receipt the row records. Go's
    // TestReconciler_AcceptsAZeroClaimAtItsOwnValues.
    for (const [name, rec] of [
        ['no receipt', openRec()],
        ['a contradicting receipt', pendingRec(HOUR)],
    ] as const) {
        it(`accepts a $0 claim at its own values: ${name}`, async () => {
            const claim: SettleArgs = {
                amountCharged: 0n,
                receiptDigest: new Uint8Array(32).fill(7),
                ttftMs: 11n,
                decodeMs: 12n,
                inputTokens: 13n,
                outputTokens: 14n,
                outputUsageType: 1,
                auxOutputUsageType: 2,
                auxOutputCount: 15n,
            }
            const j = memoryJournal()
            await put(j, rec)
            const chain = new FakeChain()
            const b = {
                ...box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, HOUR),
                pendingAmount: claim.amountCharged,
                pendingDigest: claim.receiptDigest,
                pendingTtftMs: claim.ttftMs,
                pendingDecodeMs: claim.decodeMs,
                pendingInputCount: claim.inputTokens,
                pendingOutputCount: claim.outputTokens,
                pendingOutputUsageType: claim.outputUsageType,
                pendingAuxOutputUsageType: claim.auxOutputUsageType,
                pendingAuxOutputCount: claim.auxOutputCount,
            }
            chain.boxes.set('T', b)
            const g = outcomeGuard()
            await testReconciler(j, chain, [], g).r.sweep()
            expect([chain.calls, chain.acceptedWith, chain.handed]).toEqual([['accept T'], [claim], [b]])
            expect(g.calls).toEqual(['release T'])
        })
    }

    // The accept itself refuses a claim above $0, before anything is sent, so
    // a caller other than decideSettlement can't echo a paid claim. Go's
    // TestBoxChain_AcceptRefusesAPaidClaim.
    it('refuses to accept a claim above $0', async () => {
        const chain = new FakeChain()
        const b = { ...box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, HOUR), pendingAmount: 1n }
        await expect(boxSweep(chain).accept(openRec(), { box: b }, new AbortController().signal)).rejects.toThrow('not $0')
        expect(chain.acceptedWith).toEqual([])
    })

    // A watched row's $0 claim is the sweep's to accept once the row is past
    // the settle-pending grace, receipt or none and on an escrow without
    // resolveFrozen too; inside the grace the row is not read. Go's
    // TestReconciler_AcceptsAWatchedZeroClaimPastTheGrace.
    for (const [name, rec, noResolveFrozen, want, read] of [
        ['no receipt, past the grace', openRec(), false, ['accept T'], true],
        ['no receipt, past the grace, no resolveFrozen', openRec(), true, ['accept T'], true],
        ['receipt, past the grace', pendingRec(HOUR), false, ['accept T'], true],
        ['no receipt, inside the grace', openRec({ updatedAt: NOW - SETTLE_PENDING_GRACE_MS + 1 }), false, [], false],
        ['no receipt, exactly at the grace', openRec({ updatedAt: NOW - SETTLE_PENDING_GRACE_MS }), false, ['accept T'], true],
        // A row time that isn't a number reads as long past.
        ['no receipt, no row time', openRec({ updatedAt: Number.NaN }), false, ['accept T'], true],
    ] as const) {
        it(`accepts a watched $0 claim only past the grace: ${name}`, async () => {
            const j = memoryJournal()
            await put(j, rec)
            const chain = new FakeChain()
            chain.noResolveFrozen = noResolveFrozen
            chain.boxes.set('T', box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, HOUR))
            let reads = 0
            const readBox = chain.readBox
            chain.readBox = async (id: string) => (reads++, readBox(id))
            await testReconciler(j, chain, ['T']).r.sweep()
            expect([chain.calls, reads > 0]).toEqual([want, read])
        })
    }

    it('logs each submit it made', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        const chain = new FakeChain()
        chain.boxes.set('T', box(STATUS_OPEN, 0, -MIN))
        const { r, log } = testReconciler(j, chain)
        await r.sweep()
        expect(log.logged).toEqual([{ level: 'info', msg: 'ticket reconciler: submitted refundInactive', attrs: { ticket_id: 'T', txid: 'TX' } }])
    })

    // The guard hears each outcome the chain has fixed: a refund algod
    // accepted frees the reservation, and a lapse charges the operator's
    // claim. A journaled receipt was counted when the request settled it, so
    // its ticket is only released. Where the outcome is open or unknown it
    // hears nothing.
    describe('tells the SpendGuard how a ticket ended', () => {
        const claimedAt = (amount: bigint) =>
            ({ ...box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, -11 * MIN), pendingAmount: amount }) as TicketBox
        const claimed = () => claimedAt(9n)
        // A receipt past the settle window, whose operator claim (5, not 7)
        // the payer's settle would contradict. A claim above the receipt is
        // never lapsed by the payer, so it would report nothing.
        for (const [name, rec, b, callErr, want] of [
            ['refund submitted', openRec(), box(STATUS_OPEN, 0, -MIN), undefined, ['release T']],
            ['refund refused', openRec(), box(STATUS_OPEN, 0, -MIN), new Error('rejected'), []],
            ['lapse submitted', openRec(), claimed(), undefined, ['settle T 9']],
            ['lapse refused', openRec(), claimed(), new Error('rejected'), []],
            ['lapse submitted, receipt already counted', pendingRec(HOUR), claimedAt(5n), undefined, ['release T']],
            ['claim above the receipt, never lapsed', pendingRec(HOUR), claimed(), undefined, []],
            ['inside the window', openRec(), box(STATUS_OPEN, 0, HOUR), undefined, []],
            ['re-settle submitted', pendingRec(HOUR), box(STATUS_OPEN, 0, HOUR), undefined, []],
            ['box gone, with a receipt', pendingRec(HOUR), null, undefined, ['release T']],
            ['box gone, no receipt', openRec(), null, undefined, []],
            ['frozen, with a receipt', pendingRec(HOUR), box(STATUS_FROZEN, 0, -MIN), undefined, []],
        ] as const) {
            it(name, async () => {
                const j = memoryJournal()
                await put(j, rec)
                const chain = new FakeChain()
                chain.boxes.set('T', b)
                chain.callErr = callErr
                const guard = outcomeGuard()
                await testReconciler(j, chain, [], guard).r.sweep()
                expect(guard.calls).toEqual(want)
            })
        }

        it('still forgets a closed ticket with no guard', async () => {
            const j = memoryJournal()
            await put(j, pendingRec(HOUR))
            await testReconciler(j, new FakeChain()).r.sweep()
            expect(await ids(j)).toEqual([])
        })
    })

    it('sweeps at once on start, then each interval, and close stops the loop', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        let lists = 0
        const list = j.list.bind(j)
        j.list = (...a) => (lists++, list(...a))
        const { r } = testReconciler(j, new FakeChain())
        r.interval = 30
        r.start()
        await expect.poll(async () => ids(j)).toEqual([])
        await expect.poll(() => lists).toBeGreaterThanOrEqual(3)
        await r.close()
        await r.close()
        const after = lists
        await new Promise((res) => setTimeout(res, 80))
        expect(lists).toBe(after)
    })

    // close aborts a chain call in flight rather than waiting out its
    // timeout, and counts no failure for it.
    it('aborts a call in flight on close, counting no failure', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        let entered!: () => void
        const inFlight = new Promise<void>((res) => (entered = res))
        let seen: AbortSignal | undefined
        const chain = new FakeChain()
        chain.boxes.set('T', box(STATUS_OPEN, 0, -HOUR))
        chain.refund = (_rec, signal?: AbortSignal) => {
            seen = signal
            entered()
            return new Promise<string>(() => {}) // a wedged algod that ignores the signal
        }
        const { r, log } = testReconciler(j, chain)
        r.callTimeoutMs = 3_600_000
        r.start()
        await inFlight
        const closed = r.close()
        const won = await Promise.race([closed.then(() => true), new Promise((res) => setTimeout(() => res(false), 2000))])
        expect(won, 'close waited on the call').toBe(true)
        expect(seen?.aborted).toBe(true)
        expect(log.logged.filter((l) => l.msg.includes('failed'))).toEqual([])
    })

    // Once closed, no call starts: one sent on a spent signal never hears the
    // abort, so a chain call that ignores it would hold close open.
    it('starts no call once closed mid-sweep', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        let reads = 0
        const chain = new FakeChain()
        chain.readBox = () => (reads++, new Promise(() => {}))
        let closing: Promise<void> | undefined
        const r = new Reconciler({
            journal: j,
            chain: boxSweep(chain),
            payer: 'PAYER',
            deployment: app7,
            watching: () => {
                closing = r.close()
                return false
            },
        })
        r.start()
        await expect.poll(() => closing !== undefined).toBe(true)
        const won = await Promise.race([closing!.then(() => true), new Promise((res) => setTimeout(() => res(false), 500))])
        expect(won, 'close waited on a call started after it').toBe(true)
        expect(reads).toBe(0)
    })

    // A forgotten row's delete finishes inside its sweep, so close never
    // hands the journal on with one still in flight.
    it('waits for a forgotten row to leave the journal', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        let open!: () => void
        const gate = new Promise<void>((res) => (open = res))
        const del = j.delete.bind(j)
        j.delete = async (id) => {
            await gate
            return del(id)
        }
        const { r } = testReconciler(j, new FakeChain())
        let swept = false
        const sweep = r.sweep().then(() => (swept = true))
        await new Promise((res) => setTimeout(res, 20))
        expect(swept).toBe(false)
        open()
        await sweep
        expect(await ids(j)).toEqual([])
    })

    // A ticker's cadence, as Go's: a slow sweep doesn't push the next one
    // back by its own length.
    it('times each sweep from the start of the last', async () => {
        const j = memoryJournal()
        const starts: number[] = []
        const list = j.list.bind(j)
        j.list = async (...a) => {
            starts.push(Date.now())
            await new Promise((res) => setTimeout(res, 50))
            return list(...a)
        }
        const { r } = testReconciler(j, new FakeChain())
        r.interval = 60
        r.start()
        await expect.poll(() => starts.length, { timeout: 2000 }).toBeGreaterThanOrEqual(4)
        await r.close()
        const gaps = starts.slice(1).map((t, i) => t - starts[i]!)
        // Measured from the end instead, each gap would be about 110 ms.
        expect(Math.min(...gaps)).toBeLessThan(95)
    })

    it('bounds each call by callTimeoutMs', async () => {
        const j = memoryJournal()
        await put(j, openRec())
        const chain = new FakeChain()
        chain.readBox = () => new Promise(() => {})
        const { r, log } = testReconciler(j, chain)
        r.callTimeoutMs = 20
        await r.sweep()
        expect(log.logged.map((l) => l.msg)).toEqual(['ticket reconciler: ticket read failed; retrying next sweep'])
    })

    // The journal takes no signal, so a read in flight is abandoned; what
    // matters is that no sweep acts once the claim may pass on.
    it('runs beforeRelease, then releases, and sweeps no more once closed', async () => {
        const order: string[] = []
        const j = memoryJournal()
        const list = j.list.bind(j)
        j.list = async (...a) => {
            order.push('list')
            await new Promise((res) => setTimeout(res, 20))
            return list(...a)
        }
        const { r } = testReconciler(j, new FakeChain())
        r.interval = 5
        r.release = () => void order.push('release')
        r.start()
        await expect.poll(() => order.length).toBeGreaterThanOrEqual(1)
        await r.close(async () => {
            order.push('beforeRelease')
        })
        await new Promise((res) => setTimeout(res, 50))
        expect(order.slice(-2)).toEqual(['beforeRelease', 'release'])
    })

    // Kept, the claim bars every later Client from sweeping this journal.
    it('releases the claim even when beforeRelease throws', async () => {
        const { r } = testReconciler(memoryJournal(), new FakeChain())
        let released = false
        r.release = () => {
            released = true
        }
        r.start()
        await expect(
            r.close(() => {
                throw new Error('hand-off bug')
            }),
        ).rejects.toThrow('hand-off bug')
        expect(released).toBe(true)
    })

    // The spend guard is host code: one that throws costs a log line, and the
    // sweep goes on to the next ticket.
    it('logs a spend guard that throws and goes on to the next ticket', async () => {
        const j = memoryJournal()
        await put(j, openRec({ ticketId: 'A' }), openRec({ ticketId: 'B' }))
        const chain = new FakeChain()
        for (const id of ['A', 'B']) chain.boxes.set(id, box(STATUS_OPEN, 0, -MIN))
        const released: string[] = []
        const guard: SpendGuard = {
            admit() {},
            reserve() {},
            settle() {},
            release(id) {
                released.push(id)
                if (released.length === 1) throw new Error('guard bug')
            },
        }
        const { r, log } = testReconciler(j, chain, [], guard)
        await r.sweep()
        expect(chain.calls).toEqual(['refund A', 'refund B'])
        expect(released).toEqual(['A', 'B'])
        expect(log.logged).toContainEqual({ level: 'warn', msg: 'spend guard release failed', attrs: { ticket_id: 'A', err: 'guard bug' } })
    })

    // A row the sweep can't decide, here a box with no fields, doesn't end the
    // loop for the rows after it, and counts as a failed attempt: a row that
    // always throws is given up on with the remedy.
    it('goes on to the next ticket when one row throws, and gives up on it in time', async () => {
        const j = memoryJournal()
        await put(j, openRec({ ticketId: 'A' }), openRec({ ticketId: 'B' }))
        const chain = new FakeChain()
        chain.boxes.set('A', {} as TicketBox)
        chain.boxes.set('B', box(STATUS_OPEN, 0, -MIN))
        const { r, log } = testReconciler(j, chain)
        r.remedy = 'recover it by hand'
        await r.sweep()
        expect(chain.calls).toEqual(['refund B'])
        for (let i = 1; i < RECONCILE_MAX_FAILURES; i++) await r.sweep()
        expect(log.logged).toContainEqual(
            expect.objectContaining({
                level: 'warn',
                msg: 'ticket reconciler: reconcile keeps failing; leaving the ticket for the next start',
                attrs: expect.objectContaining({ ticket_id: 'A', remedy: 'recover it by hand' }),
            }),
        )
    })

    // The lapse went through, so a guard that throws on its charge costs a log
    // line, not a failed attempt, and the sweep goes on.
    it('logs a spend guard whose lapse settle throws, counting no failure', async () => {
        const j = memoryJournal()
        await put(j, openRec({ ticketId: 'A' }), openRec({ ticketId: 'B' }))
        const chain = new FakeChain()
        chain.boxes.set('A', box(STATUS_PENDING_SETTLE, PENDING_BY_OPERATOR, -11 * MIN))
        chain.boxes.set('B', box(STATUS_OPEN, 0, -MIN))
        const guard: SpendGuard = {
            admit() {},
            reserve() {},
            settle() {
                throw new Error('guard bug')
            },
            release() {},
        }
        const { r, log } = testReconciler(j, chain, [], guard)
        r.remedy = 'recover it by hand'
        for (let i = 0; i < RECONCILE_MAX_FAILURES; i++) await r.sweep()
        expect(chain.calls.slice(0, 2)).toEqual(['lapse A', 'refund B'])
        expect(log.logged).toContainEqual({ level: 'warn', msg: 'spend guard settle failed', attrs: { ticket_id: 'A', err: 'guard bug' } })
        expect(log.logged.some((l) => l.msg.includes('keeps failing'))).toBe(false)
    })

    // A closed ticket's row goes even when the guard throws on its release;
    // kept, it would be re-read and re-released every sweep.
    it('forgets a closed ticket when the guard throws on its release', async () => {
        const j = memoryJournal()
        await put(j, pendingRec(HOUR, { ticketId: 'A' }))
        const guard: SpendGuard = {
            admit() {},
            reserve() {},
            settle() {},
            release() {
                throw new Error('guard bug')
            },
        }
        const { r, log } = testReconciler(j, new FakeChain(), [], guard)
        await r.sweep()
        expect(await ids(j)).toEqual([])
        expect(log.logged).toContainEqual({ level: 'warn', msg: 'spend guard release failed', attrs: { ticket_id: 'A', err: 'guard bug' } })
    })

    // A guard returning a rejecting Promise is caught too: unobserved, the
    // rejection would end a Node process.
    it('logs a spend guard whose release rejects', async () => {
        const j = memoryJournal()
        await put(j, openRec({ ticketId: 'A' }))
        const chain = new FakeChain()
        chain.boxes.set('A', box(STATUS_OPEN, 0, -MIN))
        const guard = {
            admit() {},
            reserve() {},
            settle() {},
            release: () => Promise.reject(new Error('guard bug')),
        } as unknown as SpendGuard
        const { r, log } = testReconciler(j, chain, [], guard)
        await r.sweep()
        await new Promise((res) => setTimeout(res, 0))
        expect(log.logged).toContainEqual({ level: 'warn', msg: 'spend guard release failed', attrs: { ticket_id: 'A', err: 'guard bug' } })
    })
})

describe('walletChain', () => {
    const TICKET_ID = 'NkImzFiSJz3WK6cx7PFU1Q=='
    const PAYER = 'Z'.repeat(58)

    function wallet() {
        const calls: Record<string, unknown[]> = {}
        const signals: Record<string, AbortSignal | undefined> = {}
        const rec =
            <T>(name: string, out: T) =>
            async (c: unknown, signal?: AbortSignal) => {
                ;(calls[name] ??= []).push(c)
                signals[name] = signal
                return out
            }
        const chain = {
            refundInactive: rec('refundInactive', 'REFUND'),
            settleLapsed: rec('settleLapsed', 'LAPSE'),
            settleStandalone: rec('settleStandalone', { txid: 'SETTLE', payerFeeMicroalgos: 5000n }),
            readTicketBox: rec('readTicketBox', null),
        } as unknown as EscrowChain
        const signer = { address: PAYER } as Signer
        return { w: new Wallet({ chain, signer }), calls, signals }
    }

    const rec = openRec({ ticketId: TICKET_ID, target: { op: 3, node: 4 }, maxPrice: 99n, settle: settled })
    const ids = { ticketIdRaw: decodeTicketId(TICKET_ID), operatorId: 3n, nodeId: 4n }
    const owned = { ...box(STATUS_OPEN, 0, 0), operatorOwnerAddr: 'BOXOWNER' } as TicketBox

    // The box's owner is the one the contract pays.
    it('acts as the payer on the journaled ticket, paying the box owner', async () => {
        const { w, calls, signals } = wallet()
        const chain = walletChain(w)!
        const signal = new AbortController().signal
        expect(await chain.refund(rec, signal)).toBe('REFUND')
        expect(await chain.lapse(rec, owned, signal)).toBe('LAPSE')
        expect(await chain.resettle(rec, owned, signal)).toBe('SETTLE')
        expect(await chain.readBox(TICKET_ID, signal)).toBeNull()
        expect(calls).toEqual({
            refundInactive: [{ ...ids, payer: PAYER }],
            settleLapsed: [{ ...ids, operatorOwnerAddr: 'BOXOWNER', payer: PAYER }],
            settleStandalone: [{ ...ids, args: settled, maxPrice: 99n, payer: PAYER, operatorOwnerAddr: 'BOXOWNER' }],
            readTicketBox: [decodeTicketId(TICKET_ID)],
        })
        for (const name of Object.keys(calls)) expect(signals[name], name).toBe(signal)
    })

    // A freeze sends the args it is handed, not the row's, and takes the
    // contract's freeze branch, which pays for the outer call alone; a
    // re-settle pays for the finalize it causes. Go's
    // TestWalletChain_LapseAndResettleSubmit.
    it('freezes with the args it is handed, paying the outer call alone', async () => {
        const { w, calls } = wallet()
        const chain = walletChain(w)!
        const frozeAt = { ...settled, amountCharged: settled.amountCharged + 1n }
        const signal = new AbortController().signal
        expect(await chain.resettle(rec, owned, signal)).toBe('SETTLE')
        expect(await chain.freeze(rec, owned, frozeAt, signal)).toBe('SETTLE')
        expect(calls.settleStandalone).toEqual([
            { ...ids, args: settled, maxPrice: 99n, payer: PAYER, operatorOwnerAddr: 'BOXOWNER' },
            { ...ids, args: frozeAt, maxPrice: 99n, payer: PAYER, operatorOwnerAddr: 'BOXOWNER', outerFeeOnly: true },
        ])
    })

    // An accept matches the claim, so it finalizes and pays for the finalize,
    // as a re-settle does: on the outer call's fee alone algod refuses it.
    // Go's TestWalletChain_LapseAndResettleSubmit.
    it('accepts a claim at the args it is handed, paying the finalizing fee', async () => {
        const { w, calls } = wallet()
        const chain = walletChain(w)!
        const acceptAt = { ...settled, amountCharged: 0n }
        expect(await chain.accept(rec, owned, acceptAt, new AbortController().signal)).toBe('SETTLE')
        expect(calls.settleStandalone).toEqual([
            { ...ids, args: acceptAt, maxPrice: 99n, payer: PAYER, operatorOwnerAddr: 'BOXOWNER' },
        ])
    })

    // The sweep's freezes reads the deployment's resolveFrozen, and a config
    // it can't read is no evidence of one.
    it('reports whether the escrow resolves a frozen ticket', async () => {
        for (const [config, want] of [
            [async () => ({ resolvesFrozen: true }), true],
            [async () => ({ resolvesFrozen: false }), false],
            [async () => ({}), false],
            [async () => Promise.reject(new Error('algod down')), false],
        ] as const) {
            const chain = { config } as unknown as EscrowChain
            const c = walletChain(new Wallet({ chain, signer: { address: PAYER } as Signer }))!
            expect(await c.freezes(new AbortController().signal)).toBe(want)
        }
    })

    it('refuses a re-settle with no recorded receipt, and names each failed call', async () => {
        const { w, calls } = wallet()
        const chain = walletChain(w)!
        const { settle: _s, ...bare } = rec
        await expect(chain.resettle(bare, owned, new AbortController().signal)).rejects.toThrow('wallet: re-settle without a recorded receipt')
        expect(calls.settleStandalone).toBeUndefined()
        const bad = { ...rec, ticketId: 'AAAA' }
        const s = new AbortController().signal
        await expect(chain.refund(bad, s)).rejects.toThrow(/^wallet: refund-inactive: /)
        await expect(chain.lapse(bad, owned, s)).rejects.toThrow(/^wallet: settle-lapsed: /)
        await expect(chain.resettle(bad, owned, s)).rejects.toThrow(/^wallet: re-settle: /)
    })

    it("has nothing for a wallet the SDK didn't build", () => {
        expect(walletChain({ open: async () => ({}), payerAddr: () => PAYER })).toBeUndefined()
    })
})

describe('journal writes', () => {
    const ticket = { ticket_id: 'TKT', max_price: 500, expires_at: 1_800_000_600 } as Ticket
    const handle = () => ({ appCallTxId: 'OPENTX', operator: { id: 3, nodeId: 4 } }) as OpenHandle
    const receipt = {
        ticket_id: 'TKT',
        actual_input_count: 4,
        actual_output_count: 5,
        amount_charged: 7,
        ttft_ms: 2,
        decode_ms: 3,
        body_hash: '0'.repeat(64),
        input_usage_type: 0,
        output_usage_type: 1,
        aux_output_usage_type: 2,
        aux_output_count: 6,
        cached_input_count: 0,
    } as UsageReceipt
    let now = NOW
    const deps = (journal: TicketJournal | undefined) => ({
        journal,
        logger: recLogger(),
        clock: () => now,
        deployment: app7,
        payer: 'PAYER',
    })

    it('journals the open, then the receipt the payer will co-sign', async () => {
        const j = memoryJournal()
        const d = deps(j)
        const h = handle()
        now = NOW
        await journalOpen(d, h, ticket)
        const opened: TicketRecord = {
            ticketId: 'TKT',
            openTxId: 'OPENTX',
            escrowAppId: 7n,
            deployment: 'algorand-localnet-7',
            target: { op: 3, node: 4 },
            payer: 'PAYER',
            maxPrice: 500n,
            expiresAt: 1_800_000_600_000,
            status: 'open',
            createdAt: NOW,
            updatedAt: NOW,
        }
        expect(await j.list('PAYER', app7)).toEqual([opened])
        now = NOW + MIN
        await journalReceipt(d, h, receipt)
        expect(await j.list('PAYER', app7)).toEqual([
            { ...opened, status: 'settle_pending', settle: settleArgsOf(receipt), updatedAt: NOW + MIN },
        ])
    })

    it('writes no receipt for a ticket it never journaled open', async () => {
        const j = memoryJournal()
        await journalReceipt(deps(j), handle(), receipt)
        expect(await j.list('PAYER', app7)).toEqual([])
    })

    it('writes nothing without a journal', async () => {
        const h = handle()
        await journalOpen(deps(undefined), h, ticket)
        await journalReceipt(deps(undefined), h, receipt)
    })

    // The USDC is already locked: the turn goes on, and the watchdog still
    // drives the ticket while this process runs.
    it('logs a failed or stalled open write instead of throwing', async () => {
        for (const put of [() => Promise.reject(new Error('disk gone')), () => new Promise<void>(() => {})]) {
            const j = { ...memoryJournal(), put }
            const d = { ...deps(j), journalTimeoutMs: 20 }
            await journalOpen(d, handle(), ticket)
            expect(d.logger.logged).toEqual([
                {
                    level: 'warn',
                    msg: 'ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline',
                    attrs: { ticket_id: 'TKT', err: expect.any(String) },
                },
            ])
        }
    })

    // The receipt row must still follow a lost open row, as Go keeps
    // h.journaled whatever journalPut says: a restart mid-settle can then
    // re-fire the settle.
    it('still journals the receipt after the open write failed', async () => {
        const j = memoryJournal()
        const put = j.put.bind(j)
        let first = true
        j.put = (rec) => {
            if (!first) return put(rec)
            first = false
            return Promise.reject(new Error('disk gone'))
        }
        const d = deps(j)
        const h = handle()
        await journalOpen(d, h, ticket)
        expect(await j.list('PAYER', app7)).toEqual([])
        await journalReceipt(d, h, receipt)
        expect(await j.list('PAYER', app7)).toMatchObject([{ ticketId: 'TKT', status: 'settle_pending', settle: settleArgsOf(receipt) }])
    })
})
