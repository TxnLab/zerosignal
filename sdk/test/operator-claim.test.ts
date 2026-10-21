/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What the payer does about an operator's settle claim that contradicts its
// receipt, porting go/zs operator_claim_test.go: the ack's reading of it, the
// refused protest's fallback, the amount the watchdog is handed, and the
// watchdog's refusal to lapse an over-claim. judgeClaim itself is pinned by
// testdata/ack_settle_vectors.json (ack.test.ts).

import { describe, expect, it } from 'vitest'

import { NoResolveFrozenError } from '../src/ack.js'
import type { SpendGuard } from '../src/config.js'
import { APPROVAL_ASSERT, ApprovalError } from '../src/escrow/revert.js'
import type { OpenHandle } from '../src/parts.js'
import { type ReceiptCheckDeps, checkTurnReceipt } from '../src/receipt-check.js'
import { type UsageReport, usageEvents } from '../src/responder.js'
import { type TicketProbe, Watchdog } from '../src/refund-watchdog.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import type { NodeRef } from '../src/types.js'
import { bodyHashOfBody } from '@txnlab/zs-proto/wire'
import { ALGO_FEES, TICKET_ID, VALID_GROUP, type Scripted, fixture, handleOf, recLogger } from './turn-fixtures.js'

type Fixture = Awaited<ReturnType<typeof fixture>>

function depsOf(over: Partial<ReceiptCheckDeps> = {}) {
    const resolved: string[] = []
    const recorded: [string, NodeRef, bigint][] = []
    const deps: ReceiptCheckDeps = {
        logger: recLogger(),
        feeUnit: ALGO_FEES,
        nodeExclusions: new NodeExclusionStore(),
        resolveRefund: (id) => resolved.push(id),
        recordReceipt: (id, node, amount) => recorded.push([id, node, amount]),
        ...over,
    }
    return { deps, resolved, recorded }
}

function run(deps: ReceiptCheckDeps, f: Fixture, handle: OpenHandle, o: { matching?: boolean; group?: string | null } = {}) {
    const computed = o.matching === false ? bodyHashOfBody(new TextEncoder().encode('other content')) : bodyHashOfBody(f.plaintext)
    return checkTurnReceipt(deps, {
        endpoint: '/v1/chat/completions',
        model: 'm',
        ticket: f.ticket,
        op: f.op,
        handle,
        receipt: f.receipt,
        computedHash: computed,
        plaintext: f.plaintext,
        settleGroup: o.group ?? null,
        hop: null,
    })
}

const NODE = { op: 7, node: 3 }

/**
 * A ticket other than the fixture receipt's: the payer holds a receipt the node
 * validly signed for another ticket.
 */
const ANOTHER_TICKET = 'YW5vdGhlci10aWNrZXQhIQ=='

type Override = { maxPrice?: number; sig?: string; ticketId?: string }

function applyOverride(f: Fixture, over: Override): void {
    if (over.maxPrice !== undefined) f.ticket.max_price = over.maxPrice
    if (over.sig !== undefined) f.receipt.sig = over.sig
    if (over.ticketId !== undefined) f.ticket.ticket_id = over.ticketId
}

const empty = { ticketId: TICKET_ID, kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 }

describe('the ack and the operator claim', () => {
    const ackErr = new Error('algod down')
    // A claim above the receipt bars the node, even when the node's group
    // failed to submit, the freeze did, or none was sent for want of
    // resolveFrozen, and the turn reports the freeze only when one went out; a
    // claim that contradicts the receipt without taking more is not acked, and
    // the turn reports no submit unless one failed; the payer's half on an
    // open box after a failed group is the payer's own ack. None stops the
    // watchdog.
    it.each([
        ['claim above the receipt', { txid: 'ACKTX', fee: 1000, claim: 'overclaims', payerSettle: true, frozen: true }, null,
            { settlement: { ...empty, kind: 'payer_ack', txId: 'ACKTX', feesMicroAlgos: 1000, networkFees: 1000, frozen: true } }, 'settle_claim_exceeds_receipt'],
        // The group's refusal came first, so it is the reason reported.
        ['rejected group, then a claim above the receipt', { txid: 'ACKTX', fee: 1000, groupRejected: true, claim: 'overclaims', payerSettle: true, frozen: true }, VALID_GROUP,
            { settlement: { ...empty, kind: 'payer_ack', txId: 'ACKTX', feesMicroAlgos: 1000, networkFees: 1000, frozen: true } }, 'settle_group_rejected'],
        // The freeze is the payer's own settle, not the group, so it neither
        // reports atomic nor stops the watchdog.
        ['failed group, then a claim above the receipt', { txid: 'FREEZETX', fee: 1000, claim: 'overclaims', payerSettle: true, frozen: true }, VALID_GROUP,
            { settlement: { ...empty, kind: 'payer_ack', txId: 'FREEZETX', feesMicroAlgos: 1000, networkFees: 1000, frozen: true } }, 'settle_claim_exceeds_receipt'],
        ['claim above the receipt, freeze failed', { claim: 'overclaims', payerSettle: true, err: ackErr }, null,
            { settlement: { ...empty, kind: 'payer_ack' }, err: ackErr }, 'settle_claim_exceeds_receipt'],
        // Nothing went out on an escrow without resolveFrozen, but the claim is
        // still the node's own contradiction.
        ['claim above the receipt, no resolveFrozen', { claim: 'overclaims' }, null, { settlement: empty }, 'settle_claim_exceeds_receipt'],
        ['failed group, then a claim above the receipt, no resolveFrozen', { claim: 'overclaims', err: ackErr }, VALID_GROUP,
            { settlement: { ...empty, kind: 'atomic' }, err: ackErr }, 'settle_claim_exceeds_receipt'],
        ['claim contradicting the receipt', { claim: 'contradicts' }, null, { settlement: empty }, undefined],
        ['failed group, then a claim contradicting the receipt', { claim: 'contradicts', err: ackErr }, VALID_GROUP,
            { settlement: { ...empty, kind: 'atomic' }, err: ackErr }, undefined],
        ['claim agreeing with the receipt', { txid: 'ACKTX', fee: 1000, claim: 'agrees', payerSettle: true }, null,
            { settlement: { ...empty, kind: 'payer_ack', txId: 'ACKTX', feesMicroAlgos: 1000, networkFees: 1000 } }, undefined],
        // The payer's half leaves a pending payer claim the node must still
        // match, so the watchdog keeps the ticket for refundInactive.
        ["failed group, then the payer's half on an open box", { txid: 'HALFTX', fee: 1000, claim: 'open', payerSettle: true }, VALID_GROUP,
            { settlement: { ...empty, kind: 'payer_ack', txId: 'HALFTX', feesMicroAlgos: 1000, networkFees: 1000 } }, undefined],
        ['failed group, then a failed half on an open box', { claim: 'open', payerSettle: true, err: ackErr }, VALID_GROUP,
            { settlement: { ...empty, kind: 'payer_ack' }, err: ackErr }, undefined],
    ] as [string, Scripted, string | null, object, string | undefined][])('%s', async (_name, script, group, want, exclusion) => {
        const f = await fixture()
        const { deps, resolved } = depsOf()
        const { submit, check } = await run(deps, f, handleOf(script), { group })
        const r = await submit!()
        expect(r).toEqual(want)
        expect(check.exclusion).toBe(exclusion)
        expect(check.excluded).toBe(exclusion !== undefined)
        expect(deps.nodeExclusions!.nodeExcluded(NODE)).toBe(exclusion !== undefined)
        expect(resolved).toEqual([])
    })

    // A failed ack over an over-claim is logged as a failed freeze only when
    // the payer's settle went out; when the node's group failed and nothing
    // followed it, the log says no freeze was sent.
    it.each([
        ['freeze failed', { claim: 'overclaims', payerSettle: true, err: ackErr }, 'the settle to freeze the ticket failed', 'no freeze was sent'],
        ['nothing sent', { claim: 'overclaims', err: ackErr }, 'no freeze was sent', 'the settle to freeze the ticket failed'],
    ] as [string, Scripted, string, string][])('logs whether the freeze went out: %s', async (_name, script, want, notWant) => {
        const f = await fixture()
        const logger = recLogger()
        const { deps } = depsOf({ logger })
        const { submit } = await run(deps, f, handleOf(script), { group: VALID_GROUP })
        expect((await submit!()).err).toBe(ackErr)
        const msgs = logger.logged.map((l) => l.msg)
        expect(msgs.some((m) => m.includes(want))).toBe(true)
        expect(msgs.some((m) => m.includes(notWant))).toBe(false)
    })
})

describe('a refused protest', () => {
    const refused = new Error('receiptDigest must match the pending claim')
    const freezeFailed = new Error('algod down')

    // It falls back to the receipt's settle only when the operator's claim
    // takes more than the receipt, which freezes the ticket as the protest
    // would have. Any other claim is left to lapse, and the protest's error
    // stands.
    it.each([
        ['claim above the receipt', { claim: 'overclaims', call: { txid: 'FREEZETX', payerFeeMicroalgos: 4000n } },
            { settlement: { ...empty, kind: 'protest', txId: 'FREEZETX', feesMicroAlgos: 4000, networkFees: 4000, frozen: true } }, true, true],
        ['claim above the receipt, freeze failed', { claim: 'overclaims', err: freezeFailed },
            { settlement: { ...empty, kind: 'protest' }, err: freezeFailed }, false, true],
        // No freeze went out, so the protest's own failure stands.
        ['claim above the receipt, no resolveFrozen', { claim: 'overclaims', err: new NoResolveFrozenError() },
            { settlement: { ...empty, kind: 'protest' }, err: refused }, false, true],
        ['claim below the receipt', { claim: 'contradicts' }, { settlement: { ...empty, kind: 'protest' }, err: refused }, false, false],
        ['claim matching the receipt', { claim: 'agrees' }, { settlement: { ...empty, kind: 'protest' }, err: refused }, false, false],
        ['no operator claim', { claim: 'none' }, { settlement: { ...empty, kind: 'protest' }, err: refused }, false, false],
        ['box unreadable', { claim: 'unreadable', err: new Error('read') }, { settlement: { ...empty, kind: 'protest' }, err: refused }, false, false],
    ] as [string, NonNullable<Scripted['freeze']>, object, boolean, boolean][])('%s', async (_name, freeze, want, resolvedIt, excluded) => {
        const f = await fixture()
        const { deps, resolved } = depsOf()
        const { submit, check } = await run(deps, f, handleOf({ err: refused, freeze }), { matching: false })
        expect(await submit!()).toEqual(want)
        expect(resolved).toEqual(resolvedIt ? [TICKET_ID] : [])
        expect(deps.nodeExclusions!.nodeExcluded(NODE)).toBe(excluded)
        // Named, so the turn's events report the bar as the ack path's do.
        expect([check.excluded, check.exclusion]).toEqual(excluded ? [true, 'settle_claim_exceeds_receipt'] : [false, undefined])
    })

    // Go's TestCheckReceipt_LateProtestTriesNoFreeze: the deadline that
    // refused the protest bars settle too, so the protest's error stands.
    it('tries no freeze after a protest refused for its deadline', async () => {
        const f = await fixture()
        const late = new Error('protest', { cause: new ApprovalError('protest', 1, APPROVAL_ASSERT.protestAfterDeadline, new Error('algod')) })
        let freezes = 0
        const handle = handleOf({ err: late })
        Object.assign(handle, {
            freezeOverclaim: async () => {
                freezes++
                return { claim: 'overclaims', call: { txid: 'FREEZETX', payerFeeMicroalgos: 4000n } }
            },
        })
        const { deps, resolved } = depsOf()
        const { submit } = await run(deps, f, handle, { matching: false })
        expect(await submit!()).toEqual({ settlement: { ...empty, kind: 'protest' }, err: late })
        expect(freezes).toBe(0)
        expect(resolved).toEqual([])
    })

    // A box that could not be read leaves the protest's failure standing, and
    // the log says why no freeze was tried.
    it('logs a claim it could not read', async () => {
        const f = await fixture()
        const { deps } = depsOf()
        const { submit } = await run(deps, f, handleOf({ err: refused, freeze: { claim: 'unreadable', err: new Error('read') } }), {
            matching: false,
        })
        await submit!()
        const failed = (deps.logger as ReturnType<typeof recLogger>).logged.find((l) => l.msg === 'protest failed')
        expect(failed?.attrs).toMatchObject({ claim_err: 'read', submit_err: refused.message })
    })

    it('has no fallback on a handle without one', async () => {
        const f = await fixture()
        const { deps } = depsOf()
        const { submit } = await run(deps, f, handleOf({ err: refused }), { matching: false })
        expect(await submit!()).toEqual({ settlement: { ...empty, kind: 'protest' }, err: refused })
    })

    it('is not needed after a protest that landed', async () => {
        const f = await fixture()
        const { deps } = depsOf()
        let freezes = 0
        const h = handleOf({ txid: 'PROTESTTX' })
        Object.assign(h, {
            freezeOverclaim: async () => {
                freezes++
                return { claim: 'overclaims' }
            },
        })
        await (await run(deps, f, h, { matching: false })).submit!()
        expect(freezes).toBe(0)
    })
})

// The watchdog holds a later operator claim against the amount the node
// signed. Only a receipt whose signature verified counts: a figure from an
// unverified one could be anything, and one set too high would let every
// over-claim through.
describe('the amount the watchdog is handed', () => {
    it.each([
        ['verified', {}, true, true],
        ['body hash mismatch', {}, false, true],
        ['amount above max price', { maxPrice: 49_999 }, true, true],
        ['bad signature', { sig: '' }, true, false],
        // Its figure is for that other ticket.
        ['receipt for another ticket', { ticketId: ANOTHER_TICKET }, false, false],
    ] as [string, Override, boolean, boolean][])('%s', async (_name, over, matching, pinned) => {
        const f = await fixture()
        applyOverride(f, over)
        const { deps, recorded } = depsOf()
        await run(deps, f, handleOf({}), { matching })
        expect(recorded).toEqual(pinned ? [[TICKET_ID, NODE, 50_000n]] : [])
    })
})

// The journal keeps the signed receipt too, so the reconciler, which outlives
// the watchdog's memory, holds an operator claim against the same figure: a
// verified receipt as the settle to re-fire, one that failed a check after its
// signature verified as signed on the open row, an unverified one not at all.
describe('the receipt the journal is handed', () => {
    it.each([
        ['verified', {}, true, 'receipt'],
        ['body hash mismatch', {}, false, 'signed'],
        ['amount above max price', { maxPrice: 49_999 }, true, 'signed'],
        ['bad signature', { sig: '' }, true, null],
        ['receipt for another ticket', { ticketId: ANOTHER_TICKET }, false, null],
    ] as [string, Override, boolean, string | null][])('%s', async (_name, over, matching, want) => {
        const f = await fixture()
        applyOverride(f, over)
        const writes: string[] = []
        const { deps } = depsOf({
            journalReceipt: () => void writes.push('receipt'),
            journalSigned: () => void writes.push('signed'),
        })
        await run(deps, f, handleOf({}), { matching })
        expect(writes).toEqual(want === null ? [] : [want])
    })
})

// Go's TestCheckReceipt_BarsANodeThatSignsAReceiptForAnotherTicket: a receipt
// the node validly signed for another ticket bars the node, as an over-claim
// does, and the turn reports why. Only a signature that verified shows the
// node wrote it, and a ticket id the payer holds in another spelling is the
// payer's fault, so neither bars anyone. Barred or not, the receipt stays a
// sig violation: released, with no submit and nothing pinned.
describe('a receipt for another ticket', () => {
    const forAnother = (f: Fixture) => void (f.ticket.ticket_id = ANOTHER_TICKET)
    it.each([
        ['receipt for another ticket', forAnother, true, true],
        // The body_hash would have driven a protest.
        ["receipt for another ticket over a body that doesn't match it", forAnother, false, true],
        ['bad signature', (f: Fixture) => void (f.receipt.sig = ''), true, false],
        ['bad signature on a receipt for another ticket', (f: Fixture) => {
            forAnother(f)
            f.receipt.sig = ''
        }, true, false],
        ['signing key of the wrong length', (f: Fixture) => {
            forAnother(f)
            f.op = { ...f.op, ticketSigningKey: f.op.ticketSigningKey.slice(0, 31) }
        }, true, false],
        // The fixture's id with non-zero padding bits: the same bytes, which the
        // receipt names in their canonical spelling.
        ["payer's ticket id not canonical", (f: Fixture) => void (f.ticket.ticket_id = 'dGlja2V0LXdhaXQtMDAwMB=='), true, false],
    ] as [string, (f: Fixture) => void, boolean, boolean][])('%s', async (_name, mutate, matching, barred) => {
        const f = await fixture()
        mutate(f)
        const calls: string[] = []
        const spendGuard: SpendGuard = {
            admit() {},
            reserve() {},
            settle: (id, charged) => calls.push(`settle ${id} ${charged}`),
            release: (id) => calls.push(`release ${id}`),
        }
        const { deps, recorded } = depsOf({ spendGuard })
        const { submit, check } = await run(deps, f, handleOf({}), { matching })
        expect(submit).toBeNull()
        expect(deps.nodeExclusions!.nodeExcluded(NODE)).toBe(barred)
        const report: UsageReport = {
            receipt: f.receipt,
            ticket: f.ticket,
            op: f.op,
            openFees: 0,
            settleFees: 0,
            algoUsdPrice: 0,
            feeUnit: ALGO_FEES,
            feeBps: 0,
            haveFee: false,
            check,
        }
        expect(usageEvents(report)).toEqual([
            { type: 'receipt.violated', violation: 'sig', protestTxId: '' },
            ...(barred ? [{ type: 'node.excluded', node: NODE, reason: 'receipt_names_other_ticket' }] : []),
        ])
        const logged = (deps.logger as ReturnType<typeof recLogger>).logged
        expect(logged.some((l) => l.msg === 'node excluded: it signed a receipt for another ticket')).toBe(barred)
        expect(calls).toEqual([`release ${f.ticket.ticket_id}`])
        expect(recorded).toEqual([])
    })

    // Without an exclusion store there is nothing to bar the node in, and the
    // turn reports no exclusion.
    it('reports no exclusion without an exclusion store', async () => {
        const f = await fixture()
        forAnother(f)
        const { deps } = depsOf({ nodeExclusions: undefined })
        const { check } = await run(deps, f, handleOf({}))
        expect([check.violation, check.excluded, check.exclusion]).toEqual(['sig', false, undefined])
    })
})

describe('Watchdog and an operator claim above the receipt', () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

    async function lapses(receipt: bigint | undefined, claim: bigint) {
        const log = recLogger()
        const rw = new Watchdog({ logger: log, remedy: 'recover it by hand' })
        rw.marginMs = 2
        rw.retryDelayMs = 5
        rw.lapseFallbackMs = 5
        let n = 0
        const probe = async (): Promise<TicketProbe> => ({ exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000, pendingAmount: claim })
        // Armed far enough out that the receipt is pinned before it fires.
        rw.arm('T', Date.now() + 20, probe, async () => {
            throw new Error('refundInactive on an operator claim')
        }, async () => {
            n++
            return 'TX'
        })
        if (receipt !== undefined) rw.recordReceipt('T', NODE, receipt)
        const deadline = Date.now() + 2000
        while (rw.watching('T') && Date.now() < deadline) await sleep(2)
        expect(rw.watching('T')).toBe(false)
        expect(rw.signedAmount('T')).toBeUndefined()
        return { n, log }
    }

    // The payer never pays the fee for a settleLapsed its receipt
    // contradicts. A claim at or below the receipt still lapses, and so does
    // any claim on a ticket this process saw no receipt for.
    it.each([
        ['claim above the receipt', 100n, 101n, 0],
        ['claim equal to the receipt', 100n, 100n, 1],
        ['claim below the receipt', 100n, 99n, 1],
        ['no receipt seen', undefined, 101n, 1],
    ] as const)('%s', async (_name, receipt, claim, want) => {
        const { n, log } = await lapses(receipt, claim)
        expect(n).toBe(want)
        if (want === 0) {
            expect(log.logged).toContainEqual({
                level: 'warn',
                msg: "refund watchdog: operator's settle claim exceeds the receipt it signed; not finalizing it with settleLapsed",
                attrs: { ticket_id: 'T', claimed_microusdc: 101, receipt_microusdc: 100, remedy: 'recover it by hand' },
            })
        }
    })

    it('pins nothing for an untracked ticket', () => {
        const rw = new Watchdog({ remedy: '' })
        rw.recordReceipt('T', NODE, 5n)
        expect(rw.signedAmount('T')).toBeUndefined()
    })

    // The claim it refuses to lapse bars the node that signed the receipt,
    // which the live ack may never have read. Go's
    // TestRefundWatchdog_BarsTheNodeOfAnOverclaim.
    it.each([
        ['claim above the receipt', 101n, [NODE]],
        ['claim equal to the receipt', 100n, []],
    ] as const)('bars the node of %s', async (_name, claim, want) => {
        const barred: unknown[] = []
        const rw = new Watchdog({ remedy: '', overclaimed: (_id, node) => void barred.push(node) })
        rw.marginMs = 2
        rw.lapseFallbackMs = 5
        const probe = async (): Promise<TicketProbe> => ({ exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000, pendingAmount: claim })
        rw.arm('T', Date.now() + 20, probe, async () => '', async () => 'TX')
        rw.recordReceipt('T', NODE, 100n)
        const deadline = Date.now() + 2000
        while (rw.watching('T') && Date.now() < deadline) await sleep(2)
        expect(barred).toEqual(want)
    })

    // A box that can't be read past the deadline is not lapsed blind while
    // the watchdog holds a receipt: the claim on it could be above the
    // receipt. With none, the lapse goes ahead. Go's
    // TestRefundWatchdog_LapsesNoUnreadBoxAgainstAReceipt.
    it.each([
        ['receipt recorded', true, 0],
        ['no receipt', false, 1],
    ] as const)('lapses no unread box against a receipt: %s', async (_name, withReceipt, want) => {
        const rw = new Watchdog({ remedy: '' })
        rw.marginMs = 2
        rw.retryDelayMs = 5
        rw.lapseFallbackMs = 5
        let probes = 0
        let lapsed = 0
        const probe = async (): Promise<TicketProbe> => {
            // The first read finds the operator claim; every one after it,
            // inside driveLapse, fails.
            if (++probes === 1) return { exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000, pendingAmount: 50n }
            throw new Error('algod down')
        }
        rw.arm('T', Date.now() + 20, probe, async () => {
            throw new Error('refundInactive on an operator claim')
        }, async () => {
            lapsed++
            return 'TX'
        })
        if (withReceipt) rw.recordReceipt('T', NODE, 100n)
        const deadline = Date.now() + 2000
        while (rw.watching('T') && Date.now() < deadline) await sleep(2)
        expect(rw.watching('T')).toBe(false)
        expect(lapsed).toBe(want)
        if (withReceipt) expect(probes).toBeGreaterThanOrEqual(1 + rw.attempts)
    })
})
