/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A buffered turn's answer and its receipt, porting go/zs settle_test.go,
// settle_after_response_test.go, lifecycle_events_test.go's usage report,
// the responder cases of emit_test.go, malicious_nodes_dispatch_test.go's
// group-rejection exclusion, and the receipt, spend and pre-envelope cases of
// go/zs/handler dispatch_test.go and spend_dispatch_test.go.

import { describe, expect, it, vi } from 'vitest'

import { type Ticket, type UsageReceipt, encodeReceiptHeader } from '@txnlab/zs-proto/ticket'
import {
    ENCRYPTED_CONTENT_TYPE,
    RECEIPT_HEADER,
    RESPONSE_KEY_HEADER,
    ResponseSealer,
    SEALED_HEADER_RECEIPT,
    SEALED_HEADER_SETTLE_GROUP,
    SETTLE_GROUP_HEADER,
    bodyHashOfBody,
    generateEphemeralIdentity,
} from '@txnlab/zs-proto/wire'

import { IDAffinity } from '../src/affinity.js'
import type { SpendGuard } from '../src/config.js'
import { NodeReply, type ZsError } from '../src/errors.js'
import { APPROVAL_ASSERT, ApprovalError } from '../src/escrow/revert.js'
import { resolveNetwork } from '../src/network.js'
import { type OpenHandle, ProtestReason, type Reserved, type SettleOutcome, memoryJournal } from '../src/parts.js'
import {
    DISPUTE_EXCERPT_CAP,
    type ReceiptCheckDeps,
    SettleSlot,
    type TurnCheck,
    checkTurnReceipt,
    protestReasonFor,
} from '../src/receipt-check.js'
import { goDecodeUTF8 } from '../src/gotext.js'
import {
    type ResponderDeps,
    type UsageReport,
    bufferedResponder,
    openAIErrorBody,
    truncateForLog,
    usageEvents,
} from '../src/responder.js'
import { MAX_NODE_RETRY_HINT_MS } from '../src/routing/verdict.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import type { SealedCall } from '../src/sealed.js'
import { Settles } from '../src/settles.js'
import { testOperator } from './fixtures.js'
import { ALGO_FEES, TICKET_ID, VALID_GROUP, fixture, handleOf, recLogger } from './turn-fixtures.js'

// Every response key the responder unwraps, kept so a test can check it was
// zeroed once the responder is done with it.
const unwrapped = vi.hoisted((): Uint8Array[] => [])
vi.mock('../src/seal.js', async (importOriginal) => {
    const seal = await importOriginal<typeof import('../src/seal.js')>()
    return {
        ...seal,
        openResponseKey: async (...args: Parameters<typeof seal.openResponseKey>) => {
            const k = await seal.openResponseKey(...args)
            unwrapped.push(k)
            return k
        },
    }
})

function depsOf(over: Partial<ReceiptCheckDeps> = {}) {
    const resolved: string[] = []
    const confirmed: [string, string][] = []
    const logger = recLogger()
    const deps: ReceiptCheckDeps = {
        logger,
        feeUnit: ALGO_FEES,
        resolveRefund: (id) => resolved.push(id),
        confirmSettled: (id, tx) => confirmed.push([id, tx]),
        ...over,
    }
    return { deps, resolved, confirmed, logger }
}

type Fixture = Awaited<ReturnType<typeof fixture>>

function check(
    deps: ReceiptCheckDeps,
    f: Fixture,
    handle: OpenHandle | null,
    o: { matching?: boolean; group?: string | null; slot?: SettleSlot } = {},
) {
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
        slot: o.slot,
    })
}

describe('checkTurnReceipt', () => {
    const ackErr = new Error('algod down')

    // Only a submit that ends the ticket on chain (a landed atomic group, a
    // protest that froze it) stops the refund watchdog, and only a landed
    // atomic group is watched until it confirms.
    it.each([
        ['atomic', { txid: 'GROUPTX' }, true, VALID_GROUP, { kind: 'atomic', txId: 'GROUPTX', feesMicroAlgos: 0, networkFees: 0 }, undefined, false, true],
        ['payer ack without a group', { txid: 'ACKTX', fee: 1000 }, true, null, { kind: 'payer_ack', txId: 'ACKTX', feesMicroAlgos: 1000, networkFees: 1000 }, undefined, true, false],
        ['payer ack after a rejected group', { txid: 'ACKTX', fee: 1000, groupRejected: true }, true, VALID_GROUP, { kind: 'payer_ack', txId: 'ACKTX', feesMicroAlgos: 1000, networkFees: 1000 }, undefined, true, false],
        // A failed ack reports what it sent and paid: a Solana ack that
        // landed and failed paid its fee.
        ['failed ack', { txid: 'SENTTX', fee: 7, err: ackErr }, true, VALID_GROUP, { kind: 'atomic', txId: 'SENTTX', feesMicroAlgos: 7, networkFees: 7 }, ackErr, true, false],
        // The payer signs the protest, so its fee is the payer's.
        ['protest', { txid: 'PROTESTTX', fee: 3000 }, false, null, { kind: 'protest', txId: 'PROTESTTX', feesMicroAlgos: 3000, networkFees: 3000, frozen: true }, undefined, false, false],
        ['failed protest', { txid: 'IGNORED', err: ackErr }, false, null, { kind: 'protest', txId: '', feesMicroAlgos: 0, networkFees: 0 }, ackErr, true, false],
    ] as const)('%s finishes the slot with the submit', async (_name, script, matching, group, want, wantErr, watched, confirms) => {
        const f = await fixture()
        const { deps, resolved, confirmed } = depsOf()
        const slot = new SettleSlot()
        const { submit, check: c } = await check(deps, f, handleOf(script), { matching, group, slot })
        expect(submit).not.toBeNull()
        expect(slot.expected).toBe(true)
        let finished = false
        void slot.done.then(() => (finished = true))
        await Promise.resolve()
        expect(finished).toBe(false)

        const r = await submit!()
        const settlement = { ticketId: TICKET_ID, ...want }
        expect(r).toEqual(wantErr === undefined ? { settlement } : { settlement, err: wantErr })
        expect(await slot.done).toBe(r)
        expect(c.settled).toEqual(settlement)
        expect(resolved.includes(TICKET_ID)).toBe(!watched)
        expect(confirmed).toEqual(confirms ? [[TICKET_ID, want.txId]] : [])
        // No exclusion store, so nothing was excluded, a refused group or not.
        expect(c.excluded).toBe(false)
    })

    // A protest refused for its deadline is the ticket lapsing on chain, not a
    // submit fault, so it logs apart from one. Either way the submit's error is
    // returned and the refund watchdog stays armed to drive the deadline path.
    it.each([
        // Wrapped, as the wallet wraps a submit failure.
        ['after the deadline', new Error('protest', { cause: new ApprovalError('protest', 1, APPROVAL_ASSERT.protestAfterDeadline, new Error('algod')) }), 'protest window closed; the ticket lapses on chain', 'protest failed'],
        ['any other revert', new Error('protest', { cause: new ApprovalError('protest', 1, APPROVAL_ASSERT.receiptDigestMismatch, new Error('algod')) }), 'protest failed', 'protest window closed; the ticket lapses on chain'],
        ['any other failure', ackErr, 'protest failed', 'protest window closed; the ticket lapses on chain'],
    ] as const)('a protest refused %s logs as such', async (_name, err, want, notWant) => {
        const f = await fixture()
        const { deps, resolved, logger } = depsOf()
        const r = await (await check(deps, f, handleOf({ err }), { matching: false })).submit!()
        expect(r.settlement.kind).toBe('protest')
        expect(r.err).toBe(err)
        const msgs = logger.logged.map((l) => l.msg)
        expect(msgs).toContain(want)
        expect(msgs).not.toContain(notWant)
        expect(resolved).toEqual([])
    })

    it('logs a submitted ack at info only when the payer paid a fee', async () => {
        const f = await fixture()
        for (const [fee, level] of [
            [1000, 'info'],
            [0, 'debug'],
        ] as const) {
            const { deps, logger } = depsOf()
            await (await check(deps, f, handleOf({ txid: 'A', fee }))).submit!()
            expect(logger.logged.find((l) => l.msg === 'ack-settle submitted')).toEqual({
                level,
                msg: 'ack-settle submitted',
                attrs: { ticket_id: TICKET_ID, txid: 'A', atomic: false, network_fee: fee },
            })
        }
    })

    it('gives the submit its own bounded signal, not the caller’s, and a whole budget', async () => {
        const f = await fixture()
        const h = handleOf({ txid: 'A' })
        const ack = h.ackSettle.bind(h)
        // A real ack takes a while; the bound mustn't end it.
        h.ackSettle = async (...a) => {
            await new Promise((r) => setTimeout(r, 20))
            return ack(...a)
        }
        await (await check(depsOf().deps, f, h)).submit!()
        const signal = h.acks[0]![2]!
        expect(signal).toBeInstanceOf(AbortSignal)
        expect(signal.aborted).toBe(false)
    })

    it('builds no submit, and leaves the slot unexpected, when there is nothing to submit', async () => {
        let f = await fixture()
        let slot = new SettleSlot()
        expect((await check(depsOf().deps, f, null, { slot })).submit).toBeNull()
        expect(slot.expected).toBe(false)

        // A bad signature is a violation the contract takes no protest for.
        f = await fixture()
        f.receipt.amount_charged++
        slot = new SettleSlot()
        const r = await check(depsOf().deps, f, handleOf(), { slot })
        expect(r.submit).toBeNull()
        expect(r.check.violation).toBe('sig')
        expect(slot.expected).toBe(false)

        // So is an amount over the ticket's ceiling.
        f = await fixture({ amount_charged: 100_001 })
        const over = await check(depsOf().deps, f, handleOf())
        expect(over.check.violation).toBe('amount')
        expect(over.submit).toBeNull()

        // And a receipt naming another ticket, even over a body that doesn't
        // match its hash.
        f = await fixture()
        f.ticket.ticket_id = 'YW5vdGhlci10aWNrZXQhIQ=='
        slot = new SettleSlot()
        const another = await check(depsOf().deps, f, handleOf(), { slot, matching: false })
        expect(another.check.violation).toBe('sig')
        expect(another.submit).toBeNull()
        expect(slot.expected).toBe(false)
    })

    it('finishes the slot when the submit throws, and rethrows', async () => {
        const f = await fixture()
        const slot = new SettleSlot()
        const boom = new Error('boom')
        const { submit } = await check(depsOf().deps, f, handleOf({ throws: boom }), { slot })
        await expect(submit!()).rejects.toBe(boom)
        expect(await slot.done).toEqual({ settlement: { ticketId: TICKET_ID, kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 }, err: boom })
    })

    it('settles the charge with the spend guard, or releases it on a violation', async () => {
        const calls: string[] = []
        const spendGuard: SpendGuard = {
            admit() {},
            reserve() {},
            settle: (id, charged) => calls.push(`settle ${id} ${charged}`),
            release: (id) => calls.push(`release ${id}`),
        }
        const f = await fixture()
        const journalReceipt = () => void calls.push('journal')
        await check(depsOf({ spendGuard, journalReceipt }).deps, f, handleOf())
        // Ahead of the journal, which the reconciler reads as counted.
        expect(calls).toEqual([`settle ${TICKET_ID} 50000`, 'journal'])

        // A receipt that failed its checks is never journaled: the reconciler
        // would re-fire its ack after a restart.
        calls.length = 0
        await check(depsOf({ spendGuard, journalReceipt }).deps, f, handleOf(), { matching: false })
        expect(calls).toEqual([`release ${TICKET_ID}`])
        const forged = await fixture()
        forged.receipt.amount_charged++
        calls.length = 0
        await check(depsOf({ spendGuard, journalReceipt }).deps, forged, handleOf())
        expect(calls).toEqual([`release ${TICKET_ID}`])
        // Without escrow there is nothing to journal.
        calls.length = 0
        await check(depsOf({ spendGuard, journalReceipt }).deps, f, null)
        expect(calls).toEqual([`settle ${TICKET_ID} 50000`])
    })

    // The charge is already decided; a guard that throws can't stop the
    // receipt being journaled, or a restart would lose the settle.
    it('journals the receipt when the spend guard throws', async () => {
        const calls: string[] = []
        const spendGuard: SpendGuard = {
            admit() {},
            reserve() {},
            settle() {
                throw new Error('guard bug')
            },
            release() {
                throw new Error('guard bug')
            },
        }
        const f = await fixture()
        const journalReceipt = () => void calls.push('journal')
        await check(depsOf({ spendGuard, journalReceipt }).deps, f, handleOf())
        expect(calls).toEqual(['journal'])
        await expect(check(depsOf({ spendGuard, journalReceipt }).deps, f, handleOf(), { matching: false })).resolves.toBeDefined()
    })

    it('logs each paying request with its usage and charge', async () => {
        const f = await fixture()
        const { deps, logger } = depsOf()
        await check(deps, f, handleOf())
        expect(logger.logged).toContainEqual({
            level: 'info',
            msg: 'zs request paid',
            attrs: {
                endpoint: '/v1/chat/completions',
                model: 'm',
                operator_id: 7,
                node_id: 3,
                ticket_id: TICKET_ID,
                actual_input_count: 10,
                cached_input_count: 0,
                actual_output_count: 5,
                amount_microusdc: 50_000,
                amount_usd: '$0.050000',
            },
        })
    })

    it('journals the receipt before returning the submit, and acks through a journal that fails', async () => {
        const f = await fixture()
        const order: string[] = []
        let release!: () => void
        const gate = new Promise<void>((r) => (release = r))
        const h = handleOf({ txid: 'A' })
        const ack = h.ackSettle.bind(h)
        h.ackSettle = async (...a) => {
            order.push('ack')
            return ack(...a)
        }
        let returned = false
        const checking = check(
            depsOf({
                journalReceipt: async (handle, receipt) => {
                    expect([handle, receipt]).toEqual([h, f.receipt])
                    order.push('journal started')
                    await gate
                    order.push('journal done')
                },
            }).deps,
            f,
            h,
        ).then((r) => {
            returned = true
            return r
        })
        await new Promise((r) => setTimeout(r, 5))
        expect(order).toEqual(['journal started'])
        expect(returned).toBe(false)
        release()
        const { submit } = await checking
        expect(order).toEqual(['journal started', 'journal done'])
        await submit!()
        expect(order).toEqual(['journal started', 'journal done', 'ack'])

        const failing = depsOf({
            journalReceipt: async () => {
                throw new Error('disk full')
            },
        })
        const h2 = handleOf({ txid: 'B' })
        expect((await (await check(failing.deps, f, h2)).submit!()).settlement.txId).toBe('B')
        expect(failing.logger.logged).toContainEqual({
            level: 'warn',
            msg: 'ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline',
            attrs: { ticket_id: TICKET_ID, err: 'disk full' },
        })
    })

    it('gives up on a journal write that hangs, and acks anyway', async () => {
        const f = await fixture()
        const { deps, logger } = depsOf({ journalReceipt: () => new Promise<void>(() => {}), journalTimeoutMs: 20 })
        const h = handleOf({ txid: 'C' })
        expect((await (await check(deps, f, h)).submit!()).settlement.txId).toBe('C')
        expect(logger.logged).toContainEqual({
            level: 'warn',
            msg: 'ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline',
            attrs: { ticket_id: TICKET_ID, err: 'journal call timed out after 20ms' },
        })
    })

    it('excludes a node whose settle group is refused, and only that one', async () => {
        const f = await fixture()
        let nodeExclusions = new NodeExclusionStore()
        let r = await check(depsOf({ nodeExclusions }).deps, f, handleOf({ txid: 'A', groupRejected: true }), { group: VALID_GROUP })
        await r.submit!()
        expect(r.check.excluded).toBe(true)
        expect(nodeExclusions.nodeExcluded({ op: 7, node: 3 })).toBe(true)

        // A forged group is proven even when the standalone fallback fails too.
        nodeExclusions = new NodeExclusionStore()
        r = await check(depsOf({ nodeExclusions }).deps, f, handleOf({ groupRejected: true, err: new Error('down') }), { group: VALID_GROUP })
        expect((await r.submit!()).err).toBeDefined()
        expect(r.check.excluded).toBe(true)
        expect(nodeExclusions.nodeExcluded({ op: 7, node: 3 })).toBe(true)

        nodeExclusions = new NodeExclusionStore()
        r = await check(depsOf({ nodeExclusions }).deps, f, handleOf({ txid: 'A' }), { group: VALID_GROUP })
        await r.submit!()
        expect(r.check.excluded).toBe(false)
        expect(nodeExclusions.nodeExcluded({ op: 7, node: 3 })).toBe(false)
    })

    it('passes the node’s group to the ack, and watches only a landed atomic settle', async () => {
        const f = await fixture()
        let d = depsOf()
        let h = handleOf({ txid: 'G' })
        await (await check(d.deps, f, h, { group: VALID_GROUP })).submit!()
        expect(h.acks[0]![1]).toBe(VALID_GROUP)
        expect(d.confirmed).toEqual([[TICKET_ID, 'G']])

        for (const [script, group] of [
            [{ txid: 'A' }, null],
            [{ txid: 'A', groupRejected: true }, VALID_GROUP],
            [{ err: new Error('down') }, VALID_GROUP],
        ] as const) {
            d = depsOf()
            h = handleOf(script)
            await (await check(d.deps, f, h, { group })).submit!()
            expect(h.acks[0]![1]).toBe(group)
            expect(d.confirmed).toEqual([])
        }
    })

    it('protests a body that doesn’t match its hash with a capped excerpt', async () => {
        const big = new Uint8Array(DISPUTE_EXCERPT_CAP + 50).fill(97)
        const f = await fixture({}, big)
        const h = handleOf({ txid: 'P' })
        await (await check(depsOf().deps, f, h, { matching: false })).submit!()
        const [receipt, excerpt, reason, signal] = h.protests[0]!
        expect(receipt).toBe(f.receipt)
        expect(excerpt).toEqual(big.slice(0, DISPUTE_EXCERPT_CAP))
        expect(reason).toBe(ProtestReason.bodyHash)
        // Bounded like the ack, so a wedged algod can't hold it.
        expect(signal).toBeInstanceOf(AbortSignal)
        expect(signal!.aborted).toBe(false)
        expect(h.acks).toEqual([])
    })

    it('maps every violation to its protest reason', () => {
        expect(protestReasonFor('body_hash')).toBe(ProtestReason.bodyHash)
        expect(protestReasonFor('sig')).toBe(ProtestReason.receiptSig)
        expect(protestReasonFor('amount')).toBe(ProtestReason.amount)
        expect(protestReasonFor('')).toBe(ProtestReason.unspecified)
    })
})

describe('usageEvents', () => {
    const op = testOperator({ id: 7, nodeId: 2, ownerAddr: 'OWNER' })
    const report = (check: Partial<TurnCheck>): UsageReport => ({
        receipt: { ticket_id: 'tid' } as UsageReceipt,
        ticket: { ticket_id: 'T', max_price: 9 } as Ticket,
        op,
        openFees: 3,
        settleFees: 5,
        algoUsdPrice: 0.25,
        feeUnit: { currency: 'ALGO', decimals: 6 },
        feeBps: 0,
        haveFee: false,
        check: { violation: '', settled: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 }, excluded: false, ...check },
    })
    const types = (u: UsageReport) => usageEvents(u).map((e) => (e.type === 'receipt.verified' ? { type: e.type } : e))

    it('reports the verified receipt with the fee snapshot as taken', () => {
        const u = report({})
        expect(usageEvents(u)).toEqual([
            {
                type: 'receipt.verified',
                receipt: u.receipt,
                ticket: u.ticket,
                target: { op: 7, node: 2 },
                ownerAddr: 'OWNER',
                openFeesMicroAlgos: 3,
                settleFeesMicroAlgos: 5,
                algoUsd: 0.25,
                feeBps: 0,
                feeBpsKnown: false,
                openNetworkFees: 3,
                settleNetworkFees: 5,
                nativeUsd: 0.25,
                feeUnit: { currency: 'ALGO', decimals: 6 },
            },
        ])
        expect(usageEvents({ ...u, feeBps: 150, haveFee: true })[0]).toMatchObject({ feeBps: 150, feeBpsKnown: true })
    })

    it('leaves the names that say ALGO at 0 when the fees are another coin', () => {
        const u = { ...report({}), feeUnit: { currency: 'SOL', decimals: 9 } }
        expect(usageEvents(u)[0]).toMatchObject({
            openFeesMicroAlgos: 0,
            settleFeesMicroAlgos: 0,
            algoUsd: 0,
            openNetworkFees: 3,
            settleNetworkFees: 5,
            // The reserve's rate is ALGO's.
            nativeUsd: 0,
            feeUnit: { currency: 'SOL', decimals: 9 },
        })
    })

    it.each([
        ['verified, nothing submitted', {}, [{ type: 'receipt.verified' }]],
        ['verified, the submit failed', { settled: { ticketId: 'T', kind: 'atomic', txId: '', feesMicroAlgos: 0, networkFees: 0 } }, [{ type: 'receipt.verified' }]],
        [
            'verified, settled atomically',
            { settled: { ticketId: 'T', kind: 'atomic', txId: 'TX', feesMicroAlgos: 0, networkFees: 0 } },
            [{ type: 'receipt.verified' }, { type: 'settle.submitted', ticketId: 'T', txId: 'TX', feesMicroAlgos: 0, atomic: true, networkFees: 0 }],
        ],
        [
            'verified, a forged group, then a payer ack',
            { excluded: true, settled: { ticketId: 'T', kind: 'payer_ack', txId: 'ACK', feesMicroAlgos: 1000, networkFees: 1000 } },
            [
                { type: 'receipt.verified' },
                { type: 'node.excluded', node: { op: 7, node: 2 }, reason: 'settle_group_rejected' },
                { type: 'settle.submitted', ticketId: 'T', txId: 'ACK', feesMicroAlgos: 1000, atomic: false, networkFees: 1000 },
            ],
        ],
        [
            'verified, a claim above the receipt, then the freezing ack',
            {
                excluded: true,
                exclusion: 'settle_claim_exceeds_receipt',
                settled: { ticketId: 'T', kind: 'payer_ack', txId: 'ACK', feesMicroAlgos: 1000, networkFees: 1000, frozen: true },
            },
            [
                { type: 'receipt.verified' },
                { type: 'node.excluded', node: { op: 7, node: 2 }, reason: 'settle_claim_exceeds_receipt' },
                { type: 'settle.submitted', ticketId: 'T', txId: 'ACK', feesMicroAlgos: 1000, atomic: false, networkFees: 1000, frozen: true },
            ],
        ],
        [
            'body_hash, protested',
            { violation: 'body_hash', settled: { ticketId: 'T', kind: 'protest', txId: 'PROTEST', feesMicroAlgos: 0, networkFees: 0, frozen: true } },
            [{ type: 'receipt.violated', violation: 'body_hash', protestTxId: 'PROTEST' }],
        ],
        [
            'body_hash, protest refused, then the freeze over a claim above the receipt',
            {
                violation: 'body_hash',
                excluded: true,
                exclusion: 'settle_claim_exceeds_receipt',
                settled: { ticketId: 'T', kind: 'protest', txId: 'FREEZE', feesMicroAlgos: 0, networkFees: 0, frozen: true },
            },
            [
                { type: 'receipt.violated', violation: 'body_hash', protestTxId: 'FREEZE' },
                { type: 'node.excluded', node: { op: 7, node: 2 }, reason: 'settle_claim_exceeds_receipt' },
            ],
        ],
        ['body_hash, protest not yet run', { violation: 'body_hash' }, [{ type: 'receipt.violated', violation: 'body_hash', protestTxId: '' }]],
        ['sig', { violation: 'sig' }, [{ type: 'receipt.violated', violation: 'sig', protestTxId: '' }]],
    ] as const)('%s', (_name, c, want) => {
        expect(types(report(c as Partial<TurnCheck>))).toEqual(want)
    })
})

describe('Settles', () => {
    const quick = { confirmTimeoutMs: 300, confirmPollMs: 5 }

    // An atomic settle is seen confirmed before wait resolves, and only then
    // does the journal row go. A ticket that may still be open keeps its row.
    it.each([
        ['confirmed on the third look', ['pending', 'pending', 'landed'], false, false, 3],
        ['failed lookups, then confirmed', [new Error('algod down'), 'landed'], false, false, 2],
        ['never confirmed', ['pending'], false, true, -1],
        ['lookups keep failing', [new Error('algod down')], false, true, -1],
        ['dropped from the pool', ['pending', 'dropped'], false, true, 2],
        // No journal, no row to drop: nothing to wait on algod for.
        ['no journal', ['landed'], true, false, 0],
    ] as const)('%s', async (_name, outcomes, noJournal, wantRow, wantLooks) => {
        const journal = memoryJournal()
        await journal.put({ ticketId: TICKET_ID, payer: 'P', escrowAppId: 1n } as never)
        const settles = new Settles({ logger: recLogger(), journal: noJournal ? undefined : journal, ...quick })
        const h = handleOf({ txid: 'G', outcomes: [...outcomes] })
        settles.confirmSettled(TICKET_ID, 'G', h)
        await settles.wait(AbortSignal.timeout(5000))
        const has = (await journal.list('P', resolveNetwork({ network: 'localnet', escrowAppId: 1n }))).length > 0
        expect(has).toBe(noJournal ? true : wantRow)
        if (wantLooks === -1) {
            expect(h.looks.length).toBeGreaterThanOrEqual(2)
            expect(h.looks.length).toBeLessThanOrEqual(quick.confirmTimeoutMs / quick.confirmPollMs + 2)
        } else {
            expect(h.looks).toHaveLength(wantLooks)
        }
        for (const tx of h.looks) expect(tx).toBe('G')
    })

    it('gives up on a journal delete that hangs, ending the watch', async () => {
        const logger = recLogger()
        const journal = { ...memoryJournal(), delete: () => new Promise<void>(() => {}) }
        const settles = new Settles({ logger, journal, ...quick, journalTimeoutMs: 20 })
        settles.confirmSettled(TICKET_ID, 'G', handleOf({ outcomes: ['landed'] }))
        await settles.wait(AbortSignal.timeout(2000))
        expect(logger.logged).toContainEqual({
            level: 'warn',
            msg: 'ticket journal delete failed',
            attrs: { ticket_id: TICKET_ID, err: 'journal call timed out after 20ms' },
        })
    })

    it('watches nothing without a lookup or a txid', async () => {
        const journal = memoryJournal()
        const settles = new Settles({ logger: recLogger(), journal, ...quick })
        settles.confirmSettled(TICKET_ID, 'G', handleOf({ txid: 'G' }))
        const h = handleOf({ outcomes: ['landed'] })
        settles.confirmSettled(TICKET_ID, '', h)
        await settles.wait()
        expect(h.looks).toEqual([])
    })

    it('ends a watch when the Client closes, keeping the row', async () => {
        const journal = memoryJournal()
        await journal.put({ ticketId: TICKET_ID, payer: 'P', escrowAppId: 1n } as never)
        const life = new AbortController()
        const settles = new Settles({ logger: recLogger(), journal, life: life.signal, confirmTimeoutMs: 60_000, confirmPollMs: 5 })
        settles.confirmSettled(TICKET_ID, 'G', handleOf({ outcomes: [] }))
        life.abort()
        await settles.wait(AbortSignal.timeout(5000))
        expect(await journal.list('P', resolveNetwork({ network: 'localnet', escrowAppId: 1n }))).toHaveLength(1)
    })

    it('ends a lookup in flight when the Client closes', async () => {
        const life = new AbortController()
        const settles = new Settles({ logger: recLogger(), journal: memoryJournal(), life: life.signal, confirmTimeoutMs: 60_000, confirmPollMs: 5 })
        let looking = false
        const h = Object.assign(handleOf({ txid: 'G' }), {
            settleOutcome: (_tx: string, signal?: AbortSignal) =>
                new Promise<SettleOutcome>((_, reject) => {
                    looking = true
                    signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
                }),
        })
        settles.confirmSettled(TICKET_ID, 'G', h)
        await new Promise((r) => setTimeout(r, 5))
        expect(looking).toBe(true)
        life.abort()
        await settles.wait(AbortSignal.timeout(500))
    })

    it('names a confirmation apart from a submit when it can’t wait them out', async () => {
        const settles = new Settles({ logger: recLogger(), journal: memoryJournal(), confirmTimeoutMs: 1000, confirmPollMs: 5 })
        settles.confirmSettled(TICKET_ID, 'G', handleOf({ outcomes: [] }))
        const err = await settles.wait(AbortSignal.timeout(20)).then(
            () => null,
            (e: unknown) => e as Error,
        )
        expect(err?.message).toMatch(new RegExp(`not yet seen to land, left journaled: ${TICKET_ID}$`))
        expect(err?.message).not.toContain('still settling')
        await settles.wait()

        let release!: () => void
        const blocked = new Promise<void>((r) => (release = r))
        settles.afterResponse('T2', async () => {
            await blocked
            return { settlement: { ticketId: 'T2', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 } }
        })
        await expect(settles.wait(AbortSignal.timeout(20))).rejects.toThrow(/; tickets still settling: T2$/)
        release()
        await settles.wait()
    })

    it('waits for work that starts while it waits, and logs a submit that throws', async () => {
        const logger = recLogger()
        const settles = new Settles({ logger })
        await settles.wait()
        let release!: () => void
        const blocked = new Promise<void>((r) => (release = r))
        settles.afterResponse('A', async () => {
            settles.afterResponse('B', async () => {
                await blocked
                throw new Error('boom')
            })
            return { settlement: { ticketId: 'A', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 } }
        })
        let waited = false
        const w = settles.wait().then(() => (waited = true))
        await new Promise((r) => setTimeout(r, 5))
        expect(waited).toBe(false)
        release()
        await w
        expect(logger.logged).toContainEqual({ level: 'error', msg: 'escrow settle submit failed', attrs: { ticket_id: 'B', err: 'boom' } })
        // A turn with nothing to submit runs nothing.
        settles.afterResponse('C', null)
        await settles.wait(AbortSignal.abort())
        expect(logger.logged.filter((l) => l.attrs?.ticket_id === 'C')).toEqual([])
    })
})

describe('bufferedResponder', () => {
    async function setup(o: { endpoint?: string; feeRate?: number | null } = {}) {
        const f = await fixture({}, new TextEncoder().encode('{"choices":[{"message":{"content":"hi","tool_calls":[{"id":"call_1"}]}}]}'))
        const identity = await generateEphemeralIdentity()
        const txId = 'APPCALL'
        const sealer = await ResponseSealer.create({ replyTo: identity.recipient, txID: txId, ticketID: TICKET_ID, key: f.responseKey })
        const handle = handleOf({ txid: 'ACK' })
        const reserved = { ticket: f.ticket, identity, responseKey: f.responseKey, algoUsdPrice: 0.2, sealRecipient: '', presignedOpenTxn: '' } as unknown as Reserved
        const call: SealedCall = {
            endpoint: (o.endpoint ?? '/v1/chat/completions') as SealedCall['endpoint'],
            model: 'm',
            op: f.op,
            reserved,
            handle,
            txId,
            hop: null,
        }
        const after: [string, unknown][] = []
        const logger = recLogger()
        const toolAffinity = new IDAffinity(16, 60_000)
        const responseAffinity = new IDAffinity(16, 60_000)
        const deps: ResponderDeps = {
            logger,
            feeUnit: ALGO_FEES,
            toolAffinity,
            responseAffinity,
            feeRate: () => (o.feeRate === undefined ? 150 : o.feeRate),
            afterResponse: (id, submit) => after.push([id, submit]),
        }
        const em = new Recorder()
        return { f, sealer, handle, call, deps, after, logger, em, toolAffinity, responseAffinity }
    }

    type Setup = Awaited<ReturnType<typeof setup>>

    function sealedResponse(s: Setup, o: { receipt?: string | null; group?: string; status?: number; plaintext?: Uint8Array } = {}) {
        const headers = new Headers({
            'Content-Type': ENCRYPTED_CONTENT_TYPE,
            [RESPONSE_KEY_HEADER]: s.sealer.wrappedKeyHeader(),
            'X-Request-Id': 'req-1',
        })
        const receipt = o.receipt === undefined ? encodeReceiptHeader(s.f.receipt) : o.receipt
        if (receipt !== null) headers.set(RECEIPT_HEADER, s.sealer.sealHeader(SEALED_HEADER_RECEIPT, new TextEncoder().encode(receipt)))
        if (o.group !== undefined) headers.set(SETTLE_GROUP_HEADER, s.sealer.sealHeader(SEALED_HEADER_SETTLE_GROUP, new TextEncoder().encode(o.group)))
        const body = s.sealer.sealBody(o.plaintext ?? s.f.plaintext)
        return { resp: new Response(null, { status: o.status ?? 200, headers }), body }
    }

    it('replies with the opened body and usage, then hands over the submit', async () => {
        const s = await setup()
        const order: string[] = []
        const reply = s.em.reply.bind(s.em)
        s.em.reply = (...a) => {
            order.push('reply')
            reply(...a)
        }
        const afterResponse = s.deps.afterResponse
        s.deps.afterResponse = (...a) => {
            order.push('afterResponse')
            afterResponse(...a)
        }
        const { resp, body } = sealedResponse(s, { group: VALID_GROUP })
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(order).toEqual(['reply', 'afterResponse'])
        expect(s.em.failed).toBeUndefined()
        const [status, header, replied, usage] = s.em.replies[0]!
        expect(status).toBe(200)
        expect(header).toBe(resp.headers)
        expect(replied).toEqual(s.f.plaintext)
        expect(usage).toMatchObject({
            receipt: s.f.receipt,
            ticket: s.f.ticket,
            op: s.f.op,
            openFees: 2000,
            settleFees: 0,
            algoUsdPrice: 0.2,
            feeBps: 150,
            haveFee: true,
            check: { violation: '', excluded: false },
        })
        // The submit runs only after the reply, and with the node's group.
        expect(s.handle.acks).toEqual([])
        expect(s.after).toHaveLength(1)
        expect(s.after[0]![0]).toBe(TICKET_ID)
        const submit = s.after[0]![1] as () => Promise<unknown>
        await submit()
        expect(s.handle.acks[0]![1]).toBe(VALID_GROUP)
    })

    it('reports usage in the unit the deps name', async () => {
        const s = await setup()
        const sol = { currency: 'SOL', decimals: 9 }
        s.deps.feeUnit = sol
        const { resp, body } = sealedResponse(s, { group: VALID_GROUP })
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(s.em.replies[0]![3]).toMatchObject({ feeUnit: sol, openFees: 2000 })
    })

    it('hands the caller its response while the settle submit is held', async () => {
        const s = await setup()
        let release!: () => void
        const held = new Promise<void>((r) => (release = r))
        const ack = s.handle.ackSettle.bind(s.handle)
        s.handle.ackSettle = async (...a) => {
            await held
            return ack(...a)
        }
        const settles = new Settles({ logger: s.logger })
        s.deps.afterResponse = (id, submit) => settles.afterResponse(id, submit)
        const slot = new SettleSlot()
        const { resp, body } = sealedResponse(s)
        await bufferedResponder(s.deps, s.call, slot)(s.em, resp, body)
        expect(s.em.replies).toHaveLength(1)
        let waited = false
        const w = settles.wait().then(() => (waited = true))
        await new Promise((r) => setTimeout(r, 5))
        expect(waited).toBe(false)
        release()
        await w
        expect((await slot.done).settlement).toEqual({ ticketId: TICKET_ID, kind: 'payer_ack', txId: 'ACK', feesMicroAlgos: 0, networkFees: 0 })
    })

    // Go unmarshals a null body as an empty response: no id, and a reply.
    it('replies to a null /v1/responses body', async () => {
        const s = await setup({ endpoint: '/v1/responses' })
        const plaintext = new TextEncoder().encode('null')
        const f2 = await fixture({}, plaintext)
        s.f.receipt = f2.receipt
        s.f.op.ticketSigningKey = f2.op.ticketSigningKey
        const { resp, body } = sealedResponse(s, { plaintext })
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(s.em.replies).toHaveLength(1)
        expect(s.em.replies[0]![3]!.check.violation).toBe('')
    })

    it('hands over the submit even when the reply fails', async () => {
        const s = await setup()
        const boom = new Error('reply failed')
        s.em.reply = () => {
            throw boom
        }
        const { resp, body } = sealedResponse(s)
        await expect(bufferedResponder(s.deps, s.call)(s.em, resp, body)).rejects.toBe(boom)
        expect(s.after).toHaveLength(1)
        expect(s.after[0]![1]).toBeTypeOf('function')
    })

    it('replies only once the receipt is journaled', async () => {
        const s = await setup()
        let release!: () => void
        const gate = new Promise<void>((r) => (release = r))
        s.deps.journalReceipt = () => gate
        const { resp, body } = sealedResponse(s)
        const responding = bufferedResponder(s.deps, s.call)(s.em, resp, body)
        await new Promise((r) => setTimeout(r, 5))
        expect(s.em.replies).toEqual([])
        release()
        await responding
        expect(s.em.replies).toHaveLength(1)
    })

    it('reports an unknown fee rate as unknown', async () => {
        const s = await setup({ feeRate: null })
        const { resp, body } = sealedResponse(s)
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(s.em.replies[0]![3]).toMatchObject({ feeBps: 0, haveFee: false })
    })

    it('records tool-call ids for affinity, and a response id only on /v1/responses', async () => {
        let s = await setup()
        let r = sealedResponse(s)
        await bufferedResponder(s.deps, s.call)(s.em, r.resp, r.body)
        expect(s.toolAffinity.lookup('call_1')).toEqual({ op: 7, node: 3 })

        for (const endpoint of ['/v1/chat/completions', '/v1/responses']) {
            s = await setup({ endpoint })
            const plaintext = new TextEncoder().encode('{"id":"resp_9","object":"response","output":[]}')
            const f2 = await fixture({}, plaintext)
            s.f.receipt = f2.receipt
            s.f.op.ticketSigningKey = f2.op.ticketSigningKey
            r = sealedResponse(s, { plaintext })
            await bufferedResponder(s.deps, s.call)(s.em, r.resp, r.body)
            expect(s.responseAffinity.lookup('resp_9')).toEqual(endpoint === '/v1/responses' ? { op: 7, node: 3 } : undefined)
        }
    })

    it('tolerates a missing, malformed or unopenable receipt, replying without usage', async () => {
        for (const receipt of [null, 'not-a-receipt']) {
            const s = await setup()
            const { resp, body } = sealedResponse(s, { receipt })
            await bufferedResponder(s.deps, s.call)(s.em, resp, body)
            expect(s.em.replies[0]![3]).toBeNull()
            expect(s.after).toEqual([[TICKET_ID, null]])
        }
        // Sealed under another key: it reads as absent.
        const s = await setup()
        const { resp, body } = sealedResponse(s, { receipt: null })
        resp.headers.set(RECEIPT_HEADER, 'AAAA')
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(s.em.replies[0]![3]).toBeNull()
        expect(s.logger.logged.map((l) => l.msg)).toContain('sealed response metadata failed to open')
    })

    it('acks standalone when the node’s settle group doesn’t decode', async () => {
        const s = await setup()
        const { resp, body } = sealedResponse(s, { group: 'bm90IGEgZ3JvdXA=' })
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        await (s.after[0]![1] as () => Promise<unknown>)()
        expect(s.handle.acks[0]![1]).toBeNull()
        expect(s.logger.logged.map((l) => l.msg)).toContain('settle-group header malformed; falling back to standalone ack')
    })

    // On Solana the header is the ticket's open_seq, in its one spelling.
    it.each([
        ['an open_seq', '7', '7'],
        ['an open_seq in another spelling', '07', null],
        ['a group', 'bm90IGEgZ3JvdXA=', null],
    ] as const)('on Solana, hands %s to the ack as the header reads', async (_, group, want) => {
        const s = await setup()
        s.deps.rail = 'solana'
        const { resp, body } = sealedResponse(s, { group })
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        await (s.after[0]![1] as () => Promise<unknown>)()
        expect(s.handle.acks[0]![1]).toBe(want)
    })

    it('reports a receipt that fails its checks, without charging it', async () => {
        const s = await setup()
        const released: string[] = []
        s.deps.spendGuard = { admit() {}, reserve() {}, settle() {}, release: (id) => released.push(id) }
        s.f.receipt.amount_charged++
        const { resp, body } = sealedResponse(s)
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(s.em.replies[0]![3]!.check.violation).toBe('sig')
        expect(released).toEqual([TICKET_ID])
        expect(s.after).toEqual([[TICKET_ID, null]])
    })

    it('refuses a success the node didn’t seal, and a key with an unsealed body', async () => {
        let s = await setup()
        await bufferedResponder(s.deps, s.call)(s.em, new Response(null, { status: 200 }), new TextEncoder().encode('{"ok":1}'))
        expect(s.em.failed).toMatchObject({
            code: 'operator_unsealed_response',
            kind: 'operator_fault',
            message: 'operator returned a response without sealing it',
        })
        expect(s.after).toEqual([])

        s = await setup()
        const resp = new Response(null, { status: 200, headers: { [RESPONSE_KEY_HEADER]: s.sealer.wrappedKeyHeader(), 'Content-Type': 'application/json' } })
        await bufferedResponder(s.deps, s.call)(s.em, resp, new Uint8Array())
        expect(s.em.failed).toMatchObject({
            code: 'operator_inconsistent_response',
            kind: 'operator_fault',
            message: 'operator returned a response key but did not seal the body',
        })
    })

    it('throws, for the forwarder to report, on a key the ticket didn’t commit to or a body that won’t open', async () => {
        let s = await setup()
        const other = await ResponseSealer.create({ replyTo: (s.call.reserved as Reserved).identity.recipient, txID: 'APPCALL', ticketID: TICKET_ID })
        const resp = new Response(null, { status: 200, headers: { [RESPONSE_KEY_HEADER]: other.wrappedKeyHeader(), 'Content-Type': ENCRYPTED_CONTENT_TYPE } })
        await expect(bufferedResponder(s.deps, s.call)(s.em, resp, other.sealBody(s.f.plaintext))).rejects.toThrow(/commit_k/)
        expect(s.em.replies).toEqual([])

        s = await setup()
        const garbled = new Response(null, { status: 200, headers: { [RESPONSE_KEY_HEADER]: 'AAAA', 'Content-Type': ENCRYPTED_CONTENT_TYPE } })
        await expect(bufferedResponder(s.deps, s.call)(s.em, garbled, new Uint8Array())).rejects.toThrow(/^unwrap response key: /)

        s = await setup()
        const r = sealedResponse(s)
        await expect(bufferedResponder(s.deps, s.call)(s.em, r.resp, new TextEncoder().encode('{"nonce":"","ciphertext":""}'))).rejects.toThrow(/^decrypt body: /)
    })

    it('zeroes the response key it unwrapped, whether the body opens or not', async () => {
        unwrapped.length = 0
        let s = await setup()
        const ok = sealedResponse(s)
        await bufferedResponder(s.deps, s.call)(s.em, ok.resp, ok.body)

        s = await setup()
        const bad = sealedResponse(s)
        await expect(bufferedResponder(s.deps, s.call)(s.em, bad.resp, new TextEncoder().encode('{"nonce":"","ciphertext":""}'))).rejects.toThrow(/^decrypt body: /)

        expect(unwrapped).toHaveLength(2)
        for (const k of unwrapped) {
            expect(k).toHaveLength(32)
            expect(k.every((b) => b === 0)).toBe(true)
        }
    })

    it('logs a sealed error envelope, still replying', async () => {
        const s = await setup()
        const plaintext = new TextEncoder().encode('{"error":{"message":"provider said no","code":"provider_error"}}')
        const f2 = await fixture({}, plaintext)
        s.f.receipt = f2.receipt
        s.f.op.ticketSigningKey = f2.op.ticketSigningKey
        const { resp, body } = sealedResponse(s, { status: 502, plaintext })
        await bufferedResponder(s.deps, s.call)(s.em, resp, body)
        expect(s.logger.logged).toContainEqual({
            level: 'warn',
            msg: 'operator returned error',
            attrs: { operator_id: 7, node_id: 3, ticket_id: TICKET_ID, error: 'provider said no' },
        })
        expect(s.em.replies[0]![0]).toBe(502)
    })

    // After the open, a node refusing admission is a paid turn interrupted,
    // and its code is what a caller branches on.
    it.each([
        ['node error', '{"error":{"message":"bad ticket","type":"invalid_request_error","code":"ticket_invalid"}}', 'ticket_invalid', 'bad ticket'],
        ['unparseable page', '<html>504</html>', '', 'operator returned HTTP 402 with a body this proxy could not parse as an OpenAI error (content-type "text/html")'],
    ] as const)('passes a pre-envelope %s on as interrupted', async (_name, text, code, message) => {
        const s = await setup()
        const resp = new Response(null, {
            status: 402,
            headers: {
                'Content-Type': 'text/html',
                // A day, which one node's hint is capped from.
                'Retry-After': '86400',
                'X-Zs-Settle-Group': 'pre-signed',
                'X-Zs-Receipt': 'receipt',
                'X-Zs-Evil': 'x',
                'X-Request-Id': 'req-1',
            },
        })
        await bufferedResponder(s.deps, s.call)(s.em, resp, new TextEncoder().encode(text))
        expect(s.em.replies).toEqual([])
        expect(s.em.failed).toMatchObject({ kind: 'interrupted', code, message, retryAfter: MAX_NODE_RETRY_HINT_MS })
        const reply = s.em.failed!.cause as NodeReply
        expect(reply).toBeInstanceOf(NodeReply)
        expect(reply.status).toBe(402)
        expect(new TextDecoder().decode(reply.body)).toContain('{')
        reply.header.forEach((_v, k) => expect(k.toLowerCase().startsWith('x-zs-'), k).toBe(false))
        expect(reply.header.get('X-Request-Id')).toBe('req-1')
        if (code === '') {
            expect(reply.contentType).toBe('application/json')
            expect(new TextDecoder().decode(reply.body)).toBe(`{"error":{"message":${JSON.stringify(message)},"type":"server_error"}}\n`)
        } else {
            expect(new TextDecoder().decode(reply.body)).toBe(text)
            expect(reply.contentType).toBe('')
        }
        expect(s.after).toEqual([])
    })

    // A key-less 4xx or 5xx is the node refusing; below 400 it is a success
    // the node didn't seal.
    it.each([
        [399, 'operator_unsealed_response'],
        [400, 'ticket_invalid'],
    ] as const)('reads a key-less %i by its status', async (status, code) => {
        const s = await setup()
        const text = '{"error":{"message":"bad ticket","type":"invalid_request_error","code":"ticket_invalid"}}'
        await bufferedResponder(s.deps, s.call)(s.em, new Response(null, { status }), new TextEncoder().encode(text))
        expect(s.em.failed?.code).toBe(code)
    })

    it('bounds the content type it echoes, and keeps no hint the node didn’t give', async () => {
        const s = await setup()
        const ct = 'x'.repeat(200)
        await bufferedResponder(s.deps, s.call)(s.em, new Response(null, { status: 503, headers: { 'Content-Type': ct } }), new Uint8Array())
        expect(s.em.failed!.message).toBe(`operator returned HTTP 503 with a body this proxy could not parse as an OpenAI error (content-type "${'x'.repeat(64)}…")`)
        expect(s.em.failed!.retryAfter).toBeUndefined()
    })

    // A header value is bytes: the cut is on bytes and can split a rune.
    it.each([
        ['ascii', 'x'.repeat(200), `${'x'.repeat(64)}…`],
        ['cut mid-rune', `${'x'.repeat(63)}\xc3\xa9`, `${'x'.repeat(63)}�…`],
        ['whole rune kept', `${'x'.repeat(62)}\xc3\xa9`, `${'x'.repeat(62)}é`],
        ['an invalid run is one replacement', 'a\xff\xfeb', 'a�b'],
        ['a real replacement character is kept', '\xef\xbf\xbd\xff', '��'],
        ['two invalid runs apart', 'a\xffb\xff', 'a�b�'],
    ])('truncateForLog: %s', (_name, header, want) => {
        expect(goDecodeUTF8(truncateForLog(header, 64))).toBe(want)
    })
})

describe('openAIErrorBody', () => {
    it('writes Go’s bytes: its key order, no empty code, its escapes and a newline', () => {
        const ls = String.fromCharCode(0x2028)
        expect(new TextDecoder().decode(openAIErrorBody('server_error', '', `a<b>&c${ls}`))).toBe(
            '{"error":{"message":"a\\u003cb\\u003e\\u0026c\\u2028","type":"server_error"}}\n',
        )
        expect(new TextDecoder().decode(openAIErrorBody('t', 'c', 'm'))).toBe('{"error":{"message":"m","type":"t","code":"c"}}\n')
    })
})

class Recorder {
    failed?: ZsError
    replies: [number, Headers, Uint8Array, UsageReport | null][] = []
    note() {}
    clamped() {}
    reserved() {}
    committed() {}
    fail(err: ZsError) {
        if (this.failed) throw new Error(`failed twice: ${this.failed.code}, then ${err.code}`)
        this.failed = err
    }
    reply(status: number, header: Headers, body: Uint8Array, usage: UsageReport | null) {
        this.replies.push([status, header, body, usage])
    }
    open(): boolean {
        throw new Error('a buffered turn never streams')
    }
    frame(): number {
        throw new Error('a buffered turn never streams')
    }
    interrupt() {
        throw new Error('a buffered turn never streams')
    }
}
