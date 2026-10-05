/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// ackSettle, checked against testdata/ack_settle_vectors.json, which Go's
// ackSettle generates; then checkReceipt, settleArgsOf and settleGroupSpecOf.

import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import algosdk from 'algosdk'

import { type Ticket, type UsageReceipt, receiptSigDigest, signReceipt } from '@txnlab/zs-proto/ticket'

import {
    type AckSettlePorts,
    discardLogger,
    SettleGroupRejectedError,
    type SettleGroupSpec,
    ackSettle,
    checkReceipt,
    settleArgsOf,
    settleGroupSpecOf,
} from '../src/index.js'

interface Scenario {
    name: string
    atomic: boolean
    spec: string
    group: string
    standalone: string
    want: {
        calls: string[]
        txid: string
        fee_microalgos: number
        group_rejected: boolean
        result: string
    }
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/ack_settle_vectors.json', import.meta.url), 'utf8'),
) as { scenarios: Scenario[] }

const groupErr = new Error('group submit')
const standaloneErr = new Error('standalone submit')

// The same scripted ports as Go's runAckSettleScenario.
function scripted(sc: Pick<Scenario, 'spec' | 'group' | 'standalone'>, calls: string[]): AckSettlePorts {
    return {
        spec: async () => {
            calls.push('spec')
            if (sc.spec === 'error') throw new Error('spec')
            return {} as SettleGroupSpec
        },
        submitGroup: async () => {
            calls.push('group')
            const rejection = new SettleGroupRejectedError('payer.rekeyTo', 'scripted')
            if (sc.group === 'rejected') throw rejection
            if (sc.group === 'rejected_wrapped') throw new Error('submit', { cause: rejection })
            if (sc.group === 'error') throw groupErr
            return { txid: 'GROUPTX', payerFeeMicroalgos: 0n }
        },
        standalone: async () => {
            calls.push('standalone')
            if (sc.standalone === 'error') throw standaloneErr
            return { txid: 'STANDALONETX', payerFeeMicroalgos: 5000n }
        },
    }
}

describe('ackSettle vectors', () => {
    it('covers every scenario', () => expect(vectors.scenarios.length).toBeGreaterThan(0))
    it.each(vectors.scenarios.map((s) => [s.name, s] as const))('%s', async (_name, sc) => {
        const calls: string[] = []
        const res = await ackSettle({ atomic: sc.atomic, ...scripted(sc, calls) })
        const result = res.err === undefined ? 'ok' : res.err === groupErr ? 'group' : res.err === standaloneErr ? 'standalone' : 'other'
        expect({
            calls,
            txid: res.txid,
            fee_microalgos: res.feeMicroalgos,
            group_rejected: res.groupRejected,
            result,
        }).toEqual(sc.want)
    })
})

function keypair() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const jwk = publicKey.export({ format: 'jwk' })
    return {
        pub: new Uint8Array(Buffer.from(jwk.x!, 'base64url')),
        signer: { signBytes: async (_a: string, msg: Uint8Array) => new Uint8Array(sign(null, msg, privateKey)) },
    }
}

const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest())
const body = new TextEncoder().encode('hello world')

const TICKET = { ticket_id: 'c2l4dGVlbi1ieXRlLWlkIQ==', max_price: 5000 } as Ticket

const IDS = {
    appId: 9n,
    ticketIdRaw: new Uint8Array(16),
    payerAddr: algosdk.encodeAddress(new Uint8Array(32).fill(1)),
    operatorSigningAddr: algosdk.encodeAddress(new Uint8Array(32).fill(2)),
}

async function signedReceipt(over: Partial<UsageReceipt> = {}) {
    const k = keypair()
    const r: UsageReceipt = {
        ticket_id: TICKET.ticket_id,
        actual_input_count: 42,
        actual_output_count: 17,
        amount_charged: 2600,
        ttft_ms: 120,
        decode_ms: 900,
        body_hash: Buffer.from(sha256(body)).toString('hex'),
        input_usage_type: 1,
        output_usage_type: 1,
        aux_output_usage_type: 2,
        aux_output_count: 3,
        cached_input_count: 0,
        ...over,
    }
    await signReceipt(r, k.signer, 'ADDR')
    return { r, pub: k.pub }
}

describe('checkReceipt', () => {
    it('journals a verified receipt before the ack, and acks only when submit runs', async () => {
        const { r, pub } = await signedReceipt()
        const order: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, order) },
            journal: () => void order.push('journal'),
        })
        expect(check.violation).toBeNull()
        expect(order).toEqual(['journal'])
        const settled = await check.submit!()
        expect(order).toEqual(['journal', 'standalone'])
        expect(settled).toMatchObject({ txid: 'STANDALONETX', kind: 'payer_ack', excluded: false })
    })

    it('reports an atomic settle as atomic', async () => {
        const { r, pub } = await signedReceipt()
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, []) },
        })
        expect(await check.submit!()).toMatchObject({ txid: 'GROUPTX', kind: 'atomic', excluded: false })
    })

    it('bars the node after the ack when its group was refused', async () => {
        const { r, pub } = await signedReceipt()
        const order: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'rejected_wrapped', standalone: 'ok' }, order) },
            excludeNode: (rejection) => order.push(`exclude ${rejection.field}`),
        })
        const settled = await check.submit!()
        expect(order).toEqual(['spec', 'group', 'standalone', 'exclude payer.rekeyTo'])
        expect(settled).toMatchObject({ groupRejected: true, excluded: true, kind: 'payer_ack' })
        expect(settled.rejection).toBeInstanceOf(SettleGroupRejectedError)
    })

    it('settles anyway when barring the node throws', async () => {
        const { r, pub } = await signedReceipt()
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'rejected', standalone: 'ok' }, []) },
            excludeNode: () => {
                throw new Error('store')
            },
        })
        expect(await check.submit!()).toMatchObject({ txid: 'STANDALONETX', groupRejected: true, excluded: false })
    })

    it('neither journals nor acks a receipt that fails its checks', async () => {
        const { r, pub } = await signedReceipt()
        const calls: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(new TextEncoder().encode('other body')),
            ack: { atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, calls) },
            journal: () => void calls.push('journal'),
        })
        expect(check).toMatchObject({ violation: 'body_hash', submit: null })
        expect(calls).toEqual([])
    })

    it('checks a receipt with no escrow to ack', async () => {
        const { r, pub } = await signedReceipt()
        const journaled: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: null,
            journal: () => void journaled.push('journal'),
        })
        expect(check).toEqual({ violation: null, submit: null })
        expect(journaled).toEqual([])
    })
})

describe('settleArgsOf / settleGroupSpecOf', () => {
    it('carries every co-signed value from the receipt, in its own slot', async () => {
        const { r } = await signedReceipt()
        expect(settleArgsOf(r)).toEqual({
            amountCharged: 2600n,
            receiptDigest: receiptSigDigest(r),
            ttftMs: 120n,
            decodeMs: 900n,
            inputTokens: 42n,
            outputTokens: 17n,
            outputUsageType: 1,
            auxOutputUsageType: 2,
            auxOutputCount: 3n,
        })
        expect(settleGroupSpecOf(r, IDS)).toEqual({
            ...IDS,
            amountCharged: 2600n,
            receiptDigest: receiptSigDigest(r),
            ttftMs: 120n,
            decodeMs: 900n,
            inputCount: 42n,
            outputCount: 17n,
            outputUsageType: 1n,
            auxOutputUsageType: 2n,
            auxOutputCount: 3n,
        })
    })

    // A malformed id is the payer's mistake. Built into a spec it would refuse
    // an honest node's group and bar the node; thrown, the ack goes standalone.
    it.each([
        ['a ticket id of the wrong length', { ticketIdRaw: new Uint8Array(15) }],
        ['a payer that is not an address', { payerAddr: 'PAYER' }],
        ['an operator signing address that is not one', { operatorSigningAddr: '' }],
    ])('refuses %s', async (_name, over) => {
        const { r } = await signedReceipt()
        expect(() => settleGroupSpecOf(r, { ...IDS, ...over })).toThrow()
    })
})

describe('checkReceipt journal', () => {
    async function run(journal: () => void | Promise<void>, order: string[]) {
        const { r, pub } = await signedReceipt()
        const warned: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, order) },
            journal,
            log: { ...discardLogger, warn: (msg) => warned.push(msg) },
        })
        return { settled: await check.submit!(), warned }
    }

    it('waits for an async journal before the ack', async () => {
        const order: string[] = []
        await run(async () => {
            await new Promise((r) => setTimeout(r, 5))
            order.push('journal')
        }, order)
        expect(order).toEqual(['journal', 'standalone'])
    })

    it.each([
        [
            'throws',
            () => {
                throw new Error('disk')
            },
        ],
        ['rejects', () => Promise.reject(new Error('disk'))],
    ])('acks anyway when the journal %s, and logs it', async (_name, journal) => {
        const order: string[] = []
        const { settled, warned } = await run(journal, order)
        expect(order).toEqual(['standalone'])
        expect(settled.txid).toBe('STANDALONETX')
        expect(warned).toEqual(['receipt journal failed; acking anyway'])
    })
})
