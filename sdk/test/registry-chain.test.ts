/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain half of discovery against a fake algod: the chain_nodes block of
// testdata/operator_vectors.json, which Go's fetchers and resolveOperatorNode
// generate, then the fetchers' paths and the signer-balance pass, ported from
// go/escrow's boxes_test.go and go/zs's signer_balance_test.go.

import { readFileSync } from 'node:fs'

import algosdk, { ABIMethod } from 'algosdk'
import {
    BASE_URL_MAX,
    NODE_RECORD_SIZE,
    OPERATOR_RECORD_SIZE,
    OPERATOR_STATUS_ACTIVE,
    OPERATOR_STATUS_EVICTED,
    decodeNodeRecord,
    decodeOperatorRecord,
    nodeBoxKey,
    operatorBoxKey,
} from '@txnlab/zs-proto/escrow'
import { describe, expect, it } from 'vitest'

import { ESCROW_METHOD_SIGNATURES } from '../src/escrow/generated/abi.js'
import { ChainOperatorSource, type LogAttrs, type Logger, type Operator } from '../src/index.js'
import {
    BoxValuesUnsupportedError,
    type ChainReadOptions,
    FETCH_BOX_CONCURRENCY,
    SIGNER_BALANCE_CONCURRENCY,
    fetchAllOperators,
    fetchNodesForOperators,
    fetchOperatorsById,
    listApplicationBoxes,
    readOperatorBox,
    resolveOperatorNode,
} from '../src/registry/index.js'

const APP = 1234n
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const utf8 = (s: string) => new TextEncoder().encode(s)
const RETURN_PREFIX = new Uint8Array([0x15, 0x1f, 0x7c, 0x75])

function httpError(status: number, message: string) {
    return Object.assign(new Error(`Network request error. Received status ${status}: ${message}`), {
        response: { status, body: utf8(JSON.stringify({ message })), headers: {} },
    })
}

const json = (v: unknown) => ({ status: 200, body: utf8(JSON.stringify(v)), headers: { 'content-type': 'application/json' } })

function methodBySelector(sel: Uint8Array): [string, ABIMethod] {
    for (const [name, sig] of Object.entries(ESCROW_METHOD_SIGNATURES)) {
        const m = ABIMethod.fromSignature(sig)
        if (b64(m.getSelector()) === b64(sel)) return [name, m]
    }
    throw new Error('unknown selector')
}

/** algod as discovery reads it, with every request it saw. */
class FakeAlgod implements algosdk.BaseHTTPClient {
    /** Box values by hex name; a number is the status a read of it fails with. */
    boxes = new Map<string, Uint8Array | number>()
    /** False: an algod that ignores include=values. */
    listsValues = true
    /** A listing failure, other than missing values. */
    listError: number | undefined
    /** Boxes per listing page; algod's own default is the limit the caller asks for. */
    pageSize: number | undefined
    nextOperatorId = 1n
    accounts = new Map<string, { amount: bigint; minBalance: bigint } | 'fail'>()
    paths: string[] = []
    listQueries: Record<string, unknown>[] = []
    accountQueries: Record<string, unknown>[] = []
    simulated: { method: string; sender: string }[] = []
    signals: (AbortSignal | undefined)[] = []
    inFlight = 0
    peak = 0
    /** While set, every request waits for it, or for its signal. */
    gate: Promise<void> | undefined
    /** Like gate, for account reads alone. */
    accountGate: Promise<void> | undefined
    onAccountRead: (() => void) | undefined

    async #enter(path: string, opts?: Record<string, unknown>) {
        this.paths.push(path)
        const signal = opts?.signal as AbortSignal | undefined
        this.signals.push(signal)
        this.inFlight++
        this.peak = Math.max(this.peak, this.inFlight)
        try {
            // A turn of the loop, so concurrent requests overlap.
            await new Promise((r) => setTimeout(r, 0))
            signal?.throwIfAborted()
            if (this.gate !== undefined) {
                const gate = this.gate
                await new Promise<void>((resolve, reject) => {
                    signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
                    void gate.then(resolve)
                })
            }
            signal?.throwIfAborted()
        } finally {
            this.inFlight--
        }
    }

    async get(path: string, query?: Record<string, unknown>, _h?: unknown, opts?: Record<string, unknown>) {
        await this.#enter(path, opts)
        if (path === '/v2/transactions/params') {
            return json({
                'consensus-version': 'future',
                fee: 0,
                'genesis-hash': b64(new Uint8Array(32)),
                'genesis-id': 'dev-v1',
                'last-round': 100,
                'min-fee': 1000,
            })
        }
        if (path === `/v2/applications/${APP}/boxes`) return this.#list(query ?? {})
        if (path === `/v2/applications/${APP}/box`) {
            const name = hex(Buffer.from(String(query?.name).replace(/^b64:/, ''), 'base64'))
            const v = this.boxes.get(name)
            if (v === undefined) throw httpError(404, 'box not found')
            if (typeof v === 'number') throw httpError(v, 'algod unavailable')
            return json({ name: b64(Buffer.from(name, 'hex')), round: 100, value: b64(v) })
        }
        const acct = /^\/v2\/accounts\/([A-Z2-7]+)$/.exec(path)
        if (acct) {
            this.accountQueries.push({ ...query })
            this.onAccountRead?.()
            const signal = opts?.signal as AbortSignal | undefined
            if (this.accountGate !== undefined) {
                const gate = this.accountGate
                await new Promise<void>((resolve, reject) => {
                    if (signal?.aborted) return reject(signal.reason)
                    signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
                    void gate.then(resolve)
                })
            }
            const a = this.accounts.get(acct[1]!)
            if (a === undefined || a === 'fail') throw httpError(503, 'algod unavailable')
            return json({
                address: acct[1],
                amount: Number(a.amount),
                'amount-without-pending-rewards': Number(a.amount),
                'min-balance': Number(a.minBalance),
                'pending-rewards': 0,
                rewards: 0,
                round: 100,
                status: 'Offline',
                'total-apps-opted-in': 0,
                'total-assets-opted-in': 0,
                'total-created-apps': 0,
                'total-created-assets': 0,
            })
        }
        throw httpError(404, `no route ${path}`)
    }

    #list(query: Record<string, unknown>) {
        this.listQueries.push({ ...query })
        if (this.listError !== undefined) throw httpError(this.listError, 'algod unavailable')
        const prefix = hex(Buffer.from(String(query.prefix).replace(/^b64:/, ''), 'base64'))
        const after = query.next === undefined ? '' : hex(Buffer.from(String(query.next).replace(/^b64:/, ''), 'base64'))
        const names = [...this.boxes.keys()].filter((n) => n.startsWith(prefix) && n >= after).sort()
        const size = this.pageSize ?? Number(query.limit)
        const page = names.slice(0, size)
        const rest = names[size]
        return json({
            round: 100,
            boxes: page.map((n) => {
                const v = this.boxes.get(n) as Uint8Array
                return this.listsValues ? { name: b64(Buffer.from(n, 'hex')), value: b64(v) } : { name: b64(Buffer.from(n, 'hex')) }
            }),
            ...(rest === undefined ? {} : { 'next-token': `b64:${b64(Buffer.from(rest, 'hex'))}` }),
        })
    }

    async post(path: string, data: Uint8Array, _q?: unknown, _h?: unknown, opts?: Record<string, unknown>) {
        await this.#enter(path, opts)
        if (path !== '/v2/transactions/simulate') throw httpError(404, `no route ${path}`)
        const req = algosdk.decodeMsgpack(data, algosdk.modelsv2.SimulateRequest)
        const stxn = req.txnGroups[0]!.txns[0]!
        const [name, m] = methodBySelector(stxn.txn.applicationCall!.appArgs[0]!)
        this.simulated.push({ method: name, sender: stxn.txn.sender.toString() })
        const logs = name === 'nextOperatorIdValue' ? [concat(RETURN_PREFIX, m.returns.type === 'void' ? new Uint8Array() : m.returns.type.encode(this.nextOperatorId))] : []
        const resp = new algosdk.modelsv2.SimulateResponse({
            version: 2,
            lastRound: 100,
            txnGroups: [
                new algosdk.modelsv2.SimulateTransactionGroupResult({
                    txnResults: [
                        new algosdk.modelsv2.SimulateTransactionResult({
                            txnResult: new algosdk.modelsv2.PendingTransactionResponse({ poolError: '', txn: stxn, logs }),
                        }),
                    ],
                }),
            ],
        })
        return { status: 200, body: algosdk.encodeMsgpack(resp), headers: { 'content-type': 'application/msgpack' } }
    }

    async delete(): Promise<never> {
        throw new Error('unused')
    }

    setBox(name: Uint8Array, value: Uint8Array | number) {
        this.boxes.set(hex(name), value)
    }

    count(path: string): number {
        return this.paths.filter((p) => p === path).length
    }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length)
    out.set(a)
    out.set(b, a.length)
    return out
}

/** A logger that keeps what it was told. */
function recordingLogger() {
    const lines: { level: string; msg: string; attrs: LogAttrs | undefined }[] = []
    const at =
        (level: string) =>
        (msg: string, attrs?: LogAttrs): void => {
            lines.push({ level, msg, attrs })
        }
    const logger: Logger = { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') }
    return { logger, lines }
}

const OWNER = algosdk.generateAccount().addr.toString()
const SIGNER_A = algosdk.generateAccount().addr.toString()
const SIGNER_B = algosdk.generateAccount().addr.toString()

// Operator and node box images with the fields discovery reads set, checked
// against the decoder so a layout change fails here rather than testing the
// wrong field.
function operatorBox(o: { id: bigint; status?: number; nextNodeId?: bigint; nfdAppId?: bigint }): Uint8Array {
    const b = new Uint8Array(OPERATOR_RECORD_SIZE)
    const v = new DataView(b.buffer)
    b.set(algosdk.decodeAddress(OWNER).publicKey, 0)
    b[32] = o.status ?? OPERATOR_STATUS_ACTIVE
    v.setBigUint64(33, o.nfdAppId ?? 0n)
    v.setBigUint64(41, o.nextNodeId ?? 1n)
    const rec = decodeOperatorRecord(o.id, b)
    expect([rec.ownerAddr, rec.status, rec.nfdAppId, rec.nextNodeId]).toEqual([OWNER, o.status ?? 1, o.nfdAppId ?? 0n, o.nextNodeId ?? 1n])
    return b
}

function nodeBox(n: { signer?: string; baseUrl?: Uint8Array | string; latencyEwmaMs?: bigint; staging?: number }): Uint8Array {
    const b = new Uint8Array(NODE_RECORD_SIZE)
    const v = new DataView(b.buffer)
    const url = typeof n.baseUrl === 'string' || n.baseUrl === undefined ? utf8(n.baseUrl ?? 'https://node.example.com') : n.baseUrl
    b[0] = 1
    b.set(algosdk.decodeAddress(n.signer ?? SIGNER_A).publicKey, 1)
    b[33] = url.length
    b.set(url, 34)
    v.setBigUint64(34 + BASE_URL_MAX + 88, n.latencyEwmaMs ?? 0n)
    b[NODE_RECORD_SIZE - 33] = n.staging ?? 0
    if (typeof n.baseUrl !== 'object') {
        const rec = decodeNodeRecord(1n, 1n, b)
        expect([rec.signingAddr, rec.latencyEwmaMs, rec.staging]).toEqual([n.signer ?? SIGNER_A, n.latencyEwmaMs ?? 0n, n.staging ?? 0])
    }
    return b
}

function chainOf(fake: FakeAlgod, logger?: Logger): ChainReadOptions {
    return { algod: new algosdk.Algodv2(fake, ''), appId: APP, logger }
}

function sourceOf(fake: FakeAlgod, over: { logger?: Logger; operatorIds?: bigint[]; nowMs?: number } = {}) {
    return new ChainOperatorSource({
        algod: new algosdk.Algodv2(fake, ''),
        escrowAppId: APP,
        operatorIds: over.operatorIds,
        logger: over.logger,
        clock: over.nowMs === undefined ? undefined : () => over.nowMs!,
    })
}

interface ChainNodeCase {
    name: string
    current_day: number
    operator_id: number
    operator_box_hex: string
    node_id: number
    node_box_hex: string
    want: Record<string, unknown> | null
    skipped: string
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/operator_vectors.json', import.meta.url), 'utf8')) as {
    chain_nodes: ChainNodeCase[]
}

function chainFields(o: Operator) {
    return {
        id: o.id,
        nodeId: o.nodeId,
        nfdAppId: o.nfdAppId,
        ownerAddr: o.ownerAddr,
        signingAddr: o.signingAddr,
        ticketSigningKeyHex: hex(o.ticketSigningKey),
        baseUrl: o.baseUrl,
        staging: o.staging,
        metrics: o.metrics,
    }
}

describe('chain node vectors', () => {
    it('covers every case', () => expect(vectors.chain_nodes.length).toBeGreaterThan(0))

    it.each(vectors.chain_nodes.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(BigInt(c.operator_id)), Buffer.from(c.operator_box_hex, 'hex'))
        fake.setBox(nodeBoxKey(BigInt(c.operator_id), BigInt(c.node_id)), Buffer.from(c.node_box_hex, 'hex'))
        const { logger, lines } = recordingLogger()
        // Late in the day, so a clock read as seconds or rounded up would land
        // on the next one.
        const nowMs = (c.current_day * 86_400 + 86_399) * 1000
        const ops = await sourceOf(fake, { logger, nowMs }).fetchChain()
        const skips = lines.filter((l) => l.msg === 'skipping unparseable node record')
        if (c.want !== null) {
            expect(c.skipped).toBe('')
            expect(ops.map(chainFields)).toEqual([c.want])
            expect(skips).toEqual([])
            return
        }
        expect(ops).toEqual([])
        if (c.skipped === 'base_url') {
            expect(skips).toHaveLength(1)
            expect(String(skips[0]!.attrs?.err)).toContain('base_url')
        } else {
            expect(c.skipped).toBe('evicted')
            expect(skips).toEqual([])
        }
    })
})

describe('the bulk box listing', () => {
    it('pages until algod runs out, asking for values and no round', async () => {
        const fake = new FakeAlgod()
        fake.pageSize = 2
        for (const id of [5n, 1n, 3n, 2n, 4n]) fake.setBox(operatorBoxKey(id), operatorBox({ id }))
        const ops = await fetchAllOperators(chainOf(fake))
        expect(ops.map((o) => o.id)).toEqual([1n, 2n, 3n, 4n, 5n])
        expect(fake.listQueries).toHaveLength(3)
        for (const q of fake.listQueries) {
            expect(q.include).toBe('values')
            expect(q.limit).toBe(1000)
            expect(q.round).toBeUndefined()
            // max, unlike limit, fails the call on an app with more boxes than it.
            expect(q.max ?? 0).toBe(0)
            expect(q.prefix).toBe(`b64:${b64(utf8('o:'))}`)
        }
        expect(fake.listQueries[0]!.next).toBeUndefined()
        expect(fake.listQueries[1]!.next).toBe(`b64:${b64(operatorBoxKey(3n))}`)
        // No count simulate and no read per box.
        expect(fake.simulated).toEqual([])
        expect(fake.count(`/v2/applications/${APP}/box`)).toBe(0)
    })

    it('skips names that are not operator boxes', async () => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(2n), operatorBox({ id: 2n }))
        fake.setBox(utf8('o:short'), operatorBox({ id: 9n }))
        expect((await fetchAllOperators(chainOf(fake))).map((o) => o.id)).toEqual([2n])
    })

    it('keeps only non-evicted requested operators’ nodes, sorted by operator then node', async () => {
        const fake = new FakeAlgod()
        for (const [op, node] of [
            [3n, 2n],
            [1n, 9n],
            [3n, 1n],
            [1n, 2n],
            [2n, 1n], // evicted
            [4n, 1n], // not requested
        ] as const) {
            fake.setBox(nodeBoxKey(op, node), nodeBox({}))
        }
        fake.setBox(utf8('n:bad'), nodeBox({}))
        const ops = [3n, 1n, 2n].map((id) =>
            decodeOperatorRecord(id, operatorBox({ id, status: id === 2n ? OPERATOR_STATUS_EVICTED : OPERATOR_STATUS_ACTIVE })),
        )
        const nodes = await fetchNodesForOperators(chainOf(fake), ops)
        expect(nodes.map((n) => [n.operatorId, n.nodeId])).toEqual([
            [1n, 2n],
            [1n, 9n],
            [3n, 1n],
            [3n, 2n],
        ])
    })

    it('reports an algod that ignores include=values as unsupported', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n }))
        await expect(listApplicationBoxes(chainOf(fake), utf8('o:'))).rejects.toBeInstanceOf(BoxValuesUnsupportedError)
    })
})

describe('the box-by-box fallback', () => {
    it('reads operators 1..next-1 from the simulated count, skipping the gone, only when values are unsupported', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        fake.nextOperatorId = 5n
        for (const id of [1n, 2n, 4n]) fake.setBox(operatorBoxKey(id), operatorBox({ id }))
        const ops = await fetchAllOperators(chainOf(fake))
        expect(ops.map((o) => o.id)).toEqual([1n, 2n, 4n])
        // As every readonly call: from the application account.
        expect(fake.simulated).toEqual([{ method: 'nextOperatorIdValue', sender: algosdk.getApplicationAddress(APP).toString() }])
        expect(fake.count(`/v2/applications/${APP}/box`)).toBe(4)
    })

    it('reads nothing when no operator was ever registered', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        fake.nextOperatorId = 1n
        expect(await fetchAllOperators(chainOf(fake))).toEqual([])
        expect(fake.count(`/v2/applications/${APP}/box`)).toBe(0)
    })

    it('does not fall back on a listing that failed outright', async () => {
        const fake = new FakeAlgod()
        fake.listError = 503
        await expect(fetchAllOperators(chainOf(fake))).rejects.toThrow(/box-list for app 1234: .*503/)
        expect(fake.simulated).toEqual([])
        await expect(fetchNodesForOperators(chainOf(fake), [decodeOperatorRecord(1n, operatorBox({ id: 1n, nextNodeId: 2n }))])).rejects.toThrow(
            /503/,
        )
        expect(fake.count(`/v2/applications/${APP}/box`)).toBe(0)
    })

    it('reads nodes in the operators’ order, then by node, skipping evicted operators and gone nodes', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        for (const [op, node] of [
            [3n, 1n],
            [3n, 3n],
            [1n, 1n],
            [1n, 2n],
            [2n, 1n],
        ] as const) {
            fake.setBox(nodeBoxKey(op, node), nodeBox({}))
        }
        const ops = [
            decodeOperatorRecord(3n, operatorBox({ id: 3n, nextNodeId: 4n })),
            decodeOperatorRecord(2n, operatorBox({ id: 2n, nextNodeId: 2n, status: OPERATOR_STATUS_EVICTED })),
            decodeOperatorRecord(1n, operatorBox({ id: 1n, nextNodeId: 3n })),
            decodeOperatorRecord(5n, operatorBox({ id: 5n, nextNodeId: 1n })),
        ]
        const nodes = await fetchNodesForOperators(chainOf(fake), ops)
        expect(nodes.map((n) => [n.operatorId, n.nodeId])).toEqual([
            [3n, 1n],
            [3n, 3n],
            [1n, 1n],
            [1n, 2n],
        ])
        // 3 ids under operator 3, 2 under operator 1, none under the evicted one.
        expect(fake.count(`/v2/applications/${APP}/box`)).toBe(5)
    })

    it('holds every node read across all operators under one limit', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        const ops = [1n, 2n, 3n].map((id) => decodeOperatorRecord(id, operatorBox({ id, nextNodeId: 21n })))
        for (const op of ops) for (let n = 1n; n <= 20n; n++) fake.setBox(nodeBoxKey(op.id, n), nodeBox({}))
        expect((await fetchNodesForOperators(chainOf(fake), ops)).length).toBe(60)
        expect(fake.count(`/v2/applications/${APP}/box`)).toBe(60)
        expect(fake.peak).toBe(FETCH_BOX_CONCURRENCY)
    })

    it('fails on the first read that fails, and stops the rest', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        fake.nextOperatorId = 40n
        fake.setBox(operatorBoxKey(3n), 500)
        await expect(fetchAllOperators(chainOf(fake))).rejects.toThrow(/fetch operator 3 box: .*500/)
        expect(fake.count(`/v2/applications/${APP}/box`)).toBeLessThan(39)
    })
})

describe('reading operators by id', () => {
    it('returns them in the order asked', async () => {
        const fake = new FakeAlgod()
        for (const id of [1n, 2n, 3n]) fake.setBox(operatorBoxKey(id), operatorBox({ id }))
        const ops = await fetchOperatorsById(chainOf(fake), [3n, 1n])
        expect(ops.map((o) => o.id)).toEqual([3n, 1n])
    })

    it('fails when one is missing', async () => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n }))
        await expect(fetchOperatorsById(chainOf(fake), [1n, 9n])).rejects.toThrow('operator 9 not found on chain')
    })

    it('reads a gone box as undefined and a failed read as an error', async () => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(2n), 500)
        expect(await readOperatorBox(chainOf(fake), 1n)).toBeUndefined()
        await expect(readOperatorBox(chainOf(fake), 2n)).rejects.toThrow(/fetch operator 2 box/)
    })

    it('is what the source reads when it is given ids', async () => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n, nextNodeId: 2n }))
        fake.setBox(operatorBoxKey(2n), operatorBox({ id: 2n, nextNodeId: 2n }))
        fake.setBox(nodeBoxKey(1n, 1n), nodeBox({}))
        fake.setBox(nodeBoxKey(2n, 1n), nodeBox({}))
        const ops = await sourceOf(fake, { operatorIds: [2n] }).fetchChain()
        expect(ops.map((o) => [o.id, o.nodeId])).toEqual([[2, 1]])
        await expect(sourceOf(fake, { operatorIds: [2n, 3n] }).fetchChain()).rejects.toThrow(
            'fetch operators: operator 3 not found on chain',
        )
    })
})

describe('the chain read', () => {
    it('refuses a source with no app id, and an app with no operators', async () => {
        const fake = new FakeAlgod()
        const algod = new algosdk.Algodv2(fake, '')
        await expect(new ChainOperatorSource({ algod, escrowAppId: 0n }).fetchChain()).rejects.toThrow('escrowAppId is 0')
        await expect(sourceOf(fake).fetchChain()).rejects.toThrow('no operators found on chain for escrow app 1234')
        const noAlgod = new ChainOperatorSource({ algod: undefined as unknown as algosdk.Algodv2, escrowAppId: APP })
        await expect(noAlgod.fetchChain()).rejects.toThrow('algod is not set')
    })

    it('skips and logs one bad node, keeping the rest', async () => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n, nextNodeId: 4n }))
        fake.setBox(nodeBoxKey(1n, 1n), nodeBox({}))
        fake.setBox(nodeBoxKey(1n, 2n), nodeBox({ baseUrl: 'ftp://node.example.com' }))
        fake.setBox(nodeBoxKey(1n, 3n), nodeBox({ baseUrl: new Uint8Array([...utf8('https://x.example/'), 0xff]) }))
        fake.accounts.set(SIGNER_A, { amount: 1n, minBalance: 0n })
        const { logger, lines } = recordingLogger()
        const ops = await sourceOf(fake, { logger }).fetchChain()
        expect(ops.map((o) => o.nodeId)).toEqual([1])
        expect(lines.filter((l) => l.level === 'warn').map((l) => [l.msg, l.attrs?.node_id])).toEqual([
            ['skipping node record whose base URL is not UTF-8', '3'],
            ['skipping unparseable node record', '2'],
        ])
    })

    it('carries the signal to every algod request', async () => {
        const fake = new FakeAlgod()
        fake.listsValues = false
        fake.nextOperatorId = 2n
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n, nextNodeId: 2n }))
        fake.setBox(nodeBoxKey(1n, 1n), nodeBox({}))
        fake.accounts.set(SIGNER_A, { amount: 1n, minBalance: 0n })
        const ctl = new AbortController()
        await sourceOf(fake).fetchChain(ctl.signal)
        // Params, simulate, both listings, the operator and node reads, the account.
        expect(fake.signals).toHaveLength(7)
        ctl.abort()
        expect(fake.paths.filter((_, i) => fake.signals[i]?.aborted !== true)).toEqual([])
    })

    it('stops a read whose caller is gone', async () => {
        const fake = new FakeAlgod()
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n }))
        fake.gate = new Promise(() => {})
        const ctl = new AbortController()
        const pending = sourceOf(fake).fetchChain(ctl.signal)
        ctl.abort(new Error('caller gone'))
        await expect(pending).rejects.toThrow(/caller gone/)
    })
})

describe('resolveOperatorNode', () => {
    const op = () => decodeOperatorRecord(7n, operatorBox({ id: 7n, nextNodeId: 3n, nfdAppId: 42n }))
    const node = () => decodeNodeRecord(7n, 2n, nodeBox({ latencyEwmaMs: 900n, staging: 1 }))

    it('leaves everything a probe fills empty, and the node unreachable', () => {
        const o = resolveOperatorNode(op(), node(), 20_000n)
        expect(o).toMatchObject({
            id: 7,
            nodeId: 2,
            nfdAppId: 42,
            ownerAddr: OWNER,
            signingAddr: SIGNER_A,
            staging: true,
            models: [],
            builtinTools: [],
            maxToolIters: 0,
            toolHeadroomPerIteration: 0,
            protoVersion: '',
            reachable: false,
            ephemeralExpiry: 0,
            ephemeralIssuedAt: 0,
            minChargeOutputTokens: 0,
            minChargeAlgoTxns: 0,
            minChargeMicroUsdc: 0,
        })
        expect(Object.keys(o.modelCapacities)).toEqual([])
        expect(o.ephemeralRecipient).toBeUndefined()
        expect(o.tee).toBeUndefined()
        expect(o.signerSpendableMicroAlgos).toBeUndefined()
        expect(o.metrics.latencyEwmaMs).toBe(900)
        expect(o.ticketSigningKey).toEqual(algosdk.decodeAddress(SIGNER_A).publicKey)
    })

    it('refuses a signing address that does not decode', () => {
        expect(() => resolveOperatorNode(op(), { ...node(), signingAddr: 'NOT-AN-ADDRESS' }, 0n)).toThrow(
            'operator 7 node 2: decode signing addr',
        )
    })

    it('refuses an id a number cannot hold exactly', () => {
        const big = 2n ** 53n + 1n
        expect(() => resolveOperatorNode({ ...op(), id: big }, node(), 0n)).toThrow(RangeError)
        expect(() => resolveOperatorNode(op(), { ...node(), nodeId: big }, 0n)).toThrow(RangeError)
    })
})

describe('signer balances', () => {
    // A source over a chain of one operator whose nodes sign with signers, in order.
    function fleet(fake: FakeAlgod, signers: string[]) {
        fake.boxes.clear()
        fake.setBox(operatorBoxKey(1n), operatorBox({ id: 1n, nextNodeId: BigInt(signers.length + 1) }))
        signers.forEach((s, i) => fake.setBox(nodeBoxKey(1n, BigInt(i + 1)), nodeBox({ signer: s })))
    }
    const spendable = (ops: Operator[]) => ops.map((o) => o.signerSpendableMicroAlgos)

    it('reads a shared signer once, asking algod for no lists', async () => {
        const fake = new FakeAlgod()
        fleet(fake, [SIGNER_A, SIGNER_A, SIGNER_B])
        fake.accounts.set(SIGNER_A, { amount: 5_100_000n, minBalance: 100_000n })
        fake.accounts.set(SIGNER_B, { amount: 50_000n, minBalance: 100_000n })
        const ops = await sourceOf(fake).fetchChain()
        expect(spendable(ops)).toEqual([5_000_000, 5_000_000, 0])
        expect(fake.count(`/v2/accounts/${SIGNER_A}`)).toBe(1)
        expect(fake.accountQueries.every((q) => q.exclude === 'all')).toBe(true)
    })

    it('keeps the last-known value through a failed read, and leaves a never-read signer unknown', async () => {
        const fake = new FakeAlgod()
        const source = sourceOf(fake)
        fleet(fake, [SIGNER_A, SIGNER_B])
        fake.accounts.set(SIGNER_A, { amount: 1_000_000n, minBalance: 0n })
        fake.accounts.set(SIGNER_B, 'fail')
        await source.fetchChain()

        fake.accounts.set(SIGNER_A, 'fail')
        const ops = await source.fetchChain()
        expect(spendable(ops)).toEqual([1_000_000, undefined])

        fake.accounts.set(SIGNER_A, { amount: 9_000_000n, minBalance: 0n })
        expect(spendable(await source.fetchChain())).toEqual([9_000_000, undefined])
    })

    it('forgets a signer that left the fleet', async () => {
        const fake = new FakeAlgod()
        const source = sourceOf(fake)
        fleet(fake, [SIGNER_A, SIGNER_B])
        fake.accounts.set(SIGNER_A, { amount: 0n, minBalance: 0n })
        fake.accounts.set(SIGNER_B, { amount: 9_000_000n, minBalance: 0n })
        await source.fetchChain()

        fleet(fake, [SIGNER_B])
        await source.fetchChain()

        fleet(fake, [SIGNER_A])
        fake.accounts.set(SIGNER_A, 'fail')
        expect(spendable(await source.fetchChain())).toEqual([undefined])
    })

    it('warns once per pass, with the count', async () => {
        const fake = new FakeAlgod()
        fleet(fake, [SIGNER_A, SIGNER_B])
        fake.accounts.set(SIGNER_A, 'fail')
        fake.accounts.set(SIGNER_B, 'fail')
        const { logger, lines } = recordingLogger()
        await sourceOf(fake, { logger }).fetchChain()
        const warns = lines.filter((l) => l.level === 'warn')
        expect(warns).toHaveLength(1)
        expect(warns[0]!.msg).toBe('signing-account balance reads failed; routing those nodes on last-known values')
        expect(warns[0]!.attrs).toMatchObject({ failed: 2, signers: 2 })
    })

    it('bounds the reads in flight', async () => {
        const fake = new FakeAlgod()
        const signers = Array.from({ length: 3 * SIGNER_BALANCE_CONCURRENCY }, () => algosdk.generateAccount().addr.toString())
        fleet(fake, signers)
        for (const s of signers) fake.accounts.set(s, { amount: 1n, minBalance: 0n })
        const ops = await sourceOf(fake).fetchChain()
        // The box reads run one at a time here, so the peak is the balance pass's.
        expect(fake.peak).toBe(SIGNER_BALANCE_CONCURRENCY)
        expect(spendable(ops).every((v) => v === 1)).toBe(true)
    })

    // The pass carries its own deadline, so a stalled algod can't hold the
    // refresh, and what it could not read keeps its last-known value.
    it('ends a stalled pass at its own deadline, keeping last-known values', async () => {
        const fake = new FakeAlgod()
        const source = new ChainOperatorSource({ algod: new algosdk.Algodv2(fake, ''), escrowAppId: APP, signerBalanceTimeoutMs: 50 })
        fleet(fake, [SIGNER_A, SIGNER_B])
        fake.accounts.set(SIGNER_A, { amount: 2_000_000n, minBalance: 0n })
        await source.fetchChain()

        fake.accounts.set(SIGNER_A, { amount: 90_000_000n, minBalance: 0n })
        fake.accountGate = new Promise(() => {})
        expect(spendable(await source.fetchChain())).toEqual([2_000_000, undefined])
    })

    it('keeps last-known values through a pass whose caller is gone', async () => {
        const fake = new FakeAlgod()
        const source = sourceOf(fake)
        fleet(fake, [SIGNER_A])
        fake.accounts.set(SIGNER_A, { amount: 2_000_000n, minBalance: 0n })
        await source.fetchChain()

        fake.accounts.set(SIGNER_A, { amount: 90_000_000n, minBalance: 0n })
        fake.accountGate = new Promise(() => {})
        const ctl = new AbortController()
        fake.onAccountRead = () => ctl.abort()
        expect(spendable(await source.fetchChain(ctl.signal))).toEqual([2_000_000])
    })
})
