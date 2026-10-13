/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The reserve phase, porting the reserve-phase cases of go/zs/handler
// dispatch_test.go, spend_dispatch_test.go, image_tools_dispatch_test.go,
// max_output_clamp_test.go, config_gates_test.go and errors_shape_test.go, and
// of go/zs admit_test.go and dispatch_cancel_test.go. Go drives them through a
// fake node over HTTP; here the parts dispatch calls are faked directly, and
// the sealed run is a recorder.

import { describe, expect, it, vi } from 'vitest'

import { MIN_SIGNER_SPENDABLE_MICROALGOS } from '@txnlab/zs-proto/selection'
import type { ReserveRequest } from '@txnlab/zs-proto/ticket'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'

import { IDAffinity } from '../src/affinity.js'
import { dispatchDepsOf } from '../src/client-parts.js'
import { Client } from '../src/client.js'
import { DuplicateTicketError, type SpendGuard } from '../src/config.js'
import { type DispatchDeps, type SealedRun, dispatch } from '../src/dispatch.js'
import type { ZsError } from '../src/errors.js'
import type { Event } from '../src/events.js'
import { MbrDepositUnaffordableError } from '../src/mbr.js'
import type { ModelCapacity, Operator } from '../src/operator.js'
import type { RegistryProvider, Reserved, ReserveClient } from '../src/parts.js'
import type { PickDeps } from '../src/pick.js'
import type { LogAttrs, Signer } from '../src/ports.js'
import {
    BadReserveEnvelopeError,
    BusyError,
    NoEphemeralError,
    PayerRefusalError,
    ReserveHTTPError,
    SizeError,
} from '../src/reserve.js'
import { TargetBackoffStore } from '../src/routing/backoff.js'
import { RelayLatencyStore } from '../src/routing/latency.js'
import { type RelayHop, relayRef, targetRef } from '../src/routing/relay.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import { type Request, turnOf } from '../src/turn.js'
import type { Endpoint } from '../src/types.js'
import { BelowTargetError } from '../src/wallet.js'
import { testOperator } from './fixtures.js'

const MODEL = 'gpt-test'

function cap(over: Partial<ModelCapacity> = {}): ModelCapacity {
    return {
        contextWindow: 0,
        maxOutputTokens: 0,
        inputUsdPer1m: 0,
        outputUsdPer1m: 0,
        longContextThresholdTokens: 0,
        weightsDigest: '',
        weightsUnverifiable: false,
        source: '',
        canonicalId: '',
        retention: '',
        imageToolRateMicroUsdc: 0,
        imageEditToolRateMicroUsdc: 0,
        imageToolBaseMicroUsdc: 0,
        imageEditToolBaseMicroUsdc: 0,
        imageRateMicroUsdc: 0,
        imageEditRateMicroUsdc: 0,
        imageDefaultMicroUsdc: 0,
        imageEditDefaultMicroUsdc: 0,
        imageCapMicroUsdc: 0,
        imageEditCapMicroUsdc: 0,
        advertisesImageGen: false,
        advertisesImageEdit: false,
        vendorToolCatchAllMicroUsdc: 0,
        vendorToolCallCap: 0,
        vendorToolTokensPerCall: 0,
        ...over,
    }
}

/** A serving node on the current wire, with no declared capacity: unbounded and unpriced. */
function op(id: number, over: Partial<Operator> = {}): Operator {
    return testOperator({
        id,
        nodeId: 0,
        ownerAddr: `OWNER${id}`,
        baseUrl: `https://n${id}.example.com`,
        models: [MODEL],
        protoVersion: PROTO_VERSION,
        ...over,
    })
}

const withCap = (o: Operator, c: Partial<ModelCapacity>, model = MODEL): Operator => ({
    ...o,
    modelCapacities: { ...o.modelCapacities, [model]: cap(c) },
})

type Req = Omit<ReserveRequest, 'proxy_recipient' | 'payer_sig' | 'payer_issued_at'>

interface Call {
    op: Operator
    req: Req
    hop: RelayHop | null
}

/**
 * A signed ticket for req, as a node returns it: unpriced but for a minimum
 * charge, which is the whole ceiling at no fee.
 */
function reservedFor(o: Operator, req: Req, id = `T${o.id}`): Reserved {
    return {
        ticket: {
            ticket_id: id,
            operator_id: o.id,
            node_id: o.nodeId,
            model: req.model,
            input_count: req.input_count,
            max_output_count: req.max_output_count,
            input_rate: 0,
            output_rate: 0,
            cache_read_rate: 0,
            max_price: 1000,
            min_price: 1000,
            stream: req.stream,
            expires_at: 2_000_000_000,
            sig: '',
        },
        responseKey: new Uint8Array(32),
        algoUsdPrice: 0,
        presignedOpenTxn: '',
        sealRecipient: 'age1test',
    } as unknown as Reserved
}

type Answer = (o: Operator, req: Req, hop: RelayHop | null, n: number) => Promise<Reserved>

/** A reserve client answering each call through answer; n counts calls from 0. */
function reserveClient(answer: Answer = async (o, req) => reservedFor(o, req)): ReserveClient & { calls: Call[] } {
    const calls: Call[] = []
    return {
        calls,
        reserve(o, req, hop) {
            calls.push({ op: o, req: { ...req }, hop })
            return answer(o, req, hop, calls.length - 1)
        },
    }
}

// Each node answers through its own script; one with none succeeds.
function perNode(scripts: Record<number, (n: number) => Reserved | Error>): Answer {
    const seen = new Map<number, number>()
    return async (o, req) => {
        const n = seen.get(o.id) ?? 0
        seen.set(o.id, n + 1)
        const s = scripts[o.id]
        if (!s) return reservedFor(o, req)
        const r = s(n)
        if (r instanceof Error) throw r
        return r
    }
}

const busy = (retryAfterMs = 0, code = 'no_capacity') => new BusyError(code, retryAfterMs)
const sizeRefusal = () => new SizeError('context_length_exceeded', 'max_output_tokens exceeds this operator')
const gateway = () => new ReserveHTTPError({ status: 504 })

function registryOf(ops: Operator[], over: Partial<RegistryProvider> = {}): RegistryProvider & { demand: string[] } {
    const demand: string[] = []
    return {
        demand,
        operators: async (model) => ops.filter((o) => o.models.includes(model)),
        resolve: async (r) => ops.find((o) => o.id === r.op && o.nodeId === r.node),
        allOperators: async () => ops,
        reprobeEphemeral: async () => null,
        recordModelDemand: (m) => demand.push(m),
        ...over,
    }
}

interface Logged {
    level: string
    msg: string
    attrs: LogAttrs | undefined
}

class Recorder {
    notes: Event[] = []
    clamps: number[] = []
    failed?: ZsError
    runs: SealedRun[] = []
    note(ev: Event) {
        this.notes.push(ev)
    }
    clamped(ceiling: number) {
        this.clamps.push(ceiling)
    }
    reserved() {}
    committed() {}
    fail(err: ZsError) {
        if (this.failed) throw new Error(`failed twice: ${this.failed.code}, then ${err.code}`)
        this.failed = err
    }
    reply() {
        throw new Error('the reserve phase never replies')
    }
    open(): boolean {
        throw new Error('the reserve phase never streams')
    }
    frame(): number {
        throw new Error('the reserve phase never streams')
    }
    interrupt() {
        throw new Error('the reserve phase never streams')
    }
}

interface Harness {
    deps: DispatchDeps
    rc: ReserveClient & { calls: Call[] }
    em: Recorder
    logged: Logged[]
    registry: RegistryProvider & { demand: string[] }
    /** Every wait dispatch asked for, in order. */
    sleeps: number[]
    /** Moves the fake clock, as a slow round trip would. */
    advance(ms: number): void
    run(body: string | Uint8Array, over?: Partial<Request>, signal?: AbortSignal): Promise<Recorder>
}

interface HarnessOptions {
    answer?: Answer
    registry?: Partial<RegistryProvider>
    pick?: Partial<PickDeps>
    deps?: Partial<DispatchDeps>
}

function harness(ops: Operator[], o: HarnessOptions = {}): Harness {
    const logged: Logged[] = []
    const at =
        (level: string) =>
        (msg: string, attrs?: LogAttrs): void => {
            logged.push({ level, msg, attrs })
        }
    const registry = registryOf(ops, o.registry)
    const rc = reserveClient(o.answer)
    // A clock the sleeps advance, so the waits cost nothing and the deadlines still bind.
    let now = 1_000_000
    const sleeps: number[] = []
    const em = new Recorder()
    const deps: DispatchDeps = {
        pick: {
            registry,
            toolAffinity: new IDAffinity(16, 60_000),
            responseAffinity: new IDAffinity(16, 60_000),
            affinityPolicy: 'none',
            allowStaging: false,
            logger: { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') },
            weightsWarned: new Set(),
            ...o.pick,
        },
        reserveClient: rc,
        wallet: { payerAddr: () => 'PAYER' },
        estimatePolicy: { maxOutputByModel: { [MODEL]: 128 }, fallbackMaxOutput: 0 },
        privacy: 'direct',
        allowPrivacyOverride: false,
        requireTeeModels: [],
        remedies: { fund: 'fund it', raiseSlots: 'add slots', raiseSpendCap: 'raise the cap remedy', recoverTicket: 'recover it' },
        network: 'testnet',
        retryBudget: 60_000,
        feeRate: () => null,
        runSealed: async (e, run) => {
            ;(e as Recorder).runs.push(run)
        },
        clock: () => now,
        sleep: async (ms, signal) => {
            if (signal?.aborted) return false
            sleeps.push(ms)
            now += Math.max(ms, 0)
            return true
        },
        ...o.deps,
    }
    return {
        deps,
        rc,
        em,
        logged,
        registry,
        sleeps,
        advance(ms) {
            now += ms
        },
        async run(body, over = {}, signal) {
            await dispatch(deps, em, turnOf({ endpoint: '/v1/chat/completions', body, ...over }), signal)
            return em
        },
    }
}

const chat = (extra = '') => `{"model":"${MODEL}","messages":[{"role":"user","content":"hi"}]${extra}}`
const ids = (calls: readonly Call[]) => calls.map((c) => c.op.id)

describe('the body', () => {
    it('needs a model', async () => {
        const h = harness([op(1)])
        const em = await h.run('{"messages":[]}')
        expect(em.failed).toMatchObject({ code: 'missing_model', kind: 'invalid_request' })
        expect(h.rc.calls).toEqual([])
    })

    it('reads an image request’s n, size and quality, and refuses a bad one', async () => {
        const gen = withCap(op(1), { imageRateMicroUsdc: 40_000 })
        let h = harness([gen])
        await h.run(`{"model":"${MODEL}","prompt":"a cat","n":2,"size":"1024x1024","quality":"hd"}`, {
            endpoint: '/v1/images/generations',
        })
        const req = h.rc.calls[0]!.req
        expect(req).toEqual({
            model: MODEL,
            input_count: 0,
            max_output_count: 0,
            stream: false,
            payer_addr: 'PAYER',
            input_bound_version: 2,
            image_n: 2,
            image_size: '1024x1024',
            image_quality: 'hd',
        })

        h = harness([gen])
        const em = await h.run(`{"model":"${MODEL}","prompt":"a cat","n":0}`, { endpoint: '/v1/images/generations' })
        expect(em.failed).toMatchObject({ code: 'bad_image_request', kind: 'invalid_request' })
        expect(em.failed!.message).toBe('image request: n must be >= 1')
    })

    it('reads an image edit from its multipart body and leaves the body as it came', async () => {
        const edit = withCap(op(1), { imageEditRateMicroUsdc: 40_000 })
        const boundary = 'XBOUNDARY'
        const body =
            `--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\n${MODEL}\r\n` +
            `--${boundary}\r\nContent-Disposition: form-data; name="n"\r\n\r\n3\r\n` +
            `--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="a.png"\r\nContent-Type: image/png\r\n\r\nPNG\r\n` +
            `--${boundary}--\r\n`
        const h = harness([edit])
        const em = await h.run(body, { endpoint: '/v1/images/edits', contentType: `multipart/form-data; boundary=${boundary}` })
        expect(h.rc.calls[0]!.req).toMatchObject({ image_n: 3, image_edit: true, input_count: 0, max_output_count: 0 })
        expect(em.runs[0]!.body).toBe(body)

        const bad = harness([edit])
        const failed = (await bad.run(body, { endpoint: '/v1/images/edits' })).failed
        expect(failed).toMatchObject({ code: 'bad_image_edit_request', message: 'multipart Content-Type header is required' })
    })

    it('is shaped before the seal: provider and prompt_cache_key out, store defaulted, empty tools gone', async () => {
        for (const body of [
            chat(',"provider":{"sort":"price"},"prompt_cache_key":"k","tools":[],"tool_choice":"auto"'),
            new TextEncoder().encode(chat(',"provider":{"sort":"price"},"prompt_cache_key":"k","tools":[],"tool_choice":"auto"')),
        ]) {
            const h = harness([op(1)])
            const em = await h.run(body)
            const sealed = em.runs[0]!.body
            expect(typeof sealed).toBe(typeof body)
            const text = typeof sealed === 'string' ? sealed : new TextDecoder().decode(sealed)
            expect(JSON.parse(text)).toEqual({
                model: MODEL,
                messages: [{ role: 'user', content: 'hi' }],
                store: false,
            })
        }
    })

    it('notes the model as in demand', async () => {
        const h = harness([op(1)])
        await h.run(chat())
        expect(h.registry.demand).toEqual([MODEL])
    })
})

describe('the estimate', () => {
    it('refuses a request with no max_output and no default', async () => {
        const h = harness([op(1)], { deps: { estimatePolicy: { maxOutputByModel: {}, fallbackMaxOutput: 0 } } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({ code: 'max_output_required', kind: 'invalid_request' })
        expect(h.rc.calls).toEqual([])
    })

    it('sizes any model that names its own max_output', async () => {
        const h = harness([op(1, { models: ['unknown'] })], { deps: { estimatePolicy: { maxOutputByModel: {}, fallbackMaxOutput: 0 } } })
        const em = await h.run('{"model":"unknown","max_tokens":64}')
        expect(em.failed).toBeUndefined()
        expect(h.rc.calls[0]!.req.max_output_count).toBe(64)
    })

    it('fails as tokenize when the body cannot be sized, logging the endpoint and model only', async () => {
        const h = harness([op(1)])
        const em = await h.run(`{"model":"${MODEL}","max_tokens":"lots"}`)
        expect(em.failed).toMatchObject({ code: 'tokenize', kind: 'internal', message: 'input tokenization failed' })
        expect(h.logged.find((l) => l.msg === 'tokenize failed')!.attrs).toMatchObject({ endpoint: '/v1/chat/completions', model: MODEL })
    })
})

describe('the max_output clamp', () => {
    const CLAMP = 'big-out'
    const big = (id: number, maxOut: number, over: Partial<ModelCapacity> = {}) =>
        withCap(op(id, { models: [CLAMP] }), { maxOutputTokens: maxOut, ...over }, CLAMP)
    const ask = (n: number, extra = '') => `{"model":"${CLAMP}","max_tokens":${n}${extra},"messages":[{"role":"user","content":"hi"}]}`
    const sealedMax = (em: Recorder) => JSON.parse(em.runs[0]!.body as string).max_tokens as number

    it('lowers the caller’s max_output to the pool ceiling, in the reserve and the sealed body', async () => {
        const h = harness([big(1, 32_768)])
        const em = await h.run(ask(65_536))
        expect(em.failed).toBeUndefined()
        expect(h.rc.calls[0]!.req.max_output_count).toBe(32_768)
        expect(sealedMax(em)).toBe(32_768)
        expect(em.clamps).toEqual([32_768])
        expect(h.logged).toContainEqual({
            level: 'debug',
            msg: 'lowered caller max_output_tokens to the pool ceiling',
            attrs: { model: CLAMP, requested: 65_536, clamped_to: 32_768 },
        })
    })

    it('leaves it alone when a node declares no cap, and routes there', async () => {
        const h = harness([big(1, 0), big(2, 32_768)])
        const em = await h.run(ask(65_536))
        expect(em.clamps).toEqual([])
        expect(ids(h.rc.calls)).toEqual([1])
        expect(h.rc.calls[0]!.req.max_output_count).toBe(65_536)
        expect(sealedMax(em)).toBe(65_536)
    })

    it('can’t rescue a window miss, which still says so after reporting the clamp', async () => {
        const h = harness([big(1, 32_768, { contextWindow: 1000 })])
        const em = await h.run(ask(65_536))
        expect(em.clamps).toEqual([32_768])
        expect(em.failed!.code).toBe('context_length_exceeded')
        expect(em.failed!.message).toContain('context_window=1000')
        expect(h.rc.calls).toEqual([])
    })

    it('lowers to the most generous routable node, not counting staging or ignored ones', async () => {
        let h = harness([big(1, 32_768), big(2, 8192)])
        await h.run(ask(65_536))
        expect(ids(h.rc.calls)).toEqual([1])
        expect(h.rc.calls[0]!.req.max_output_count).toBe(32_768)

        h = harness([big(1, 32_768), { ...big(2, 0), staging: true }])
        await h.run(ask(65_536))
        expect(ids(h.rc.calls)).toEqual([1])
        expect(h.rc.calls[0]!.req.max_output_count).toBe(32_768)

        h = harness([big(1, 32_768), big(2, 0)])
        await h.run(ask(65_536, ',"provider":{"ignore":["2"]}'))
        expect(ids(h.rc.calls)).toEqual([1])
        expect(h.rc.calls[0]!.req.max_output_count).toBe(32_768)
    })

    it('leaves a request under the ceiling unchanged', async () => {
        const h = harness([big(1, 32_768)])
        const em = await h.run(ask(512))
        expect(em.clamps).toEqual([])
        expect(h.rc.calls[0]!.req.max_output_count).toBe(512)
        expect(sealedMax(em)).toBe(512)
    })
})

describe('an empty pick', () => {
    const fail = async (ops: Operator[], body = chat(), o: HarnessOptions = {}, over: Partial<Request> = {}) => {
        const h = harness(ops, o)
        const em = await h.run(body, over)
        expect(h.rc.calls.length, `${body} at ${over.endpoint ?? 'chat'}: ${em.failed?.code}`).toBe(0)
        return em.failed!
    }

    it('fails as registry when selection fails', async () => {
        const failed = await fail([], chat(), { registry: { operators: () => Promise.reject(new Error('down')) } })
        expect(failed).toMatchObject({ code: 'registry', kind: 'internal', message: 'operator selection failed' })
    })

    it('names each cause, most specific first', async () => {
        expect(await fail([])).toMatchObject({
            code: 'no_operator',
            kind: 'no_route',
            message: `no operator is currently advertising the model "${MODEL}"`,
        })
        expect((await fail([], '{"model":"a\\u0001b","max_tokens":5}')).message).toBe(
            'no operator is currently advertising the model "a\\x01b"',
        )
        expect(await fail([op(1, { protoVersion: '1.0' })])).toMatchObject({
            code: 'no_compatible_operator',
            message: `no operator advertises a compatible wire protocol version (${PROTO_VERSION})`,
        })
        expect(await fail([op(1, { staging: true })])).toMatchObject({
            code: 'no_production_operator',
            message: `the model "${MODEL}" is only served by staging nodes; allow routing to staging nodes to reach them`,
        })
        expect(await fail([op(1, { signerSpendableMicroAlgos: 0 })])).toMatchObject({
            code: 'no_funded_operator',
            message: `every node serving the model "${MODEL}" has less than ${MIN_SIGNER_SPENDABLE_MICROALGOS / 1_000_000} ALGO spendable in its signing account to pay network fees; retry later or pick another model`,
        })
        // A chat model pricing the image tool doesn't serve the dedicated route.
        const chatTool = withCap(op(1), { imageToolRateMicroUsdc: 80_000, outputUsdPer1m: 10 })
        expect(await fail([chatTool], chat(), {}, { endpoint: '/v1/images/generations' })).toMatchObject({
            code: 'no_operator',
            message: `no operator advertises ${MODEL} for image generation`,
        })
        expect(await fail([op(1)], chat(), {}, { endpoint: '/v1/images/generations' })).toMatchObject({
            code: 'no_operator',
            message: `no operator advertises ${MODEL} for image generation`,
        })
        expect(await fail([op(1)], chat(',"provider":{"only":["9"]}'))).toMatchObject({
            code: 'no_pinned_operator',
            kind: 'no_route',
            message: `no operator matching your provider preferences is currently available to serve ${MODEL}; adjust provider.only / provider.order or remove the pin`,
        })
        expect(await fail([withCap(op(1), { inputUsdPer1m: 9, outputUsdPer1m: 9 })], chat(',"provider":{"max_price":{"input":1}}'))).toMatchObject({
            code: 'price_ceiling_exceeded',
            kind: 'price_rejected',
            message: `no operator serves ${MODEL} within your provider.max_price ceiling; raise or remove the ceiling`,
        })
        expect(await fail([op(1)], chat(',"tools":[{"type":"zs_web_search"}],"provider":{"require_tools":true}'))).toMatchObject({
            code: 'no_tool_capacity',
            message: `no operator advertises every requested built-in tool for ${MODEL} (provider.require_tools is set)`,
        })
    })

    it('is no_tee_capacity before any reserve, for a listed model or the request’s own flag', async () => {
        for (const [models, flag, want] of [
            [[MODEL], false, true],
            [['other'], false, false],
            [[], true, true],
            [[], false, false],
        ] as const) {
            const h = harness([op(1)], { deps: { requireTeeModels: models } })
            const em = await h.run(chat(), { requireTee: flag })
            expect(em.failed?.code === 'no_tee_capacity').toBe(want)
            if (want) {
                expect(em.failed!.message).toBe('no operator with current TEE attestation can serve this request')
                expect(h.rc.calls).toEqual([])
            }
        }
    })

    it('lists each node the sizing filter refused, with the limit it blew', async () => {
        const failed = await fail([withCap(op(1), { contextWindow: 4 }), withCap(op(2), { maxOutputTokens: 64 })])
        expect(failed.code).toBe('context_length_exceeded')
        expect(failed.message).toMatch(/^no operator serves gpt-test with input_tokens=\d+ max_output_tokens=128\n/)
        expect(failed.message).toMatch(/op 1: context_window=4 \(request needs \d+\)/)
        expect(failed.message).toContain('op 2: max_output_tokens=64 (over by 64)')
    })

    it('reports a filtered node’s miss when the rest of the pool only refused', async () => {
        const h = harness([withCap(op(1), { maxOutputTokens: 64 }), op(2)], {
            answer: perNode({ 2: () => busy() }),
            deps: { sweepDelay: () => 0 },
        })
        const em = await h.run(chat())
        expect(ids(h.rc.calls)).toEqual([2, 2, 2])
        expect(em.failed!.code).toBe('context_length_exceeded')
        expect(em.failed!.message).toMatch(/\n {2}operators advertising this model:\n {2}- op 1: max_output_tokens=64 \(over by 64\)$/)
    })

    it('routes around a node the sizing filter refused', async () => {
        const h = harness([withCap(op(1), { contextWindow: 4 }), op(2)])
        const em = await h.run(chat())
        expect(ids(h.rc.calls)).toEqual([2])
        expect(em.runs[0]!.op.id).toBe(2)
    })

    it('names a strict pin that cannot fit, rather than blaming the pool', async () => {
        const h = harness([withCap(op(1), { contextWindow: 4 }), op(2)], { pick: { affinityPolicy: 'strict' } })
        h.deps.pick.toolAffinity.record({ op: 1, node: 0 }, ['call-strict-1'])
        const em = await h.run(`{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"call-strict-1","content":"x"}]}`)
        expect(em.failed!.code).toBe('context_length_exceeded')
        expect(em.failed!.message).toMatch(
            /^strict affinity target cannot serve gpt-test with input_tokens=\d+ max_output_tokens=128; reduce prompt size or switch affinity_policy to "prefer"$/,
        )
        expect(h.rc.calls).toEqual([])
    })

    it('blocks a previous_response_id it cannot route, or whose node is gone', async () => {
        let h = harness([op(1)])
        let em = await h.run(`{"model":"${MODEL}","previous_response_id":"resp_unknown","input":[]}`, { endpoint: '/v1/responses' })
        expect(em.failed!.code).toBe('context_length_exceeded')
        expect(em.failed!.message).toContain('previous_response_id "resp_unknown" not found in routing cache')

        h = harness([op(2)])
        h.deps.pick.responseAffinity.record({ op: 1, node: 0 }, ['resp_X'])
        em = await h.run(`{"model":"${MODEL}","previous_response_id":"resp_X","input":[]}`, { endpoint: '/v1/responses' })
        expect(em.failed!.message).toBe(
            'previous_response_id "resp_X" is pinned to operator 1 node 0 which is no longer registered; retry without previous_response_id',
        )
        expect(h.rc.calls).toEqual([])
    })

    it('refuses a continuation the caller’s own pin excludes', async () => {
        const h = harness([op(1), op(2)])
        h.deps.pick.responseAffinity.record({ op: 1, node: 0 }, ['resp_X'])
        const em = await h.run(`{"model":"${MODEL}","previous_response_id":"resp_X","input":[],"provider":{"only":["2"]}}`, {
            endpoint: '/v1/responses',
        })
        expect(em.failed).toMatchObject({ code: 'pin_conflicts_with_continuation', kind: 'invalid_request' })
        expect(em.failed!.message).toContain('which your provider preferences (only/ignore/order) exclude')
    })
})

describe('admission', () => {
    const priced = (id: number, inUsd: number, outUsd: number) => withCap(op(id), { inputUsdPer1m: inUsd, outputUsdPer1m: outUsd })

    function guard(limit: number): SpendGuard & { estimates: number[]; reserved: string[] } {
        const estimates: number[] = []
        const reserved: string[] = []
        return {
            estimates,
            reserved,
            admit(est) {
                estimates.push(est)
                if (est > limit) throw new Error('over the cap')
            },
            reserve(id) {
                reserved.push(id)
            },
            settle() {},
            release() {},
        }
    }

    it('admits on the cheapest candidate, whichever routing tries first', async () => {
        for (const [body, firstRouted] of [
            [chat(',"max_tokens":100'), 1],
            [chat(',"max_tokens":100,"provider":{"order":["2"]}'), 2],
        ] as const) {
            const cheapOnly = harness([priced(1, 1, 2)], { deps: { feeRate: () => 0, spendGuard: guard(Infinity) } })
            await cheapOnly.run(body)
            const low = (cheapOnly.deps.spendGuard as ReturnType<typeof guard>).estimates[0]!
            const dearOnly = harness([priced(2, 10, 20)], { deps: { feeRate: () => 0, spendGuard: guard(Infinity) } })
            await dearOnly.run(body)
            const high = (dearOnly.deps.spendGuard as ReturnType<typeof guard>).estimates[0]!
            expect(low).toBeLessThan(high)

            // A ceiling the ticket's own numbers don't add up to, so the price
            // gate refuses each and both are asked.
            const misPriced = async (o: Operator, req: Req): Promise<Reserved> => {
                const r = reservedFor(o, req)
                r.ticket.min_price = 0
                return r
            }
            const g = guard(Math.floor((low + high) / 2))
            const h = harness([priced(1, 1, 2), priced(2, 10, 20)], { deps: { feeRate: () => 0, spendGuard: g }, answer: misPriced })
            await h.run(body)
            expect(g.estimates).toEqual([low])
            const cheap = h.rc.calls.find((c) => c.op.id === 1)!.req
            expect(low).toBe(cheap.input_count + 2 * cheap.max_output_count)
            expect(h.rc.calls[0]!.op.id).toBe(firstRouted)
        }
    })

    it('a refusal ends the turn as a spend cap, with the remedy, before any reserve', async () => {
        const g = guard(0)
        const h = harness([priced(1, 1, 2)], { deps: { feeRate: () => 0, spendGuard: g } })
        const em = await h.run(chat(',"max_tokens":100'))
        expect(em.failed).toMatchObject({ code: 'spend_cap_exceeded', kind: 'spend_cap' })
        expect(em.failed!.message).toBe(
            'spend cap reached (over the cap): the cheapest available operator would escrow more than the limit allows. No reservation was made. To fix it, raise the cap remedy.',
        )
        expect(h.rc.calls).toEqual([])
        expect(g.estimates).toHaveLength(1)
        expect(g.estimates[0]).toBeGreaterThan(0)
    })

    it('is skipped for an unpriced pool, an unread fee and the image routes', async () => {
        const json = `{"model":"${MODEL}","prompt":"a cat","messages":[],"max_tokens":100}`
        const boundary = 'B'
        const edit =
            `--${boundary}\r\nContent-Disposition: form-data; name="model"\r\n\r\n${MODEL}\r\n` +
            `--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="a.png"\r\nContent-Type: image/png\r\n\r\nPNG\r\n` +
            `--${boundary}--\r\n`
        const imaging = withCap(op(1), { inputUsdPer1m: 1, outputUsdPer1m: 2, imageRateMicroUsdc: 40_000, imageEditRateMicroUsdc: 40_000 })
        for (const [ops, fee, body, req] of [
            [[op(1)], 0, json, {}],
            [[priced(1, 1, 2)], null, json, {}],
            [[imaging], 0, json, { endpoint: '/v1/images/generations' as Endpoint }],
            [[imaging], 0, edit, { endpoint: '/v1/images/edits' as Endpoint, contentType: `multipart/form-data; boundary=${boundary}` }],
        ] as const) {
            const g = guard(0)
            const h = harness([...ops], { deps: { feeRate: () => fee, spendGuard: g } })
            await h.run(body, req)
            expect(g.estimates).toEqual([])
            expect(h.rc.calls).toHaveLength(1)
        }
    })
})

describe('the relay', () => {
    // Three owners, so each target has a relay of another owner.
    const fleet = () => [op(1), op(2), op(3)]

    it('follows the configured posture, the caller’s override and the body over the request', async () => {
        for (const [name, privacy, allow, flag, bodyRelay, want] of [
            ['relay_required relays', 'relay_required', false, '', '', true],
            ['direct sends direct', 'direct', false, '', '', false],
            ['off refused without override', 'relay_required', false, 'off', '', true],
            ['off honored with override', 'relay_required', true, 'off', '', false],
            ['body required beats request off', 'relay_required', true, 'off', 'required', true],
            ['body off beats request required', 'relay_required', true, 'required', 'off', false],
        ] as const) {
            const h = harness(fleet(), {
                deps: { privacy, allowPrivacyOverride: allow },
                answer: async () => {
                    throw new ReserveHTTPError({ status: 400, code: 'invalid_request' })
                },
            })
            const body = bodyRelay === '' ? chat() : chat(`,"provider":{"relay":"${bodyRelay}"}`)
            await h.run(body, flag === '' ? {} : { relay: flag })
            expect(h.rc.calls.length, name).toBeGreaterThan(0)
            for (const c of h.rc.calls) expect(c.hop !== null, name).toBe(want)
        }
    })

    it('says when a relay=off override is ignored', async () => {
        const h = harness(fleet(), { deps: { privacy: 'relay_required' } })
        await h.run(chat(), { relay: 'off' })
        expect(h.logged).toContainEqual({
            level: 'debug',
            msg: 'ignoring relay=off override; allow_privacy_override is disabled',
            attrs: { endpoint: '/v1/chat/completions' },
        })
    })

    it('skips a target with no eligible relay, never going direct, and says so when none had one', async () => {
        let h = harness([op(1), op(2, { ownerAddr: 'OWNER1' })], { deps: { privacy: 'relay_required' } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({
            code: 'no_relay_available',
            message: 'transport-privacy mode is enabled but no eligible relay operator is available for the selected target(s)',
        })
        expect(h.rc.calls).toEqual([])

        // Under strict, an unpinned turn routes like any other. Op 1's only
        // other-owner relay shares its subnet; ops 2 and 3 relay each other.
        const at = (o: Operator, host: string) => ({ ...o, baseUrl: `http://${host}` })
        h = harness([at(op(1), '203.0.113.1'), at(op(2), '203.0.113.2'), at(op(3, { ownerAddr: 'OWNER1' }), '198.51.100.1')], {
            deps: { privacy: 'relay_required' },
            pick: { affinityPolicy: 'strict' },
            answer: async () => {
                throw new ReserveHTTPError({ status: 400, code: 'invalid_request' })
            },
        })
        await h.run(chat())
        expect(ids(h.rc.calls)).toEqual([2, 3])
        for (const c of h.rc.calls) expect(c.hop).not.toBeNull()
        expect(h.logged).toContainEqual({
            level: 'info',
            msg: 'privacy mode: no eligible relay; skipping operator',
            attrs: { operator_id: 1, node_id: 0, endpoint: '/v1/chat/completions' },
        })
    })

    it('rides the chosen relay into the sealed run, and announces it', async () => {
        const h = harness(fleet(), { deps: { privacy: 'relay_required' } })
        const em = await h.run(chat())
        const hop = em.runs[0]!.hop!
        expect(hop).toEqual(h.rc.calls[0]!.hop)
        expect(em.notes).toContainEqual({
            type: 'relay.hop',
            relay: { op: hop.relayId, node: hop.relayNodeId },
            target: { op: 1, node: 0 },
            reason: 'chosen',
        })
    })

    it('charges a relay its own front door', async () => {
        const relayReputation = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const spy = vi.spyOn(relayReputation, 'recordRelayOutcome')
        const h = harness(fleet(), {
            deps: { privacy: 'relay_required' },
            pick: { relayReputation },
            answer: perNode({ 1: (n) => (n === 0 ? new ReserveHTTPError({ status: 503, code: 'relay_busy' }) : reservedFor(op(1), {} as Req)) }),
        })
        await h.run(chat())
        const first = h.rc.calls[0]!.hop!
        expect(spy).toHaveBeenCalledWith({ op: first.relayId, node: first.relayNodeId }, false)
    })
})

describe('the reserve request', () => {
    it('carries the per-operator sizing, the stream flag, the payer and the bound version', async () => {
        const h = harness([op(1)])
        await h.run(chat(',"stream":true'))
        const req = h.rc.calls[0]!.req
        expect(req).toMatchObject({ model: MODEL, max_output_count: 128, stream: true, payer_addr: 'PAYER', input_bound_version: 2 })
        expect(req.input_count).toBeGreaterThan(0)

        const old = harness([op(1, { protoVersion: '9.1' })])
        await old.run(chat())
        expect(old.rc.calls[0]!.req.input_bound_version).toBe(1)
    })

    it('leaves the payer off when the wallet names none', async () => {
        const h = harness([op(1)], { deps: { wallet: { payerAddr: () => '' } } })
        await h.run(chat())
        expect(h.rc.calls[0]!.req).not.toHaveProperty('payer_addr')
    })

    it('carries an image-tool budget only when one is asked for, clamped to 64', async () => {
        const gen = withCap(op(1), { imageToolRateMicroUsdc: 100_000, imageEditToolRateMicroUsdc: 120_000, outputUsdPer1m: 10 })
        const responses = (extra = '') =>
            `{"model":"${MODEL}","input":[{"role":"user","content":"hi"}],"max_output_tokens":50${extra}}`
        for (const [extra, want] of [
            ['', {}],
            [',"tool_budgets":{"zs_image_generation":{"max_n":3}}', { image_tool_budget: 3 }],
            [',"tool_budgets":{"zs_image_edit":{"max_n":2}}', { image_edit_tool_budget: 2 }],
            [',"tool_budgets":{"zs_image_generation":{"max_n":114}}', { image_tool_budget: 64 }],
            [',"tool_budgets":{"zs_image_edit":{"max_n":114}}', { image_edit_tool_budget: 64 }],
        ] as const) {
            const h = harness([gen])
            await h.run(responses(extra), { endpoint: '/v1/responses' })
            const req = h.rc.calls[0]!.req
            expect(req.image_tool_budget).toBe((want as { image_tool_budget?: number }).image_tool_budget)
            expect(req.image_edit_tool_budget).toBe((want as { image_edit_tool_budget?: number }).image_edit_tool_budget)
        }
    })

    it('skips a node that can’t price a budgeted tool, and fails unsupported_tool when none can', async () => {
        const responses = `{"model":"${MODEL}","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":1},"zs_image_edit":{"max_n":1}}}`
        for (const [gen, edit] of [
            [0, 80_000],
            [80_000, 0],
        ] as const) {
            const h = harness([withCap(op(1), { imageToolRateMicroUsdc: gen, imageEditToolRateMicroUsdc: edit }), withCap(op(2), { imageToolRateMicroUsdc: 80_000, imageEditToolRateMicroUsdc: 80_000 })], {
                pick: { affinityPolicy: 'strict' },
            })
            await h.run(responses, { endpoint: '/v1/responses' })
            expect(ids(h.rc.calls)).toEqual([2])
        }

        const h = harness([withCap(op(1), { outputUsdPer1m: 10 })])
        const em = await h.run(responses, { endpoint: '/v1/responses' })
        expect(em.failed).toMatchObject({
            code: 'unsupported_tool',
            kind: 'invalid_request',
            message: `no operator serves a built-in image tool for model ${MODEL} — the model does not advertise an image-tool factor`,
        })
        expect(h.rc.calls).toEqual([])
    })

    it('lets a busy node outrank a missing tool price', async () => {
        const h = harness(
            [withCap(op(1), { imageToolRateMicroUsdc: 100_000 }), withCap(op(2), {})],
            { answer: perNode({ 1: () => busy(7000) }), deps: { sweepDelay: () => 0 } },
        )
        const em = await h.run(
            `{"model":"${MODEL}","input":[],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":2}}}`,
            { endpoint: '/v1/responses' },
        )
        expect(em.failed).toMatchObject({ code: 'operators_busy', retryAfter: 7000 })
    })

    it('keeps the tool budgets on a request re-sized after a re-probe, either one alone', async () => {
        const rates = { imageToolRateMicroUsdc: 80_000, imageEditToolRateMicroUsdc: 80_000 }
        for (const [budgets, gen, edit] of [
            ['"zs_image_generation":{"max_n":2},"zs_image_edit":{"max_n":1}', 2, 1],
            ['"zs_image_generation":{"max_n":2}', 2, undefined],
            ['"zs_image_edit":{"max_n":1}', undefined, 1],
        ] as const) {
            const healed = withCap(op(1, { protoVersion: '9.1' }), rates)
            const h = harness([withCap(op(1), rates)], {
                registry: { reprobeEphemeral: async () => healed },
                answer: async (o, req, _hop, n) => {
                    if (n === 0) throw new NoEphemeralError()
                    return reservedFor(o, req)
                },
            })
            await h.run(`{"model":"${MODEL}","input":[],"max_output_tokens":50,"tool_budgets":{${budgets}}}`, {
                endpoint: '/v1/responses',
            })
            expect(
                h.rc.calls.map((c) => [c.req.input_bound_version, c.req.image_tool_budget, c.req.image_edit_tool_budget]),
                budgets,
            ).toEqual([
                [2, gen, edit],
                [1, gen, edit],
            ])
        }
    })

    it('re-sizes against the node a stale ephemeral was re-probed into', async () => {
        for (const stale of [new NoEphemeralError(), new BadReserveEnvelopeError()]) {
            const healed = op(1, { protoVersion: '9.1' })
            const reprobe = vi.fn(async () => healed)
            const h = harness([op(1)], {
                registry: { reprobeEphemeral: reprobe },
                answer: async (o, req, _hop, n) => {
                    if (n === 0) throw stale
                    return reservedFor(o, req)
                },
            })
            const em = await h.run(chat())
            expect(reprobe).toHaveBeenCalledTimes(1)
            expect(h.rc.calls.map((c) => c.req.input_bound_version)).toEqual([2, 1])
            expect(em.runs[0]!.op).toBe(healed)

            // The re-sized reserve is what a healthy first attempt at that node sends.
            const direct = harness([healed])
            await direct.run(chat())
            expect(h.rc.calls[1]!.req).toEqual(direct.rc.calls[0]!.req)
        }
    })

    // Pick admitted the node under its old key; the re-probe swaps the key
    // after pick has run, so the TEE gate must be applied again.
    it('takes a re-probed node for a TEE-required request only if attested under its new key', async () => {
        // Every status is a pass, so only the release check separates them: a
        // re-check that read the pass alone would take the unattested key.
        const tee = (attested: boolean) => ({
            mode: 'dstack-tdx',
            attestedAt: 0,
            verifierId: 'dstack-tdx',
            verified: true,
            failureTag: '',
            osImageChecked: true,
            composeReleaseChecked: attested,
        })
        // A null verdict is a re-probe that found nothing: still no refresh,
        // and no throw on the way.
        for (const [requireTee, healedVerified, wantSecond] of [
            [true, false, false],
            [true, true, true],
            [false, false, true],
            [true, null, false],
        ] as const) {
            const healed = healedVerified === null ? null : op(1, { tee: tee(healedVerified) })
            const h = harness([op(1, { tee: tee(true) })], {
                registry: { reprobeEphemeral: async () => healed },
                answer: async (o, req, _hop, n) => {
                    if (n === 0) throw new NoEphemeralError()
                    return reservedFor(o, req)
                },
            })
            const em = await h.run(chat(), { requireTee })
            const label = `requireTee=${requireTee} healedVerified=${healedVerified}`
            expect(h.rc.calls.length, label).toBe(wantSecond ? 2 : 1)
            if (wantSecond) expect(em.runs[0]!.op, label).toBe(healed)
            else expect(em.runs, label).toEqual([])
        }
    })
})

describe('the caller’s admitNode check', () => {
    it('skips a node it refuses before any reserve, and is handed the turn’s signal', async () => {
        const signal = new AbortController().signal
        const asked: [number, AbortSignal | undefined][] = []
        const h = harness([op(1), op(2)])
        const em = await h.run(
            chat(),
            {
                admitNode: (o, s) => {
                    asked.push([o.id, s])
                    return o.id !== 1
                },
            },
            signal,
        )
        expect(asked).toEqual([
            [1, signal],
            [2, signal],
        ])
        expect(ids(h.rc.calls)).toEqual([2])
        expect(em.runs[0]!.op.id).toBe(2)
    })

    it('fails no_tee_capacity with its own message when it refuses every node, without a re-sweep', async () => {
        for (const admitNode of [() => false, async () => false, () => Promise.reject(new Error('no verdict'))]) {
            const h = harness([op(1), op(2)], { deps: { sweepDelay: () => 0 } })
            const em = await h.run(chat(), { admitNode })
            expect(em.failed).toMatchObject({
                code: 'no_tee_capacity',
                kind: 'no_route',
                message: 'no operator the caller admits can serve this request',
            })
            expect(h.rc.calls).toEqual([])
            expect(h.sleeps).toEqual([])
        }
    })

    // A refusal filters, as requireTee does at pick: the node it let through
    // reports its own failure, retryable ones included.
    it('leaves an admitted node’s failure as the answer', async () => {
        for (const [fail, want] of [
            [() => gateway(), 'operators_unreachable'],
            [() => new NoEphemeralError(), 'no_ephemeral_capacity'],
            [() => busy(7000), 'operators_busy'],
        ] as const) {
            const h = harness([op(1), op(2)], {
                answer: perNode({ 2: () => fail() }),
                deps: { sweepDelay: () => 0, retryBudget: 1500 },
            })
            const em = await h.run(chat(), { admitNode: (o) => o.id !== 1 })
            expect(em.failed?.code, want).toBe(want)
        }
    })

    it('keeps the weather and busy re-sweeps for the nodes it lets through', async () => {
        const unreachable = harness([op(1), op(2)], {
            answer: perNode({ 2: () => gateway() }),
            deps: { sweepDelay: () => 0, retryBudget: 1500 },
        })
        await unreachable.run(chat(), { admitNode: (o) => o.id !== 1 })
        const alone = harness([op(2)], {
            answer: perNode({ 2: () => gateway() }),
            deps: { sweepDelay: () => 0, retryBudget: 1500 },
        })
        await alone.run(chat())
        expect(alone.sleeps.length).toBeGreaterThan(0)
        expect(unreachable.sleeps).toEqual(alone.sleeps)

        const freed = harness([op(1), op(2)], {
            answer: perNode({ 2: (n) => (n === 0 ? busy() : reservedFor(op(2), {} as Req)) }),
            deps: { sweepDelay: () => 0 },
        })
        const em = await freed.run(chat(), { admitNode: (o) => o.id !== 1 })
        expect(em.failed).toBeUndefined()
        expect(em.runs[0]!.op.id).toBe(2)
    })

    // Admitted under the key pick saw; the re-probe hands back one it never judged.
    // A refusal of that key is the answer even where the node had no key at
    // all, which would otherwise read as the ephemeral gap.
    it('is asked again about a re-probed node, under its new key', async () => {
        for (const first of [() => new BadReserveEnvelopeError(), () => new NoEphemeralError()]) {
            for (const refuseNew of [true, false]) {
                const label = `${first().constructor.name}, refuseNew=${refuseNew}`
                const healed = op(1, { ephemeralRecipient: 'age1new' })
                const seen: (string | undefined)[] = []
                const h = harness([op(1, { ephemeralRecipient: 'age1old' })], {
                    registry: { reprobeEphemeral: async () => healed },
                    answer: async (o, req, _hop, n) => {
                        if (n === 0) throw first()
                        return reservedFor(o, req)
                    },
                })
                const em = await h.run(chat(), {
                    admitNode: (o) => {
                        seen.push(o.ephemeralRecipient)
                        const ok = !(refuseNew && o.ephemeralRecipient === 'age1new')
                        // The registry refreshing in place after the check.
                        if (o.ephemeralRecipient === 'age1new') healed.ephemeralRecipient = 'age1swapped'
                        return ok
                    },
                })
                expect(seen, label).toEqual(['age1old', 'age1new'])
                if (refuseNew) {
                    expect(h.rc.calls, label).toHaveLength(1)
                    expect(em.runs, label).toEqual([])
                    expect(em.failed, label).toMatchObject({ code: 'no_tee_capacity' })
                } else {
                    expect(h.rc.calls, label).toHaveLength(2)
                    expect(h.rc.calls[1]!.op.ephemeralRecipient, label).toBe('age1new')
                    expect(Object.isFrozen(h.rc.calls[1]!.op), label).toBe(true)
                    expect(em.runs[0]!.op.ephemeralRecipient, label).toBe('age1new')
                }
            }
        }
    })

    // A verdict can change between sweeps (a key's check lands, or is withdrawn).
    it('asks again on every sweep rather than keeping its first answer', async () => {
        const asked = new Map<number, number>()
        const events: string[] = []
        const h = harness([op(1), op(2)], {
            answer: perNode({
                2: () => {
                    events.push('reserve')
                    return gateway()
                },
            }),
            deps: { sweepDelay: () => 0, retryBudget: 1500 },
        })
        await h.run(chat(), {
            admitNode: (o) => {
                const n = (asked.get(o.id) ?? 0) + 1
                asked.set(o.id, n)
                const ok = o.id === 2 && n === 1
                if (o.id === 2) events.push(ok ? 'admit' : 'refuse')
                return ok
            },
        })
        // Admitted on the first sweep (whose own retry reserves it again), then
        // refused on the re-sweep, and never reserved after that.
        expect(events[0]).toBe('admit')
        expect(events.slice(events.indexOf('refuse'))).toEqual(['refuse'])
    })

    it('counts a node whose re-probed key it refused as not let through, beside a busy one', async () => {
        const h = harness([op(1, { ephemeralRecipient: 'age1old' }), op(2)], {
            registry: { reprobeEphemeral: async () => op(1, { ephemeralRecipient: 'age1new' }) },
            answer: perNode({ 1: () => new BadReserveEnvelopeError(), 2: () => busy(7000) }),
            deps: { sweepDelay: () => 0 },
        })
        const em = await h.run(chat(), { admitNode: (o) => o.ephemeralRecipient !== 'age1new' })
        expect(em.failed?.code).toBe('operators_busy')
    })

    // A registry may refresh its operators in place: what the reserve seals to
    // must be the key that was judged.
    it('seals to the frozen copy it judged, whatever the registry does to its own', async () => {
        const live = op(1, { ephemeralRecipient: 'age1judged' })
        let frozen = false
        const h = harness([live])
        const em = await h.run(chat(), {
            admitNode: (o) => {
                frozen = Object.isFrozen(o)
                live.ephemeralRecipient = 'age1swapped'
                return true
            },
        })
        expect(frozen).toBe(true)
        expect(h.rc.calls[0]!.op.ephemeralRecipient).toBe('age1judged')
        expect(em.runs[0]!.op.ephemeralRecipient).toBe('age1judged')
    })

    it('does not warn about a check the caller’s own abort ended', async () => {
        const ac = new AbortController()
        const h = harness([op(1)])
        await h.run(
            chat(),
            {
                admitNode: () => {
                    ac.abort()
                    throw new Error('aborted')
                },
            },
            ac.signal,
        )
        expect(h.logged.filter((l) => l.msg === 'admit check failed; refusing operator')).toEqual([])
    })
})

// A node may refuse a payer with no prepaid pool at reserve, so the pool is
// funded before the first reserve rather than only inside open.
describe('the prepaid pool before reserve', () => {
    const body = chat(',"max_tokens":100')
    const preparing = (fail?: unknown, deps: Partial<DispatchDeps> = {}, onPrepare?: () => void, ops = [op(1)]) => {
        const h: { calls: number; reservesBefore: number; signal?: AbortSignal | undefined } = { calls: 0, reservesBefore: -1 }
        let rc: ReserveClient & { calls: Call[] }
        const wallet = {
            payerAddr: () => 'PAYER',
            prepareDeposit: async (signal?: AbortSignal) => {
                h.calls++
                h.reservesBefore = rc.calls.length
                h.signal = signal
                onPrepare?.()
                if (fail !== undefined) throw fail
            },
        }
        const harnessed = harness(ops, { deps: { wallet, ...deps } })
        rc = harnessed.rc
        return { ...harnessed, prep: h }
    }

    it('is not funded for a request the spend cap refuses', async () => {
        const refuseAll: SpendGuard = {
            admit() {
                throw new Error('over the cap')
            },
            reserve() {},
            settle() {},
            release() {},
        }
        const priced = withCap(op(1), { inputUsdPer1m: 1, outputUsdPer1m: 2 })
        const h = preparing(undefined, { feeRate: () => 0, spendGuard: refuseAll }, undefined, [priced])
        const em = await h.run(body)
        expect(em.failed?.code).toBe('spend_cap_exceeded')
        expect(h.prep.calls).toBe(0)
    })

    // An async guard's refusal would land after the reserve it was meant to
    // stop, and unobserved it ends a Node process: refused, its rejection caught.
    it('refuses an admit guard that answers with a Promise', async () => {
        const asyncAdmit = {
            admit: () => Promise.reject(new Error('over the cap')),
            reserve() {},
            settle() {},
            release() {},
        } as unknown as SpendGuard
        const priced = withCap(op(1), { inputUsdPer1m: 1, outputUsdPer1m: 2 })
        const h = preparing(undefined, { feeRate: () => 0, spendGuard: asyncAdmit }, undefined, [priced])
        const em = await h.run(body)
        expect(em.failed?.code).toBe('spend_cap_exceeded')
        expect(em.failed?.message).toContain('SpendGuard.admit returned a Promise')
        expect(em.failed?.message).not.toContain('raise')
        expect(h.prep.calls).toBe(0)
    })

    it('runs under the turn’s signal, and a turn aborted during it ends without a funds error', async () => {
        const ac = new AbortController()
        const h = preparing(new MbrDepositUnaffordableError(0n, 10n, 50_000n, 1_000n), {}, () => ac.abort())
        const em = await h.run(body, {}, ac.signal)
        expect(h.prep.signal).toBe(ac.signal)
        expect(em.failed?.code).not.toBe('mbr_pool_underfunded')
        expect(h.logged.some((l) => l.msg.startsWith('prepaid pool'))).toBe(false)
    })

    it('is funded once, before the first reserve', async () => {
        const h = preparing()
        const em = await h.run(body)
        expect(em.failed).toBeUndefined()
        expect(h.prep).toEqual({ calls: 1, reservesBefore: 0 })
        expect(em.runs).toHaveLength(1)
    })

    it.each([
        ['unaffordable', new MbrDepositUnaffordableError(0n, 10n, 50_000n, 1_000n), 'mbr_pool_underfunded'],
        ['below target', new BelowTargetError(115_000n), 'mbr_pool_underfunded'],
        ['a deposit that overspends', new Error('wallet: deposit: TransactionPool.Remember: overspend'), 'wallet_unfunded'],
    ])('a pool the payer can’t fund (%s) ends the turn before any reserve', async (_name, err, code) => {
        const h = preparing(err)
        const em = await h.run(body)
        expect(em.failed).toMatchObject({ code, kind: 'funds' })
        expect(em.failed!.message).toContain('PAYER')
        expect(em.failed!.message).toContain('fund it')
        expect(h.rc.calls).toEqual([])
    })

    it('goes on past a failure that says nothing about funds', async () => {
        const h = preparing(new Error('wallet: deposit-shortfall read: connection refused'))
        const em = await h.run(body)
        expect(em.failed).toBeUndefined()
        expect(h.rc.calls).toHaveLength(1)
        expect(h.logged.some((l) => l.level === 'warn' && l.msg === 'prepaid pool check failed before reserve; continuing')).toBe(true)
    })

    it('is not funded for a request no node can serve', async () => {
        const h = preparing(new MbrDepositUnaffordableError(0n, 10n, 50_000n, 1_000n))
        const em = await h.run(`{"model":"no-such-model","messages":[],"max_tokens":100}`)
        expect(em.failed?.code).toBe('no_operator')
        expect(h.prep.calls).toBe(0)
    })
})

describe('the sweep', () => {
    it('falls through a busy node to a healthy one', async () => {
        const h = harness([op(1), op(2)], { answer: perNode({ 1: () => busy() }) })
        const em = await h.run(chat())
        expect(ids(h.rc.calls)).toEqual([1, 2])
        expect(em.runs[0]!.op.id).toBe(2)
    })

    it('ends operators_busy with the node’s hint, capped at five minutes, after two busy re-sweeps', async () => {
        for (const [hint, want] of [
            [5000, 5000],
            [86_400_000, 300_000],
        ]) {
            const h = harness([op(1)], { answer: perNode({ 1: () => busy(hint) }), deps: { sweepDelay: () => 0 } })
            const em = await h.run(chat())
            expect(em.failed).toMatchObject({
                code: 'operators_busy',
                kind: 'busy',
                retryAfter: want,
                message: 'all eligible operators are at capacity; retry after the hint',
            })
            // Literal 3, one pass plus two busy re-sweeps: derived from the
            // constant, it would pass with no re-sweep at all.
            expect(h.rc.calls).toHaveLength(3)
        }
    })

    it('waits out the node’s hint, capped, and re-sweeps only inside the busy budget', async () => {
        // Each reserve takes 3s: the second pass ends at 9s, past the 8s budget.
        let h: Harness
        h = harness([op(1)], {
            answer: async () => {
                h.advance(3000)
                throw busy(5000)
            },
        })
        let em = await h.run(chat())
        expect(h.sleeps).toEqual([3000])
        expect(h.rc.calls).toHaveLength(2)
        expect(em.failed).toMatchObject({ code: 'operators_busy', retryAfter: 5000 })

        // A hint-less 429 waits the 1s default.
        h = harness([op(1)], { answer: async () => Promise.reject(busy()) })
        em = await h.run(chat())
        expect(h.sleeps).toEqual([1000, 1000])
        expect(em.failed!.retryAfter).toBeUndefined()

        // Inside the budget after the pass, but the 3s wait isn't: no re-sweep.
        h = harness([op(1)], {
            answer: async () => {
                h.advance(6000)
                throw busy(5000)
            },
        })
        em = await h.run(chat())
        expect(h.sleeps).toEqual([])
        expect(h.rc.calls).toHaveLength(1)
        expect(em.failed).toMatchObject({ code: 'operators_busy', retryAfter: 5000 })
    })

    it('keeps the largest busy hint, not the last', async () => {
        const h = harness([op(1), op(2)], { answer: perNode({ 1: () => busy(9000), 2: () => busy(2000) }), deps: { sweepDelay: () => 0 } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({ code: 'operators_busy', retryAfter: 9000 })
    })

    it('serves the request once a busy node’s queue drains', async () => {
        const h = harness([op(1)], { answer: perNode({ 1: (n) => (n === 0 ? busy(1000) : reservedFor(op(1), {} as Req)) }), deps: { sweepDelay: () => 0 } })
        const em = await h.run(chat())
        expect(em.failed).toBeUndefined()
        expect(em.runs).toHaveLength(1)
        expect(em.notes.filter((e) => e.type === 'route.candidates')).toHaveLength(2)
        expect(h.logged.map((l) => l.msg)).toContain('every operator was at capacity; re-sweeping after the hinted wait')
    })

    it('does not re-ask a busy node whose code says waiting won’t help', async () => {
        for (const code of ['payer_slot_cap', 'reserve_temporarily_banned', 'rate_limited', 'some_unknown_future_code', '']) {
            const h = harness([op(1)], { answer: perNode({ 1: () => busy(1000, code) }), deps: { sweepDelay: () => 0 } })
            const em = await h.run(chat())
            expect(em.failed!.code).toBe('operators_busy')
            expect(h.rc.calls, code).toHaveLength(1)
        }
    })

    it('reads a hint-less 429 as capacity, over a missing ephemeral, and invents no hint', async () => {
        const h = harness([op(1), op(2)], { answer: perNode({ 1: () => busy(), 2: () => new NoEphemeralError() }), deps: { sweepDelay: () => 0 } })
        const em = await h.run(chat())
        expect(em.failed!.code).toBe('operators_busy')
        expect(em.failed!.retryAfter).toBeUndefined()
        expect(h.rc.calls.filter((c) => c.op.id === 1).length).toBeGreaterThanOrEqual(2)
    })

    it('lets a size refusal outrank busy, without a busy re-sweep', async () => {
        const h = harness([op(1), op(2)], { answer: perNode({ 1: () => busy(1000), 2: () => sizeRefusal() }), deps: { sweepDelay: () => 0 } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({ code: 'context_length_exceeded', kind: 'context_exceeded' })
        expect(em.failed!.message).toContain('op 2: max_output_tokens exceeds this operator (context_length_exceeded)')
        expect(em.failed!.retryAfter).toBeUndefined()
        expect(ids(h.rc.calls)).toEqual([1, 2])
    })

    it('reports every node’s size refusal, and does not retry one', async () => {
        const h = harness([op(1), op(2)], { answer: async () => Promise.reject(sizeRefusal()) })
        const em = await h.run(chat())
        expect(em.failed!.message).toMatch(
            /^no operator serves gpt-test with input_tokens=\d+ max_output_tokens=128\n {2}operators rejected the request at reserve time:\n {2}- op 1: max_output_tokens exceeds this operator \(context_length_exceeded\)\n {2}- op 2: /,
        )
        expect(ids(h.rc.calls)).toEqual([1, 2])
    })

    it('rides out a gateway outage, then says the pool is unreachable rather than busy', async () => {
        const h = harness([op(1), op(2)], { answer: async () => Promise.reject(gateway()), deps: { retryBudget: 1500 } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({ code: 'operators_unreachable', kind: 'unreachable', retryAfter: 30_000 })
        expect(em.failed!.message).toBe(
            `every operator serving ${MODEL} is currently unreachable through its gateway, and none refused the request; this usually clears within a minute — retry after the hint`,
        )
        const a = h.rc.calls.filter((c) => c.op.id === 1).length
        const b = h.rc.calls.filter((c) => c.op.id === 2).length
        expect(a).toBeGreaterThanOrEqual(1)
        expect(b).toBeGreaterThanOrEqual(1)
        expect(a + b).toBeGreaterThanOrEqual(3)
    })

    it('re-sweeps a pure outage, and a refusal in a later sweep keeps it from reading unreachable', async () => {
        const h = harness([op(1)], {
            answer: perNode({ 1: (n) => (n === 0 ? gateway() : new ReserveHTTPError({ status: 503, code: 'provider_unavailable' })) }),
            deps: { sweepDelay: () => 0, retryBudget: 300 },
        })
        const em = await h.run(chat())
        expect(em.failed!.code).toBe('operators_busy')
        expect(h.rc.calls).toHaveLength(2)
        expect(h.logged.map((l) => l.msg)).toContain('every operator failed transiently; re-sweeping the candidate list')
    })

    it('waits out the largest gateway Retry-After before re-sweeping, over the 4s schedule', async () => {
        const hinted = (ms: number) => () => new ReserveHTTPError({ status: 503, retryAfterMs: ms })
        const h = harness([op(1), op(2)], { answer: perNode({ 1: hinted(5000), 2: hinted(2000) }) })
        await h.run(chat())
        // Each node's two inner retries wait its own hint; the sweep waits the largest.
        expect(h.sleeps.slice(0, 5)).toEqual([5000, 5000, 2000, 2000, 5000])
    })

    it('gives up rather than re-sweep when the hinted wait outruns the retry budget', async () => {
        const h = harness([op(1)], {
            answer: async () => Promise.reject(new ReserveHTTPError({ status: 503, retryAfterMs: 50_000 })),
        })
        const em = await h.run(chat())
        expect(h.sleeps).toEqual([50_000])
        expect(h.rc.calls).toHaveLength(2)
        expect(em.failed!.code).toBe('operators_unreachable')
    })

    it('ends with what it knows when the re-pick fails or comes back empty', async () => {
        for (const later of [() => Promise.reject(new Error('down')), async () => []]) {
            let h: Harness
            h = harness([op(1)], {
                answer: async () => Promise.reject(gateway()),
                registry: { operators: async () => (h.rc.calls.length === 0 ? [op(1)] : later()) },
                deps: { sweepDelay: () => 0 },
            })
            const em = await h.run(chat())
            expect(em.failed!.code).toBe('operators_unreachable')
            expect(h.rc.calls).toHaveLength(3)
            // No empty candidate list is announced.
            expect(em.notes.filter((e) => e.type === 'route.candidates')).toHaveLength(1)
        }
    })

    it('re-draws the relay pool for each re-sweep', async () => {
        let draws = 0
        const ops = [op(1), op(2), op(3)]
        const h = harness(ops, {
            deps: { privacy: 'relay_required', sweepDelay: () => 0 },
            registry: {
                allOperators: async () => {
                    draws++
                    return ops
                },
            },
            answer: async () => Promise.reject(gateway()),
        })
        const em = await h.run(chat())
        const sweeps = em.notes.filter((e) => e.type === 'route.candidates').length
        expect(sweeps).toBeGreaterThan(1)
        expect(draws).toBe(sweeps)
    })

    it('fails no_ephemeral_capacity when no node has one, with no hint', async () => {
        const h = harness([op(1), op(2)], { answer: async () => Promise.reject(new NoEphemeralError()) })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({
            code: 'no_ephemeral_capacity',
            message: 'no operator with a valid forward-secrecy ephemeral recipient can serve this request',
        })
        expect(em.failed!.retryAfter).toBeUndefined()
    })

    it('ends at a payer refusal with the node’s code, message and reset', async () => {
        for (const code of ['free_quota_exhausted', 'unlisted_payer_refusal']) {
            const h = harness([op(1), op(2)], {
                answer: async () => Promise.reject(new PayerRefusalError(code, 'daily free tickets used', 3_600_000)),
            })
            const em = await h.run(chat())
            expect(em.failed).toMatchObject({ code, kind: 'funds', message: 'daily free tickets used', retryAfter: 3_600_000 })
            expect(h.rc.calls).toHaveLength(1)
        }
    })

    it('stops when the caller leaves, unpaid and canceled', async () => {
        const ac = new AbortController()
        const h = harness([op(1), op(2)], {
            answer: async () => {
                ac.abort(new Error('caller left'))
                throw busy(1000)
            },
        })
        const em = await h.run(chat(), {}, ac.signal)
        expect(em.failed).toMatchObject({
            code: 'canceled',
            kind: 'interrupted',
            paid: false,
            message: 'the request ended before any operator was paid',
        })
        expect((em.failed!.cause as Error).message).toBe('caller left')
        expect(h.rc.calls).toHaveLength(1)
    })

    it('announces the candidates, and the route to each', async () => {
        const h = harness([op(1), op(2)], { answer: perNode({ 1: () => busy() }) })
        const em = await h.run(chat())
        expect(em.notes.filter((e) => e.type !== 'reserve.started')).toEqual([
            { type: 'route.candidates', model: MODEL, candidates: [{ op: 1, node: 0 }, { op: 2, node: 0 }] },
            { type: 'relay.hop', relay: null, target: { op: 1, node: 0 }, reason: 'chosen' },
            { type: 'relay.hop', relay: null, target: { op: 2, node: 0 }, reason: 'chosen' },
        ])
    })

    it('clears a served node’s backoff and records the round trip it rode; a gateway failure strikes it', async () => {
        const targetBackoff = new TargetBackoffStore(Date.now)
        const relayLatency = new RelayLatencyStore({ clock: Date.now })
        const backoff = vi.spyOn(targetBackoff, 'recordTargetOutcome')
        const rtt = vi.spyOn(relayLatency, 'recordDirectRtt')
        const h = harness([op(1), op(2)], {
            pick: { targetBackoff, relayLatency },
            answer: perNode({ 1: () => gateway() }),
            deps: { retryBudget: 0 },
        })
        await h.run(chat())
        expect(backoff.mock.calls).toEqual([
            [{ op: 1, node: 0 }, false],
            [{ op: 2, node: 0 }, true],
        ])
        expect(rtt).toHaveBeenCalledWith({ op: 2, node: 0 }, 0)
    })

    it('records a relayed reserve’s round trip against its relay and target', async () => {
        const relayLatency = new RelayLatencyStore({ clock: Date.now })
        const rtt = vi.spyOn(relayLatency, 'recordRelayedRtt')
        let h: Harness
        h = harness([op(1), op(2), op(3)], {
            deps: { privacy: 'relay_required' },
            pick: { relayLatency },
            answer: async (o, req) => {
                h.advance(40)
                return reservedFor(o, req)
            },
        })
        await h.run(chat())
        const hop = h.rc.calls[0]!.hop!
        expect(rtt).toHaveBeenCalledWith(relayRef(hop), targetRef(hop), 40)
    })
})

describe('the ticket', () => {
    const pricedOp = (id: number) => withCap(op(id), { inputUsdPer1m: 1, outputUsdPer1m: 2 })
    // A ticket at pricedOp's $1/$2 per 1M: 1 and 2 microUSDC a token, no fee.
    const honest = (o: Operator, req: Req): Reserved => {
        const r = reservedFor(o, req)
        Object.assign(r.ticket, {
            input_rate: 1_000_000,
            output_rate: 2_000_000,
            min_price: 0,
            max_price: req.input_count + 2 * req.max_output_count,
        })
        return r
    }
    // A ticket signed far above any advertised rate.
    const overpriced = (o: Operator, req: Req): Reserved => {
        const r = reservedFor(o, req)
        Object.assign(r.ticket, { input_rate: 1e9, output_rate: 1e9, max_price: 1e9 })
        return r
    }

    function spend(o: { reserveErr?: (id: string) => Error | undefined } = {}) {
        const asks: [string, number][] = []
        const g: SpendGuard & { asks: typeof asks } = {
            asks,
            admit() {},
            reserve(id, max) {
                asks.push([id, max])
                const err = o.reserveErr?.(id)
                if (err) throw err
            },
            settle() {},
            release() {},
        }
        return g
    }

    it('reserves the signed ceiling, then hands the ticket to the sealed run', async () => {
        const g = spend()
        const h = harness([op(1)], { deps: { spendGuard: g } })
        const em = await h.run(chat(',"stream":true'))
        expect(g.asks).toEqual([['T1', 1000]])
        const run = em.runs[0]!
        expect(run).toMatchObject({ endpoint: '/v1/chat/completions', model: MODEL, stream: true, hop: null })
        expect(run.reserved.ticket.ticket_id).toBe('T1')
        expect(h.logged.find((l) => l.msg === 'reserve response')!.attrs).toMatchObject({
            operator_id: 1,
            node_id: 0,
            ticket_id: 'T1',
            max_price_microusdc: 1000,
            max_price_usd: '$0.001000',
        })
    })

    it('accepts a ticket signed at the advertised rates', async () => {
        const h = harness([pricedOp(1)], { deps: { feeRate: () => 0 }, answer: async (o, req) => honest(o, req) })
        const em = await h.run(chat())
        expect(em.failed).toBeUndefined()
        expect(em.runs).toHaveLength(1)
    })

    it('refuses a mis-priced ticket and tries the next node', async () => {
        const h = harness([pricedOp(1), pricedOp(2)], {
            deps: { feeRate: () => 0 },
            answer: async (o, req) => (o.id === 1 ? overpriced(o, req) : honest(o, req)),
        })
        let em = await h.run(chat())
        expect(em.runs[0]!.op.id).toBe(2)
        expect(h.logged.find((l) => l.msg === 'reserve refused: ticket price failed verification; trying next operator')!.attrs).toMatchObject({
            operator_id: 1,
            node_id: 0,
        })

        // An input_count above the payer's own, priced consistently, is
        // caught against the count the request carried.
        const inflated = harness([pricedOp(1)], {
            deps: { feeRate: () => 0 },
            answer: async (o, req) => honest(o, { ...req, input_count: req.input_count * 3 }),
        })
        em = await inflated.run(chat())
        expect(em.failed!.code).toBe('ticket_price_rejected')

        const all = harness([pricedOp(1)], { deps: { feeRate: () => 0 }, answer: async (o, req) => overpriced(o, req) })
        em = await all.run(chat())
        expect(em.failed).toMatchObject({
            code: 'ticket_price_rejected',
            kind: 'operator_fault',
            message: 'every eligible operator returned a ticket whose price failed verification (mis-priced or internally inconsistent)',
        })
    })

    // SPEC § 3a: with no fee to price against, and for an image-tool reserve,
    // max_price is bounded from above rather than recomputed exactly, so an
    // honest ceiling passes and an inflated one or an inflated rate is refused.
    it('bounds max_price with no fee to price against, and for an image-tool reserve', async () => {
        const inflatedCeiling = (o: Operator, req: Req): Reserved => {
            const r = honest(o, req)
            r.ticket.max_price = 1e9
            return r
        }
        for (const [answer, runs] of [
            [honest, 1],
            [inflatedCeiling, 0],
            [overpriced, 0],
        ] as const) {
            let h = harness([pricedOp(1)], { answer: async (o, req) => answer(o, req) })
            let em = await h.run(chat())
            expect(em.runs, `no fee, ${answer.name}`).toHaveLength(runs)

            for (const budget of ['"zs_image_generation":{"max_n":1}', '"zs_image_edit":{"max_n":1}']) {
                const tooled = withCap(pricedOp(1), { inputUsdPer1m: 1, outputUsdPer1m: 2, imageToolRateMicroUsdc: 80_000, imageEditToolRateMicroUsdc: 80_000 })
                h = harness([tooled], { deps: { feeRate: () => 0 }, answer: async (o, req) => answer(o, req) })
                em = await h.run(`{"model":"${MODEL}","input":[],"max_output_tokens":50,"tool_budgets":{${budget}}}`, {
                    endpoint: '/v1/responses',
                })
                expect(em.runs, `${budget}, ${answer.name}`).toHaveLength(runs)
            }
        }
    })

    it('lets a busy node outrank a mis-priced ticket', async () => {
        const h = harness([pricedOp(1), pricedOp(2)], {
            deps: { feeRate: () => 0, sweepDelay: () => 0 },
            answer: async (o, req) => {
                if (o.id === 1) throw busy(2000)
                return overpriced(o, req)
            },
        })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({ code: 'operators_busy', retryAfter: 2000 })
    })

    // Whatever the Promise would resolve to: an allowing one is still too late.
    // No other candidate can cure it, so the request ends at the first.
    it('ends the request at a reserve guard that answers with a Promise, even an allowing one', async () => {
        let asks = 0
        const asyncReserve = {
            admit() {},
            reserve: () => {
                asks++
                return Promise.resolve()
            },
            settle() {},
            release() {},
        } as unknown as SpendGuard
        const h = harness([op(1), op(2)], { deps: { spendGuard: asyncReserve } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({ code: 'spend_cap_exceeded', kind: 'spend_cap' })
        expect(em.failed!.message).toContain('SpendGuard.reserve returned a Promise')
        expect(em.failed!.message).not.toContain('raise')
        expect(asks).toBe(1)
        expect(em.runs).toEqual([])
    })

    it('moves on past a ticket over the cap, and fails spend_cap_exceeded when every one is', async () => {
        let g = spend({ reserveErr: (id) => (id === 'T1' ? new Error('daily spend cap exceeded') : undefined) })
        let h = harness([op(1), op(2)], { deps: { spendGuard: g } })
        let em = await h.run(chat())
        expect(em.runs[0]!.op.id).toBe(2)
        expect(g.asks.map(([id]) => id)).toEqual(['T1', 'T2'])

        g = spend({ reserveErr: () => new Error('daily spend cap exceeded') })
        h = harness([op(1)], { deps: { spendGuard: g } })
        em = await h.run(chat())
        expect(em.failed).toMatchObject({
            code: 'spend_cap_exceeded',
            kind: 'spend_cap',
            message: 'spend cap reached: this request would exceed the configured USDC limit — to fix it, raise the cap remedy.',
        })
        expect(em.runs).toEqual([])
    })

    it('lets a busy node outrank the cap, without a busy re-sweep', async () => {
        const g = spend({ reserveErr: () => new Error('daily spend cap exceeded') })
        const h = harness([op(1), op(2)], { deps: { spendGuard: g, sweepDelay: () => 0 }, answer: perNode({ 1: () => busy(7000) }) })
        const em = await h.run(chat())
        expect(em.failed!.code).toBe('operators_busy')
        expect(g.asks).toHaveLength(1)
    })

    it('lets the cap outrank a missing tool price, a mis-priced ticket and a missing ephemeral', async () => {
        const capped = () => spend({ reserveErr: () => new Error('daily spend cap exceeded') })
        let h = harness([withCap(op(1), { imageToolRateMicroUsdc: 100_000 }), withCap(op(2), {})], { deps: { spendGuard: capped() } })
        let em = await h.run(`{"model":"${MODEL}","input":[],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":2}}}`, {
            endpoint: '/v1/responses',
        })
        expect(em.failed!.code).toBe('spend_cap_exceeded')

        h = harness([op(1), pricedOp(2)], { deps: { spendGuard: capped(), feeRate: () => 0 }, answer: async (o, req) => overpriced(o, req) })
        em = await h.run(chat())
        expect(em.failed!.code).toBe('spend_cap_exceeded')

        h = harness([op(1), op(2)], { deps: { spendGuard: capped() }, answer: perNode({ 2: () => new NoEphemeralError() }) })
        em = await h.run(chat())
        expect(em.failed!.code).toBe('spend_cap_exceeded')
    })

    it('ends at a reused ticket id as the operator’s fault, not the cap', async () => {
        const g = spend({ reserveErr: () => new Error('wrapped', { cause: new DuplicateTicketError() }) })
        const h = harness([op(1), op(2)], { deps: { spendGuard: g } })
        const em = await h.run(chat())
        expect(em.failed).toMatchObject({
            code: 'operator_ticket_reuse',
            kind: 'operator_fault',
            message: 'the operator issued a ticket id that is already in flight for this payer; no payment was made',
        })
        expect(em.runs).toEqual([])
        expect(g.asks).toHaveLength(1)
    })
})

describe('the Client’s parts', () => {
    const signer: Signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }

    it('stay out of the package exports', async () => {
        const sdk = await import('../src/index.js')
        for (const name of [
            'dispatchDepsOf',
            'partsOf',
            'sleep',
            'dispatch',
            'runSealed',
            'forwardBuffered',
            'openAIError',
            'checkTurnReceipt',
            'SettleSlot',
            'Settles',
            'bufferedResponder',
            'usageEvents',
            'openAIErrorBody',
            'truncateForLog',
            'openCommittedKey',
            'openSealedResponseMeta',
            'settleGroupOf',
            'forwardStream',
            'frameFactory',
            'pumpSSE',
            'StreamTally',
            'frameSSE',
            'emptyFrame',
            'isEmptyFrame',
            'streamApiFor',
            'Watchdog',
            'refundSources',
            'Reconciler',
            'walletChain',
            'walletParts',
            'journalOpen',
            'journalReceipt',
            'idle',
            'StreamEmitter',
            'TurnStream',
            'turnOf',
            'errorResponse',
            'errorShapes',
            'openAIErrorResponse',
            'copyResponseHeaders',
            'stripZsHeaders',
            'setUsageHeaders',
            'usageFrame',
            'feeBreakdownFor',
            'goJSON',
            'dollars',
        ]) {
            expect(sdk, name).not.toHaveProperty(name)
        }
    })

    it('reach dispatch: affinity, staging, max_output and privacy as configured', async () => {
        const ops = [op(1, { staging: true }), op(2)]
        // Busy, so only strict keeps the turn off op 2.
        const rc = reserveClient(perNode({ 1: () => busy() }))
        const c = await Client.create({
            signer,
            network: { algodEndpoint: 'http://127.0.0.1:1', algodToken: '', escrowAppId: 1n } as never,
            registry: registryOf(ops),
            reserveClient: rc,
            wallet: { open: () => Promise.reject(new Error('unused')), payerAddr: () => 'PAYER' },
            affinity: { policy: 'strict' },
            allowStaging: true,
            privacy: 'direct',
            maxOutputByModel: { [MODEL]: 77 },
            sweepDelay: () => 0,
        })
        const runs: SealedRun[] = []
        const deps = dispatchDepsOf(c, async (_em, run) => {
            runs.push(run)
        })
        const em = new Recorder()
        // A strict pin to the staging node: only allowStaging lets it route,
        // and only strict keeps it to that node.
        deps.pick.toolAffinity.record({ op: 1, node: 0 }, ['call_1'])
        await dispatch(deps, em, turnOf({ endpoint: '/v1/chat/completions', body: `{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"call_1"}]}` }))
        expect(em.failed!.code).toBe('operators_busy')
        expect(ids(rc.calls)).toEqual([1, 1, 1])
        expect(rc.calls[0]!.req.max_output_count).toBe(77)
        expect(rc.calls[0]!.hop).toBeNull()
        c.close()

        const strict = await Client.create({
            signer,
            network: { algodEndpoint: 'http://127.0.0.1:1', algodToken: '', escrowAppId: 1n } as never,
            registry: registryOf([op(2)]),
            reserveClient: reserveClient(),
            wallet: { open: () => Promise.reject(new Error('unused')), payerAddr: () => 'PAYER' },
            requireMaxOutput: true,
            privacy: 'direct',
        })
        const em2 = new Recorder()
        await dispatch(dispatchDepsOf(strict, async () => {}), em2, turnOf({ endpoint: '/v1/chat/completions', body: chat() }))
        expect(em2.failed!.code).toBe('max_output_required')
        strict.close()
    })

    it('reach dispatch: the spend guard, the warmed fee rate and the rest of the config', async () => {
        const estimates: number[] = []
        const spendGuard: SpendGuard = {
            admit(est) {
                estimates.push(est)
                throw new Error('over the cap')
            },
            reserve() {},
            settle() {},
            release() {},
        }
        const rc = reserveClient()
        const c = await Client.create({
            signer,
            network: { algodEndpoint: 'http://127.0.0.1:1', algodToken: '', escrowAppId: 1n } as never,
            registry: registryOf([withCap(op(1), { inputUsdPer1m: 1, outputUsdPer1m: 2 })]),
            reserveClient: rc,
            wallet: { open: () => Promise.reject(new Error('unused')), payerAddr: () => 'PAYER', protocolFeeBps: async () => 250 },
            spendGuard,
            privacy: 'direct',
            allowPrivacyOverride: true,
            requireTeeModels: ['other'],
            retryBudget: 1234,
            remedies: { raiseSpendCap: 'raise it here' },
        })
        // The warm read create started lands.
        await new Promise((r) => setTimeout(r, 0))
        const deps = dispatchDepsOf(c, async () => {})
        expect(deps.feeRate()).toBe(250)
        const cfg = c.config
        expect(deps).toMatchObject({
            allowPrivacyOverride: true,
            requireTeeModels: ['other'],
            retryBudget: 1234,
            remedies: cfg.remedies,
        })
        expect(deps.clock).toBe(cfg.clock)

        // Admission needs both the guard and a fee rate, and runs before any reserve.
        const em = new Recorder()
        await dispatch(deps, em, turnOf({ endpoint: '/v1/chat/completions', body: chat(',"max_tokens":100') }))
        expect(em.failed!.code).toBe('spend_cap_exceeded')
        expect(em.failed!.message).toContain('raise it here')
        expect(estimates).toHaveLength(1)
        expect(rc.calls).toEqual([])
        c.close()
    })
})
