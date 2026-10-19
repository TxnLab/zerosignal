/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Client.stream end to end against a node that seals its answers: what a paid
// turn reports, and the escrow, watchdog and journal work it leaves.

import { describe, expect, it, vi } from 'vitest'

import type { Ticket } from '@txnlab/zs-proto/ticket'
import {
    ENCRYPTED_CONTENT_TYPE,
    PROTO_VERSION,
    RECEIPT_HEADER,
    RESPONSE_KEY_HEADER,
    ResponseSealer,
    SEALED_HEADER_RECEIPT,
    SEALED_HEADER_SETTLE_GROUP,
    bodyHashFromFrames,
    generateEphemeralIdentity,
} from '@txnlab/zs-proto/wire'
import { encodeReceiptHeader } from '@txnlab/zs-proto/ticket'

import {
    Client,
    type Config,
    type Event,
    IDAffinity,
    type RegistryProvider,
    type Signer,
    type SpendGuard,
    type TicketJournal,
    memoryJournal,
    testnet,
} from '../src/index.js'
import { retryable } from '../src/codes.js'
import { ZsError, findError } from '../src/errors.js'
import { IdleWatchdog, StreamIdleTimeoutError } from '../src/idle.js'
import { MbrDepositUnaffordableError } from '../src/mbr.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import type { Request } from '../src/turn.js'
import { partsOf } from '../src/client-parts.js'
import type { OpenHandle, Reserved, SettleOutcome } from '../src/parts.js'
import type { Fetch } from '../src/ports.js'
import { TICKET_ID, VALID_GROUP, fixture, handleOf } from './turn-fixtures.js'

// The default fetch reaches the harness's node, and the header backstop
// counts the requests it carries, so a test can see which ones get it.
const defaultFetchHook = vi.hoisted(() => ({
    fetch: undefined as Fetch | undefined,
    backstopped: [] as string[],
    // The fetch each SDK-built reserve client was handed.
    reserveFetches: [] as unknown[],
}))
vi.mock('../src/parts.js', async (importOriginal) => {
    const m = await importOriginal<typeof import('../src/parts.js')>()
    return {
        ...m,
        httpReserveClient: (o: Parameters<typeof m.httpReserveClient>[0]) => {
            defaultFetchHook.reserveFetches.push(o.fetch)
            return m.httpReserveClient(o)
        },
    }
})
vi.mock('#default-fetch', () => ({
    defaultFetch: (): Fetch => (url, init) => defaultFetchHook.fetch!(url, init),
}))
vi.mock('../src/header-backstop.js', async (importOriginal) => {
    const m = await importOriginal<typeof import('../src/header-backstop.js')>()
    return {
        withHeaderBackstop: (f: Fetch, ms: number): Fetch => {
            const inner = m.withHeaderBackstop(f, ms)
            return (url, init) => {
                defaultFetchHook.backstopped.push(String(url))
                return inner(url, init)
            }
        },
    }
})

const enc = new TextEncoder()
const MODEL = 'gpt-test'
const CHAT = '/v1/chat/completions'

const signer: Signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }

const ANSWER = '{"choices":[{"index":0,"message":{"content":"hi"},"finish_reason":"stop"}]}'
const FRAMES = ['{"choices":[{"index":0,"delta":{"content":"hi"}}]}', '{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}']

interface Node {
    /** The node's answer to one sealed request. */
    answer(sealer: ResponseSealer, init: RequestInit): Response
}

interface HarnessOptions {
    stream?: boolean
    outcomes?: (SettleOutcome | Error)[]
    group?: boolean
    groupRejected?: boolean
    journal?: TicketJournal
    /** A whole reply's plaintext, ANSWER by default. */
    plaintext?: string
    /** Streamed: send the first frame, then hold the stream open until the request is aborted. */
    hold?: boolean
    /** A whole reply: send the start of the sealed body, then hold until the request is aborted. */
    holdReply?: boolean
    /** The plaintext of the frame a held stream sends, the first content frame by default. */
    holdFrame?: string
    /** Streamed: send the content, then the receipt tail a moment later, unless the request is aborted first. */
    lateTail?: boolean
    /** The open handle carries no operator, so the journal row can't be built. */
    noOperator?: boolean
    /** Route through a relay of another owner. */
    relay?: boolean
    openErr?: unknown
    /** The wallet's prepaid-pool check before the reserve fails with this. */
    prepareErr?: unknown
    feeBps?: number
    /** Leave Config.fetch unset, so the Client builds its default. */
    defaultFetch?: boolean
    /** Leave Config.reserveClient unset, so the reserve rides Config.fetch. */
    sdkReserve?: boolean
    config?: Partial<Config>
}

async function harness(o: HarnessOptions = {}) {
    const stream = o.stream ?? false
    const frames = FRAMES.map((t) => enc.encode(t))
    const f = stream ? await fixture({}, enc.encode(''), bodyHashFromFrames(frames)) : await fixture({}, enc.encode(o.plaintext ?? ANSWER))
    const identity = await generateEphemeralIdentity()
    const nodeKey = await generateEphemeralIdentity()
    const sealer = await ResponseSealer.create({ replyTo: identity.recipient, txID: 'APPCALL', ticketID: TICKET_ID, key: f.responseKey })
    const op = { ...f.op, baseUrl: 'https://n7.example.com', models: [MODEL], protoVersion: PROTO_VERSION }
    const ticket = {
        ...f.ticket,
        model: MODEL,
        input_count: 10,
        max_output_count: 100,
        input_rate: 0,
        output_rate: 0,
        cache_read_rate: 0,
        min_price: 0,
        stream,
        expires_at: 2_000_000_000,
        sig: '',
    } as unknown as Ticket
    const handle = Object.assign(
        handleOf({ txid: 'ACK', groupRejected: o.groupRejected ?? false, ...(o.outcomes ? { outcomes: o.outcomes } : {}) }),
        o.noOperator ? {} : { operator: op },
    )
    const relayOp = { ...op, id: 8, ownerAddr: 'OWNER8', baseUrl: 'https://r8.example.com', models: ['other-model'] }
    const fleet = o.relay ? [op, relayOp] : [op]
    const registry: RegistryProvider = {
        operators: async () => [op],
        resolve: async () => undefined,
        allOperators: async () => fleet,
        reprobeEphemeral: async () => null,
        recordModelDemand: () => {},
    }
    const node: Node = {
        answer: (s, init) => {
            if (o.hold) {
                const pt = o.holdFrame === undefined ? frames[0]! : enc.encode(o.holdFrame)
                const first = `event: zs\ndata: ${s.sealStreamFrame(pt)}\n\n`
                const body = new ReadableStream<Uint8Array>({
                    start(ctl) {
                        ctl.enqueue(enc.encode(first))
                        init.signal?.addEventListener('abort', () => ctl.error(init.signal!.reason), { once: true })
                    },
                })
                return new Response(body, { headers: { 'Content-Type': 'text/event-stream', [RESPONSE_KEY_HEADER]: s.wrappedKeyHeader() } })
            }
            if (o.lateTail) {
                // The content, the finishing frame and the receipt tail, each
                // a moment apart, so a reader can leave between them.
                const steps = [
                    ...frames.map((pt) => `event: zs\ndata: ${s.sealStreamFrame(pt)}\n\n`),
                    `event: zs-receipt\ndata: ${s.sealStreamFrame(enc.encode(JSON.stringify(f.receipt)))}\n\ndata: [DONE]\n\n`,
                ]
                let timer: ReturnType<typeof setTimeout> | undefined
                let done = false
                const body = new ReadableStream<Uint8Array>({
                    start(ctl) {
                        const next = (i: number) => {
                            ctl.enqueue(enc.encode(steps[i]!))
                            if (i + 1 < steps.length) timer = setTimeout(() => next(i + 1), 30)
                            else {
                                done = true
                                ctl.close()
                            }
                        }
                        next(0)
                        init.signal?.addEventListener(
                            'abort',
                            () => {
                                // An abort after the whole answer went out cancels nothing.
                                if (done) return
                                upstreamAborted = true
                                clearTimeout(timer)
                                ctl.error(init.signal!.reason)
                            },
                            { once: true },
                        )
                    },
                })
                return new Response(body, { headers: { 'Content-Type': 'text/event-stream', [RESPONSE_KEY_HEADER]: s.wrappedKeyHeader() } })
            }
            if (!stream) {
                const headers = new Headers({
                    'Content-Type': ENCRYPTED_CONTENT_TYPE,
                    [RESPONSE_KEY_HEADER]: s.wrappedKeyHeader(),
                    [RECEIPT_HEADER]: s.sealHeader(SEALED_HEADER_RECEIPT, enc.encode(encodeReceiptHeader(f.receipt))),
                })
                const sealed = s.sealBody(f.plaintext)
                if (o.holdReply) {
                    const body = new ReadableStream<Uint8Array>({
                        start(ctl) {
                            ctl.enqueue(sealed.slice(0, 8))
                            init.signal?.addEventListener('abort', () => ctl.error(init.signal!.reason), { once: true })
                        },
                    })
                    return new Response(body, { headers })
                }
                return new Response(sealed, { headers })
            }
            let sse = ''
            for (const pt of frames) sse += `event: zs\ndata: ${s.sealStreamFrame(pt)}\n\n`
            if (o.group) sse += `event: zs-settle-group\ndata: ${s.sealHeader(SEALED_HEADER_SETTLE_GROUP, enc.encode(VALID_GROUP))}\n\n`
            sse += `event: zs-receipt\ndata: ${s.sealStreamFrame(enc.encode(JSON.stringify(f.receipt)))}\n\n`
            sse += 'data: [DONE]\n\n'
            return new Response(sse, { headers: { 'Content-Type': 'text/event-stream', [RESPONSE_KEY_HEADER]: s.wrappedKeyHeader() } })
        },
    }
    let upstreamAborted = false
    const sent: RequestInit[] = []
    const urls: string[] = []
    const mem = o.journal ?? memoryJournal()
    // Each write, as `put <status>` or `delete`.
    const writes: string[] = []
    const journal: TicketJournal = {
        put: (rec) => {
            writes.push(`put ${rec.status}`)
            return mem.put(rec)
        },
        delete: (id) => {
            writes.push('delete')
            return mem.delete(id)
        },
        list: (payer, d) => mem.list(payer, d),
    }
    const nodeFetch: Fetch = async (url, init) => {
        urls.push(String(url))
        sent.push(init!)
        return node.answer(sealer, init!)
    }
    // A Config with no fetch gets the default, which here reaches this node.
    defaultFetchHook.fetch = nodeFetch
    const c = await Client.create({
        signer,
        network: testnet(),
        registry,
        privacy: o.relay ? 'relay_required' : 'direct',
        sweepDelay: () => 0,
        ...(o.sdkReserve
            ? {}
            : {
                  reserveClient: {
                      reserve: async () =>
                          ({
                              ticket,
                              responseKey: f.responseKey,
                              identity,
                              presignedOpenTxn: '',
                              sealRecipient: nodeKey.recipient,
                              algoUsdPrice: 0.2,
                          }) as unknown as Reserved,
                  },
              }),
        wallet: {
            payerAddr: () => 'PAYER',
            open: async () => {
                if (o.openErr !== undefined) throw o.openErr
                return handle as unknown as OpenHandle
            },
            ...(o.feeBps !== undefined ? { protocolFeeBps: async () => o.feeBps! } : {}),
            ...(o.prepareErr !== undefined
                ? {
                      prepareDeposit: async () => {
                          throw o.prepareErr
                      },
                  }
                : {}),
        },
        ...(o.defaultFetch ? {} : { fetch: nodeFetch }),
        ...o.config,
        stores: { journal, ...o.config?.stores },
    })
    const p = partsOf.get(c)!
    const body = `{"model":"${MODEL}","messages":[{"role":"user","content":"hi"}]${stream ? ',"stream":true' : ''}}`
    return {
        c,
        p,
        f,
        handle,
        journal,
        writes,
        sent,
        urls,
        body,
        deployment: p.cfg.network,
        get upstreamAborted() {
            return upstreamAborted
        },
    }
}

async function read(it: AsyncIterable<Event>) {
    const events: Event[] = []
    for await (const ev of it) events.push(ev)
    return events
}

describe('Client.stream', () => {
    it('pays for a whole reply, reports it, and submits the ack after it', async () => {
        const h = await harness()
        const track = vi.spyOn(h.p.refunds, 'track')
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        const events = await read(st.events())
        expect(events.map((e) => e.type)).toEqual([
            'route.candidates',
            'relay.hop',
            'reserve.started',
            'reserve.succeeded',
            'payment.committed',
            'response.started',
            'frame',
            'delta.text',
            'receipt.verified',
            'done',
        ])
        expect(st.err).toBeUndefined()
        expect(h.sent).toHaveLength(1)
        expect(await st.wait()).toEqual({ settlement: { ticketId: TICKET_ID, kind: 'payer_ack', txId: 'ACK', feesMicroAlgos: 0, networkFees: 0 } })
        expect(h.handle.acks).toHaveLength(1)
        // The watchdog took the ticket once escrow opened.
        expect(track).toHaveBeenCalledWith(h.handle, 2_000_000_000)
        await h.c.waitSettles()
        // A standalone ack doesn't finish the ticket, so its row stays,
        // carrying what the payer co-signed.
        expect(h.writes).toEqual(['put open', 'put settle_pending'])
        const rows = await h.journal.list('PAYER', h.deployment)
        expect(rows).toHaveLength(1)
        expect(rows[0]).toMatchObject({ ticketId: TICKET_ID, openTxId: 'APPCALL', status: 'settle_pending', payer: 'PAYER' })
        await h.c.close()
    })

    it('settles a stream inline, resolves its refund, and drops its row once the settle lands', async () => {
        const h = await harness({ stream: true, group: true, outcomes: ['landed'] })
        const resolve = vi.spyOn(h.p.refunds, 'resolve')
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        expect(await st.text()).toBe('hi')
        expect(await st.wait()).toEqual({ settlement: { ticketId: TICKET_ID, kind: 'atomic', txId: 'ACK', feesMicroAlgos: 0, networkFees: 0 } })
        expect(h.handle.acks.map((a) => a[1])).toEqual([VALID_GROUP])
        expect(resolve).toHaveBeenCalledWith(TICKET_ID)
        await h.c.waitSettles()
        expect(h.handle.looks).toEqual(['ACK'])
        expect(h.writes).toEqual(['put open', 'put settle_pending', 'delete'])
        expect(await h.journal.list('PAYER', h.deployment)).toEqual([])
        await h.c.close()
    })

    it('ends a settle watch at close, leaving the row for the reconciler', async () => {
        // Pending forever: only close ends the watch inside its 20s.
        const h = await harness({ stream: true, group: true, outcomes: [] })
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        await st.text()
        await new Promise((r) => setTimeout(r, 20))
        expect(h.handle.looks.length).toBeGreaterThan(0)
        const started = Date.now()
        await h.c.close()
        await h.c.waitSettles()
        expect(Date.now() - started).toBeLessThan(5_000)
        expect(h.writes).toEqual(['put open', 'put settle_pending'])
        expect(await h.journal.list('PAYER', h.deployment)).toHaveLength(1)
    })

    it('fails a turn the caller aborted before it ran, not as a retry', async () => {
        const h = await harness()
        const ac = new AbortController()
        ac.abort()
        await expect(h.c.stream({ endpoint: CHAT, body: h.body }, ac.signal).text()).rejects.toMatchObject({ retryable: false })
        expect(h.sent).toEqual([])
        await h.c.close()
    })

    // The node is cut off mid-answer, which by kind is worth a retry; the
    // caller's own abort is what says it isn't.
    it('judges a turn the caller aborted mid-stream by its signal, not its kind', async () => {
        const h = await harness({ stream: true, hold: true })
        const ac = new AbortController()
        const st = h.c.stream({ endpoint: CHAT, body: h.body }, ac.signal)
        let err: unknown
        try {
            for await (const ev of st.events()) if (ev.type === 'delta.text') ac.abort()
        } catch (e) {
            err = e
        }
        expect(err).toBeInstanceOf(ZsError)
        expect(retryable(err as ZsError)).toBe(true)
        expect(err).toMatchObject({ retryable: false, paid: true })
        expect(st.err).toBe(err)
        await h.c.close()
    })

    describe('on a node that goes silent', () => {
        async function silence(config: Partial<Config>, holdFrame?: string, abortAfterMs?: number) {
            const h = await harness({ stream: true, hold: true, config, ...(holdFrame === undefined ? {} : { holdFrame }) })
            const ac = new AbortController()
            const timer = abortAfterMs === undefined ? undefined : setTimeout(() => ac.abort(), abortAfterMs)
            const started = Date.now()
            let err: unknown
            try {
                await read(h.c.stream({ endpoint: CHAT, body: h.body }, ac.signal).events())
            } catch (e) {
                err = e
            }
            clearTimeout(timer)
            await h.c.close()
            return { err: err as ZsError, elapsed: Date.now() - started }
        }

        it('ends the turn stream_interrupted, a retry, with the timeout as its cause', async () => {
            const { err } = await silence({ streamIdle: { midStream: 20 } })
            expect(err).toBeInstanceOf(ZsError)
            expect(err).toMatchObject({ code: 'stream_interrupted', retryable: true, paid: true })
            const cause = findError(err, StreamIdleTimeoutError)
            expect([cause?.phase, cause?.timeoutMs]).toEqual(['mid-stream', 20])
        })

        it('waits out an image tool round on the tool budget', async () => {
            const opening = '{"type":"response.zs_tool_call.in_progress","item_id":"t1","tool":"zs_image_generation"}'
            const { err, elapsed } = await silence({ streamIdle: { midStream: 20, toolActive: 150 } }, opening)
            expect(elapsed).toBeGreaterThanOrEqual(140)
            expect([findError(err, StreamIdleTimeoutError)?.phase]).toEqual(['tool-active'])
        })

        it('arms the configured budgets by default, and nothing with the watchdog off', async () => {
            const start = vi.spyOn(IdleWatchdog.prototype, 'start')
            try {
                const { err } = await silence({}, undefined, 50)
                expect(err).toMatchObject({ retryable: false })
                expect(start).toHaveBeenCalledTimes(1)
                start.mockClear()
                const off = await silence({ streamIdle: false }, undefined, 50)
                expect(off.err).toMatchObject({ retryable: false })
                expect(findError(off.err, StreamIdleTimeoutError)).toBeUndefined()
                expect(start).not.toHaveBeenCalled()
            } finally {
                start.mockRestore()
            }
        })
    })

    // Config.streamIdle reaches the whole reply's read as well as the stream's.
    it('ends a whole reply silent mid-body read_upstream at the configured bound', async () => {
        async function silentReply(config: Partial<Config>) {
            const h = await harness({ holdReply: true, config })
            const ac = new AbortController()
            const timer = setTimeout(() => ac.abort(), 500)
            const err = (await h.c
                .stream({ endpoint: CHAT, body: h.body }, ac.signal)
                .text()
                .catch((e: unknown) => e)) as ZsError
            clearTimeout(timer)
            await h.c.close()
            return err
        }
        const cut = await silentReply({ streamIdle: { midStream: 20 } })
        expect(cut).toMatchObject({ code: 'read_upstream' })
        expect(findError(cut, StreamIdleTimeoutError)?.timeoutMs).toBe(20)
        const off = await silentReply({ streamIdle: false })
        expect(findError(off, StreamIdleTimeoutError)).toBeUndefined()
    })

    // A caller who stops reading once generation has finished still has the
    // receipt tail drained and the ticket settled: the receipt is where the
    // operator is paid.
    it('settles after a reader who left once generation finished', async () => {
        const h = await harness({ stream: true, lateTail: true })
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        for await (const ev of st.events()) if (ev.type === 'frame' && new TextDecoder().decode(ev.data).includes('finish_reason')) break
        expect(h.upstreamAborted).toBe(false)
        expect(h.handle.acks).toHaveLength(1)
        expect(await st.wait()).toMatchObject({ settlement: { ticketId: TICKET_ID, kind: 'payer_ack', txId: 'ACK' } })
        await h.c.close()
    })

    for (const withSignal of [false, true]) {
        it(`cancels the node when the reader leaves before generation finished${withSignal ? ', its own signal live' : ''}`, async () => {
            const h = await harness({ stream: true, lateTail: true })
            const st = h.c.stream({ endpoint: CHAT, body: h.body }, withSignal ? new AbortController().signal : undefined)
            for await (const ev of st.events()) if (ev.type === 'delta.text') break
            expect(h.upstreamAborted).toBe(true)
            expect(h.handle.acks).toEqual([])
            await h.c.close()
        })
    }

    // The watchdog is what recovers the escrow if nothing settles it, so it
    // takes the ticket even when the journal row can't be written.
    it('arms the watchdog when the journal write fails', async () => {
        const h = await harness({ noOperator: true })
        const track = vi.spyOn(h.p.refunds, 'track')
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        expect(track).toHaveBeenCalledWith(h.handle, 2_000_000_000)
        expect(h.writes).toEqual([])
        await h.c.close()
    })

    it('reads the request when it is made, not when its events are read', async () => {
        const h = await harness()
        const req: Request = { endpoint: CHAT, body: h.body }
        const st = h.c.stream(req)
        req.body = 'not json'
        req.endpoint = '/v1/responses'
        expect(await st.text()).toBe('hi')
        await h.c.close()
    })
})

describe('Client.fetch', () => {
    const sse = (data: string) => `data: ${data}\n\n`
    const post = (h: Awaited<ReturnType<typeof harness>>, init: RequestInit = {}) =>
        h.c.fetch(`${h.c.baseURL}/chat/completions`, { method: 'POST', body: h.body, ...init })

    it('answers a whole reply with the node’s body and the usage in headers', async () => {
        const h = await harness()
        const res = await post(h, { headers: { Authorization: 'Bearer sk-not-forwarded' } })
        expect(res.status).toBe(200)
        expect(await res.text()).toBe(ANSWER)
        expect(res.headers.get('Content-Type')).toBe('application/json')
        expect(res.headers.get('X-Zs-Ticket-Id')).toBe(TICKET_ID)
        // The caller's own credentials never reach the node.
        expect(new Headers(h.sent[0]!.headers).get('Authorization')).toBeNull()
        await h.c.waitSettles()
        expect(h.handle.acks).toHaveLength(1)
        await h.c.close()
    })

    it('streams the node’s frames as SSE and settles inline', async () => {
        const h = await harness({ stream: true, group: true, outcomes: ['landed'] })
        const res = await post(h)
        expect(res.headers.get('Content-Type')).toBe('text/event-stream')
        expect(await res.text()).toBe(FRAMES.map(sse).join('') + sse('[DONE]'))
        expect(h.handle.acks.map((a) => a[1])).toEqual([VALID_GROUP])
        await h.c.close()
    })

    it('reports a stream’s usage in a zs.usage frame on the opt-in header', async () => {
        const h = await harness({ stream: true })
        const text = await (await post(h, { headers: { 'X-Zs-Usage-Frame': '1' } })).text()
        expect(text).toContain(`event: zs.usage\ndata: {"type":"zs.usage","ticket_id":"${TICKET_ID}"`)
        await h.c.close()
    })

    it('cancels the node when the caller cancels the body before generation finished', async () => {
        const h = await harness({ stream: true, lateTail: true })
        const reader = (await post(h)).body!.getReader()
        await reader.read()
        await reader.cancel()
        await vi.waitFor(() => expect(h.upstreamAborted).toBe(true))
        expect(h.handle.acks).toEqual([])
        await h.c.close()
    })

    it('settles when the caller aborts after generation finished', async () => {
        const h = await harness({ stream: true, lateTail: true })
        const caller = new AbortController()
        const reader = (await post(h, { signal: caller.signal })).body!.getReader()
        let seen = ''
        while (!seen.includes('finish_reason')) seen += new TextDecoder().decode((await reader.read()).value)
        caller.abort()
        await expect(reader.read()).rejects.toThrow()
        await vi.waitFor(() => expect(h.handle.acks).toHaveLength(1))
        expect(h.upstreamAborted).toBe(false)
        await h.c.close()
    })
})

describe('Client.stream’s wiring', () => {
    function guard() {
        const calls: string[] = []
        const g: SpendGuard = {
            admit: () => {},
            reserve: (id, max) => calls.push(`reserve ${id} ${max}`),
            settle: (id, charged) => calls.push(`settle ${id} ${charged}`),
            release: (id) => calls.push(`release ${id}`),
        }
        return { g, calls }
    }

    it('settles the spend guard at what the receipt charged', async () => {
        const s = guard()
        const h = await harness({ config: { spendGuard: s.g } })
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        await h.c.waitSettles()
        expect(s.calls).toContain(`settle ${TICKET_ID} 50000`)
        await h.c.close()
    })

    it('releases the spend guard and names the network when the open fails', async () => {
        const s = guard()
        const h = await harness({
            config: { spendGuard: s.g },
            openErr: new Error('wallet: submit presigned open group: account XYZ balance 99000 below min 100000'),
        })
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        await expect(st.text()).rejects.toMatchObject({ code: 'wallet_unfunded' })
        expect(st.err!.message).toContain('on testnet')
        expect(s.calls).toContain(`release ${TICKET_ID}`)
        await h.c.close()
    })

    it('names the network when the pool can’t be funded before the reserve', async () => {
        const h = await harness({ prepareErr: new MbrDepositUnaffordableError(0n, 1n, 120_000n, 1_000n) })
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        await expect(st.text()).rejects.toMatchObject({ code: 'mbr_pool_underfunded' })
        expect(st.err!.message).toContain('on testnet')
        await h.c.close()
    })

    it('records the reply’s tool calls in the Client’s tool affinity', async () => {
        const toolAffinity = new IDAffinity(16, 60_000)
        const h = await harness({
            plaintext: '{"choices":[{"index":0,"message":{"content":"","tool_calls":[{"id":"call_9","type":"function","function":{"name":"f","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}',
            config: { stores: { toolAffinity } },
        })
        await read(h.c.stream({ endpoint: CHAT, body: h.body }).events())
        expect(toolAffinity.lookup('call_9')).toEqual({ op: 7, node: 3 })
        await h.c.close()
    })

    it('records the response id in the Client’s response affinity', async () => {
        const responseAffinity = new IDAffinity(16, 60_000)
        const h = await harness({
            plaintext: '{"object":"response","id":"resp_9","status":"completed","output":[{"type":"message","id":"m1","content":[{"type":"output_text","text":"yo"}]}]}',
            config: { stores: { responseAffinity } },
        })
        expect(await h.c.stream({ endpoint: '/v1/responses', body: `{"model":"${MODEL}","input":"hi"}` }).text()).toBe('yo')
        expect(responseAffinity.lookup('resp_9')).toEqual({ op: 7, node: 3 })
        await h.c.close()
    })

    it('reports the Client’s fee rate with the receipt', async () => {
        const h = await harness({ feeBps: 150 })
        await vi.waitFor(() => expect(h.c.feeRate()).toBe(150))
        const events = await read(h.c.stream({ endpoint: CHAT, body: h.body }).events())
        expect(events.find((e) => e.type === 'receipt.verified')).toMatchObject({ feeBps: 150, feeBpsKnown: true })
        await h.c.close()
    })

    it('bars a node whose settle group failed verification in the Client’s exclusions', async () => {
        const nodeExclusions = new NodeExclusionStore()
        const h = await harness({ stream: true, group: true, groupRejected: true, config: { stores: { nodeExclusions } } })
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        expect(nodeExclusions.nodeExcluded({ op: 7, node: 3 })).toBe(true)
        await h.c.close()
    })

    it('credits the relay a turn rode in the Client’s relay reputation', async () => {
        const relayReputation = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const record = vi.spyOn(relayReputation, 'recordRelayOutcome')
        const h = await harness({ relay: true, config: { stores: { relayReputation } } })
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        expect(h.urls[0]).toMatch(/^https:\/\/r8\.example\.com\//)
        expect(record).toHaveBeenCalledWith({ op: 8, node: 3 }, true)
        await h.c.close()
    })

    // The Client hands a turn the relay pool its own requests ride. Without
    // it a relayed turn's settle ack has no route and the payer broadcasts
    // the group from its own IP, as before 9.12.
    it('sends a relayed turn’s settle ack through a relay', async () => {
        const h = await harness({ relay: true })
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        const deliverAck = (h.handle as unknown as OpenHandle).deliverAck
        expect(deliverAck).toBeTypeOf('function')
        h.urls.length = 0
        // The fake answers the ack like an inference reply; only the route is in question.
        await deliverAck!({ ticket_id: TICKET_ID, settle_group: 'G' }).catch(() => {})
        expect(h.urls).toEqual(['https://r8.example.com/v1/zs/relay'])
        await h.c.close()
    })

    // Config.clock drives affinity; journal rows carry the wall clock, as Go's do.
    it('dates journal rows by the wall clock', async () => {
        const before = Date.now()
        const h = await harness({ config: { clock: () => 1000 } })
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        await h.c.waitSettles()
        const [row] = await h.journal.list('PAYER', h.deployment)
        expect(row!.createdAt).toBeGreaterThanOrEqual(before)
        expect(row!.updatedAt).toBeGreaterThanOrEqual(row!.createdAt)
        await h.c.close()
    })

    // Go's default HTTPClient carries inference with the header backstop; a
    // client the caller supplies keeps its own rules.
    it('sends inference through the header backstop on the default fetch only', async () => {
        defaultFetchHook.backstopped.length = 0
        const d = await harness({ defaultFetch: true })
        await d.c.stream({ endpoint: CHAT, body: d.body }).text()
        expect(defaultFetchHook.backstopped).toEqual(d.urls)
        expect(d.urls).toHaveLength(1)
        await d.c.close()

        // The reserve rides the plain fetch, as Go's reserve client has no
        // backstop.
        defaultFetchHook.reserveFetches.length = 0
        const r = await harness({ defaultFetch: true, sdkReserve: true })
        expect(defaultFetchHook.reserveFetches).toHaveLength(1)
        expect(defaultFetchHook.reserveFetches[0]).toBe(r.p.cfg.fetch)
        expect(r.p.cfg.fetch).not.toBe(r.p.cfg.inferenceFetch)
        await r.c.close()

        defaultFetchHook.backstopped.length = 0
        const s = await harness()
        await s.c.stream({ endpoint: CHAT, body: s.body }).text()
        expect(s.urls).toHaveLength(1)
        expect(defaultFetchHook.backstopped).toEqual([])
        await s.c.close()
    })
})
