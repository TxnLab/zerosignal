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
import { ZsError } from '../src/errors.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import type { Request } from '../src/turn.js'
import { partsOf } from '../src/client-parts.js'
import type { OpenHandle, Reserved, SettleOutcome } from '../src/parts.js'
import { TICKET_ID, VALID_GROUP, fixture, handleOf } from './turn-fixtures.js'

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
    /** Streamed: send the content, then the receipt tail a moment later, unless the request is aborted first. */
    lateTail?: boolean
    /** The open handle carries no operator, so the journal row can't be built. */
    noOperator?: boolean
    /** Route through a relay of another owner. */
    relay?: boolean
    openErr?: unknown
    feeBps?: number
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
                const first = `event: zs\ndata: ${s.sealStreamFrame(frames[0]!)}\n\n`
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
                return new Response(s.sealBody(f.plaintext), { headers })
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
        list: (payer, appId) => mem.list(payer, appId),
    }
    const c = await Client.create({
        signer,
        network: testnet(),
        registry,
        privacy: o.relay ? 'relay_required' : 'direct',
        sweepDelay: () => 0,
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
        wallet: {
            payerAddr: () => 'PAYER',
            open: async () => {
                if (o.openErr !== undefined) throw o.openErr
                return handle as unknown as OpenHandle
            },
            ...(o.feeBps !== undefined ? { protocolFeeBps: async () => o.feeBps! } : {}),
        },
        fetch: async (url, init) => {
            urls.push(String(url))
            sent.push(init!)
            return node.answer(sealer, init!)
        },
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
        escrowAppId: p.cfg.network.escrowAppId,
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
        expect(await st.wait()).toEqual({ settlement: { ticketId: TICKET_ID, kind: 'payer_ack', txId: 'ACK', feesMicroAlgos: 0 } })
        expect(h.handle.acks).toHaveLength(1)
        // The watchdog took the ticket once escrow opened.
        expect(track).toHaveBeenCalledWith(h.handle, 2_000_000_000)
        await h.c.waitSettles()
        // A standalone ack doesn't finish the ticket, so its row stays,
        // carrying what the payer co-signed.
        expect(h.writes).toEqual(['put open', 'put settle_pending'])
        const rows = await h.journal.list('PAYER', h.escrowAppId)
        expect(rows).toHaveLength(1)
        expect(rows[0]).toMatchObject({ ticketId: TICKET_ID, openTxId: 'APPCALL', status: 'settle_pending', payer: 'PAYER' })
        await h.c.close()
    })

    it('settles a stream inline, resolves its refund, and drops its row once the settle lands', async () => {
        const h = await harness({ stream: true, group: true, outcomes: ['landed'] })
        const resolve = vi.spyOn(h.p.refunds, 'resolve')
        const st = h.c.stream({ endpoint: CHAT, body: h.body })
        expect(await st.text()).toBe('hi')
        expect(await st.wait()).toEqual({ settlement: { ticketId: TICKET_ID, kind: 'atomic', txId: 'ACK', feesMicroAlgos: 0 } })
        expect(h.handle.acks.map((a) => a[1])).toEqual([VALID_GROUP])
        expect(resolve).toHaveBeenCalledWith(TICKET_ID)
        await h.c.waitSettles()
        expect(h.handle.looks).toEqual(['ACK'])
        expect(h.writes).toEqual(['put open', 'put settle_pending', 'delete'])
        expect(await h.journal.list('PAYER', h.escrowAppId)).toEqual([])
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
        expect(await h.journal.list('PAYER', h.escrowAppId)).toHaveLength(1)
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

    // Config.clock drives affinity; journal rows carry the wall clock, as Go's do.
    it('dates journal rows by the wall clock', async () => {
        const before = Date.now()
        const h = await harness({ config: { clock: () => 1000 } })
        await h.c.stream({ endpoint: CHAT, body: h.body }).text()
        await h.c.waitSettles()
        const [row] = await h.journal.list('PAYER', h.escrowAppId)
        expect(row!.createdAt).toBeGreaterThanOrEqual(before)
        expect(row!.updatedAt).toBeGreaterThanOrEqual(row!.createdAt)
        await h.c.close()
    })
})
