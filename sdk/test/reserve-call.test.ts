/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'

import {
    type BytesSigner,
    type ReserveRequest,
    type Ticket,
    commitResponseKey,
    encodeDeploymentId,
    verifyReserveRequestFor,
} from '@txnlab/zs-proto/ticket'
import {
    type EphemeralIdentity,
    RELAY_HOP_HEADER,
    RELAY_PATH,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
    SEALED_RESERVE_CONTENT_TYPE,
    SEALED_RESERVE_RESPONSE_CONTENT_TYPE,
    generateEphemeralIdentity,
    openReserveResponse,
    sealReserveResponse,
} from '@txnlab/zs-proto/wire'

import {
    BadReserveEnvelopeError,
    BusyError,
    DEFAULT_RESERVE_TIMEOUT_MS,
    PayerRefusalError,
    type ReserveCall,
    ReserveHTTPError,
    ReserveResponseError,
    SizeError,
    parseRetryAfter,
    reserve,
    reserveRefusal,
} from '../src/index.js'
import type { RelayHop } from '../src/routing/index.js'

const NOW_MS = 1_700_000_000_500
const NOW = 1_700_000_000
const KEY = new Uint8Array(32).fill(5)
const BASE = 'https://node.example/'

function b64(b: Uint8Array): string {
    return Buffer.from(b).toString('base64')
}

function keypair(): { pub: Uint8Array; signer: BytesSigner } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const jwk = publicKey.export({ format: 'jwk' })
    return {
        pub: new Uint8Array(Buffer.from(jwk.x!, 'base64url')),
        signer: { signBytes: async (_addr, msg) => new Uint8Array(sign(null, msg, privateKey)) },
    }
}

interface Seen {
    url: string
    init: RequestInit
    request: ReserveRequest
}

// A node: opens the sealed reserve, answers with reply(request, n) where n
// counts the requests it has seen. The request and response seals share one
// envelope, so the payer's opener opens the request too.
async function fakeNode(reply: (r: ReserveRequest, n: number) => Promise<Response> | Response) {
    const node = await generateEphemeralIdentity()
    const seen: Seen[] = []
    const fetch = (async (url: string, init: RequestInit) => {
        const plain = await openReserveResponse(init.body as Uint8Array, node)
        const request = JSON.parse(new TextDecoder().decode(plain)) as ReserveRequest
        seen.push({ url, init, request })
        return reply(request, seen.length)
    }) as unknown as typeof globalThis.fetch
    return { node, seen, fetch }
}

function ticketFor(r: ReserveRequest, over: Partial<Ticket> = {}): Ticket {
    return {
        ticket_id: 'dGlja2V0',
        operator_id: 3,
        node_id: 9,
        input_count: r.input_count,
        max_output_count: r.max_output_count,
        input_rate: 1,
        output_rate: 1,
        max_price: 1000,
        min_price: 1,
        expires_at: NOW + 600,
        model: r.model,
        stream: r.stream,
        commit_k: b64(commitResponseKey(KEY)),
        input_usage_type: 2,
        output_usage_type: 2,
        cache_read_rate: 1,
        sig: 'c2ln',
        ...over,
    }
}

async function wrap(k: Uint8Array, recipient: string): Promise<string> {
    const env = JSON.parse(new TextDecoder().decode(await sealReserveResponse(k, recipient)))
    return env.ciphertext
}

// What a node answers a reserve with: the response sealed to its proxy_recipient.
async function ok(r: ReserveRequest, extra: Record<string, unknown> = {}, ticket: Partial<Ticket> = {}) {
    const body = {
        ticket: ticketFor(r, ticket),
        wrapped_response_key: await wrap(KEY, r.proxy_recipient!),
        presigned_open_txn: 'cGc=',
        ...extra,
    }
    const sealed = await sealReserveResponse(new TextEncoder().encode(JSON.stringify(body)), r.proxy_recipient!)
    return new Response(sealed, { status: 200, headers: { 'Content-Type': SEALED_RESERVE_RESPONSE_CONTENT_TYPE } })
}

function refuse(status: number, code: string | null, message = '', headers: Record<string, string> = {}) {
    const body = code === null ? '<html>bad gateway</html>' : JSON.stringify({ error: { code, message } })
    return new Response(body, { status, headers })
}

function call(node: EphemeralIdentity, fetch: typeof globalThis.fetch, over: Partial<ReserveCall> = {}): ReserveCall {
    return {
        target: { operatorId: 3, nodeId: 9, baseUrl: BASE, sealRecipient: node.recipient },
        request: { model: 'm', input_count: 300, max_output_count: 64, stream: true },
        hop: null,
        fetch,
        clock: () => NOW_MS,
        ...over,
    }
}

const HOP: RelayHop = {
    baseUrl: 'https://relay.example',
    targetId: 3,
    targetNodeId: 9,
    relayId: 4,
    relayNodeId: 1,
    relayProtoVersion: '9.1',
}

describe('reserve', () => {
    it('seals the request to the node and returns the checked ticket', async () => {
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        const got = await reserve(call(node, fetch))

        expect(seen).toHaveLength(1)
        expect(seen[0]!.url).toBe('https://node.example/v1/zs/reserve')
        const headers = seen[0]!.init.headers as Record<string, string>
        expect(headers['Content-Type']).toBe(SEALED_RESERVE_CONTENT_TYPE)
        expect(headers.Accept).toBe(`${SEALED_RESERVE_RESPONSE_CONTENT_TYPE}, application/json`)
        expect(seen[0]!.request).toMatchObject({ model: 'm', input_count: 300, max_output_count: 64, stream: true })
        expect(seen[0]!.request.proxy_recipient).toBe(got.identity.recipient)
        expect(seen[0]!.request.payer_sig).toBeUndefined()

        expect(got.ticket.model).toBe('m')
        expect(got.responseKey).toEqual(KEY)
        expect(got.presignedOpenTxn).toBe('cGc=')
    })

    it('mints a fresh identity per call', async () => {
        const { node, fetch } = await fakeNode((r) => ok(r))
        const a = await reserve(call(node, fetch))
        const b = await reserve(call(node, fetch))
        expect(a.identity.recipient).not.toBe(b.identity.recipient)
    })

    it('routes through the hop, carrying the target to the relay', async () => {
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        await reserve(call(node, fetch, { hop: HOP }))
        expect(seen[0]!.url).toBe(`https://relay.example${RELAY_PATH}`)
        const headers = seen[0]!.init.headers as Record<string, string>
        expect(headers[RELAY_TARGET_HEADER]).toBe('3')
        expect(headers[RELAY_TARGET_NODE_HEADER]).toBe('9')
        expect(headers[RELAY_PATH_HEADER]).toBe('/v1/zs/reserve')
        expect(headers['Content-Type']).toBe(SEALED_RESERVE_CONTENT_TYPE)
    })

    it('signs under the payer, bound to the target, at the clock', async () => {
        const { pub, signer } = keypair()
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        const dep = new Uint8Array(32).fill(5)
        const request = { ...call(node, fetch).request, payer_addr: 'PAYER', deployment: encodeDeploymentId(dep) }
        await reserve(call(node, fetch, { signer, request }))
        const r = seen[0]!.request
        expect(r.payer_addr).toBe('PAYER')
        expect(r.payer_issued_at).toBe(NOW)
        expect(() => verifyReserveRequestFor(3, 9, r, pub, NOW, 0, dep)).not.toThrow()
        expect(() => verifyReserveRequestFor(3, 8, r, pub, NOW, 0, dep)).toThrow()
    })

    it('leaves a request unsigned without a payer, even with a signer', async () => {
        const { signer } = keypair()
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        await reserve(call(node, fetch, { signer }))
        expect(seen[0]!.request.payer_sig).toBeUndefined()
        expect(seen[0]!.request.payer_issued_at).toBeUndefined()
    })

    // The id a Solana payer named reaches the node, and a ticket naming any
    // other is refused even when the node signed it.
    it('holds the ticket to the id the request named', async () => {
        const named = { request: { model: 'm', input_count: 300, max_output_count: 64, stream: true, ticket_id: 'dGlja2V0' } }
        const echo = await fakeNode((r) => ok(r))
        await expect(reserve(call(echo.node, echo.fetch, named))).resolves.toBeDefined()
        expect(echo.seen[0]!.request.ticket_id).toBe('dGlja2V0')
        const other = await fakeNode((r) => ok(r, {}, { ticket_id: 'b3RoZXI=' }))
        await expect(reserve(call(other.node, other.fetch, named))).rejects.toThrow(/is not the requested/)
    })

    // A ticket-only node never sends one, so requiring it is the caller's call.
    it('requires a presigned open group only when asked', async () => {
        const { node, fetch } = await fakeNode((r) => ok(r, { presigned_open_txn: '' }))
        const payer = { request: { ...call(node, fetch).request, payer_addr: 'PAYER' } }
        await expect(reserve(call(node, fetch, payer))).resolves.toBeDefined()
        await expect(reserve(call(node, fetch, { ...payer, requirePresignedOpen: true }))).rejects.toThrow(
            /missing presigned_open_txn/,
        )
    })

    it('refuses a hop that targets another node, before signing or posting', async () => {
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        let signed = false
        const signer: BytesSigner = {
            signBytes: async () => {
                signed = true
                return new Uint8Array(64)
            },
        }
        const req = { ...call(node, fetch).request, payer_addr: 'PAYER' }
        for (const hop of [{ ...HOP, targetId: 4 }, { ...HOP, targetNodeId: 8 }]) {
            await expect(reserve(call(node, fetch, { hop, signer, request: req }))).rejects.toThrow(/hop targets node/)
        }
        expect(signed).toBe(false)
        expect(seen).toHaveLength(0)
    })

    it('sends the route alone to a relay, whatever path the base URL has', async () => {
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        const c = call(node, fetch, { hop: HOP })
        await reserve({ ...c, target: { ...c.target, baseUrl: 'https://node.example/zs/' } })
        expect((seen[0]!.init.headers as Record<string, string>)[RELAY_PATH_HEADER]).toBe('/v1/zs/reserve')
    })

    it('drops a stale signature left on the request object', async () => {
        const { node, seen, fetch } = await fakeNode((r) => ok(r))
        const request = { ...call(node, fetch).request, payer_sig: 'stale', payer_issued_at: 1 }
        await reserve(call(node, fetch, { request }))
        expect(seen[0]!.request.payer_sig).toBeUndefined()
        expect(seen[0]!.request.payer_issued_at).toBeUndefined()
    })

    it('times out a node that never answers, as an abort', async () => {
        const { node } = await fakeNode(() => refuse(500, null))
        const hang = ((_u: string, init: RequestInit) =>
            new Promise((_, reject) => {
                init.signal!.addEventListener('abort', () => reject(init.signal!.reason))
            })) as unknown as typeof globalThis.fetch
        const err = await reserve(call(node, hang, { timeoutMs: 20 })).catch((e) => e)
        expect(err).toBeInstanceOf(ReserveHTTPError)
        expect(err).toMatchObject({ status: 0, aborted: true })
    })

    it('bounds the call by default', async () => {
        const { node } = await fakeNode(() => refuse(500, null))
        let signal: AbortSignal | null | undefined
        const spy = (async (_u: string, init: RequestInit) => {
            signal = init.signal
            throw new TypeError('stop')
        }) as unknown as typeof globalThis.fetch
        const timeout = vi.spyOn(AbortSignal, 'timeout')
        try {
            const err = await reserve(call(node, spy)).catch((e) => e)
            expect(signal).toBeInstanceOf(AbortSignal)
            expect(timeout).toHaveBeenCalledWith(DEFAULT_RESERVE_TIMEOUT_MS)
            expect(DEFAULT_RESERVE_TIMEOUT_MS).toBe(5000)
            // A plain transport failure is not an abort.
            expect(err).toMatchObject({ status: 0, aborted: false })
        } finally {
            timeout.mockRestore()
        }
    })

    // The caller's own signal must not replace the timeout.
    it('times out a node that never answers when the caller passes a signal too', async () => {
        const { node } = await fakeNode(() => refuse(500, null))
        const hang = ((_u: string, init: RequestInit) =>
            new Promise((_, reject) => {
                init.signal!.addEventListener('abort', () => reject(init.signal!.reason))
            })) as unknown as typeof globalThis.fetch
        const err = await reserve(call(node, hang, { signal: new AbortController().signal, timeoutMs: 20 })).catch(
            (e) => e,
        )
        expect(err).toMatchObject({ name: 'ReserveHTTPError', status: 0, aborted: true })
    })

    it('checks the ticket against the target and request', async () => {
        const { node, fetch } = await fakeNode((r) => ok(r, {}, { node_id: 8 }))
        await expect(reserve(call(node, fetch))).rejects.toThrow(ReserveResponseError)
    })

    it('passes minTtlSeconds through', async () => {
        const { node, fetch } = await fakeNode((r) => ok(r, {}, { expires_at: NOW + 10 }))
        await expect(reserve(call(node, fetch))).resolves.toBeDefined()
        await expect(reserve(call(node, fetch, { minTtlSeconds: 15 }))).rejects.toThrow(/leaves under 15s/)
    })

    it('refuses a 200 past the size Go reads, rather than buffering it', async () => {
        const { node, fetch } = await fakeNode((r) => ok(r, { pad: 'x'.repeat(300 << 10) }))
        await expect(reserve(call(node, fetch))).rejects.toThrow(ReserveResponseError)
    })

    describe('refusals', () => {
        it('reads a 429 as a BusyError whose code decides the retry', async () => {
            const { node, fetch } = await fakeNode(() => refuse(429, 'no_capacity', '', { 'Retry-After': '3' }))
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).toBeInstanceOf(BusyError)
            expect(err).toMatchObject({ code: 'no_capacity', retryAfterMs: 3000, retryable: true })

            const slot = await fakeNode(() => refuse(429, 'payer_slot_cap'))
            const err2 = await reserve(call(slot.node, slot.fetch)).catch((e) => e)
            expect(err2).toMatchObject({ code: 'payer_slot_cap', retryAfterMs: 0, retryable: false })
        })

        it('reads a 400 context_length_exceeded as a SizeError', async () => {
            const { node, fetch } = await fakeNode(() => refuse(400, 'context_length_exceeded', 'too long'))
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).toBeInstanceOf(SizeError)
            expect(err).toMatchObject({ code: 'context_length_exceeded', nodeMessage: 'too long' })
        })

        it('reads a 400 bad_reserve_envelope as a BadReserveEnvelopeError', async () => {
            const { node, fetch } = await fakeNode(() => refuse(400, 'bad_reserve_envelope'))
            await expect(reserve(call(node, fetch))).rejects.toThrow(BadReserveEnvelopeError)
        })

        it('reads any other 400 as a ReserveHTTPError', async () => {
            const { node, fetch } = await fakeNode(() => refuse(400, 'invalid_payer_addr', 'nope'))
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).toBeInstanceOf(ReserveHTTPError)
            expect(err).toMatchObject({ status: 400, code: 'invalid_payer_addr', nodeMessage: 'nope' })
        })

        it('reads a 403 free_quota_exhausted as a PayerRefusalError with its reset', async () => {
            const { node, fetch } = await fakeNode(() =>
                refuse(403, 'free_quota_exhausted', 'spent', { 'Retry-After': '76172' }),
            )
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).toBeInstanceOf(PayerRefusalError)
            expect(err).toMatchObject({ code: 'free_quota_exhausted', nodeMessage: 'spent', retryAfterMs: 76_172_000 })
        })

        // Every node reads the same account, so no other node would accept it.
        it('reads a 403 payer_not_opted_in as a PayerRefusalError', async () => {
            const { node, fetch } = await fakeNode(() => refuse(403, 'payer_not_opted_in', 'opt in to USDC'))
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).toBeInstanceOf(PayerRefusalError)
            expect(err).toMatchObject({ code: 'payer_not_opted_in', nodeMessage: 'opt in to USDC' })
        })

        it('reads a 403 payer_usdc_account_unusable as a PayerRefusalError', async () => {
            const { node, fetch } = await fakeNode(() => refuse(403, 'payer_usdc_account_unusable', 'frozen'))
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).toBeInstanceOf(PayerRefusalError)
            expect(err).toMatchObject({ code: 'payer_usdc_account_unusable', nodeMessage: 'frozen' })
        })

        it('reads another 403 as a ReserveHTTPError', async () => {
            const { node, fetch } = await fakeNode(() => refuse(403, 'forbidden'))
            await expect(reserve(call(node, fetch))).rejects.toMatchObject({ name: 'ReserveHTTPError', status: 403 })
        })

        // As Go: the payer and sizing codes mean what they say only on their
        // own status. A payer refusal ends failover to every node, so a 500
        // that happens to carry the code must not.
        it('reads a payer or sizing code on another status as a ReserveHTTPError', async () => {
            for (const [status, code] of [
                [500, 'free_quota_exhausted'],
                [502, 'context_length_exceeded'],
                [500, 'bad_reserve_envelope'],
            ] as const) {
                const { node, fetch } = await fakeNode(() => refuse(status, code))
                const err = await reserve(call(node, fetch)).catch((e) => e)
                expect(err.constructor).toBe(ReserveHTTPError)
                expect(err).toMatchObject({ status, code })
            }
        })

        // Go's unmarshal into a string code fails on a number, leaving it
        // code-less, and a code-less 503 is a retryable gateway failure.
        it('reads a numeric error code as no code', async () => {
            const { node, fetch } = await fakeNode(
                () => new Response(JSON.stringify({ error: { code: 503, message: 'x' } }), { status: 503 }),
            )
            await expect(reserve(call(node, fetch))).rejects.toMatchObject({ name: 'ReserveHTTPError', status: 503, code: '' })
        })

        it('reads a refusal with no body as a ReserveHTTPError', async () => {
            const { node, fetch } = await fakeNode(() => new Response(null, { status: 204 }))
            await expect(reserve(call(node, fetch))).rejects.toMatchObject({ name: 'ReserveHTTPError', status: 204 })
        })

        // Go's io.ReadAll failure is a plain error whatever cut the body off, so
        // its dispatcher reads it as a hard refusal: no strike, no weather.
        it('leaves a body broken off by the abort unclassified, as Go does', async () => {
            const ac = new AbortController()
            const { node, fetch } = await fakeNode(
                () =>
                    new Response(
                        new ReadableStream({
                            start(c) {
                                c.enqueue(new TextEncoder().encode('{"error":'))
                                ac.abort()
                                c.error(new TypeError('aborted'))
                            },
                        }),
                        { status: 503 },
                    ),
            )
            const err = await reserve(call(node, fetch, { signal: ac.signal })).catch((e) => e)
            expect(err).not.toBeInstanceOf(ReserveHTTPError)
            expect(String(err.message)).toMatch(/^read reserve response: /)
        })

        it('reads a code-less 5xx as a ReserveHTTPError with no code, and the hop marker', async () => {
            const marked = await fakeNode(() => refuse(502, null, '', { [RELAY_HOP_HEADER]: '1', 'Retry-After': '2' }))
            const err = await reserve(call(marked.node, marked.fetch, { hop: HOP })).catch((e) => e)
            expect(err).toBeInstanceOf(ReserveHTTPError)
            expect(err).toMatchObject({ status: 502, code: '', relayHopMarked: true, retryAfterMs: 2000 })
            // Any hop can write the body, so it's kept for logs, not shown.
            expect(err.body).toBe('<html>bad gateway</html>')
            expect(err.message).toBe('reserve: HTTP 502')

            const unmarked = await fakeNode(() => refuse(502, null))
            await expect(reserve(call(unmarked.node, unmarked.fetch, { hop: HOP }))).rejects.toMatchObject({
                relayHopMarked: false,
            })
            // An empty header is no marker, as Go reads it.
            const empty = await fakeNode(() => refuse(502, null, '', { [RELAY_HOP_HEADER]: '' }))
            await expect(reserve(call(empty.node, empty.fetch, { hop: HOP }))).rejects.toMatchObject({
                relayHopMarked: false,
            })
        })

        // Classified on its status alone, a coded 503 cut short would pass for
        // a gateway's code-less one, which is retried.
        it('leaves a refusal whose body breaks off unclassified', async () => {
            const broken = () =>
                new Response(
                    new ReadableStream({
                        start(c) {
                            c.enqueue(new TextEncoder().encode('{"error":'))
                            c.error(new TypeError('connection reset'))
                        },
                    }),
                    { status: 503 },
                )
            const { node, fetch } = await fakeNode(broken)
            const err = await reserve(call(node, fetch)).catch((e) => e)
            expect(err).not.toBeInstanceOf(ReserveHTTPError)
            expect(err.message).toMatch(/^read reserve response: connection reset/)
        })

        it('reads a transport failure as status 0 with the cause', async () => {
            const { node } = await fakeNode(() => refuse(500, null))
            const boom = new TypeError('Failed to fetch')
            const failing = (async () => {
                throw boom
            }) as unknown as typeof globalThis.fetch
            const err = await reserve(call(node, failing)).catch((e) => e)
            expect(err).toBeInstanceOf(ReserveHTTPError)
            expect(err).toMatchObject({ status: 0, code: '', relayHopMarked: false })
            expect(err.cause).toBe(boom)
        })

        it("ends the fetch on the caller's signal, as an abort", async () => {
            const { node } = await fakeNode(() => refuse(500, null))
            const ac = new AbortController()
            const hang = ((_u: string, init: RequestInit) =>
                new Promise((_, reject) => {
                    init.signal!.addEventListener('abort', () => reject(init.signal!.reason))
                    ac.abort()
                })) as unknown as typeof globalThis.fetch
            const err = await reserve(call(node, hang, { signal: ac.signal })).catch((e) => e)
            expect(err).toMatchObject({ name: 'ReserveHTTPError', status: 0, aborted: true })
        })
    })

    describe('clock-skew resync', () => {
        const skew = () => refuse(401, 'invalid_payer_sig', 'payer_issued_at out of window; node_time=1700000500')
        const signed = (node: EphemeralIdentity, fetch: typeof globalThis.fetch) =>
            call(node, fetch, {
                signer: keypair().signer,
                request: { model: 'm', input_count: 300, max_output_count: 64, stream: true, payer_addr: 'PAYER' },
            })

        it("re-signs once at the node's clock", async () => {
            const { node, seen, fetch } = await fakeNode((r, n) => (n === 1 ? skew() : ok(r)))
            await expect(reserve(signed(node, fetch))).resolves.toBeDefined()
            expect(seen.map((s) => s.request.payer_issued_at)).toEqual([NOW, 1_700_000_500])
            expect(seen[1]!.request.payer_sig).not.toBe(seen[0]!.request.payer_sig)
        })

        it('resyncs at most once, then surfaces the 401', async () => {
            const { node, seen, fetch } = await fakeNode(() => skew())
            await expect(reserve(signed(node, fetch))).rejects.toMatchObject({
                name: 'ReserveHTTPError',
                status: 401,
                code: 'invalid_payer_sig',
            })
            expect(seen).toHaveLength(2)
        })

        it('does not resync an unsigned reserve', async () => {
            const { node, seen, fetch } = await fakeNode(() => skew())
            await expect(reserve(call(node, fetch))).rejects.toMatchObject({ status: 401 })
            expect(seen).toHaveLength(1)
        })

        it('resyncs only a 401, as Go does', async () => {
            const { node, seen, fetch } = await fakeNode(() => refuse(403, 'invalid_payer_sig', 'node_time=1700000500'))
            await expect(reserve(signed(node, fetch))).rejects.toMatchObject({ name: 'ReserveHTTPError', status: 403 })
            expect(seen).toHaveLength(1)
        })

        it('does not resync a 401 without a node_time', async () => {
            const { node, seen, fetch } = await fakeNode(() => refuse(401, 'invalid_payer_sig', 'bad signature'))
            await expect(reserve(signed(node, fetch))).rejects.toMatchObject({ status: 401 })
            expect(seen).toHaveLength(1)
        })
    })
})

// Go's TestParseRetryAfter holds the same cases.
describe('parseRetryAfter', () => {
    it.each<[string | null, number]>([
        [null, 0],
        ['', 0],
        ['0', 0],
        ['-5', 0],
        ['1.5', 0],
        ['Wed, 21 Oct 2026 07:28:00 GMT', 0],
        [' 30 ', 30_000],
        ['+30', 30_000],
        ['86400', 86_400_000],
        ['86401', 86_400_000],
        ['76172', 76_172_000],
        ['9223372037', 86_400_000],
        ['18446744074', 86_400_000],
        ['9223372036854775807', 86_400_000],
        ['9223372036854775808', 0],
        ['99999999999999999999', 0],
    ])('reads %j as %d ms', (v, want) => {
        expect(parseRetryAfter(v)).toBe(want)
    })
})

// The mapping reserve applies to every refusal, exported so a caller holding a
// refusal's facts in another shape gets the same typed error.
describe('reserveRefusal', () => {
    it.each([
        ['a 429, whatever its code', { status: 429, code: 'no_capacity', retryAfterMs: 2000 }, BusyError],
        ['a 400 sizing code', { status: 400, code: 'context_length_exceeded' }, SizeError],
        ['a 400 bad_reserve_envelope', { status: 400, code: 'bad_reserve_envelope' }, BadReserveEnvelopeError],
        ['a 403 payer code', { status: 403, code: 'free_quota_exhausted', retryAfterMs: 5000 }, PayerRefusalError],
        ['a sizing code on another status', { status: 502, code: 'context_length_exceeded' }, ReserveHTTPError],
        ['a payer code on another status', { status: 400, code: 'free_quota_exhausted' }, ReserveHTTPError],
        ['any other refusal', { status: 503, code: '' }, ReserveHTTPError],
    ])('reads %s as the error reserve throws', (_, fields, want) => {
        expect(reserveRefusal(fields)).toBeInstanceOf(want)
    })

    it('carries what the verdict reads off a ReserveHTTPError', () => {
        expect(
            reserveRefusal({ status: 502, code: '', retryAfterMs: 20_000, relayHopMarked: true }),
        ).toMatchObject({ status: 502, code: '', retryAfterMs: 20_000, relayHopMarked: true, aborted: false })
    })

    it('carries the wait a busy node and a payer refusal name', () => {
        expect(reserveRefusal({ status: 429, code: 'no_capacity', retryAfterMs: 2000 })).toMatchObject({
            code: 'no_capacity',
            retryAfterMs: 2000,
            retryable: true,
        })
        expect(reserveRefusal({ status: 403, code: 'free_quota_exhausted', retryAfterMs: 5000 })).toMatchObject({
            retryAfterMs: 5000,
        })
    })

    it('reads an omitted wait and message as none', () => {
        expect(reserveRefusal({ status: 429, code: 'no_capacity' })).toMatchObject({ retryAfterMs: 0 })
        expect(reserveRefusal({ status: 403, code: 'free_quota_exhausted' })).toMatchObject({
            retryAfterMs: 0,
            nodeMessage: '',
        })
        expect(reserveRefusal({ status: 400, code: 'context_length_exceeded' })).toMatchObject({ nodeMessage: '' })
        expect(reserveRefusal({ status: 502, code: '' })).toMatchObject({
            retryAfterMs: 0,
            nodeMessage: '',
            body: '',
            relayHopMarked: false,
        })
    })
})
