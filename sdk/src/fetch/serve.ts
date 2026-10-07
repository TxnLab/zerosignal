/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// zs.fetch: an OpenAI-compatible endpoint as a fetch function, mirroring
// proto/go/zs handler (emit.go, the POST routes of server.go and handlers.go,
// and completions.go's entry). An OpenAI client built once over
// FETCH_BASE_URL with this as its fetch sends every request through the
// Client, which picks the node per request.
//
// What the Go handler adds as an HTTP server and this leaves out: CORS (the
// caller is in-process, never a cross-origin browser), the per-request log
// line (the Client already logs each turn's outcome), and the catalog GET
// routes, which are not ported yet.

import { NodeReply, findError, isZsError } from '../errors.js'
import type { Event, ReceiptVerified, ResponseStarted } from '../events.js'
import { goJSON } from '../gojson.js'
import { goDecodeRune } from '../gotext.js'
import type { Fetch, Logger } from '../ports.js'
import { nodeRetryAfter } from '../responder.js'
import { emptyFrame, frameSSE } from '../stream.js'
import type { Request as TurnRequest, Stream } from '../turn.js'
import type { Endpoint } from '../types.js'
import { chatRequestFromCompletions, completionsChunkFromChat, completionsResponseFromChat } from './completions.js'
import { errorResponse, openAIErrorResponse, setRetryAfter, setShouldRetry, shouldRetry } from './errors.js'
import { copyResponseHeaders, snapshotZsHeaders, stripNodeZsHeaders } from './headers.js'
import { USAGE_FRAME_HEADER, setUsageHeaders, usageFrame } from './usage.js'

/**
 * FETCH_BASE_URL is the base URL to build an OpenAI client on when its fetch
 * is zs.fetch. It names no server: the .invalid top-level domain never
 * resolves, so a client that loses the fetch fails rather than reaching a
 * host, and the node each request goes to is chosen per request.
 */
export const FETCH_BASE_URL = 'https://zerosignal.invalid/v1'

/**
 * MAX_CLIENT_BODY_BYTES caps the request body zs.fetch buffers. An
 * OpenAI-shaped body is typically tens of KB; 16 MiB leaves room for large
 * tool-call arguments and image edits.
 */
export const MAX_CLIENT_BODY_BYTES = 16 << 20

/** What zs.fetch reads off the Client. */
export interface FetchTarget {
    stream(request: TurnRequest, signal?: AbortSignal): Stream
}

export interface FetchOptions {
    /**
     * The web app a mainnet wallet_unfunded error points the payer at. The
     * hosted app is built for one network, so the hint is never offered
     * elsewhere.
     */
    fundingUrl?: string | undefined
    /** The Client's network; the funding hint is offered on mainnet only. */
    network?: string | undefined
    logger?: Logger | undefined
}

// The POST routes, by path. Each streamable endpoint is its own wire endpoint;
// /v1/completions is emulated over chat.
const ROUTES: ReadonlyMap<string, { endpoint: Endpoint; legacy: boolean }> = new Map([
    ['/v1/chat/completions', { endpoint: '/v1/chat/completions', legacy: false }],
    ['/v1/responses', { endpoint: '/v1/responses', legacy: false }],
    ['/v1/images/generations', { endpoint: '/v1/images/generations', legacy: false }],
    ['/v1/images/edits', { endpoint: '/v1/images/edits', legacy: false }],
    ['/v1/completions', { endpoint: '/v1/chat/completions', legacy: true }],
])

/**
 * openAIFetch serves target as an OpenAI-compatible endpoint behind a fetch
 * function: the request's path picks the endpoint, its body is the turn's,
 * and the response is the node's, as the Go handler writes it. A request
 * whose signal aborts before the response is ready rejects with the
 * signal's reason; one that aborts mid-stream errors the body. Either way,
 * and when the caller cancels the body, the turn ends as a departed client's:
 * the node is stopped if it was still generating, and otherwise its receipt
 * is still read and the ticket settled.
 */
export function openAIFetch(target: FetchTarget, opts: FetchOptions = {}): Fetch {
    const hint =
        opts.network === 'mainnet' && opts.fundingUrl
            ? `If this is your web account, you can add funds in the web app instead (${opts.fundingUrl}).`
            : ''
    return async (input, init) => {
        const req = new Request(input, init)
        req.signal.throwIfAborted()
        // Go's mux matches the unescaped path, and its server refuses a
        // request whose path doesn't unescape.
        let path: string
        try {
            path = decodeURIComponent(new URL(req.url).pathname)
        } catch {
            return plainError(400, 'Bad Request')
        }
        const route = ROUTES.get(path)
        if (route === undefined) return plainError(404, '404 page not found')
        if (req.method !== 'POST') {
            const r = plainError(405, 'Method Not Allowed')
            r.headers.set('Allow', 'POST')
            return r
        }
        const read = await readClientBody(req)
        if (read instanceof Response) return read
        let body = read
        if (route.legacy) {
            const t = chatRequestFromCompletions(body)
            if ('error' in t) return openAIErrorResponse(new Headers(), t.error.status, t.error.type, t.error.code, t.error.message)
            body = t.body
        }
        // The turn ends on the caller's abort, or on local's when the caller
        // cancels the body, which is how Go's request context ends.
        const local = new AbortController()
        const stop = () => local.abort()
        try {
            const stream = target.stream(
                {
                    endpoint: route.endpoint,
                    body,
                    contentType: req.headers.get('Content-Type') ?? '',
                    // Headers joins a repeated header's values where Go
                    // reads the first. Joined, the requirement is set when
                    // any value is, which is at least as strict as Go.
                    requireTee: !goBlank(req.headers.get('X-Zs-Require-TEE')),
                    relay: firstValue(req.headers.get('X-Zs-Relay')),
                    // The node's own frames are the response, error frames included.
                    framesOnly: true,
                },
                AbortSignal.any([req.signal, local.signal]),
            )
            return await serveTurn(stream.events(), {
                legacy: route.legacy,
                usageFrame: !goBlank(req.headers.get(USAGE_FRAME_HEADER)),
                fundingHint: hint,
                caller: req.signal,
                stop,
            })
        } catch (err) {
            if (req.signal.aborted) throw req.signal.reason
            // Go's recoverer: whatever broke, the caller gets a 500 and the
            // turn is not left running for nobody.
            stop()
            opts.logger?.error('panic in handler', { path, err: err instanceof Error ? err.message : String(err) })
            return openAIErrorResponse(new Headers(), 500, 'proxy_error', 'panic', 'internal server error')
        }
    }
}

/**
 * firstValue is the first of a header's values as Go's Header.Get reads it,
 * from the comma-joined list Headers.get returns. Joined, two `required`
 * lines would read as no preference at all, dropping the requirement. No relay
 * preference contains a comma, so the split loses nothing a caller meant.
 */
export function firstValue(v: string | null): string {
    if (v === null) return ''
    const comma = v.indexOf(',')
    return comma === -1 ? v : v.slice(0, comma)
}

// plainError is net/http's http.Error, which its ServeMux answers an
// unrouted path or method with.
function plainError(status: number, text: string): Response {
    return new Response(`${text}\n`, {
        status,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
    })
}

// readClientBody buffers the body up to MAX_CLIENT_BODY_BYTES, or answers the
// error Go's readClientBody writes: 413 past the cap, 400 when the read fails.
async function readClientBody(req: Request): Promise<Uint8Array | Response> {
    const parts: Uint8Array[] = []
    let n = 0
    if (req.body !== null) {
        const reader = req.body.getReader()
        try {
            for (;;) {
                const { done, value } = await reader.read()
                if (done) break
                n += value.length
                if (n > MAX_CLIENT_BODY_BYTES) {
                    reader.cancel().catch(() => {})
                    return openAIErrorResponse(new Headers(), 413, 'invalid_request_error', 'body_too_large', 'request body exceeds proxy limit')
                }
                parts.push(value)
            }
        } catch {
            req.signal.throwIfAborted()
            return openAIErrorResponse(new Headers(), 400, 'invalid_request_error', 'read_body', 'failed to read request body')
        }
    }
    req.signal.throwIfAborted()
    const out = new Uint8Array(n)
    let at = 0
    for (const p of parts) {
        out.set(p, at)
        at += p.length
    }
    return out
}

// Go's unicode.IsSpace.
const GO_SPACES = new Set([
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
    0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
])

/**
 * goBlank is whether Go's strings.TrimSpace leaves a header value empty, the
 * test the Go handler puts its opt-in headers to. A header value is bytes,
 * one char per byte here, which Go reads as UTF-8: a lone 0xA0 is an invalid
 * byte to Go and not a space, where String.prototype.trim would strip it and
 * read X-Zs-Require-TEE as unset.
 */
export function goBlank(v: string | null): boolean {
    if (v === null) return true
    for (let i = 0; i < v.length; ) {
        const [r, w] = goDecodeRune(v, i)
        if (!GO_SPACES.has(r)) return false
        i += w
    }
    return true
}

/** How serveTurn renders a turn. */
export interface ServeOptions {
    /** The caller asked /v1/completions: content is reshaped to text-completion shape. */
    legacy: boolean
    /** The caller opted into the zs.usage stream frame. */
    usageFrame: boolean
    /** Completes a wallet_unfunded message; empty for none. */
    fundingHint: string
    /** The caller's signal. */
    caller?: AbortSignal | undefined
    /** Ends the turn as a departed client's, beyond leaving its events. */
    stop?: (() => void) | undefined
}

// Statuses a Response can't carry a body under, so the body is left out. Go's
// writer refuses the writes under 204 and 304 too, but allows them under 205,
// which a Response can't be built with.
const NULL_BODY_STATUSES = new Set([204, 205, 304])

/**
 * responseStatus is the status a node's answer goes out under. A Response
 * takes 200 to 599 only, where Go's writer takes up to 999, so a node status
 * outside that range is answered as what it is, a bad gateway, rather than
 * failing the Response.
 */
function responseStatus(status: number): number {
    return status >= 200 && status <= 599 ? status : 502
}

function respond(status: number, h: Headers, body: Uint8Array | null): Response {
    const s = responseStatus(status)
    return new Response(NULL_BODY_STATUSES.has(s) ? null : body, { status: s, headers: h })
}

// The codings every fetch decodes. undici and browsers decode the body but
// keep Content-Encoding, where Go's transport, which asks for gzip, drops the
// header with the coding. Left in, it labels a decoded body as compressed.
const DECODED_CODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br'])

function dropDecodedEncoding(h: Headers): void {
    const ce = h.get('Content-Encoding')
    if (ce === null) return
    const codings = ce.split(',').map((c) => c.trim().toLowerCase())
    if (codings.every((c) => DECODED_CODINGS.has(c))) h.delete('Content-Encoding')
}

/**
 * serveTurn renders a turn's events as an OpenAI-compatible response, Go's
 * httpEmitter.serve. A whole reply is held until done, because its usage
 * headers precede its body; a stream's response is returned as it opens and
 * its body carries the frames. Leaving the events before they end stops the
 * turn, which the Client treats as the caller leaving.
 */
export async function serveTurn(events: AsyncIterable<Event>, o: ServeOptions): Promise<Response> {
    const it = events[Symbol.asyncIterator]()
    const stop = () => {
        o.stop?.()
        it.return?.()?.catch(() => {})
    }
    const h = new Headers()
    let started: ResponseStarted | undefined
    let body: Uint8Array | undefined
    let usage: ReceiptVerified | undefined
    for (;;) {
        let r: IteratorResult<Event>
        try {
            r = await untilAborted(it.next(), o.caller)
        } catch (err) {
            if (o.caller?.aborted) {
                stop()
                throw o.caller.reason
            }
            return fail(h, err, o.fundingHint)
        }
        // Go writes nothing, which net/http sends as an empty 200.
        if (r.done) return respond(200, h, null)
        const ev = r.value
        switch (ev.type) {
            case 'max_output.clamped':
                h.set('X-Zs-Max-Output-Clamped', String(ev.ceiling))
                break
            case 'response.started':
                started = ev
                if (ev.streaming) return openStream(it, h, ev.status, o, stop)
                break
            case 'frame':
                body = ev.data
                break
            case 'receipt.verified':
                usage = ev
                break
            case 'done':
                if (started !== undefined) {
                    // The turn is over; its events run out to their end.
                    void drain(it)
                    return reply(h, started, body, usage, o.legacy)
                }
                break
        }
    }
}

async function drain(it: AsyncIterator<Event>): Promise<void> {
    try {
        while (!(await it.next()).done);
    } catch {
        // The response is already decided.
    }
}

// untilAborted is p, or signal's reason once it aborts first.
function untilAborted<T>(p: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
    if (signal === undefined) return p
    return new Promise<T>((resolve, reject) => {
        const onAbort = () => reject(signal.reason)
        if (signal.aborted) onAbort()
        else signal.addEventListener('abort', onAbort, { once: true })
        p.then(
            (v) => {
                signal.removeEventListener('abort', onAbort)
                resolve(v)
            },
            (err: unknown) => {
                signal.removeEventListener('abort', onAbort)
                reject(err)
            },
        )
    })
}

// fail answers a turn that ended before its response started.
function fail(h: Headers, err: unknown, fundingHint: string): Response {
    if (!isZsError(err)) return openAIErrorResponse(h, 500, 'proxy_error', '', err instanceof Error ? err.message : String(err))
    const up = findError(err.cause, NodeReply)
    if (up !== undefined) return passThrough(h, up, shouldRetry(err), err.retryAfter)
    if (err.code === 'wallet_unfunded' && fundingHint !== '') return errorResponse(h, err, `${err.message} ${fundingHint}`)
    return errorResponse(h, err)
}

/**
 * passThrough answers with an operator's error response. No node-set X-Zs-*
 * header reaches the caller (SPEC §5.2 step 4); the SDK's own are kept. The
 * retry advice is the SDK's, set over any the node sent: Retry-After is the
 * error's, which caps one node's hint, not the node's header.
 */
function passThrough(h: Headers, up: NodeReply, retry: boolean, retryAfterMs: number | undefined): Response {
    const saved = snapshotZsHeaders(h)
    copyResponseHeaders(h, up.header)
    stripNodeZsHeaders(h, saved)
    setShouldRetry(h, retry)
    setRetryAfter(h, retryAfterMs)
    h.delete('Content-Length')
    dropDecodedEncoding(h)
    if (up.contentType !== '') h.set('Content-Type', up.contentType)
    return respond(up.status, h, up.body)
}

function reply(h: Headers, started: ResponseStarted, body: Uint8Array | undefined, usage: ReceiptVerified | undefined, legacy: boolean): Response {
    // Taken before the copy: the X-Zs-* the SDK set earlier in the turn (the
    // max_output clamp marker) would otherwise go with the node's.
    const saved = snapshotZsHeaders(h)
    copyResponseHeaders(h, started.header)
    stripNodeZsHeaders(h, saved)
    h.delete('Content-Length')
    // The body is the opened plaintext, which no coding of the node's applies to.
    h.delete('Content-Encoding')
    h.set('Content-Type', 'application/json')
    setRetryAfter(h, nodeRetryAfter(started.header))
    // A reply comes after the open, so resending it pays again.
    if (started.status >= 400) setShouldRetry(h, false)
    if (usage !== undefined) setUsageHeaders(h, usage)
    let out = body ?? new Uint8Array()
    // Anything that isn't a chat completion (a sealed error) passes through.
    if (legacy) out = completionsResponseFromChat(out)
    return respond(started.status, h, out)
}

const enc = new TextEncoder()

// What a stream that broke after it opened ends with: an OpenAI-shaped error
// frame and [DONE]. The caller sees a generic message; the cause is logged.
const INTERRUPTED = (() => {
    const err = frameSSE({
        ...emptyFrame(),
        data: enc.encode(goJSON({ error: { message: 'stream interrupted', type: 'proxy_error', code: 'stream_error' } })),
    })
    const done = frameSSE({ ...emptyFrame(), data: enc.encode('[DONE]') })
    const out = new Uint8Array(err.length + done.length)
    out.set(err)
    out.set(done, err.length)
    return out
})()

function openStream(it: AsyncIterator<Event>, h: Headers, nodeStatus: number, o: ServeOptions, stop: () => void): Response {
    const status = responseStatus(nodeStatus)
    h.set('Content-Type', 'text/event-stream')
    h.set('Cache-Control', 'no-cache')
    h.set('Connection', 'keep-alive')
    h.set('X-Accel-Buffering', 'no')
    // Every stream is past the escrow open, and a node may open one under a
    // failed status, which an OpenAI SDK reads before the stream and resends.
    setShouldRetry(h, false)
    if (NULL_BODY_STATUSES.has(status)) {
        // No frame can be delivered, so the turn runs for nobody.
        stop()
        return new Response(null, { status, headers: h })
    }
    const caller = o.caller
    let ended = false
    let onAbort: (() => void) | undefined
    const end = () => {
        ended = true
        if (onAbort !== undefined) caller?.removeEventListener('abort', onAbort)
    }
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            if (caller === undefined) return
            onAbort = () => {
                if (ended) return
                end()
                controller.error(caller.reason)
                stop()
            }
            if (caller.aborted) onAbort()
            else caller.addEventListener('abort', onAbort, { once: true })
        },
        async pull(controller) {
            for (;;) {
                let r: IteratorResult<Event>
                try {
                    r = await it.next()
                } catch {
                    if (ended) return
                    end()
                    controller.enqueue(INTERRUPTED)
                    controller.close()
                    return
                }
                if (ended) return
                if (r.done) {
                    end()
                    controller.close()
                    return
                }
                const ev = r.value
                try {
                    if (ev.type === 'frame') {
                        const data = ev.sealed && o.legacy ? completionsChunkFromChat(ev.data) : ev.data
                        controller.enqueue(frameSSE({ event: ev.event, id: ev.id, data, comment: ev.comment, retry: ev.retry, sealed: ev.sealed }))
                        return
                    }
                    if (ev.type === 'receipt.verified' && o.usageFrame) {
                        controller.enqueue(frameSSE(usageFrame(ev)))
                        return
                    }
                } catch (err) {
                    // As Go's recoverer: the stream ends, and the turn with it.
                    end()
                    controller.error(err)
                    stop()
                    return
                }
            }
        },
        // The caller stopped reading: it has left.
        cancel() {
            if (ended) return
            end()
            stop()
        },
    })
    return new Response(body, { status, headers: h })
}
