/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The algod transport: testdata/algod_retry_vectors.json, which go/algod
// generates from DefaultTransport, then the retry loop against a fake algod,
// ported from go/algod transport_test.go.

import { readFileSync } from 'node:fs'
import { type IncomingMessage, type ServerResponse, createServer } from 'node:http'
import type { AddressInfo } from 'node:net'

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
    ALGOD_MAX_RETRIES,
    ALGOD_RETRY_WAIT_MAX_MS,
    ALGOD_RETRY_WAIT_MIN_MS,
    AlgodHTTPError,
    RetryingAlgodClient,
    algodBackoffMs,
    algodShouldRetry,
    retryingAlgod,
} from '../src/algod-transport.js'
import { isNotFound } from '../src/escrow/algod.js'
import type { LogAttrs, Logger } from '../src/ports.js'

const vectors = JSON.parse(readFileSync(new URL('../../testdata/algod_retry_vectors.json', import.meta.url), 'utf8')) as {
    max_retries: number
    wait_min_ms: number
    wait_max_ms: number
    statuses: { status: number; retry: boolean }[]
    schedule_ms: number[]
    now_unix_ms: number
    backoff: { attempt: number; retry_after: string; wait_ms: number }[]
}

describe('algod_retry vectors', () => {
    it("keeps Go's DefaultTransport budget", () => {
        expect([ALGOD_MAX_RETRIES, ALGOD_RETRY_WAIT_MIN_MS, ALGOD_RETRY_WAIT_MAX_MS]).toEqual([
            vectors.max_retries,
            vectors.wait_min_ms,
            vectors.wait_max_ms,
        ])
    })

    it.each(vectors.statuses.map((c) => [c.status, c.retry] as const))('status %i: retried %s', (status, retry) => {
        expect(algodShouldRetry(status === 0 ? undefined : status)).toBe(retry)
    })

    it('waits the linear schedule with no Retry-After', () => {
        expect(vectors.schedule_ms).toHaveLength(ALGOD_MAX_RETRIES)
        expect(vectors.schedule_ms.map((_, i) => algodBackoffMs(i, null, vectors.now_unix_ms))).toEqual(vectors.schedule_ms)
    })

    it('has backoff cases', () => expect(vectors.backoff.length).toBeGreaterThan(50))

    it.each(vectors.backoff.map((c) => [c.attempt, c.retry_after, c.wait_ms] as const))(
        'after attempt %i with Retry-After %j: waits %d ms',
        (attempt, retryAfter, waitMs) => {
            expect(algodBackoffMs(attempt, retryAfter, vectors.now_unix_ms)).toBe(waitMs)
        },
    )
})

// ---- against a fake algod ----

type Handler = (req: IncomingMessage, body: Buffer, res: ServerResponse) => void

const servers: { close: () => void }[] = []
afterEach(() => {
    for (const s of servers.splice(0)) s.close()
})

/** A fake algod answering each request with the next handler, the last one repeating. */
async function fakeAlgod(...handlers: Handler[]) {
    const seen: { method: string; url: string; token: string | undefined; body: string }[] = []
    const server = createServer((req, res) => {
        const chunks: Buffer[] = []
        req.on('data', (c: Buffer) => chunks.push(c))
        req.on('end', () => {
            const body = Buffer.concat(chunks)
            seen.push({ method: req.method!, url: req.url!, token: req.headers['x-algo-api-token'] as string | undefined, body: body.toString() })
            handlers[Math.min(seen.length - 1, handlers.length - 1)]!(req, body, res)
        })
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    servers.push({ close: () => server.close() })
    const { port } = server.address() as AddressInfo
    return { endpoint: `http://127.0.0.1:${port}`, seen }
}

const status =
    (code: number, headers: Record<string, string> = {}, body = ''): Handler =>
    (_req, _body, res) => {
        res.writeHead(code, headers)
        res.end(body)
    }
const ok = status(200, { 'Content-Type': 'application/json' }, '{"ok":true}')

function recordingLogger() {
    const lines: { msg: string; attrs: LogAttrs | undefined }[] = []
    const at = (msg: string, attrs?: LogAttrs) => void lines.push({ msg, attrs })
    const logger: Logger = { debug: at, info: at, warn: at, error: at }
    return { logger, lines }
}

// Short waits, as Go's newTestRetry uses.
const quick = { maxRetries: 2, retryWaitMinMs: 10, retryWaitMaxMs: 20 }

describe('RetryingAlgodClient', () => {
    it('retries a 503 and returns the answer after it', async () => {
        const a = await fakeAlgod(status(503), ok)
        const { logger, lines } = recordingLogger()
        const res = await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick, logger }).get('/v2/status')
        expect(res.status).toBe(200)
        expect(new TextDecoder().decode(res.body)).toBe('{"ok":true}')
        expect(a.seen).toHaveLength(2)
        expect(lines).toEqual([
            { msg: 'algod transport retry', attrs: { method: 'GET', url: `${a.endpoint}/v2/status`, status: 503, wait_ms: 10, attempt: 1, max: 3 } },
        ])
    })

    // An unref'd wait let a process awaiting the request exit mid-retry, its
    // promise never settled.
    it('waits on a timer that keeps the process alive for its caller', async () => {
        const a = await fakeAlgod(status(503), ok)
        const timers: { ms: number | undefined; t: NodeJS.Timeout }[] = []
        const real = globalThis.setTimeout
        const spy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
            const t = real(fn, ms)
            timers.push({ ms, t })
            return t
        }) as typeof setTimeout)
        try {
            const p = new RetryingAlgodClient({ endpoint: a.endpoint, maxRetries: 1, retryWaitMinMs: 250, retryWaitMaxMs: 250 }).get('/v2/status')
            await vi.waitFor(() => expect(timers.some((x) => x.ms === 250)).toBe(true))
            expect(timers.filter((x) => x.ms === 250).map((x) => x.t.hasRef())).toEqual([true])
            expect((await p).status).toBe(200)
        } finally {
            spy.mockRestore()
        }
    })

    it("retries past a logger that throws", async () => {
        const a = await fakeAlgod(status(503), ok)
        const thrower = () => {
            throw new Error('logger down')
        }
        const logger: Logger = { debug: thrower, info: thrower, warn: thrower, error: thrower }
        expect((await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick, logger }).get('/v2/status')).status).toBe(200)
        expect(a.seen).toHaveLength(2)
    })

    it.each([429, 500, 502, 504, 599])('retries a %i', async (code) => {
        const a = await fakeAlgod(status(code), status(code), ok)
        expect((await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick }).get('/v2/status')).status).toBe(200)
        expect(a.seen).toHaveLength(3)
    })

    it.each([400, 401, 403, 404, 409])('answers a %i at once, as an error algosdk reads', async (code) => {
        const a = await fakeAlgod(status(code, { 'Content-Type': 'application/json', 'X-Extra': 'yes' }, '{"message":"refused"}'))
        const err = await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick }).get('/v2/status').catch((e: unknown) => e)
        expect(err).toBeInstanceOf(AlgodHTTPError)
        const { response } = err as AlgodHTTPError
        expect(response.status).toBe(code)
        // Keyed by name, unlike algosdk 3.6's own client.
        expect(response.headers['x-extra']).toBe('yes')
        expect((err as Error).message).toMatch(new RegExp(`status ${code} .*: refused$`))
        expect(a.seen).toHaveLength(1)
    })

    it('gives up after maxRetries, answering with the last failure', async () => {
        const a = await fakeAlgod(status(503, {}, '{"message":"down"}'))
        const err = await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick }).get('/v2/status').catch((e: unknown) => e)
        expect((err as AlgodHTTPError).response.status).toBe(503)
        expect(a.seen).toHaveLength(quick.maxRetries + 1)
    })

    it('resends a POST body unchanged', async () => {
        const a = await fakeAlgod(status(503), ok)
        const body = new TextEncoder().encode('signed-group')
        await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick }).post('/v2/transactions', body, undefined, {
            'content-type': 'application/x-binary',
        })
        expect(a.seen.map((s) => [s.method, s.body])).toEqual([
            ['POST', 'signed-group'],
            ['POST', 'signed-group'],
        ])
    })

    it('retries a request that got no response', async () => {
        const a = await fakeAlgod(ok)
        let calls = 0
        const fetch = ((...args: Parameters<typeof globalThis.fetch>) => {
            if (calls++ === 0) return Promise.reject(new TypeError('fetch failed'))
            return globalThis.fetch(...args)
        }) as typeof globalThis.fetch
        expect((await new RetryingAlgodClient({ endpoint: a.endpoint, ...quick, fetch }).get('/v2/status')).status).toBe(200)
        expect(calls).toBe(2)
    })

    it('rethrows a transport failure once the retries run out', async () => {
        const fetch = (() => Promise.reject(new TypeError('fetch failed'))) as typeof globalThis.fetch
        await expect(new RetryingAlgodClient({ endpoint: 'http://algod.invalid', ...quick, fetch }).get('/v2/status')).rejects.toThrow(
            'fetch failed',
        )
    })

    it('waits out a Retry-After longer than the schedule, held to the cap', async () => {
        const a = await fakeAlgod(status(429, { 'Retry-After': '5' }), ok)
        const started = Date.now()
        await new RetryingAlgodClient({ endpoint: a.endpoint, maxRetries: 2, retryWaitMinMs: 10, retryWaitMaxMs: 120 }).get('/v2/status')
        const waited = Date.now() - started
        expect(waited).toBeGreaterThanOrEqual(110)
        expect(waited).toBeLessThan(1_000)
    })

    it("stops on the request's signal, mid-wait, without another attempt", async () => {
        const a = await fakeAlgod(status(503))
        const ac = new AbortController()
        const p = new RetryingAlgodClient({ endpoint: a.endpoint, maxRetries: 5, retryWaitMinMs: 5_000, retryWaitMaxMs: 5_000 }).get(
            '/v2/status',
            undefined,
            undefined,
            { signal: ac.signal },
        )
        await new Promise((r) => setTimeout(r, 50))
        ac.abort(new Error('caller left'))
        await expect(p).rejects.toThrow('caller left')
        expect(a.seen).toHaveLength(1)
    })

    it('does not retry a request its signal ended', async () => {
        let calls = 0
        const ac = new AbortController()
        const fetch = (() => {
            calls++
            ac.abort(new Error('deadline'))
            return Promise.reject(new DOMException('aborted', 'AbortError'))
        }) as typeof globalThis.fetch
        await expect(
            new RetryingAlgodClient({ endpoint: 'http://algod.invalid', ...quick, fetch }).get('/v2/status', undefined, undefined, { signal: ac.signal }),
        ).rejects.toThrow('aborted')
        expect(calls).toBe(1)
    })

    it('sends the token and resolves paths under the endpoint, as algosdk does', async () => {
        const a = await fakeAlgod(ok)
        await new RetryingAlgodClient({ endpoint: `${a.endpoint}/algod`, token: 'tok' }).get('/v2/status', { format: 'json', round: 5 })
        await new RetryingAlgodClient({ endpoint: `${a.endpoint}/algod/` }).get('v2/status')
        expect(a.seen.map((s) => [s.url, s.token])).toEqual([
            ['/algod/v2/status?format=json&round=5', 'tok'],
            ['/algod/v2/status', undefined],
        ])
    })

    it('serves an algosdk client whose 404 reads as not found', async () => {
        const a = await fakeAlgod(status(503), status(404, { 'Content-Type': 'application/json' }, '{"message":"box not found"}'))
        const algod = retryingAlgod({ endpoint: a.endpoint })
        // The default wait is a second, so this exercises the real schedule once.
        const err = await algod
            .getApplicationBoxByName(1234n, new Uint8Array([1]))
            .do()
            .catch((e: unknown) => e)
        expect(isNotFound(err)).toBe(true)
        expect(a.seen).toHaveLength(2)
    })
})
