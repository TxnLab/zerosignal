/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import type { LookupAddress } from 'node:dns'
import { createServer, type Server } from 'node:http'
import {
    type AddressInfo,
    createServer as createNetServer,
    getDefaultAutoSelectFamily,
    setDefaultAutoSelectFamily,
} from 'node:net'

import { Agent } from 'undici'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { type Config, resolveConfig, testnet, ZsError } from '../src/index.js'
import { guardedLookup } from '../src/node/fetch.js'
import { nodeFetch, PrivateTargetError } from '../src/node/index.js'

let server: Server
let port: number

// Echoes what arrived, so a test sees whether the request kept its shape.
beforeAll(async () => {
    server = createServer((req, res) => {
        let body = ''
        req.on('data', (c: Buffer) => (body += c.toString()))
        req.on('end', () => res.end(JSON.stringify({ method: req.method, body, header: req.headers['x-t'] ?? null })))
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    port = (server.address() as AddressInfo).port
})
afterAll(() => new Promise<void>((r) => server.close(() => r())))

const GET = { method: 'GET', body: '', header: null }
const POST_INIT: RequestInit = { method: 'POST', body: 'x', headers: { 'x-t': '1' } }
const POSTED = { method: 'POST', body: 'x', header: '1' }

// The address a refused fetch failed on, from the cause fetch wraps it in.
async function refusal(p: Promise<Response>): Promise<PrivateTargetError> {
    const err = (await p.then(
        () => expect.fail('the fetch was not refused'),
        (e: unknown) => e,
    )) as { cause?: unknown }
    expect(err).toBeInstanceOf(TypeError)
    expect(err.cause).toBeInstanceOf(PrivateTargetError)
    return err.cause as PrivateTargetError
}

// A resolver that answers every name with these addresses.
function answering(...addresses: string[]) {
    const calls: string[] = []
    const resolve = (host: string, _: unknown, cb: (err: NodeJS.ErrnoException | null, a: LookupAddress[]) => void) => {
        calls.push(host)
        cb(
            null,
            addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })),
        )
    }
    return { resolve, calls }
}

describe('nodeFetch', () => {
    it('refuses a private literal address', async () => {
        const e = await refusal(nodeFetch()(`http://127.0.0.1:${port}/`))
        expect(e.host).toBe('127.0.0.1')
    })

    it('refuses a private literal IPv6 address', async () => {
        const e = await refusal(nodeFetch()(`http://[::1]:${port}/`))
        expect(e.host).toBe('::1')
    })

    // The literal check is not enough: a name an attacker registers can
    // resolve anywhere, and that answer is only known at the dial.
    it('refuses a name that resolves only to private addresses', async () => {
        const { resolve, calls } = answering('10.0.0.7', 'fd00::7')
        const e = await refusal(nodeFetch({ resolve })(`http://operator.example:${port}/`))
        expect(calls).toEqual(['operator.example'])
        expect(e.host).toBe('operator.example')
        expect(e.addresses).toEqual(['10.0.0.7', 'fd00::7'])
    })

    // A rebind: the name answers with an allowed address, then with loopback.
    // The socket dials the answer the guard judged, never asking again, so
    // the loopback server is never reached. 0.0.0.1 is an address Go allows
    // and no host can be dialed at, so the dial fails at once.
    it('dials the address it judged, with no second resolution', async () => {
        const calls: string[] = []
        let hits = 0
        const counting = createServer((_, res) => {
            hits++
            res.end('reached')
        })
        await new Promise<void>((r) => counting.listen(0, '127.0.0.1', r))
        try {
            const resolve = (host: string, _: unknown, cb: (err: NodeJS.ErrnoException | null, a: LookupAddress[]) => void) => {
                calls.push(host)
                cb(null, [{ address: calls.length === 1 ? '0.0.0.1' : '127.0.0.1', family: 4 }])
            }
            const p = (counting.address() as AddressInfo).port
            const err = (await nodeFetch({ resolve })(`http://rebind.example:${p}/`).then(
                () => expect.fail('the fetch reached a server'),
                (e: unknown) => e,
            )) as { cause?: unknown }
            expect((err.cause as { address?: unknown }).address).toBe('0.0.0.1')
            expect(calls).toEqual(['rebind.example'])
            expect(hits).toBe(0)
        } finally {
            await new Promise<void>((r) => counting.close(() => r()))
        }
    })

    it('dials a private address when allowed', async () => {
        const res = await nodeFetch({ allowPrivateHosts: true })(`http://127.0.0.1:${port}/`)
        expect(await res.json()).toEqual(GET)
    })

    // The SDK's reserve and probe pass a URL and an init; the request must
    // arrive as they built it.
    it('sends the init as given', async () => {
        const res = await nodeFetch({ allowPrivateHosts: true })(`http://127.0.0.1:${port}/`, POST_INIT)
        expect(await res.json()).toEqual(POSTED)
    })

    it('takes a Request as well as a URL, keeping its method, body and headers', async () => {
        const res = await nodeFetch({ allowPrivateHosts: true })(new Request(`http://127.0.0.1:${port}/`, POST_INIT))
        expect(await res.json()).toEqual(POSTED)
        await refusal(nodeFetch()(new Request(`http://127.0.0.1:${port}/`)))
    })

    it("keeps its guard against a caller's own dispatcher", async () => {
        await refusal(nodeFetch()(`http://127.0.0.1:${port}/`, { dispatcher: new Agent() } as RequestInit))
    })

    // A refusal that still connected would be a port scan of the LAN behind a
    // correct-looking error.
    it('opens no connection to a refused literal address', async () => {
        let conns = 0
        const tcp = createNetServer((s) => {
            conns++
            s.destroy()
        })
        await new Promise<void>((r) => tcp.listen(0, '127.0.0.1', r))
        try {
            await refusal(nodeFetch()(`http://127.0.0.1:${(tcp.address() as AddressInfo).port}/`))
            await new Promise((r) => setTimeout(r, 50))
            expect(conns).toBe(0)
        } finally {
            await new Promise<void>((r) => tcp.close(() => r()))
        }
    })

    // Through the real resolver, both ways Node asks it: every address at once
    // (family autoselection, Node's default) or one.
    it.each([true, false])('refuses a name the system resolves to loopback (autoselect %s)', async (autoselect) => {
        const before = getDefaultAutoSelectFamily()
        setDefaultAutoSelectFamily(autoselect)
        try {
            const e = await refusal(nodeFetch()(`http://localhost:${port}/`))
            expect(e.host).toBe('localhost')
        } finally {
            setDefaultAutoSelectFamily(before)
        }
    })

    // Bun's undici ignores the Agent, so a guard there would check nothing;
    // Deno is untested. Better no fetch than one that only looks guarded.
    describe('outside Node', () => {
        afterEach(() => {
            delete (process.versions as Record<string, string>).bun
            vi.unstubAllGlobals()
        })

        it.each([
            ['Bun', () => Object.defineProperty(process.versions, 'bun', { value: '1.3.9', configurable: true })],
            ['Deno', () => vi.stubGlobal('Deno', {})],
        ])('refuses to guard under %s, and dials unguarded when allowed', async (_, enter) => {
            enter()
            expect(() => nodeFetch()).toThrow(ZsError)
            const res = await nodeFetch({ allowPrivateHosts: true })(`http://127.0.0.1:${port}/`)
            expect(await res.json()).toEqual(GET)
        })
    })
})

describe('guardedLookup', () => {
    function lookup(resolve: ReturnType<typeof answering>['resolve'], all: boolean) {
        return new Promise<{ err: unknown; address: unknown; family: unknown }>((r) =>
            guardedLookup(resolve)('node.example', { all }, (err, address, family) => r({ err, address, family })),
        )
    }

    // Go's dial hook refuses each private address and dials the next, so a
    // name with a public answer among private ones still connects, to it.
    it('drops the private addresses and keeps the rest, in order', async () => {
        const { resolve } = answering('10.0.0.1', '203.0.113.9', '::1', '2001:db8::9')
        expect(await lookup(resolve, true)).toEqual({
            err: null,
            address: [
                { address: '203.0.113.9', family: 4 },
                { address: '2001:db8::9', family: 6 },
            ],
            family: undefined,
        })
        expect(await lookup(resolve, false)).toEqual({ err: null, address: '203.0.113.9', family: 4 })
    })

    it('fails when nothing public is left', async () => {
        const { err } = await lookup(answering('127.0.0.1', '169.254.169.254').resolve, false)
        expect(err).toBeInstanceOf(PrivateTargetError)
        expect((err as PrivateTargetError).addresses).toEqual(['127.0.0.1', '169.254.169.254'])
    })

    it('passes a resolver error through', async () => {
        const failing = (_h: string, _o: unknown, cb: (err: NodeJS.ErrnoException | null, a: LookupAddress[]) => void) =>
            cb(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }), [])
        const { err } = await lookup(failing, false)
        expect((err as NodeJS.ErrnoException).code).toBe('ENOTFOUND')
    })
})

describe("resolveConfig's default fetch in Node", () => {
    const signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
    const base: Config = { signer, network: testnet() }

    it('refuses a private address, as Go’s default client does', async () => {
        await refusal(resolveConfig(base).fetch(`http://127.0.0.1:${port}/`))
    })

    it('dials one with allowPrivateHosts, sending the init as given', async () => {
        const fetch = resolveConfig({ ...base, allowPrivateHosts: true }).fetch
        expect(await (await fetch(`http://127.0.0.1:${port}/`)).json()).toEqual(GET)
        expect(await (await fetch(`http://127.0.0.1:${port}/`, POST_INIT)).json()).toEqual(POSTED)
    })
})
