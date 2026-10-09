/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { withHeaderBackstop } from '../src/header-backstop.js'
import type { Fetch } from '../src/ports.js'

// A fetch that answers only when respond is called, or rejects with the
// signal's reason, as a runtime's fetch does.
function pending() {
    const seen: { signal?: AbortSignal; respond?: () => void } = {}
    const f: Fetch = (_, init) => {
        seen.signal = init!.signal!
        return new Promise<Response>((resolve, reject) => {
            seen.respond = () => resolve(new Response('body'))
            init!.signal!.addEventListener('abort', () => reject(init!.signal!.reason), { once: true })
        })
    }
    return { seen, f: withHeaderBackstop(f, 1000) }
}

describe('withHeaderBackstop', () => {
    beforeEach(() => {
        vi.useFakeTimers()
    })
    afterEach(() => {
        vi.useRealTimers()
    })

    it('sends the request as given, adding only its signal', async () => {
        const seen: RequestInit[] = []
        const f = withHeaderBackstop(async (_, init) => {
            seen.push(init!)
            return new Response()
        }, 1000)
        await f('http://x.example', { method: 'POST', headers: { 'x-a': 'b' }, body: 'payload' })
        expect(seen).toHaveLength(1)
        expect(seen[0]).toMatchObject({ method: 'POST', headers: { 'x-a': 'b' }, body: 'payload' })
        expect(seen[0]!.signal).toBeInstanceOf(AbortSignal)
    })

    it('gives up once the headers are late, with a TimeoutError', async () => {
        const { f } = pending()
        const p = f('http://x.example')
        const settled = vi.fn()
        p.then(settled, settled)
        await vi.advanceTimersByTimeAsync(999)
        expect(settled).not.toHaveBeenCalled()
        await vi.advanceTimersByTimeAsync(1)
        const err = await p.catch((e: unknown) => e)
        expect(err).toBeInstanceOf(DOMException)
        expect(err).toMatchObject({ name: 'TimeoutError', message: 'timeout awaiting response headers' })
    })

    it('puts no bound on the body once the headers are in', async () => {
        const { seen, f } = pending()
        const p = f('http://x.example')
        await vi.advanceTimersByTimeAsync(990)
        seen.respond!()
        await p
        await vi.advanceTimersByTimeAsync(10_000)
        expect(seen.signal!.aborted).toBe(false)
    })

    it('still ends on the caller’s signal, given in init or on a Request, and leaves it unaborted itself', async () => {
        const { seen, f } = pending()
        const viaInit = new AbortController()
        const a = f('http://x.example', { signal: viaInit.signal })
        viaInit.abort(new Error('left'))
        await expect(a).rejects.toThrow('left')
        const viaRequest = new AbortController()
        const b = f(new Request('http://x.example', { signal: viaRequest.signal }))
        viaRequest.abort(new Error('left too'))
        await expect(b).rejects.toThrow('left too')
        expect(seen.signal!.aborted).toBe(true)

        const caller = new AbortController()
        const c = f('http://x.example', { signal: caller.signal })
        c.catch(() => {})
        await vi.advanceTimersByTimeAsync(1000)
        await expect(c).rejects.toMatchObject({ name: 'TimeoutError' })
        expect(caller.signal.aborted).toBe(false)
    })
})
