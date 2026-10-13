/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { IdleWatchdog, readReply } from '../src/idle.js'
import { DEFAULT_STREAM_IDLE, StreamIdleTimeoutError } from '../src/index.js'

const enc = new TextEncoder()

// replyOf is a body that sends parts, waiting gapMs before each after the
// first, then closes unless open; cancelled records the read's cancel.
function replyOf(parts: string[], gapMs = 0, open = false) {
    const cancelled: unknown[] = []
    const body = new ReadableStream<Uint8Array>({
        async start(c) {
            for (const [i, p] of parts.entries()) {
                if (i > 0) await new Promise((r) => setTimeout(r, gapMs))
                c.enqueue(enc.encode(p))
            }
            if (!open) c.close()
        },
        cancel(reason) {
            cancelled.push(reason)
        },
    })
    return { resp: new Response(body), cancelled }
}

describe('readReply', () => {
    const bound = { preStream: 60_000, midStream: 30, toolActive: 60_000 }

    // Before the first byte too: the node writes a buffered body with its
    // headers, so the pre-stream budget doesn't apply.
    it.each([
        ['before the first byte', [], 'pre-stream'],
        ['between bytes', ['ab'], 'mid-stream'],
    ] as const)('cuts a silence %s at the mid-stream budget', async (_, parts, phase) => {
        const { resp, cancelled } = replyOf([...parts], 0, true)
        const err = await readReply(resp, bound).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(StreamIdleTimeoutError)
        expect(err).toMatchObject({ phase, timeoutMs: 30 })
        expect(cancelled).toEqual([err])
    })

    // A transport may reject the pending read when the body is cancelled,
    // rather than end it; the cut is still the cause.
    it('reports the cut though the cancelled read rejects', async () => {
        let pending: ((err: unknown) => void) | undefined
        const reader = {
            read: () => new Promise((_, reject) => (pending = reject)),
            cancel: async () => pending?.(new DOMException('aborted', 'AbortError')),
        }
        const resp = { body: { getReader: () => reader } } as unknown as Response
        const err = await readReply(resp, bound).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(StreamIdleTimeoutError)
    })

    it('reads a body still flowing', async () => {
        const { resp } = replyOf(Array(10).fill('x'), 10)
        expect(new TextDecoder().decode(await readReply(resp, { ...bound, midStream: 100 }))).toBe('xxxxxxxxxx')
    })

    it('waits out the silence with no bound', async () => {
        const { resp } = replyOf(['a', 'b'], 60)
        expect(new TextDecoder().decode(await readReply(resp, null))).toBe('ab')
    })

    it('refuses a body over the limit', async () => {
        expect(new TextDecoder().decode(await readReply(replyOf(['123', '45']).resp, null, 5))).toBe('12345')
        const { resp, cancelled } = replyOf(['123', '456'], 0, true)
        const err = await readReply(resp, null, 5).catch((e: unknown) => e)
        expect(err).not.toBeInstanceOf(StreamIdleTimeoutError)
        expect((err as Error).message).toBe("the node's reply is over 5 bytes")
        expect(cancelled).toEqual([err])
    })

    it('reads no body as empty', async () => {
        expect(await readReply(new Response(null), bound)).toEqual(new Uint8Array(0))
    })
})

const BUDGETS = { preStream: 1000, midStream: 100, toolActive: 500 }

function watch() {
    const w = new IdleWatchdog(BUDGETS)
    const fired: StreamIdleTimeoutError[] = []
    w.start((e) => fired.push(e))
    return { w, fired }
}

// A tool round's frame, as the node seals it.
function tool(type: 'in_progress' | 'completed', itemId: string, name = 'zs_image_generation'): [() => string, Uint8Array] {
    const s = JSON.stringify({ type: `response.zs_tool_call.${type}`, item_id: itemId, tool: name })
    return [() => s, enc.encode(s)]
}

describe('IdleWatchdog', () => {
    beforeEach(() => {
        vi.useFakeTimers()
    })
    afterEach(() => {
        vi.useRealTimers()
    })

    it('keeps the chat app’s budgets by default', () => {
        expect(DEFAULT_STREAM_IDLE).toEqual({ preStream: 300_000, midStream: 60_000, toolActive: 300_000 })
    })

    it('fires once on the pre-stream budget before the first chunk', () => {
        const { fired } = watch()
        vi.advanceTimersByTime(999)
        expect(fired).toEqual([])
        vi.advanceTimersByTime(1)
        expect(fired).toHaveLength(1)
        const e = fired[0]!
        expect(e).toBeInstanceOf(StreamIdleTimeoutError)
        expect([e.name, e.phase, e.timeoutMs, e.message]).toEqual([
            'StreamIdleTimeoutError',
            'pre-stream',
            1000,
            'no bytes from the node for 1000ms (pre-stream)',
        ])
        vi.advanceTimersByTime(10_000)
        expect(fired).toHaveLength(1)
    })

    it('measures against the mid-stream budget once bytes flow, each chunk re-arming', () => {
        const { w, fired } = watch()
        vi.advanceTimersByTime(900)
        w.chunk()
        vi.advanceTimersByTime(99)
        w.chunk()
        vi.advanceTimersByTime(99)
        expect(fired).toEqual([])
        vi.advanceTimersByTime(1)
        expect(fired.map((e) => [e.phase, e.timeoutMs])).toEqual([['mid-stream', 100]])
    })

    it('measures against the tool budget while an image round is open, and drops back once it closes', () => {
        const { w, fired } = watch()
        w.chunk()
        w.frame(...tool('in_progress', 'a'))
        vi.advanceTimersByTime(499)
        expect(fired).toEqual([])
        w.chunk()
        w.frame(...tool('completed', 'a'))
        vi.advanceTimersByTime(99)
        expect(fired).toEqual([])
        vi.advanceTimersByTime(1)
        expect(fired.map((e) => [e.phase, e.timeoutMs])).toEqual([['mid-stream', 100]])
    })

    it('fires on the tool budget for a round that never closes', () => {
        const { w, fired } = watch()
        w.chunk()
        w.frame(...tool('in_progress', 'a', 'zs_image_edit'))
        vi.advanceTimersByTime(500)
        expect(fired.map((e) => [e.phase, e.timeoutMs])).toEqual([['tool-active', 500]])
    })

    it('stays on the tool budget until the last of several rounds closes', () => {
        const { w, fired } = watch()
        w.chunk()
        w.frame(...tool('in_progress', 'a'))
        w.frame(...tool('in_progress', 'b'))
        w.chunk()
        w.frame(...tool('completed', 'a'))
        vi.advanceTimersByTime(499)
        expect(fired).toEqual([])
        w.chunk()
        w.frame(...tool('completed', 'b'))
        vi.advanceTimersByTime(100)
        expect(fired.map((e) => e.phase)).toEqual(['mid-stream'])
    })

    // The chunk carrying the round's opening frame armed the mid-stream budget.
    it('moves to the tool budget on the opening frame, not the next chunk', () => {
        const { w, fired } = watch()
        w.chunk()
        vi.advanceTimersByTime(50)
        w.frame(...tool('in_progress', 'a'))
        vi.advanceTimersByTime(499)
        expect(fired).toEqual([])
        vi.advanceTimersByTime(1)
        expect(fired.map((e) => e.phase)).toEqual(['tool-active'])
    })

    it('re-arms the mid-stream budget when the last round closes, not leaving the tool budget running', () => {
        const { w, fired } = watch()
        w.chunk()
        w.frame(...tool('in_progress', 'a'))
        vi.advanceTimersByTime(300)
        w.frame(...tool('completed', 'a'))
        vi.advanceTimersByTime(100)
        expect(fired.map((e) => e.phase)).toEqual(['mid-stream'])
    })

    it('ignores other tools, other frames and a frame that won’t parse', () => {
        const { w, fired } = watch()
        w.chunk()
        w.frame(...tool('in_progress', 'a', 'zs_web_search'))
        const other = JSON.stringify({ type: 'response.output_text.delta', item_id: 'a', tool: 'zs_image_generation' })
        w.frame(() => other, enc.encode(other))
        const noItem = JSON.stringify({ type: 'response.zs_tool_call.in_progress', tool: 'zs_image_generation' })
        w.frame(() => noItem, enc.encode(noItem))
        w.frame(() => '{"zs_tool_call"', enc.encode('{"zs_tool_call"'))
        w.frame(() => '"zs_tool_call"', enc.encode('"zs_tool_call"'))
        vi.advanceTimersByTime(100)
        expect(fired.map((e) => e.phase)).toEqual(['mid-stream'])
    })

    it('decodes only the frames that could open or close a round', () => {
        const { w } = watch()
        w.chunk()
        const text = vi.fn(() => '{}')
        w.frame(text, enc.encode('{"type":"response.output_text.delta","delta":"zs_tool_cal"}'))
        expect(text).not.toHaveBeenCalled()
        w.frame(text, enc.encode('zzs_tool_call'))
        expect(text).toHaveBeenCalledTimes(1)
    })

    it('a completed frame for a round it never saw open changes nothing', () => {
        const { w, fired } = watch()
        w.chunk()
        vi.advanceTimersByTime(60)
        w.frame(...tool('completed', 'x'))
        vi.advanceTimersByTime(40)
        expect(fired.map((e) => e.phase)).toEqual(['mid-stream'])
    })

    // forwardStream feeds chunks until the abort it ordered lands.
    it('fires once, though bytes or a resume follow the fire', () => {
        const { w, fired } = watch()
        w.chunk()
        vi.advanceTimersByTime(100)
        w.chunk()
        w.resume()
        vi.advanceTimersByTime(10_000)
        expect(fired).toHaveLength(1)
    })

    it('doesn’t fire while paused, and resumes on the whole budget', () => {
        const { w, fired } = watch()
        w.chunk()
        vi.advanceTimersByTime(90)
        w.pause()
        vi.advanceTimersByTime(10_000)
        expect(fired).toEqual([])
        w.resume()
        vi.advanceTimersByTime(99)
        expect(fired).toEqual([])
        vi.advanceTimersByTime(1)
        expect(fired.map((e) => e.phase)).toEqual(['mid-stream'])
    })

    // The hook reads a tool round's frame while the watchdog is paused.
    it('stays paused through a round opening, and resumes on the tool budget', () => {
        const { w, fired } = watch()
        w.chunk()
        w.pause()
        w.frame(...tool('in_progress', 'a'))
        vi.advanceTimersByTime(10_000)
        expect(fired).toEqual([])
        w.resume()
        vi.advanceTimersByTime(500)
        expect(fired.map((e) => e.phase)).toEqual(['tool-active'])
    })

    it('stays stopped through a resume', () => {
        const { w, fired } = watch()
        w.stop()
        w.resume()
        vi.advanceTimersByTime(10_000)
        expect(fired).toEqual([])
    })

    it('never fires once stopped, nor restarts', () => {
        const { w, fired } = watch()
        w.chunk()
        w.stop()
        w.chunk()
        w.start((e) => fired.push(e))
        vi.advanceTimersByTime(10_000)
        expect(fired).toEqual([])
    })

    it('arms nothing before start, and a second start keeps the first callback', () => {
        const w = new IdleWatchdog(BUDGETS)
        const first: StreamIdleTimeoutError[] = []
        const second: StreamIdleTimeoutError[] = []
        w.chunk()
        vi.advanceTimersByTime(10_000)
        w.start((e) => first.push(e))
        w.start((e) => second.push(e))
        vi.advanceTimersByTime(100)
        expect([first.map((e) => e.phase), second]).toEqual([['mid-stream'], []])
    })
})
