/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The read-side silence bound on a streamed answer. A fetch in a browser has
// no read timeout at all, and the SDK's Node fetch sets none, so a stream
// whose node or relay stops sending, without closing, would hold the turn and
// its escrow until the caller gave up. The bound is on bytes, not frames: a
// node's keepalive comment proves the hop is alive.
//
// Ported from the chat app's envelope-fetch watchdog, with its three budgets.
// Go's twin is go/zs/idle.go, tested per language.

/** Which budget a silence was measured against. */
export type StreamIdlePhase = 'pre-stream' | 'mid-stream' | 'tool-active'

/** The silence a streamed answer may keep, in milliseconds, by phase. */
export interface StreamIdle {
    /**
     * Before the first byte of the body. A reasoning model can buffer its
     * whole thinking window before the first frame.
     */
    preStream: number
    /** Between bytes once they flow. */
    midStream: number
    /**
     * Between bytes while the node runs an image tool, whose round sends
     * nothing until the image is done.
     */
    toolActive: number
}

export const DEFAULT_STREAM_IDLE: Readonly<StreamIdle> = { preStream: 300_000, midStream: 60_000, toolActive: 300_000 }

/** The node sent nothing for longer than the phase allows. It is the cause of the turn's stream_interrupted error. */
export class StreamIdleTimeoutError extends Error {
    readonly phase: StreamIdlePhase
    readonly timeoutMs: number

    constructor(timeoutMs: number, phase: StreamIdlePhase) {
        super(`no bytes from the node for ${timeoutMs}ms (${phase})`)
        this.name = 'StreamIdleTimeoutError'
        this.phase = phase
        this.timeoutMs = timeoutMs
    }
}

// The built-in tools whose round leaves the stream silent while it runs.
const IMAGE_TOOLS = new Set(['zs_image_generation', 'zs_image_edit'])

/**
 * IdleWatchdog times one stream's silences. start arms it, each chunk of the
 * body re-arms it, and when a silence outlives its budget it calls onIdle
 * once. While an image tool round is open, silences are measured against
 * toolActive; closing the last one re-arms against midStream at once, so a
 * node that hangs after the tool is still caught at the normal budget.
 *
 * pause and resume bracket the SDK's own work on a frame, which reads no
 * bytes meanwhile: a receipt's settle can take longer than a small budget,
 * and that wait is not the node's silence.
 */
export class IdleWatchdog {
    readonly #budgets: StreamIdle
    #onIdle: ((err: StreamIdleTimeoutError) => void) | undefined
    #timer: ReturnType<typeof setTimeout> | undefined
    #started = false
    #flowing = false
    #paused = false
    #stopped = false
    readonly #toolRounds = new Set<string>()

    constructor(budgets: StreamIdle) {
        this.#budgets = budgets
    }

    /** Arms the pre-stream budget; onIdle runs at most once. */
    start(onIdle: (err: StreamIdleTimeoutError) => void): void {
        if (this.#started || this.#stopped) return
        this.#started = true
        this.#onIdle = onIdle
        this.#arm()
    }

    /** A chunk of the body arrived. */
    chunk(): void {
        this.#flowing = true
        this.#arm()
    }

    /**
     * Reads one opened frame for an image tool round opening or closing. The
     * frame's text is decoded only when it could be one.
     */
    frame(text: () => string, raw: Uint8Array): void {
        if (!includesToolCall(raw)) return
        let top: unknown
        try {
            top = JSON.parse(text())
        } catch {
            return
        }
        if (typeof top !== 'object' || top === null) return
        const { type, item_id: itemId, tool } = top as Record<string, unknown>
        if (typeof itemId !== 'string') return
        const before = this.#toolRounds.size
        if (type === 'response.zs_tool_call.in_progress' && typeof tool === 'string' && IMAGE_TOOLS.has(tool)) {
            this.#toolRounds.add(itemId)
        } else if (type === 'response.zs_tool_call.completed') {
            this.#toolRounds.delete(itemId)
        } else {
            return
        }
        // Entering re-arms too, though the chunk that carried this frame just
        // did: the budget that chunk armed was the one for outside a round.
        if ((before === 0) !== (this.#toolRounds.size === 0)) this.#arm()
    }

    /** Disarms until resume. */
    pause(): void {
        this.#paused = true
        this.#disarm()
    }

    /** Re-arms the whole budget of the current phase. */
    resume(): void {
        this.#paused = false
        this.#arm()
    }

    /** Disarms for good. */
    stop(): void {
        this.#stopped = true
        this.#disarm()
    }

    #disarm(): void {
        if (this.#timer !== undefined) clearTimeout(this.#timer)
        this.#timer = undefined
    }

    #arm(): void {
        if (!this.#started || this.#paused || this.#stopped) return
        this.#disarm()
        const phase: StreamIdlePhase = !this.#flowing ? 'pre-stream' : this.#toolRounds.size > 0 ? 'tool-active' : 'mid-stream'
        const ms = phase === 'pre-stream' ? this.#budgets.preStream : phase === 'tool-active' ? this.#budgets.toolActive : this.#budgets.midStream
        this.#timer = setTimeout(() => {
            this.#timer = undefined
            if (this.#stopped) return
            this.stop()
            this.#onIdle?.(new StreamIdleTimeoutError(ms, phase))
        }, ms)
    }
}

/**
 * The largest buffered reply the SDK reads, Go's maxReplyBytes. The node puts
 * generated media in the body, base64, and caps none of it, so without this a
 * node or relay that never ends a body holds the turn, its escrow and the
 * payer's memory.
 */
export const MAX_REPLY_BYTES = 256 * 1024 * 1024

/**
 * readReply reads a buffered reply's body whole, refusing one over limit, Go's
 * readReply. The node writes a buffered reply's body with its headers, so
 * every silence in it is measured against midStream; null is no bound, and
 * undefined is the default budgets. A silence past that cancels the body and
 * rejects with the StreamIdleTimeoutError.
 */
export async function readReply(resp: Response, idle: StreamIdle | null | undefined, limit = MAX_REPLY_BYTES): Promise<Uint8Array> {
    if (resp.body === null) return new Uint8Array(0)
    const reader = resp.body.getReader()
    let cut: unknown
    const end = (err: Error) => {
        cut ??= err
        reader.cancel(err).catch(() => {})
    }
    let watchdog: IdleWatchdog | undefined
    if (idle !== null) {
        const mid = (idle ?? DEFAULT_STREAM_IDLE).midStream
        watchdog = new IdleWatchdog({ preStream: mid, midStream: mid, toolActive: mid })
        watchdog.start(end)
    }
    const parts: Uint8Array[] = []
    let size = 0
    try {
        for (;;) {
            let r: ReadableStreamReadResult<Uint8Array>
            try {
                r = await reader.read()
            } catch (err) {
                throw cut ?? err
            }
            if (cut !== undefined) throw cut
            if (r.done) break
            watchdog?.chunk()
            size += r.value.byteLength
            if (size > limit) {
                const tooLarge = new Error(`the node's reply is over ${limit} bytes`)
                end(tooLarge)
                throw tooLarge
            }
            parts.push(r.value)
        }
    } finally {
        watchdog?.stop()
    }
    if (parts.length === 1) return parts[0]!
    const out = new Uint8Array(size)
    let at = 0
    for (const p of parts) {
        out.set(p, at)
        at += p.byteLength
    }
    return out
}

const NEEDLE = new TextEncoder().encode('zs_tool_call')

// includesToolCall is whether raw holds the bytes of "zs_tool_call", so the
// frames that can't be a tool round's skip the parse.
function includesToolCall(raw: Uint8Array): boolean {
    const first = NEEDLE[0]!
    for (let i = raw.indexOf(first); i !== -1 && i + NEEDLE.length <= raw.length; i = raw.indexOf(first, i + 1)) {
        let j = 1
        while (j < NEEDLE.length && raw[i + j] === NEEDLE[j]) j++
        if (j === NEEDLE.length) return true
    }
    return false
}
