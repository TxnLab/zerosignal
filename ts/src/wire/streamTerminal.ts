/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Terminal-frame classification for streamed responses (SPEC.md § 5.3,
// "Consuming the settlement tail").
//
// Why this lives in proto rather than in each consumer: a stream's settlement
// tail (`zs-settle-group`, `zs-receipt`, `[DONE]`) arrives *after* the frame
// that tells a human the answer is done. A consumer that tears the stream down
// on that frame never reads the receipt — so it cannot verify the operator's
// charge, cannot protest it, and cannot co-sign the atomic settle. The ticket
// then lapses into whatever the operator unilaterally claimed, because
// `settleLapsed` reads payer silence as acceptance. Which frames are terminal
// is therefore a *payer-safety* property of the protocol, not a rendering
// detail, and both the reference proxy and the reference client MUST answer it
// identically.
//
// Mirrors proto/go/wire/stream_terminal.go — golden-vectored against it via
// proto/testdata/stream_vectors.json. Any edit here needs the matching Go edit
// plus a vectors regeneration, or both sides' vector tests fail.

/**
 * Which upstream event vocabulary a frame is read against.
 * - `chat`      — /v1/chat/completions: terminal on a choice's finish_reason,
 *                 errors as `{"error": {...}}`.
 * - `responses` — /v1/responses: terminal on the response.* lifecycle events,
 *                 errors as the union's `{"type":"error"}` member.
 */
export type StreamApi = 'chat' | 'responses'

/** What a decrypted content frame means for stream lifecycle. */
export interface FrameVerdict {
    /**
     * True when the node has finished producing output and the settlement tail
     * is next on the wire. A consumer MUST keep reading after a terminal frame
     * until `[DONE]` / stream end (bounded by its own idle timeout) even if its
     * caller has gone away.
     */
    terminal: boolean
    /**
     * True when this frame is an error envelope rather than content. Implies
     * `terminal` — every node error path writes the error frame, then the
     * zero-cost receipt, then `[DONE]`, then returns.
     */
    error: boolean
    /** Operator/upstream error text when `error` is true, else `''`. */
    message: string
}

// Fast-path markers for a terminal chat-completions frame: compact (vLLM and
// OpenAI, the common case) and single-space JSON forms. "tool_calls" is
// deliberately excluded — the node runs the tool and keeps generating, so it is
// NOT complete. A miss here is not the answer, only the end of the cheap path:
// chatGenerationComplete falls through to a real parse, because failing to
// recognize a terminal frame is this classifier's UNSAFE direction (the
// consumer cancels and drops the settlement tail).
const CHAT_GENERATION_COMPLETE_TOKENS = [
    '"finish_reason":"stop"',
    '"finish_reason": "stop"',
    '"finish_reason":"length"',
    '"finish_reason": "length"',
]

// The /v1/responses lifecycle events the node follows with the settlement
// tail.
const RESPONSES_TERMINAL_TYPES = [
    'response.completed',
    'response.incomplete',
    'response.failed',
]

// Prefilter needles: each terminal type in its quoted JSON-string form.
// Derived from the list above so the two can't drift. A hit means the frame
// MENTIONS a terminal type somewhere; responsesGenerationComplete then
// confirms it is the frame's own discriminator.
const RESPONSES_GENERATION_COMPLETE_TOKENS = RESPONSES_TERMINAL_TYPES.map((t) => `"${t}"`)

const decoder = new TextDecoder()

function asText(plaintext: Uint8Array | string): string {
    return typeof plaintext === 'string' ? plaintext : decoder.decode(plaintext)
}

function asRecord(value: unknown): Record<string, unknown> | null {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
    return value as Record<string, unknown>
}

/** `''` for an absent, null, or non-string member — see rawString in the Go twin. */
function memberString(obj: Record<string, unknown>, key: string): string {
    const v = obj[key]
    return typeof v === 'string' ? v : ''
}

/**
 * Whether a chat-completions frame carries a terminal finish_reason on any
 * choice.
 *
 * Two prefilters guard a real parse. A frame that never mentions finish_reason
 * can't be terminal, and a normal delta chunk mentions it only as
 * `"finish_reason":null` — carrying neither terminal value — so the hot path
 * still costs substring sweeps alone. Anything that gets past both is rare
 * enough (roughly one frame per stream) to afford a parse, and paying for it is
 * how `{"finish_reason" : "stop"}` from an unusually-spaced emitter still arms
 * the drain instead of silently disarming it.
 *
 * The prefilters match the Go twin byte-for-byte, including the fact that they
 * read the *raw* text: a frame that escapes its way out of them (`"stop"`)
 * is classified non-terminal by both implementations. That is a deliberate
 * bound on cost, and parity matters more here than either answer.
 */
function chatGenerationComplete(text: string): boolean {
    for (const t of CHAT_GENERATION_COMPLETE_TOKENS) {
        if (text.includes(t)) return true
    }
    if (!text.includes('"finish_reason"')) return false
    if (!text.includes('"stop"') && !text.includes('"length"')) return false
    let parsed: unknown
    try {
        parsed = JSON.parse(text)
    } catch {
        return false
    }
    const top = asRecord(parsed)
    if (top === null) return false
    const choices = top.choices
    if (!Array.isArray(choices)) return false
    for (const raw of choices) {
        // Not an object — skip it rather than failing the frame, so one junk
        // element can't hide a terminal sibling. Mirrors the Go `continue`.
        const choice = asRecord(raw)
        if (choice === null) continue
        const reason = memberString(choice, 'finish_reason')
        if (reason === 'stop' || reason === 'length') return true
    }
    return false
}

/**
 * Whether a /v1/responses frame IS one of the lifecycle terminals — not merely
 * one that mentions the name.
 *
 * A substring prefilter guards a real parse, the same shape as the chat path: a
 * frame that never mentions a terminal type can't be one, so ordinary deltas
 * still cost a couple of substring sweeps. What gets past it is rare — the
 * single real terminal frame per stream, plus the odd frame whose own content
 * quotes an event name — and affords a parse.
 *
 * The parse is not decoration. These frames carry text nobody on this side
 * chose: as of proto 9.4 a tool-round status frame embeds the model's own
 * search query (SPEC § 5.3.1 `action`), and `{"query":"response.completed"}`
 * matches the prefilter exactly; an output_text delta quoting the event name
 * does the same. Reading the top-level `type` is what separates "this frame is
 * the terminal" from "this frame talks about one". Without it a user who asks
 * about the Responses API mid-conversation flips the verdict, which is
 * user-controllable input steering a payer-safety signal.
 *
 * Unparseable input answers TRUE. Failing to recognize a terminal frame is this
 * classifier's unsafe direction — the consumer cancels and drops the settlement
 * tail — while a spurious terminal only arms the drain early. The prefilter has
 * already established that the text mentions a terminal type, so "malformed and
 * mentions one" is the right place to be generous.
 */
function responsesGenerationComplete(text: string): boolean {
    let mentions = false
    for (const t of RESPONSES_GENERATION_COMPLETE_TOKENS) {
        if (text.includes(t)) {
            mentions = true
            break
        }
    }
    if (!mentions) return false
    let parsed: unknown
    try {
        parsed = JSON.parse(text)
    } catch {
        return true
    }
    const top = asRecord(parsed)
    if (top === null) return true
    return RESPONSES_TERMINAL_TYPES.includes(memberString(top, 'type'))
}

/**
 * Reports whether a decrypted `event: zs` frame ends the node's generation, and
 * whether it is an error envelope.
 *
 * Substring checks before any JSON parse: this runs on every content frame on
 * the streaming hot path, and the overwhelmingly common case (a content delta)
 * must stay cheap.
 */
export function classifyStreamFrame(
    plaintext: Uint8Array | string,
    api: StreamApi,
): FrameVerdict {
    const text = asText(plaintext)
    const message = streamErrorMessage(text)
    if (message !== null) return { terminal: true, error: true, message }
    if (api === 'responses') {
        if (responsesGenerationComplete(text)) return { terminal: true, error: false, message: '' }
        return { terminal: false, error: false, message: '' }
    }
    if (chatGenerationComplete(text)) return { terminal: true, error: false, message: '' }
    return { terminal: false, error: false, message: '' }
}

/**
 * Returns the operator/upstream error message when `plaintext` is an error
 * envelope in either wire shape, else `null`:
 *
 *   - chat completions: `{"error": {...}}` with no `"choices"`
 *   - /v1/responses:    `{"type":"error", "code": …, "message": …}` — the
 *     Responses event union's error member, which carries no top-level
 *     `"error"` key at all
 *
 * Shape-sniffing rather than api-dispatched on purpose: it is also the
 * classifier for non-stream bodies and pre-envelope error bodies, which use the
 * chat shape on both endpoints. The two shapes are disjoint, so accepting
 * either costs nothing and removes a way to hold it wrong.
 */
export function streamErrorMessage(plaintext: Uint8Array | string): string | null {
    const text = asText(plaintext)
    // Cheap prefilter. `"error"` appears as the key in the chat shape and as
    // the *value* of "type" in the Responses shape, so one substring covers
    // both.
    if (!text.includes('"error"')) return null

    let parsed: unknown
    try {
        parsed = JSON.parse(text)
    } catch {
        return null
    }
    const obj = asRecord(parsed)
    if (obj === null) return null

    // Responses-API error event. `type` is the union discriminator, so an exact
    // "error" match cannot collide with a content event — the terminal failure
    // events are typed response.failed / response.incomplete and nest their
    // error object under "response", not at the top level.
    if (memberString(obj, 'type') === 'error') {
        const msg = memberString(obj, 'message')
        return msg !== '' ? msg : 'error'
    }

    // An error envelope has a non-null "error" object and no "choices" — a real
    // chunk/response carries choices (the usage-only chunk carries "choices":[],
    // so a present-but-empty choices is still not an error).
    const err = obj.error
    if (err === undefined || err === null) return null
    if ('choices' in obj) return null

    const errObj = asRecord(err)
    if (errObj !== null) {
        const msg = memberString(errObj, 'message')
        if (msg !== '') return msg
    }
    // Object present but no string message (e.g. nested/odd shape) — surface
    // the raw error object so the operator still sees the cause. Go compacts
    // the original bytes here, so the TS side must re-serialize with the same
    // key order the wire had; JSON.stringify preserves insertion order from
    // JSON.parse, which matches on the shapes the vectors pin.
    //
    // Not byte-identical in general, though: this round-trip renormalizes
    // numbers and escapes (`1e3` → `1000`, `é` → `é`) where Go echoes
    // the wire's spelling. That residue is accepted, not overlooked — `message`
    // is a log/display string on both sides, while `terminal` and `error` are
    // the cross-implementation guarantees and neither depends on this branch.
    return JSON.stringify(err)
}
