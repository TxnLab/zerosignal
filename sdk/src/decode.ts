/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The node's decrypted frames as typed events. Mirrors proto/go/zs's decoder
// (decode.go); testdata/stream_events_vectors.json pins it against Go's.
//
// Every node frame is untrusted. A frame that does not parse yields no events
// rather than an error, and each field is read on its own, so one field of an
// unexpected type costs that field alone: the frame still reaches the caller,
// and the receipt is what settles the charge.
//
// Differences from Go, all from reading parsed JSON rather than bytes: a
// frame can be handed over already parsed (frameValue); a tool action's icons
// are taken in the order the parsed object keeps, which puts a host that is a
// whole number first where Go keeps the order sent, and so differs only past
// the icon caps; a chat choice whose index is written 0.0 or -0 counts as the
// first, where Go wants the literal 0; and an escaped lone surrogate stays in
// a string, where Go's decoder replaces it with U+FFFD.

import { newError } from './codes.js'
import { type NodeReply, ProviderError, type ZsError } from './errors.js'
import type {
    AnnotationAdded,
    Done,
    Event,
    ItemClosed,
    ItemOpened,
    ReasoningDelta,
    TextDelta,
    ToolCallDelta,
    Usage,
} from './events.js'
import type { Endpoint, Item } from './types.js'

type Obj = Record<string, unknown>

interface FnCall {
    id: string
    name: string
}

/** The usage source of counts the response itself reported, as opposed to the receipt's. */
export const USAGE_SOURCE_RESPONSE = 'response'

/**
 * StreamDecoder reads one response in the dialect its endpoint answers in:
 * Responses API events on /v1/responses, Chat Completions chunks on
 * /v1/chat/completions, and the image routes' zs_image events.
 */
export class StreamDecoder {
    private readonly responses: boolean
    private readonly images: boolean
    // Set by the node's sealed word that generation ended. The plaintext
    // [DONE] after a stream is not authenticated, so it is not evidence.
    private finished = false
    // Set by anything a caller would show as the answer: text that is not
    // blank, a refusal, a tool call, or an image. Reasoning is not one.
    private answered = false
    private finish = ''
    private incomplete = ''
    private failure: ZsError | null = null
    // A Responses function_call item's call id and name, which its argument
    // deltas do not repeat.
    private readonly fnCalls = new Map<string, FnCall>()
    // A zs tool call's call id and tool, which its completed event does not repeat.
    private readonly zsCalls = new Map<string, FnCall>()
    // A chat tool call's id and name by index, which only its first chunk carries.
    private readonly chatCalls = new Map<number, FnCall>()

    constructor(endpoint: Endpoint | string) {
        this.responses = endpoint === '/v1/responses'
        this.images = endpoint === '/v1/images/generations' || endpoint === '/v1/images/edits'
    }

    /**
     * outcome is how the turn ends once its response is over: the error the
     * node reported, else done if the node said generation ended, else an
     * interrupted turn, since nothing authenticated says the answer is whole.
     */
    outcome(): Done | ZsError {
        if (this.failure !== null) return this.failure
        if (this.finished) {
            return {
                type: 'done',
                finishReason: this.finish,
                incompleteReason: this.incomplete,
                empty: !this.answered,
            }
        }
        return newError('stream_interrupted', 'the stream ended before the node said generation finished')
    }

    /** @internal The error the node reported in place of content, or null; for the stream emitter. */
    reportedFailure(): ZsError | null {
        return this.failure
    }

    /**
     * @internal For the stream emitter.
     * replyStatus folds a single-body reply's HTTP status into the outcome,
     * once body has decoded it. A reply the node marked failed is not a
     * finished answer even when its body doesn't say why, and a failure the
     * body did report takes the reply's status and retryAfterMs.
     */
    replyStatus(reply: NodeReply, retryAfterMs: number): void {
        if (reply.status < 400) return
        this.failure ??= newError('upstream_error', `the node answered HTTP ${reply.status}`, { cause: reply })
        if (retryAfterMs > 0) (this.failure as { retryAfter?: number }).retryAfter = retryAfterMs
        if (this.failure.cause instanceof ProviderError) this.failure.cause.status = reply.status
    }

    /** frame decodes one streamed frame's data. */
    frame(data: string): Event[] {
        return this.frameValue(parse(data))
    }

    /** frameValue decodes one streamed frame the caller already parsed. */
    frameValue(value: unknown): Event[] {
        const top = object(value)
        if (top === null || this.noteFailure(top)) return []
        if (this.responses || this.images) return this.responsesEvent(top)
        return this.chatChunk(top)
    }

    /** body decodes a single-body reply. A whole reply is generation's end. */
    body(data: string): Event[] {
        this.finished = true
        const top = object(parse(data))
        if (top === null || this.noteFailure(top)) return []
        if (this.images) {
            this.answered ||= array(top.data).length > 0
            return []
        }
        if (this.responses) return this.responsesBody(top)
        return this.chatBody(top)
    }

    // noteFailure records an error the node reported in place of content: the
    // Responses API's error and response.failed events, or a chat error
    // envelope (an "error" that is not null, and no "choices"). The node's
    // code rides a ProviderError, never as the error's code: it is the node's
    // choice, and an SDK code there would read as the SDK's own finding.
    private noteFailure(top: Obj): boolean {
        let errObj: Obj | null
        switch (str(top.type)) {
            case 'error':
                errObj = top
                break
            case 'response.failed':
                errObj = object(object(top.response)?.error)
                break
            default: {
                const raw = top.error
                if (raw === undefined || raw === null) return false
                if ('choices' in top) return false
                // A bare string or other non-object still means the reply failed.
                errObj = object(raw) ?? { message: raw }
            }
        }
        if (this.failure === null) {
            const pe = new ProviderError(codeString(errObj?.code), str(errObj?.message))
            const msg = pe.message === '' ? 'the provider behind the node failed' : pe.message
            this.failure = newError('upstream_error', msg, { cause: pe })
        }
        return true
    }

    // responsesEvent decodes one Responses API event, or an image route's
    // zs_image event, which share its shape.
    private responsesEvent(top: Obj): Event[] {
        switch (str(top.type)) {
            case 'response.output_item.added': {
                const it = item(top.item)
                if (it === null) return []
                if (it.type === 'function_call') {
                    this.answered = true
                    const f = object(it.raw)
                    this.fnCalls.set(it.id, { id: str(f?.call_id), name: str(f?.name) })
                }
                return [{ type: 'item.opened', item: it } satisfies ItemOpened]
            }
            case 'response.output_item.done': {
                const it = item(top.item)
                if (it === null) return []
                if (isImageItem(it)) this.answered = true
                return [{ type: 'item.closed', item: it } satisfies ItemClosed]
            }
            case 'response.output_text.delta': {
                const delta = str(top.delta)
                this.noteAnswer(delta)
                return [{ type: 'delta.text', itemId: str(top.item_id), delta } satisfies TextDelta]
            }
            case 'response.refusal.delta':
                // A refusal is an answer, but not answer text: it stays in the frame.
                this.noteAnswer(str(top.delta))
                return []
            case 'response.reasoning_text.delta':
            case 'response.reasoning_summary_text.delta':
                return [{ type: 'delta.reasoning', itemId: str(top.item_id), delta: str(top.delta) } satisfies ReasoningDelta]
            case 'response.function_call_arguments.delta': {
                const id = str(top.item_id)
                const fc = this.fnCalls.get(id) ?? { id: '', name: '' }
                return [toolCallDelta(id, fc, str(top.delta))]
            }
            case 'response.output_text.annotation.added': {
                const ann = top.annotation
                if (ann === undefined || ann === null) return []
                return [{ type: 'annotation.added', itemId: str(top.item_id), annotation: ann } satisfies AnnotationAdded]
            }
            case 'response.zs_tool_call.in_progress': {
                const itemId = str(top.item_id)
                const fc = { id: str(top.call_id), name: str(top.tool) }
                this.zsCalls.set(itemId, fc)
                this.answered = true
                const { action, icons } = toolAction(top.action)
                return [
                    { type: 'tool.status', itemId, callId: fc.id, name: fc.name, state: 'in_progress', action, icons },
                ]
            }
            case 'response.zs_tool_call.completed': {
                const itemId = str(top.item_id)
                const fc = this.zsCalls.get(itemId) ?? { id: '', name: '' }
                const { action, icons } = toolAction(top.action)
                return [
                    { type: 'tool.status', itemId, callId: fc.id, name: fc.name, state: 'completed', action, icons },
                ]
            }
            case 'response.zs_image.progress':
                return [{ type: 'image.progress', itemId: str(top.item_id), value: num(top.value), max: num(top.max) }]
            case 'response.zs_image.partial': {
                const b64 = str(top.partial_image_b64)
                if (b64 === '') return []
                return [{ type: 'image.partial', itemId: str(top.item_id), b64, mime: str(top.mime) }]
            }
            case 'response.zs_image.completed':
                this.finished = true
                this.answered ||= array(object(top.response)?.data).length > 0
                return []
            case 'response.completed':
            case 'response.incomplete':
                return this.responseEnd(object(top.response))
        }
        return []
    }

    // responseEnd records a Responses API response's status, which ends
    // generation, and returns its usage.
    private responseEnd(r: Obj | null): Event[] {
        this.finished = true
        this.finish = str(r?.status)
        if (this.finish === 'incomplete') {
            this.incomplete = str(object(r?.incomplete_details)?.reason)
            if (this.incomplete === '') this.incomplete = 'incomplete'
        }
        const u = object(r?.usage)
        if (u === null) return []
        return [
            usage(
                num(u.input_tokens),
                num(u.output_tokens),
                num(object(u.output_tokens_details)?.reasoning_tokens),
            ),
        ]
    }

    // responsesBody decodes a whole Responses API reply as the events its
    // stream would have carried, one item at a time.
    private responsesBody(top: Obj): Event[] {
        const evs: Event[] = []
        for (const raw of array(top.output)) {
            const it = item(raw)
            if (it === null) continue
            const f = object(raw)
            evs.push({ type: 'item.opened', item: it })
            switch (it.type) {
                case 'message':
                    for (const part of array(f?.content)) {
                        const p = object(part)
                        switch (str(p?.type)) {
                            case 'output_text': {
                                const text = str(p?.text)
                                this.noteAnswer(text)
                                evs.push({ type: 'delta.text', itemId: it.id, delta: text })
                                for (const a of array(p?.annotations)) {
                                    evs.push({ type: 'annotation.added', itemId: it.id, annotation: a })
                                }
                                break
                            }
                            case 'refusal':
                                this.noteAnswer(str(p?.refusal))
                                break
                        }
                    }
                    break
                case 'reasoning':
                    for (const part of [...array(f?.summary), ...array(f?.content)]) {
                        evs.push({ type: 'delta.reasoning', itemId: it.id, delta: str(object(part)?.text) })
                    }
                    break
                case 'function_call':
                    this.answered = true
                    evs.push(toolCallDelta(it.id, { id: str(f?.call_id), name: str(f?.name) }, str(f?.arguments)))
                    break
                default:
                    if (isImageItem(it)) this.answered = true
            }
            evs.push({ type: 'item.closed', item: it })
        }
        return [...evs, ...this.responseEnd(top)]
    }

    private chatChunk(top: Obj): Event[] {
        const evs: Event[] = []
        for (const ch of firstChoices(top)) {
            evs.push(...this.chatPart(object(ch.delta), true))
            const r = str(ch.finish_reason)
            if (r !== '') {
                this.finished = true
                this.finish = r
            }
        }
        return [...evs, ...chatUsage(top)]
    }

    private chatBody(top: Obj): Event[] {
        const evs: Event[] = []
        for (const ch of firstChoices(top)) {
            evs.push(...this.chatPart(object(ch.message), false))
            this.finish = str(ch.finish_reason)
        }
        return [...evs, ...chatUsage(top)]
    }

    // chatPart decodes a delta or a whole message. In a stream a tool call's
    // id and name arrive on its first chunk alone, keyed by its index.
    private chatPart(p: Obj | null, streamed: boolean): Event[] {
        if (p === null) return []
        const evs: Event[] = []
        // reasoning is vLLM's field; reasoning_content is DeepSeek's and the
        // older vLLM name. A backend may send both with the same text, so one
        // is read, the one the node's own translator prefers.
        let r = str(p.reasoning_content)
        if (r === '') r = str(p.reasoning)
        if (r !== '') evs.push({ type: 'delta.reasoning', itemId: '', delta: r })
        const c = contentText(p.content)
        if (c !== '') {
            this.noteAnswer(c)
            evs.push({ type: 'delta.text', itemId: '', delta: c })
        }
        this.noteAnswer(str(p.refusal))
        for (const raw of array(p.tool_calls)) {
            const tc = object(raw)
            if (tc === null) continue
            this.answered = true
            const fn = object(tc.function)
            const fc = { id: str(tc.id), name: str(fn?.name) }
            if (streamed) {
                const idx = num(tc.index)
                const prev = this.chatCalls.get(idx) ?? { id: '', name: '' }
                if (fc.id === '') fc.id = prev.id
                if (fc.name === '') fc.name = prev.name
                this.chatCalls.set(idx, fc)
            }
            evs.push(toolCallDelta('', fc, str(fn?.arguments)))
        }
        return evs
    }

    private noteAnswer(s: string): void {
        if (!isBlank(s)) this.answered = true
    }
}

// Blank is Go's unicode.IsSpace, which differs from String.prototype.trim's
// set: U+0085 is space and U+FEFF is not.
const SPACES = new Set([
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
    ...Array.from({ length: 0x200a - 0x2000 + 1 }, (_, i) => 0x2000 + i),
])

function isBlank(s: string): boolean {
    for (let i = 0; i < s.length; i++) if (!SPACES.has(s.charCodeAt(i))) return false
    return true
}

function toolCallDelta(itemId: string, fc: FnCall, argumentsDelta: string): ToolCallDelta {
    return { type: 'delta.tool_call', itemId, callId: fc.id, name: fc.name, argumentsDelta }
}

function usage(inputTokens: number, outputTokens: number, reasoningTokens: number): Usage {
    return { type: 'usage', inputTokens, outputTokens, reasoningTokens, source: USAGE_SOURCE_RESPONSE }
}

// firstChoices returns the choices that are a chunk's or reply's first, index
// 0. The events carry no choice index, so a request for several choices is
// decoded for the first alone; the rest reach the caller only as frames.
function firstChoices(top: Obj): Obj[] {
    const out: Obj[] = []
    for (const raw of array(top.choices)) {
        const ch = object(raw)
        if (ch === null) continue
        // An absent index is the first choice; one that is present must be 0.
        if ('index' in ch && ch.index !== 0) continue
        out.push(ch)
    }
    return out
}

// contentText reads chat content as a string, or as an array of text parts,
// which some providers send.
function contentText(raw: unknown): string {
    const s = str(raw)
    if (s !== '') return s
    let out = ''
    for (const part of array(raw)) {
        const p = object(part)
        const t = str(p?.type)
        if (t === 'text' || t === 'output_text') out += str(p?.text)
    }
    return out
}

function chatUsage(top: Obj): Event[] {
    const u = object(top.usage)
    if (u === null) return []
    return [
        usage(
            num(u.prompt_tokens),
            num(u.completion_tokens),
            num(object(u.completion_tokens_details)?.reasoning_tokens),
        ),
    ]
}

// item reads a Responses output item. A function_call may carry only its
// call_id, which then stands in for the id.
function item(raw: unknown): Item | null {
    const f = object(raw)
    const type = str(f?.type)
    if (type === '') return null
    let id = str(f?.id)
    if (id === '') id = str(f?.call_id)
    return { id, type, raw }
}

// isImageItem reports a zs image tool's finished item that holds an image.
function isImageItem(it: Item): boolean {
    if (it.type !== 'zs_image_generation_call' && it.type !== 'zs_image_edit_call') return false
    const f = object(it.raw)
    return str(f?.result) !== '' || array(f?.results).length > 0
}

// Icon limits, the node's own: a node chooses these bytes, and a caller may
// render them.
const MAX_ICONS = 12
const MAX_ICON_B64_CHARS = Math.floor((16 * 1024 + 2) / 3) * 4 // 16 KiB decoded
const MAX_ICONS_B64_CHARS = 96 * 1024
const ICON_HOST_RE = /^[a-z0-9._\-:[\]]{1,253}$/
// Standard base64 alone: a data URL is built by concatenation, so the
// alphabet is what keeps it a data URL and nothing else.
const ICON_B64_RE = /^[A-Za-z0-9+/]+={0,2}$/
// No SVG, which can carry script.
const ICON_MIMES = new Set(['image/x-icon', 'image/png', 'image/gif', 'image/jpeg', 'image/webp'])

// toolAction splits a zs tool call's action into the action without its
// icons, and the icons by host as data URLs.
function toolAction(raw: unknown): { action: unknown; icons: Record<string, string> } {
    const icons: Record<string, string> = {}
    const a = object(raw)
    if (a === null) return { action: null, icons }
    const { icons: iconsRaw, ...rest } = a
    let n = 0
    let total = 0
    for (const [host, value] of Object.entries(object(iconsRaw) ?? {})) {
        if (n >= MAX_ICONS) break
        const ic = object(value)
        const mime = str(ic?.mime)
        const b64 = str(ic?.data_b64)
        if (
            !ICON_HOST_RE.test(host) ||
            !ICON_MIMES.has(mime) ||
            b64.length === 0 ||
            b64.length > MAX_ICON_B64_CHARS ||
            total + b64.length > MAX_ICONS_B64_CHARS ||
            !ICON_B64_RE.test(b64)
        ) {
            continue
        }
        // Defined, not assigned: a host named __proto__ would otherwise hit
        // the prototype setter and vanish.
        Object.defineProperty(icons, host, {
            value: `data:${mime};base64,${b64}`,
            enumerable: true,
            writable: true,
            configurable: true,
        })
        total += b64.length
        n++
    }
    return { action: Object.keys(rest).length > 0 ? rest : null, icons }
}

function parse(data: string): unknown {
    try {
        return JSON.parse(data)
    } catch {
        return undefined
    }
}

function object(v: unknown): Obj | null {
    return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Obj) : null
}

function array(v: unknown): unknown[] {
    return Array.isArray(v) ? v : []
}

function str(v: unknown): string {
    return typeof v === 'string' ? v : ''
}

// num reads a non-negative whole number, or 0. Token counts and indexes are
// never fractional, so a fraction is a malformed field, not a rounding; past
// 2^53 a number no longer holds a whole number exactly.
function num(v: unknown): number {
    // `|| 0` turns -0, which passes the range check, into 0.
    return (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 2 ** 53 ? v : 0) || 0
}

// codeString renders an error code the node sent as a string or a number.
function codeString(v: unknown): string {
    if (typeof v === 'string') return v
    return typeof v === 'number' ? String(v) : ''
}
