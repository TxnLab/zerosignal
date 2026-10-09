/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The sealed events a node emits while it runs a built-in tool or an image
// generation, and the action a tool round reports. Mirrors
// proto/go/tools/tool_status.go and tool_action.go.
//
// These ride the `event: zs` SSE channel and are sealed like any content frame,
// so they reach a payer only after decryptSSEDataValue. A consumer that doesn't
// know one of these types can ignore it.

import {
    ICON_MIME_JPEG,
    ICON_MIME_PNG,
    ICON_MIME_WEBP,
    base64DecodedLength,
    iconHostKey,
    sanitizeIcons,
    sniffBase64Mime,
    type SourceIcon,
} from './icon.js'
import { isLinkableUrl } from './url.js'

export const STATUS_EVENT_TOOL_CALL_IN_PROGRESS = 'response.zs_tool_call.in_progress'
export const STATUS_EVENT_TOOL_CALL_COMPLETED = 'response.zs_tool_call.completed'
export const STATUS_EVENT_IMAGE_PROGRESS = 'response.zs_image.progress'
export const STATUS_EVENT_IMAGE_PARTIAL = 'response.zs_image.partial'
export const STATUS_EVENT_IMAGE_COMPLETED = 'response.zs_image.completed'

// OpenAI's web_search_call.action vocabulary, so a renderer for that can render these.
export const ACTION_TYPE_SEARCH = 'search'
export const ACTION_TYPE_OPEN_PAGE = 'open_page'

// The bounds a node applies before emitting an action.
export const MAX_ACTION_SOURCES = 20
export const MAX_ACTION_QUERY_BYTES = 512
export const MAX_ACTION_URL_BYTES = 2048

/** One URL a tool round consulted. type is always "url". */
export interface ActionSource {
    type: string
    url: string
}

/**
 * What a tool round is doing: the query it searched, the page it read, and the
 * sources it found. `query` is prompt-derived: fine to show the payer, who
 * wrote the prompt, never fine to log.
 */
export interface ToolAction {
    type: typeof ACTION_TYPE_SEARCH | typeof ACTION_TYPE_OPEN_PAGE
    /** Only on a search. */
    query?: string
    /** Only on an open_page, and only once the node has actually fetched it. */
    url?: string
    sources?: ActionSource[]
    /**
     * Favicons for the sources' sites, keyed by iconHostKey. A node sends a
     * host's icon once per stream, so cache these by host for the life of the
     * stream (SPEC §5.3.1) — and no longer: they are third-party bytes, not
     * something to persist.
     */
    icons?: Record<string, SourceIcon>
}

export interface ToolCallStatusFrame {
    type: typeof STATUS_EVENT_TOOL_CALL_IN_PROGRESS | typeof STATUS_EVENT_TOOL_CALL_COMPLETED
    item_id: string
    output_index: number
    tool: string
    call_id?: string
    action?: ToolAction
}

/** Sampling-step progress for an in-flight image: value of max, for the current stage. */
export interface ImageProgressFrame {
    type: typeof STATUS_EVENT_IMAGE_PROGRESS
    item_id: string
    value: number
    max: number
    node?: string
}

/** A low-resolution preview render. Image content: never log it. */
export interface ImagePartialFrame {
    type: typeof STATUS_EVENT_IMAGE_PARTIAL
    item_id: string
    partial_image_b64: string
    /** The node's label; partialImageDataUrl goes by the bytes instead. */
    mime?: string
}

/** The terminal frame of a streamed image route: the buffered response body, nested. */
export interface ImageCompletedFrame {
    type: typeof STATUS_EVENT_IMAGE_COMPLETED
    item_id: string
    response: Record<string, unknown>
}

export type ZsStatusEvent = ToolCallStatusFrame | ImageProgressFrame | ImagePartialFrame | ImageCompletedFrame

// The formats a preview render comes in.
const PARTIAL_MIMES: ReadonlySet<string> = new Set([ICON_MIME_JPEG, ICON_MIME_PNG, ICON_MIME_WEBP])

type Obj = Record<string, unknown>

function isObj(v: unknown): v is Obj {
    return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function str(v: unknown): string | undefined {
    return typeof v === 'string' && v.length > 0 ? v : undefined
}

function count(v: unknown): number | undefined {
    return Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : undefined
}

const encoder = new TextEncoder()

// Bounded but never truncated: a clipped URL points at a different resource
// than the one the node fetched.
function linkable(v: unknown): string | undefined {
    return isLinkableUrl(v) && encoder.encode(v).length <= MAX_ACTION_URL_BYTES ? v : undefined
}

// Clips s to at most max UTF-8 bytes without splitting a code point.
function clipUtf8(s: string, max: number): string {
    if (encoder.encode(s).length <= max) return s
    let bytes = 0
    let end = 0
    for (const cp of s) {
        const n = encoder.encode(cp).length
        if (bytes + n > max) break
        bytes += n
        end += cp.length
    }
    return s.slice(0, end)
}

/**
 * Applies the rules a node follows when it builds an action to one read off
 * the wire, or null when there is nothing to show. A query is trimmed and
 * clipped to MAX_ACTION_QUERY_BYTES; a URL that is too long or not linkable is
 * dropped rather than shortened; sources are de-duplicated and capped; and an
 * icon survives only for the host of one of the action's own sources.
 */
export function parseToolAction(raw: unknown): ToolAction | null {
    if (!isObj(raw)) return null
    const type = raw.type
    if (type !== ACTION_TYPE_SEARCH && type !== ACTION_TYPE_OPEN_PAGE) return null
    const out: ToolAction = { type }
    if (type === ACTION_TYPE_SEARCH) {
        const query = clipUtf8(str(raw.query)?.trim() ?? '', MAX_ACTION_QUERY_BYTES)
        if (query !== '') out.query = query
    } else {
        const url = linkable(raw.url)
        if (url !== undefined) out.url = url
    }
    const hosts = new Set<string>()
    if (Array.isArray(raw.sources)) {
        const seen = new Set<string>()
        const sources: ActionSource[] = []
        for (const s of raw.sources) {
            if (sources.length === MAX_ACTION_SOURCES) break
            if (!isObj(s) || s.type !== 'url') continue
            const u = linkable(s.url)
            if (u === undefined || seen.has(u)) continue
            seen.add(u)
            sources.push({ type: 'url', url: u })
            hosts.add(iconHostKey(u) as string)
        }
        if (sources.length > 0) out.sources = sources
    }
    const icons = sanitizeIcons(raw.icons)
    if (icons !== null) {
        for (const host of Object.keys(icons)) if (!hosts.has(host)) delete icons[host]
        if (Object.keys(icons).length > 0) out.icons = icons
    }
    if (out.query === undefined && out.url === undefined && out.sources === undefined) return null
    return out
}

/**
 * A data: URL for a preview render, typed by its own bytes, or null when they
 * are not JPEG, PNG or WebP. The frame's mime is the node's label, and a label
 * is not what decides how a page interprets bytes it inlines.
 */
export function partialImageDataUrl(frame: Pick<ImagePartialFrame, 'partial_image_b64'>): string | null {
    const mime = sniffBase64Mime(frame.partial_image_b64)
    return PARTIAL_MIMES.has(mime) ? `data:${mime};base64,${frame.partial_image_b64}` : null
}

/**
 * Parses an unsealed `event: zs` payload into one of the tool or image status
 * events, or null for any other type or a frame missing what it needs. A
 * malformed optional field (an action, a node label, a mime) is dropped and the
 * frame kept: losing a progress indicator is better than losing the stream.
 */
export function parseStatusEvent(raw: unknown): ZsStatusEvent | null {
    if (!isObj(raw)) return null
    const itemId = str(raw.item_id)
    if (itemId === undefined) return null
    switch (raw.type) {
        case STATUS_EVENT_TOOL_CALL_IN_PROGRESS:
        case STATUS_EVENT_TOOL_CALL_COMPLETED: {
            const tool = str(raw.tool)
            const outputIndex = count(raw.output_index)
            if (tool === undefined || outputIndex === undefined) return null
            const out: ToolCallStatusFrame = { type: raw.type, item_id: itemId, output_index: outputIndex, tool }
            const callId = str(raw.call_id)
            if (callId !== undefined) out.call_id = callId
            const action = parseToolAction(raw.action)
            if (action !== null) out.action = action
            return out
        }
        case STATUS_EVENT_IMAGE_PROGRESS: {
            const value = count(raw.value)
            const max = count(raw.max)
            if (value === undefined || max === undefined || max === 0) return null
            const out: ImageProgressFrame = { type: raw.type, item_id: itemId, value, max }
            const node = str(raw.node)
            if (node !== undefined) out.node = node
            return out
        }
        case STATUS_EVENT_IMAGE_PARTIAL: {
            const b64 = str(raw.partial_image_b64)
            if (b64 === undefined || base64DecodedLength(b64) <= 0) return null
            const out: ImagePartialFrame = { type: raw.type, item_id: itemId, partial_image_b64: b64 }
            if (typeof raw.mime === 'string' && PARTIAL_MIMES.has(raw.mime)) out.mime = raw.mime
            return out
        }
        case STATUS_EVENT_IMAGE_COMPLETED:
            return isObj(raw.response) ? { type: raw.type, item_id: itemId, response: raw.response } : null
        default:
            return null
    }
}
