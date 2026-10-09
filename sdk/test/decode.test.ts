/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// StreamDecoder, checked against testdata/stream_events_vectors.json, which
// Go's decoder generates from the same frames.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { type Event, ProviderError, StreamDecoder, ZsError } from '../src/index.js'

interface Case {
    name: string
    endpoint: string
    frames?: string[]
    // Text, so a number reaches the decoder as the node wrote it.
    body?: string
    events: Array<Record<string, unknown>>
    end: Record<string, unknown>
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/stream_events_vectors.json', import.meta.url), 'utf8'),
) as Case[]

// The vectors' own form of an event, as Go's vectorEvent writes it.
function vectorEvent(ev: Event): Record<string, unknown> {
    switch (ev.type) {
        case 'item.opened':
        case 'item.closed':
            return { type: ev.type, item_id: ev.item.id, item_type: ev.item.type }
        case 'delta.text':
        case 'delta.reasoning':
            return { type: ev.type, item_id: ev.itemId, delta: ev.delta }
        case 'delta.tool_call':
            return {
                type: ev.type,
                item_id: ev.itemId,
                call_id: ev.callId,
                name: ev.name,
                arguments_delta: ev.argumentsDelta,
            }
        case 'annotation.added':
            return { type: ev.type, item_id: ev.itemId, annotation: ev.annotation }
        case 'tool.status':
            return {
                type: ev.type,
                item_id: ev.itemId,
                call_id: ev.callId,
                name: ev.name,
                state: ev.state,
                action: ev.action,
                icons: ev.icons,
            }
        case 'image.progress':
            return { type: ev.type, item_id: ev.itemId, value: ev.value, max: ev.max }
        case 'image.partial':
            return { type: ev.type, item_id: ev.itemId, b64: ev.b64, mime: ev.mime }
        case 'usage':
            return {
                type: ev.type,
                input_tokens: ev.inputTokens,
                output_tokens: ev.outputTokens,
                reasoning_tokens: ev.reasoningTokens,
                source: ev.source,
            }
        default:
            return { type: ev.type, unexpected: true }
    }
}

function vectorEnd(end: ReturnType<StreamDecoder['outcome']>): Record<string, unknown> {
    if (end instanceof ZsError) {
        const e: Record<string, unknown> = { kind: end.kind, code: end.code, message: end.message }
        if (end.cause instanceof ProviderError) e.provider_code = end.cause.code
        return { error: e }
    }
    return {
        done: { finish_reason: end.finishReason, incomplete_reason: end.incompleteReason, empty: end.empty },
    }
}

function run(c: Case, parsed = false) {
    const d = new StreamDecoder(c.endpoint)
    const evs: Event[] = []
    if (c.body !== undefined) {
        evs.push(...d.body(c.body))
    } else {
        for (const f of c.frames ?? []) {
            if (!parsed) {
                evs.push(...d.frame(f))
                continue
            }
            let v: unknown
            try {
                v = JSON.parse(f)
            } catch {
                v = undefined
            }
            evs.push(...d.frameValue(v))
        }
    }
    return { events: evs.map(vectorEvent), end: vectorEnd(d.outcome()) }
}

describe('StreamDecoder vectors', () => {
    it('covers every case', () => expect(vectors.length).toBeGreaterThan(0))
    it.each(vectors.map((c) => [c.name, c] as const))('%s', (_name, c) => {
        expect(run(c)).toEqual({ events: c.events, end: c.end })
    })
    // A caller that parsed the frame itself gets the same events.
    it.each(vectors.filter((c) => c.frames !== undefined).map((c) => [c.name, c] as const))(
        'parsed: %s',
        (_name, c) => {
            expect(run(c, true)).toEqual({ events: c.events, end: c.end })
        },
    )
})
