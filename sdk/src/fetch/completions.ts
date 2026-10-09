/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The legacy /v1/completions endpoint, emulated over chat, mirroring
// proto/go/zs handler/completions.go: the request is rewritten into a chat
// request, so the node, relays, ticket and wire all see an ordinary chat
// request, and the chat reply is reshaped back into text-completion shape.
// Byte for byte as Go rewrites them, pinned by
// testdata/completions_vectors.json: the rewrite goes through Go's
// map[string]json.RawMessage, which sorts the keys and compacts every value.

import { decodeGoFields, goJSON, goMarshalRawObject, goMarshalRawObjects, goRawObject, goRawObjects } from '../gojson.js'
import { goDecodeUTF8, wellFormed } from '../gotext.js'

/** A request the emulation can't rewrite, as the OpenAI error it answers with. No reserve is spent on it. */
export interface CompletionsTranslateError {
    status: number
    type: string
    code: string
    message: string
}

const utf8 = new TextEncoder()

const UNSUPPORTED_PROMPT: CompletionsTranslateError = {
    status: 400,
    type: 'invalid_request_error',
    code: 'unsupported_prompt',
    message:
        'the /v1/completions compatibility shim accepts only a single string prompt (array and token-id prompts are not supported)',
}

/**
 * chatRequestFromCompletions rewrites a /v1/completions body as a
 * /v1/chat/completions body. The prompt becomes one user message; the
 * completions-only fields and logprobs, whose type differs between the two
 * APIs, are dropped; every other field rides through.
 */
export function chatRequestFromCompletions(body: Uint8Array): { body: Uint8Array } | { error: CompletionsTranslateError } {
    let raw: Map<string, Uint8Array> | null
    try {
        raw = goRawObject(body)
    } catch {
        return { error: { status: 400, type: 'invalid_request_error', code: 'invalid_json', message: 'request body is not valid JSON' } }
    }
    const promptRaw = raw?.get('prompt')
    if (raw === null || promptRaw === undefined) {
        return { error: { status: 400, type: 'invalid_request_error', code: 'missing_prompt', message: 'request body has no prompt field' } }
    }
    const prompt = completionsPromptText(promptRaw)
    if (prompt === null) return { error: UNSUPPORTED_PROMPT }
    for (const k of ['prompt', 'echo', 'best_of', 'suffix', 'logprobs']) raw.delete(k)
    // Go marshals a map[string]string, so content sorts before role.
    raw.set('messages', utf8.encode(`[{"content":${goJSON(prompt)},"role":"user"}]`))
    return { body: goMarshalRawObject(raw) }
}

// completionsPromptText is the prompt as Go reads it, first into a string and
// then into a []string, or null for a prompt the emulation can't represent
// as one conversation. null reads as an empty string, and so does a null
// element.
function completionsPromptText(raw: Uint8Array): string | null {
    const v: unknown = JSON.parse(goDecodeUTF8(raw))
    if (v === null) return ''
    if (typeof v === 'string') return wellFormed(v)
    if (!Array.isArray(v) || !v.every((e) => e === null || typeof e === 'string')) return null
    if (v.length !== 1) return null
    return wellFormed((v[0] as string | null) ?? '')
}

/**
 * completionsResponseFromChat reshapes a whole chat reply into a text
 * completion. Anything that isn't a chat completion, a sealed error among
 * them, passes through unchanged.
 */
export function completionsResponseFromChat(body: Uint8Array): Uint8Array {
    return reshapeChatToText(body, false) ?? body
}

/**
 * completionsChunkFromChat reshapes one streamed chat chunk (an SSE frame's
 * data) into a text-completion chunk, passing anything else through.
 */
export function completionsChunkFromChat(data: Uint8Array): Uint8Array {
    return reshapeChatToText(data, true) ?? data
}

/**
 * reshapeChatToText turns a chat completion, or a chunk when streaming, into
 * text-completion shape: object becomes "text_completion", and each choice's
 * message (or delta) becomes a flat text holding its content. It returns null,
 * for the caller to pass the input through, for anything else: an error
 * envelope, an object of another kind, or a body Go can't decode.
 */
export function reshapeChatToText(body: Uint8Array, streaming: boolean): Uint8Array | null {
    let raw: Map<string, Uint8Array> | null
    try {
        raw = goRawObject(body)
    } catch {
        return null
    }
    if (raw === null || raw.has('error')) return null
    let obj = ''
    const objRaw = raw.get('object')
    if (objRaw !== undefined) {
        // Go ignores the error, so a value that isn't a string leaves it empty.
        const v: unknown = JSON.parse(goDecodeUTF8(objRaw))
        if (typeof v === 'string') obj = wellFormed(v)
    }
    const want = streaming ? 'chat.completion.chunk' : 'chat.completion'
    const choicesRaw = raw.get('choices')
    // A recognized chat object, or one without an object that still carries
    // choices, for the rare upstream that omits it.
    if (obj !== want && !(obj === '' && choicesRaw !== undefined)) return null

    if (choicesRaw !== undefined) {
        let choices: (Map<string, Uint8Array> | null)[] | null
        try {
            choices = goRawObjects(choicesRaw)
        } catch {
            return null
        }
        const srcKey = streaming ? 'delta' : 'message'
        for (const ch of choices ?? []) {
            // A null choice is Go's nil map, which can't take the text.
            if (ch === null) return null
            let text = ''
            const msg = ch.get(srcKey)
            if (msg !== undefined) {
                try {
                    // A *string, so a later null content clears an earlier one.
                    const { content } = decodeGoFields(msg, { content: 'stringptr' })
                    if (typeof content === 'string') text = content
                } catch {
                    // Go reads no text from a message it can't decode.
                }
                ch.delete(srcKey)
            }
            ch.set('text', utf8.encode(goJSON(text)))
            // A completion's choice carries logprobs, null when not asked
            // for; SDKs that read it unconditionally would trip on its absence.
            if (!ch.has('logprobs')) ch.set('logprobs', utf8.encode('null'))
        }
        raw.set('choices', goMarshalRawObjects(choices))
    }
    raw.set('object', utf8.encode('"text_completion"'))
    return goMarshalRawObject(raw)
}
