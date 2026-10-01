/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'

import {
    decodeInnerRequest,
    encodeInnerRequest,
    type InnerRequestHeader,
} from '../src/wire/inner.js'

const utf8 = (s: string) => new TextEncoder().encode(s)

describe('inner request frame', () => {
    it('round-trips header and body', () => {
        const header: InnerRequestHeader = {
            reply_to_public_key: 'age1qqq',
            algorand_tx_id: 'TXABC',
            ticket_id: 'dGlja2V0',
            admission_tag: 'dGFn',
        }
        const body = utf8('{"model":"gpt-4","messages":[]}')

        const { header: gotHeader, body: gotBody } = decodeInnerRequest(encodeInnerRequest(header, body))
        expect(gotHeader).toEqual(header)
        expect(gotBody).toEqual(body)
    })

    // The admission tag and the receipt's body_hash both commit to sha256(body),
    // so the framing must return the body's exact bytes — including whitespace a
    // JSON re-serialization would drop.
    it('preserves body bytes exactly', () => {
        const body = utf8('{\n  "model" : "gpt-4",\n  "n":\t1\n}\n')
        const { body: got } = decodeInnerRequest(encodeInnerRequest({ reply_to_public_key: 'age1', algorand_tx_id: '' }, body))
        expect(got).toEqual(body)
    })

    it('handles an empty body', () => {
        const { body } = decodeInnerRequest(
            encodeInnerRequest({ reply_to_public_key: 'age1', algorand_tx_id: '' }, new Uint8Array()),
        )
        expect(body.length).toBe(0)
    })

    // Pins the framing against proto/go/wire/inner.go: "zsrq" || u8 version ||
    // u32be headerLen. Only the node (Go) decodes what TS encodes, so the
    // header JSON's key order is free, but these prefix bytes are not.
    //
    // The header is deliberately multibyte. headerLen must count BYTES, not
    // UTF-16 code units — `JSON.stringify(header).length` would under-count and
    // Go would slice the header short, failing on every non-ASCII input. An
    // ASCII-only fixture cannot see that bug.
    it('emits the Go-compatible frame prefix with a byte-counted headerLen', () => {
        const header = { reply_to_public_key: 'age1é☃', algorand_tx_id: 'TX' }
        const frame = encodeInnerRequest(header, utf8('ünicode ☃ body'))
        expect(Array.from(frame.subarray(0, 4))).toEqual([...utf8('zsrq')])
        expect(frame[4]).toBe(1)

        const headerLen = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(5, false)
        expect(headerLen).toBe(utf8(JSON.stringify(header)).length)
        expect(headerLen).toBeGreaterThan(JSON.stringify(header).length) // bytes > code units

        const headerJSON = JSON.parse(new TextDecoder().decode(frame.subarray(9, 9 + headerLen)))
        expect(headerJSON.reply_to_public_key).toBe('age1é☃')
        expect(headerJSON.algorand_tx_id).toBe('TX')
        expect(new TextDecoder().decode(frame.subarray(9 + headerLen))).toBe('ünicode ☃ body')
    })

    it('rejects malformed frames', () => {
        const good = encodeInnerRequest({ reply_to_public_key: 'age1', algorand_tx_id: '' }, utf8('body'))

        const withHeaderLen = (len: number) => {
            const f = good.slice()
            new DataView(f.buffer).setUint32(5, len, false)
            return f
        }
        const mutate = (i: number, v: number) => {
            const f = good.slice()
            f[i] = v
            return f
        }

        expect(() => decodeInnerRequest(good.subarray(0, 8))).toThrow(/truncated/)
        expect(() => decodeInnerRequest(mutate(0, 0x78))).toThrow(/bad magic/)
        expect(() => decodeInnerRequest(mutate(4, 2))).toThrow(/version/)
        expect(() => decodeInnerRequest(withHeaderLen(good.length))).toThrow(/past end/)
        expect(() => decodeInnerRequest(withHeaderLen((64 << 10) + 1))).toThrow(/exceeds max/)
        expect(() => decodeInnerRequest(mutate(9, 0x5b))).toThrow(/parse inner request header/)
    })
})
