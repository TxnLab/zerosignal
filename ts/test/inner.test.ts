/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'

import {
    decodeInnerRequest,
    encodeInnerRequest,
    type InnerRequestHeader,
    paymentFields,
} from '../src/wire/inner.js'
import * as age from 'age-encryption'
import { base64 } from '@scure/base'

import { decryptRequest } from '../src/wire/seal.js'
import { generateEphemeralIdentity } from '../src/wire/identity.js'
import { sealReserveRequest } from '../src/wire/reserveSeal.js'
import { openSettleAck, sealSettleAck } from '../src/wire/settleAck.js'
import { wrapRequest } from '../src/wire/wrap.js'

const utf8 = (s: string) => new TextEncoder().encode(s)

// TestPaymentFields
describe('paymentFields', () => {
    it.each([
        ['legacy', { algorand_tx_id: 'TX', open_group: 'G' }, 'TX', 'G'],
        ['neutral', { payment_ref: 'TX', payment_open: 'G' }, 'TX', 'G'],
        ['both agreeing', { algorand_tx_id: 'TX', payment_ref: 'TX', open_group: 'G', payment_open: 'G' }, 'TX', 'G'],
        ['mixed', { payment_ref: 'TX', open_group: 'G' }, 'TX', 'G'],
        ['neither', {}, '', ''],
    ])('reads %s names', (_name, fields, ref, open) => {
        expect(paymentFields({ reply_to_public_key: 'age1', ...fields })).toEqual({ ref, open })
    })

    // The admission tag binds the tx id, so admitting on the other value would
    // check a payment the tag never named.
    it.each([
        ['refs', { algorand_tx_id: 'TX', payment_ref: 'OTHER' }],
        ['opens', { algorand_tx_id: 'TX', open_group: 'G', payment_open: 'H' }],
    ])('refuses %s that disagree', (_name, fields) => {
        expect(() => paymentFields({ reply_to_public_key: 'age1', ...fields })).toThrow(/disagree/)
    })
})

// TestWrapRequestBound_WritesTheChosenNames
describe('wrapRequest names', () => {
    it.each([false, true])('neutralNames=%s writes only those names', async (neutralNames) => {
        const node = await generateEphemeralIdentity()
        const { envelope } = await wrapRequest({
            body: utf8('{}'),
            txID: 'TX',
            ticketID: 'T',
            nodeRecipient: node.recipient,
            openGroup: 'G',
            neutralNames,
        })
        const got = await decryptRequest(envelope, node.secret)
        expect([got.algorandTxID, got.openGroup, got.neutralNames]).toEqual(['TX', 'G', neutralNames])

        // The raw header carries only the chosen keys: an older node reads an
        // absent algorand_tx_id as '' and admits nothing.
        const d = new age.Decrypter()
        d.addIdentity(node.secret)
        const env = JSON.parse(new TextDecoder().decode(envelope)) as { ciphertext: string }
        const { header } = decodeInnerRequest(await d.decrypt(base64.decode(env.ciphertext)))
        const { reply_to_public_key: _reply, ...rest } = header
        expect(rest).toEqual(
            neutralNames
                ? { payment_ref: 'TX', ticket_id: 'T', payment_open: 'G' }
                : { algorand_tx_id: 'TX', ticket_id: 'T', open_group: 'G' },
        )
    })
})

// A payer-submitted open carries no group, so payment_ref alone must still
// read as the neutral names.
it('reads payment_ref alone as the neutral names', async () => {
    const node = await generateEphemeralIdentity()
    const { envelope } = await wrapRequest({ body: utf8('{}'), txID: 'TX', ticketID: 'T', nodeRecipient: node.recipient, neutralNames: true })
    const got = await decryptRequest(envelope, node.secret)
    expect([got.algorandTxID, got.neutralNames]).toEqual(['TX', true])
})

describe('decryptRequest refuses disagreeing names', () => {
    it.each([
        ['refs', { algorand_tx_id: 'TX', payment_ref: 'OTHER' }],
        ['opens', { algorand_tx_id: 'TX', open_group: 'G', payment_open: 'H' }],
    ])('%s', async (_name, fields) => {
        const node = await generateEphemeralIdentity()
        const e = new age.Encrypter()
        e.addRecipient(node.recipient)
        const inner = encodeInnerRequest({ reply_to_public_key: node.recipient, ...fields }, utf8('{}'))
        const envelope = utf8(JSON.stringify({ ciphertext: base64.encode(await e.encrypt(inner)) }))
        await expect(decryptRequest(envelope, node.secret)).rejects.toThrow(/disagree/)
    })

    // Go's json.Unmarshal refuses a non-string here; a TS peer must not read it as absent.
    it('refuses a non-string value', () => {
        expect(() => paymentFields({ reply_to_public_key: 'age1', algorand_tx_id: 1 as unknown as string, payment_ref: 'X' })).toThrow(
            /not a string/,
        )
    })
})

describe('openSettleAck', () => {
    it.each([
        ['settle_group', false],
        ['payment_settle', true],
    ] as const)('reads %s', async (_key, neutralNames) => {
        const node = await generateEphemeralIdentity()
        const sealed = await sealSettleAck({ ticket_id: 'T', settle_group: 'G' }, node.recipient, neutralNames)
        expect(await openSettleAck(sealed, node.secret)).toEqual({ ticket_id: 'T', settle_group: 'G', neutralNames })
    })

    it('reads a group named twice, agreeing, as the neutral name', async () => {
        const node = await generateEphemeralIdentity()
        const sealed = await sealReserveRequest(
            utf8(JSON.stringify({ ticket_id: 'T', settle_group: 'G', payment_settle: 'G' })),
            node.recipient,
        )
        expect(await openSettleAck(sealed, node.secret)).toEqual({ ticket_id: 'T', settle_group: 'G', neutralNames: true })
    })

    it('refuses a group named twice, differently', async () => {
        const node = await generateEphemeralIdentity()
        const sealed = await sealReserveRequest(
            utf8(JSON.stringify({ ticket_id: 'T', settle_group: 'G', payment_settle: 'H' })),
            node.recipient,
        )
        await expect(openSettleAck(sealed, node.secret)).rejects.toThrow(/disagree/)
    })
})

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

    // Go decodes a null header as the zero header.
    it('reads a null header as an empty one', () => {
        const frame = encodeInnerRequest({} as InnerRequestHeader, utf8('b'))
        const prefix = frame.length - utf8('{}').length - 1
        const withNull = new Uint8Array([...frame.subarray(0, prefix), ...utf8('null'), ...utf8('b')])
        new DataView(withNull.buffer).setUint32(prefix - 4, 4, false)
        const { header, body } = decodeInnerRequest(withNull)
        expect(header).toEqual({})
        expect(body).toEqual(utf8('b'))
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
