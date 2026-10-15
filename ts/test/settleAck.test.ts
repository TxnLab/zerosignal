/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The sealed settle ack's TS round trip. The TS -> Go direction, which is the
// one production runs, is pinned by ts_sealed_vectors.json.

import { describe, expect, it } from 'vitest'
import * as age from 'age-encryption'

import {
    SEALED_RESERVE_CONTENT_TYPE,
    SEALED_SETTLE_ACK_CONTENT_TYPE,
    SETTLE_ACK_MIN_VERSION,
    SETTLE_ACK_PATH,
    openSettleAck,
    sealSettleAck,
    takesSettleAck,
} from '../src/wire/index.js'
import { newTestNode } from './helpers.js'

const enc = new TextEncoder()
const ack = { ticket_id: 'AQIDBAUGBwgJCgsMDQ4PEA==', settle_group: 'kgEC' }

describe('settle ack', () => {
    it('pins the route, the media type and the version gate', () => {
        expect(SETTLE_ACK_PATH).toBe('/v1/zs/settle-ack')
        expect(SEALED_SETTLE_ACK_CONTENT_TYPE).toBe('application/vnd.zs-settle-ack+json')
        expect(SEALED_SETTLE_ACK_CONTENT_TYPE).not.toBe(SEALED_RESERVE_CONTENT_TYPE)
        expect(SETTLE_ACK_MIN_VERSION).toBe('9.12')
        expect(takesSettleAck('9.12')).toBe(true)
        expect(takesSettleAck('10.0')).toBe(true)
        // Fails closed: an older or unknown node gets the payer's broadcast.
        for (const v of ['9.11', '8.99', '', 'garbage', undefined, null]) expect(takesSettleAck(v), String(v)).toBe(false)
    })

    it('round-trips to the node identity, and only to it', async () => {
        const node = await newTestNode()
        const other = await newTestNode()
        const sealed = await sealSettleAck(ack, node.recipient)
        const text = new TextDecoder().decode(sealed)
        expect(Object.keys(JSON.parse(text) as object)).toEqual(['ciphertext'])
        // The group names the payer, and a relay carries this: nothing in clear.
        expect(text).not.toContain(ack.ticket_id)
        expect(text).not.toContain('settle_group')

        expect(await openSettleAck(sealed, node.secret)).toEqual(ack)
        // Tried in order, as Go's variadic identities are.
        expect(await openSettleAck(sealed, other.secret, node.secret)).toEqual(ack)
        await expect(openSettleAck(sealed, other.secret)).rejects.toThrow(/open sealed reserve envelope/)
        await expect(openSettleAck(sealed)).rejects.toThrow(/no node identities/)
    })

    it('refuses an empty recipient, a malformed envelope and an incomplete ack', async () => {
        const node = await newTestNode()
        await expect(sealSettleAck(ack, '')).rejects.toThrow(/empty node recipient/)
        await expect(openSettleAck(enc.encode('not json'), node.secret)).rejects.toThrow(/parse sealed reserve envelope/)
        await expect(openSettleAck(enc.encode('{}'), node.secret)).rejects.toThrow(/missing ciphertext/)
        for (const body of ['{"ticket_id":"T"}', '{"settle_group":"G"}', 'null', '{"ticket_id":1,"settle_group":"G"}']) {
            const e = new age.Encrypter()
            e.addRecipient(node.recipient)
            const ct = await e.encrypt(enc.encode(body))
            const env = enc.encode(JSON.stringify({ ciphertext: Buffer.from(ct).toString('base64') }))
            await expect(openSettleAck(env, node.secret), body).rejects.toThrow(/missing ticket_id or settle_group/)
        }
    })
})
