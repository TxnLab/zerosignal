/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A paid turn's fixtures, shared by the buffered and streamed responder tests:
// a ticket with its committed response key, a receipt its operator signed, and
// an escrow handle whose ack and protest answer from a script.

import { generateKeyPairSync, sign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { type Ticket, type UsageReceipt, commitResponseKey, setBodyHashBytes, signReceipt } from '@txnlab/zs-proto/ticket'
import { bodyHashOfBody } from '@txnlab/zs-proto/wire'

import type { AckSettleResult } from '../src/ack.js'
import type { OpenHandle, SettleOutcome } from '../src/parts.js'
import type { LogAttrs, Logger } from '../src/ports.js'
import { testOperator } from './fixtures.js'

const groupVectors = JSON.parse(
    readFileSync(fileURLToPath(new URL('../../testdata/escrow_group_vectors.json', import.meta.url)), 'utf8'),
) as { settle: { cases: { name: string; group_b64: string }[] } }

/** A settle group that decodes, from the golden vectors. */
export const VALID_GROUP = groupVectors.settle.cases.find((c) => c.name === 'valid')!.group_b64

export interface Logged {
    level: string
    msg: string
    attrs: LogAttrs | undefined
}

export function recLogger(): Logger & { logged: Logged[] } {
    const logged: Logged[] = []
    const at = (level: string) => (msg: string, attrs?: LogAttrs) => {
        logged.push({ level, msg, attrs })
    }
    return { logged, debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') }
}

function keypair() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const jwk = publicKey.export({ format: 'jwk' })
    return {
        pub: new Uint8Array(Buffer.from(jwk.x!, 'base64url')),
        signer: { signBytes: async (_a: string, msg: Uint8Array) => new Uint8Array(sign(null, msg, privateKey)) },
    }
}

export const TICKET_ID = 'dGlja2V0LXdhaXQtMDAwMDA='

/**
 * A ticket and a receipt its operator signed over plaintext, Go's
 * settleFixture. bodyHash is what the receipt claims, plaintext's by default.
 */
export async function fixture(
    over: Partial<UsageReceipt> = {},
    plaintext = new TextEncoder().encode('hello world'),
    bodyHash: Uint8Array = bodyHashOfBody(plaintext),
) {
    const k = keypair()
    const op = testOperator({ id: 7, nodeId: 3, ownerAddr: 'OWNER7', ticketSigningKey: k.pub })
    const responseKey = crypto.getRandomValues(new Uint8Array(32))
    const ticket = {
        ticket_id: TICKET_ID,
        operator_id: 7,
        node_id: 3,
        max_price: 100_000,
        commit_k: Buffer.from(commitResponseKey(responseKey)).toString('base64'),
    } as unknown as Ticket
    const receipt: UsageReceipt = {
        ticket_id: TICKET_ID,
        actual_input_count: 10,
        actual_output_count: 5,
        amount_charged: 50_000,
        ttft_ms: 0,
        decode_ms: 0,
        body_hash: '',
        input_usage_type: 1,
        output_usage_type: 1,
        aux_output_usage_type: 0,
        aux_output_count: 0,
        cached_input_count: 0,
    } as UsageReceipt
    setBodyHashBytes(receipt, bodyHash)
    Object.assign(receipt, over)
    await signReceipt(receipt, k.signer, 'SIGNER')
    return { op, ticket, receipt, plaintext, responseKey }
}

export interface Scripted {
    txid?: string
    fee?: number
    groupRejected?: boolean
    err?: unknown
    throws?: unknown
    outcomes?: (SettleOutcome | Error)[]
}

/** An OpenHandle whose ack and protest answer from s, Go's scriptedSettleHandle. */
export function handleOf(s: Scripted = {}) {
    const acks: [UsageReceipt, string | null, AbortSignal | undefined][] = []
    const protests: [UsageReceipt, Uint8Array, number, AbortSignal | undefined][] = []
    const looks: string[] = []
    const h = {
        appCallTxId: 'APPCALL',
        groupId: 'GROUP',
        ticketId: TICKET_ID,
        openFeesMicroalgos: 2000,
        acks,
        protests,
        looks,
        async ackSettle(r: UsageReceipt, g: string | null, signal?: AbortSignal): Promise<AckSettleResult> {
            acks.push([r, g, signal])
            if (s.throws !== undefined) throw s.throws
            const res: AckSettleResult = { txid: s.err ? '' : (s.txid ?? ''), feeMicroalgos: s.err ? 0 : (s.fee ?? 0), groupRejected: s.groupRejected ?? false }
            if (s.err) res.err = s.err
            return res
        },
        async protest(r: UsageReceipt, excerpt: Uint8Array, reason: number, signal?: AbortSignal) {
            protests.push([r, excerpt, reason, signal])
            if (s.throws !== undefined) throw s.throws
            if (s.err) throw s.err
            return { txId: s.txid ?? '', feeMicroalgos: s.fee ?? 0 }
        },
        async refundInactive() {
            return ''
        },
        async settleLapsed() {
            return ''
        },
    }
    if (s.outcomes !== undefined) {
        const script = s.outcomes
        Object.assign(h, {
            async settleOutcome(txid: string): Promise<SettleOutcome> {
                looks.push(txid)
                if (script.length === 0) return 'pending'
                const step = script[Math.min(looks.length, script.length) - 1]!
                if (step instanceof Error) throw step
                return step
            },
        })
    }
    return h as typeof h & OpenHandle
}
