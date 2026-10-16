/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The sealed settle ack. Mirror of proto/go/wire/settle_ack.go. Before
// SETTLE_ACK_MIN_VERSION the payer broadcast its half of the atomic settle
// group itself, from its own IP, and the group names the payer as gtxn[1]'s
// sender: every settle linked the payer's IP to its address at whichever algod
// it used. From 9.12 the payer hands the completed group to the node instead.

import * as age from 'age-encryption'
import { base64 } from '@scure/base'

import { pickPaymentField } from './inner.js'
import type { SealedReserveEnvelope } from './reserveSeal.js'
import { protoVersionAtLeast } from './version.js'

/** Where a payer hands a node its signed half of the atomic settle group (SPEC.md § 3a "Settle ack"). */
export const SETTLE_ACK_PATH = '/v1/zs/settle-ack'

/**
 * Content-Type of a sealed settle ack: a SealedReserveEnvelope whose plaintext
 * is a marshaled SettleAck, sealed to the node's ephemeral recipient, since the
 * group names the payer and the ack usually rides a relay.
 */
export const SEALED_SETTLE_ACK_CONTENT_TYPE = 'application/vnd.zs-settle-ack+json'

/** The first PROTO_VERSION at which a node serves SETTLE_ACK_PATH. */
export const SETTLE_ACK_MIN_VERSION = '9.12' as const

/**
 * Whether a node advertising protoVersion serves SETTLE_ACK_PATH. Mirrors Go's
 * wire.TakesSettleAck. Fails closed: a payer that cannot tell broadcasts the
 * group itself, which settles the same ticket at the old privacy cost.
 */
export function takesSettleAck(protoVersion: string | undefined | null): boolean {
    return protoVersionAtLeast(protoVersion, SETTLE_ACK_MIN_VERSION)
}

/** The plaintext of a sealed settle ack. Key order matches Go's json.Marshal. */
export interface SettleAck {
    ticket_id: string
    /**
     * The completed atomic settle group in Go's escrow.EncodeSettleGroup form:
     * the node's own gtxn[0] as it sent it, and the payer-signed gtxn[1].
     */
    settle_group: string
}

/**
 * sealSettleAck marshals ack and age-seals it to the node's recipient
 * ("age1..."). neutralNames writes the group as payment_settle; set it only for
 * a node that reads it (usesRailNeutralNames).
 */
export async function sealSettleAck(ack: SettleAck, nodeRecipient: string, neutralNames = false): Promise<Uint8Array> {
    if (!nodeRecipient) throw new Error('seal settle ack: empty node recipient')
    const wire = neutralNames
        ? { ticket_id: ack.ticket_id, payment_settle: ack.settle_group }
        : { ticket_id: ack.ticket_id, settle_group: ack.settle_group }
    const body = new TextEncoder().encode(JSON.stringify(wire))
    const e = new age.Encrypter()
    e.addRecipient(nodeRecipient)
    const env: SealedReserveEnvelope = { ciphertext: base64.encode(await e.encrypt(body)) }
    return new TextEncoder().encode(JSON.stringify(env))
}

/**
 * openSettleAck is the node-side inverse of sealSettleAck, trying each identity
 * in order as Go's OpenSettleAck does. It lives here so a TS peer can play the
 * node and round-trip tests need no Go.
 */
/** An opened settle ack, with which name the group arrived under (Go's SettleAck.NeutralNames). */
export interface OpenedSettleAck extends SettleAck {
    neutralNames: boolean
}

export async function openSettleAck(envelopeJSON: Uint8Array, ...nodeIdentities: string[]): Promise<OpenedSettleAck> {
    if (nodeIdentities.length === 0) throw new Error('open settle ack: no node identities supplied')
    let env: SealedReserveEnvelope
    try {
        env = JSON.parse(new TextDecoder().decode(envelopeJSON)) as SealedReserveEnvelope
    } catch (err) {
        throw new Error(`parse sealed reserve envelope: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (!env?.ciphertext) throw new Error('sealed reserve envelope missing ciphertext')
    let ct: Uint8Array
    try {
        ct = base64.decode(env.ciphertext)
    } catch (err) {
        throw new Error(`decode ciphertext: ${err instanceof Error ? err.message : String(err)}`)
    }
    const d = new age.Decrypter()
    for (const id of nodeIdentities) d.addIdentity(id)
    let body: Uint8Array
    try {
        body = await d.decrypt(ct)
    } catch (err) {
        throw new Error(`open sealed reserve envelope: ${err instanceof Error ? err.message : String(err)}`)
    }
    let ack: (Partial<SettleAck> & { payment_settle?: unknown }) | null
    let settleGroup: string
    try {
        ack = JSON.parse(new TextDecoder().decode(body)) as typeof ack
        settleGroup = pickPaymentField('settle_group', ack?.settle_group, 'payment_settle', ack?.payment_settle)
    } catch (err) {
        throw new Error(`parse settle ack: ${err instanceof Error ? err.message : String(err)}`)
    }
    const ticketId = typeof ack?.ticket_id === 'string' ? ack.ticket_id : ''
    if (!ticketId || !settleGroup) throw new Error('settle ack missing ticket_id or settle_group')
    const neutralNames = typeof ack?.payment_settle === 'string' && ack.payment_settle !== ''
    return { ticket_id: ticketId, settle_group: settleGroup, neutralNames }
}
