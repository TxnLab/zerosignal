/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A buffered turn's answer, mirroring proto/go/zs dispatch.go's
// buildNonStreamResponder and verifyNonStreamReceipt, and emit.go's
// usageReport: refuse an answer the node didn't seal, open the one it did,
// check its receipt, and reply, then submit the escrow half once the caller
// has the response.

import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'
import { decodeReceiptHeader } from '@txnlab/zs-proto/ticket'
import { extractResponseID, extractResponseToolCallIDs } from '@txnlab/zs-proto/selection'
import {
    ENCRYPTED_CONTENT_TYPE,
    RECEIPT_HEADER,
    RESPONSE_KEY_HEADER,
    ResponseOpener,
    SEALED_HEADER_RECEIPT,
    SEALED_HEADER_SETTLE_GROUP,
    SETTLE_GROUP_HEADER,
    bodyHashOfBody,
    streamErrorMessage,
} from '@txnlab/zs-proto/wire'

import type { AffinityStore } from './affinity.js'
import { newError } from './codes.js'
import { NodeReply, ZsError } from './errors.js'
import { decodeSettleGroup } from './escrow/settle.js'
import type { Event } from './events.js'
import { algoOnly } from './fees.js'
import type { FeeUnit } from './network.js'
import { goJSON } from './gojson.js'
import { goDecodeRune, goDecodeUTF8, goQuote } from './gotext.js'
import { openAIError } from './http.js'
import { type Operator, refOf } from './operator.js'
import type { Reserved } from './parts.js'
import type { LogAttrs, Logger } from './ports.js'
import {
    EXCLUSION_REASONS,
    type ReceiptCheckDeps,
    type SettleSlot,
    type SettleSubmit,
    type TurnCheck,
    checkTurnReceipt,
} from './receipt-check.js'
import { parseRetryAfter } from './reserve.js'
import type { RelayHop } from './routing/relay.js'
import { nodeRetryHintMs } from './routing/verdict.js'
import { ResponseKeyUnwrapError, openResponseKey } from './seal.js'
import { type BufferedResponder, type SealedCall, nodeHeader } from './sealed.js'

/** What the payer is told about a turn's receipt, and on a stream, the settle submitted before done. */
export interface UsageReport {
    receipt: UsageReceipt
    ticket: Ticket
    op: Operator
    openFees: number
    settleFees: number
    algoUsdPrice: number
    feeUnit: FeeUnit
    feeBps: number
    haveFee: boolean
    /** How the receipt fared and what its submit did. */
    check: TurnCheck
}

/** usageEvents is the report in the order the payer hears it. */
export function usageEvents(u: UsageReport): Event[] {
    const c = u.check
    const excluded: Event[] = c.excluded
        ? [{ type: 'node.excluded', node: refOf(u.op), reason: c.exclusion ?? EXCLUSION_REASONS.settleGroup }]
        : []
    if (c.violation !== '') {
        return [
            { type: 'receipt.violated', violation: c.violation, protestTxId: c.settled.kind === 'protest' ? c.settled.txId : '' },
            ...excluded,
        ]
    }
    const evs: Event[] = [
        {
            type: 'receipt.verified',
            receipt: u.receipt,
            ticket: u.ticket,
            target: refOf(u.op),
            ownerAddr: u.op.ownerAddr,
            openFeesMicroAlgos: algoOnly(u.feeUnit, u.openFees),
            settleFeesMicroAlgos: algoOnly(u.feeUnit, u.settleFees),
            algoUsd: algoOnly(u.feeUnit, u.algoUsdPrice),
            feeBps: u.feeBps,
            feeBpsKnown: u.haveFee,
            openNetworkFees: u.openFees,
            settleNetworkFees: u.settleFees,
            // The reserve's rate is ALGO/USD, so it prices no other coin.
            nativeUsd: algoOnly(u.feeUnit, u.algoUsdPrice),
            feeUnit: u.feeUnit,
        },
    ]
    evs.push(...excluded)
    if (c.settled.txId !== '') {
        evs.push({
            type: 'settle.submitted',
            ticketId: u.ticket.ticket_id,
            txId: c.settled.txId,
            feesMicroAlgos: c.settled.feesMicroAlgos,
            atomic: c.settled.kind === 'atomic',
            networkFees: c.settled.networkFees,
            ...(c.settled.frozen === true ? { frozen: true } : {}),
        })
    }
    return evs
}

/** What the buffered responder reads off the Client. */
export interface ResponderDeps extends ReceiptCheckDeps {
    toolAffinity?: AffinityStore | undefined
    responseAffinity?: AffinityStore | undefined
    /** The cached protocol fee rate, never waiting; null when unknown. */
    feeRate(): number | null
    /** Runs a turn's escrow submit once the caller has its response. */
    afterResponse(ticketId: string, submit: SettleSubmit | null): void
}

const opAttrs = (op: Operator): LogAttrs => ({ operator_id: op.id, node_id: op.nodeId })

const relayAttrs = (hop: RelayHop | null): LogAttrs =>
    hop === null ? {} : { relay_operator_id: hop.relayId, relay_node_id: hop.relayNodeId }

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err))

/** A node's Retry-After as the caller is told it, capped; 0 when absent. */
export function nodeRetryAfter(h: Headers): number {
    return nodeRetryHintMs(parseRetryAfter(h.get('Retry-After')))
}

const retryAfterOf = (ms: number): { retryAfter?: number } => (ms > 0 ? { retryAfter: ms } : {})

/**
 * bufferedResponder opens the node's buffered answer to call: it refuses one
 * the node didn't seal, passes a refusal the node made before sealing, opens
 * the body under K_response once it checks against commit_k, checks the
 * receipt, records the turn's affinity, and replies. The escrow submit runs
 * after the reply, through deps.afterResponse.
 */
export function bufferedResponder(deps: ResponderDeps, call: SealedCall, slot?: SettleSlot): BufferedResponder {
    const log = deps.logger
    const { endpoint, model, op, reserved, handle, txId, hop } = call
    const ticket = reserved.ticket
    return async (em, resp, body) => {
        const h = resp.headers
        const status = resp.status
        const wrappedKey = h.get(RESPONSE_KEY_HEADER) ?? ''
        const ct = h.get('Content-Type') ?? ''
        if (wrappedKey === '') {
            // The node omits the key only on an error it writes before sealing
            // (SPEC §10). A success without one would be plaintext served
            // through an admitted ticket.
            if (status < 400) {
                log.warn('operator returned non-error response without sealed key — protocol violation', {
                    ...opAttrs(op),
                    ...relayAttrs(hop),
                    upstream_status: status,
                })
                em.fail(newError('operator_unsealed_response', 'operator returned a response without sealing it'))
                return
            }
            const msg = streamErrorMessage(body)
            if (msg === null) {
                // Not a node's error: an operator's CDN or load balancer page.
                // An OpenAI client can't parse it, so it is replaced, with the
                // status and headers kept. No code, on purpose: a code-less
                // 5xx is how a caller recognizes retryable infrastructure.
                const ctSafe = truncateForLog(ct, 64)
                log.warn('operator returned a non-OpenAI error body; replacing it with a structured error', {
                    ...opAttrs(op),
                    ...relayAttrs(hop),
                    upstream_status: status,
                    content_type: goDecodeUTF8(ctSafe),
                    body_bytes: body.length,
                })
                const message = `operator returned HTTP ${status} with a body this proxy could not parse as an OpenAI error (content-type ${goQuote(ctSafe)})`
                em.fail(
                    new ZsError({
                        kind: 'interrupted',
                        code: '',
                        message,
                        ...retryAfterOf(nodeRetryAfter(h)),
                        cause: new NodeReply(status, {
                            header: nodeHeader(h),
                            body: openAIErrorBody('server_error', '', message),
                            contentType: 'application/json',
                        }),
                    }),
                )
                return
            }
            log.warn('operator returned pre-envelope error', {
                ...opAttrs(op),
                ...relayAttrs(hop),
                upstream_status: status,
                error: msg,
            })
            // Paid, and the node refused admission: its code and body go back,
            // but none of its X-Zs-* headers, whose values it chooses.
            em.fail(
                new ZsError({
                    kind: 'interrupted',
                    code: openAIError(new TextDecoder().decode(body)).code,
                    message: msg,
                    ...retryAfterOf(nodeRetryAfter(h)),
                    cause: new NodeReply(status, { header: nodeHeader(h), body }),
                }),
            )
            return
        }

        if (!ct.startsWith(ENCRYPTED_CONTENT_TYPE)) {
            log.warn('operator set response key but returned non-envelope content-type — protocol violation', {
                ...opAttrs(op),
                ...relayAttrs(hop),
                content_type: ct,
            })
            em.fail(newError('operator_inconsistent_response', 'operator returned a response key but did not seal the body'))
            return
        }

        // Throws on a key that won't unwrap or doesn't match commit_k, which
        // the forwarder reports.
        const responseKey = await openCommittedKey(wrappedKey, reserved)
        // One opener binds the body and both sealed headers to one (txId, ticketId).
        const opener = new ResponseOpener(responseKey, txId, ticket.ticket_id)
        const meta: MetaContext = { ticket, op, hop, log }
        let plaintext: Uint8Array
        let receiptHdr: string
        let settleGroupHdr: string
        try {
            try {
                plaintext = opener.openBody(body)
            } catch (err) {
                throw new Error(`decrypt body: ${errText(err)}`, { cause: err })
            }
            receiptHdr = openSealedResponseMeta(meta, opener, h.get(RECEIPT_HEADER) ?? '', SEALED_HEADER_RECEIPT)
            settleGroupHdr = openSealedResponseMeta(meta, opener, h.get(SETTLE_GROUP_HEADER) ?? '', SEALED_HEADER_SETTLE_GROUP)
        } finally {
            // Nothing else is sealed under it (SPEC § 3: no per-request key
            // outlives the response). The opener holds these same bytes.
            responseKey.fill(0)
        }

        // A sealed error after admission is diagnosable here without the
        // body: the error envelope is not completion content.
        const failure = streamErrorMessage(plaintext)
        if (failure !== null) {
            log.warn('operator returned error', {
                ...opAttrs(op),
                ...relayAttrs(hop),
                ticket_id: ticket.ticket_id,
                error: failure,
            })
        }

        let receipt: UsageReceipt | null = null
        let submit: SettleSubmit | null = null
        let violation = ''
        if (receiptHdr === '') {
            log.debug('no receipt header on zs response; tolerating', { ...opAttrs(op), ...relayAttrs(hop), ticket_id: ticket.ticket_id })
        } else {
            try {
                receipt = decodeReceiptHeader(receiptHdr)
            } catch (err) {
                log.warn('receipt header malformed', {
                    ...opAttrs(op),
                    ...relayAttrs(hop),
                    ticket_id: ticket.ticket_id,
                    err: errText(err),
                })
            }
            if (receipt !== null) {
                const r = await checkTurnReceipt(deps, {
                    endpoint,
                    model,
                    ticket,
                    op,
                    handle,
                    receipt,
                    computedHash: bodyHashOfBody(plaintext),
                    plaintext,
                    settleGroup: settleGroupOf(meta, settleGroupHdr),
                    hop,
                    slot,
                })
                // Only the verdict is known before the reply; the submit runs after it.
                submit = r.submit
                violation = r.check.violation
            }
        }

        // The submit waits for the reply, so the caller never waits on algod.
        // Its fee therefore can't be in this reply: 0 on the atomic path by
        // construction, and the standalone fallback logs its own.
        try {
            const text = new TextDecoder().decode(plaintext)
            // So the next turn of a tool-calling conversation routes back here.
            if (deps.toolAffinity) {
                const ids = extractResponseToolCallIDs(text)
                if (ids.length > 0) deps.toolAffinity.record(refOf(op), ids)
            }
            // A previous_response_id continuation is pinned to this node.
            if (deps.responseAffinity && endpoint === '/v1/responses') {
                const id = extractResponseID(text)
                if (id !== '') deps.responseAffinity.record(refOf(op), [id])
            }
            let usage: UsageReport | null = null
            if (receipt !== null) {
                const feeBps = deps.feeRate()
                usage = {
                    receipt,
                    ticket,
                    op,
                    openFees: handle.openFeesMicroalgos,
                    settleFees: 0,
                    algoUsdPrice: reserved.algoUsdPrice,
                    feeUnit: deps.feeUnit,
                    feeBps: feeBps ?? 0,
                    haveFee: feeBps !== null,
                    check: { violation, settled: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 }, excluded: false },
                }
            }
            em.reply(status, h, plaintext, usage)
        } finally {
            deps.afterResponse(ticket.ticket_id, submit)
        }
    }
}

/**
 * openCommittedKey unwraps the response key the node sent and checks it
 * against the ticket's commit_k. It throws on either failure, prefixed as Go's
 * responders do.
 */
export async function openCommittedKey(wrappedKey: string, reserved: Reserved): Promise<Uint8Array> {
    try {
        return await openResponseKey(wrappedKey, reserved.identity, reserved.ticket)
    } catch (err) {
        if (err instanceof ResponseKeyUnwrapError) throw new Error(`unwrap response key: ${err.message}`, { cause: err })
        throw err
    }
}

export interface MetaContext {
    ticket: Ticket
    op: Operator
    hop: RelayHop | null
    log: Logger
}

/**
 * openSealedResponseMeta opens one piece of sealed response metadata (the
 * receipt or settle-group header) under K_response. Both are sealed because
 * both link to the payer and a relay forwards the response verbatim. '' for
 * an absent value; a failed open is logged and reads as absent.
 */
export function openSealedResponseMeta(m: MetaContext, opener: ResponseOpener, sealed: string, name: string): string {
    if (sealed === '') return ''
    try {
        return new TextDecoder().decode(opener.openHeader(sealed, name))
    } catch (err) {
        m.log.warn('sealed response metadata failed to open', {
            ...opAttrs(m.op),
            ...relayAttrs(m.hop),
            metadata: name,
            ticket_id: m.ticket.ticket_id,
            err: errText(err),
        })
        return ''
    }
}

/**
 * settleGroupOf is the node's settle group when it sent one that decodes, else
 * null: an absent one is normal, a malformed one is logged and the ack goes
 * standalone.
 */
export function settleGroupOf(m: MetaContext, b64: string): string | null {
    if (b64 === '') return null
    try {
        decodeSettleGroup(b64)
    } catch (err) {
        m.log.warn('settle-group header malformed; falling back to standalone ack', {
            ...opAttrs(m.op),
            ...relayAttrs(m.hop),
            ticket_id: m.ticket.ticket_id,
            err: errText(err),
        })
        return null
    }
    return b64
}

// The UTF-8 bytes of U+2026 and U+FFFD, as binary strings.
const ELLIPSIS_BYTES = '\xe2\x80\xa6'
const REPLACEMENT_BYTES = '\xef\xbf\xbd'

/**
 * truncateForLog bounds an untrusted upstream header value before it reaches
 * a log line or a message: an operator's headers can run to megabytes. A
 * header value is a binary string, one char per byte, and so is the result:
 * cut at n bytes, then made valid UTF-8 the way Go's strings.ToValidUTF8 does,
 * each run of invalid bytes becoming one U+FFFD, since the cut can land
 * mid-rune.
 */
export function truncateForLog(s: string, n: number): string {
    if (s.length > n) s = s.slice(0, n) + ELLIPSIS_BYTES
    let out = ''
    let invalid = false
    for (let i = 0; i < s.length; ) {
        const [r, w] = goDecodeRune(s, i)
        if (r === 0xfffd && w === 1) {
            if (!invalid) out += REPLACEMENT_BYTES
            invalid = true
        } else {
            out += s.slice(i, i + w)
            invalid = false
        }
        i += w
    }
    return out
}

/** openAIErrorBody is an OpenAI-shaped error body, newline included, byte for byte as Go writes it. */
export function openAIErrorBody(type: string, code: string, message: string): Uint8Array {
    const error: Record<string, string> = { message, type }
    if (code !== '') error.code = code
    return new TextEncoder().encode(`${goJSON({ error })}\n`)
}
