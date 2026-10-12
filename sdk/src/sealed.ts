/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The sealed run's open and send, mirroring proto/go/zs dispatch.go's runSealed
// and forward.go: open escrow on the ticket the reserve phase accepted, seal
// the body to the recipient the reserve pinned, and forward it to the node,
// directly or through the reserve's relay. Opening the response is the
// responder's. Nothing here fails over: once escrow opens the turn is this
// node's.

import type { Ticket } from '@txnlab/zs-proto/ticket'
import { type RelayEvidence, TRANSPORT_FAILURE_STATUS } from '@txnlab/zs-proto/transient'
import { ENCRYPTED_CONTENT_TYPE, RELAY_HOP_HEADER, setsRelayHopHeader } from '@txnlab/zs-proto/wire'

import { newError } from './codes.js'
import type { Remedies, SpendGuard } from './config.js'
import type { SealedRun } from './dispatch.js'
import { findError } from './errors.js'
import { APPROVAL_ASSERT, ApprovalError } from './escrow/revert.js'
import { openAIError } from './http.js'
import { MbrDepositUnaffordableError } from './mbr.js'
import type { Operator } from './operator.js'
import type { OpenHandle, Reserved, WalletOpener } from './parts.js'
import type { Fetch, LogAttrs, Logger } from './ports.js'
import { recordRelayHopAction, relayHopAction } from './routing/attribution.js'
import { type RelayHop, applyRelay } from './routing/relay.js'
import type { RelayReputationStore } from './routing/reputation.js'
import { sealRequest } from './seal.js'
import type { Emitter } from './turn.js'
import type { Endpoint } from './types.js'
import { BelowTargetError } from './wallet.js'

/** How long a payer whose ticket slots are all in flight is told to wait: Go's 2s. */
export const MBR_POOL_EXHAUSTED_RETRY_AFTER_MS = 2000

/** What a responder needs to open the node's answer to one sealed run. */
export interface SealedCall {
    endpoint: Endpoint
    model: string
    op: Operator
    reserved: Reserved
    /** The opened escrow, for the ack and a protest. */
    handle: OpenHandle
    /** The open() app call's txid, which the envelope carries. */
    txId: string
    hop: RelayHop | null
    signal?: AbortSignal | undefined
}

/**
 * BufferedResponder handles a node response the forwarder has read whole. It
 * owns what the caller sees (a reply or em.fail); throwing means it emitted
 * nothing, and the forwarder reports it. Go's nonStreamResponder.
 */
export type BufferedResponder = (em: Emitter, resp: Response, body: Uint8Array) => Promise<void>

/** The sealed request as it goes on the wire: to the node, or to the relay that forwards it. */
export interface Outbound {
    url: string
    body: Uint8Array
    headers: Record<string, string>
}

/** Everything the sealed run reads off the Client. */
export interface SealedDeps {
    wallet: WalletOpener
    spendGuard?: SpendGuard | undefined
    remedies: Remedies
    /** The network's name, as failure messages give it. Empty when named only by endpoint. */
    network: string
    fetch: Fetch
    relayReputation?: RelayReputationStore | undefined
    logger: Logger
    /**
     * Runs once escrow has opened, before anything is sent: Go arms the refund
     * watchdog and journals the open ticket here. The turn waits for it, so the
     * open row is written before a receipt row can follow it; the hook bounds
     * its own write. A throw is logged and the turn goes on.
     */
    opened?(handle: OpenHandle, ticket: Ticket): Promise<void> | void
    /** Builds the responder for a buffered answer. */
    buffered(call: SealedCall): BufferedResponder
    /**
     * Forwards a streamed request and pumps its answer to em. buffered handles
     * a node that answers a streamed request with a plain body.
     */
    streamed(em: Emitter, out: Outbound, call: SealedCall, buffered: BufferedResponder): Promise<void>
}

const opAttrs = (op: Operator): LogAttrs => ({ operator_id: op.id, node_id: op.nodeId })

const relayAttrs = (hop: RelayHop | null): LogAttrs =>
    hop === null ? {} : { relay_operator_id: hop.relayId, relay_node_id: hop.relayNodeId }

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err))

/**
 * runSealed opens escrow on the reserved ticket, seals the body to the
 * recipient pinned at reserve time, and sends it to the node with the ticket
 * bound into the envelope. The responder opens what comes back.
 */
export async function runSealed(deps: SealedDeps, em: Emitter, run: SealedRun, signal?: AbortSignal): Promise<void> {
    try {
        await sealAndSend(deps, em, run, signal)
    } finally {
        // Only the seal reads it. The response's own key is a separate copy,
        // which its reader wipes. The identity is a string, which can't be.
        run.reserved.responseKey.fill(0)
    }
}

async function sealAndSend(deps: SealedDeps, em: Emitter, run: SealedRun, signal?: AbortSignal): Promise<void> {
    const log = deps.logger
    const { endpoint, model, op, reserved: rt, stream, hop } = run
    const ticket = rt.ticket
    em.reserved(rt, op)

    // The caller has already reserved the ticket's ceiling with the spend guard.
    let handle: OpenHandle
    try {
        handle = await deps.wallet.open(ticket, op, rt.presignedOpenTxn, signal)
    } catch (err) {
        // The open didn't commit, so a failed attempt doesn't keep the cap.
        deps.spendGuard?.release(ticket.ticket_id)
        log.error('wallet open failed', {
            endpoint,
            ...opAttrs(op),
            ...relayAttrs(hop),
            ticket_id: ticket.ticket_id,
            err: errText(err),
        })
        em.fail(openFailure(deps, err))
        return
    }
    // The ceiling stays on the spend tally: settlement charges less on chain,
    // and the cap counts the ceiling on purpose. The hook can't stop the turn:
    // escrow is open, so the caller must still hear that it paid.
    try {
        await deps.opened?.(handle, ticket)
    } catch (err) {
        log.warn('open hook failed', { ticket_id: ticket.ticket_id, err: errText(err) })
    }
    const txId = handle.appCallTxId
    em.committed(ticket.ticket_id, txId, handle.openFeesMicroalgos)
    log.debug('wallet open submitted', {
        endpoint,
        ...opAttrs(op),
        ...relayAttrs(hop),
        ticket_id: ticket.ticket_id,
        app_call_txid: handle.appCallTxId,
        group_id: handle.groupId,
    })

    // Sealed to the recipient pinned at reserve, not the operator's current
    // one: a refresh since may have rotated it, and the node committed
    // K_response against the key it could open then. The reserve's identity
    // is the reply-to, so it opens the response key as it opened the reserve's.
    let envelope: Uint8Array
    try {
        envelope = await sealRequest({
            body: typeof run.body === 'string' ? new TextEncoder().encode(run.body) : run.body,
            txId,
            ticketId: ticket.ticket_id,
            responseKey: rt.responseKey,
            nodeRecipient: rt.sealRecipient,
            ephemeral: rt.identity,
        })
    } catch (err) {
        log.error('wrap request failed', { endpoint, ...opAttrs(op), ...relayAttrs(hop), err: errText(err) })
        em.fail(newError('wrap_request', 'request could not be wrapped'))
        return
    }

    const call: SealedCall = { endpoint, model, op, reserved: rt, handle, txId, hop, signal }
    const respond = deps.buffered(call)
    // Relayed, the envelope goes to the relay's route with the inner request
    // in its headers; it stays sealed to the target, which the relay can't open.
    const fwd = applyRelay(hop, op.baseUrl + endpoint, 'POST', operatorHeaders(ENCRYPTED_CONTENT_TYPE), endpoint)
    const out: Outbound = { url: fwd.url, body: envelope, headers: fwd.headers }
    if (stream) {
        await deps.streamed(em, out, call, respond)
        return
    }
    await forwardBuffered(deps, em, out, call, respond)
}

// openFailure is the error a failed open ends the turn with, most specific
// first.
function openFailure(deps: SealedDeps, err: unknown) {
    const payer = deps.wallet.payerAddr()
    // The payer is short of ALGO (not USDC) to grow the prepaid ticket-MBR
    // pool, and no slot is free. A deposit that landed but left the pool short
    // with no slot free is the same condition. Checked before exhaustion: an
    // open retried after a failed top-up carries the pool revert too, which
    // alone reads as exhaustion.
    if (findError(err, MbrDepositUnaffordableError) !== undefined || findError(err, BelowTargetError) !== undefined) {
        return newError(
            'mbr_pool_underfunded',
            `zerosignal wallet ${payer} needs more ALGO (not USDC) to fund the prepaid ticket-MBR pool on ${deps.network} — ${errText(err)}. To fix it, ${deps.remedies.fund}.`,
        )
    }
    // The wallet holds the ALGO but every slot backs an in-flight ticket: a
    // concurrency cap that clears as those settle, not an unfunded wallet.
    if (isPoolExhaustedOpenError(err)) {
        return newError(
            'mbr_pool_exhausted',
            `zerosignal wallet ${payer} has all concurrent ticket slots in use by in-flight requests on ${deps.network} — retry once in-flight requests settle, or to allow more at once, ${deps.remedies.raiseSlots}.`,
            { retryAfter: MBR_POOL_EXHAUSTED_RETRY_AFTER_MS },
        )
    }
    if (isUnderfundedOpenError(err)) {
        return newError(
            'wallet_unfunded',
            `zerosignal wallet ${payer} can't pay for this request on ${deps.network}. To fix it, ${deps.remedies.fund}.`,
        )
    }
    return newError('wallet_open', 'payment group could not be submitted')
}

// open()'s prepaid-pool guards: no headroom for another ticket box, none for
// the one-time free-quota box, or no deposit at all. None is a balance shortfall.
const POOL_EXHAUSTED_ASSERTS: ReadonlySet<string> = new Set([
    APPROVAL_ASSERT.insufficientMbrDeposit,
    APPROVAL_ASSERT.insufficientMbrDepositFreeQuota,
    APPROVAL_ASSERT.payerHasNoMbrDeposit,
])

/**
 * isPoolExhaustedOpenError reports whether an open failed on a prepaid-pool
 * guard of open() itself. It matches the typed revert, never the text, and
 * the method too: the pool top-up's depositMbr fails through the same call,
 * and the advice to raise the slot count fits only an open.
 */
export function isPoolExhaustedOpenError(err: unknown): boolean {
    const revert = findError(err, ApprovalError)
    return revert !== undefined && revert.method === 'open' && POOL_EXHAUSTED_ASSERTS.has(revert.assert)
}

// algod's ledger-eval text for a payer who can't cover the open: too little
// ALGO for fees or min-balance, too little USDC to lock, or no USDC opt-in.
// Tight, so an unrelated failure stays wallet_open rather than "fund me".
const UNDERFUNDED_OPEN_SIGNATURES = ['overspend', 'below min', 'underflow', 'missing from']

/** isUnderfundedOpenError reports whether an open failed because the payer can't pay. */
export function isUnderfundedOpenError(err: unknown): boolean {
    if (err === undefined || err === null) return false
    const msg = errText(err).toLowerCase()
    return UNDERFUNDED_OPEN_SIGNATURES.some((sig) => msg.includes(sig))
}

// Per-hop headers, never forwarded end to end.
const HOP_BY_HOP_HEADERS: ReadonlySet<string> = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
])

/**
 * operatorHeaders is an outbound request's headers, Go's buildOperatorRequest.
 * No Authorization ever goes out, extra's included: the sealed envelope is the
 * admission credential.
 */
export function operatorHeaders(contentType: string, extra: Record<string, string> = {}): Record<string, string> {
    const out: Record<string, string> = {
        'Content-Type': contentType,
        // A sealed answer may come back as either, so a strict node
        // negotiating content doesn't 406.
        Accept: contentType === ENCRYPTED_CONTENT_TYPE ? `${ENCRYPTED_CONTENT_TYPE}, application/json` : 'application/json',
    }
    for (const [k, v] of Object.entries(extra)) {
        const lower = k.toLowerCase()
        if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'authorization') continue
        // Replaces any spelling of the name, as Go's canonical keys do;
        // otherwise fetch would send both values joined.
        for (const have of Object.keys(out)) if (have.toLowerCase() === lower) delete out[have]
        out[k] = v
    }
    return out
}

/**
 * forwardBuffered sends out and hands the whole answer to respond, Go's
 * forwardRawNonStream. Every outcome is attributed to the relay it rode.
 */
export async function forwardBuffered(
    deps: Pick<SealedDeps, 'fetch' | 'relayReputation' | 'logger'>,
    em: Emitter,
    out: Outbound,
    call: Pick<SealedCall, 'endpoint' | 'hop' | 'signal'>,
    respond: BufferedResponder,
): Promise<void> {
    const log = deps.logger
    const { endpoint, hop, signal } = call
    // A URL that won't parse is the operator's or relay's publishing fault,
    // not a hop failure: Go's request construction refuses it before any dial.
    try {
        new URL(out.url)
    } catch (err) {
        em.fail(newError('build_request', errText(err)))
        return
    }
    let resp: Response
    try {
        resp = await deps.fetch(out.url, {
            method: 'POST',
            headers: out.headers,
            body: out.body,
            ...(signal ? { signal } : {}),
        })
    } catch (err) {
        // Relayed, the socket was the relay's, but only once the verdict has
        // ruled out our own abort: this waits out the whole generation, so a
        // payer hanging up mid-answer lands here too.
        attributeRelayHop(deps.relayReputation, hop, signal, TRANSPORT_FAILURE_STATUS, null, null)
        log.error('operator request failed', { endpoint, ...relayAttrs(hop), err: errText(err) })
        em.fail(newError('upstream_unreachable', errText(err)))
        return
    }

    let body: Uint8Array
    try {
        body = new Uint8Array(await resp.arrayBuffer())
    } catch (err) {
        em.fail(newError('read_upstream', errText(err)))
        return
    }

    attributeRelayHop(deps.relayReputation, hop, signal, resp.status, resp.headers, body)

    try {
        await respond(em, resp, body)
    } catch (err) {
        // The detail is logged; the caller gets nothing of the decrypt's internals.
        log.error('response handling failed', { endpoint, err: errText(err) })
        em.fail(newError('response_handler', 'operator response could not be processed'))
    }
}

/**
 * relayEvidence is what narrowRelayed needs about a relayed forward that the
 * body can't carry. headers is null when no response arrived, which reads as
 * no marker. signal is the one the request rode: a payer leaving surfaces as
 * the same transport failure as a dead relay, and must not be charged to it.
 */
export function relayEvidence(hop: RelayHop | null, headers: Headers | null, signal?: AbortSignal): RelayEvidence {
    if (hop === null) return { relayed: false, hopMarker: false, relayMarksHops: false, callerAborted: false }
    return {
        relayed: true,
        // Present and non-empty, as Go's Header.Get(...) != "".
        hopMarker: !!headers?.get(RELAY_HOP_HEADER),
        relayMarksHops: setsRelayHopHeader(hop.relayProtoVersion),
        callerAborted: signal?.aborted ?? false,
    }
}

/**
 * attributeRelayHop records what a forward through hop says about the relay,
 * Go's attributeRelayHop: status is TRANSPORT_FAILURE_STATUS, with no headers
 * or body, when no response arrived. A direct route or no store records nothing.
 */
export function attributeRelayHop(
    store: RelayReputationStore | undefined,
    hop: RelayHop | null,
    signal: AbortSignal | undefined,
    status: number,
    headers: Headers | null,
    body: Uint8Array | null,
): void {
    if (hop === null || store === undefined) return
    // A success body is the answer itself; only an error is parsed for a code.
    let code = ''
    if ((status === TRANSPORT_FAILURE_STATUS || status >= 400) && body !== null) {
        code = openAIError(new TextDecoder().decode(body)).code
    }
    recordRelayHopAction(store, hop, relayHopAction(status, code, relayEvidence(hop, headers, signal)))
}

/**
 * nodeHeader is the node's response headers as the caller sees them: every
 * X-Zs-* field removed (SPEC §5.2 step 4), so the response key, receipt and
 * settle group, and anything a later node adds under the prefix, stay the SDK's.
 */
export function nodeHeader(h: Headers): Headers {
    const out = new Headers()
    h.forEach((v, k) => {
        if (!k.toLowerCase().startsWith('x-zs-')) out.append(k, v)
    })
    return out
}
