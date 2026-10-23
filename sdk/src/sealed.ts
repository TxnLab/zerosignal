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

import type { Operator as SelectionOperator } from '@txnlab/zs-proto/selection'
import type { Ticket } from '@txnlab/zs-proto/ticket'
import { type RelayEvidence, TRANSPORT_FAILURE_STATUS } from '@txnlab/zs-proto/transient'
import {
    ENCRYPTED_CONTENT_TYPE,
    RELAY_HOP_HEADER,
    RESPONSE_KEY_HEADER,
    SEALED_SETTLE_ACK_CONTENT_TYPE,
    SETTLE_ACK_PATH,
    type SettleAck,
    sealSettleAck,
    setsRelayHopHeader,
    submitsOpen,
    takesSettleAck,
    usesRailNeutralNames,
} from '@txnlab/zs-proto/wire'

import { newError } from './codes.js'
import type { Remedies, SpendGuard } from './config.js'
import type { SealedRun } from './dispatch.js'
import { type ZsError, findError } from './errors.js'
import { APPROVAL_ASSERT, ApprovalError } from './escrow/revert.js'
import { openAIError } from './http.js'
import { type StreamIdle, readReply } from './idle.js'
import { MbrDepositUnaffordableError } from './mbr.js'
import type { Rail } from './network.js'
import type { Operator } from './operator.js'
import type { OpenHandle, Reserved, WalletOpener } from './parts.js'
import type { Fetch, LogAttrs, Logger } from './ports.js'
import { recordRelayHopAction, relayHopAction } from './routing/attribution.js'
import { type RelayHop, applyRelay } from './routing/relay.js'
import type { RelayReputationStore } from './routing/reputation.js'
import { sealRequest } from './seal.js'
import { guardRecords } from './spend-guard.js'
import type { Emitter } from './turn.js'
import type { Endpoint } from './types.js'
import { BelowTargetError, NoSettleAckRouteError } from './wallet.js'

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
    /** The payer's rail, which names the coin and pool in failure messages; absent is algorand. */
    rail?: Rail | undefined
    fetch: Fetch
    relayReputation?: RelayReputationStore | undefined
    logger: Logger
    /** Bounds a buffered reply's silences, as readReply reads it; null is no bound. */
    streamIdle?: StreamIdle | null | undefined
    /** Overrides MAX_REPLY_BYTES. */
    maxReplyBytes?: number | undefined
    /**
     * Runs once escrow has opened, before anything is sent: Go arms the refund
     * watchdog and journals the open ticket here. The turn waits for it, so the
     * open row is written before a receipt row can follow it; the hook bounds
     * its own write. A throw is logged and the turn goes on.
     */
    opened?(handle: OpenHandle, ticket: Ticket): Promise<void> | void
    /**
     * The relay candidates and the picker a relayed request's hop came from,
     * which the settle ack's own hop is chosen from. Without it a relayed
     * request's ack has no route and is broadcast as before 9.12.
     */
    relays?: SettleAckRelays | undefined
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
    // The wallet completes the open group and submits it unless the node will
    // (submitsOpen). The app-call txid goes into the envelope either way: the
    // node finds a payer-submitted open by it, and checks that a handed-off
    // group carries it.
    let handle: OpenHandle
    try {
        handle =
            deps.wallet.openForNode && submitsOpen(op.protoVersion)
                ? await deps.wallet.openForNode(ticket, op, rt.presignedOpenTxn, signal)
                : await deps.wallet.open(ticket, op, rt.presignedOpenTxn, signal)
    } catch (err) {
        // The open didn't commit, so a failed attempt doesn't keep the cap.
        const guard = deps.spendGuard
        if (guard) guardRecords(log, 'release', ticket.ticket_id, () => guard.release(ticket.ticket_id))
        log.error('wallet open failed', {
            endpoint,
            ...opAttrs(op),
            ...relayAttrs(hop),
            ticket_id: ticket.ticket_id,
            err: errText(err),
        })
        em.fail(openFailure(deps.wallet.payerAddr(), deps.network, deps.remedies, err, deps.rail))
        return
    }
    // The ceiling stays on the spend tally: settlement charges less on chain,
    // and the cap counts the ceiling on purpose. The hook can't stop the turn:
    // escrow is open, or for a handed-off group may open whenever the node
    // submits it, so the caller must still hear that it paid.
    try {
        await deps.opened?.(handle, ticket)
    } catch (err) {
        log.warn('open hook failed', { ticket_id: ticket.ticket_id, err: errText(err) })
    }
    const deliverAck = settleAckPoster(deps, op, rt.sealRecipient, hop !== null)
    if (deliverAck) handle.deliverAck = deliverAck
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
            ...(handle.openGroup ? { openGroup: handle.openGroup } : {}),
            neutralNames: usesRailNeutralNames(op.protoVersion),
        })
    } catch (err) {
        log.error('wrap request failed', { endpoint, ...opAttrs(op), ...relayAttrs(hop), err: errText(err) })
        em.fail(newError('wrap_request', 'request could not be wrapped'))
        return
    }

    const call: SealedCall = { endpoint, model, op, reserved: rt, handle, txId, hop, signal }
    const buffered = deps.buffered(call)
    const respond = handle.openGroup ? recheckDepositOnRefusedOpen(deps.wallet, buffered) : buffered
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

/** Where a settle ack's relay hop comes from: the pool and picker the request's own did. */
export interface SettleAckRelays {
    pool(signal?: AbortSignal): Promise<SelectionOperator[]>
    hopFor(pool: SelectionOperator[], target: Operator): RelayHop | null
}

// What the node's settle-ack reply is read for: its error code. Go's 4 KiB.
const SETTLE_ACK_REPLY_LIMIT = 4 << 10

/**
 * settleAckPoster returns the handle's deliverAck for a node that takes the
 * payer's settle half (takesSettleAck), or undefined to keep broadcasting it,
 * Go's settleAckPoster. The ack is sealed to the recipient the request was
 * sealed to, and goes the way the request went: through a relay when the
 * request was relayed, or the ack would tie the payer's IP to the node the
 * relay hid it from.
 *
 * Only relays that forward the path can carry it. With none, the poster
 * rejects with NoSettleAckRouteError and the ack is broadcast as before 9.12,
 * or on Solana the payer sends its own ack transaction. Any other failure is
 * final: the node's settlement driver claims the ticket
 * on its own, and broadcasting after a send that may have arrived would only
 * race it.
 */
export function settleAckPoster(
    deps: Pick<SealedDeps, 'fetch' | 'relays'>,
    op: Operator,
    recipient: string,
    relayed: boolean,
): ((ack: SettleAck, signal?: AbortSignal) => Promise<void>) | undefined {
    if (!takesSettleAck(op.protoVersion) || !recipient) return undefined
    return async (ack, signal) => {
        const body = await sealSettleAck(ack, recipient, usesRailNeutralNames(op.protoVersion))
        let hop: RelayHop | null = null
        if (relayed) {
            const relays = deps.relays
            if (!relays) throw new NoSettleAckRouteError()
            const capable = (await relays.pool(signal)).filter((r) => takesSettleAck(r.proto_version))
            hop = relays.hopFor(capable, op)
            if (hop === null) throw new NoSettleAckRouteError()
        }
        const fwd = applyRelay(hop, op.baseUrl + SETTLE_ACK_PATH, 'POST', operatorHeaders(SEALED_SETTLE_ACK_CONTENT_TYPE), SETTLE_ACK_PATH)
        let resp: Response
        try {
            resp = await deps.fetch(fwd.url, { method: 'POST', headers: fwd.headers, body, ...(signal ? { signal } : {}) })
        } catch (err) {
            throw new Error(`zs: settle ack: ${errText(err)}`, { cause: err })
        }
        let reply = new Uint8Array()
        try {
            reply = await readReply(resp, null, SETTLE_ACK_REPLY_LIMIT)
        } catch {
            // Read only for the error code; an unreadable reply has none.
        }
        if (resp.status !== 202) {
            throw new Error(`zs: settle ack: node answered ${resp.status} ${openAIError(new TextDecoder().decode(reply)).code}`)
        }
    }
}

/**
 * recheckDepositOnRefusedOpen wraps the responder for a request whose open
 * the node submits, Go's recheckDepositOnRefusedOpen. A prepaid-pool shortfall
 * used to surface as the payer's own submit failing, and open topped the pool
 * up and retried. Now the revert happens at the node, which answers only
 * payment_verification_failed and burns the ticket, so the wallet rechecks its
 * deposit before the next open rather than trusting a cached "ready" every
 * later open would fail on too. Rechecking after some other refusal costs one
 * read.
 */
export function recheckDepositOnRefusedOpen(wallet: Pick<WalletOpener, 'recheckDeposit'>, next: BufferedResponder): BufferedResponder {
    return (em, resp, body) => {
        if (
            resp.status === 402 &&
            !resp.headers.get(RESPONSE_KEY_HEADER) &&
            openAIError(new TextDecoder().decode(body)).code === 'payment_verification_failed'
        ) {
            wallet.recheckDeposit?.()
        }
        return next(em, resp, body)
    }
}

/** openFailure is the error a failed open ends the turn with, most specific first. */
export function openFailure(payer: string, network: string, remedies: Remedies, err: unknown, rail?: Rail | undefined) {
    // The payer is short of ALGO (not USDC) to grow the prepaid ticket-MBR
    // pool, and no slot is free. A deposit that landed but left the pool short
    // with no slot free is the same condition. Checked before exhaustion: an
    // open retried after a failed top-up carries the pool revert too, which
    // alone reads as exhaustion. A Solana rent pool's shortfall extends these
    // errors, and its coin and pool are SOL and ticket rent.
    if (findError(err, MbrDepositUnaffordableError) !== undefined || findError(err, BelowTargetError) !== undefined) {
        const [coin, pool] = rail === 'solana' ? ['SOL', 'prepaid ticket rent pool'] : ['ALGO', 'prepaid ticket-MBR pool']
        return newError(
            'mbr_pool_underfunded',
            `zerosignal wallet ${payer} needs more ${coin} (not USDC) to fund the ${pool} on ${network} — ${errText(err)}. To fix it, ${remedies.fund}.`,
        )
    }
    // The wallet holds the ALGO but every slot backs an in-flight ticket: a
    // concurrency cap that clears as those settle, not an unfunded wallet.
    if (isPoolExhaustedOpenError(err)) {
        return newError(
            'mbr_pool_exhausted',
            `zerosignal wallet ${payer} has all concurrent ticket slots in use by in-flight requests on ${network} — retry once in-flight requests settle, or to allow more at once, ${remedies.raiseSlots}.`,
            { retryAfter: MBR_POOL_EXHAUSTED_RETRY_AFTER_MS },
        )
    }
    if (isUnderfundedOpenError(err)) {
        return newError(
            'wallet_unfunded',
            `zerosignal wallet ${payer} can't pay for this request on ${network}. To fix it, ${remedies.fund}.`,
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
    deps: Pick<SealedDeps, 'fetch' | 'relayReputation' | 'logger' | 'streamIdle' | 'maxReplyBytes'>,
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
        logForwardFailure(log, 'error', signal, 'operator request failed', endpoint, hop, err)
        em.fail(newError('upstream_unreachable', errText(err)))
        return
    }

    let body: Uint8Array
    try {
        body = await readReply(resp, deps.streamIdle, deps.maxReplyBytes)
    } catch (err) {
        logForwardFailure(log, 'warn', signal, 'operator reply read failed', endpoint, hop, err)
        em.fail(readUpstreamError(err))
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
 * logForwardFailure logs a forward that failed at level, Go's
 * logForwardFailure. One the caller ended by leaving is expected, so it is
 * logged at debug.
 */
export function logForwardFailure(
    log: Logger,
    level: 'warn' | 'error',
    signal: AbortSignal | undefined,
    msg: string,
    endpoint: Endpoint,
    hop: RelayHop | null,
    err: unknown,
): void {
    log[signal?.aborted ? 'debug' : level](msg, { endpoint, ...relayAttrs(hop), err: errText(err) })
}

/** readUpstreamError is the turn's error for a buffered reply that couldn't be read, with why as its cause. */
export function readUpstreamError(err: unknown): ZsError {
    return newError('read_upstream', errText(err), { cause: err })
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
