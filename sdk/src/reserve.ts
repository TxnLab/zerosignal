/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// One POST /v1/zs/reserve and the payer's checks on its answer, mirroring
// proto/go/zs's Reserve: from minting the reply-to identity to a ticket ready
// to open escrow against, short of the ticket's signature and price. Retrying
// a refusal is the caller's: Go's lives in its dispatcher, not in Reserve.

import { retryableBusyCode } from '@txnlab/zs-proto/transient'
import {
    type BytesSigner,
    type ReserveRequest,
    type Ticket,
    RESERVE_CONTENT_TYPE,
    parseReserveResponseJSON,
    signReserveRequest,
} from '@txnlab/zs-proto/ticket'
import {
    type EphemeralIdentity,
    RELAY_HOP_HEADER,
    SEALED_RESERVE_CONTENT_TYPE,
    SEALED_RESERVE_RESPONSE_CONTENT_TYPE,
    generateEphemeralIdentity,
    openReserveResponse,
    sealReserveRequest,
    unwrapResponseKey,
} from '@txnlab/zs-proto/wire'

import { openAIError, readLimited } from './http.js'
import type { Clock, Fetch } from './ports.js'
import { type RelayHop, applyRelay } from './routing/relay.js'
import { verifyCommitK } from './verify.js'

/** ReserveTerms is what the payer asked the node for. */
export interface ReserveTerms {
    model: string
    maxOutputCount: number
    stream: boolean
    /**
     * The node the reserve was sent to. open() snapshots the pair and settles
     * against that node's signing key, and an operator's nodes can share one,
     * so the signature alone doesn't catch a ticket for a sibling node.
     */
    operatorId: number | bigint
    nodeId: number | bigint
}

/** ReserveResponseError is a 200 reserve response the payer refuses to escrow against. */
export class ReserveResponseError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message, cause === undefined ? undefined : { cause })
        this.name = 'ReserveResponseError'
    }
}

export interface OpenReserveOptions {
    nowMs: number
    /** See checkTicketTerms. */
    minTtlSeconds?: number
    /** The reserve named a payer, so the node owes a presigned open group. */
    requirePresignedOpen?: boolean
}

export interface ReservedTicket {
    ticket: Ticket & { sig: string }
    /** K_response. The caller zeroes it when the turn ends. */
    responseKey: Uint8Array
    /** ALGO/USD at reserve, for display; 0 when the node sent none. */
    algoUsdPrice: number
    /** base64 msgpack of the presigned open group; '' when the node sent none. */
    presignedOpenTxn: string
}

/**
 * openReserve opens a sealed 200 reserve response with the identity whose
 * recipient the reserve declared, and runs Go's checks: a strict parse, the
 * ticket's terms against the request, then the wrapped K_response, which must
 * hash to the ticket's commit_k. Every failure is a ReserveResponseError except
 * the last, a CommitKMismatchError. Go has no requirePresignedOpen; it composes
 * the open only when a group came back.
 *
 * Two checks are the caller's before it escrows: the ticket's signature, with
 * verifyTicketSignature, since the node's signing key comes from the chain;
 * and its price, with zs-proto's verifyTicketPrice against what the node
 * advertised, which is also what bounds the input_count checkTicketTerms
 * leaves alone.
 */
export async function openReserve(
    sealed: Uint8Array,
    identity: EphemeralIdentity,
    terms: ReserveTerms,
    opts: OpenReserveOptions,
): Promise<ReservedTicket> {
    let plaintext: Uint8Array
    try {
        plaintext = await openReserveResponse(sealed, identity)
    } catch (err) {
        throw new ReserveResponseError(`open reserve response: ${message(err)}`, err)
    }
    let parsed
    try {
        parsed = parseReserveResponseJSON(plaintext)
    } catch (err) {
        throw new ReserveResponseError(`parse reserve response: ${message(err)}`, err)
    }
    const { ticket } = parsed
    if (!ticket.sig) throw new ReserveResponseError('reserve ticket is unsigned')
    checkTicketTerms(ticket, terms, opts.nowMs, opts.minTtlSeconds)
    if (!parsed.wrapped_response_key) {
        throw new ReserveResponseError('reserve response missing wrapped_response_key')
    }
    if (opts.requirePresignedOpen && !parsed.presigned_open_txn) {
        throw new ReserveResponseError('reserve response missing presigned_open_txn')
    }
    let responseKey: Uint8Array
    try {
        responseKey = await unwrapResponseKey(parsed.wrapped_response_key, identity)
    } catch (err) {
        throw new ReserveResponseError(`unwrap response key: ${message(err)}`, err)
    }
    // Before the open: a node that committed to one K and wrapped another
    // would have the payer escrow for a response its admission then refuses.
    try {
        verifyCommitK(ticket, responseKey)
    } catch (err) {
        responseKey.fill(0)
        throw err
    }
    return {
        ticket: ticket as Ticket & { sig: string },
        responseKey,
        algoUsdPrice: parsed.algo_usd_price ?? 0,
        presignedOpenTxn: parsed.presigned_open_txn ?? '',
    }
}

/**
 * checkTicketTerms throws a ReserveResponseError unless a ticket reflects the
 * request it answers. A valid signature over other terms (a cheaper model, a
 * different node, a stale ticket) is still no ticket to escrow against.
 *
 * input_count is deliberately not compared: the node caps it at
 * context_window − max_output_count (SPEC §3a), and an older node also floored
 * it at min_input_count, so an honest ticket can differ from the request.
 * verifyTicketPrice's input_count_bound is what stops a node inflating it.
 * That bound allows the payer's own count plus 10%, so it refuses a short
 * request from an older node whose floor was set above the payer's.
 *
 * The ticket must have at least minTtlSeconds left at nowMs, default and
 * minimum 1: Go's "not yet expired". A caller with a slow path from here to
 * the node's admission asks for more, or the ticket lapses between the open
 * and the request it pays for.
 */
export function checkTicketTerms(t: Ticket, terms: ReserveTerms, nowMs: number, minTtlSeconds = 1): void {
    if (BigInt(t.operator_id) !== id('operatorId', terms.operatorId)) {
        throw new ReserveResponseError(`ticket operator id ${t.operator_id} != requested ${terms.operatorId}`)
    }
    if (BigInt(t.node_id) !== id('nodeId', terms.nodeId)) {
        throw new ReserveResponseError(`ticket node id ${t.node_id} != requested ${terms.nodeId}`)
    }
    if (t.model !== terms.model) {
        throw new ReserveResponseError(`ticket model ${JSON.stringify(t.model)} != requested ${JSON.stringify(terms.model)}`)
    }
    if (t.max_output_count !== terms.maxOutputCount) {
        throw new ReserveResponseError(`ticket max_output_count ${t.max_output_count} != requested ${terms.maxOutputCount}`)
    }
    if (t.stream !== terms.stream) {
        throw new ReserveResponseError(`ticket stream ${t.stream} != requested ${terms.stream}`)
    }
    // A NaN either side would make the comparison below false and pass the
    // ticket, and a minimum under 1 would pass one already expired.
    if (!Number.isFinite(nowMs) || !Number.isFinite(minTtlSeconds) || minTtlSeconds < 1) {
        throw new ReserveResponseError(`cannot check expiry: now ${nowMs}ms, minimum TTL ${minTtlSeconds}s`)
    }
    const now = Math.floor(nowMs / 1000)
    if (t.expires_at - now < minTtlSeconds) {
        throw new ReserveResponseError(
            `ticket expires_at ${t.expires_at} leaves under ${minTtlSeconds}s (now ${now})`,
        )
    }
    if (!t.ticket_id) throw new ReserveResponseError('ticket_id is empty')
    if (!t.commit_k) throw new ReserveResponseError('commit_k is empty')
    // The node bumps max_price up to min_price for a tiny paid request, so a
    // ticket that breaks this would underfund escrow or marks a misbehaving
    // node.
    if (t.min_price > t.max_price) {
        throw new ReserveResponseError(`ticket min_price ${t.min_price} > max_price ${t.max_price}`)
    }
}

/**
 * BusyError is a 429. code is the node's, and it decides whether re-asking
 * can help: of the four conditions a 429 carries, only no_capacity clears in
 * seconds, and re-asking after payer_slot_cap earns the payer a strike.
 */
export class BusyError extends Error {
    readonly code: string
    readonly retryAfterMs: number
    /**
     * Whether re-asking this node can produce a different answer within
     * seconds. A property, as ZsError's is, so `if (err.retryable)` can't
     * read a method as true.
     */
    readonly retryable: boolean
    constructor(code: string, retryAfterMs: number) {
        super(retryAfterMs === 0 ? 'operator busy (no retry-after hint)' : `operator busy (retry after ${retryAfterMs}ms)`)
        this.name = 'BusyError'
        this.code = code
        this.retryAfterMs = retryAfterMs
        this.retryable = retryableBusyCode(code)
    }
}

/**
 * SizeError is a 400 sizing refusal: max_output_count over the node's cap for
 * the model, or not below its context window. Every node refuses it the same
 * way, so it isn't a reason to try another.
 */
export class SizeError extends Error {
    readonly code: string
    /** The node's own message, for display. */
    readonly nodeMessage: string
    constructor(code: string, nodeMessage: string) {
        super(nodeMessage ? `operator rejected request: ${code}: ${nodeMessage}` : `operator rejected request: ${code}`)
        this.name = 'SizeError'
        this.code = code
        this.nodeMessage = nodeMessage
    }
}

/**
 * PayerRefusalError is a 403 for a reason the chain holds against the payer
 * (today, its daily free tickets are spent), so every node refuses it alike.
 * retryAfterMs is the node's estimate of the reset.
 */
export class PayerRefusalError extends Error {
    readonly code: string
    readonly nodeMessage: string
    readonly retryAfterMs: number
    constructor(code: string, nodeMessage: string, retryAfterMs: number) {
        super(
            nodeMessage
                ? `operator refused for a payer-scoped reason: ${code}: ${nodeMessage}`
                : `operator refused for a payer-scoped reason: ${code}`,
        )
        this.name = 'PayerRefusalError'
        this.code = code
        this.nodeMessage = nodeMessage
        this.retryAfterMs = retryAfterMs
    }
}

/**
 * BadReserveEnvelopeError is the node unable to open the sealed body: the
 * ephemeral it was sealed to is gone (the node restarted or rotated before the
 * key's advertised expiry). Re-probing the node's ephemeral and reserving once
 * more is the caller's remedy, as Go's dispatcher does.
 */
export class BadReserveEnvelopeError extends Error {
    constructor() {
        super('node rejected sealed reserve envelope (bad_reserve_envelope)')
        this.name = 'BadReserveEnvelopeError'
    }
}

/**
 * NoEphemeralError is a node with no valid, unexpired signed ephemeral to seal
 * the reserve to. Forward secrecy is mandatory, so there is nothing to fall back
 * to: the dispatcher skips the node rather than counting it as a transport
 * failure, and reports no_ephemeral_capacity when every node is skipped for
 * this. Go's errNoEphemeral.
 */
export class NoEphemeralError extends Error {
    constructor() {
        super('operator has no valid forward-secrecy ephemeral recipient')
        this.name = 'NoEphemeralError'
    }
}

/**
 * ReserveHTTPError is any other refusal, or a transport failure (status 0,
 * cause set) that produced no response. It carries the facts
 * zs-proto/transient's classify and narrowRelayed decide a retry from.
 */
export class ReserveHTTPError extends Error {
    readonly status: number
    /** The node's error.code; '' when the body had none, as a gateway's page. */
    readonly code: string
    /** The node's error.message; '' when it gave none. */
    readonly nodeMessage: string
    /**
     * Up to 256 characters of what came back, for logs. Any hop can write it
     * (a gateway's HTML page, say), so it stays out of message.
     */
    readonly body: string
    readonly retryAfterMs: number
    /**
     * Whether the response carried the relay-hop header: the relay's own
     * handler produced or forwarded it. Always false with no response.
     */
    readonly relayHopMarked: boolean
    /**
     * Whether the call's own signal or timeout ended it: the round trip ran
     * out of time, which says nothing about whether a relay forwarded.
     */
    readonly aborted: boolean
    constructor(
        init: {
            status: number
            code?: string
            nodeMessage?: string
            body?: string
            retryAfterMs?: number
            relayHopMarked?: boolean
            aborted?: boolean
        },
        cause?: unknown,
    ) {
        super(
            init.status === 0
                ? `reserve: ${cause instanceof Error ? cause.message : String(cause)}`
                : `reserve: HTTP ${init.status}${init.code ? `: ${init.code}` : ''}`,
            cause === undefined ? undefined : { cause },
        )
        this.name = 'ReserveHTTPError'
        this.status = init.status
        this.code = init.code ?? ''
        this.nodeMessage = init.nodeMessage ?? ''
        this.body = init.body ?? ''
        this.retryAfterMs = init.retryAfterMs ?? 0
        this.relayHopMarked = init.relayHopMarked ?? false
        this.aborted = init.aborted ?? false
    }
}

/** The node a reserve goes to. */
export interface ReserveTarget {
    operatorId: number | bigint
    nodeId: number | bigint
    /** The node's root URL; the reserve route is appended. */
    baseUrl: string
    /**
     * The age recipient the body is sealed to: the node's verified, unexpired
     * ephemeral. There is no durable-key fallback (forward secrecy is
     * mandatory), so a node without one isn't reserved against at all.
     */
    sealRecipient: string
}

export interface ReserveCall {
    target: ReserveTarget
    /**
     * The request, short of what reserve fills: proxy_recipient (a fresh
     * identity per call) and the payer signature.
     */
    request: Omit<ReserveRequest, 'proxy_recipient' | 'payer_sig' | 'payer_issued_at'>
    /**
     * The relay to route through; null sends to the node directly. Its
     * target must be call.target, or the relay would carry a body sealed and
     * signed for one node to another.
     */
    hop: RelayHop | null
    /**
     * Require a presigned open group back. A node with escrow admission sends
     * one whenever the request names a payer; a ticket-only node (localnet,
     * tests) never does, so this is the caller's to know.
     */
    requirePresignedOpen?: boolean
    /**
     * Bounds the round trip, default DEFAULT_RESERVE_TIMEOUT_MS: fetch has no
     * timeout of its own, and a node that accepts the connection and sends
     * nothing would otherwise hold the call forever.
     */
    timeoutMs?: number
    /**
     * Signs the request under payer_addr (SPEC §3a "Reserve-request
     * signature"), binding the target. Without one, or without a payer_addr,
     * the request goes unsigned, which a node accepts under
     * verify-if-present.
     */
    signer?: BytesSigner
    fetch: Fetch
    signal?: AbortSignal
    clock?: Clock
    /** See checkTicketTerms. */
    minTtlSeconds?: number
}

/** Reservation is a reserved ticket and the reply-to identity its key was wrapped to. */
export interface Reservation extends ReservedTicket {
    /**
     * The identity the response key, and later X-Zs-Response-Key, unwraps
     * with. Ephemeral: the caller drops it when the turn ends.
     */
    identity: EphemeralIdentity
}

const RESERVE_PATH = '/v1/zs/reserve'

/**
 * DEFAULT_RESERVE_TIMEOUT_MS is Go's DefaultReserveTimeout. The node simulates
 * the open group and signs a ticket, which takes a cross-internet node a few
 * seconds.
 */
export const DEFAULT_RESERVE_TIMEOUT_MS = 5_000

// A Retry-After is read up to a day, because a free-ticket allowance resets
// on that scale. Go caps one node's hint far lower where it becomes the
// caller's wait (nodeRetryHint); a caller here decides that for itself.
const MAX_RETRY_AFTER_SECONDS = 24 * 60 * 60

// The 400 codes that are a sizing refusal, and the 403 codes that are the
// payer's. Allowlists: a code added here changes what the caller does next,
// so each must match what a node emits.
const sizingErrorCodes = new Set(['context_length_exceeded'])
const payerRefusalCodes = new Set(['free_quota_exhausted'])

/**
 * reserve posts one reserve to call.target, through call.hop when given, and
 * returns the ticket it got back once openReserve's checks pass. A refusal
 * throws one of the error types above. A signed request the node refuses with
 * 401 invalid_payer_sig and its own clock is re-signed at that clock and sent
 * once more, since a skewed clock would sign every attempt the caller made.
 * The node names its clock on every invalid_payer_sig, not only a skewed one,
 * so any such refusal costs a second signature.
 */
export async function reserve(call: ReserveCall): Promise<Reservation> {
    const { hop, target } = call
    if (hop !== null && (BigInt(hop.targetId) !== BigInt(target.operatorId) || BigInt(hop.targetNodeId) !== BigInt(target.nodeId))) {
        throw new Error(
            `reserve: hop targets node ${hop.targetId}/${hop.targetNodeId}, not ${target.operatorId}/${target.nodeId}`,
        )
    }
    const clock = call.clock ?? Date.now
    const identity = await generateEphemeralIdentity()
    // Rebuilt, not spread alone: the type keeps a stale signature out at
    // compile time only, and one left on a reused object would go out as is.
    const { payer_sig: _sig, payer_issued_at: _at, ...fields } = call.request as ReserveRequest
    const request: ReserveRequest = { ...fields, proxy_recipient: identity.recipient }
    const signs = call.signer !== undefined && !!request.payer_addr
    const timeout = AbortSignal.timeout(call.timeoutMs ?? DEFAULT_RESERVE_TIMEOUT_MS)
    const signal = call.signal ? AbortSignal.any([call.signal, timeout]) : timeout

    const seal = async (issuedAt: number): Promise<Uint8Array> => {
        if (signs) {
            request.payer_issued_at = issuedAt
            try {
                await signReserveRequest(
                    call.target.operatorId,
                    call.target.nodeId,
                    request,
                    call.signer!,
                    request.payer_addr!,
                )
            } catch (err) {
                throw new Error(`sign reserve request: ${message(err)}`, { cause: err })
            }
        }
        try {
            return await sealReserveRequest(
                new TextEncoder().encode(JSON.stringify(request)),
                call.target.sealRecipient,
            )
        } catch (err) {
            throw new Error(`seal reserve request: ${message(err)}`, { cause: err })
        }
    }

    const attempt = async (
        issuedAt: number,
    ): Promise<{ body: Uint8Array; refusal?: undefined } | { body?: undefined; refusal: Error }> => {
        const sealed = await seal(issuedAt)
        const url = target.baseUrl.replace(/\/+$/, '') + RESERVE_PATH
        const req = applyRelay(
            hop,
            url,
            'POST',
            {
                'Content-Type': SEALED_RESERVE_CONTENT_TYPE,
                // A 200 comes back sealed to our identity; a refusal stays
                // plaintext so we can tell why.
                Accept: `${SEALED_RESERVE_RESPONSE_CONTENT_TYPE}, ${RESERVE_CONTENT_TYPE}`,
            },
            // The relay joins this to the target's own base URL, so it is the
            // route alone, not url's path: a base URL with a path of its own
            // would otherwise reach the relay twice over.
            RESERVE_PATH,
        )
        let resp: Response
        try {
            resp = await call.fetch(req.url, { method: req.method, headers: req.headers, body: sealed, signal })
        } catch (err) {
            throw new ReserveHTTPError({ status: 0, aborted: signal.aborted }, err)
        }
        try {
            if (resp.status === 200) return { body: await readLimited(resp) }
            return { refusal: await refusal(resp) }
        } catch (err) {
            // The body didn't arrive whole, our own abort included. Left
            // unclassified, as Go leaves it: a response did arrive, so it is no
            // transport failure to charge a relay for, and no refusal to read a
            // code from. A dispatcher reads it as a hard refusal.
            throw new Error(`read reserve response: ${message(err)}`, { cause: err })
        }
    }

    let got = await attempt(Math.floor(clock() / 1000))
    if (got.refusal instanceof PayerSigSkew && signs) {
        got = await attempt(got.refusal.nodeTime)
    }
    if (got.refusal) {
        throw got.refusal instanceof PayerSigSkew ? got.refusal.asHTTPError : got.refusal
    }
    const checked = await openReserve(
        got.body,
        identity,
        {
            model: request.model,
            maxOutputCount: request.max_output_count,
            stream: request.stream,
            operatorId: target.operatorId,
            nodeId: target.nodeId,
        },
        {
            nowMs: clock(),
            requirePresignedOpen: call.requirePresignedOpen ?? false,
            ...(call.minTtlSeconds !== undefined ? { minTtlSeconds: call.minTtlSeconds } : {}),
        },
    )
    return { ...checked, identity }
}

// A 401 invalid_payer_sig carrying the node's clock: our payer_issued_at fell
// outside its window. Internal: reserve resyncs once, and surfaces the 401 as
// a ReserveHTTPError when it can't.
class PayerSigSkew extends Error {
    constructor(
        readonly nodeTime: number,
        readonly asHTTPError: ReserveHTTPError,
    ) {
        super(asHTTPError.message)
    }
}

// refusal reads a non-200 into the error that says what to do about it. A
// body that won't read throws: classified on its status alone, a node's coded
// refusal cut short would pass for a gateway's code-less one, which is retried.
async function refusal(resp: Response): Promise<Error> {
    const text = new TextDecoder().decode(await readLimited(resp))
    const { code, nodeMessage } = openAIError(text)
    const err = reserveRefusal({
        status: resp.status,
        code,
        nodeMessage,
        body: truncate(text, 256),
        retryAfterMs: parseRetryAfter(resp.headers.get('Retry-After')),
        // Present and non-empty, as Go's Header.Get(...) != "".
        relayHopMarked: !!resp.headers.get(RELAY_HOP_HEADER),
    })
    if (err instanceof ReserveHTTPError && err.status === 401 && code === 'invalid_payer_sig') {
        const nodeTime = parseNodeTime(nodeMessage)
        if (nodeTime !== undefined) return new PayerSigSkew(nodeTime, err)
    }
    return err
}

/** The facts of a non-200 reserve answer, as reserveRefusal reads them. */
export interface ReserveRefusalFields {
    status: number
    /** The node's error.code; '' when the body had none. */
    code: string
    nodeMessage?: string
    body?: string
    retryAfterMs?: number
    relayHopMarked?: boolean
}

/**
 * reserveRefusal is the typed error a non-200 reserve answer means, as reserve
 * throws it (short of its clock-skew resync): BusyError, SizeError,
 * BadReserveEnvelopeError, PayerRefusalError or ReserveHTTPError. Exported for
 * a caller that holds a refusal's facts in some other shape and wants the
 * SDK's verdict on it (classifyReserveFailure).
 */
export function reserveRefusal(f: ReserveRefusalFields): Error {
    const { status, code } = f
    const nodeMessage = f.nodeMessage ?? ''
    const retryAfterMs = f.retryAfterMs ?? 0
    if (status === 429) return new BusyError(code, retryAfterMs)
    if (status === 400) {
        if (sizingErrorCodes.has(code)) return new SizeError(code, nodeMessage)
        if (code === 'bad_reserve_envelope') return new BadReserveEnvelopeError()
    }
    if (status === 403 && payerRefusalCodes.has(code)) {
        return new PayerRefusalError(code, nodeMessage, retryAfterMs)
    }
    return new ReserveHTTPError({
        status,
        code,
        nodeMessage,
        body: f.body ?? '',
        retryAfterMs,
        relayHopMarked: f.relayHopMarked ?? false,
    })
}

/**
 * parseRetryAfter reads a delta-seconds Retry-After into milliseconds, 0 when
 * absent or not a positive integer, capped at a day: Go's parseRetryAfter,
 * which reads with strconv.Atoi. An HTTP-date is read as absent; no node sends
 * one.
 */
export function parseRetryAfter(v: string | null): number {
    const m = v === null ? null : /^\s*\+?(\d+)\s*$/.exec(v)
    if (!m) return 0
    // Atoi refuses what doesn't fit an int64, so a longer number reads as
    // absent there, not as the cap.
    if (BigInt(m[1]!) > 0x7fff_ffff_ffff_ffffn) return 0
    const seconds = Number(m[1])
    return Math.min(seconds, MAX_RETRY_AFTER_SECONDS) * 1000
}

// parseNodeTime reads the node_time=<unix seconds> the node stamps into a 401
// invalid_payer_sig message.
function parseNodeTime(msg: string): number | undefined {
    const m = /node_time=(\d+)/.exec(msg)
    if (!m) return undefined
    const n = Number(m[1])
    return Number.isSafeInteger(n) && n > 0 ? n : undefined
}

function truncate(s: string, n: number): string {
    return s.length <= n ? s : `${s.slice(0, n)}…`
}

// A caller's id that isn't an integer would throw a bare RangeError from BigInt.
function id(name: string, v: number | bigint): bigint {
    if (typeof v === 'number' && !Number.isSafeInteger(v)) {
        throw new ReserveResponseError(`requested ${name} ${v} is not an integer`)
    }
    return BigInt(v)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
