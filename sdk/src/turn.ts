/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// One turn as the caller asks for it and as dispatch sees it, and the emitter
// dispatch reports through, mirroring proto/go/zs Request, turn and emitter.

import { normalizeRelay } from '@txnlab/zs-proto/selection'

import type { ZsError } from './errors.js'
import type { Event } from './events.js'
import type { Operator } from './operator.js'
import type { Reserved } from './parts.js'
import type { Endpoint } from './types.js'

/**
 * Request is one turn: an OpenAI-shaped body for one endpoint, plus the
 * routing preferences that don't travel in it. Those that do (the body's
 * `provider` object) are read from body and stripped before it is sealed.
 */
export interface Request {
    endpoint: Endpoint
    body: Uint8Array | string
    /** body's media type. Only an image edit, which is multipart, needs it. */
    contentType?: string
    /** Routes only to attested nodes, on top of Config.requireTeeModels. */
    requireTee?: boolean
    /**
     * "auto", "off" or "required"; absent or anything else defers to
     * Config.privacy. A `provider.relay` in body outranks it. "off" takes
     * effect only with Config.allowPrivacyOverride.
     */
    relay?: string
    /**
     * Skips decoding, for a caller that re-emits the node's bytes: the turn
     * yields each frame but no content events, an error the node reports
     * inside its response passes as a frame, and done's fields are zero.
     */
    framesOnly?: boolean
}

/** Turn is one request as dispatch sees it. */
export interface Turn {
    endpoint: Endpoint
    body: Uint8Array | string
    contentType: string
    requireTee: boolean
    /** The caller's normalized relay preference; the body's outranks it. */
    relay: string
}

export function turnOf(r: Request): Turn {
    return {
        endpoint: r.endpoint,
        body: r.body,
        contentType: r.contentType ?? '',
        requireTee: r.requireTee ?? false,
        relay: normalizeRelay(r.relay),
    }
}

/**
 * Emitter receives what the reserve phase produces: dispatch decides what
 * happened, and the emitter turns it into the caller's view. A request ends in
 * fail or in the sealed run; note, clamped, reserved and committed may precede
 * either. The sealed run's reply and stream calls join this with it.
 */
export interface Emitter {
    /** A routing milestone. It never ends the request. */
    note(ev: Event): void
    /** The request's max_output was lowered to ceiling. */
    clamped(ceiling: number): void
    /** The ticket a node signed. */
    reserved(r: Reserved, op: Operator): void
    /** The escrow open; nothing is resent after it. */
    committed(ticketId: string, openTxId: string, feesMicroAlgos: number): void
    /** Ends the request with err before any response has started. */
    fail(err: ZsError): void
}
