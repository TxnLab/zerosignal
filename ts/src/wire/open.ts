/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Mirrors proto/go/wire/open.go.

import { RESPONSE_KEY_SIZE } from './constants.js'
import { decryptBody, decryptSSEDataValue, openSealedHeader } from './wrap.js'

/**
 * The read half of ResponseSealer: opens the response payloads for a single
 * request under the per-response key the node wrapped to the caller's
 * ephemeral recipient.
 *
 * It exists so SPEC.md § 5.3's frame-counter rule is a property of which
 * method is called, as it is on the seal side: openHeader does not advance,
 * openNextFrame does. It also takes txID and ticketID once, at construction,
 * since transposing two adjacent strings in a positional call compiles and
 * silently produces a different AAD.
 *
 * Frames must be opened in wire order.
 */
export class ResponseOpener {
    readonly txId: string
    readonly ticketId: string
    readonly #key: Uint8Array
    #frameIndex = 0

    /**
     * txID and ticketID MUST be the values the caller sealed into the request
     * envelope; both are bound into every AAD. responseKey comes from
     * unwrapResponseKey and is held by reference, so zeroing it disables the
     * opener. Unlike Go's, which keeps its own copy inside the AEAD.
     */
    constructor(responseKey: Uint8Array, txID: string, ticketID: string) {
        if (responseKey.length !== RESPONSE_KEY_SIZE) {
            throw new Error(`response key must be ${RESPONSE_KEY_SIZE} bytes, got ${responseKey.length}`)
        }
        this.#key = responseKey
        this.txId = txID
        this.ticketId = ticketID
    }

    /** The index the next openNextFrame uses: how many frames have opened so far. */
    get frameIndex(): number {
        return this.#frameIndex
    }

    /** Opens a non-streaming ResponseEnvelope. A buffered response carries no frames. */
    openBody(envelopeJSON: Uint8Array): Uint8Array {
        return decryptBody(envelopeJSON, this.#key, this.txId, this.ticketId)
    }

    /**
     * Opens one piece of sealed response metadata: the X-Zs-Receipt or
     * X-Zs-Settle-Group header value, or the data of a `zs-settle-group` frame.
     * name is the SEALED_HEADER_* constant it was sealed under.
     *
     * Does not advance the frame counter. A settle-group frame arrives between
     * content frames, and taking an index for it would push the receipt frame
     * after it off by one.
     */
    openHeader(b64: string, name: string): Uint8Array {
        return openSealedHeader(b64, this.#key, this.txId, this.ticketId, name)
    }

    /**
     * Opens the next sealed frame (`event: zs` or `zs-receipt`) at the current
     * index, and advances the counter on success only. A failed open means the
     * bytes were not a frame this key and index produced; charging a slot for
     * them would put every later frame out of step with the sealer.
     */
    openNextFrame(b64: string): Uint8Array {
        const pt = decryptSSEDataValue(b64, this.#key, this.txId, this.ticketId, this.#frameIndex)
        this.#frameIndex++
        return pt
    }
}
