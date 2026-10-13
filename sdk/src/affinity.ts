/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Continuation pinning, mirroring proto/go/zs IDAffinity.

import type { Clock } from './ports.js'
import type { NodeRef } from './types.js'

/**
 * AffinityStore maps an id a node issued (a tool_call_id, a Responses call_id,
 * or a Responses API response_id) to that node, so a continuation returns to it: its KV cache and
 * the Responses session live in that node's upstream account, not merely its
 * operator's. A host shares one across Clients through Stores.
 */
export interface AffinityStore {
    /** Pins each id to ref; a later record of the same id wins. */
    record(ref: NodeRef, ids: readonly string[]): void
    /** The node id was pinned to, or undefined on a miss or an expired pin. */
    lookup(id: string): NodeRef | undefined
}

interface Entry {
    ref: NodeRef
    expiresAt: number
}

/** IDAffinity is the default AffinityStore: bounded, TTL plus LRU. */
export class IDAffinity implements AffinityStore {
    readonly #ttl: number
    readonly #max: number
    readonly #clock: Clock
    // Map iteration is insertion order, so re-inserting on use keeps the least
    // recently used entry first.
    readonly #entries = new Map<string, Entry>()

    /** A max of 0 or less is 1024, as in Go. ttl is milliseconds. */
    constructor(max: number, ttl: number, clock: Clock = Date.now) {
        this.#ttl = ttl
        this.#max = max > 0 ? max : 1024
        this.#clock = clock
    }

    record(ref: NodeRef, ids: readonly string[]): void {
        // Operator id 0 is no operator; Go skips it so a zero ref never pins.
        if (ref.op === 0 || ids.length === 0) return
        const expiresAt = this.#clock() + this.#ttl
        for (const id of ids) {
            if (id === '') continue
            this.#entries.delete(id)
            this.#entries.set(id, { ref: { op: ref.op, node: ref.node }, expiresAt })
        }
        for (const id of this.#entries.keys()) {
            if (this.#entries.size <= this.#max) break
            this.#entries.delete(id)
        }
    }

    lookup(id: string): NodeRef | undefined {
        if (id === '') return undefined
        const e = this.#entries.get(id)
        if (e === undefined) return undefined
        this.#entries.delete(id)
        // Live through expiresAt itself, as Go's now.After(expiresAt).
        if (this.#clock() > e.expiresAt) return undefined
        this.#entries.set(id, e)
        return { op: e.ref.op, node: e.ref.node }
    }

    /** The entry count, expired ones not yet swept included. */
    get size(): number {
        return this.#entries.size
    }
}
