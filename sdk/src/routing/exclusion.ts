/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Hard exclusion of a proven-malicious node, mirroring
// proto/go/zs/malicious_nodes.go. Every other routing signal heals itself: a
// TTL lapses, a streak resets, a demotion floats back. This one is write-once
// and drops the node outright, because its trigger is proof of misbehaviour,
// not a fault: the node composed a settle group that contradicts its own
// signed receipt, or that would rekey the payer's account or bypass the
// approval program. It authored both halves, so the mismatch can't be honest
// desync.

import { type NodeRef, nodeRefString } from '../types.js'

export class NodeExclusionStore {
    readonly #excluded = new Set<string>()

    /**
     * excludeNode bars the node from candidate selection and the relay pool for
     * the store's lifetime. Call it only on proof of settle-group fraud; a
     * transient failure belongs in TargetBackoffStore, which heals.
     */
    excludeNode(target: NodeRef): void {
        this.#excluded.add(nodeRefString(target))
    }

    nodeExcluded(target: NodeRef): boolean {
        return this.#excluded.has(nodeRefString(target))
    }

    clear(): void {
        this.#excluded.clear()
    }
}
