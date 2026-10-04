/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * boundedMapSet inserts key as the newest entry and then evicts the oldest
 * until the map holds at most max (no bound when max ≤ 0). A bulk re-set of
 * the live fleet moves every live entry to the newest positions, so eviction
 * takes a departed node rather than one just refreshed. Reads don't touch
 * recency: the re-set is what keeps entries fresh.
 */
export function boundedMapSet<K, V>(m: Map<K, V>, key: K, value: V, max: number): void {
    if (m.has(key)) m.delete(key)
    m.set(key, value)
    if (max > 0) {
        while (m.size > max) {
            const oldest = m.keys().next()
            if (oldest.done) break
            m.delete(oldest.value)
        }
    }
}
