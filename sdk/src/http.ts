/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go reads every node answer through an io.LimitReader capped at this, so a
// node can't make the payer buffer an unbounded body.
export const MAX_RESPONSE_BYTES = 256 << 10

/** readLimited reads at most max bytes of the body and drops the rest, as Go's LimitReader. */
export async function readLimited(resp: Response, max: number = MAX_RESPONSE_BYTES): Promise<Uint8Array> {
    if (!resp.body) return new Uint8Array()
    const reader = resp.body.getReader()
    const chunks: Uint8Array[] = []
    let n = 0
    try {
        while (n < max) {
            const { done, value } = await reader.read()
            if (done) break
            const take = value.subarray(0, max - n)
            chunks.push(take)
            n += take.length
        }
    } finally {
        reader.cancel().catch(() => {})
    }
    const out = new Uint8Array(n)
    let off = 0
    for (const c of chunks) {
        out.set(c, off)
        off += c.length
    }
    return out
}
