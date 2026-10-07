/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: not exported from the package.

/**
 * sleep resolves true after ms, or false at once when signal aborts first. A
 * non-positive ms still checks the signal, so a caller gone during a zero wait
 * is noticed before another round trip. Go's sleepCtx.
 */
export function sleep(ms: number, signal: AbortSignal | undefined): Promise<boolean> {
    if (signal?.aborted) return Promise.resolve(false)
    if (ms <= 0) return Promise.resolve(true)
    return new Promise((resolve) => {
        const onAbort = () => {
            clearTimeout(timer)
            resolve(false)
        }
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort)
            resolve(true)
        }, ms)
        signal?.addEventListener('abort', onAbort, { once: true })
    })
}
