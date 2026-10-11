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

/**
 * untilAborted is p, or signal's reason once it aborts first. p is left
 * running, and its rejection handled.
 */
export function untilAborted<T>(p: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
    if (signal === undefined) return p
    if (signal.aborted) {
        p.catch(() => {})
        return Promise.reject(signal.reason)
    }
    return new Promise<T>((resolve, reject) => {
        const onAbort = () => reject(signal.reason)
        signal.addEventListener('abort', onAbort, { once: true })
        p.then(
            (v) => {
                signal.removeEventListener('abort', onAbort)
                resolve(v)
            },
            (err: unknown) => {
                signal.removeEventListener('abort', onAbort)
                reject(err)
            },
        )
    })
}

// setTimeout fires at once past this delay, so a longer wait is taken in steps.
export const MAX_TIMER_MS = 2 ** 31 - 1

/**
 * idle is the background loops' sleep: the refund watchdog's and the
 * journal sweep's. It resolves true after ms, or false at once when signal
 * aborts first, and never wakes early, as Go's timers don't: a box read
 * before a deadline that fails would send a refund the contract must revert.
 * Its timers never hold a Node process open, as a goroutine never holds Go's
 * main: a process that exits first leaves its tickets to the next sweep.
 */
export async function idle(ms: number, signal: AbortSignal): Promise<boolean> {
    let left = Math.max(ms, 0)
    do {
        const step = Math.min(left, MAX_TIMER_MS)
        if (!(await unrefTimer(step, signal))) return false
        left -= step
    } while (left > 0)
    return true
}

function unrefTimer(ms: number, signal: AbortSignal): Promise<boolean> {
    if (signal.aborted) return Promise.resolve(false)
    return new Promise((resolve) => {
        const onAbort = () => {
            clearTimeout(timer)
            resolve(false)
        }
        const timer = setTimeout(() => {
            signal.removeEventListener('abort', onAbort)
            resolve(true)
        }, ms)
        ;(timer as { unref?: () => void }).unref?.()
        signal.addEventListener('abort', onAbort, { once: true })
    })
}
