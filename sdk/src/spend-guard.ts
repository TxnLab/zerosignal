/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The SDK's two ways of calling a SpendGuard, which is host code. admit and
// reserve decide before money moves, so they must answer synchronously: a
// Promise's refusal would land after the reserve or open it was meant to stop,
// and a rejection nothing observes ends a Node process. settle and release
// record an outcome the SDK has already committed to, so a failing one is
// logged and the request, the sweep or the watchdog carries on, as Go's
// recordSpend does with a panic.

import type { Logger } from './ports.js'

function isThenable(v: unknown): v is PromiseLike<unknown> {
    return (typeof v === 'object' || typeof v === 'function') && v !== null && typeof (v as { then?: unknown }).then === 'function'
}

function errText(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}

/**
 * AsyncSpendGuardError is a SpendGuard decision that came back as a Promise:
 * the host's integration bug, which no cap setting or other candidate cures.
 */
export class AsyncSpendGuardError extends Error {
    constructor(readonly method: 'admit' | 'reserve') {
        super(`SpendGuard.${method} returned a Promise; its methods must answer synchronously`)
        this.name = 'AsyncSpendGuardError'
    }
}

/**
 * guardDecides runs admit or reserve. A throw passes through as the refusal;
 * a returned Promise throws AsyncSpendGuardError, whatever it would have
 * settled to.
 */
export function guardDecides(method: 'admit' | 'reserve', call: () => unknown): void {
    const r = call()
    if (isThenable(r)) {
        r.then(undefined, () => {})
        throw new AsyncSpendGuardError(method)
    }
}

/** guardRecords runs settle or release, logging a throw or a rejection rather than passing it on. */
export function guardRecords(log: Logger, method: 'settle' | 'release', ticketId: string, call: () => unknown): void {
    const failed = (err: unknown) => log.warn(`spend guard ${method} failed`, { ticket_id: ticketId, err: errText(err) })
    try {
        const r = call()
        if (isThenable(r)) r.then(undefined, failed)
    } catch (err) {
        failed(err)
    }
}
