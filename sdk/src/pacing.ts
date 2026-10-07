/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Per-request dispatch decisions with no state of their own: the relay choice
// and the wait before a busy re-sweep. Mirror of proto/go/zs dispatch.go.

import { RELAY_OFF, RELAY_REQUIRED } from '@txnlab/zs-proto/selection'
import { type WaitDecision, wait } from '@txnlab/zs-proto/transient'

/**
 * resolveUsePrivacy is whether this request goes through a relay. A request
 * asking for one always gets it; one turning it off is honored only when
 * allowOverride; anything else keeps the configured default. relayPref is
 * already normalized.
 */
export function resolveUsePrivacy(configPrivacy: boolean, allowOverride: boolean, relayPref: string): boolean {
    if (relayPref === RELAY_REQUIRED) return true
    if (relayPref === RELAY_OFF && allowOverride) return false
    return configPrivacy
}

/**
 * A sweep in which every candidate answered busy earns this many more passes.
 * Capacity is the one refusal that changes by itself within seconds.
 */
export const BUSY_RETRIES = 2
/** A busy re-sweep may start only this long after dispatch began. */
export const BUSY_RETRY_BUDGET_MS = 8_000
/** The wait before a busy re-sweep when no node sent a Retry-After. */
export const BUSY_RETRY_DELAY_MS = 1_000
/** The most a node's Retry-After may stretch that wait, so one node can't spend the budget. */
export const BUSY_RETRY_MAX_DELAY_MS = 3_000
/** The Retry-After given to the caller when the whole pool was unreachable. */
export const TRANSIENT_RETRY_AFTER_HINT_MS = 30_000

/**
 * busyRetryWait is the wait before busy re-sweep `sweep`, within remainingMs of
 * the busy budget. A configured sweepDelay replaces the schedule and the node's
 * hint alike; otherwise the hint, clamped, wins when it is the longer.
 */
export function busyRetryWait(
    sweep: number,
    hintMs: number,
    remainingMs: number,
    sweepDelay?: (sweep: number) => number,
): WaitDecision {
    if (sweepDelay !== undefined) {
        if (remainingMs <= 0) return { delayMs: 0, ok: false }
        return { delayMs: Math.min(sweepDelay(sweep), remainingMs), ok: true }
    }
    return wait(BUSY_RETRY_DELAY_MS, Math.min(hintMs, BUSY_RETRY_MAX_DELAY_MS), remainingMs)
}
