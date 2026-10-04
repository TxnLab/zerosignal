/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import { TARGET_BACKOFF_BASE_MS as BASE, TARGET_BACKOFF_CAP_MS as CAP } from '@txnlab/zs-proto/steering'

import { TargetBackoffStore } from '../src/routing/index.js'

const n = { op: 2, node: 0 }

function store(): TargetBackoffStore {
    return new TargetBackoffStore(() => 0)
}

describe('TargetBackoffStore', () => {
    it('a node with no failures is never backed off', () => {
        expect(store().targetBackedOff(n)).toBe(false)
    })

    it('reads the clock when no time is given', () => {
        let now = 0
        const s = new TargetBackoffStore(() => now)
        s.recordTargetOutcome(n, false)
        now = BASE - 1
        expect(s.targetBackedOff(n)).toBe(true)
        now = BASE
        expect(s.targetBackedOff(n)).toBe(false)
    })

    it('doubles the window per consecutive failure', () => {
        const s = store()
        let t = 1_000_000
        for (const w of [30_000, 60_000, 120_000, 240_000, CAP, CAP]) {
            s.recordTargetOutcome(n, false, t)
            expect(s.targetBackedOff(n, t + w - 1)).toBe(true)
            expect(s.targetBackedOff(n, t + w)).toBe(false)
            t += w
        }
    })

    it('a success clears the backoff and the streak', () => {
        const s = store()
        s.recordTargetOutcome(n, false, 0)
        s.recordTargetOutcome(n, false, BASE)
        s.recordTargetOutcome(n, true, 0)
        expect(s.targetBackedOff(n, 0)).toBe(false)
        s.recordTargetOutcome(n, false, 0)
        expect(s.targetBackoffRemainingMs(n, 0)).toBe(BASE)
    })

    it('forgets a node left alone a full cap after its window', () => {
        const s = store()
        s.recordTargetOutcome(n, false, 0)
        s.recordTargetOutcome(n, false, 1)
        const until = 1 + 2 * BASE
        expect(s.targetBackedOff(n, until + CAP - 1)).toBe(false)
        s.recordTargetOutcome(n, false, until + CAP - 1)
        expect(s.targetBackoffRemainingMs(n, until + CAP - 1)).toBe(4 * BASE)

        const t = store()
        t.recordTargetOutcome(n, false, 0)
        t.recordTargetOutcome(n, false, 1)
        expect(t.targetBackedOff(n, until + CAP)).toBe(false)
        t.recordTargetOutcome(n, false, until + CAP)
        expect(t.targetBackoffRemainingMs(n, until + CAP)).toBe(BASE)
    })

    it('keys by node', () => {
        const s = store()
        s.recordTargetOutcome({ op: 3, node: 4 }, false, 0)
        expect(s.targetBackedOff({ op: 3, node: 2 }, 0)).toBe(false)
        s.recordTargetOutcome({ op: 3, node: 2 }, true, 0)
        expect(s.targetBackedOff({ op: 3, node: 4 }, 0)).toBe(true)
    })

    it('floorMs extends the window from the last failure and never shortens it', () => {
        const s = store()
        const FLOOR = 3 * 60_000
        s.recordTargetOutcome(n, false, 0)
        expect(s.targetBackoffRemainingMs(n, BASE)).toBe(0)
        expect(s.targetBackoffRemainingMs(n, BASE, FLOOR)).toBe(FLOOR - BASE)
        expect(s.targetBackoffRemainingMs(n, FLOOR, FLOOR)).toBe(0)
        expect(s.targetBackoffRemainingMs(n, 0, 1_000)).toBe(BASE)
    })

    // A wall clock that steps back a day must not demote a node for a day.
    it('a backwards clock step leaves the window at most its length', () => {
        const s = store()
        const day = 86_400_000
        s.recordTargetOutcome(n, false, day)
        s.recordTargetOutcome(n, false, day)
        expect(s.targetBackoffRemainingMs(n, 0)).toBe(2 * BASE)
        expect(s.targetBackedOff(n, 2 * BASE)).toBe(false)
        s.recordTargetOutcome(n, false, 2 * BASE)
        expect(s.targetBackoffRemainingMs(n, 2 * BASE)).toBe(4 * BASE)
    })

    it('clear forgets every node', () => {
        const s = store()
        s.recordTargetOutcome(n, false, 0)
        s.clear()
        expect(s.targetBackedOff(n, 0)).toBe(false)
    })
})
