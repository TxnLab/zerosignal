/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import { AsyncSpendGuardError, guardDecides, guardRecords } from '../src/spend-guard.js'
import { recLogger } from './turn-fixtures.js'

// A thenable needn't be an object: a function carrying then is awaited all
// the same, so it is refused like a Promise.
describe('the spend guard calls', () => {
    const fnThenable = () => Object.assign(() => {}, { then: () => {} })

    it('refuses a decision that answers with any thenable', () => {
        expect(() => guardDecides('admit', () => Promise.resolve())).toThrow(AsyncSpendGuardError)
        expect(() => guardDecides('reserve', fnThenable)).toThrow(AsyncSpendGuardError)
        expect(() => guardDecides('admit', () => undefined)).not.toThrow()
        expect(() => guardDecides('admit', () => 1)).not.toThrow()
    })

    it('carries on past a record that throws or rejects, logging it', async () => {
        const log = recLogger()
        expect(() =>
            guardRecords(log, 'settle', 'T', () => {
                throw new Error('guard bug')
            }),
        ).not.toThrow()
        guardRecords(log, 'release', 'T', () => Promise.reject(new Error('later bug')))
        guardRecords(log, 'release', 'T', fnThenable)
        await new Promise((res) => setTimeout(res, 0))
        expect(log.logged).toEqual([
            { level: 'warn', msg: 'spend guard settle failed', attrs: { ticket_id: 'T', err: 'guard bug' } },
            { level: 'warn', msg: 'spend guard release failed', attrs: { ticket_id: 'T', err: 'later bug' } },
        ])
    })
})
