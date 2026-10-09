/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils.js'
import { describe, expect, it, vi } from 'vitest'

import {
    type EphemeralVerdict,
    EphemeralVerifyCache,
    ageX25519RecipientError,
    checkEphemeralAdvertisement,
    recordEphemeralStaleness,
} from '../src/catalog/index.js'

interface VectorCase {
    name: string
    operator_id: number
    node_id: number
    signing_key: string
    now: number
    advertisement: {
        ephemeral_age_pubkey: string
        ephemeral_expiry: number
        ephemeral_issued_at: number
        ephemeral_sig: string
    }
    want: { outcome: EphemeralVerdict['outcome']; stale: boolean }
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/ephemeral_verdict_vectors.json', import.meta.url), 'utf8'),
) as { cases: VectorCase[] }

const staleOf = (v: EphemeralVerdict) => (v.outcome === 'verified' ? v.stale : false)
const caseNamed = (name: string) => {
    const c = vectors.cases.find((v) => v.name === name)
    if (!c) throw new Error(`no vector named ${name}`)
    return c
}

describe('checkEphemeralAdvertisement vectors', () => {
    it('covers every outcome', () => {
        expect(new Set(vectors.cases.map((c) => c.want.outcome))).toEqual(
            new Set(['absent', 'verified', 'expired', 'rejected', 'unparseable']),
        )
        expect(vectors.cases.some((c) => c.want.stale)).toBe(true)
    })

    for (const ids of ['number', 'bigint'] as const) {
        it(`matches Go for every case, with ${ids} ids`, () => {
            for (const c of vectors.cases) {
                const target =
                    ids === 'bigint'
                        ? { op: BigInt(c.operator_id), node: BigInt(c.node_id) }
                        : { op: c.operator_id, node: c.node_id }
                const v = checkEphemeralAdvertisement(target, hexToBytes(c.signing_key), c.advertisement, c.now)
                expect({ name: c.name, outcome: v.outcome, stale: staleOf(v) }).toEqual({
                    name: c.name,
                    ...c.want,
                })
            }
        })
    }

    it('returns the advertised recipient and window on a verified block', () => {
        const c = caseNamed('a fresh, genuine block')
        const v = checkEphemeralAdvertisement(
            { op: c.operator_id, node: c.node_id },
            hexToBytes(c.signing_key),
            c.advertisement,
            c.now,
        )
        expect(v).toEqual({
            outcome: 'verified',
            recipient: c.advertisement.ephemeral_age_pubkey,
            expiry: c.advertisement.ephemeral_expiry,
            issuedAt: c.advertisement.ephemeral_issued_at,
            stale: false,
        })
    })

    it('refuses a field of the wrong type, which Go’s typed decode never lets through', () => {
        // Genuine and long expired: as a string the expiry would still sign the
        // same bytes, then concatenate with the skew and never expire.
        const c = caseNamed('past expiry plus skew is expired')
        const target = { op: c.operator_id, node: c.node_id }
        const key = hexToBytes(c.signing_key)
        const later = c.now + 365 * 86_400
        const mistyped = (patch: Record<string, unknown>) =>
            checkEphemeralAdvertisement(target, key, { ...c.advertisement, ...patch } as never, later).outcome
        expect(mistyped({})).toBe('expired')
        expect(mistyped({ ephemeral_expiry: String(c.advertisement.ephemeral_expiry) })).toBe('rejected')
        expect(mistyped({ ephemeral_issued_at: String(c.advertisement.ephemeral_issued_at) })).toBe('rejected')
        expect(mistyped({ ephemeral_expiry: c.advertisement.ephemeral_expiry + 0.5 })).toBe('rejected')
        expect(mistyped({ ephemeral_expiry: null })).toBe('rejected')
        expect(mistyped({ ephemeral_sig: 42 })).toBe('rejected')
        expect(mistyped({ ephemeral_age_pubkey: ['age1x'] })).toBe('rejected')
    })

    it('reads missing fields as Go zero values', () => {
        const c = caseNamed('a fresh, genuine block')
        const key = hexToBytes(c.signing_key)
        const target = { op: c.operator_id, node: c.node_id }
        expect(checkEphemeralAdvertisement(target, key, {}, c.now).outcome).toBe('absent')
        const { ephemeral_sig: _sig, ...unsigned } = c.advertisement
        expect(checkEphemeralAdvertisement(target, key, unsigned, c.now).outcome).toBe('rejected')
    })
})

describe('ageX25519RecipientError', () => {
    it('accepts a recipient and names why it refuses one', () => {
        const ok = caseNamed('a fresh, genuine block').advertisement.ephemeral_age_pubkey
        expect(ageX25519RecipientError(ok)).toBeNull()
        expect(ageX25519RecipientError(ok.toUpperCase())?.message).toMatch(/lower case/)
        expect(ageX25519RecipientError(caseNamed('a signed recipient of another type').advertisement.ephemeral_age_pubkey)?.message).toMatch(/invalid type/)
        expect(ageX25519RecipientError(caseNamed('a signed 31-byte recipient').advertisement.ephemeral_age_pubkey)?.message).toMatch(/X25519/)
    })
})

describe('recordEphemeralStaleness', () => {
    const relay = { op: 9, node: 1 }
    const verified = (stale: boolean): EphemeralVerdict => ({
        outcome: 'verified',
        recipient: 'age1x',
        expiry: 2,
        issuedAt: 1,
        stale,
    })
    const sink = () => ({ recordRelayStaleEphemeral: vi.fn(), recordRelayFreshEphemeral: vi.fn() })

    it('charges the relay for a stale block and clears it for a fresh one', () => {
        const s = sink()
        recordEphemeralStaleness(s, relay, verified(true))
        expect(s.recordRelayStaleEphemeral).toHaveBeenCalledWith(relay)
        expect(s.recordRelayFreshEphemeral).not.toHaveBeenCalled()
        const f = sink()
        recordEphemeralStaleness(f, relay, verified(false))
        expect(f.recordRelayFreshEphemeral).toHaveBeenCalledWith(relay)
        expect(f.recordRelayStaleEphemeral).not.toHaveBeenCalled()
    })

    it('records nothing for a direct probe or an unverified block', () => {
        const s = sink()
        recordEphemeralStaleness(s, null, verified(true))
        for (const outcome of ['absent', 'expired'] as const) recordEphemeralStaleness(s, relay, { outcome })
        recordEphemeralStaleness(s, relay, { outcome: 'rejected', error: new Error('x') })
        recordEphemeralStaleness(s, relay, { outcome: 'unparseable', error: new Error('x') })
        expect(s.recordRelayStaleEphemeral).not.toHaveBeenCalled()
        expect(s.recordRelayFreshEphemeral).not.toHaveBeenCalled()
    })
})

describe('EphemeralVerifyCache', () => {
    const c = caseNamed('a fresh, genuine block')
    const key = hexToBytes(c.signing_key)
    const target = { op: c.operator_id, node: c.node_id }
    const setup = (startSec = c.now) => {
        let nowMs = startSec * 1000
        const onVerdict = vi.fn()
        const cache = new EphemeralVerifyCache({ clock: () => nowMs, onVerdict })
        return { cache, onVerdict, advance: (sec: number) => (nowMs += sec * 1000) }
    }

    it('reuses a verdict within its bucket and recomputes in the next', () => {
        // At a bucket's start, so 14s stays in it and 15s leaves.
        const { cache, onVerdict, advance } = setup(Math.floor(c.now / 15) * 15)
        expect(cache.check(target, key, c.advertisement).outcome).toBe('verified')
        advance(14)
        cache.check(target, key, c.advertisement)
        expect(onVerdict).toHaveBeenCalledTimes(1)
        advance(1)
        cache.check(target, key, c.advertisement)
        expect(onVerdict).toHaveBeenCalledTimes(2)
    })

    it('verifies at the clock it was given', () => {
        const expired = caseNamed('past expiry plus skew is expired')
        const { cache } = setup(expired.now)
        expect(cache.check(target, key, expired.advertisement).outcome).toBe('expired')
    })

    it('never hands one node a sibling node’s verdict', () => {
        const { cache } = setup()
        expect(cache.check(target, key, c.advertisement).outcome).toBe('verified')
        expect(cache.check({ ...target, node: target.node + 1 }, key, c.advertisement).outcome).toBe('rejected')
    })

    it('never answers for one signing key with a verdict reached under another', () => {
        // Ids repeat across networks and survive a key rotation; the key doesn't.
        const { cache } = setup()
        expect(cache.check(target, key, c.advertisement).outcome).toBe('verified')
        const other = hexToBytes('ab'.repeat(32))
        expect(cache.check(target, other, c.advertisement).outcome).toBe('rejected')
        // ...and the other way round, starting from the refusal.
        const { cache: fresh } = setup()
        expect(fresh.check(target, other, c.advertisement).outcome).toBe('rejected')
        expect(fresh.check(target, key, c.advertisement).outcome).toBe('verified')
    })

    it('keeps a mistyped field from sharing a verdict with its well-typed twin', () => {
        const { cache } = setup()
        const asString = { ...c.advertisement, ephemeral_expiry: String(c.advertisement.ephemeral_expiry) } as never
        expect(cache.check(target, key, asString).outcome).toBe('rejected')
        expect(cache.check(target, key, c.advertisement).outcome).toBe('verified')
    })

    it('rechecks a block whose issued_at changed', () => {
        const { cache } = setup()
        expect(cache.check(target, key, c.advertisement).outcome).toBe('verified')
        const tampered = { ...c.advertisement, ephemeral_issued_at: c.advertisement.ephemeral_issued_at + 1 }
        expect(cache.check(target, key, tampered).outcome).toBe('rejected')
    })

    it('hands onVerdict the target as passed', () => {
        const onVerdict = vi.fn()
        const cache = new EphemeralVerifyCache<{ op: number; node: number; label: string }>({
            clock: () => c.now * 1000,
            onVerdict,
        })
        const labelled = { ...target, label: 'n1' }
        const v = cache.check(labelled, key, c.advertisement)
        expect(onVerdict).toHaveBeenCalledWith(labelled, v)
    })

    it('starts over once full', () => {
        const onVerdict = vi.fn()
        const cache = new EphemeralVerifyCache({ clock: () => c.now * 1000, maxEntries: 2, onVerdict })
        cache.check(target, key, c.advertisement)
        cache.check({ ...target, node: 100 }, key, c.advertisement)
        cache.check(target, key, c.advertisement)
        expect(onVerdict).toHaveBeenCalledTimes(2)
        cache.check({ ...target, node: 101 }, key, c.advertisement)
        cache.check(target, key, c.advertisement)
        expect(onVerdict).toHaveBeenCalledTimes(4)
    })
})
