/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'

import {
    DEFAULT_EPHEMERAL_SKEW_SEC,
    FRESHNESS_TARGET_SEC,
    MAX_EPHEMERAL_LIFETIME_SEC,
    EphemeralExpiredError,
    EphemeralLifetimeError,
    ephemeralCanonicalBytes,
    ephemeralStale,
    signEphemeral,
    verifyEphemeral,
    type EphemeralAdvertisement,
} from '../src/ticket/ephemeral.js'
import {
    generateAlgorandKeypair,
    inMemoryEd25519Signer,
} from '../src/ticket/signing.js'
import { ed25519 } from '../src/util/ed25519.js'

const OPERATOR_ID = 42
const NODE_ID = 7
const NOW = 1_700_000_000
// A fixed, well-formed age1… recipient string (treated as opaque bytes).
const AGE_PUBKEY = 'age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s'

function sampleAdvertisement(): EphemeralAdvertisement {
    return {
        ephemeral_age_pubkey: AGE_PUBKEY,
        // A 25m window issued at NOW — an in-policy lifetime (≤ the 40m cap) so
        // the verify roundtrip tests don't trip the new lifetime check.
        ephemeral_issued_at: NOW,
        ephemeral_expiry: NOW + 25 * 60,
    }
}

function newSigner(): {
    signer: ReturnType<typeof inMemoryEd25519Signer>
    address: string
    publicKey: Uint8Array
} {
    const kp = generateAlgorandKeypair()
    const signer = inMemoryEd25519Signer(new Map([[kp.address, kp.privateKey]]))
    return { signer, address: kp.address, publicKey: kp.publicKey }
}

describe('EphemeralAdvertisement sign / verify', () => {
    it('round-trips through signEphemeral + verifyEphemeral', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(a.ephemeral_sig).toBeTruthy()
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).not.toThrow()
    })

    it('sign fails for an unknown address', async () => {
        const { signer } = newSigner()
        const a = sampleAdvertisement()
        await expect(
            signEphemeral(OPERATOR_ID, NODE_ID, a, signer, generateAlgorandKeypair().address),
        ).rejects.toThrow()
    })

    it('sign fails on a nil signer', async () => {
        const a = sampleAdvertisement()
        await expect(
            signEphemeral(OPERATOR_ID, NODE_ID, a, null as never, 'anything'),
        ).rejects.toThrow(/signer is nil/)
    })

    it('verify fails under a wrong key', async () => {
        const { signer, address } = newSigner()
        const otherPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey())
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, otherPub, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/verification failed/)
    })

    it('verify fails on an operator_id mismatch', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(() =>
            verifyEphemeral(OPERATOR_ID + 1, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/verification failed/)
    })

    it('verify fails on a node_id mismatch (sibling-node substitution, v3 tag)', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID + 1, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/verification failed/)
    })

    it('verify fails when a signed field is tampered after signing', async () => {
        const cases: Array<{ name: string; mutate: (a: EphemeralAdvertisement) => void }> = [
            {
                name: 'ephemeral_age_pubkey',
                mutate: (a) =>
                    (a.ephemeral_age_pubkey =
                        'age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxxxxxx'),
            },
            { name: 'ephemeral_expiry', mutate: (a) => (a.ephemeral_expiry += 1) },
            {
                name: 'ephemeral_sig',
                mutate: (a) => {
                    const raw = base64.decode(a.ephemeral_sig!)
                    raw[0] = (raw[0]! ^ 0xff) & 0xff
                    a.ephemeral_sig = base64.encode(raw)
                },
            },
        ]
        for (const c of cases) {
            const { signer, address, publicKey } = newSigner()
            const a = sampleAdvertisement()
            await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
            c.mutate(a)
            expect(
                () => verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
                `tampered ${c.name}`,
            ).toThrow()
        }
    })

    it('verify rejects a malformed / wrong-length sig', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        a.ephemeral_sig = '!!!not-base64!!!'
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow()
        a.ephemeral_sig = base64.encode(new TextEncoder().encode('too-short'))
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/invalid ed25519 signature length/)
    })

    it('verify rejects a missing sig', () => {
        const { publicKey } = newSigner()
        const a = sampleAdvertisement()
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/signature missing/)
    })

    it('verify rejects a wrong-length pubkey', async () => {
        const { signer, address } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, new Uint8Array([1, 2, 3]), NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/invalid ed25519 public key length/)
    })
})

describe('EphemeralAdvertisement expiry boundary', () => {
    it('is valid at exactly expiry + skew', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        const atBoundary = a.ephemeral_expiry + DEFAULT_EPHEMERAL_SKEW_SEC
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, atBoundary, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).not.toThrow()
    })

    it('throws EphemeralExpiredError one second past expiry + skew', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        const pastBoundary = a.ephemeral_expiry + DEFAULT_EPHEMERAL_SKEW_SEC + 1
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, pastBoundary, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(EphemeralExpiredError)
    })

    it('runs the signature check before the expiry check (forged + expired → not the sentinel)', async () => {
        const { signer, address } = newSigner()
        const otherPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey())
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        const pastBoundary = a.ephemeral_expiry + DEFAULT_EPHEMERAL_SKEW_SEC + 1
        // Forged-and-expired must surface as a verification failure, not the
        // expired sentinel, so callers log it as a substitution attempt.
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, otherPub, pastBoundary, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).not.toThrow(EphemeralExpiredError)
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, otherPub, pastBoundary, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/verification failed/)
    })
})

describe('EphemeralAdvertisement lifetime + not-before (hard checks)', () => {
    it('rejects an authentically-signed but over-long window', async () => {
        const { signer, address, publicKey } = newSigner()
        const a: EphemeralAdvertisement = {
            ephemeral_age_pubkey: AGE_PUBKEY,
            // Window one second over the cap.
            ephemeral_issued_at: NOW,
            ephemeral_expiry: NOW + MAX_EPHEMERAL_LIFETIME_SEC + 1,
        }
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(EphemeralLifetimeError)
    })

    it('accepts a window exactly at the cap', async () => {
        const { signer, address, publicKey } = newSigner()
        const a: EphemeralAdvertisement = {
            ephemeral_age_pubkey: AGE_PUBKEY,
            ephemeral_issued_at: NOW,
            ephemeral_expiry: NOW + MAX_EPHEMERAL_LIFETIME_SEC,
        }
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, NOW, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).not.toThrow()
    })

    it('rejects a future-dated issued_at (beyond skew)', async () => {
        const { signer, address, publicKey } = newSigner()
        const a = sampleAdvertisement()
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        // now sits more than skew before issued_at.
        const now = a.ephemeral_issued_at - 2 * DEFAULT_EPHEMERAL_SKEW_SEC
        expect(() =>
            verifyEphemeral(OPERATOR_ID, NODE_ID, a, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC),
        ).toThrow(/not yet valid/)
    })
})

describe('ephemeralStale (soft relay-attribution)', () => {
    it('is fresh within FRESHNESS_TARGET_SEC and stale past it', () => {
        const a = sampleAdvertisement()
        expect(ephemeralStale(a, a.ephemeral_issued_at + FRESHNESS_TARGET_SEC - 1)).toBe(false)
        expect(ephemeralStale(a, a.ephemeral_issued_at + FRESHNESS_TARGET_SEC + 1)).toBe(true)
    })
})

describe('ephemeralCanonicalBytes', () => {
    it('is deterministic for identical inputs', () => {
        const a = sampleAdvertisement()
        expect(ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, a)).toEqual(
            ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, a),
        )
    })

    it('does not depend on the signature', async () => {
        const { signer, address } = newSigner()
        const a = sampleAdvertisement()
        const before = ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, a)
        await signEphemeral(OPERATOR_ID, NODE_ID, a, signer, address)
        const after = ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, a)
        expect(after).toEqual(before)
    })

    it('starts with the ephemeral signing tag', () => {
        const bytes = ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, sampleAdvertisement())
        const expected = new TextEncoder().encode('zs-ephemeral-v1\x00')
        expect(bytes.subarray(0, expected.length)).toEqual(expected)
    })

    it('binds the operator id (different id → different bytes)', () => {
        const a = sampleAdvertisement()
        expect(ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, a)).not.toEqual(
            ephemeralCanonicalBytes(OPERATOR_ID + 1, NODE_ID, a),
        )
    })

    it('binds the node id (different node → different bytes)', () => {
        const a = sampleAdvertisement()
        expect(ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID, a)).not.toEqual(
            ephemeralCanonicalBytes(OPERATOR_ID, NODE_ID + 1, a),
        )
    })
})
