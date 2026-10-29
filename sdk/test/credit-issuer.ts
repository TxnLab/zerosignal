/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A free credit issuer for tests, Go's fakeIssuer in free_credits_test.go. It
// signs through node:crypto, as an issuer in TS would: the raw RSA private
// operation over a blinded message is RFC 9474's BlindSign.

import { type KeyObject, constants, generateKeyPairSync, privateDecrypt, sign } from 'node:crypto'

import { type DayKeyCert, dayKeyCertMessage } from '@txnlab/zs-proto/freecredit'
import { base64 } from '@scure/base'

import type { CreditIssuer, CreditsExhaustedError } from '../src/solana/credits.js'

export const creditDep = Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 0xc0 : i))

/** The middle of a UTC day, well clear of the grace either side. */
export const noon = Date.UTC(2026, 9, 27, 12)

export class FakeIssuer implements CreditIssuer {
    readonly master = generateKeyPairSync('ed25519')
    readonly signers = new Map<number, { key: KeyObject; cert: DayKeyCert }>()
    dayKeys = 0
    issues = 0
    /** Fails every call. */
    err: Error | undefined
    /** Answers credits_exhausted. */
    exhausted: CreditsExhaustedError | undefined
    /** Signs only the first n messages when set. */
    signOnly = 0
    /** Replaces the certificate served. */
    certFor: ((c: DayKeyCert) => DayKeyCert) | undefined
    /** Signs with this day key instead. */
    signWith: KeyObject | undefined
    /** Holds issue until it resolves. */
    gate: Promise<void> | undefined

    /** The issuer's key, standard base64, as presets and details spell it. */
    get key(): string {
        return base64.encode(this.publicKey)
    }

    get publicKey(): Uint8Array {
        const x = this.master.publicKey.export({ format: 'jwk' }).x!
        return base64.decode(x.replace(/-/g, '+').replace(/_/g, '/') + '=')
    }

    signer(epoch: number): { key: KeyObject; cert: DayKeyCert } {
        let s = this.signers.get(epoch)
        if (s === undefined) {
            const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 })
            const spki = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }))
            const sig = sign(null, dayKeyCertMessage(creditDep, epoch, spki), this.master.privateKey)
            s = {
                key: privateKey,
                cert: {
                    issuer: this.key,
                    epoch,
                    day_key: base64.encode(spki),
                    day_key_sig: base64.encode(new Uint8Array(sig)),
                },
            }
            this.signers.set(epoch, s)
        }
        return s
    }

    async dayKey(_dep: Uint8Array, epoch: number): Promise<DayKeyCert> {
        this.dayKeys++
        if (this.err) throw this.err
        const cert = this.signer(epoch).cert
        return this.certFor ? this.certFor(cert) : cert
    }

    async issue(_dep: Uint8Array, epoch: number, blinded: Uint8Array[], signal?: AbortSignal): Promise<Uint8Array[]> {
        if (this.gate) {
            await new Promise<void>((resolve, reject) => {
                if (signal?.aborted) return reject(signal.reason)
                void this.gate!.then(resolve)
                signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
            })
        }
        this.issues++
        if (this.err) throw this.err
        if (this.exhausted) throw this.exhausted
        const key = this.signWith ?? this.signer(epoch).key
        const n = this.signOnly > 0 ? Math.min(blinded.length, this.signOnly) : blinded.length
        return blinded
            .slice(0, n)
            .map((b) => new Uint8Array(privateDecrypt({ key, padding: constants.RSA_NO_PADDING }, b)))
    }
}
