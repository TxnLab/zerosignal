/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The runtime's signature check. Mirrors proto/go/solana/verify.go, pinned by
// the signatures section of solana_codec_vectors.json.

import { sha512 } from '@noble/hashes/sha2.js'

import { concatBytes, equalBytes } from '../util/bytes.js'
import { ed25519 } from '../util/ed25519.js'
import { type PublicKey, publicKeyBytes } from './key.js'

const L = ed25519.CURVE.n

function numberLE(b: Uint8Array): bigint {
    let v = 0n
    for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!)
    return v
}

/**
 * verifyStrict is curve25519-dalek's verify_strict, which the runtime uses: S
 * must be canonical, neither the key nor R may be of small order, and the
 * equation is cofactorless, R = [S]B - [k]A compared as encoded bytes, so a
 * non-canonical R fails too. @noble's own verify is cofactored and accepts
 * small-order points; a payer that accepts a signature the runtime refuses
 * believes a transaction will land that never can.
 */
export function verifyStrict(key: PublicKey, msg: Uint8Array, sig: Uint8Array): boolean {
    if (sig.length !== 64) return false
    const keyBytes = publicKeyBytes(key)
    const rBytes = sig.subarray(0, 32)
    let A: InstanceType<typeof ed25519.ExtendedPoint>
    let R: InstanceType<typeof ed25519.ExtendedPoint>
    try {
        A = ed25519.ExtendedPoint.fromHex(keyBytes, true)
        R = ed25519.ExtendedPoint.fromHex(rBytes, true)
    } catch {
        return false
    }
    if (A.isSmallOrder() || R.isSmallOrder()) return false
    const s = numberLE(sig.subarray(32))
    if (s >= L) return false
    const k = numberLE(sha512(concatBytes(rBytes, keyBytes, msg))) % L
    const got = ed25519.ExtendedPoint.BASE.mul(s, false).add(A.negate().mul(k, false))
    return equalBytes(got.toRawBytes(), rBytes)
}
