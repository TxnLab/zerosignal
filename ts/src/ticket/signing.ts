/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Signing seam + Algorand address codec. Mirrors
// proto/go/ticket/signing.go.
//
// BytesSigner produces a raw Ed25519 signature over msg under the key
// identified by an Algorand address. Implementations MUST sign msg
// verbatim — no domain prefix, no hashing — because signTicket /
// signReceipt hand the signer a precomputed sha256 digest of a
// domain-tagged canonical body.
//
// Note this is NOT compatible with go-algorand-sdk's crypto.SignBytes
// (which prepends "MX" to the raw message). Hayai signatures are raw
// Ed25519 over a 32-byte sha256 digest; the signer must expose a raw
// Ed25519 sign operation, or accept the precomputed digest without
// further framing. A wallet whose sign-bytes / sign-data flow tags or
// prefixes the message (MX, ARC-60 domains) therefore cannot implement
// BytesSigner, however the digest is handed to it.
//
// inMemoryEd25519Signer below is the one reference signer, for tests,
// bootstrap, and any caller that holds raw key material.

import { sha512_256 } from '@noble/hashes/sha2.js'
import { base32nopad } from '@scure/base'

import { ed25519 } from '../util/ed25519.js'
import { constantTimeEqual } from '../util/bytes.js'

export interface BytesSigner {
    signBytes(address: string, msg: Uint8Array): Promise<Uint8Array>
}

const ALGO_PUBKEY_SIZE = 32
const ALGO_CHECKSUM_SIZE = 4
const ALGO_ADDRESS_RAW_LEN = ALGO_PUBKEY_SIZE + ALGO_CHECKSUM_SIZE // 36
const ALGO_ADDRESS_LEN = 58 // ceil(36*8/5) with no padding

// algorandChecksum returns the last 4 bytes of SHA-512/256(pub) — the
// checksum Algorand embeds in addresses.
function algorandChecksum(pub: Uint8Array): Uint8Array {
    const h = sha512_256(pub)
    return h.subarray(h.length - ALGO_CHECKSUM_SIZE)
}

// decodeAlgorandAddress decodes a 58-character Algorand address into
// its underlying Ed25519 public key, validating the checksum. The
// verifier callers use for verifyTicket / verifyReceipt: the registry
// publishes only the address; the pubkey is recovered on demand.
export function decodeAlgorandAddress(addr: string): Uint8Array {
    if (addr.length !== ALGO_ADDRESS_LEN) {
        throw new Error(`algorand address length ${addr.length}, want ${ALGO_ADDRESS_LEN}`)
    }
    let raw: Uint8Array
    try {
        raw = base32nopad.decode(addr)
    } catch (err) {
        throw new Error(`decode base32 address: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (raw.length !== ALGO_ADDRESS_RAW_LEN) {
        throw new Error(`decoded address ${raw.length} bytes, want ${ALGO_ADDRESS_RAW_LEN}`)
    }
    const pub = raw.subarray(0, ALGO_PUBKEY_SIZE)
    const gotChk = raw.subarray(ALGO_PUBKEY_SIZE)
    const wantChk = algorandChecksum(pub)
    if (!constantTimeEqual(gotChk, wantChk)) {
        throw new Error('algorand address checksum mismatch')
    }
    return new Uint8Array(pub)
}

// encodeAlgorandAddress is the inverse of decodeAlgorandAddress.
// Primarily for tests and tooling that derives an address from a
// generated keypair.
export function encodeAlgorandAddress(pub: Uint8Array): string {
    if (pub.length !== ALGO_PUBKEY_SIZE) return ''
    const raw = new Uint8Array(ALGO_ADDRESS_RAW_LEN)
    raw.set(pub, 0)
    raw.set(algorandChecksum(pub), ALGO_PUBKEY_SIZE)
    return base32nopad.encode(raw)
}

export interface AlgorandKeypair {
    address: string
    publicKey: Uint8Array
    privateKey: Uint8Array // 32-byte ed25519 seed; pair with publicKey to sign
}

// generateAlgorandKeypair returns a fresh ed25519 keypair and the
// pre-encoded Algorand address for it. The "private key" here is the
// 32-byte seed (the form @noble/ed25519 wants for sign).
export function generateAlgorandKeypair(): AlgorandKeypair {
    const privateKey = ed25519.utils.randomPrivateKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    return {
        address: encodeAlgorandAddress(publicKey),
        publicKey,
        privateKey,
    }
}

// inMemoryEd25519Signer returns a BytesSigner backed by an
// {address: priv-seed} table. Suitable for tests, bootstrap scripts,
// or any caller that already holds raw key material. Production
// browser callers should implement BytesSigner against their wallet
// instead.
export function inMemoryEd25519Signer(keys: Map<string, Uint8Array>): BytesSigner {
    return {
        async signBytes(address: string, msg: Uint8Array): Promise<Uint8Array> {
            const priv = keys.get(address)
            if (!priv) throw new Error(`address not in in-memory signer: ${address}`)
            return ed25519.sign(msg, priv)
        },
    }
}
