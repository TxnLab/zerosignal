/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { generateEphemeralIdentity } from '../src/wire/identity.js'
import {
    encodeAlgorandAddress,
    inMemoryEd25519Signer,
    type BytesSigner,
} from '../src/ticket/signing.js'
import { ed25519 } from '../src/util/ed25519.js'

export async function newTestNode(): Promise<{ secret: string; recipient: string }> {
    return generateEphemeralIdentity()
}

export function randomBytes(n: number): Uint8Array {
    const out = new Uint8Array(n)
    crypto.getRandomValues(out)
    return out
}

export function newFakeSigner(): {
    signer: BytesSigner
    address: string
    publicKey: Uint8Array
} {
    const priv = ed25519.utils.randomPrivateKey()
    const pub = ed25519.getPublicKey(priv)
    const address = encodeAlgorandAddress(pub)
    const signer = inMemoryEd25519Signer(new Map([[address, priv]]))
    return { signer, address, publicKey: pub }
}
