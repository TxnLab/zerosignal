/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A transaction's signature through the host's custody. Mirrors
// proto/go/solana/sign.go, pinned by solana_tx_vectors.json and
// solana_sign_vectors.json.

import type { PublicKey } from './key.js'
import { MalformedMessageError, type Transaction, encodeMessage } from './message.js'
import { verifyStrict } from './verify.js'

/**
 * TransactionSigner is the custody seam for a Solana transaction signature,
 * as algosdk's TransactionSigner is for an Algorand one: the key stays with
 * the host (a wallet worker, a keystore), which signs whatever message it is
 * handed. A Solana signature is raw Ed25519 over the message bytes, the same
 * primitive BytesSigner exposes, but it is a separate method so a host can
 * route each to its own custody path and so neither framing is mistaken for
 * the other. An off-chain message signer that prefixes its input, or refuses
 * bytes that parse as a transaction, cannot implement it.
 *
 * It signs blindly. A message someone else built must pass its verifier
 * first, which zsescrow's complete functions do before they call it.
 */
export interface TransactionSigner {
    /** The 64-byte Ed25519 signature of message under address's key. address is base58. */
    signTransactionMessage(address: string, message: Uint8Array): Promise<Uint8Array>
}

/**
 * signTransactionWith has signer sign t's message as key and puts the
 * signature in key's slot among the message's signers, leaving the other
 * slots as they are. The signature must verify under key as the runtime
 * checks it, so a host that signs with another key (the payer's Algorand key,
 * say) fails here rather than on chain. A signer's own error is the cause of
 * the one thrown.
 */
export async function signTransactionWith(t: Transaction, key: PublicKey, signer: TransactionSigner): Promise<void> {
    // Encoded first, which sanitizes, so the header's signer count fits the keys.
    const msg = encodeMessage(t.message)
    const n = t.message.header.numRequiredSignatures
    if (t.signatures.length !== n) throw new MalformedMessageError(`${t.signatures.length} signatures for ${n} signers`)
    const i = t.message.accountKeys.slice(0, n).indexOf(key)
    if (i < 0) throw new Error(`solana: ${key} is not a signer of this message`)
    let sig: Uint8Array
    try {
        sig = await signer.signTransactionMessage(key, msg)
    } catch (err) {
        throw new Error(`solana: sign as ${key}: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    if (!(sig instanceof Uint8Array)) throw new Error(`solana: signer returned a non-Uint8Array for ${key}, want a 64-byte signature`)
    if (sig.length !== 64) throw new Error(`solana: signer returned ${sig.length} bytes for ${key}, want a 64-byte signature`)
    if (!verifyStrict(key, msg, sig)) throw new Error(`solana: signer's signature does not verify under ${key}`)
    t.signatures[i] = sig.slice()
}
