/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Ephemeral X25519 identity helpers. The proxy (or browser playing the
// proxy role) generates a fresh identity per request, places its
// recipient in RequestEnvelope.reply_to_public_key, and uses the secret
// to unwrap the X-Zs-Response-Key header and the
// reserve-time wrapped_response_key.
//
// We hold both halves as the bech32 strings typage exposes
// (AGE-SECRET-KEY-1... / age1...). JS strings are immutable so we
// cannot reliably wipe these from memory the way the Go side does
// with reflect+unsafe — see README.md "Secret-key lifetime".

import * as age from 'age-encryption'

export interface EphemeralIdentity {
    // AGE-SECRET-KEY-1... — keep secret; treat as ephemeral, do not
    // persist. Used to age-decrypt the wrapped response key.
    secret: string
    // age1... — placed in RequestEnvelope.reply_to_public_key so the
    // node knows whom to wrap K_response to.
    recipient: string
}

export async function generateEphemeralIdentity(): Promise<EphemeralIdentity> {
    const secret = await age.generateIdentity()
    const recipient = await age.identityToRecipient(secret)
    return { secret, recipient }
}
