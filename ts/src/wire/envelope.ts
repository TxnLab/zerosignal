/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Wire-shaped types. Property names use snake_case so JSON.stringify
// produces the exact bytes the Go side emits. See SPEC.md §5 for the
// authoritative envelope spec.

// RequestEnvelope is the JSON body the proxy (or browser playing the
// proxy role) sends to the node. Since protocol 8.0 it carries nothing
// but ciphertext: algorand_tx_id, ticket_id, admission_tag, and
// reply_to_public_key ride inside the age-sealed inner-request frame
// (inner.ts), where a forwarding relay cannot read them.
export interface RequestEnvelope {
    ciphertext: string
}

// ResponseEnvelope is the JSON body the node returns for non-streaming
// encrypted responses. The node also sets the X-Zs-Response-Key
// header so the proxy can recover the symmetric key used to seal
// ciphertext.
//
// algorand_tx_id is not echoed here — both sides reconstruct the body AAD
// from state they already hold, so the echo only handed a relay the
// identifier that resolves to the payer on chain.
export interface ResponseEnvelope {
    nonce: string
    ciphertext: string
}
