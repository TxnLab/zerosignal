/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The zs_escrow Solana program, the mirror of proto/go/solana/zsescrow: its
// addresses, its instructions, its accounts and its events. Builders derive
// every program address from the ids the caller names, so a caller never
// passes an address the program would refuse.

export * from './program.js'
export * from './instructions.js'
export * from './accounts.js'
export * from './events.js'
export * from './offer.js'
export * from './ack.js'
export { DecodeError } from './borsh.js'
