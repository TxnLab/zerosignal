/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Deployment id — names one escrow deployment (rail, network genesis hash,
// escrow id). Mirrors proto/go/ticket/deployment.go; the reasoning lives there.
//
// On the wire it is base64 of 32 bytes, and an unbound object omits the field.
// In memory the TS twin keeps it as that string (like ticket_id / commit_k) and
// decodes it where the canonical bytes need the raw bytes.

import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'

import { CanonicalWriter } from '../util/canonical.js'

export const RAIL_ALGORAND = 1
export const RAIL_SOLANA = 2

const DEPLOYMENT_TAG = 'zs-deployment-v1\x00'

/** DeploymentMismatchError: the object names a deployment other than the verifier's. Go: ErrDeploymentMismatch. */
export class DeploymentMismatchError extends Error {
    constructor(what: string) {
        super(`${what}: signed for a different deployment`)
        this.name = 'DeploymentMismatchError'
    }
}

/** LegacySignatureError: the object is unbound and the verifier requires a binding. Go: ErrLegacySignature. */
export class LegacySignatureError extends Error {
    constructor(what: string) {
        super(`${what}: signature is not deployment-bound`)
        this.name = 'LegacySignatureError'
    }
}

/**
 * newDeploymentId returns
 * sha256("zs-deployment-v1\x00" ‖ u8(rail) ‖ genesis_hash[32] ‖ u32be(len(escrow)) ‖ escrow).
 */
export function newDeploymentId(rail: number, genesisHash: Uint8Array, escrow: Uint8Array): Uint8Array {
    if (rail !== RAIL_ALGORAND && rail !== RAIL_SOLANA) throw new Error(`deployment id: unknown rail ${rail}`)
    if (genesisHash.length !== 32) {
        throw new Error(`deployment id: genesis hash is ${genesisHash.length} bytes, want 32`)
    }
    if (escrow.length === 0) throw new Error('deployment id: escrow id is empty')
    const len = new Uint8Array(4)
    new DataView(len.buffer).setUint32(0, escrow.length)
    return sha256(
        new CanonicalWriter().str(DEPLOYMENT_TAG).u8(rail).bytes(genesisHash).bytes(len).bytes(escrow).finish(),
    )
}

/** algorandDeploymentId: the escrow input is the app id as 8 big-endian bytes. */
export function algorandDeploymentId(genesisHash: Uint8Array, appId: number | bigint): Uint8Array {
    if (BigInt(appId) === 0n) throw new Error('deployment id: app id is 0')
    const escrow = new CanonicalWriter().u64(appId).finish()
    return newDeploymentId(RAIL_ALGORAND, genesisHash, escrow)
}

/** solanaDeploymentId: the escrow input is the 32-byte program id. */
export function solanaDeploymentId(genesisHash: Uint8Array, programId: Uint8Array): Uint8Array {
    if (programId.length !== 32) throw new Error(`deployment id: program id is ${programId.length} bytes, want 32`)
    return newDeploymentId(RAIL_SOLANA, genesisHash, programId)
}

/**
 * knownDeployment is d as a payer's own id: undefined when absent or all zero,
 * as Go's zero DeploymentID means unknown. A zero id named on the wire would
 * be refused as malformed. Any length but 32 is a caller bug Go's type rules
 * out, so it throws.
 */
export function knownDeployment(d: Uint8Array | undefined): Uint8Array | undefined {
    if (d === undefined) return undefined
    if (d.length !== 32) throw new Error(`deployment id is ${d.length} bytes, want 32`)
    return d.every((b) => b === 0) ? undefined : d
}

/** encodeDeploymentId is the wire form. */
export function encodeDeploymentId(d: Uint8Array): string {
    return base64.encode(d)
}

/**
 * decodeDeploymentId reads the wire form, refusing anything but 32 bytes and
 * the all-zero id, as Go's UnmarshalText does: on the wire the zero id is
 * spelled by omitting the field.
 */
export function decodeDeploymentId(s: string): Uint8Array {
    let raw: Uint8Array
    try {
        raw = base64.decode(s)
    } catch (err) {
        throw new Error(`decode deployment id: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (raw.length !== 32) throw new Error(`deployment id is ${raw.length} bytes, want 32`)
    if (raw.every((b) => b === 0)) throw new Error('deployment id is all zero')
    return raw
}

/**
 * checkDeployment is the shared verifier rule (Go's checkDeployment): a bound
 * object must name want; an unbound one passes only when allowLegacy.
 */
export function checkDeployment(
    what: string,
    got: string | undefined,
    want: Uint8Array | undefined,
    allowLegacy: boolean,
): void {
    if (!got) {
        if (!allowLegacy) throw new LegacySignatureError(what)
        return
    }
    const g = decodeDeploymentId(got)
    if (!want || want.length !== 32 || !g.every((b, i) => b === want[i])) throw new DeploymentMismatchError(what)
}
