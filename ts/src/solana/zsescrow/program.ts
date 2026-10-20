/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The zs_escrow program's addresses. Mirrors proto/go/solana/zsescrow/program.go,
// pinned by the PDAs in solana_account_vectors.json and the accounts of
// solana_instruction_vectors.json.

import { sha256 } from '@noble/hashes/sha2.js'

import { utf8 } from '../../util/bytes.js'
import { type PublicKey, publicKeyBytes } from '../key.js'
import { associatedTokenAddress, findProgramAddress } from '../pda.js'

/** The program on every cluster it is deployed to today. */
export const PROGRAM_ID: PublicKey = '2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1'

export const CONFIG_SEED = 'config'
export const OPERATOR_SEED = 'op'
export const NODE_SEED = 'node'
export const VAULT_SEED = 'vault'
export const STAKE_VAULT_SEED = 'stake'
export const OWED_VAULT_SEED = 'owed_vault'
export const REFUND_OWED_SEED = 'owed'
export const TICKET_SEED = 't'
export const EVENT_AUTHORITY_SEED = '__event_authority'

/** The version every account this program creates carries. */
export const ACCOUNT_VERSION = 1

/** The longest node URL the program stores. */
export const BASE_URL_MAX = 248

export function u64le(v: bigint): Uint8Array {
    if (v < 0n || v >= 1n << 64n) throw new RangeError(`zsescrow: ${v} is not a u64`)
    const out = new Uint8Array(8)
    new DataView(out.buffer).setBigUint64(0, v, true)
    return out
}

/** discriminator is Anchor's: the first 8 bytes of sha256 of a namespaced name. */
export function discriminator(namespace: string, name: string): Uint8Array {
    return sha256(utf8(`${namespace}:${name}`)).slice(0, 8)
}

/**
 * Bumps of the payer's token account and RefundOwed. A settle carries them so
 * the program derives each address once instead of searching, a search whose
 * length the payer could grind its key to stretch.
 */
export interface RefundBumps {
    payerAta: number
    refundOwed: number
}

/**
 * The addresses of one deployment of the program: its id and the USDC mint
 * its Config names. The mint is a parameter because a test cluster has its
 * own. Deployment (instructions.ts) adds the builders.
 */
export class Addresses {
    constructor(
        readonly program: PublicKey,
        readonly mint: PublicKey,
    ) {}

    private pda(...seeds: Uint8Array[]): [PublicKey, number] {
        return findProgramAddress(seeds, this.program)
    }

    config(): PublicKey {
        return this.pda(utf8(CONFIG_SEED))[0]
    }
    stakeVault(): PublicKey {
        return this.pda(utf8(STAKE_VAULT_SEED))[0]
    }
    owedVault(): PublicKey {
        return this.pda(utf8(OWED_VAULT_SEED))[0]
    }
    /** Signs the program's self-invocations that carry events. */
    eventAuthority(): PublicKey {
        return this.pda(utf8(EVENT_AUTHORITY_SEED))[0]
    }
    /** The operator with this id. Ids start at 1. */
    operator(id: bigint): PublicKey {
        return this.pda(utf8(OPERATOR_SEED), u64le(id))[0]
    }
    /** The operator's node with this id. Node ids start at 1 within each operator and are never reused. */
    node(operatorId: bigint, nodeId: bigint): PublicKey {
        return this.pda(utf8(NODE_SEED), u64le(operatorId), u64le(nodeId))[0]
    }
    /** The node's USDC token account, which holds its tickets' escrow and is its own authority. */
    vault(node: PublicKey): PublicKey {
        return this.pda(utf8(VAULT_SEED), publicKeyBytes(node))[0]
    }
    /** The node's ticket with this 16-byte wire ticket id. */
    ticket(node: PublicKey, ticketId: Uint8Array): PublicKey {
        if (ticketId.length !== 16) throw new RangeError(`zsescrow: a ticket id of ${ticketId.length} bytes`)
        return this.pda(utf8(TICKET_SEED), publicKeyBytes(node), ticketId)[0]
    }
    /** Holds what settles owe the payer but could not pay its token account. */
    refundOwed(payer: PublicKey): PublicKey {
        return this.pda(utf8(REFUND_OWED_SEED), publicKeyBytes(payer))[0]
    }
    /** owner's associated USDC account. */
    tokenAccount(owner: PublicKey): PublicKey {
        return associatedTokenAddress(owner, this.mint)[0]
    }
    refundBumps(payer: PublicKey): RefundBumps {
        return {
            payerAta: associatedTokenAddress(payer, this.mint)[1],
            refundOwed: this.pda(utf8(REFUND_OWED_SEED), publicKeyBytes(payer))[1],
        }
    }
}
