/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The program's account decoders. Mirrors proto/go/solana/zsescrow/accounts.go,
// pinned by solana_account_vectors.json. None checks the account's owner,
// which is not in the data: a caller must check the owner is the program (the
// token program for a TokenAccount) before it trusts anything decoded here.

import { equalBytes } from '../../util/bytes.js'
import { type Hash, type PublicKey, encodeBase58 } from '../key.js'
import { DecodeError, Reader, decodeUtf8 } from './borsh.js'
import { ACCOUNT_VERSION, BASE_URL_MAX, discriminator } from './program.js'

export class DiscriminatorError extends Error {
    constructor(want: string) {
        super(`zsescrow: not this account type: want ${want}`)
        this.name = 'DiscriminatorError'
    }
}

/** An account a later program wrote: its reserve bytes may hold fields this decoder can't see, so it refuses rather than guesses. */
export class AccountVersionError extends Error {
    constructor(name: string, v: number) {
        super(`zsescrow: unknown account version: ${name} version ${v}`)
        this.name = 'AccountVersionError'
    }
}

export const CONFIG_SIZE = 349
export const OPERATOR_SIZE = 171
export const NODE_SIZE = 880
export const TICKET_SIZE = 233
export const SIGNER_INDEX_SIZE = 58
export const REFUND_OWED_SIZE = 98
export const TOKEN_ACCOUNT_SIZE = 165

export const OUTPUT_UNITS_LEN = 8
export const RING_DAYS = 30

/** The only status a node is created with. */
export const NODE_ACTIVE = 1

function accountReader(name: string, data: Uint8Array, size: number): Reader {
    if (data.length < 8 || !equalBytes(data.subarray(0, 8), discriminator('account', name))) throw new DiscriminatorError(name)
    if (data.length < size) throw new DecodeError(`${name} of ${data.length} bytes, want ${size}`)
    if (data[8] !== ACCOUNT_VERSION) throw new AccountVersionError(name, data[8]!)
    return new Reader(data, 8)
}

export interface Config {
    version: number
    bump: number
    stakeVaultBump: number
    owedVaultBump: number
    usdcDecimals: number
    pauseOpen: boolean
    pauseRegistry: boolean
    feeBps: number
    maxGrace: number
    defaultGrace: number
    maxTicketLifetime: bigint
    operatorStake: bigint
    nodeStake: bigint
    nextOperatorId: bigint
    admin: PublicKey
    arbiter: PublicKey
    usdcMint: PublicKey
    treasury: PublicKey
    genesisHash: Hash
    pendingAdmin: PublicKey
    minGrace: number
    pendingArbiter: PublicKey
    reserve: Uint8Array
}

export function decodeConfig(data: Uint8Array): Config {
    const r = accountReader('Config', data, CONFIG_SIZE)
    return {
        version: r.u8(),
        bump: r.u8(),
        stakeVaultBump: r.u8(),
        owedVaultBump: r.u8(),
        usdcDecimals: r.u8(),
        pauseOpen: r.bool(),
        pauseRegistry: r.bool(),
        feeBps: r.u16(),
        maxGrace: r.u32(),
        defaultGrace: r.u32(),
        maxTicketLifetime: r.i64(),
        operatorStake: r.u64(),
        nodeStake: r.u64(),
        nextOperatorId: r.u64(),
        admin: r.key(),
        arbiter: r.key(),
        usdcMint: r.key(),
        treasury: r.key(),
        genesisHash: encodeBase58(r.array(32)),
        pendingAdmin: r.key(),
        minGrace: r.u32(),
        pendingArbiter: r.key(),
        reserve: r.array(64),
    }
}

/** Variant names; an unknown byte reads as `OperatorStatus(n)`, never as Active. */
export function operatorStatusName(s: number): string {
    return ['Active', 'Evicted'][s] ?? `OperatorStatus(${s})`
}
export const OPERATOR_STATUS_ACTIVE = 0
export const OPERATOR_STATUS_EVICTED = 1

export interface Operator {
    version: number
    status: number
    bump: number
    id: bigint
    nextNodeId: bigint
    liveNodeCount: bigint
    stake: bigint
    owner: PublicKey
    nameRef: PublicKey
    reserve: Uint8Array
}

export function decodeOperator(data: Uint8Array): Operator {
    const r = accountReader('Operator', data, OPERATOR_SIZE)
    return {
        version: r.u8(),
        status: r.u8(),
        bump: r.u8(),
        id: r.u64(),
        nextNodeId: r.u64(),
        liveNodeCount: r.u64(),
        stake: r.u64(),
        owner: r.key(),
        nameRef: r.key(),
        reserve: r.array(64),
    }
}

/** Zero-copy on chain: its fields sit at fixed offsets with no padding, the same bytes a sequential read gives. */
export interface Node {
    version: number
    status: number
    staging: number
    bump: number
    vaultBump: number
    baseUrlLen: number
    pad0: Uint8Array
    signing: PublicKey
    vault: PublicKey
    operator: PublicKey
    baseUrl: string
    operatorId: bigint
    nodeId: bigint
    stake: bigint
    accruedPayout: bigint
    accruedFee: bigint
    liveTickets: bigint
    opensTotal: bigint
    // The metrics are the Algorand NodeRecord's, folded by the same rules.
    lastActivityAt: bigint
    settledCount: bigint
    lapsedCount: bigint
    refundedCount: bigint
    refundedTotal: bigint
    latencyTotalMs: bigint
    latencySamples: bigint
    ttftEwmaMs: bigint
    decodeTpsEwma: bigint
    revenueTotal: bigint
    inputUnitsTotal: bigint
    outputUnits: bigint[]
    ringDay: bigint
    ringRevenue: bigint[]
    protestedCount: bigint
    protestedTotal: bigint
    reserve: Uint8Array
}

export function decodeNode(data: Uint8Array): Node {
    const r = accountReader('Node', data, NODE_SIZE)
    const head = { version: r.u8(), status: r.u8(), staging: r.u8(), bump: r.u8(), vaultBump: r.u8(), baseUrlLen: r.u8(), pad0: r.array(2) }
    const keys = { signing: r.key(), vault: r.key(), operator: r.key() }
    const url = r.take(BASE_URL_MAX)
    if (head.baseUrlLen > BASE_URL_MAX) throw new DecodeError(`base_url_len ${head.baseUrlLen}`)
    const baseUrl = decodeUtf8(url.subarray(0, head.baseUrlLen), 'base_url')
    const n = {
        ...head,
        ...keys,
        baseUrl,
        operatorId: r.u64(),
        nodeId: r.u64(),
        stake: r.u64(),
        accruedPayout: r.u64(),
        accruedFee: r.u64(),
        liveTickets: r.u64(),
        opensTotal: r.u64(),
        lastActivityAt: r.i64(),
        settledCount: r.u64(),
        lapsedCount: r.u64(),
        refundedCount: r.u64(),
        refundedTotal: r.u64(),
        latencyTotalMs: r.u64(),
        latencySamples: r.u64(),
        ttftEwmaMs: r.u64(),
        decodeTpsEwma: r.u64(),
        revenueTotal: r.u64(),
        inputUnitsTotal: r.u64(),
        outputUnits: Array.from({ length: OUTPUT_UNITS_LEN }, () => r.u64()),
        ringDay: r.i64(),
        ringRevenue: Array.from({ length: RING_DAYS }, () => r.u64()),
        protestedCount: r.u64(),
        protestedTotal: r.u64(),
        reserve: r.array(48),
    }
    return n
}

/** Variant names; an unknown byte reads as `TicketStatus(n)`. */
export function ticketStatusName(s: number): string {
    return ['Open', 'PendingByOperator', 'Frozen'][s] ?? `TicketStatus(${s})`
}
export const TICKET_OPEN = 0
/** The node filed a claim the payer has not acked. */
export const TICKET_PENDING_BY_OPERATOR = 1
/** The payer protested; only the arbiter ends it. */
export const TICKET_FROZEN = 2

export interface Ticket {
    version: number
    status: number
    bump: number
    feeBps: number
    grace: number
    openSeq: bigint
    maxPrice: bigint
    pendingAmount: bigint
    openedAt: bigint
    expiresAt: bigint
    payer: PublicKey
    node: PublicKey
    /** The node's key at open, which signs this ticket's receipt; a protest checks the receipt against it, not the current key. */
    nodeSigning: PublicKey
    rentPayer: PublicKey
    claimHash: Uint8Array
    reserve: Uint8Array
}

const I64_MAX = (1n << 63n) - 1n

/** The last moment a cooperative settle is accepted; settle_lapsed and refund_inactive open after it. */
export function ticketDeadline(t: Ticket): bigint {
    const d = t.expiresAt + BigInt(t.grace)
    return d > I64_MAX ? I64_MAX : d
}

export function decodeTicket(data: Uint8Array): Ticket {
    const r = accountReader('Ticket', data, TICKET_SIZE)
    return {
        version: r.u8(),
        status: r.u8(),
        bump: r.u8(),
        feeBps: r.u16(),
        grace: r.u32(),
        openSeq: r.u64(),
        maxPrice: r.u64(),
        pendingAmount: r.u64(),
        openedAt: r.i64(),
        expiresAt: r.i64(),
        payer: r.key(),
        node: r.key(),
        nodeSigning: r.key(),
        rentPayer: r.key(),
        claimHash: r.array(32),
        reserve: r.array(16),
    }
}

export interface SignerIndex {
    version: number
    bump: number
    node: PublicKey
    reserve: Uint8Array
}

export function decodeSignerIndex(data: Uint8Array): SignerIndex {
    const r = accountReader('SignerIndex', data, SIGNER_INDEX_SIZE)
    return { version: r.u8(), bump: r.u8(), node: r.key(), reserve: r.array(16) }
}

export interface RefundOwed {
    version: number
    bump: number
    amount: bigint
    payer: PublicKey
    rentPayer: PublicKey
    reserve: Uint8Array
}

export function decodeRefundOwed(data: Uint8Array): RefundOwed {
    const r = accountReader('RefundOwed', data, REFUND_OWED_SIZE)
    return { version: r.u8(), bump: r.u8(), amount: r.u64(), payer: r.key(), rentPayer: r.key(), reserve: r.array(16) }
}

export function tokenAccountStateName(s: number): string {
    return ['Uninitialized', 'Initialized', 'Frozen'][s] ?? `TokenAccountState(${s})`
}
export const TOKEN_UNINITIALIZED = 0
export const TOKEN_INITIALIZED = 1
export const TOKEN_FROZEN = 2

/** An SPL token account: a vault, or an owner's USDC account. */
export interface TokenAccount {
    mint: PublicKey
    owner: PublicKey
    amount: bigint
    delegate: PublicKey | null
    state: number
    isNative: bigint | null
    delegatedAmount: bigint
    closeAuthority: PublicKey | null
}

/** The token program's COption: a u32 tag, then the value, which is present (zeroed) even when the tag is 0. */
function cOption<T>(r: Reader, get: () => T): T | null {
    const tag = r.u32()
    const v = get()
    if (tag === 1) return v
    if (tag !== 0) throw new DecodeError(`COption tag ${tag}`)
    return null
}

export function decodeTokenAccount(data: Uint8Array): TokenAccount {
    if (data.length !== TOKEN_ACCOUNT_SIZE) throw new DecodeError(`token account of ${data.length} bytes`)
    const r = new Reader(data)
    return {
        mint: r.key(),
        owner: r.key(),
        amount: r.u64(),
        delegate: cOption(r, () => r.key()),
        state: r.u8(),
        isNative: cOption(r, () => r.u64()),
        delegatedAmount: r.u64(),
        closeAuthority: cOption(r, () => r.key()),
    }
}
