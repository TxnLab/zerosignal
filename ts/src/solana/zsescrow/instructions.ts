/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// One builder per program instruction. Mirrors
// proto/go/solana/zsescrow/instructions.go, pinned by
// solana_instruction_vectors.json. Each lists the accounts in the program's
// order (the IDL's); an optional account the caller leaves out is the program
// id, read-only, which is how Anchor reads None.

import { sha256 } from '@noble/hashes/sha2.js'

import { BPF_LOADER_UPGRADEABLE_PROGRAM_ID, SYSTEM_PROGRAM_ID, SYSVAR_INSTRUCTIONS_ID, TOKEN_PROGRAM_ID, type Hash, type PublicKey, decodeBase58, publicKeyBytes } from '../key.js'
import type { AccountMeta, Instruction } from '../message.js'
import { findProgramAddress } from '../pda.js'
import { utf8 } from '../../util/bytes.js'
import { Writer } from './borsh.js'
import { Addresses, discriminator, u64le } from './program.js'

const writable = (k: PublicKey): AccountMeta => ({ publicKey: k, isSigner: false, isWritable: true })
const readonly = (k: PublicKey): AccountMeta => ({ publicKey: k, isSigner: false, isWritable: false })
const signer = (k: PublicKey): AccountMeta => ({ publicKey: k, isSigner: true, isWritable: false })
const payer = (k: PublicKey): AccountMeta => ({ publicKey: k, isSigner: true, isWritable: true })

/** The terms initialize sets. */
export interface InitializeArgs {
    genesisHash: Hash
    feeBps: number
    maxGrace: number
    defaultGrace: number
    minGrace: number
    maxTicketLifetime: bigint
    operatorStake: bigint
    nodeStake: bigint
}

/**
 * Changes the fields that are set and leaves the rest. paused stops open and
 * every registry write, as Algorand's paused does; settles, unregisters and
 * the admin's levers run through a pause.
 */
export interface SetConfigArgs {
    paused?: boolean | null
    feeBps?: number | null
    maxGrace?: number | null
    defaultGrace?: number | null
    minGrace?: number | null
    maxTicketLifetime?: bigint | null
    operatorStake?: bigint | null
    nodeStake?: bigint | null
    treasury?: PublicKey | null
}

/**
 * Refuses a treasury of the default key: the program accepts it, and nobody
 * can sign for its token accounts, so every later fee and slash would be lost.
 */
export class ZeroTreasuryError extends Error {
    constructor() {
        super('zsescrow: the treasury is the default key')
        this.name = 'ZeroTreasuryError'
    }
}

/** What the node's open instruction commits to. grace 0 takes the Config's default, the only grace a payer's verifier accepts. */
export interface OpenArgs {
    ticketId: Uint8Array
    payer: PublicKey
    maxPrice: bigint
    expiresAt: bigint
    grace: number
}

/** What a node claims for a ticket; the payer's ack signs their hash. */
export interface ClaimFields {
    amount: bigint
    receiptDigest: Uint8Array
    ttftMs: bigint
    decodeMs: bigint
    inputUnits: bigint
    outputUnits: bigint
    outputUsageType: number
    auxUsageType: number
    auxCount: bigint
}

function putClaim(w: Writer, f: ClaimFields): void {
    w.u64(f.amount)
    w.fixed(f.receiptDigest, 32)
    w.u64(f.ttftMs)
    w.u64(f.decodeMs)
    w.u64(f.inputUnits)
    w.u64(f.outputUnits)
    w.u8(f.outputUsageType)
    w.u8(f.auxUsageType)
    w.u64(f.auxCount)
}

// The domain tags of the claim hash and the payer's ack digest, the program's
// CLAIM_TAG and ACK_TAG.
const CLAIM_TAG = utf8('zs-claim-v3\0')
const ACK_TAG = utf8('zs-settle-ack-v3\0')

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
    let at = 0
    for (const p of parts) {
        out.set(p, at)
        at += p.length
    }
    return out
}

/** The hash a ticket stores for the first half's fields, and the one the other half and settle_lapsed must match. */
export function claimHash(f: ClaimFields): Uint8Array {
    const w = new Writer()
    putClaim(w, f)
    return sha256(concat(CLAIM_TAG, w.done()))
}

/**
 * How a settle passes the treasury's USDC account, which takes the refund
 * only when the payer's token account can't (closed, never created, or
 * frozen): the refund is forfeited there, as Algorand's payOrForfeit forfeits
 * it. 'none' leaves it out (the common settle); 'readonly' may always be
 * passed, and the program refuses with TreasuryAccountNotWritable if it needs
 * it; 'writable' is for a payer whose token account can't take the refund,
 * and only then, since the account is one for the whole protocol and a write
 * lock on it in every settle would serialize them all.
 */
export type RefundFallback = 'none' | 'readonly' | 'writable'

/** Names the ticket a settle ends and who submits it. */
export interface Ending {
    /**
     * Signs: the node's current signing key for claim (and for a
     * settleCooperative of an open ticket), the payer for ack, the admin for
     * resolveFrozen, anyone for settleLapsed and refundInactive.
     */
    submitter: PublicKey
    operatorId: bigint
    nodeId: bigint
    ticketId: Uint8Array
    /** Funded the ticket and gets its rent back: the ticket's rent_payer. */
    rentPayer: PublicKey
    /** The ticket's payer, whose token account takes the refund. */
    payer: PublicKey
    /**
     * The Config's treasury, read only when fallback passes its USDC account;
     * set_config can move it, so it comes from the Config, not a constant.
     * Absent there, it names the default key's account, which the program
     * refuses as the forfeit's destination.
     */
    treasury?: PublicKey
    fallback?: RefundFallback
}

/** A deployment's addresses and the builders of its instructions. */
export class Deployment extends Addresses {
    private ix(name: string, data: Uint8Array, ...accounts: AccountMeta[]): Instruction {
        const disc = discriminator('global', name)
        const out = new Uint8Array(8 + data.length)
        out.set(disc)
        out.set(data, 8)
        return { programId: this.program, accounts, data: out }
    }

    private optional(k: PublicKey | null | undefined): AccountMeta {
        return readonly(k ?? this.program)
    }

    private eventCpi(): AccountMeta[] {
        return [readonly(this.eventAuthority()), readonly(this.program)]
    }

    private programData(): PublicKey {
        return findProgramAddress([publicKeyBytes(this.program)], BPF_LOADER_UPGRADEABLE_PROGRAM_ID)[0]
    }

    /**
     * Must be signed by the program's upgrade authority, which becomes the admin. The treasury's USDC account must
     * already exist, unfrozen: the program refuses a treasury that couldn't take a fee (TreasuryCannotReceive).
     */
    initialize(admin: PublicKey, treasury: PublicKey, a: InitializeArgs): Instruction {
        const w = new Writer()
        w.fixed(decodeBase58(a.genesisHash, 32), 32)
        w.u16(a.feeBps)
        w.u32(a.maxGrace)
        w.u32(a.defaultGrace)
        w.u32(a.minGrace)
        w.i64(a.maxTicketLifetime)
        w.u64(a.operatorStake)
        w.u64(a.nodeStake)
        const d = this
        return this.ix(
            'initialize',
            w.done(),
            payer(admin),
            readonly(this.programData()),
            writable(d.config()),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(treasury),
            readonly(d.tokenAccount(treasury)),
            readonly(TOKEN_PROGRAM_ID),
            readonly(SYSTEM_PROGRAM_ID),
        )
    }

    /**
     * Passes the new treasury as an account too, so the program can check it is not one of its own, and the
     * treasury's USDC account, which the program requires to exist unfrozen, as Algorand's setTreasury does.
     */
    setConfig(admin: PublicKey, a: SetConfigArgs): Instruction {
        if (a.treasury === SYSTEM_PROGRAM_ID) throw new ZeroTreasuryError()
        const w = new Writer()
        w.option(a.paused, (v) => w.bool(v))
        w.option(a.feeBps, (v) => w.u16(v))
        w.option(a.maxGrace, (v) => w.u32(v))
        w.option(a.defaultGrace, (v) => w.u32(v))
        w.option(a.minGrace, (v) => w.u32(v))
        w.option(a.maxTicketLifetime, (v) => w.i64(v))
        w.option(a.operatorStake, (v) => w.u64(v))
        w.option(a.nodeStake, (v) => w.u64(v))
        w.option(a.treasury, (v) => w.key(v))
        const treasuryUsdc = a.treasury == null ? null : this.tokenAccount(a.treasury)
        return this.ix('set_config', w.done(), signer(admin), writable(this.config()), this.optional(a.treasury), this.optional(treasuryUsdc))
    }

    proposeAdmin(admin: PublicKey, next: PublicKey): Instruction {
        const w = new Writer()
        w.key(next)
        return this.ix('propose_admin', w.done(), signer(admin), writable(this.config()))
    }

    acceptAdmin(next: PublicKey): Instruction {
        return this.ix('accept_admin', new Uint8Array(), signer(next), writable(this.config()))
    }

    // The program takes any USDC account the owner (or the treasury) holds
    // where it pays a stake in or out, so a frozen or closed associated
    // account can't block a registration, an unregister or an eviction. Those
    // builders take the account; tokenAccount(owner) is the usual one.
    // Payouts, fee sweeps, refunds and forfeited refunds go only to the
    // associated account, which their builders derive.

    /** Registers the owner as operator nextOperatorId, the Config's next_operator_id, and escrows the operator stake from ownerUsdc. */
    createOperator(owner: PublicKey, ownerUsdc: PublicKey, nextOperatorId: bigint): Instruction {
        const d = this
        return this.ix(
            'create_operator',
            new Uint8Array(),
            payer(owner),
            writable(d.config()),
            writable(d.operator(nextOperatorId)),
            writable(ownerUsdc),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
            readonly(SYSTEM_PROGRAM_ID),
        )
    }

    /** Adds node nextNodeId, the operator's next_node_id, with signing as its key. The owner alone signs, as on Algorand: the node holds the key. It escrows the node stake from ownerUsdc unless the operator has no live node, whose stake the operator stake covers. */
    createNode(owner: PublicKey, ownerUsdc: PublicKey, operatorId: bigint, nextNodeId: bigint, signing: PublicKey, baseUrl: string): Instruction {
        const w = new Writer()
        w.key(signing)
        w.vec(utf8(baseUrl))
        const d = this
        const node = d.node(operatorId, nextNodeId)
        return this.ix(
            'create_node',
            w.done(),
            payer(owner),
            readonly(d.config()),
            writable(d.operator(operatorId)),
            writable(node),
            writable(d.vault(node)),
            writable(ownerUsdc),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
            readonly(SYSTEM_PROGRAM_ID),
        )
    }

    /** Moves the node to signing as its key, and sets its URL. The owner alone signs. It is pause-gated, as Algorand's updateNode is, so a key can't be rotated while the protocol is paused. */
    updateNode(owner: PublicKey, operatorId: bigint, nodeId: bigint, signing: PublicKey, baseUrl: string): Instruction {
        const w = new Writer()
        w.key(signing)
        w.vec(utf8(baseUrl))
        const d = this
        return this.ix('update_node', w.done(), signer(owner), readonly(d.config()), readonly(d.operator(operatorId)), writable(d.node(operatorId, nodeId)))
    }

    /** Signed by the owner or by the node's signing key. */
    updateNodeUrl(authority: PublicKey, operatorId: bigint, nodeId: bigint, baseUrl: string): Instruction {
        const w = new Writer()
        w.vec(utf8(baseUrl))
        return this.ix('update_node_url', w.done(), ...this.nodeField(authority, operatorId, nodeId))
    }

    /** Signed by the owner or by the node's signing key. */
    setNodeStaging(authority: PublicKey, operatorId: bigint, nodeId: bigint, staging: boolean): Instruction {
        const w = new Writer()
        w.bool(staging)
        return this.ix('set_node_staging', w.done(), ...this.nodeField(authority, operatorId, nodeId))
    }

    private nodeField(authority: PublicKey, operatorId: bigint, nodeId: bigint): AccountMeta[] {
        const d = this
        return [signer(authority), readonly(d.config()), readonly(d.operator(operatorId)), writable(d.node(operatorId, nodeId))]
    }

    /** Hands the operator to newOwner (or keeps it, passing the owner) and sets its name record; the default key clears it. */
    updateOperator(owner: PublicKey, operatorId: bigint, newOwner: PublicKey, nameRef: PublicKey): Instruction {
        const w = new Writer()
        w.key(newOwner)
        w.key(nameRef)
        const d = this
        const cleared = nameRef === SYSTEM_PROGRAM_ID
        return this.ix('update_operator', w.done(), signer(owner), readonly(d.config()), writable(d.operator(operatorId)), this.optional(cleared ? null : nameRef))
    }

    /** Removes a node with no live tickets, refunding its stake and payout to ownerUsdc and its unswept fee to treasuryUsdc. */
    unregisterNode(owner: PublicKey, ownerUsdc: PublicKey, operatorId: bigint, nodeId: bigint, treasuryUsdc: PublicKey): Instruction {
        const d = this
        const node = d.node(operatorId, nodeId)
        return this.ix(
            'unregister_node',
            new Uint8Array(),
            payer(owner),
            readonly(d.config()),
            writable(d.operator(operatorId)),
            writable(node),
            writable(d.vault(node)),
            writable(ownerUsdc),
            writable(treasuryUsdc),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
        )
    }

    /** Closes an operator with no nodes and returns its stake to ownerUsdc. */
    unregisterOperator(owner: PublicKey, ownerUsdc: PublicKey, operatorId: bigint): Instruction {
        const d = this
        return this.ix(
            'unregister_operator',
            new Uint8Array(),
            payer(owner),
            readonly(d.config()),
            writable(d.operator(operatorId)),
            writable(ownerUsdc),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
        )
    }

    /** unregisterOperator by the admin, the stake going to ownerUsdc, an account the owner holds. */
    adminUnregisterOperator(admin: PublicKey, operatorId: bigint, owner: PublicKey, ownerUsdc: PublicKey): Instruction {
        const d = this
        return this.ix(
            'admin_unregister_operator',
            new Uint8Array(),
            signer(admin),
            readonly(d.config()),
            writable(d.operator(operatorId)),
            writable(owner),
            writable(ownerUsdc),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
        )
    }

    /** Tombstones an operator and slashes slashBps of its stake to treasuryUsdc, an account the treasury holds. */
    evict(admin: PublicKey, operatorId: bigint, treasuryUsdc: PublicKey, slashBps: number, reason: string): Instruction {
        const w = new Writer()
        w.u16(slashBps)
        w.vec(utf8(reason))
        const d = this
        return this.ix(
            'evict',
            w.done(),
            signer(admin),
            readonly(d.config()),
            writable(d.operator(operatorId)),
            writable(treasuryUsdc),
            writable(d.stakeVault()),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
            ...this.eventCpi(),
        )
    }

    reinstate(admin: PublicKey, operatorId: bigint): Instruction {
        return this.ix('reinstate', new Uint8Array(), signer(admin), readonly(this.config()), writable(this.operator(operatorId)))
    }

    /** The node's half of the open offer: the node signs and pays for the ticket; the payer's TransferChecked into the vault rides beside it. */
    open(nodeSigner: PublicKey, operatorId: bigint, nodeId: bigint, a: OpenArgs): Instruction {
        const w = new Writer()
        w.fixed(a.ticketId, 16)
        w.key(a.payer)
        w.u64(a.maxPrice)
        w.i64(a.expiresAt)
        w.u32(a.grace)
        const d = this
        const node = d.node(operatorId, nodeId)
        return this.ix(
            'open',
            w.done(),
            payer(nodeSigner),
            readonly(d.config()),
            readonly(d.operator(operatorId)),
            writable(node),
            writable(d.ticket(node, a.ticketId)),
            readonly(SYSVAR_INSTRUCTIONS_ID),
            readonly(SYSTEM_PROGRAM_ID),
        )
    }

    /**
     * What the payer signs off chain to accept a claim, for the Ed25519
     * precompile instruction before a settleCooperative. It binds the cluster,
     * the program, the ticket and its open_seq: a closed ticket's address can
     * be opened again with the same id, and only open_seq tells the two apart,
     * so an ack never replays against the reopened ticket.
     */
    ackDigest(genesis: Hash, ticket: PublicKey, openSeq: bigint, claimHash: Uint8Array): Uint8Array {
        if (claimHash.length !== 32) throw new RangeError(`zsescrow: a claim hash of ${claimHash.length} bytes`)
        return sha256(concat(ACK_TAG, decodeBase58(genesis, 32), publicKeyBytes(this.program), publicKeyBytes(ticket), u64le(openSeq), claimHash))
    }

    private ending(name: string, e: Ending, args: (w: Writer) => void): Instruction {
        const d = this
        const w = new Writer()
        args(w)
        w.u8(d.refundBumps(e.payer).payerAta)
        const node = d.node(e.operatorId, e.nodeId)
        const fallback = e.fallback ?? 'none'
        const treasuryUsdc =
            fallback === 'none' ? readonly(d.program) : { publicKey: d.tokenAccount(e.treasury ?? SYSTEM_PROGRAM_ID), isSigner: false, isWritable: fallback === 'writable' }
        return this.ix(
            name,
            w.done(),
            signer(e.submitter),
            readonly(d.config()),
            writable(node),
            writable(d.vault(node)),
            writable(d.ticket(node, e.ticketId)),
            writable(e.rentPayer),
            writable(d.tokenAccount(e.payer)),
            readonly(d.mint),
            readonly(SYSVAR_INSTRUCTIONS_ID),
            readonly(TOKEN_PROGRAM_ID),
            treasuryUsdc,
            ...this.eventCpi(),
        )
    }

    /**
     * The node's half of a settle, signed by its current signing key. On an
     * open ticket it is the first half, which lapses to the node at the
     * deadline unless the payer answers; on the payer's first half it is the
     * second, which settles if the fields match and freezes the ticket if
     * not. Reposting the same fields is a no-op; other fields are refused.
     */
    claim(e: Ending, f: ClaimFields): Instruction {
        return this.ending('claim', e, (w) => putClaim(w, f))
    }

    /** Settles on the payer's ack: an Ed25519 precompile instruction over the ack digest, or the payer's own signature on the transaction. */
    settleCooperative(e: Ending, f: ClaimFields): Instruction {
        return this.ending('settle_cooperative', e, (w) => putClaim(w, f))
    }

    /** The payer's half of a settle, signed by the payer, with claim's rules from the other side: on an open ticket the first half, which refundInactive refunds in full at the deadline unless the node answers. */
    ack(e: Ending, f: ClaimFields): Instruction {
        return this.ending('ack', e, (w) => putClaim(w, f))
    }

    /** Pays a node's claim the payer did not answer by the deadline; the claim fields are resupplied and checked against the stored hash. */
    settleLapsed(e: Ending, f: ClaimFields): Instruction {
        return this.ending('settle_lapsed', e, (w) => putClaim(w, f))
    }

    /** Refunds the whole escrow of a ticket the node never claimed, or whose payer-posted first half the node never answered, after the deadline. */
    refundInactive(e: Ending): Instruction {
        return this.ending('refund_inactive', e, () => {})
    }

    /**
     * The admin's split of a frozen ticket: the node is awarded
     * operatorShareBps of the pre-fee ceiling, the protocol its fee on that,
     * and the rest returns to the payer. reason is the admin's stated basis,
     * at most 1024 bytes, kept in the TicketResolved event.
     */
    resolveFrozen(e: Ending, operatorShareBps: number, reason: string): Instruction {
        return this.ending('resolve_frozen', e, (w) => {
            w.u16(operatorShareBps)
            w.vec(utf8(reason))
        })
    }

    /**
     * Freezes a ticket on the node's receipt, which the payer proves the node signed with an Ed25519 precompile
     * instruction beside it. On a ticket with a pending half, `pending` must be that half's claim fields, and the
     * receipt the one whose digest they carry, as Algorand requires the protested digest to equal the pending one;
     * the program ignores it on an open ticket. The ticket keeps only the fields' hash: a payer has its own half's
     * fields, and the node's from the node's claim instruction, which are claimFromReceipt(receipt) only when the
     * node claimed exactly its receipt.
     */
    protest(
        payerKey: PublicKey,
        operatorId: bigint,
        nodeId: bigint,
        ticketId: Uint8Array,
        receipt: Uint8Array,
        reason: number,
        pending: ClaimFields | null,
    ): Instruction {
        const w = new Writer()
        w.fixed(ticketId, 16)
        w.vec(receipt)
        w.u8(reason)
        w.option(pending, (f) => putClaim(w, f))
        const d = this
        const node = d.node(operatorId, nodeId)
        return this.ix(
            'protest',
            w.done(),
            signer(payerKey),
            readonly(d.config()),
            writable(node),
            writable(d.ticket(node, ticketId)),
            readonly(SYSVAR_INSTRUCTIONS_ID),
            ...this.eventCpi(),
        )
    }

    /** Sends the node's accrued payout to the operator owner's USDC account. Anyone may submit it. */
    withdrawPayout(operatorId: bigint, nodeId: bigint, owner: PublicKey): Instruction {
        const d = this
        const node = d.node(operatorId, nodeId)
        return this.ix(
            'withdraw_payout',
            new Uint8Array(),
            readonly(d.config()),
            readonly(d.operator(operatorId)),
            writable(node),
            writable(d.vault(node)),
            writable(d.tokenAccount(owner)),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
        )
    }

    /** Sends the node's accrued protocol fee to the treasury's USDC account. Anyone may submit it. */
    sweepFees(operatorId: bigint, nodeId: bigint, treasury: PublicKey): Instruction {
        const d = this
        const node = d.node(operatorId, nodeId)
        return this.ix(
            'sweep_fees',
            new Uint8Array(),
            readonly(d.config()),
            writable(node),
            writable(d.vault(node)),
            writable(d.tokenAccount(treasury)),
            readonly(d.mint),
            readonly(TOKEN_PROGRAM_ID),
        )
    }
}
