/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Replays the instructions, accounts and events the zs_escrow program's own
// tests recorded (solana_instruction_vectors.json, solana_account_vectors.json,
// solana_event_vectors.json, from contracts-solana `make sync-proto-fixtures`)
// against proto/ts/src/solana/zsescrow, as proto/go/solana/zsescrow does. If
// this fails, the TS port has drifted from the program — fix the divergence,
// never the fixture.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { base64, hex } from '@scure/base'
import { describe, expect, it } from 'vitest'

import type { Instruction } from '../src/solana/index.js'
import { ED25519_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, decodeBase58, encodeBase58, publicKeyBytes, transferChecked } from '../src/solana/index.js'
import { findProgramAddress } from '../src/solana/pda.js'
import {
    type AckSpec,
    type ClaimFields,
    type Ending,
    type OpenOfferSpec,
    type RefundFallback,
    AckRejectedError,
    OfferRejectedError,
    CONFIG_SIZE,
    Deployment,
    EVENT_IX_TAG,
    NODE_SIZE,
    OPERATOR_SIZE,
    PROGRAM_ID,
    RENT_POOL_SEED,
    RENT_POOL_SIZE,
    STAKE_VAULT_SEED,
    TICKET_SIZE,
    TOKEN_ACCOUNT_SIZE,
    VAULT_SEED,
    ZeroTreasuryError,
    claimFromReceipt,
    claimHash,
    decodeConfig,
    decodeNode,
    decodeOperator,
    decodeRentPool,
    decodeTicket,
    decodeTokenAccount,
    discriminator,
    isEventInstruction,
    operatorStatusName,
    parseEvent,
    receiptAckDigest,
    settleOutcomeName,
    ticketDeadline,
    ticketStatusName,
    tokenAccountStateName,
    verifyOpenOffer,
    verifyRelayedAck,
} from '../src/solana/zsescrow/index.js'
import { solanaDeploymentId } from '../src/ticket/deployment.js'
import { parseReceiptJSON, receiptCanonicalBytes, receiptSigDigest } from '../src/ticket/receipt.js'

type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const here = path.dirname(fileURLToPath(import.meta.url))
const load = (name: string): Json => JSON.parse(fs.readFileSync(path.resolve(here, '..', '..', name), 'utf8')) as Json

const accounts = load('testdata/solana_account_vectors.json')
const instructions = load('testdata/solana_instruction_vectors.json')
const events = load('testdata/solana_event_vectors.json')
const vectors = load('testdata/solana_zsescrow_vectors.json')
const idl = load('go/solana/idl/zs_escrow.json')

// The fixtures' shape: snake_case names, u64 and i64 as decimal strings, byte
// arrays hex, enums by variant name.
const ENUMS: Record<string, (n: number) => string> = {
    Operator: operatorStatusName,
    Ticket: ticketStatusName,
    TokenAccount: tokenAccountStateName,
    TicketSettled: settleOutcomeName,
}
function toFixture(type: string, v: Json): Json {
    const out: Json = {}
    for (const [k, x] of Object.entries(v)) {
        if (k === 'event') continue
        let name = k.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)
        if (name === 'pad0' || name === 'reserve' || name.startsWith('retired_')) name = `_${name}`
        if ((name === 'status' || name === 'state' || name === 'outcome') && ENUMS[type]) out[name] = ENUMS[type]!(x)
        else if (name === 'genesis_hash') out[name] = hex.encode(decodeBase58(x, 32))
        else out[name] = plain(x)
    }
    return out
}
function plain(x: unknown): unknown {
    if (typeof x === 'bigint') return x.toString()
    if (x instanceof Uint8Array) return hex.encode(x)
    if (Array.isArray(x)) return x.map(plain)
    return x
}

const decoders: Record<string, [(d: Uint8Array) => Json, number]> = {
    Config: [decodeConfig, CONFIG_SIZE],
    Operator: [decodeOperator, OPERATOR_SIZE],
    Node: [decodeNode, NODE_SIZE],
    Ticket: [decodeTicket, TICKET_SIZE],
    RentPool: [decodeRentPool, RENT_POOL_SIZE],
    TokenAccount: [decodeTokenAccount, TOKEN_ACCOUNT_SIZE],
}

describe('solana_account_vectors.json', () => {
    const d = new Deployment(accounts.program_id, accounts.context.usdc_mint)
    it('covers every decoder', () => {
        expect(new Set((accounts.accounts as Json[]).map((a) => a.type))).toEqual(new Set(Object.keys(decoders)))
    })
    for (const a of accounts.accounts as Json[]) {
        it(a.name, () => {
            const data = base64.decode(a.data_base64)
            const [decode, size] = decoders[a.type]!
            expect([data.length, size]).toEqual([a.data_len, a.data_len])
            const v = decode(data)
            // The address is the one Deployment derives from what the
            // account holds, and the account belongs to the program that
            // writes it.
            let want: string | undefined
            let owner = d.program
            switch (a.type) {
                case 'Config':
                    want = d.config()
                    break
                case 'Operator':
                    want = d.operator(v.id)
                    break
                case 'Node':
                    want = d.node(v.operatorId, v.nodeId)
                    expect([v.vault, v.operator]).toEqual([d.vault(want), d.operator(v.operatorId)])
                    break
                case 'Ticket':
                    want = d.ticket(v.node, hex.decode(a.seeds_hex[2]))
                    break
                case 'RentPool':
                    want = d.rentPool(v.payer)
                    expect(v.bump).toBe(findProgramAddress([new TextEncoder().encode(RENT_POOL_SEED), publicKeyBytes(v.payer)], d.program)[1])
                    break
                case 'TokenAccount': {
                    owner = TOKEN_PROGRAM_ID
                    const seed = new TextDecoder().decode(hex.decode(a.seeds_hex[0]))
                    want = seed === VAULT_SEED ? d.vault(v.owner) : seed === STAKE_VAULT_SEED ? d.stakeVault() : undefined
                    expect(v.mint).toBe(d.mint)
                    break
                }
            }
            expect([a.address, a.owner]).toEqual([want, owner])
            const flat = toFixture(a.type, v)
            // The fixture gives a token account's mint, owner, amount and
            // state only; the program's own accounts in full.
            if (a.type !== 'TokenAccount') expect(Object.keys(flat).sort()).toEqual(Object.keys(a.decoded).sort())
            for (const [k, want] of Object.entries(a.decoded as Json)) expect(flat[k], k).toEqual(want)
            if (a.type !== 'Config' && a.type !== 'TokenAccount') expect(() => decodeConfig(data)).toThrow()
        })
    }
})

describe('solana_instruction_vectors.json', () => {
    const ctx = instructions.context
    const d = new Deployment(instructions.program_id, ctx.usdc_mint)
    const known: string[] = [ctx.treasury, ...Object.values(ctx.keys as Record<string, Json>).map((k) => k.pubkey)]
    const covered = new Set<string>()

    for (const c of instructions.instructions as Json[]) {
        it(c.case, () => {
            const acct: Record<string, string> = Object.fromEntries((c.accounts as Json[]).map((a) => [a.name, a.pubkey]))
            const args = c.args as Json
            // The fixtures name accounts, not the ids and keys a builder
            // derives them from; find those by deriving.
            const find = (what: string, match: (k: string) => boolean): string => {
                const k = known.find(match)
                if (!k) throw new Error(`no known key gives the ${what}`)
                return k
            }
            const ownerOf = (account: string) => find(account, (k) => d.tokenAccount(k) === acct[account])
            const operatorId = (): bigint => {
                for (let id = 1n; id < 16n; id++) if (d.operator(id) === acct.operator) return id
                throw new Error('no operator id gives the operator')
            }
            const nodeIds = (): [bigint, bigint] => {
                for (let op = 1n; op < 8n; op++) for (let n = 1n; n < 8n; n++) if (d.node(op, n) === acct.node) return [op, n]
                throw new Error('no ids give the node')
            }
            const ticketId = (node: string): Uint8Array => {
                for (let b = 0; b < 256; b++) {
                    const id = new Uint8Array(16).fill(b)
                    if (d.ticket(node, id) === acct.ticket) return id
                }
                throw new Error('no ticket id gives the ticket')
            }
            const claim = (f: Json): ClaimFields => ({
                amount: BigInt(f.amount),
                receiptDigest: hex.decode(f.receipt_digest),
                ttftMs: BigInt(f.ttft_ms),
                decodeMs: BigInt(f.decode_ms),
                inputUnits: BigInt(f.input_units),
                outputUnits: BigInt(f.output_units),
                outputUsageType: f.output_usage_type,
                auxUsageType: f.aux_usage_type,
                auxCount: BigInt(f.aux_count),
            })
            const ending = (): Ending => {
                const [op, n] = nodeIds()
                const e: Ending = {
                    submitter: acct.submitter!,
                    operatorId: op,
                    nodeId: n,
                    ticketId: ticketId(acct.node!),
                    rentPayer: acct.rent_payer!,
                    payer: ownerOf('payer_ata'),
                }
                const treasury = (c.accounts as Json[]).find((a) => a.name === 'treasury_usdc')
                if (treasury && treasury.pubkey !== d.program) {
                    e.treasury = ownerOf('treasury_usdc')
                    e.fallback = treasury.is_writable ? 'writable' : 'readonly'
                }
                expect(d.refundBumps(e.payer)).toEqual({ payerAta: args.bumps.payer_ata })
                expect(Object.keys(args.bumps)).toEqual(['payer_ata'])
                return e
            }
            const big = (v: string | null) => (v === null ? null : BigInt(v))

            let ix: Instruction
            switch (c.instruction) {
                case 'initialize':
                    ix = d.initialize(acct.admin!, acct.treasury!, {
                        // The fixture writes the genesis hash as hex; the builder takes base58.
                        genesisHash: encodeBase58(hex.decode(args.genesis_hash)),
                        feeBps: args.fee_bps,
                        maxGrace: args.max_grace,
                        defaultGrace: args.default_grace,
                        minGrace: args.min_grace,
                        maxTicketLifetime: BigInt(args.max_ticket_lifetime),
                        operatorStake: BigInt(args.operator_stake),
                        nodeStake: BigInt(args.node_stake),
                    })
                    break
                case 'set_config':
                    ix = d.setConfig(acct.admin!, {
                        paused: args.paused,
                        feeBps: args.fee_bps,
                        maxGrace: args.max_grace,
                        defaultGrace: args.default_grace,
                        minGrace: args.min_grace,
                        maxTicketLifetime: big(args.max_ticket_lifetime),
                        operatorStake: big(args.operator_stake),
                        nodeStake: big(args.node_stake),
                        treasury: args.treasury,
                    })
                    break
                case 'propose_admin':
                    ix = d.proposeAdmin(acct.admin!, args.new_admin)
                    break
                case 'accept_admin':
                    ix = d.acceptAdmin(acct.new_admin!)
                    break
                case 'create_operator':
                    ix = d.createOperator(acct.owner!, acct.owner_usdc!, operatorId())
                    break
                case 'create_node': {
                    const [op, n] = nodeIds()
                    ix = d.createNode(acct.owner!, acct.owner_usdc!, op, n, args.signing, args.base_url)
                    break
                }
                case 'update_node': {
                    const [op, n] = nodeIds()
                    ix = d.updateNode(acct.owner!, op, n, args.signing, args.base_url)
                    break
                }
                case 'update_node_url': {
                    const [op, n] = nodeIds()
                    ix = d.updateNodeUrl(acct.authority!, op, n, args.base_url)
                    break
                }
                case 'set_node_staging': {
                    const [op, n] = nodeIds()
                    ix = d.setNodeStaging(acct.authority!, op, n, args.staging)
                    break
                }
                case 'update_operator':
                    ix = d.updateOperator(acct.owner!, operatorId(), args.new_owner, args.name_ref)
                    break
                case 'unregister_node': {
                    const [op, n] = nodeIds()
                    ix = d.unregisterNode(acct.owner!, acct.owner_usdc!, op, n, acct.treasury_usdc!)
                    break
                }
                case 'unregister_operator':
                    ix = d.unregisterOperator(acct.owner!, acct.owner_usdc!, operatorId())
                    break
                case 'admin_unregister_operator':
                    ix = d.adminUnregisterOperator(acct.admin!, operatorId(), acct.owner!, acct.owner_usdc!)
                    break
                case 'evict':
                    ix = d.evict(acct.admin!, operatorId(), acct.treasury_usdc!, args.slash_bps, args.reason)
                    break
                case 'reinstate':
                    ix = d.reinstate(acct.admin!, operatorId())
                    break
                case 'open': {
                    const [op, n] = nodeIds()
                    ix = d.open(acct.node_signer!, op, n, {
                        ticketId: hex.decode(args.ticket_id),
                        payer: args.payer,
                        maxPrice: BigInt(args.max_price),
                        expiresAt: BigInt(args.expires_at),
                        grace: args.grace,
                    })
                    break
                }
                case 'claim':
                    ix = d.claim(ending(), claim(args.fields))
                    break
                case 'settle_cooperative':
                    ix = d.settleCooperative(ending(), claim(args.fields))
                    break
                case 'ack':
                    ix = d.ack(ending(), claim(args.fields))
                    break
                case 'settle_lapsed':
                    ix = d.settleLapsed(ending(), claim(args.fields))
                    break
                case 'refund_inactive':
                    ix = d.refundInactive(ending())
                    break
                case 'resolve_frozen':
                    ix = d.resolveFrozen(ending(), args.operator_share_bps, args.reason)
                    break
                case 'protest': {
                    const [op, n] = nodeIds()
                    const id = hex.decode(args.ticket_id)
                    expect(d.ticket(acct.node!, id)).toBe(acct.ticket)
                    ix = d.protest(acct.payer!, op, n, id, hex.decode(args.receipt), args.reason, args.pending === null ? null : claim(args.pending))
                    break
                }
                case 'withdraw_payout': {
                    const [op, n] = nodeIds()
                    ix = d.withdrawPayout(op, n, ownerOf('owner_usdc'))
                    break
                }
                case 'sweep_fees': {
                    const [op, n] = nodeIds()
                    ix = d.sweepFees(op, n, ownerOf('treasury_usdc'))
                    break
                }
                case 'deposit_rent':
                    ix = d.depositRent(acct.payer!, BigInt(args.amount))
                    break
                case 'withdraw_rent':
                    ix = d.withdrawRent(acct.payer!, BigInt(args.amount))
                    break
                case 'close_rent_pool':
                    ix = d.closeRentPool(acct.payer!)
                    break
                default:
                    throw new Error(`no builder for ${c.instruction}`)
            }
            covered.add(c.instruction)
            expect(ix.programId).toBe(d.program)
            expect(hex.encode(ix.data)).toBe(hex.encode(base64.decode(c.data_base64)))
            expect(ix.accounts).toEqual((c.accounts as Json[]).map((a) => ({ publicKey: a.pubkey, isSigner: a.is_signer, isWritable: a.is_writable })))
        })
    }

    it('pins every builder the IDL lists', () => {
        for (const ix of idl.instructions as Json[]) expect(covered.has(ix.name), ix.name).toBe(true)
    })
})

describe('solana_event_vectors.json', () => {
    const d = new Deployment(events.program_id, events.context.usdc_mint)
    it('names the event authority and tag the program uses', () => {
        expect(d.eventAuthority()).toBe(events.emit_cpi.event_authority)
        expect(hex.encode(EVENT_IX_TAG)).toBe(events.emit_cpi.event_ix_tag_hex)
        expect(events.events.length).toBeGreaterThan(0)
    })
    for (const e of events.events as Json[]) {
        it(e.case, () => {
            const data = base64.decode(e.inner_instruction.data_base64)
            expect(base64.encode(data.subarray(8))).toBe(e.event_base64)
            expect(hex.encode(data.subarray(8, 16))).toBe(e.discriminator_hex)
            expect(isEventInstruction(d, e.inner_instruction.program_id, e.inner_instruction.accounts)).toBe(true)
            expect(isEventInstruction(d, e.inner_instruction.program_id, [...e.inner_instruction.accounts, d.program])).toBe(false)
            const ev = parseEvent(data)
            expect(ev.event).toBe(e.event)
            expect(toFixture(e.event, ev)).toEqual(e.decoded)
            expect(() => parseEvent(new Uint8Array([...data, 0]))).toThrow()
            expect(() => parseEvent(data.subarray(0, data.length - 1))).toThrow()
        })
    }
})

// The payer's ack the program checked, from solana_tx_vectors.json: the claim
// hash of the settle's own fields, the digest over it, and the Ed25519
// precompile instruction signing exactly that digest with the payer's key, as
// Go's TestAckDigestFixture reads them.
describe('the ack digest in solana_tx_vectors.json', () => {
    const txs = load('testdata/solana_tx_vectors.json')
    const d = new Deployment(txs.program_id, txs.context.usdc_mint)
    const genesis = encodeBase58(hex.decode(txs.context.genesis_hash))
    const settleDisc = discriminator('global', 'settle_cooperative')
    const acks = (txs.transactions as Json[]).filter((t) => t.ack_digest_hex)
    it('is carried by a transaction', () => expect(acks.length).toBeGreaterThan(0))
    for (const tx of acks) {
        it(tx.name, () => {
            const ixs = (tx.built_instructions as Json[]).map((b) => ({ programId: b.program_id as string, accounts: b.accounts as Json[], data: base64.decode(b.data_base64) }))
            const settle = ixs.find((ix) => ix.programId === d.program && hex.encode(ix.data.subarray(0, 8)) === hex.encode(settleDisc))
            const precompile = ixs.find((ix) => ix.programId === ED25519_PROGRAM_ID)
            if (!settle || !precompile) throw new Error('no settle_cooperative beside an Ed25519 instruction')
            const claim = claimHash(claimFieldsOf(settle.data.subarray(8)))
            expect(hex.encode(claim)).toBe(tx.claim_hash_hex)
            const ticketAt = 4
            const digest = d.ackDigest(genesis, settle.accounts[ticketAt]!.pubkey, BigInt(tx.open_seq), claim)
            expect(hex.encode(digest)).toBe(tx.ack_digest_hex)
            const { message, signer } = ed25519Message(precompile.data)
            expect([hex.encode(message), signer]).toEqual([hex.encode(digest), tx.payer])
        })
    }
    // Go's [32]byte rules out any other length; here a check has to, or the
    // payer would sign a digest over a hash of the wrong size.
    it('refuses a claim hash of any length but 32', () => {
        const ticket = acks[0]!.payer as string
        for (const n of [31, 33]) {
            expect(() => d.ackDigest(genesis, ticket, 1n, new Uint8Array(n))).toThrow(RangeError)
        }
    })
})

// The protest of a pending ticket the program accepted, as Go's
// TestProtestPendingFixture reads it: its pending claim fields hash to the
// ticket's claim and carry the receipt's digest, sha256 of its canonical bytes,
// which the node's Ed25519 instruction signs.
describe('the protest of a pending ticket in solana_tx_vectors.json', () => {
    const txs = load('testdata/solana_tx_vectors.json')
    const protestDisc = discriminator('global', 'protest')
    const tx = (txs.transactions as Json[]).find((t) => t.name === 'protest_pending')
    it('passes the pending half the receipt names', () => {
        if (!tx) throw new Error('no protest_pending transaction')
        expect(tx.program).toBe('ok')
        const ixs = (tx.built_instructions as Json[]).map((b) => ({ programId: b.program_id as string, data: base64.decode(b.data_base64) }))
        const protest = ixs.find((ix) => ix.programId === txs.program_id && hex.encode(ix.data.subarray(0, 8)) === hex.encode(protestDisc))
        const precompile = ixs.find((ix) => ix.programId === ED25519_PROGRAM_ID)
        if (!protest || !precompile) throw new Error('no protest beside an Ed25519 instruction')
        // ticket_id, then the receipt as a u32-prefixed vector, the reason, and the pending fields as Some.
        const args = protest.data.subarray(8 + 16)
        const n = new DataView(args.buffer, args.byteOffset, args.byteLength).getUint32(0, true)
        const receipt = args.subarray(4, 4 + n)
        const rest = args.subarray(4 + n + 1)
        expect(rest[0]).toBe(1)
        const pending = claimFieldsOf(rest.subarray(1))
        expect(hex.encode(claimHash(pending))).toBe(tx.claim_hash_hex)
        const r = parseReceiptJSON(new TextEncoder().encode(JSON.stringify(tx.receipt_value)))
        expect(hex.encode(receiptCanonicalBytes(r))).toBe(hex.encode(receipt))
        const digest = receiptSigDigest(r)
        expect([hex.encode(pending.receiptDigest), hex.encode(digest)]).toEqual([tx.receipt_digest_hex, tx.receipt_digest_hex])
        expect(claimFromReceipt(r)).toEqual(pending)
        expect(hex.encode(ed25519Message(precompile.data).message)).toBe(hex.encode(digest))
    })
})

// ClaimFields from the head of an instruction's arguments, in the program's Borsh order.
function claimFieldsOf(b: Uint8Array): ClaimFields {
    if (b.length < 82) throw new Error(`claim fields of ${b.length} bytes`)
    const v = new DataView(b.buffer, b.byteOffset, b.byteLength)
    const le = (at: number) => v.getBigUint64(at, true)
    return {
        amount: le(0),
        receiptDigest: b.slice(8, 40),
        ttftMs: le(40),
        decodeMs: le(48),
        inputUnits: le(56),
        outputUnits: le(64),
        outputUsageType: b[72]!,
        auxUsageType: b[73]!,
        auxCount: le(74),
    }
}

// The one signature an Ed25519 precompile instruction verifies: the message it
// signs and the key, each at an offset in the instruction's own data.
function ed25519Message(data: Uint8Array): { message: Uint8Array; signer: string } {
    if (data.length < 16 || data[0] !== 1) throw new Error(`an Ed25519 instruction of ${data.length} bytes, not one signature`)
    const v = new DataView(data.buffer, data.byteOffset, data.byteLength)
    const u16 = (at: number) => v.getUint16(at, true)
    const own = 0xffff
    if (u16(4) !== own || u16(8) !== own || u16(14) !== own) throw new Error("the precompile reads another instruction's data")
    const [pk, msg, size] = [u16(6), u16(10), u16(12)]
    if (pk + 32 > data.length || msg + size > data.length) throw new Error("the precompile's offsets run past its data")
    return { message: data.subarray(msg, msg + size), signer: encodeBase58(data.subarray(pk, pk + 32)) }
}

// What the program never writes, pinned by the Go-generated
// solana_zsescrow_vectors.json: data the decoders refuse or read a particular
// way, instructions that only look like events, deadlines at their edges,
// and settles built with each refund fallback.
describe('solana_zsescrow_vectors.json', () => {
    const d = new Deployment(vectors.program_id, vectors.usdc_mint)
    for (const c of vectors.accounts_refused as Json[]) {
        it(`refuses ${c.name}`, () => {
            expect(() => decoders[c.type]![0](base64.decode(c.data_base64))).toThrow()
        })
    }
    for (const c of vectors.accounts_accepted as Json[]) {
        it(`reads ${c.name}`, () => {
            const flat = toFixture(c.type, decoders[c.type]![0](base64.decode(c.data_base64)))
            expect(flat).toEqual(c.decoded)
        })
    }
    for (const c of vectors.events_refused as Json[]) {
        it(`refuses event ${c.name}`, () => {
            expect(() => parseEvent(base64.decode(c.data_base64))).toThrow()
        })
    }
    for (const c of vectors.events_accepted as Json[]) {
        it(`reads event ${c.name}`, () => {
            const ev = parseEvent(base64.decode(c.data_base64))
            expect(toFixture(ev.event, ev)).toEqual(c.decoded)
        })
    }
    for (const c of vectors.event_instructions as Json[]) {
        it(`event instruction ${c.name}`, () => {
            expect(isEventInstruction(d, c.program_id, c.accounts)).toBe(c.is_event)
        })
    }
    it('gives each deadline', () => {
        for (const c of vectors.deadlines as Json[]) {
            const t = { expiresAt: BigInt(c.expires_at), grace: c.grace } as Parameters<typeof ticketDeadline>[0]
            expect(ticketDeadline(t).toString(), `${c.expires_at} + ${c.grace}`).toBe(c.deadline)
        }
    })
    for (const c of vectors.builds as Json[]) {
        it(`builds ${c.name}`, () => {
            const e: Ending = {
                submitter: c.ending.submitter,
                operatorId: BigInt(c.ending.operator_id),
                nodeId: BigInt(c.ending.node_id),
                ticketId: hex.decode(c.ending.ticket_id),
                rentPayer: c.ending.rent_payer,
                payer: c.ending.payer,
                treasury: c.ending.treasury,
                fallback: c.ending.fallback as RefundFallback,
            }
            if (c.builder !== 'refund_inactive') throw new Error(`no builder for ${c.builder}`)
            const ix = d.refundInactive(e)
            expect(base64.encode(ix.data)).toBe(c.data_base64)
            expect(ix.accounts).toEqual((c.accounts as Json[]).map((a) => ({ publicKey: a.pubkey, isSigner: a.is_signer, isWritable: a.is_writable })))
        })
    }
    it('refuses a zero treasury', () => {
        expect(vectors.set_config_refused.map((c: Json) => c.treasury)).toEqual([SYSTEM_PROGRAM_ID])
        for (const c of vectors.set_config_refused as Json[]) expect(() => d.setConfig(d.program, { treasury: c.treasury })).toThrow(ZeroTreasuryError)
    })
})

// The open-offer verdicts, pinned by the Go-generated
// solana_open_offer_vectors.json: every open offer the program wrote, and the
// ones Go built for checks the program's shapes don't reach.
describe('solana_open_offer_vectors.json', () => {
    const offers = load('testdata/solana_open_offer_vectors.json')
    const d = new Deployment(offers.program_id, offers.usdc_mint)
    const specOf = (s: Json): OpenOfferSpec => ({
        nodeSigning: s.node_signing,
        operatorId: BigInt(s.operator_id),
        nodeId: BigInt(s.node_id),
        payer: s.payer,
        payerUsdc: s.payer_usdc,
        decimals: s.decimals,
        ticketId: hex.decode(s.ticket_id),
        maxPrice: BigInt(s.max_price),
        expiresAt: BigInt(s.expires_at),
        ...(s.fold
            ? {
                  fold: {
                      operatorId: BigInt(s.fold.operator_id),
                      nodeId: BigInt(s.fold.node_id),
                      ticketId: hex.decode(s.fold.ticket_id),
                      receipt: s.fold.receipt === null ? (undefined as never) : parseReceiptJSON(new TextEncoder().encode(JSON.stringify(s.fold.receipt))),
                      treasury: s.fold.treasury,
                  },
              }
            : {}),
    })
    it('covers both sources and every check that refuses', () => {
        expect(new Set((offers.cases as Json[]).map((c) => c.source))).toEqual(new Set(['fixture', 'built']))
        expect((offers.cases as Json[]).filter((c) => c.verdict === 'ok').length).toBeGreaterThan(2)
        expect(new Set((offers.cases as Json[]).map((c) => c.verdict))).toEqual(
            new Set([
                'ok',
                'message.parse',
                'message.lookups',
                'header.signers',
                'header.feePayer',
                'header.payer',
                'header.payerWritable',
                'computeBudget.order',
                'computeBudget.instruction',
                'computeBudget.duplicate',
                'token.instruction',
                'escrow.instruction',
                'instruction.program',
                'instructions.shape',
                'transfer.accounts',
                'transfer.data',
                'open.accounts',
                'open.data',
                'fold.unexpected',
                'fold.receipt',
                'fold.accounts',
                'fold.data',
            ]),
        )
    })
    for (const c of offers.cases as Json[]) {
        it(`${c.source} ${c.name}: ${c.verdict}`, () => {
            let verdict = 'ok'
            try {
                verifyOpenOffer(d, base64.decode(c.message_base64), specOf(c.spec))
            } catch (err) {
                if (!(err instanceof OfferRejectedError)) throw err
                verdict = err.field
            }
            expect(verdict, c.about).toBe(c.verdict)
        })
    }
    it('throws a RangeError for a spec ticket id not 16 bytes', () => {
        const c = (offers.cases as Json[]).find((c) => c.name === 'open_fold_settle')!
        const message = base64.decode(c.message_base64)
        const spec = specOf(c.spec)
        expect(() => verifyOpenOffer(d, message, spec)).not.toThrow()
        expect(() => verifyOpenOffer(d, message, { ...spec, ticketId: spec.ticketId.subarray(1) })).toThrow(RangeError)
        // Ahead of every refusal, so a caller's bad spec never reads as the node's bad offer.
        expect(() => verifyOpenOffer(d, new Uint8Array(), { ...spec, ticketId: spec.ticketId.subarray(1) })).toThrow(RangeError)
        expect(() => verifyOpenOffer(d, message, { ...spec, fold: { ...spec.fold!, ticketId: spec.fold!.ticketId.subarray(1) } })).toThrow(RangeError)
    })
    it('transferChecked refuses an amount or decimals its data cannot carry', () => {
        const k = d.mint
        expect(() => transferChecked(k, k, k, k, (1n << 64n) - 1n, 255)).not.toThrow()
        expect(() => transferChecked(k, k, k, k, 1n << 64n, 6)).toThrow(RangeError)
        expect(() => transferChecked(k, k, k, k, -1n, 6)).toThrow(RangeError)
        expect(() => transferChecked(k, k, k, k, 1n, 256)).toThrow(RangeError)
        expect(() => transferChecked(k, k, k, k, 1n, -1)).toThrow(RangeError)
    })
    it("matches the program's own fixture messages", () => {
        const tx = new Map((load('testdata/solana_tx_vectors.json').transactions as Json[]).map((t) => [t.name, t.message_base64]))
        for (const c of (offers.cases as Json[]).filter((c) => c.source === 'fixture')) expect(c.message_base64, c.name).toBe(tx.get(c.name))
    })
})

// The relayed-ack verdicts and receipt ack digests, pinned by the Go-generated
// solana_ack_vectors.json: the program's own ack transactions, and the ones Go
// built for checks those shapes don't reach.
describe('solana_ack_vectors.json', () => {
    const acks = load('testdata/solana_ack_vectors.json')
    const d = new Deployment(acks.program_id, acks.usdc_mint)
    const genesis = encodeBase58(hex.decode(acks.genesis_hash))
    const receiptOf = (r: Json | null) => (r === null ? undefined : parseReceiptJSON(new TextEncoder().encode(JSON.stringify(r))))
    const specOf = (s: Json): AckSpec => ({
        payer: s.payer,
        operatorId: BigInt(s.operator_id),
        nodeId: BigInt(s.node_id),
        ticketId: hex.decode(s.ticket_id),
        receipt: receiptOf(s.receipt),
        treasury: s.treasury,
    })
    const verdictOf = (f: () => unknown): string => {
        try {
            f()
        } catch (err) {
            if (!(err instanceof AckRejectedError)) throw err
            return err.field
        }
        return 'ok'
    }
    it('covers both sources and every check that refuses', () => {
        const cases = acks.relayed_acks as Json[]
        expect(new Set(cases.map((c) => c.source))).toEqual(new Set(['fixture', 'built']))
        expect(cases.filter((c) => c.verdict === 'ok').length).toBeGreaterThan(2)
        expect(new Set(cases.map((c) => c.verdict))).toEqual(
            new Set([
                'ok',
                'message.parse',
                'message.lookups',
                'header.signers',
                'header.payer',
                'header.payerWritable',
                'computeBudget.order',
                'computeBudget.instruction',
                'computeBudget.duplicate',
                'escrow.instruction',
                'instruction.program',
                'instructions.shape',
                'ack.receipt',
                'ack.accounts',
                'ack.data',
            ]),
        )
    })
    for (const c of acks.relayed_acks as Json[]) {
        it(`${c.source} ${c.name}: ${c.verdict}`, () => {
            expect(verdictOf(() => verifyRelayedAck(d, base64.decode(c.message_base64), specOf(c.spec))), c.about).toBe(c.verdict)
        })
    }
    for (const c of acks.digests as Json[]) {
        it(`digest ${c.name}: ${c.verdict}`, () => {
            let digest: Uint8Array | undefined
            const verdict = verdictOf(() => {
                digest = receiptAckDigest(d, genesis, BigInt(c.operator_id), BigInt(c.node_id), hex.decode(c.ticket_id), BigInt(c.open_seq), receiptOf(c.receipt))
            })
            expect(verdict, c.about).toBe(c.verdict)
            if (verdict === 'ok') expect(hex.encode(digest!)).toBe(c.digest_hex)
        })
    }
    it('throws a RangeError for a ticket id not 16 bytes', () => {
        const c = (acks.relayed_acks as Json[]).find((c) => c.name === 'ack_relayed')!
        const message = base64.decode(c.message_base64)
        const spec = specOf(c.spec)
        expect(() => verifyRelayedAck(d, message, spec)).not.toThrow()
        // Ahead of every refusal, so a caller's bad spec never reads as the relayer's bad ack.
        expect(() => verifyRelayedAck(d, new Uint8Array(), { ...spec, ticketId: spec.ticketId.subarray(1) })).toThrow(RangeError)
        expect(() => receiptAckDigest(d, genesis, spec.operatorId, spec.nodeId, spec.ticketId.subarray(1), 1n, spec.receipt)).toThrow(RangeError)
    })
    it("matches the program's own fixture messages", () => {
        const tx = new Map((load('testdata/solana_tx_vectors.json').transactions as Json[]).map((t) => [t.name, t.message_base64]))
        const fixtures = (acks.relayed_acks as Json[]).filter((c) => c.source === 'fixture')
        expect(fixtures.map((c) => c.name)).toEqual(expect.arrayContaining(['ack_relayed', 'ack_extra_settle']))
        for (const c of fixtures) expect(c.message_base64, c.name).toBe(tx.get(c.name))
    })
    // The vectors' specs carry each fixture's receipt; this ties that receipt to the ack the program ran, so the
    // acceptance of ack_relayed is the verifier's on a real receipt's claim.
    it("claims, in each of the program's acks, the receipt its fixture records", () => {
        const txs = load('testdata/solana_tx_vectors.json')
        const dep = hex.encode(solanaDeploymentId(hex.decode(txs.context.genesis_hash), decodeBase58(txs.program_id, 32)))
        const ackDisc = hex.encode(discriminator('global', 'ack'))
        const fixtures = (txs.transactions as Json[]).filter((t) => (t.name as string).startsWith('ack'))
        const cases = (acks.relayed_acks as Json[]).filter((c) => c.source === 'fixture')
        expect(fixtures.map((t) => t.name)).toEqual(cases.map((c) => c.name))
        for (const f of fixtures) {
            expect(cases.find((c) => c.name === f.name)!.spec.receipt, f.name).toEqual(f.receipt_value)
            const r = parseReceiptJSON(new TextEncoder().encode(JSON.stringify(f.receipt_value)))
            expect(hex.encode(receiptCanonicalBytes(r)), f.name).toBe(f.receipt_hex)
            expect(hex.encode(receiptSigDigest(r)), f.name).toBe(f.receipt_digest_hex)
            expect([f.deployment_hex, hex.encode(base64.decode(r.deployment!))], f.name).toEqual([dep, dep])
            const ack = (f.built_instructions as Json[]).map((b) => base64.decode(b.data_base64)).find((d) => hex.encode(d.subarray(0, 8)) === ackDisc)
            if (!ack) throw new Error(`${f.name}: no ack`)
            expect(claimFieldsOf(ack.subarray(8)), f.name).toEqual(claimFromReceipt(r))
        }
    })
})

describe('the IDL', () => {
    it('lists the program id and discriminators the builders and decoders compute', () => {
        expect(idl.address).toBe(PROGRAM_ID)
        for (const [ns, list] of [
            ['global', idl.instructions],
            ['account', idl.accounts],
            ['event', idl.events],
        ] as [string, Json[]][]) {
            for (const e of list) expect(Array.from(discriminator(ns, e.name)), `${ns}:${e.name}`).toEqual(e.discriminator)
        }
        expect(idl.accounts.length).toBe(5)
        expect(idl.events.length).toBe(6)
    })
})
