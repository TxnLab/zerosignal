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
import { SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, decodeBase58, encodeBase58 } from '../src/solana/index.js'
import {
    type ClaimFields,
    type Ending,
    type RefundFallback,
    CONFIG_SIZE,
    Deployment,
    EVENT_IX_TAG,
    NODE_SIZE,
    OPERATOR_SIZE,
    OWED_VAULT_SEED,
    PROGRAM_ID,
    REFUND_OWED_SIZE,
    SIGNER_INDEX_SIZE,
    STAKE_VAULT_SEED,
    TICKET_SIZE,
    TOKEN_ACCOUNT_SIZE,
    VAULT_SEED,
    ZeroTreasuryError,
    decodeConfig,
    decodeNode,
    decodeOperator,
    decodeRefundOwed,
    decodeSignerIndex,
    decodeTicket,
    decodeTokenAccount,
    discriminator,
    isEventInstruction,
    operatorStatusName,
    parseEvent,
    settleOutcomeName,
    ticketDeadline,
    ticketStatusName,
    tokenAccountStateName,
} from '../src/solana/zsescrow/index.js'

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
        if (name === 'pad0' || name === 'reserve') name = `_${name}`
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
    SignerIndex: [decodeSignerIndex, SIGNER_INDEX_SIZE],
    RefundOwed: [decodeRefundOwed, REFUND_OWED_SIZE],
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
                case 'SignerIndex':
                    want = d.signerIndex(encodeBase58(hex.decode(a.seeds_hex[1])))
                    break
                case 'RefundOwed':
                    want = d.refundOwed(v.payer)
                    break
                case 'TokenAccount': {
                    owner = TOKEN_PROGRAM_ID
                    const seed = new TextDecoder().decode(hex.decode(a.seeds_hex[0]))
                    want = seed === VAULT_SEED ? d.vault(v.owner) : seed === STAKE_VAULT_SEED ? d.stakeVault() : seed === OWED_VAULT_SEED ? d.owedVault() : undefined
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
                ttftMs: f.ttft_ms,
                decodeMs: f.decode_ms,
                inputUnits: BigInt(f.input_units),
                outputUnits: BigInt(f.output_units),
                outputUsageType: f.output_usage_type,
                auxUsageType: f.aux_usage_type,
                auxCount: f.aux_count,
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
                const owed = (c.accounts as Json[]).find((a) => a.name === 'refund_owed')
                if (owed && owed.pubkey !== d.program) e.fallback = owed.is_writable ? 'writable' : 'readonly'
                expect(d.refundBumps(e.payer)).toEqual({ payerAta: args.bumps.payer_ata, refundOwed: args.bumps.refund_owed })
                return e
            }
            const big = (v: string | null) => (v === null ? null : BigInt(v))

            let ix: Instruction
            switch (c.instruction) {
                case 'initialize':
                    ix = d.initialize(acct.admin!, acct.treasury!, {
                        // The fixture writes the genesis hash as hex; the builder takes base58.
                        genesisHash: encodeBase58(hex.decode(args.genesis_hash)),
                        arbiter: args.arbiter,
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
                        pauseOpen: args.pause_open,
                        pauseRegistry: args.pause_registry,
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
                case 'propose_arbiter':
                    ix = d.proposeArbiter(acct.arbiter!, args.new_arbiter)
                    break
                case 'accept_arbiter':
                    ix = d.acceptArbiter(acct.new_arbiter!)
                    break
                case 'create_operator':
                    ix = d.createOperator(acct.owner!, acct.owner_usdc!, operatorId())
                    break
                case 'create_node': {
                    const [op, n] = nodeIds()
                    ix = d.createNode(acct.owner!, acct.owner_usdc!, op, n, acct.signing!, args.base_url)
                    break
                }
                case 'update_node': {
                    const [op, n] = nodeIds()
                    const old = find('old signer index', (k) => d.signerIndex(k) === acct.old_signer_index)
                    ix = d.updateNode(acct.owner!, op, n, old, acct.new_signing!, args.base_url)
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
                    const signing = find('signer index', (k) => d.signerIndex(k) === acct.signer_index)
                    ix = d.unregisterNode(acct.owner!, acct.owner_usdc!, op, n, signing, acct.treasury_usdc!)
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
                case 'claim': {
                    const [op, n] = nodeIds()
                    ix = d.claim(acct.node_signer!, op, n, ticketId(acct.node!), claim(args.fields))
                    break
                }
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
                    ix = d.resolveFrozen(ending(), BigInt(args.node_amount))
                    break
                case 'protest': {
                    const [op, n] = nodeIds()
                    const id = hex.decode(args.ticket_id)
                    expect(d.ticket(acct.node!, id)).toBe(acct.ticket)
                    ix = d.protest(acct.payer!, op, n, id, hex.decode(args.receipt), args.reason)
                    break
                }
                case 'claim_refund_owed':
                    ix = d.claimRefundOwed(acct.payer!, acct.rent_payer!)
                    break
                case 'close_refund_owed': {
                    const payer = find('refund owed', (k) => d.refundOwed(k) === acct.refund_owed)
                    ix = d.closeRefundOwed(acct.rent_payer!, payer)
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
        expect(idl.accounts.length).toBe(6)
        expect(idl.events.length).toBe(4)
    })
})
