/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Replays the zs_escrow program's own transactions and addresses
// (solana_tx_vectors.json, solana_account_vectors.json, written by its tests
// on LiteSVM) and Go's codec edges (solana_codec_vectors.json, from
// `cd proto/go && go test ./solana -run TestCodecVectors -update`) against
// proto/ts/src/solana. If this fails, the TS port has drifted from Go or from
// the runtime — fix the divergence rather than regenerating a fixture.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { base64, hex } from '@scure/base'
import { describe, expect, it } from 'vitest'

import {
    type Instruction,
    compileMessage,
    createAssociatedTokenAccountIdempotent,
    createProgramAddress,
    decodeBase58,
    encodeBase58,
    encodeMessage,
    encodeTransaction,
    feePayer,
    findProgramAddress,
    isOnCurve,
    isSigner,
    isWritable,
    mintTo,
    newTransaction,
    parseMessage,
    parsePublicKey,
    parseTransaction,
    publicKeyBytes,
    setComputeUnitLimit,
    setComputeUnitPrice,
    signTransaction,
    transferChecked,
    verifySignatures,
    verifyStrict,
} from '../src/solana/index.js'
import { ed25519 } from '../src/util/ed25519.js'

type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const here = path.dirname(fileURLToPath(import.meta.url))
const load = (name: string): Json => JSON.parse(fs.readFileSync(path.resolve(here, '..', '..', 'testdata', name), 'utf8')) as Json

const txs = load('solana_tx_vectors.json')
const accounts = load('solana_account_vectors.json')
const codec = load('solana_codec_vectors.json')

const seedOf = new Map<string, number>(Object.values(txs.context.keys as Record<string, Json>).map((k) => [k.pubkey, k.seed]))
const secretOf = (seed: number) => new Uint8Array(32).fill(seed)

describe('solana_tx_vectors.json', () => {
    it('has transactions', () => {
        expect(txs.transactions.length).toBeGreaterThan(0)
    })

    it('names keys whose secrets are their seeds', () => {
        for (const [pub, seed] of seedOf) expect(encodeBase58(ed25519.getPublicKey(secretOf(seed)))).toBe(pub)
    })

    for (const c of txs.transactions as Json[]) {
        it(c.name, () => {
            const wire = base64.decode(c.wire_base64)
            const msgBytes = base64.decode(c.message_base64)
            const tx = parseTransaction(wire)
            const m = tx.message
            expect(hex.encode(encodeMessage(m))).toBe(hex.encode(msgBytes))
            expect(hex.encode(encodeTransaction(tx))).toBe(hex.encode(wire))
            expect(m.version).toBe(c.version)
            expect(m.recentBlockhash).toBe(c.recent_blockhash)
            expect(feePayer(m)).toBe(c.fee_payer)
            expect(m.header).toEqual({
                numRequiredSignatures: c.header.num_required_signatures,
                numReadonlySignedAccounts: c.header.num_readonly_signed_accounts,
                numReadonlyUnsignedAccounts: c.header.num_readonly_unsigned_accounts,
            })
            expect(m.accountKeys.length).toBe(c.account_keys.length)
            ;(c.account_keys as Json[]).forEach((k, i) => {
                expect([m.accountKeys[i], isSigner(m, i), isWritable(m, i)]).toEqual([k.pubkey, k.is_signer, k.is_writable])
            })
            expect(m.instructions.map((ix) => [ix.programIdIndex, ix.accounts, base64.encode(ix.data)])).toEqual(
                (c.instructions as Json[]).map((ix) => [ix.program_id_index, ix.accounts, ix.data_base64]),
            )
            expect(m.addressTableLookups).toEqual(
                (c.address_table_lookups as Json[]).map((l) => ({
                    accountKey: l.account_key,
                    writableIndexes: l.writable_indexes,
                    readonlyIndexes: l.readonly_indexes,
                })),
            )
            expect(tx.signatures.map(encodeBase58)).toEqual(c.signatures)
            verifySignatures(tx)

            // Looked-up addresses follow the static keys, writable ones
            // first, and none signs; an index past them all has no answer.
            const n = m.accountKeys.length
            const w = m.addressTableLookups.reduce((s, l) => s + l.writableIndexes.length, 0)
            const total = n + m.addressTableLookups.reduce((s, l) => s + l.writableIndexes.length + l.readonlyIndexes.length, 0)
            for (let i = n; i < total; i++) expect([isWritable(m, i), isSigner(m, i)], `looked-up ${i}`).toEqual([i < n + w, false])
            for (const i of [-1, total]) {
                expect(() => isWritable(m, i)).toThrow(RangeError)
                expect(() => isSigner(m, i)).toThrow(RangeError)
            }

            // Signing again with the seeded keys gives the same signatures,
            // each in its signer's slot: ed25519 is deterministic.
            const resigned = newTransaction(m)
            for (const k of m.accountKeys.slice(0, m.header.numRequiredSignatures).reverse()) {
                signTransaction(resigned, secretOf(seedOf.get(k)!))
            }
            expect(resigned.signatures.map(encodeBase58)).toEqual(c.signatures)

            // The rest compile to the bytes Rust signed, except a message with
            // lookups or with a key no instruction names: no instruction list
            // compiles to either.
            if (c.address_table_lookups.length > 0) return
            const ixs: Instruction[] = (c.built_instructions as Json[]).map((b) => ({
                programId: b.program_id,
                accounts: (b.accounts as Json[]).map((a) => ({ publicKey: a.pubkey, isSigner: a.is_signer, isWritable: a.is_writable })),
                data: base64.decode(b.data_base64),
            }))
            const named = new Set([feePayer(m), ...ixs.flatMap((ix) => [ix.programId, ...ix.accounts.map((a) => a.publicKey)])])
            if (named.size !== m.accountKeys.length) return
            const compiled = compileMessage(feePayer(m), m.recentBlockhash, ixs, c.version)
            expect(hex.encode(encodeMessage(compiled))).toBe(hex.encode(msgBytes))
        })
    }
})

describe('solana_account_vectors.json PDAs', () => {
    it('has accounts', () => {
        expect(accounts.accounts.length).toBeGreaterThan(0)
    })
    for (const a of accounts.accounts as Json[]) {
        it(a.name, () => {
            const seeds = (a.seeds_hex as string[]).map((s) => hex.decode(s))
            expect(findProgramAddress(seeds, accounts.program_id)).toEqual([a.address, a.bump])
            expect(createProgramAddress([...seeds, Uint8Array.of(a.bump)], accounts.program_id)).toBe(a.address)
            expect(isOnCurve(publicKeyBytes(a.address))).toBe(false)
        })
    }
})

describe('solana_codec_vectors.json', () => {
    it('is the schema this test expects', () => {
        expect(codec.version).toBe(4)
        for (const s of [
            'base58',
            'base58_refused',
            'compact_u16',
            'compact_u16_refused',
            'messages_refused',
            'messages_accepted',
            'transactions_refused',
            'create_program_address',
            'on_curve',
            'signatures',
            'compile',
            'builders',
        ]) {
            expect(codec[s].length, s).toBeGreaterThan(0)
        }
    })

    it('spells base58 as Go does', () => {
        for (const c of codec.base58 as Json[]) {
            const b = hex.decode(c.hex)
            expect(encodeBase58(b)).toBe(c.base58)
            expect(hex.encode(decodeBase58(c.base58, b.length))).toBe(c.hex)
        }
    })

    it('refuses the base58 Go refuses', () => {
        for (const c of codec.base58_refused as Json[]) {
            expect(() => decodeBase58(c.base58, c.size), c.about).toThrow()
            if (c.size === 32) expect(() => parsePublicKey(c.base58), c.about).toThrow()
        }
    })

    it('writes and reads each compact-u16 spelling as its value', () => {
        // As an instruction's data length, which sits at a fixed offset in a
        // message with two keys and one instruction.
        const at = 3 + 1 + 64 + 32 + 1 + 1 + 1
        for (const c of codec.compact_u16 as Json[]) {
            const msg = encodeMessage({
                version: 'legacy',
                header: { numRequiredSignatures: 1, numReadonlySignedAccounts: 0, numReadonlyUnsignedAccounts: 1 },
                accountKeys: ['11111111111111111111111111111112', '11111111111111111111111111111111'],
                recentBlockhash: '11111111111111111111111111111111',
                instructions: [{ programIdIndex: 1, accounts: [], data: new Uint8Array(c.value) }],
                addressTableLookups: [],
            })
            expect(hex.encode(msg.subarray(at, at + c.hex.length / 2)), String(c.value)).toBe(c.hex)
            expect(parseMessage(msg).instructions[0]!.data.length).toBe(c.value)
        }
    })

    it('refuses the compact-u16 spellings Go refuses', () => {
        for (const c of codec.compact_u16_refused as Json[]) {
            expect(() => parseMessage(base64.decode(c.message_base64)), c.about).toThrow(/length/)
        }
    })

    for (const c of codec.messages_refused as Json[]) {
        it(`refuses message ${c.name}`, () => {
            expect(() => parseMessage(base64.decode(c.base64)), c.about).toThrow()
        })
    }

    for (const c of codec.messages_accepted as Json[]) {
        it(`accepts message ${c.name}`, () => {
            expect(() => parseMessage(base64.decode(c.base64)), c.about).not.toThrow()
        })
    }

    for (const c of codec.transactions_refused as Json[]) {
        it(`refuses transaction ${c.name}`, () => {
            expect(() => parseTransaction(base64.decode(c.base64)), c.about).toThrow()
        })
    }

    for (const c of codec.signatures as Json[]) {
        it(`verifies signature ${c.name} as the runtime does`, () => {
            expect(verifyStrict(encodeBase58(hex.decode(c.key_hex)), hex.decode(c.message_hex), hex.decode(c.signature_hex)), c.about).toBe(c.valid)
        })
    }

    for (const c of codec.compile as Json[]) {
        it(`compiles ${c.name} as Go does`, () => {
            const ixs: Instruction[] = (c.instructions as Json[]).map((b) => ({
                programId: b.program_id,
                accounts: (b.accounts as Json[]).map((a) => ({ publicKey: a.pubkey, isSigner: a.is_signer, isWritable: a.is_writable })),
                data: base64.decode(b.data_base64),
            }))
            expect(base64.encode(encodeMessage(compileMessage(c.fee_payer, c.recent_blockhash, ixs, c.version)))).toBe(c.message_base64)
        })
    }

    const builders: Record<string, (a: Record<string, string>) => Instruction> = {
        set_compute_unit_limit: (a) => setComputeUnitLimit(Number(a.units)),
        set_compute_unit_price: (a) => setComputeUnitPrice(BigInt(a.micro_lamports!)),
        transfer_checked: (a) => transferChecked(a.source!, a.mint!, a.destination!, a.authority!, BigInt(a.amount!), Number(a.decimals)),
        mint_to: (a) => mintTo(a.mint!, a.destination!, a.authority!, BigInt(a.amount!)),
        create_associated_token_account_idempotent: (a) => createAssociatedTokenAccountIdempotent(a.payer!, a.owner!, a.mint!),
    }
    it('covers every builder', () => {
        expect(new Set((codec.builders as Json[]).map((c) => c.builder))).toEqual(new Set(Object.keys(builders)))
    })
    for (const c of codec.builders as Json[]) {
        it(`builds ${c.builder}(${Object.values(c.args).join(', ')}) as Go does`, () => {
            const ix = builders[c.builder]!(c.args)
            expect({
                program_id: ix.programId,
                accounts: ix.accounts.map((a) => ({ pubkey: a.publicKey, is_signer: a.isSigner, is_writable: a.isWritable })),
                data_base64: base64.encode(ix.data),
            }).toEqual(c.instruction)
        })
    }
    it('refuses compute-budget values their data cannot carry', () => {
        expect(() => setComputeUnitLimit(0xffffffff)).not.toThrow()
        expect(() => setComputeUnitLimit(0x100000000)).toThrow(RangeError)
        expect(() => setComputeUnitLimit(-1)).toThrow(RangeError)
        expect(() => setComputeUnitLimit(1.5)).toThrow(RangeError)
        expect(() => setComputeUnitPrice((1n << 64n) - 1n)).not.toThrow()
        expect(() => setComputeUnitPrice(1n << 64n)).toThrow(RangeError)
        expect(() => setComputeUnitPrice(-1n)).toThrow(RangeError)
    })

    it('derives program addresses as Go does', () => {
        for (const c of codec.create_program_address as Json[]) {
            const seeds = (c.seeds_hex as string[]).map((s) => hex.decode(s))
            if (c.address === '') {
                expect(() => createProgramAddress(seeds, c.program)).toThrow()
            } else {
                expect(createProgramAddress(seeds, c.program)).toBe(c.address)
            }
        }
    })

    it('finds the same points on the curve', () => {
        for (const c of codec.on_curve as Json[]) expect(isOnCurve(hex.decode(c.hex)), c.about).toBe(c.on_curve)
    })
})
