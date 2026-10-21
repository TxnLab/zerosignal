/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's signature through the signer port, as proto/go/solana's
// sign_test.go and zsescrow's sign_vectors_test.go check it: every program
// transaction re-signed through the port, the Go-generated
// solana_sign_vectors.json replayed with each key's recorded secret, and
// every open-offer and relayed-ack verdict run through the complete
// functions. sdk/test replays the sign vectors again from the phrases.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { sha512 } from '@noble/hashes/sha2.js'
import { base64, hex } from '@scure/base'
import { describe, expect, it } from 'vitest'

import {
    type PublicKey,
    type Transaction,
    type TransactionSigner,
    MalformedMessageError,
    encodeBase58,
    encodeMessage,
    encodeTransaction,
    newTransaction,
    parseTransaction,
    signTransactionWith,
    verifyStrict,
} from '../src/solana/index.js'
import {
    type AckSpec,
    type OpenOfferSpec,
    AckRejectedError,
    Deployment,
    OfferRejectedError,
    completeOpenOffer,
    completeRelayedAck,
} from '../src/solana/zsescrow/index.js'
import { type UsageReceipt, parseReceiptJSON } from '../src/ticket/receipt.js'
import { concatBytes } from '../src/util/bytes.js'
import { ed25519 } from '../src/util/ed25519.js'

type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const here = path.dirname(fileURLToPath(import.meta.url))
const load = (name: string): Json => JSON.parse(fs.readFileSync(path.resolve(here, '..', '..', 'testdata', name), 'utf8')) as Json

const txs = load('solana_tx_vectors.json')
const signVectors = load('solana_sign_vectors.json')
const offerVectors = load('solana_open_offer_vectors.json')
const ackVectors = load('solana_ack_vectors.json')
const accountVectors = load('account_vectors.json')

/** A signer over 32-byte secrets, by address, that records each address it is asked to sign as. */
class SecretSigner implements TransactionSigner {
    readonly asked: string[] = []
    private readonly secrets = new Map<string, Uint8Array>()
    constructor(secrets: Uint8Array[]) {
        for (const s of secrets) this.secrets.set(encodeBase58(ed25519.getPublicKey(s)), s)
    }
    signTransactionMessage(address: string, message: Uint8Array): Promise<Uint8Array> {
        this.asked.push(address)
        const s = this.secrets.get(address)
        return s ? Promise.resolve(ed25519.sign(message, s)) : Promise.reject(new Error(`no key for ${address}`))
    }
}

const fixtureSecrets = new Map<string, Uint8Array>(
    Object.entries(txs.context.keys as Record<string, Json>).map(([name, k]) => [name, new Uint8Array(32).fill(k.seed)]),
)
const fixtureSigner = () => new SecretSigner([...fixtureSecrets.values()])

const receiptOf = (r: Json | null) => (r === null ? undefined : parseReceiptJSON(new TextEncoder().encode(JSON.stringify(r))))
const offerSpecOf = (s: Json): OpenOfferSpec => ({
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
                  // fold_no_receipt holds none, past the type, for the verifier to refuse.
                  receipt: receiptOf(s.fold.receipt) as UsageReceipt,
                  treasury: s.fold.treasury,
              },
          }
        : {}),
})
const ackSpecOf = (s: Json): AckSpec => ({
    payer: s.payer,
    operatorId: BigInt(s.operator_id),
    nodeId: BigInt(s.node_id),
    ticketId: hex.decode(s.ticket_id),
    receipt: receiptOf(s.receipt),
    treasury: s.treasury,
})

describe('signTransactionWith', () => {
    for (const c of txs.transactions as Json[]) {
        it(`re-signs ${c.name} through the port, last signer first`, async () => {
            const tx = parseTransaction(base64.decode(c.wire_base64))
            const resigned = newTransaction(tx.message)
            const signers = tx.message.accountKeys.slice(0, tx.message.header.numRequiredSignatures).reverse()
            const s = fixtureSigner()
            for (const k of signers) await signTransactionWith(resigned, k, s)
            expect(base64.encode(encodeTransaction(resigned))).toBe(c.wire_base64)
        })
    }

    describe('refuses', () => {
        const open = (txs.transactions as Json[]).find((t) => t.name === 'open')!
        const given = parseTransaction(base64.decode(open.wire_base64))
        const fresh = (): Transaction => ({ message: given.message, signatures: given.signatures.map((s) => s.slice()) })
        const [node, payer] = given.message.accountKeys as [PublicKey, PublicKey]
        const msg = encodeMessage(given.message)
        const nodeSig = ed25519.sign(msg, fixtureSecrets.get('node1_signing')!)
        const fixed = (sig: Uint8Array | undefined, err?: Error): TransactionSigner => ({
            signTransactionMessage: () => (err ? Promise.reject(err) : Promise.resolve(sig as Uint8Array)),
        })

        it('a key that signs nothing, without asking', async () => {
            const s = fixtureSigner()
            const nonSigner = given.message.accountKeys[given.message.header.numRequiredSignatures]!
            await expect(signTransactionWith(fresh(), nonSigner, s)).rejects.toThrow('is not a signer')
            expect(s.asked).toEqual([])
        })

        // R the identity point, S = k·a: the equation holds, so @noble's own
        // (cofactored) verify accepts it, but R is of small order, which the
        // runtime refuses.
        const payerSecret = fixtureSecrets.get('payer')!
        const identityR = (() => {
            const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(payerSecret)
            const r = ed25519.ExtendedPoint.ZERO.toRawBytes()
            let k = 0n
            const h = sha512(concatBytes(r, pointBytes, msg))
            for (let i = h.length - 1; i >= 0; i--) k = (k << 8n) | BigInt(h[i]!)
            let s = ed25519.etc.mod(k * scalar, ed25519.CURVE.n)
            const sBytes = new Uint8Array(32)
            for (let i = 0; i < 32; i++, s >>= 8n) sBytes[i] = Number(s & 0xffn)
            return concatBytes(r, sBytes)
        })()
        it("uses a case only the runtime's check refuses", () => {
            expect(ed25519.verify(identityR, msg, ed25519.getPublicKey(payerSecret))).toBe(true)
        })

        const boom = new Error('custody refused')
        it.each([
            ['a small-order R', fixed(identityR), 'does not verify'],
            ['a short signature', fixed(nodeSig.subarray(0, 63)), '63 bytes'],
            ['a long signature', fixed(new Uint8Array([...nodeSig, 0])), '65 bytes'],
            ["another key's signature", fixed(nodeSig), 'does not verify'],
            ['no signature', fixed(undefined), 'non-Uint8Array'],
            ['an empty signature', fixed(new Uint8Array()), '0 bytes'],
            ['a signer error', fixed(undefined, boom), 'custody refused'],
        ])('%s, leaving the slots as they were', async (_, signer, want) => {
            const t = fresh()
            const err = await signTransactionWith(t, payer, signer).then(
                () => undefined,
                (e: unknown) => e as Error,
            )
            expect(err?.message).toContain(want)
            if (want === 'custody refused') expect(err?.cause).toBe(boom)
            expect(t.signatures.map((s) => hex.encode(s))).toEqual(given.signatures.map((s) => hex.encode(s)))
        })

        it('one slot for two signers', async () => {
            const t = fresh()
            t.signatures = t.signatures.slice(0, 1)
            await expect(signTransactionWith(t, payer, fixtureSigner())).rejects.toThrow(MalformedMessageError)
        })

        // A slot past the signer count would go out with whatever it holds.
        it('three slots for two signers, without asking', async () => {
            const t = fresh()
            t.signatures = [...t.signatures, new Uint8Array(64)]
            const padded = t.signatures.map((s) => hex.encode(s))
            const inner = fixtureSigner()
            let asked = 0
            const counting = {
                signTransactionMessage: (address: string, message: Uint8Array) => {
                    asked++
                    return inner.signTransactionMessage(address, message)
                },
            }
            await expect(signTransactionWith(t, payer, counting)).rejects.toThrow(MalformedMessageError)
            expect(asked).toBe(0)
            expect(t.signatures.map((s) => hex.encode(s))).toEqual(padded)
        })

        it("fills the payer's slot and leaves the node's", async () => {
            const t = fresh()
            t.signatures[1] = new Uint8Array(64)
            await signTransactionWith(t, payer, fixtureSigner())
            expect(base64.encode(encodeTransaction(t))).toBe(open.wire_base64)
            expect(node).toBe(open.fee_payer)
        })
    })
})

describe('solana_sign_vectors.json', () => {
    const d = new Deployment(signVectors.program_id, signVectors.usdc_mint)
    // Each key's secret as recorded: the fixture's seed, or the seed
    // account_vectors.json derives from the phrase (sdk/test derives it).
    const secretOf = (k: Json): Uint8Array => {
        if (k.fixture) return fixtureSecrets.get(k.fixture)!
        const row = (accountVectors.solana as Json[]).find((r) => r.name === k.account)!
        return hex.decode(row.seed)
    }
    const signerOf = (k: Json) => {
        const secret = secretOf(k)
        expect(encodeBase58(ed25519.getPublicKey(secret))).toBe(k.address)
        return new SecretSigner([secret])
    }

    it('covers both sources in each group', () => {
        for (const g of ['offers', 'relayed_acks', 'own']) {
            expect(new Set((signVectors[g] as Json[]).map((c) => c.source)), g).toEqual(new Set(['fixture', 'built']))
        }
    })
    for (const c of signVectors.offers as Json[]) {
        it(`offer ${c.source} ${c.name}`, async () => {
            const got = await completeOpenOffer(d, base64.decode(c.offer_base64), offerSpecOf(c.spec), signerOf(c.signer))
            expect(base64.encode(got)).toBe(c.wire_base64)
        })
    }
    for (const c of signVectors.relayed_acks as Json[]) {
        it(`relayed ack ${c.source} ${c.name}`, async () => {
            const got = await completeRelayedAck(d, base64.decode(c.ack_base64), ackSpecOf(c.spec), signerOf(c.signer))
            expect(base64.encode(got)).toBe(c.wire_base64)
        })
    }
    for (const c of signVectors.own as Json[]) {
        it(`own ${c.source} ${c.name}`, async () => {
            const tx = parseTransaction(base64.decode(c.unsigned_base64))
            await signTransactionWith(tx, c.signer.address, signerOf(c.signer))
            expect(base64.encode(encodeTransaction(tx))).toBe(c.wire_base64)
        })
    }
    it("matches, for the program's own transactions, the wire Rust signed", () => {
        const rust = new Map((txs.transactions as Json[]).map((t) => [t.name, t.wire_base64]))
        const fixtures = [...signVectors.offers, ...signVectors.relayed_acks, ...signVectors.own].filter((c: Json) => c.source === 'fixture') as Json[]
        expect(fixtures.length).toBeGreaterThanOrEqual(6)
        for (const c of fixtures) expect(c.wire_base64, c.name).toBe(rust.get(c.name))
    })
})

// A message's transaction with every slot empty, as its builder hands it over
// before anyone signs. A message too short to name its signer count gets one
// slot, which the decode refuses either way.
function emptySlots(message: Uint8Array): Uint8Array {
    let n = 1
    if (message.length > 1 && (message[0]! & 0x80) !== 0) n = message[1]!
    else if (message.length > 0) n = message[0]!
    const out = new Uint8Array(1 + 64 * n + message.length)
    out[0] = n
    out.set(message, 1 + 64 * n)
    return out
}

describe('the complete functions sign only what passes', () => {
    const d = new Deployment(offerVectors.program_id, offerVectors.usdc_mint)
    it('read one deployment', () => {
        expect([ackVectors.program_id, ackVectors.usdc_mint]).toEqual([offerVectors.program_id, offerVectors.usdc_mint])
        expect((offerVectors.cases as Json[]).length).toBeGreaterThanOrEqual(40)
        expect((ackVectors.relayed_acks as Json[]).length).toBeGreaterThanOrEqual(30)
    })
    const run = async (c: Json, complete: (wire: Uint8Array, s: SecretSigner) => Promise<Uint8Array>, Rejected: typeof OfferRejectedError | typeof AckRejectedError) => {
        const s = fixtureSigner()
        const msg = base64.decode(c.message_base64)
        const out = await complete(emptySlots(msg), s).then(
            (wire) => ({ wire, err: undefined }),
            (err: unknown) => ({ wire: undefined, err }),
        )
        if (c.verdict === 'ok') {
            expect(out.err).toBeUndefined()
            expect(s.asked).toEqual([c.spec.payer])
            const tx = parseTransaction(out.wire!)
            expect(hex.encode(encodeMessage(tx.message))).toBe(hex.encode(msg))
            tx.signatures.forEach((sig, i) => {
                const k = tx.message.accountKeys[i]!
                if (k === c.spec.payer) expect(verifyStrict(k, msg, sig)).toBe(true)
                else expect(hex.encode(sig)).toBe('00'.repeat(64))
            })
            return
        }
        expect(s.asked).toEqual([])
        if (c.verdict === 'message.parse') {
            expect(out.err).toBeInstanceOf(Error)
            expect(out.err).not.toBeInstanceOf(Rejected)
            return
        }
        expect(out.err).toBeInstanceOf(Rejected)
        expect((out.err as InstanceType<typeof Rejected>).field).toBe(c.verdict)
    }
    for (const c of offerVectors.cases as Json[]) {
        it(`offer ${c.source} ${c.name}: ${c.verdict}`, () => run(c, (wire, s) => completeOpenOffer(d, wire, offerSpecOf(c.spec), s), OfferRejectedError))
    }
    for (const c of ackVectors.relayed_acks as Json[]) {
        it(`ack ${c.source} ${c.name}: ${c.verdict}`, () => run(c, (wire, s) => completeRelayedAck(d, wire, ackSpecOf(c.spec), s), AckRejectedError))
    }

    it('fails, and refuses nothing, when the signer signs as another key', async () => {
        const c = (signVectors.offers as Json[]).find((c) => c.name === 'open')!
        const impostor: TransactionSigner = { signTransactionMessage: (_, m) => Promise.resolve(ed25519.sign(m, fixtureSecrets.get('attacker')!)) }
        const err = await completeOpenOffer(d, base64.decode(c.offer_base64), offerSpecOf(c.spec), impostor).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect(err).not.toBeInstanceOf(OfferRejectedError)
        expect(String((err as Error).message)).toContain('does not verify')
    })

    it('decodes before it signs', async () => {
        const c = (signVectors.offers as Json[]).find((c) => c.name === 'open')!
        const offer = base64.decode(c.offer_base64)
        const s = fixtureSigner()
        await expect(completeOpenOffer(d, offer.subarray(0, offer.length - 1), offerSpecOf(c.spec), s)).rejects.toThrow('zsescrow: decode open offer')
        expect(s.asked).toEqual([])
    })
})
