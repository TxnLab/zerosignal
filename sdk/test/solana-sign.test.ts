/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// testdata/solana_sign_vectors.json through the SDK's own custody: each
// account key derived from its phrase by solanaKeyFromPhrase and signing
// through solanaSigner, as Go's generator signs through keystore.SolanaKeys.
// proto/ts replays the same file from the recorded seeds.

import { readFileSync } from 'node:fs'

import { base64, hex } from '@scure/base'
import { encodeBase58, encodeTransaction, parseTransaction, signTransactionWith } from '@txnlab/zs-proto/solana'
import { type AckSpec, type OpenOfferSpec, Deployment, completeOpenOffer, completeRelayedAck } from '@txnlab/zs-proto/solana/zsescrow'
import { parseReceiptJSON } from '@txnlab/zs-proto/ticket'
import * as ed25519 from '@noble/ed25519'
import { describe, expect, it } from 'vitest'

import { solanaKeyFromPhrase, solanaSigner } from '../src/accounts/solana.js'
import type { SolanaSigner } from '../src/ports.js'

type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const load = (name: string): Json => JSON.parse(readFileSync(new URL(`../../testdata/${name}`, import.meta.url), 'utf8')) as Json
const vectors = load('solana_sign_vectors.json')
const accounts = load('account_vectors.json')
const txs = load('solana_tx_vectors.json')

// Every case here carries its receipt: the complete functions sign only an accepted transaction.
const receiptOf = (r: Json) => parseReceiptJSON(new TextEncoder().encode(JSON.stringify(r)))
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
                  receipt: receiptOf(s.fold.receipt),
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

// An account key comes from its phrase; a fixture key's secret is its seed.
function signerOf(k: Json): SolanaSigner {
    if (k.account) {
        const row = (accounts.solana as Json[]).find((r) => r.name === k.account)!
        return solanaSigner(solanaKeyFromPhrase(row.phrase))
    }
    const seed = new Uint8Array(32).fill((txs.context.keys as Json)[k.fixture].seed)
    const publicKey = ed25519.getPublicKey(seed)
    return solanaSigner({ seed, publicKey, address: encodeBase58(publicKey) })
}

describe('solana_sign_vectors.json through solanaSigner', () => {
    const d = new Deployment(vectors.program_id, vectors.usdc_mint)
    const all = [...vectors.offers, ...vectors.relayed_acks, ...vectors.own] as Json[]

    it('signs as the phrases account_vectors.json pins', () => {
        const named = all.filter((c) => c.signer.account)
        expect(new Set(named.map((c) => c.signer.account))).toEqual(new Set(['client vector', 'solana-keygen 24 words', 'solana-keygen 12 words']))
        for (const c of named) expect(signerOf(c.signer).address, c.name).toBe(c.signer.address)
    })
    for (const c of vectors.offers as Json[]) {
        it(`offer ${c.source} ${c.name}`, async () => {
            const got = await completeOpenOffer(d, base64.decode(c.offer_base64), offerSpecOf(c.spec), signerOf(c.signer))
            expect(base64.encode(got)).toBe(c.wire_base64)
        })
    }
    for (const c of vectors.relayed_acks as Json[]) {
        it(`relayed ack ${c.source} ${c.name}`, async () => {
            const got = await completeRelayedAck(d, base64.decode(c.ack_base64), ackSpecOf(c.spec), signerOf(c.signer))
            expect(base64.encode(got)).toBe(c.wire_base64)
        })
    }
    for (const c of vectors.own as Json[]) {
        it(`own ${c.source} ${c.name}`, async () => {
            const tx = parseTransaction(base64.decode(c.unsigned_base64))
            const signer = signerOf(c.signer)
            await signTransactionWith(tx, signer.address, signer)
            expect(base64.encode(encodeTransaction(tx))).toBe(c.wire_base64)
        })
    }
})
