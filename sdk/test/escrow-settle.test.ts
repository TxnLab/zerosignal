/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import algosdk, { ABIMethod } from 'algosdk'
import { describe, expect, it } from 'vitest'

import {
    SETTLE_METHOD_SIGNATURE,
    SettleGroupRejectedError,
    type SettleGroupSpec,
    type Signer,
    SignerAddressError,
    completeSettleGroup,
    decodeSettleGroup,
    decodeSignedGroup,
    verifySettleGroup,
} from '../src/index.js'

interface Vectors {
    selectors: Record<string, string>
    settle: {
        spec: {
            app_id: number
            ticket_id_b64: string
            amount_charged: number
            receipt_digest_b64: string
            ttft_ms: number
            decode_ms: number
            input_count: number
            output_count: number
            output_usage_type: number
            aux_output_usage_type: number
            aux_output_count: number
            payer_addr: string
            operator_signing_addr: string
        }
        cases: { name: string; group_b64: string; expected: string | null }[]
        completed: { payer_seed: number; encoded: string }
    }
}

const vectors = JSON.parse(
    readFileSync(fileURLToPath(new URL('../../testdata/escrow_group_vectors.json', import.meta.url)), 'utf8'),
) as Vectors

const s = vectors.settle.spec
const spec: SettleGroupSpec = {
    appId: BigInt(s.app_id),
    ticketIdRaw: algosdk.base64ToBytes(s.ticket_id_b64),
    amountCharged: BigInt(s.amount_charged),
    receiptDigest: algosdk.base64ToBytes(s.receipt_digest_b64),
    ttftMs: BigInt(s.ttft_ms),
    decodeMs: BigInt(s.decode_ms),
    inputCount: BigInt(s.input_count),
    outputCount: BigInt(s.output_count),
    outputUsageType: BigInt(s.output_usage_type),
    auxOutputUsageType: BigInt(s.aux_output_usage_type),
    auxOutputCount: BigInt(s.aux_output_count),
    payerAddr: s.payer_addr,
    operatorSigningAddr: s.operator_signing_addr,
}
const caseB64 = (name: string) => vectors.settle.cases.find((c) => c.name === name)!.group_b64
const validB64 = caseB64('valid')

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

function verdict(b64: string): string | null {
    try {
        verifySettleGroup(decodeSignedGroup(b64), spec)
        return null
    } catch (err) {
        if (err instanceof SettleGroupRejectedError) return err.field
        throw err
    }
}

describe('settle group vectors', () => {
    it('hard-codes the deployed settle() signature', () => {
        expect(hex(ABIMethod.fromSignature(SETTLE_METHOD_SIGNATURE).getSelector())).toBe(vectors.selectors.settle)
    })
    it('covers every check', () => {
        expect(vectors.settle.cases.length).toBeGreaterThan(50)
    })
    for (const c of vectors.settle.cases) {
        it(c.name, () => {
            expect(verdict(c.group_b64)).toBe(c.expected)
        })
    }
})

function payerSigner(address = s.payer_addr): Signer & { calls: number[][] } {
    const calls: number[][] = []
    return {
        address,
        calls,
        signBytes: () => Promise.reject(new Error('unused')),
        signTransactions: async (txns, idx) => {
            calls.push(idx)
            return idx.map((i) => algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn: txns[i]!, sig: new Uint8Array(64).fill(7) })))
        },
    }
}

describe('completeSettleGroup', () => {
    it('signs only the ack and sends the operator half first, as the node encoded it', async () => {
        const signer = payerSigner()
        const out = await completeSettleGroup(validB64, spec, signer)
        expect(signer.calls).toEqual([[1]])
        const [op, ack] = decodeSettleGroup(validB64).map((m) => m)
        expect(hex(out.signedGroup.subarray(0, op!.bytes.length))).toBe(hex(op!.bytes))
        expect(out.txid).toBe(ack!.stxn.txn.txID())
        expect(out.payerFeeMicroalgos).toBe(0n)
        expect(out.feeMicroalgos).toBe(op!.stxn.txn.fee)
        expect(out.groupId).toMatch(/^[A-Z2-7]{52}$/)
    })

    it('signs the canonical ack when the node sent an explicit zero fee', async () => {
        const out = await completeSettleGroup(caseB64('payer_explicit_zero_fee'), spec, payerSigner())
        const honest = await completeSettleGroup(validB64, spec, payerSigner())
        expect(out.txid).toBe(honest.txid)
        expect(out.groupId).toBe(honest.groupId)
    })

    it('signs nothing for a group that fails a check, and says which', async () => {
        const signer = payerSigner()
        const err = await completeSettleGroup(caseB64('payer_rekey'), spec, signer).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(SettleGroupRejectedError)
        expect((err as SettleGroupRejectedError).field).toBe('payer.rekeyTo')
        expect((err as Error).message).toMatch(/^escrow: settle group rejected \[payer\.rekeyTo\]: /)
        expect(signer.calls).toEqual([])
    })

    it('refuses a signer for another account before decoding', async () => {
        const signer = payerSigner(s.operator_signing_addr)
        await expect(completeSettleGroup(validB64, spec, signer)).rejects.toBeInstanceOf(SignerAddressError)
        expect(signer.calls).toEqual([])
    })

    // A node that takes the settle ack decodes the group with Go's
    // DecodeSettleGroup, so the payer must write Go's EncodeSettleGroup bytes.
    // The vector is Go's CompletePresignedSettleGroup under the same payer key.
    it("encodes the completed group as Go's EncodeSettleGroup, byte for byte", async () => {
        const c = vectors.settle.completed
        const sk = new Uint8Array(64)
        sk.set(new Uint8Array(32).fill(c.payer_seed))
        sk.set(algosdk.decodeAddress(s.payer_addr).publicKey, 32)
        const real: Signer = {
            address: s.payer_addr,
            signBytes: () => Promise.reject(new Error('unused')),
            signTransactions: async (txns, idx) => idx.map((i) => algosdk.signTransaction(txns[i]!, sk).blob),
        }
        const out = await completeSettleGroup(validB64, spec, real)
        expect(out.encoded).toBe(c.encoded)
        expect(hex(algosdk.base64ToBytes(out.encoded))).toBe(`92${hex(out.signedGroup)}`)
        expect(decodeSettleGroup(out.encoded)[1]!.stxn.txn.txID()).toBe(out.txid)
    })

    it('refuses an empty payload or a group that is not two txns, as a plain error', () => {
        expect(() => decodeSettleGroup('')).toThrow(/empty/)
        expect(() => decodeSettleGroup(caseB64('size_one'))).toThrow(/want 2/)
        expect(() => decodeSettleGroup('')).not.toThrow(SettleGroupRejectedError)
    })
})
