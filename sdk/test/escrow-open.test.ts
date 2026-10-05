/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import algosdk, { ABIMethod } from 'algosdk'
import { describe, expect, it } from 'vitest'

import {
    OPEN_METHOD_SIGNATURE,
    OpenGroupRejectedError,
    type OpenGroupSpec,
    type Signer,
    SignerAddressError,
    completeOpenGroup,
    decodeOpenGroup,
    decodeSignedGroup,
    verifyOpenGroup,
} from '../src/index.js'

interface Vectors {
    selectors: Record<string, string>
    open: {
        spec: {
            app_id: number
            app_address: string
            ticket_id_b64: string
            operator_id: number
            node_id: number
            max_price: number
            usdc_asset_id: number
            node_signing_addr: string
            payer_addr: string
            expires_at: number
            settlement_grace_seconds: number
        }
        cases: { name: string; group_b64: string; expected: string | null }[]
    }
}

const vectors = JSON.parse(
    readFileSync(fileURLToPath(new URL('../../testdata/escrow_group_vectors.json', import.meta.url)), 'utf8'),
) as Vectors

const s = vectors.open.spec
const spec: OpenGroupSpec = {
    appId: BigInt(s.app_id),
    appAddress: s.app_address,
    ticketIdRaw: algosdk.base64ToBytes(s.ticket_id_b64),
    operatorId: BigInt(s.operator_id),
    nodeId: BigInt(s.node_id),
    maxPrice: BigInt(s.max_price),
    usdcAssetId: BigInt(s.usdc_asset_id),
    nodeSigningAddr: s.node_signing_addr,
    payerAddr: s.payer_addr,
    expiresAt: BigInt(s.expires_at),
    settlementGraceSeconds: BigInt(s.settlement_grace_seconds),
}
const validB64 = vectors.open.cases.find((c) => c.name === 'valid')!.group_b64

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

function verdict(b64: string): string | null {
    try {
        verifyOpenGroup(decodeSignedGroup(b64), spec)
        return null
    } catch (err) {
        if (err instanceof OpenGroupRejectedError) return err.field
        throw err
    }
}

describe('open group vectors', () => {
    it('hard-codes the deployed open() signature', () => {
        expect(hex(ABIMethod.fromSignature(OPEN_METHOD_SIGNATURE).getSelector())).toBe(vectors.selectors.open)
    })
    it('covers every check', () => {
        expect(vectors.open.cases.length).toBeGreaterThan(30)
    })
    for (const c of vectors.open.cases) {
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

describe('completeOpenGroup', () => {
    it('signs only the transfer and sends the node half as the node encoded it', async () => {
        const signer = payerSigner()
        const out = await completeOpenGroup(validB64, spec, signer)
        expect(signer.calls).toEqual([[0]])
        const node = decodeOpenGroup(validB64)[1]!.bytes
        expect(hex(out.signedGroup.subarray(out.signedGroup.length - node.length))).toBe(hex(node))
        const decoded = decodeOpenGroup(validB64).map((m) => m.stxn.txn)
        expect(out.txids).toEqual(decoded.map((t) => t.txID()))
        expect(out.groupId).toMatch(/^[A-Z2-7]{52}$/)
    })

    it('signs the canonical transfer when the node sent explicit zeros', async () => {
        // algod drops the explicit zero before hashing, so the payer's signed
        // txn must be the one the honest gid commits to.
        const zeroFee = vectors.open.cases.find((c) => c.name === 'payer_explicit_zero_fee')!.group_b64
        const out = await completeOpenGroup(zeroFee, spec, payerSigner())
        const honest = await completeOpenGroup(validB64, spec, payerSigner())
        expect(out.txids).toEqual(honest.txids)
        expect(out.groupId).toBe(honest.groupId)
    })

    it('signs nothing for a group that fails a check', async () => {
        const signer = payerSigner()
        const bad = vectors.open.cases.find((c) => c.name === 'payer_rekey')!.group_b64
        await expect(completeOpenGroup(bad, spec, signer)).rejects.toBeInstanceOf(OpenGroupRejectedError)
        expect(signer.calls).toEqual([])
    })

    it('refuses a signer for another account before decoding', async () => {
        const signer = payerSigner(s.node_signing_addr)
        await expect(completeOpenGroup(validB64, spec, signer)).rejects.toBeInstanceOf(SignerAddressError)
        expect(signer.calls).toEqual([])
    })

    it('refuses a group that is not two txns', () => {
        const one = vectors.open.cases.find((c) => c.name === 'size_one')!.group_b64
        expect(() => decodeOpenGroup(one)).toThrow(/want 2/)
        expect(() => decodeOpenGroup('')).toThrow(/empty/)
    })
})
