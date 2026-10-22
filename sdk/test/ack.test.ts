/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// ackSettle, judgeClaim and judgeSolanaClaim, checked against
// testdata/ack_settle_vectors.json, which Go's twins generate; then
// checkReceipt, settleArgsOf and settleGroupSpecOf.

import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import algosdk from 'algosdk'

import { hex } from '@scure/base'
import { TICKET_PENDING_BY_OPERATOR, claimFromReceipt, claimHash } from '@txnlab/zs-proto/solana/zsescrow'
import { type Ticket, type UsageReceipt, receiptSigDigest, signReceipt } from '@txnlab/zs-proto/ticket'

import {
    type AckSettlePorts,
    type ClaimVerdict,
    discardLogger,
    SettleGroupRejectedError,
    type SettleArgs,
    type SettleGroupSpec,
    type TicketBoxView,
    ackSettle,
    checkReceipt,
    judgeClaim,
    judgeSolanaClaim,
    settleArgsOf,
    settleGroupSpecOf,
} from '../src/index.js'

interface Scenario {
    name: string
    atomic: boolean
    spec: string
    group: string
    claim: string
    standalone: string
    freeze: string
    half: string
    resolves_frozen: boolean
    want: {
        calls: string[]
        txid: string
        fee_microalgos: number
        group_rejected: boolean
        claim: ClaimVerdict
        payer_settle: boolean
        frozen: boolean
        result: string
    }
}

interface VectorSettle {
    amount_charged: number
    receipt_digest: string
    ttft_ms: number
    decode_ms: number
    input_tokens: number
    output_tokens: number
    output_usage_type: number
    aux_output_usage_type: number
    aux_output_count: number
}

interface VectorBox {
    status: number
    pending_by: number
    expires_at: number
    settlement_grace_seconds: number
    pending_amount: number
    pending_digest: string
    pending_ttft_ms: number
    pending_decode_ms: number
    pending_input_count: number
    pending_output_count: number
    pending_output_usage_type: number
    pending_aux_output_usage_type: number
    pending_aux_output_count: number
}

interface Claim {
    name: string
    settle: VectorSettle
    box: VectorBox | null
    verdict: ClaimVerdict
}

interface SolanaClaim {
    name: string
    settle: VectorSettle
    ticket: { status: number; pending_amount: number; claim_hash: string } | null
    verdict: ClaimVerdict
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/ack_settle_vectors.json', import.meta.url), 'utf8'),
) as { scenarios: Scenario[]; claims: Claim[]; solana_claims: SolanaClaim[] }

const groupErr = new Error('group submit')
const standaloneErr = new Error('standalone submit')
const freezeErr = new Error('freeze submit')
const halfErr = new Error('half submit')

// The same scripted ports as Go's runAckSettleScenario. A scenario without a
// claim scripts no claim port, which reads nothing, one without a freeze no
// freeze port, which freezes through standalone, and one without
// resolves_frozen no resolvesFrozen port, which sends no freeze and no half.
function scripted(
    sc: Pick<Scenario, 'spec' | 'group' | 'standalone'> & { claim?: string; freeze?: string; half?: string; resolves_frozen?: boolean },
    calls: string[],
): AckSettlePorts {
    const { claim, freeze, half, resolves_frozen: resolves } = sc
    return {
        ...(freeze !== undefined && {
            freeze: async () => {
                calls.push('freeze')
                if (freeze === 'error') throw freezeErr
                return { txid: 'FREEZETX', payerFeeMicroalgos: 1000n }
            },
        }),
        ...(half !== undefined && {
            half: async () => {
                calls.push('half')
                if (half === 'error') throw halfErr
                return { txid: 'HALFTX', payerFeeMicroalgos: 1000n }
            },
        }),
        ...(resolves !== undefined && { resolvesFrozen: async () => resolves }),
        ...(claim !== undefined && {
            claim: async () => {
                calls.push('claim')
                if (claim === 'error') throw new Error('box read')
                return claim as ClaimVerdict
            },
        }),
        spec: async () => {
            calls.push('spec')
            if (sc.spec === 'error') throw new Error('spec')
            return {} as SettleGroupSpec
        },
        submitGroup: async () => {
            calls.push('group')
            const rejection = new SettleGroupRejectedError('payer.rekeyTo', 'scripted')
            if (sc.group === 'rejected') throw rejection
            if (sc.group === 'rejected_wrapped') throw new Error('submit', { cause: rejection })
            if (sc.group === 'error') throw groupErr
            return { txid: 'GROUPTX', payerFeeMicroalgos: 0n }
        },
        standalone: async () => {
            calls.push('standalone')
            if (sc.standalone === 'error') throw standaloneErr
            return { txid: 'STANDALONETX', payerFeeMicroalgos: 5000n }
        },
    }
}

describe('ackSettle vectors', () => {
    it('covers every scenario', () => expect(vectors.scenarios.length).toBeGreaterThan(0))
    it.each(vectors.scenarios.map((s) => [s.name, s] as const))('%s', async (_name, sc) => {
        const calls: string[] = []
        const res = await ackSettle({ atomic: sc.atomic, ...scripted(sc, calls) })
        const errs = new Map<unknown, string>([
            [groupErr, 'group'],
            [standaloneErr, 'standalone'],
            [freezeErr, 'freeze'],
            [halfErr, 'half'],
        ])
        const result = res.err === undefined ? 'ok' : (errs.get(res.err) ?? 'other')
        expect({
            calls,
            txid: res.txid,
            fee_microalgos: res.feeMicroalgos,
            group_rejected: res.groupRejected,
            claim: res.claim ?? '',
            payer_settle: res.payerSettle ?? false,
            frozen: res.frozen ?? false,
            result,
        }).toEqual(sc.want)
    })
})

const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'))

function boxOf(b: VectorBox): TicketBoxView {
    return {
        status: b.status,
        pendingBy: b.pending_by,
        expiresAt: BigInt(b.expires_at),
        settlementGraceSeconds: BigInt(b.settlement_grace_seconds),
        pendingAmount: BigInt(b.pending_amount),
        pendingDigest: b64(b.pending_digest),
        pendingTtftMs: BigInt(b.pending_ttft_ms),
        pendingDecodeMs: BigInt(b.pending_decode_ms),
        pendingInputCount: BigInt(b.pending_input_count),
        pendingOutputCount: BigInt(b.pending_output_count),
        pendingOutputUsageType: b.pending_output_usage_type,
        pendingAuxOutputUsageType: b.pending_aux_output_usage_type,
        pendingAuxOutputCount: BigInt(b.pending_aux_output_count),
    }
}

describe('judgeClaim vectors', () => {
    it('covers every verdict a box can give', () => {
        expect(new Set(vectors.claims.map((c) => c.verdict))).toEqual(new Set(['none', 'open', 'agrees', 'overclaims', 'contradicts']))
    })
    it.each(vectors.claims.map((c) => [c.name, c] as const))('%s', (_name, c) => {
        expect(judgeClaim(argsOf(c.settle), c.box === null ? null : boxOf(c.box))).toBe(c.verdict)
    })
})

function argsOf(s: VectorSettle): SettleArgs {
    return {
        amountCharged: BigInt(s.amount_charged),
        receiptDigest: b64(s.receipt_digest),
        ttftMs: BigInt(s.ttft_ms),
        decodeMs: BigInt(s.decode_ms),
        inputTokens: BigInt(s.input_tokens),
        outputTokens: BigInt(s.output_tokens),
        outputUsageType: s.output_usage_type,
        auxOutputUsageType: s.aux_output_usage_type,
        auxOutputCount: BigInt(s.aux_output_count),
    }
}

describe('judgeSolanaClaim vectors', () => {
    it('covers every verdict a ticket can give', () => {
        expect(new Set(vectors.solana_claims.map((c) => c.verdict))).toEqual(new Set(['none', 'open', 'agrees', 'overclaims', 'contradicts']))
    })
    it.each(vectors.solana_claims.map((c) => [c.name, c] as const))('%s', (_name, c) => {
        const t = c.ticket === null ? null : { status: c.ticket.status, pendingAmount: BigInt(c.ticket.pending_amount), claimHash: hex.decode(c.ticket.claim_hash) }
        expect(judgeSolanaClaim(argsOf(c.settle), t)).toBe(c.verdict)
    })

    // Go's types rule these out; a host journal's JSON doesn't.
    it('reads args it cannot hash as contradicting the claim', () => {
        const c = vectors.solana_claims.find((c) => c.verdict === 'agrees')!
        const t = { status: c.ticket!.status, pendingAmount: BigInt(c.ticket!.pending_amount), claimHash: hex.decode(c.ticket!.claim_hash) }
        const a = argsOf(c.settle)
        expect(judgeSolanaClaim({ ...a, receiptDigest: a.receiptDigest.subarray(0, 31) }, t)).toBe('contradicts')
        expect(judgeSolanaClaim({ ...a, ttftMs: 1n << 64n }, t)).toBe('contradicts')
    })

    // The claim the payer judges must be the one the node's first half
    // hashes, which zs-proto builds from the receipt; a field swapped in the
    // mapping would read every honest claim as a contradiction.
    it('agrees with the claim the node hashes from the receipt', () => {
        const r: UsageReceipt = {
            ticket_id: 'AAAAAAAAAAAAAAAAAAAAAA==',
            actual_input_count: 11,
            actual_output_count: 13,
            amount_charged: 17,
            ttft_ms: 19,
            decode_ms: 23,
            body_hash: 'a'.repeat(64),
            input_usage_type: 1,
            output_usage_type: 1,
            aux_output_usage_type: 2,
            aux_output_count: 29,
            cached_input_count: 0,
        }
        const t = { status: TICKET_PENDING_BY_OPERATOR, pendingAmount: 17n, claimHash: claimHash(claimFromReceipt(r)) }
        expect(judgeSolanaClaim(settleArgsOf(r), t)).toBe('agrees')
    })
})

describe('ackSettle without a claim port', () => {
    // A host's own ports may not read the box: the ack then goes out as before.
    it('acks standalone and reports no claim', async () => {
        const calls: string[] = []
        const res = await ackSettle({ atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, calls) })
        expect(calls).toEqual(['standalone'])
        expect(res).toMatchObject({ txid: 'STANDALONETX', claim: '' })
    })

    // Nor may they size a freeze: an over-claim is then frozen through the
    // plain standalone settle, which overpays but still freezes.
    it('freezes through standalone without a freeze port', async () => {
        const calls: string[] = []
        const res = await ackSettle({
            atomic: false,
            ...scripted({ spec: 'ok', group: 'ok', claim: 'overclaims', standalone: 'ok', resolves_frozen: true }, calls),
        })
        expect(calls).toEqual(['claim', 'standalone'])
        expect(res).toMatchObject({ txid: 'STANDALONETX', claim: 'overclaims', frozen: true })
    })

    // Ports that can't say whether the escrow resolves a frozen ticket send
    // neither a freeze nor the half after a failed group, as on an escrow
    // without resolveFrozen.
    it.each([
        ['no resolvesFrozen port', undefined],
        ['a resolvesFrozen port that rejects', 'rejects'],
    ] as const)('sends no freeze and no half with %s', async (_name, how) => {
        for (const [atomic, group, claim] of [
            [false, 'ok', 'overclaims'],
            [true, 'error', 'overclaims'],
            [true, 'error', 'open'],
        ] as const) {
            const calls: string[] = []
            const ports = scripted({ spec: 'ok', group, claim, standalone: 'ok', freeze: 'ok', half: 'ok' }, calls)
            if (how === 'rejects') ports.resolvesFrozen = async () => Promise.reject(new Error('algod down'))
            const res = await ackSettle({ atomic, ...ports })
            expect(calls.filter((c) => c === 'freeze' || c === 'half' || c === 'standalone'), `${group} ${claim}`).toEqual([])
            expect(res.payerSettle ?? false).toBe(false)
        }
    })
})

function keypair() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const jwk = publicKey.export({ format: 'jwk' })
    return {
        pub: new Uint8Array(Buffer.from(jwk.x!, 'base64url')),
        signer: { signBytes: async (_a: string, msg: Uint8Array) => new Uint8Array(sign(null, msg, privateKey)) },
    }
}

const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest())
const body = new TextEncoder().encode('hello world')

const TICKET = { ticket_id: 'c2l4dGVlbi1ieXRlLWlkIQ==', max_price: 5000 } as Ticket

const IDS = {
    appId: 9n,
    ticketIdRaw: new Uint8Array(16),
    payerAddr: algosdk.encodeAddress(new Uint8Array(32).fill(1)),
    operatorSigningAddr: algosdk.encodeAddress(new Uint8Array(32).fill(2)),
}

async function signedReceipt(over: Partial<UsageReceipt> = {}) {
    const k = keypair()
    const r: UsageReceipt = {
        ticket_id: TICKET.ticket_id,
        actual_input_count: 42,
        actual_output_count: 17,
        amount_charged: 2600,
        ttft_ms: 120,
        decode_ms: 900,
        body_hash: Buffer.from(sha256(body)).toString('hex'),
        input_usage_type: 1,
        output_usage_type: 1,
        aux_output_usage_type: 2,
        aux_output_count: 3,
        cached_input_count: 0,
        ...over,
    }
    await signReceipt(r, k.signer, 'ADDR')
    return { r, pub: k.pub }
}

describe('checkReceipt', () => {
    it('journals a verified receipt before the ack, and acks only when submit runs', async () => {
        const { r, pub } = await signedReceipt()
        const order: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, order) },
            journal: () => void order.push('journal'),
        })
        expect(check.violation).toBeNull()
        expect(order).toEqual(['journal'])
        const settled = await check.submit!()
        expect(order).toEqual(['journal', 'standalone'])
        expect(settled).toMatchObject({ txid: 'STANDALONETX', kind: 'payer_ack', excluded: false })
    })

    it('reports an atomic settle as atomic', async () => {
        const { r, pub } = await signedReceipt()
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, []) },
        })
        expect(await check.submit!()).toMatchObject({ txid: 'GROUPTX', kind: 'atomic', excluded: false })
    })

    // Go's settledAtomically: a group that failed to submit and was followed
    // by the payer's own settle, the freeze or the half, is the payer's ack.
    it.each([
        ['a freeze of a claim above the receipt', { claim: 'overclaims', freeze: 'ok' }, 'FREEZETX', true],
        ["the payer's half on an open box", { claim: 'open', half: 'ok' }, 'HALFTX', false],
    ] as const)('reports %s after a failed group as the payer ack', async (_name, ports, txid, frozen) => {
        const { r, pub } = await signedReceipt()
        const calls: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'error', standalone: 'ok', resolves_frozen: true, ...ports }, calls) },
        })
        const settled = await check.submit!()
        expect(settled).toMatchObject({ txid, kind: 'payer_ack', payerSettle: true, frozen, groupRejected: false })
        expect(settled.err).toBeUndefined()
        expect(calls).toEqual(['spec', 'group', 'claim', frozen ? 'freeze' : 'half'])
    })

    it('bars the node after the ack when its group was refused', async () => {
        const { r, pub } = await signedReceipt()
        const order: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'rejected_wrapped', standalone: 'ok' }, order) },
            excludeNode: (rejection) => order.push(`exclude ${rejection.field}`),
        })
        const settled = await check.submit!()
        expect(order).toEqual(['spec', 'group', 'standalone', 'exclude payer.rekeyTo'])
        expect(settled).toMatchObject({ groupRejected: true, excluded: true, kind: 'payer_ack' })
        expect(settled.rejection).toBeInstanceOf(SettleGroupRejectedError)
    })

    it('settles anyway when barring the node throws', async () => {
        const { r, pub } = await signedReceipt()
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: true, ...scripted({ spec: 'ok', group: 'rejected', standalone: 'ok' }, []) },
            excludeNode: () => {
                throw new Error('store')
            },
        })
        expect(await check.submit!()).toMatchObject({ txid: 'STANDALONETX', groupRejected: true, excluded: false })
    })

    it('neither journals nor acks a receipt that fails its checks', async () => {
        const { r, pub } = await signedReceipt()
        const calls: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(new TextEncoder().encode('other body')),
            ack: { atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, calls) },
            journal: () => void calls.push('journal'),
        })
        expect(check).toMatchObject({ violation: 'body_hash', submit: null })
        expect(calls).toEqual([])
    })

    it('checks a receipt with no escrow to ack', async () => {
        const { r, pub } = await signedReceipt()
        const journaled: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: null,
            journal: () => void journaled.push('journal'),
        })
        expect(check).toEqual({ violation: null, submit: null })
        expect(journaled).toEqual([])
    })
})

describe('settleArgsOf / settleGroupSpecOf', () => {
    it('carries every co-signed value from the receipt, in its own slot', async () => {
        const { r } = await signedReceipt()
        expect(settleArgsOf(r)).toEqual({
            amountCharged: 2600n,
            receiptDigest: receiptSigDigest(r),
            ttftMs: 120n,
            decodeMs: 900n,
            inputTokens: 42n,
            outputTokens: 17n,
            outputUsageType: 1,
            auxOutputUsageType: 2,
            auxOutputCount: 3n,
        })
        expect(settleGroupSpecOf(r, IDS)).toEqual({
            ...IDS,
            amountCharged: 2600n,
            receiptDigest: receiptSigDigest(r),
            ttftMs: 120n,
            decodeMs: 900n,
            inputCount: 42n,
            outputCount: 17n,
            outputUsageType: 1n,
            auxOutputUsageType: 2n,
            auxOutputCount: 3n,
        })
    })

    // A malformed id is the payer's mistake. Built into a spec it would refuse
    // an honest node's group and bar the node; thrown, the ack goes standalone.
    it.each([
        ['a ticket id of the wrong length', { ticketIdRaw: new Uint8Array(15) }],
        ['a payer that is not an address', { payerAddr: 'PAYER' }],
        ['an operator signing address that is not one', { operatorSigningAddr: '' }],
    ])('refuses %s', async (_name, over) => {
        const { r } = await signedReceipt()
        expect(() => settleGroupSpecOf(r, { ...IDS, ...over })).toThrow()
    })
})

describe('checkReceipt journal', () => {
    async function run(journal: () => void | Promise<void>, order: string[]) {
        const { r, pub } = await signedReceipt()
        const warned: string[] = []
        const check = checkReceipt({
            receipt: r,
            ticket: TICKET,
            signingKey: pub,
            computedHash: sha256(body),
            ack: { atomic: false, ...scripted({ spec: 'ok', group: 'ok', standalone: 'ok' }, order) },
            journal,
            log: { ...discardLogger, warn: (msg) => warned.push(msg) },
        })
        return { settled: await check.submit!(), warned }
    }

    it('waits for an async journal before the ack', async () => {
        const order: string[] = []
        await run(async () => {
            await new Promise((r) => setTimeout(r, 5))
            order.push('journal')
        }, order)
        expect(order).toEqual(['journal', 'standalone'])
    })

    it.each([
        [
            'throws',
            () => {
                throw new Error('disk')
            },
        ],
        ['rejects', () => Promise.reject(new Error('disk'))],
    ])('acks anyway when the journal %s, and logs it', async (_name, journal) => {
        const order: string[] = []
        const { settled, warned } = await run(journal, order)
        expect(order).toEqual(['standalone'])
        expect(settled.txid).toBe('STANDALONETX')
        expect(warned).toEqual(['receipt journal failed; acking anyway'])
    })
})
