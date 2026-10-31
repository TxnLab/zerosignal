/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain step against the REAL @phala/dcap-qvl: the real capture, verified
// with Intel collateral recorded for its platform by
// sdk/scripts/record-collateral.mjs (testdata/attest/ds_collateral.json says
// where and when, and is re-recorded when the root CA CRL pin moves), at a time
// inside those documents' validity window. Only getCollateral is replaced, by
// the recording, so nothing reaches the network; parsing, the FMSPC read and
// verify are the library's own. Every other suite mocks the library, so this
// is the one place a signature is checked.

import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'

import { TEE_MODE_DSTACK_TDX, type TEECollateral, type TEEEvidenceBundle } from '@txnlab/zs-proto/inject'
import { reportData } from '@txnlab/zs-proto/attest'

import {
    COLLATERAL_TTL_MS,
    CollateralUnavailableError,
    StaleCollateralRejectedError,
    carriedChainVerifier,
    defaultVerifier,
    pccsChainVerifier,
} from '../src/tee/index.js'

const fetcher = vi.hoisted(() => ({ getCollateral: (async () => ({})) as (url: string, quote: Uint8Array) => Promise<unknown> }))
vi.mock('@phala/dcap-qvl', async (importOriginal) => {
    const real = ((await importOriginal()) as { default: Record<string, unknown> }).default
    return { default: { ...real, getCollateral: (url: string, q: Uint8Array) => fetcher.getCollateral(url, q) } }
})

const testdata = (p: string) => new URL(`../../testdata/${p}`, import.meta.url)
const quote = Uint8Array.from(Buffer.from(readFileSync(testdata('attest/ds_quote_hex.txt'), 'utf8').trim(), 'hex'))
const recorded = JSON.parse(readFileSync(testdata('attest/ds_collateral.json'), 'utf8')) as {
    valid_from: string
    valid_until: string
    verify_at: string
    collateral: TEECollateral
}
const AT = Date.parse(recorded.verify_at)
const at = (ms: number) => () => ms

/**
 * The recording in the shape getCollateral returns: DER and signatures as byte
 * arrays, and the asking quote's own chain attached.
 */
function fetched(q: Uint8Array): Record<string, unknown> {
    const c = recorded.collateral
    const bytes = (hex: string) => Array.from(Buffer.from(hex, 'hex'))
    const v = new DataView(q.buffer, q.byteOffset, q.byteLength)
    const inner = 770 + 384 + 64 + 2 + v.getUint16(770 + 384 + 64, true)
    const chain = Buffer.from(q.subarray(inner + 6, inner + 6 + v.getUint32(inner + 2, true))).toString('utf8')
    return {
        ...c,
        root_ca_crl: bytes(c.root_ca_crl),
        pck_crl: bytes(c.pck_crl),
        tcb_info_signature: bytes(c.tcb_info_signature),
        qe_identity_signature: bytes(c.qe_identity_signature),
        pck_certificate_chain: chain,
    }
}

/** As in tee-pccs.test.ts: a byte appended after the chain's last certificate. */
function junkAfterChain(q: Uint8Array): Uint8Array {
    const v = new DataView(q.buffer, q.byteOffset, q.byteLength)
    const inner = 770 + 384 + 64 + 2 + v.getUint16(770 + 384 + 64, true)
    const chainLen = v.getUint32(inner + 2, true)
    const end = inner + 6 + chainLen
    const out = new Uint8Array(q.length + 1)
    out.set(q.subarray(0, end))
    out[end] = 0x58
    out.set(q.subarray(end), end + 1)
    const w = new DataView(out.buffer)
    w.setUint32(632, v.getUint32(632, true) + 1, true)
    w.setUint32(766, v.getUint32(766, true) + 1, true)
    w.setUint32(inner + 2, chainLen + 1, true)
    return out
}

const UP_TO_DATE = { tcbStatus: 'UpToDate', advisoryIds: [] }

describe('the real library on the real capture', () => {
    it('verifies against the node-carried shape (hex strings)', async () => {
        expect(await carriedChainVerifier({ now: at(AT) })(quote, recorded.collateral)).toStrictEqual(UP_TO_DATE)
    })

    it('verifies against fetched collateral', async () => {
        fetcher.getCollateral = async (_url, q) => fetched(q)
        expect(await pccsChainVerifier({ now: at(AT) })(quote)).toStrictEqual(UP_TO_DATE)
    })

    it('refuses a quote whose signed body was altered', async () => {
        const forged = Uint8Array.from(quote)
        forged[48 + 520] = forged[48 + 520]! ^ 0xff
        await expect(carriedChainVerifier({ now: at(AT) })(forged, recorded.collateral)).rejects.toThrow()
    })

    it('refuses before the documents were issued, as a refusal and not an outage', async () => {
        // Also proves the clock reaches the library in seconds: in
        // milliseconds every date would read as long past.
        fetcher.getCollateral = async (_url, q) => fetched(q)
        const before = Date.parse(recorded.valid_from) - 24 * 60 * 60_000
        const err: unknown = await pccsChainVerifier({ now: at(before) })(quote).catch((e: unknown) => e)
        expect(String(err)).toMatch(/issue date is in the future/)
        expect(err).not.toBeInstanceOf(CollateralUnavailableError)
    })

    it('verifies a quote padded after its chain, which is why the cache is not keyed by those bytes', async () => {
        const padded = junkAfterChain(quote)
        expect(await carriedChainVerifier({ now: at(AT) })(padded, recorded.collateral)).toStrictEqual(UP_TO_DATE)

        // ...and it lands in the capture's slot: during an outage it is
        // served from the entry the capture seated, never handed onward.
        let up = true
        fetcher.getCollateral = async (_url, q) => (up ? fetched(q) : Promise.reject(new TypeError('fetch failed')))
        const t = { now: AT }
        const v = pccsChainVerifier({ now: () => t.now })
        await v(quote)
        up = false
        t.now += COLLATERAL_TTL_MS + 60_000
        expect(await v(padded)).toStrictEqual({ ...UP_TO_DATE, servedStale: true })
    })

    it("reports our cached documents' expiry during an outage as their refusal, not an outage", async () => {
        let up = true
        fetcher.getCollateral = async (_url, q) => (up ? fetched(q) : Promise.reject(new TypeError('fetch failed')))
        // Seated two days before the documents expire, asked a day after:
        // inside the stale bound, past Intel's window.
        const t = { now: Date.parse(recorded.valid_until) - 2 * 24 * 60 * 60_000 }
        const v = pccsChainVerifier({ now: () => t.now })
        expect(await v(quote)).toStrictEqual(UP_TO_DATE)
        up = false
        t.now += 3 * 24 * 60 * 60_000
        await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
    })

    it('carries defaultVerifier through the chain step to the release match', async () => {
        // The unpatched capture binds a key we do not hold, but the chain and
        // the measurement checks come first: the shipped policy stops it at
        // the missing compose, after the real chain step passed.
        fetcher.getCollateral = async (_url, q) => fetched(q)
        const v = await defaultVerifier({ now: at(AT) }).verify(ADVERTISED, captureBundle(), CAPTURE_NODE)
        expect(v.detail?.tcbStatus).toBe('UpToDate')
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.detail?.composeViolations).toEqual(['missing_app_compose'])
    })

    it("falls back to Intel's recorded set when the PCCS is unreachable", async () => {
        // Intel's root CA CRL is reissued about yearly, so the recording's is
        // usually months old at verify_at. The carried gate once held it to the
        // 14-day floor, and so refused every honest carried set.
        fetcher.getCollateral = async () => Promise.reject(new TypeError('fetch failed'))
        const v = await defaultVerifier({ now: at(AT) }).verify(
            ADVERTISED,
            { ...captureBundle(), collateral: recorded.collateral },
            CAPTURE_NODE,
        )
        expect(v.detail?.tcbStatus).toBe('UpToDate')
        expect(v.failureTag).toBe('measurement_mismatch')
    })
})

const CAPTURE_PUBKEY = 'age1ysu8p4akgwu3rj8h5hcqntxmmhum9rxuy5mz9xsxgkju5q42sd4sswf5t2'
const ADVERTISED = { mode: TEE_MODE_DSTACK_TDX, evidence_url: '/v1/zs/attestation' }
const CAPTURE_NODE = { operatorId: 42n, nodeId: 1n, ephemeralRecipientPubkey: CAPTURE_PUBKEY }

function captureBundle(): TEEEvidenceBundle {
    const pubkey = CAPTURE_PUBKEY
    return {
        mode: TEE_MODE_DSTACK_TDX,
        cpu_report: Buffer.from(quote).toString('base64'),
        gpu_eat: '',
        event_log: readFileSync(testdata('attest/ds_event_log.json'), 'utf8'),
        app_compose: '',
        posture: undefined,
        node_pubkey: pubkey,
        operator_id: 42,
        report_data: Buffer.from(reportData(pubkey, 42n)).toString('base64'),
        app_models: [],
        nonce: undefined,
        generated_at: new Date(AT - 60_000).toISOString(),
        refresh_seconds: 1200,
        stub: false,
    }
}
