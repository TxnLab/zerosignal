/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A failed import of @phala/dcap-qvl. Its own file because the SDK memoizes
// the import for the whole module, failure included.

import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { TEE_MODE_DSTACK_TDX, type TEECollateral, type TEEEvidenceBundle } from '@txnlab/zs-proto/inject'
import { reportData } from '@txnlab/zs-proto/attest'

import { BundleVerifier } from '../src/tee/index.js'

// The first two imports fail, as a browser's chunk fetch can; any later one
// succeeds with a library that would pass everything. So a carried rung that
// re-imported within the same verification would pass the node on its own
// collateral. The cases run in order, each starting from the last one's load.
const lib = vi.hoisted(() => ({ loads: 0, verifyCalls: 0 }))
vi.mock('@phala/dcap-qvl', () => {
    lib.loads++
    if (lib.loads <= 2) throw new Error('chunk load failed')
    return {
        default: {
            PHALA_PCCS_URL: 'https://default.example',
            getCollateral: async () => ({}),
            verify: () => {
                lib.verifyCalls++
                return { status: 'UpToDate', advisory_ids: [] }
            },
            Quote: { parse: () => ({ header: { teeType: 0x81 } }) },
            intel: { getFmspc: () => new Uint8Array(6), getCa: () => 'platform' },
        },
    }
})

const testdata = (p: string) => new URL(`../../testdata/${p}`, import.meta.url)
const vector = (
    JSON.parse(readFileSync(testdata('collateral_vectors.json'), 'utf8')) as {
        collateral_fresh: { name: string; collateral: TEECollateral; now_unix_ms: number }[]
    }
).collateral_fresh.find((c) => c.name === 'all_now')!
const NOW = vector.now_unix_ms + 60_000
const PUBKEY = 'age1ysu8p4akgwu3rj8h5hcqntxmmhum9rxuy5mz9xsxgkju5q42sd4sswf5t2'

function bundle(now: number): TEEEvidenceBundle {
    const quote = Buffer.from(readFileSync(testdata('attest/ds_quote_hex.txt'), 'utf8').trim(), 'hex')
    return {
        mode: TEE_MODE_DSTACK_TDX,
        cpu_report: quote.toString('base64'),
        gpu_eat: '',
        event_log: readFileSync(testdata('attest/ds_event_log.json'), 'utf8'),
        app_compose: '',
        posture: undefined,
        node_pubkey: PUBKEY,
        operator_id: 42,
        report_data: Buffer.from(reportData(PUBKEY, 42n)).toString('base64'),
        app_models: [],
        nonce: undefined,
        generated_at: new Date(now - 60_000).toISOString(),
        refresh_seconds: 1200,
        stub: false,
        collateral: vector.collateral,
    }
}

const verifyAt = (now: number) =>
    new BundleVerifier({ trustedOSImages: [], composePolicy: {}, now: () => now }).verify(
        { mode: TEE_MODE_DSTACK_TDX, evidence_url: '/v1/zs/attestation' },
        bundle(now),
        { operatorId: 42n, nodeId: 1n, ephemeralRecipientPubkey: PUBKEY },
    )

describe('a failed load of the chain library', () => {
    afterEach(() => vi.restoreAllMocks())

    // When the second load failed, as its clock read.
    let failedAt = 0

    it('fails both rungs of one verification alike, so the node never reaches its own collateral', async () => {
        const v = await verifyAt(NOW)
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(lib.verifyCalls).toBe(0)
        expect(lib.loads).toBe(1)
    })

    // Otherwise a clock stepped back an hour holds the failure for an hour.
    it('is retried when the clock has stepped backwards', async () => {
        failedAt = Date.now() - 60 * 60_000
        vi.spyOn(Date, 'now').mockReturnValue(failedAt)
        const v = await verifyAt(NOW)
        expect(lib.loads).toBe(2)
        // Failed again, and held for the rest of the verification.
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(lib.verifyCalls).toBe(0)
    })

    it('is retried once the hold has passed', async () => {
        // Exactly the hold: the failure is retried at 60s, not after it.
        vi.spyOn(Date, 'now').mockReturnValue(failedAt + 60_000)
        const v = await verifyAt(NOW)
        // Loaded this time, so the chain step ran and passed; the empty trust
        // list refuses the image after it.
        expect(lib.loads).toBe(3)
        expect(lib.verifyCalls).toBeGreaterThan(0)
        expect(v.detail?.tcbStatus).toBe('UpToDate')
        expect(v.failureTag).toBe('measurement_mismatch')
    })
})
