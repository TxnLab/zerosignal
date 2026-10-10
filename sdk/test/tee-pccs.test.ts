/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The real chain step with @phala/dcap-qvl mocked. tee-verify.test.ts injects
// chain stubs that throw the right class, so it exercises DstackVerifier's
// dispatch and never the code deciding WHICH class to throw; that code is
// here. Ported from the browser client's suite, whose cases each pinned a
// defect that shipped: a try/catch widened around verify() made forged
// evidence read as an outage, a millisecond clock passed where dcap-qvl takes
// seconds, an evicted refusal let a node pass on its own collateral.
//
// The quotes are the real Phala capture, so the cache key reads a genuine PCK
// chain. Nothing here verifies a signature: the library is mocked throughout.

import { readFileSync } from 'node:fs'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
    EMBEDDED_COLLATERAL_MAX_AGE_MS,
    type ModelEntry,
    WeightsState,
    auxBinding,
    hApp,
    hPosture,
    reportData,
    trustedComposeSkeletons,
    trustedDstackOSImages,
    trustedNodeImages,
    zeroSignalComposePolicy,
} from '@txnlab/zs-proto/attest'
import {
    TEE_MODE_DSTACK_TDX,
    type TEEAdvertisement,
    type TEECollateral,
    type TEEEvidenceBundle,
} from '@txnlab/zs-proto/inject'

import {
    BundleVerifier,
    COLLATERAL_STALE_MAX_MS,
    COLLATERAL_TIMEOUT_MS,
    COLLATERAL_TTL_MS,
    CollateralUnavailableError,
    type Node,
    StaleCollateralRejectedError,
    carriedChainVerifier,
    defaultComposePolicy,
    defaultVerifier,
    pccsChainVerifier,
} from '../src/tee/index.js'

type Report = { status: string; advisory_ids: string[] }

type Parsed = { header: { teeType: number }; raw?: Uint8Array }
type Intel = { getFmspc(q: Parsed): Uint8Array; getCa(q: Parsed): string }

// Reassigned per case. The SDK memoizes the import, and the mocked module's
// default export is this object, so a case's functions are the ones called.
// Quote parsing and the FMSPC/CA reads are the real library's, so the cache
// slot is derived from the capture's genuine leaf certificate.
const qvl = vi.hoisted(() => ({
    PHALA_PCCS_URL: 'https://default.example',
    getCollateral: (async () => ({})) as (url: string, quote: Uint8Array) => Promise<unknown>,
    verify: (() => ({ status: 'UpToDate', advisory_ids: [] })) as (q: Uint8Array, c: unknown, nowSecs: number) => Report,
    Quote: undefined as unknown as { parse(q: Uint8Array): Parsed },
    intel: undefined as unknown as Intel,
    realIntel: undefined as unknown as Intel,
}))
vi.mock('@phala/dcap-qvl', async (importOriginal) => {
    const real = ((await importOriginal()) as { default: { Quote: { parse(q: Uint8Array): Parsed }; intel: Intel } })
        .default
    // The raw bytes ride along so a case can make one quote read as another platform.
    qvl.Quote = { parse: (q) => Object.assign(real.Quote.parse(q), { raw: q }) }
    qvl.realIntel = real.intel
    qvl.intel = real.intel
    return { default: qvl }
})

const UP: Report = { status: 'UpToDate', advisory_ids: [] }
const OK = { tcbStatus: 'UpToDate', advisoryIds: [] }

function mockLib(getCollateral: (url: string, quote: Uint8Array) => Promise<unknown>, verify?: (q: Uint8Array, c: unknown, n: number) => Report) {
    const g = vi.fn(getCollateral)
    const v = vi.fn(verify ?? (() => UP))
    qvl.getCollateral = g
    qvl.verify = v
    if (qvl.realIntel !== undefined) qvl.intel = qvl.realIntel
    return { getCollateral: g, verify: v }
}

const outage = () => Promise.reject(new TypeError('Failed to fetch'))
const never = () => new Promise<never>(() => {})

/** Succeeds `okTimes` times with `platform`, then fails as fetch does when the host is down. */
function pccsUpThenDown(okTimes: number, platform: () => string = () => 'x') {
    let calls = 0
    return () => {
        calls += 1
        return calls <= okTimes ? Promise.resolve({ platform: platform() }) : outage()
    }
}

/** Refuses any collateral not fetched for the platform the quote is currently on. */
function platformVerify(onPlatform: () => string) {
    return (_q: Uint8Array, c: unknown): Report => {
        if ((c as { platform?: string }).platform !== onPlatform()) throw new Error('pck chain does not match')
        return UP
    }
}

const testdata = (p: string) => new URL(`../../testdata/${p}`, import.meta.url)
const quote = Uint8Array.from(Buffer.from(readFileSync(testdata('attest/ds_quote_hex.txt'), 'utf8').trim(), 'hex'))
const eventLog = readFileSync(testdata('attest/ds_event_log.json'), 'utf8')
const measured = (JSON.parse(readFileSync(testdata('attest_vectors.json'), 'utf8')) as {
    measurements: Record<string, string>
}).measurements
const OS_IMAGE = measured['os-image-hash']!
const COMPOSE_HASH = measured['compose-hash']!

const REPORT_DATA_OFF = 48 + 520

/** The same platform's next quote: report_data moves, the PCK chain does not. */
function remint(q: Uint8Array, seed = 1): Uint8Array {
    const out = Uint8Array.from(q)
    out.fill(seed, REPORT_DATA_OFF, REPORT_DATA_OFF + 64)
    return out
}

/**
 * The capture with a byte appended inside its PCK chain, after the last
 * certificate, and the three enclosing lengths bumped. None of those bytes is
 * signed, and the real library still verifies the result (tee-pccs-real).
 */
function junkAfterChain(q: Uint8Array): Uint8Array {
    const v = new DataView(q.buffer, q.byteOffset, q.byteLength)
    const sigLen = v.getUint32(632, true)
    const outerLen = v.getUint32(766, true)
    const inner = 770 + 384 + 64 + 2 + v.getUint16(770 + 384 + 64, true)
    const chainLen = v.getUint32(inner + 2, true)
    const end = inner + 6 + chainLen
    const out = new Uint8Array(q.length + 1)
    out.set(q.subarray(0, end))
    out[end] = 0x58
    out.set(q.subarray(end), end + 1)
    const w = new DataView(out.buffer)
    w.setUint32(632, sigLen + 1, true)
    w.setUint32(766, outerLen + 1, true)
    w.setUint32(inner + 2, chainLen + 1, true)
    return out
}

/** Makes the quote whose report_data starts with `marker` read as another FMSPC or CA. */
function otherPlatformFor(marker: number, fmspc?: string, ca?: string) {
    const real = qvl.realIntel
    const is = (p: Parsed) => p.raw?.[REPORT_DATA_OFF] === marker
    qvl.intel = {
        getFmspc: (p) => (is(p) && fmspc !== undefined ? Buffer.from(fmspc, 'hex') : real.getFmspc(p)),
        getCa: (p) => (is(p) && ca !== undefined ? ca : real.getCa(p)),
    }
}

function clock(start = 1_800_000_000_000) {
    const c = { t: start, now: () => c.t }
    return c
}

describe('pccsChainVerifier', () => {
    beforeEach(() => mockLib(async () => ({ some: 'collateral' })))

    it('reports a collateral FETCH failure as an outage, not as forged evidence', async () => {
        mockLib(outage)
        await expect(pccsChainVerifier()(quote)).rejects.toBeInstanceOf(CollateralUnavailableError)
    })

    it('does NOT dress a real verification failure as an outage', async () => {
        // The try/catch WIDTH decides this: widening it around verify() turns
        // forged evidence into a transient PCCS problem, fleet-wide.
        mockLib(async () => ({}), () => {
            throw new Error('signature does not verify')
        })
        const err: unknown = await pccsChainVerifier()(quote).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect(err).not.toBeInstanceOf(CollateralUnavailableError)
        expect(err).not.toBeInstanceOf(StaleCollateralRejectedError)
    })

    // Collateral moves on Intel's cadence (days to weeks) while a node re-mints
    // its quote every twenty minutes and each is re-verified.
    it("reuses collateral across one platform's re-minted quotes", async () => {
        const { getCollateral } = mockLib(async () => ({ some: 'collateral' }))
        const v = pccsChainVerifier()
        await v(quote)
        await v(remint(quote))
        expect(getCollateral).toHaveBeenCalledTimes(1)
    })

    // The pair brackets Go's `age < ttl`.
    it.each([
        ['serves an entry 1ms short of COLLATERAL_TTL_MS', COLLATERAL_TTL_MS - 1, 1],
        ['re-fetches an entry COLLATERAL_TTL_MS old', COLLATERAL_TTL_MS, 2],
    ])('%s', async (_label, age, fetches) => {
        const { getCollateral } = mockLib(async () => ({}))
        const c = clock()
        const v = pccsChainVerifier({ now: c.now })
        await v(quote)
        c.t += age
        await v(quote)
        expect(getCollateral).toHaveBeenCalledTimes(fetches)
    })

    it.each([
        ['short', '0A0B0C0D0E'],
        ['long', '0A0B0C0D0E0F10'],
    ])('does not cache a quote whose FMSPC reads too %s', async (_label, fmspc) => {
        const { getCollateral } = mockLib(async () => ({}))
        otherPlatformFor(9, fmspc)
        const v = pccsChainVerifier()
        const q = remint(quote, 9)
        await v(q)
        await v(q)
        expect(getCollateral).toHaveBeenCalledTimes(2)
    })

    it.each([
        ['another FMSPC', 'B0C06F000000', undefined],
        ['another CA', undefined, 'processor'],
    ])('does not share an entry with a quote naming %s', async (_label, fmspc, ca) => {
        // Collateral is chosen by the FMSPC and CA in the leaf, so one
        // platform's documents must never stand in for another's.
        const { getCollateral, verify } = mockLib(async (_url, q) => ({ for: q[REPORT_DATA_OFF] === 9 ? 'b' : 'a' }))
        otherPlatformFor(9, fmspc, ca)
        const v = pccsChainVerifier()
        const b = remint(quote, 9)
        await v(quote)
        await v(b)
        await v(b)
        expect(getCollateral).toHaveBeenCalledTimes(2)
        expect(verify.mock.calls.map((c) => c[1])).toEqual([{ for: 'a' }, { for: 'b' }, { for: 'b' }])
    })

    // The chain's bytes are outside the quote's signature; keyed by them, a
    // node could pad its chain into an empty slot and turn our cached refusal
    // into an outage that reaches its own collateral.
    it('keys by the platform the leaf names, not by the bytes of the chain', async () => {
        const { getCollateral } = mockLib(async () => ({ platform: 'x' }))
        const v = pccsChainVerifier()
        await v(quote)
        await v(junkAfterChain(quote))
        expect(getCollateral).toHaveBeenCalledTimes(1)
    })

    it('hands later quotes the platform documents, not the chain of the quote that fetched them', async () => {
        // dcap-qvl verifies against collateral.pck_certificate_chain in
        // preference to the quote's own, so a cached copy carrying it would
        // judge every later quote by the first one's certificate.
        const { verify } = mockLib(async () => ({ platform: 'x', pck_certificate_chain: 'first quote chain' }))
        const v = pccsChainVerifier()
        await v(quote)
        await v(remint(quote))
        expect(verify.mock.calls[0]![1]).toEqual({ platform: 'x', pck_certificate_chain: 'first quote chain' })
        expect(verify.mock.calls[1]![1]).toEqual({ platform: 'x' })
    })

    describe('a quote padded after a cached platform\'s chain, during an outage', () => {
        async function seatedThenDown(refuse: boolean) {
            const padded = junkAfterChain(quote)
            const { verify } = mockLib(pccsUpThenDown(1), (q) => {
                if (refuse && q.length === padded.length) throw new Error('crl revokes this platform')
                return UP
            })
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            return { v, c, padded, verify }
        }

        it('is served from the cache, never reported as an outage', async () => {
            const { v, c, padded } = await seatedThenDown(false)
            expect(await v(padded)).toStrictEqual(OK)
            c.t += COLLATERAL_TTL_MS + 60_000
            expect(await v(padded)).toStrictEqual({ ...OK, servedStale: true })
        })

        it.each([
            ['fresh', 0],
            ['stale', COLLATERAL_TTL_MS + 60_000],
        ])('meets our %s refusal, never an outage', async (_label, advance) => {
            const { v, c, padded } = await seatedThenDown(true)
            c.t += advance
            await expect(v(padded)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
        })
    })

    it('keys by PCCS too: another URL fetches its own', async () => {
        const { getCollateral } = mockLib(async () => ({}))
        // One verifier holds one URL, so two verifiers stand in; the per-instance
        // cache is the other half of what this pins.
        await pccsChainVerifier({ pccsUrl: 'https://a.example' })(quote)
        await pccsChainVerifier({ pccsUrl: 'https://b.example' })(quote)
        expect(getCollateral).toHaveBeenCalledTimes(2)
    })

    it('does not cache when told not to, nor a quote whose chain cannot be located', async () => {
        const { getCollateral } = mockLib(async () => ({}))
        const off = pccsChainVerifier({ cache: false })
        await off(quote)
        await off(quote)
        expect(getCollateral).toHaveBeenCalledTimes(2)

        const on = pccsChainVerifier()
        await on(new Uint8Array(8))
        await on(new Uint8Array(8))
        expect(getCollateral).toHaveBeenCalledTimes(4)
    })

    // Collateral describes a PLATFORM: a node that moved hardware has an FMSPC
    // the cached documents do not cover, and the chain check fails closed on
    // that. A refusal on cached collateral costs one re-fetch before it counts.
    it('re-fetches rather than believing a failure reached on cached collateral', async () => {
        let on = 'old'
        const { getCollateral } = mockLib(
            vi.fn().mockResolvedValueOnce({ platform: 'old' }).mockResolvedValueOnce({ platform: 'new' }),
            platformVerify(() => on),
        )
        const v = pccsChainVerifier()
        expect(await v(quote)).toStrictEqual(OK)
        on = 'new'
        expect(await v(quote)).toStrictEqual(OK)
        expect(getCollateral).toHaveBeenCalledTimes(2)
    })

    // A refusal on current documents (a PCK revoked in today's CRL) is the
    // strongest answer there is. Seating nothing would make the next outage
    // "we could not check", and the node's pre-revocation set would pass.
    it('keeps a refusal on freshly fetched collateral for the next outage', async () => {
        const { getCollateral, verify } = mockLib(pccsUpThenDown(1), () => {
            throw new Error('pck certificate is revoked')
        })
        const v = pccsChainVerifier()
        await expect(v(quote)).rejects.toThrow('pck certificate is revoked')
        await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
        expect(getCollateral).toHaveBeenCalledTimes(2)
        // The mark answered; the verification was not re-run.
        expect(verify).toHaveBeenCalledTimes(1)
    })

    it("does not let one node's fetched refusal stop another on the same platform", async () => {
        const other = remint(quote, 0x33)
        const { verify } = mockLib(pccsUpThenDown(1), (q) => {
            if (q[REPORT_DATA_OFF] !== 0x33) throw new Error('pck certificate is revoked')
            return UP
        })
        const c = clock()
        const v = pccsChainVerifier({ now: c.now })
        await expect(v(quote)).rejects.toThrow('pck certificate is revoked')
        // The PCCS is down from here: the other node is judged by the seated entry.
        expect(await v(other)).toStrictEqual(OK)
        c.t += COLLATERAL_TTL_MS + 60_000
        expect(await v(other)).toStrictEqual({ ...OK, servedStale: true })
        expect(verify.mock.calls.at(-1)![1]).toEqual({ platform: 'x' })
    })

    it('does not mark a fresh or fetched result as served stale', async () => {
        // DstackVerifier refuses a stale-served non-UpToDate status as
        // collateral_unreachable; a stray flag would misfile a current refusal.
        mockLib(async () => ({}))
        const v = pccsChainVerifier()
        expect(await v(quote)).toStrictEqual(OK) // fetched
        expect(await v(quote)).toStrictEqual(OK) // fresh cache
    })

    describe('when the PCCS cannot be reached', () => {
        it('serves a cached entry past its TTL, marked as served stale', async () => {
            const { getCollateral } = mockLib(pccsUpThenDown(1))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t += COLLATERAL_TTL_MS + 60_000
            expect(await v(quote)).toStrictEqual({ ...OK, servedStale: true })
            // A refresh was still attempted: the entry is a fallback, not a
            // reason to stop asking.
            expect(getCollateral).toHaveBeenCalledTimes(2)
        })

        it('reports the library status on the stale arm too, for DstackVerifier to classify', async () => {
            let status = 'UpToDate'
            mockLib(pccsUpThenDown(1), () => ({ status, advisory_ids: ['INTEL-SA-00001'] }))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t += COLLATERAL_TTL_MS + 60_000
            status = 'OutOfDate'
            expect(await v(quote)).toStrictEqual({ tcbStatus: 'OutOfDate', advisoryIds: ['INTEL-SA-00001'], servedStale: true })
        })

        // The pair brackets the bound: any bound between TTL+60s and the
        // refusal below satisfies one of them alone.
        it('serves an entry just inside COLLATERAL_STALE_MAX_MS', async () => {
            mockLib(pccsUpThenDown(1))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t += COLLATERAL_STALE_MAX_MS - 60_000
            expect(await v(quote)).toStrictEqual({ ...OK, servedStale: true })
        })

        it('refuses an entry COLLATERAL_STALE_MAX_MS old, as Go does', async () => {
            mockLib(pccsUpThenDown(1))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t += COLLATERAL_STALE_MAX_MS
            await expect(v(quote)).rejects.toBeInstanceOf(CollateralUnavailableError)
        })

        // Past the bound an entry answers nothing, refusals included, as Go's
        // cache does not serve it. Otherwise a marked quote would be refused
        // while the same quote padded to a new digest reached the carried rung.
        it.each([
            ['inside', -60_000, StaleCollateralRejectedError],
            ['past', 60_000, CollateralUnavailableError],
        ])('answers a marked quote %s COLLATERAL_STALE_MAX_MS as an unmarked one', async (_label, offset, want) => {
            let refuse = false
            mockLib(pccsUpThenDown(1), () => {
                if (refuse) throw new Error('crl revokes this platform')
                return UP
            })
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            refuse = true
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError) // marks it
            c.t += COLLATERAL_STALE_MAX_MS + offset
            await expect(v(quote)).rejects.toBeInstanceOf(want)
            await expect(v(junkAfterChain(quote))).rejects.toBeInstanceOf(want)
        })

        it('reports the outage when nothing was ever cached', async () => {
            mockLib(outage)
            await expect(pccsChainVerifier()(quote)).rejects.toBeInstanceOf(CollateralUnavailableError)
        })

        // A moved platform and a REVOKED one are indistinguishable from here:
        // both read as "our cached document refuses this quote". Calling it an
        // outage would let a revoked node pass on its own collateral by
        // waiting for any PCCS outage.
        it('reports a refusal by the cached entry as one, not as an outage', async () => {
            let on = 'old'
            const { verify } = mockLib(pccsUpThenDown(1, () => 'old'), platformVerify(() => on))
            const v = pccsChainVerifier()
            await v(quote)
            on = 'new'
            const err: unknown = await v(quote).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(StaleCollateralRejectedError)
            // Both causes, in their slots: what refused, and why our document was asked.
            expect(String((err as Error).message)).toContain('pck chain does not match')
            expect(String((err as Error).message)).toContain('Failed to fetch')
            // One attempt against the refusing entry, not two.
            expect(verify).toHaveBeenCalledTimes(2)
        })

        it('reaches the same refusal on the stale arm, and marks it', async () => {
            let on = 'old'
            const { verify } = mockLib(pccsUpThenDown(1, () => 'old'), platformVerify(() => on))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t += COLLATERAL_TTL_MS + 60_000
            on = 'new'
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            expect(verify).toHaveBeenCalledTimes(2)
        })

        // collateral_unreachable files a node for a re-check, so a refusal that
        // held only within one call would admit it on the next tick, on its own
        // collateral.
        it('keeps refusing across calls once our own collateral has said no', async () => {
            let on = 'old'
            const { getCollateral, verify } = mockLib(pccsUpThenDown(1, () => 'old'), platformVerify(() => on))
            const v = pccsChainVerifier()
            await v(quote)
            on = 'new'
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            const later: unknown = await v(quote).catch((e: unknown) => e)
            expect(later).toBeInstanceOf(StaleCollateralRejectedError)
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            // The verification it already knows the answer to is not re-run...
            expect(verify).toHaveBeenCalledTimes(2)
            // ...but the PCCS is still asked: the mark is no circuit breaker,
            // and a successful fetch is what clears it.
            expect(getCollateral).toHaveBeenCalledTimes(4)
            // Only the mark survives, so no verdict text is invented for it.
            expect((later as Error).message).toContain('on an earlier attempt')
        })

        // The entry is keyed by a PCK chain, which any node can copy out of
        // another's public quote. A forged quote carrying the victim's chain
        // must not change how the victim's own quotes are judged.
        it("keeps one quote's refusal off another quote on the same platform", async () => {
            const forged = remint(quote, 7)
            let up = true
            const { verify } = mockLib(
                () => (up ? Promise.resolve({ platform: 'x' }) : outage()),
                (q) => {
                    if (q[REPORT_DATA_OFF] === 7) throw new Error('quote signature does not verify')
                    return UP
                },
            )
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            expect(await v(quote)).toStrictEqual(OK)

            const refusal: unknown = await v(forged).catch((e: unknown) => e)
            expect(refusal).toBeInstanceOf(Error)
            expect(refusal).not.toBeInstanceOf(CollateralUnavailableError)
            expect(refusal).not.toBeInstanceOf(StaleCollateralRejectedError)

            up = false
            // The victim, from the cache, inside the TTL and then past it.
            expect(await v(quote)).toStrictEqual(OK)
            c.t += COLLATERAL_TTL_MS + 60_000
            expect(await v(quote)).toStrictEqual({ ...OK, servedStale: true })
            // The forged quote still meets its own refusal, never a plain outage.
            await expect(v(forged)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            expect(verify.mock.calls.filter((call) => call[0] === forged)).toHaveLength(2)
        })

        it('holds 256 marks, re-verifies a quote whose mark was dropped, and refuses it again', async () => {
            let up = true
            const { verify } = mockLib(() => (up ? Promise.resolve({ platform: 'x' }) : outage()), (q) => {
                if (q[REPORT_DATA_OFF] !== 0x55) throw new Error('quote signature does not verify')
                return UP
            })
            const good = remint(quote, 0x55)
            const v = pccsChainVerifier()
            await v(good)
            up = false
            const forgeries = Array.from({ length: 257 }, (_, i) => {
                const f = remint(quote, 1)
                f[REPORT_DATA_OFF + 1] = i & 0xff
                f[REPORT_DATA_OFF + 2] = i >> 8
                return f
            })
            for (const f of forgeries) await expect(v(f)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            const verifiedFor = (q: Uint8Array) => verify.mock.calls.filter((call) => call[0] === q).length
            // The 257th mark pushed out the first and kept the second. The
            // second is asked first: re-verifying the first marks it again,
            // which pushes the second out.
            await expect(v(forgeries[1]!)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            expect(verifiedFor(forgeries[1]!), 'a kept mark was re-verified').toBe(1)
            await expect(v(forgeries[0]!)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            expect(verifiedFor(forgeries[0]!), 'the oldest mark was not dropped').toBe(2)
            expect(await v(good)).toStrictEqual(OK)
        })

        it('clears the mark when the PCCS is back and the quote verifies', async () => {
            let on = 'old'
            let up = true
            const { getCollateral } = mockLib(
                () => (up ? Promise.resolve({ platform: on }) : outage()),
                platformVerify(() => on),
            )
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            on = 'new'
            up = false
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            up = true
            expect(await v(quote)).toStrictEqual(OK)
            // Reseated by that fetch, unmarked, so the next outage serves it.
            c.t += COLLATERAL_TTL_MS + 60_000
            up = false
            expect(await v(quote)).toStrictEqual({ ...OK, servedStale: true })
            expect(getCollateral).toHaveBeenCalledTimes(4)
        })

        // One call drives both arms. A clock stepped backwards makes the
        // entry's age negative.
        it('does not treat a backwards clock as freshness, but still serves under an outage', async () => {
            const { getCollateral } = mockLib(pccsUpThenDown(1))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t -= 30 * 24 * 60 * 60_000
            const got = await v(quote)
            // Fresh arm refused: the second fetch is the proof.
            expect(getCollateral, 'a future-dated entry was served as fresh').toHaveBeenCalledTimes(2)
            // Stale arm served anyway: refusing would take every node out over a clock step.
            expect(got).toStrictEqual({ ...OK, servedStale: true })
        })
    })

    describe('the caller abort', () => {
        it('rejects promptly while the fetch hangs', async () => {
            const { getCollateral } = mockLib(never)
            const ac = new AbortController()
            // A budget far past the test timeout, so only the signal can end it.
            const p = pccsChainVerifier({ timeoutMs: 600_000 })(quote, ac.signal)
            await vi.waitFor(() => expect(getCollateral).toHaveBeenCalled())
            ac.abort(new Error('caller left'))
            await expect(p).rejects.toBeInstanceOf(CollateralUnavailableError)
        })

        it('does not start a fetch, or serve a fresh entry, once aborted', async () => {
            // Go's getter refuses every Get on a cancelled context, cache hits
            // included.
            const { getCollateral, verify } = mockLib(async () => ({}))
            const v = pccsChainVerifier()
            await v(quote)
            const ac = new AbortController()
            ac.abort()
            await expect(v(quote, ac.signal)).rejects.toBeInstanceOf(CollateralUnavailableError)
            expect(getCollateral).toHaveBeenCalledTimes(1)
            expect(verify).toHaveBeenCalledTimes(1)
        })

        it('does not serve a stale entry to a caller that left', async () => {
            const { verify } = mockLib(pccsUpThenDown(1))
            const c = clock()
            const v = pccsChainVerifier({ now: c.now })
            await v(quote)
            c.t += COLLATERAL_TTL_MS + 60_000
            const ac = new AbortController()
            ac.abort()
            await expect(v(quote, ac.signal)).rejects.toBeInstanceOf(CollateralUnavailableError)
            expect(verify).toHaveBeenCalledTimes(1)
        })

        it('still reports a refusal our collateral already made', async () => {
            // An abort reads as an outage, and an outage must not launder the
            // mark into a plain one: that would hand the quote to the node's set.
            let on = 'old'
            mockLib(pccsUpThenDown(1, () => 'old'), platformVerify(() => on))
            const v = pccsChainVerifier()
            await v(quote)
            on = 'new'
            await expect(v(quote)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
            const ac = new AbortController()
            ac.abort()
            await expect(v(quote, ac.signal)).rejects.toBeInstanceOf(StaleCollateralRejectedError)
        })
    })

    it('passes the validity clock in SECONDS, not milliseconds', async () => {
        // dcap-qvl takes Unix seconds; milliseconds read every certificate as
        // long expired.
        const { verify } = mockLib(async () => ({}))
        await pccsChainVerifier({ now: () => 1_800_000_123_999 })(quote)
        expect(verify.mock.calls[0]![2]).toBe(1_800_000_123)
    })

    it('sends the caller-supplied PCCS url', async () => {
        const { getCollateral } = mockLib(async () => ({}))
        await pccsChainVerifier({ pccsUrl: 'https://mine.example' })(quote)
        expect(getCollateral.mock.calls[0]![0]).toBe('https://mine.example')
    })

    it("defaults to the library's PCCS mirror rather than an empty url", async () => {
        const { getCollateral } = mockLib(async () => ({}))
        await pccsChainVerifier()(quote)
        expect(getCollateral.mock.calls[0]![0]).toBe('https://default.example')
    })

    it('bounds a hanging collateral fetch and calls it an outage', async () => {
        mockLib(never)
        await expect(pccsChainVerifier({ timeoutMs: 20 })(quote)).rejects.toBeInstanceOf(CollateralUnavailableError)
    })

    it("matches Go's collateral constants", () => {
        // Shared numbers, not local preferences: a marginal network should
        // reach the same verdict in either SDK.
        expect(COLLATERAL_TIMEOUT_MS).toBe(8_000)
        expect(COLLATERAL_TTL_MS).toBe(60 * 60_000)
        expect(COLLATERAL_STALE_MAX_MS).toBe(7 * 24 * 60 * 60_000)
    })

    it("returns the library's OWN status, not the one we accept", async () => {
        mockLib(async () => ({}), () => ({ status: 'Revoked', advisory_ids: ['INTEL-SA-00001'] }))
        expect(await pccsChainVerifier()(quote)).toStrictEqual({ tcbStatus: 'Revoked', advisoryIds: ['INTEL-SA-00001'] })
    })

    it('hands verify() the quote and the collateral it just fetched', async () => {
        const collateral = { some: 'collateral' }
        const { verify } = mockLib(async () => collateral)
        await pccsChainVerifier()(quote)
        expect(verify.mock.calls[0]![0]).toBe(quote)
        expect(verify.mock.calls[0]![1]).toBe(collateral)
    })

    // A PCCS that ANSWERED is not one that is down. The FMSPC in the URL comes
    // from the node's own quote, so a node on a platform the mirror does not
    // publish could otherwise earn the carried fallback at will. The messages
    // are dcap-qvl's own, which also match "failed to fetch".
    it.each([
        ['a 404 for this FMSPC', new Error('Failed to fetch TCB info: 404')],
        ['a 404 on a named URL', new Error('Failed to fetch https://pccs.example/sgx/certification/v4/rootcacrl: 404')],
        ['a malformed document', new SyntaxError('Unexpected token < in JSON at position 0')],
        ['a missing issuer-chain header', new Error('missing SGX-PCK-CRL-Issuer-Chain header')],
        // A number shaped like a 5xx anywhere in the text is not a status.
        ['a parse error at position 512', new SyntaxError('Unexpected token < in JSON at position 512')],
        ['an error naming offset 503', new Error('bad DER length at offset 503')],
        // A TypeError is also what a 200 with a missing field throws.
        ['a TypeError from parsing a 200', new TypeError('The first argument must be of type string or an instance of Buffer. Received undefined')],
        ['a TypeError saying fetch failed mid-message', new TypeError('cannot read tcbInfo: fetch failed earlier')],
        ['an error naming a socket code mid-message', new Error('bad issuer: expected connect ECONNREFUSED in field')],
        ['a 600, which is no HTTP status', new Error('Failed to fetch PCK CRL: 600')],
    ])('rethrows %s unwrapped', async (_label, err) => {
        mockLib(() => Promise.reject(err))
        await expect(pccsChainVerifier()(quote)).rejects.toBe(err)
    })

    it.each([
        ['a TypeError from fetch', new TypeError('Failed to fetch')],
        ["undici's fetch failure", new TypeError('fetch failed')],
        ["Safari's fetch failure", new TypeError('Load failed')],
        ["Firefox's fetch failure", new TypeError('NetworkError when attempting to fetch resource.')],
        ['a connection refusal', new Error('connect ECONNREFUSED 127.0.0.1:443')],
        ['a 503', new Error('Failed to fetch PCK CRL: 503')],
        ['a 429', new Error('Failed to fetch PCK CRL: 429')],
        ['a 599', new Error('Failed to fetch PCK CRL: 599')],
        ['a 500 on a named URL', new Error('Failed to fetch PCK certificate from https://pccs.example/x: 500')],
        ['a timeout', new Error('connect ETIMEDOUT 10.0.0.1:443')],
    ])('calls %s an outage', async (_label, err) => {
        mockLib(() => Promise.reject(err))
        await expect(pccsChainVerifier()(quote)).rejects.toBeInstanceOf(CollateralUnavailableError)
    })
})

describe('carriedChainVerifier', () => {
    const carried = (): TEECollateral => ({
        pck_crl_issuer_chain: 'chain',
        root_ca_crl: 'aa',
        pck_crl: 'bb',
        tcb_info_issuer_chain: 'chain',
        tcb_info: '{}',
        tcb_info_signature: 'cc',
        qe_identity_issuer_chain: 'chain',
        qe_identity: '{}',
        qe_identity_signature: 'dd',
    })

    it('verifies against the carried set without reaching a PCCS', async () => {
        const { getCollateral, verify } = mockLib(async () => ({}))
        const c = carried()
        expect(await carriedChainVerifier({ now: () => 1_800_000_000_500 })(quote, c)).toStrictEqual(OK)
        expect(getCollateral).not.toHaveBeenCalled()
        // Values untouched: the wire shape is the library's, and a translation
        // here would surface as an attestation failure.
        expect(verify.mock.calls[0]![1]).toStrictEqual(c)
        expect(verify.mock.calls[0]![2]).toBe(1_800_000_000)
    })

    it('hands dcap-qvl the nine members only, never a chain riding along', async () => {
        // dcap-qvl verifies against collateral.pck_certificate_chain in place
        // of the quote's own, and a set parsed from a bundle could carry one.
        const { verify } = mockLib(async () => ({}))
        const c = carried()
        const withChain = { ...c, pck_certificate_chain: 'not this quote\'s chain', extra: 1 } as TEECollateral
        await carriedChainVerifier()(quote, withChain)
        expect(verify.mock.calls[0]![1]).toStrictEqual(c)
    })

    it('refuses once the caller has aborted', async () => {
        const { verify } = mockLib(async () => ({}))
        const ac = new AbortController()
        ac.abort()
        await expect(carriedChainVerifier()(quote, carried(), ac.signal)).rejects.toThrow()
        expect(verify).not.toHaveBeenCalled()
    })
})

// ---------------------------------------------------------------------------
// The precedence through BundleVerifier with the real chain verifiers wired,
// as defaultVerifier wires them, on test trust lists so the capture passes.

const NODE_PUBKEY = 'age1ysu8p4akgwu3rj8h5hcqntxmmhum9rxuy5mz9xsxgkju5q42sd4sswf5t2'
const OPERATOR_ID = 42n
const NODE_ID = 0x0102030405060708n

const models = (): ModelEntry[] => [
    { model_id: 'm', source: '', weights_digest: '', weights_state: WeightsState.Unverifiable },
]

function boundQuote(): Uint8Array {
    const q = Uint8Array.from(quote)
    q.set(reportData(NODE_PUBKEY, OPERATOR_ID), REPORT_DATA_OFF)
    q.set(auxBinding(NODE_ID, hApp(models()), hPosture(undefined), null), REPORT_DATA_OFF + 32)
    return q
}

const freshVector = (
    JSON.parse(readFileSync(testdata('collateral_vectors.json'), 'utf8')) as {
        collateral_fresh: { name: string; collateral: TEECollateral; now_unix_ms: number; fresh: boolean }[]
    }
).collateral_fresh.find((c) => c.name === 'all_now')!
const CARRIED = freshVector.collateral
const T0 = freshVector.now_unix_ms + 60_000

function bundleAt(nowMs: number, over: Partial<TEEEvidenceBundle> = {}): TEEEvidenceBundle {
    return {
        mode: TEE_MODE_DSTACK_TDX,
        cpu_report: Buffer.from(boundQuote()).toString('base64'),
        gpu_eat: '',
        event_log: eventLog,
        app_compose: '',
        posture: undefined,
        node_pubkey: NODE_PUBKEY,
        operator_id: Number(OPERATOR_ID),
        report_data: Buffer.from(reportData(NODE_PUBKEY, OPERATOR_ID)).toString('base64'),
        app_models: models(),
        nonce: undefined,
        generated_at: new Date(nowMs - 60_000).toISOString(),
        refresh_seconds: 1200,
        stub: false,
        ...over,
    }
}

const advert = (): TEEAdvertisement => ({ mode: TEE_MODE_DSTACK_TDX, evidence_url: '/v1/zs/attestation' })
const node = (): Node => ({ operatorId: OPERATOR_ID, nodeId: NODE_ID, ephemeralRecipientPubkey: NODE_PUBKEY })

/** BundleVerifier wired as defaultVerifier wires it, on lists the capture satisfies. */
function wired(c: { now: () => number }, pccsUrl?: string): BundleVerifier {
    return new BundleVerifier({
        trustedOSImages: [OS_IMAGE],
        composePolicy: { ...zeroSignalComposePolicy(), enforceComposeSkeleton: false },
        trustedComposeHashes: [COMPOSE_HASH],
        verifyChain: pccsChainVerifier({ now: c.now, ...(pccsUrl !== undefined && { pccsUrl }) }),
        verifyChainCarried: carriedChainVerifier({ now: c.now }),
        now: c.now,
    })
}

describe('the chain precedence with the real verifiers', () => {
    async function run(collateral: TEECollateral | undefined, opts: { pccsFails?: boolean; chainRefuses?: boolean; nowMs?: number } = {}) {
        const { getCollateral, verify } = mockLib(
            opts.pccsFails === true ? outage : async () => ({ from: 'pccs' }),
            () => {
                if (opts.chainRefuses === true) throw new Error('pck chain invalid')
                return UP
            },
        )
        const c = clock(opts.nowMs ?? T0)
        const v = await wired(c).verify(advert(), bundleAt(c.t, collateral === undefined ? {} : { collateral }), node())
        return { v, getCollateral, verify }
    }

    it('fetches from the PCCS even when the node carried collateral', async () => {
        const { v, getCollateral, verify } = await run(CARRIED)
        expect(v.pass, v.failureTag).toBe(true)
        expect(getCollateral).toHaveBeenCalledOnce()
        // The FETCHED documents, not the node's.
        expect(verify.mock.calls[0]![1]).toEqual({ from: 'pccs' })
    })

    it('falls back to carried collateral when the PCCS is unreachable', async () => {
        const { v, verify } = await run(CARRIED, { pccsFails: true })
        expect(v.pass, v.failureTag).toBe(true)
        expect(verify.mock.calls[0]![1]).toEqual(CARRIED)
    })

    it.each([
        ['older than the floor', T0 + EMBEDDED_COLLATERAL_MAX_AGE_MS + 60_000],
        ['dated in the future', T0 - 2 * 24 * 60 * 60_000],
    ])('refuses carried collateral %s', async (_label, nowMs) => {
        const { v, verify } = await run(CARRIED, { pccsFails: true, nowMs })
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(verify).not.toHaveBeenCalled()
    })

    it('reports an outage when the node carried nothing', async () => {
        const { v } = await run(undefined, { pccsFails: true })
        expect(v.failureTag).toBe('collateral_unreachable')
    })

    // A refusal is an answer; retrying it against the node's documents is the
    // talking-itself-into-a-pass move the ordering prevents.
    it('does not hand a quote refused on fetched collateral to its carried set at the next outage', async () => {
        const { getCollateral, verify } = mockLib(pccsUpThenDown(1), () => {
            throw new Error('pck certificate is revoked')
        })
        const c = clock(T0)
        const verifier = wired(c)
        const first = await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        expect(first.failureTag).toBe('vendor_chain_invalid')
        c.t += 60_000
        const second = await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        expect(second.failureTag).toBe('collateral_unreachable')
        expect(getCollateral).toHaveBeenCalledTimes(2)
        // Once, on the fetched set. A second call would be the carried rung.
        expect(verify).toHaveBeenCalledOnce()
    })

    it('does not retry a failed chain verification against carried collateral', async () => {
        const { v, verify } = await run(CARRIED, { chainRefuses: true })
        expect(v.failureTag).toBe('vendor_chain_invalid')
        expect(verify).toHaveBeenCalledOnce()
    })

    it.each([
        ['a 404 for this FMSPC', new Error('Failed to fetch TCB info: 404')],
        ['a malformed document', new SyntaxError('Unexpected token < in JSON at position 0')],
    ])('does NOT fall back to carried collateral on %s', async (_label, err) => {
        const { verify } = mockLib(() => Promise.reject(err))
        const c = clock(T0)
        const v = await wired(c).verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        expect(v.failureTag).toBe('vendor_chain_invalid')
        expect(verify).not.toHaveBeenCalled()
    })

    // Our own document, consulted because the PCCS was down, said no. Falling
    // through to the node's set would trade a vintage we chose for one it did.
    it.each([
        ['stale', COLLATERAL_TTL_MS + 60_000],
        ['fresh', 0],
    ])('does not retry a %s cached refusal against carried collateral', async (_label, advance) => {
        let refuse = false
        const { getCollateral, verify } = mockLib(pccsUpThenDown(1), () => {
            if (refuse) throw new Error('crl revokes this platform')
            return UP
        })
        const c = clock(T0)
        const verifier = wired(c)
        expect((await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())).pass).toBe(true)
        c.t += advance
        refuse = true
        const second = await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        // The outage TAG: an outage is why our document was asked, and the
        // refusal cannot be attributed.
        expect(second.failureTag).toBe('collateral_unreachable')
        // Two: the first serve and our cache's refusal. A third would be the
        // node's own collateral consulted after ours said no.
        expect(verify).toHaveBeenCalledTimes(2)
        expect(verify.mock.calls[1]![1]).toEqual({ platform: 'x' })
        expect(getCollateral).toHaveBeenCalledTimes(2)
    })

    it('refuses a non-UpToDate status reached on stale collateral as an outage, without the fallback', async () => {
        // Go refuses the status inside the chain check, where a stale serve
        // makes it ErrStaleCollateralRejected. servedStale is how the TS side
        // reaches the same tag.
        let status = 'UpToDate'
        const { verify } = mockLib(pccsUpThenDown(1), () => ({ status, advisory_ids: [] }))
        const c = clock(T0)
        const verifier = wired(c)
        await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        c.t += COLLATERAL_TTL_MS + 60_000
        status = 'OutOfDate'
        const v = await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(verify).toHaveBeenCalledTimes(2)
    })

    it('refuses the same status on freshly fetched collateral as invalid evidence', async () => {
        mockLib(async () => ({}), () => ({ status: 'OutOfDate', advisory_ids: ['INTEL-SA-00001'] }))
        const v = await wired(clock(T0)).verify(advert(), bundleAt(T0), node())
        expect(v.failureTag).toBe('vendor_chain_invalid')
        expect(v.detail?.tcbStatus).toBe('OutOfDate')
        expect(v.detail?.advisoryIds).toEqual(['INTEL-SA-00001'])
    })
})

describe('defaultComposePolicy', () => {
    it("is Go's DefaultComposePolicy: the shared rules, the release lists, the match enforced", () => {
        const p = defaultComposePolicy()
        expect(p).toEqual({
            ...zeroSignalComposePolicy(),
            trustedComposeSkeletons: trustedComposeSkeletons(),
            trustedNodeImages: trustedNodeImages(),
            enforceComposeSkeleton: true,
        })
        expect(p.enforceComposeSkeleton).toBe(true)
        expect(p.trustedComposeSkeletons).toEqual(trustedComposeSkeletons())
        expect(p.trustedNodeImages).toEqual(trustedNodeImages())
        expect(p.trustedComposeSkeletons!.length).toBeGreaterThan(0)
        expect(p.trustedNodeImages!.length).toBeGreaterThan(0)
    })

    it('hands each caller its own lists', () => {
        const images = defaultComposePolicy().trustedNodeImages as string[]
        images.push('ghcr.io/evil/node@sha256:00')
        expect(defaultComposePolicy().trustedNodeImages).toEqual(trustedNodeImages())
    })
})

describe('defaultVerifier', () => {
    // The capture's OS image is a production one and it publishes no compose,
    // so under the shipped policy a verification that gets past the chain
    // stops at the release match. That stop is the proof the chain passed.
    it('passes the chain step through the real verifier and stops at the release match', async () => {
        expect(trustedDstackOSImages()).toContain(OS_IMAGE)
        const { getCollateral, verify } = mockLib(async () => ({ from: 'pccs' }))
        const v = await defaultVerifier({ now: () => T0 }).verify(advert(), bundleAt(T0), node())
        expect(getCollateral).toHaveBeenCalledOnce()
        expect(getCollateral.mock.calls[0]![0]).toBe('https://default.example')
        expect(verify.mock.calls[0]![2]).toBe(Math.floor(T0 / 1000))
        expect(v.detail?.tcbStatus).toBe('UpToDate')
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.detail?.composeViolations).toEqual(['missing_app_compose'])
        expect(v.detail?.measurements?.osImageHash).toBe(OS_IMAGE)
    })

    it('refuses a bundle the chain refuses', async () => {
        mockLib(async () => ({}), () => {
            throw new Error('signature does not verify')
        })
        const v = await defaultVerifier({ now: () => T0 }).verify(advert(), bundleAt(T0), node())
        expect(v.pass).toBe(false)
        expect(v.failureTag).toBe('vendor_chain_invalid')
    })

    it('sends a supplied PCCS url', async () => {
        const { getCollateral } = mockLib(async () => ({}))
        await defaultVerifier({ now: () => T0, pccsUrl: 'https://mine.example' }).verify(advert(), bundleAt(T0), node())
        expect(getCollateral.mock.calls[0]![0]).toBe('https://mine.example')
    })

    it('wires the carried rung for an outage', async () => {
        const { verify } = mockLib(outage)
        const v = await defaultVerifier({ now: () => T0 }).verify(advert(), bundleAt(T0, { collateral: CARRIED }), node())
        // Past the chain on the node's own set, so stopped at the release match.
        expect(verify.mock.calls[0]![1]).toEqual(CARRIED)
        expect(verify.mock.calls[0]![2]).toBe(Math.floor(T0 / 1000))
        expect(v.detail?.tcbStatus).toBe('UpToDate')
        expect(v.failureTag).toBe('measurement_mismatch')
    })
})

describe('a verifier built without chain seams', () => {
    // The injected clock must reach the library's validity check too, or a
    // host's clock judges the bundle's age while the wall clock judges the
    // documents.
    it.each([
        ['fetched', async () => ({ from: 'pccs' })],
        ['carried', outage],
    ])('verifies %s collateral at the injected clock', async (_label, fetch) => {
        const { verify } = mockLib(fetch)
        const c = clock(T0)
        const verifier = new BundleVerifier({
            trustedOSImages: [OS_IMAGE],
            composePolicy: { ...zeroSignalComposePolicy(), enforceComposeSkeleton: false },
            trustedComposeHashes: [COMPOSE_HASH],
            now: c.now,
        })
        const v = await verifier.verify(advert(), bundleAt(c.t, { collateral: CARRIED }), node())
        expect(v.pass, v.failureTag).toBe(true)
        expect(verify).toHaveBeenCalledOnce()
        expect(verify.mock.calls[0]![2]).toBe(Math.floor(T0 / 1000))
    })
})
