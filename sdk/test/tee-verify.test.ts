/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The TEE verifier, driven by the same real Phala tdx.small capture that
// proto/go/attest and proto/ts/attest are golden-vectored against: a genuine
// quote and the event log minted in the same call. A hand-built fixture would
// let the verifier and the fixture agree on arithmetic neither shares with the
// hardware.
//
// The chain step is stubbed throughout. That is the standing limit of this
// file: the chain check is what makes every other step mean something, so
// these cases say the steps AFTER it are right and nothing about whether a
// forged quote is rejected. The quotes below are patched (report_data, RTMR3),
// which invalidates their signatures; only a stubbed chain lets them through.
//
// Go is the reference: where the browser client this replaces behaved
// differently, the cases pin Go's behaviour (chain fallback ordering, Go's
// StdEncoding base64, the compose-hash guard, the TCB status on the carried
// rung, nanosecond freshness with int64 wrapping).

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'

import {
    type ComposePolicy,
    EMBEDDED_COLLATERAL_MAX_AGE_MS,
    EVENT_COMPOSE_HASH,
    type ModelEntry,
    WeightsState,
    auxBinding,
    composeSkeletonDigest,
    extractComposeSkeleton,
    hApp,
    hPosture,
    parseEventLog,
    quoteRTMR,
    replayRTMR3,
    reportData,
    trustedComposeSkeletons,
    trustedNodeImages,
    verifyAppCompose,
    zeroSignalComposePolicy,
} from '@txnlab/zs-proto/attest'
import {
    TEE_MODE_DSTACK_TDX,
    TEE_MODE_NVIDIA_CC_SEV_SNP,
    TEE_MODE_NVIDIA_CC_TDX,
    TEE_MODE_STUB,
    type TEEAdvertisement,
    type TEECollateral,
    type TEEEvidenceBundle,
    type UpstreamAttestation,
} from '@txnlab/zs-proto/inject'
import { DEFAULT_EPHEMERAL_SKEW_SEC, MAX_EPHEMERAL_LIFETIME_SEC } from '@txnlab/zs-proto/ticket'

import type { Logger } from '../src/ports.js'
import {
    ACCEPTED_TCB_STATUS,
    BundleVerifier,
    type BundleVerifierOptions,
    type CarriedChainVerifier,
    type ChainResult,
    CollateralUnavailableError,
    DstackVerifier,
    EVIDENCE_MAX_AGE_CEILING_MS,
    type Node,
    PLAINTEXT_IN_ENCLAVE,
    PLAINTEXT_NAMED_UPSTREAM,
    type QuoteChainVerifier,
    StaleCollateralRejectedError,
    type Verdict,
    checkPosture,
    measurementTrusted,
} from '../src/tee/index.js'

const testdata = (p: string) => new URL(`../../testdata/${p}`, import.meta.url)

const quoteHex = readFileSync(testdata('attest/ds_quote_hex.txt'), 'utf8').trim()
const eventLog = readFileSync(testdata('attest/ds_event_log.json'), 'utf8')
const measured = (
    JSON.parse(readFileSync(testdata('attest_vectors.json'), 'utf8')) as { measurements: Record<string, string> }
).measurements

function measurement(name: string): string {
    const v = measured[name]
    if (v === undefined || v === '') throw new Error(`attest_vectors.json has no ${name} measurement`)
    return v
}

// Read off the capture, never typed in: the os-image-hash is the trust anchor
// the SDK has no default for, and a hand-copied value could drift from the
// bytes the replay recovers.
const COMPOSE_HASH = measurement('compose-hash')
const OS_IMAGE = measurement('os-image-hash')
const APP_ID = measurement('app-id')

const quote = Uint8Array.from(Buffer.from(quoteHex, 'hex'))

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

// The capture's report_data binds the real node's ephemeral, which we do not
// have, so passing cases patch the quote to a binding we can reproduce. The
// unpatched capture is asserted to fail closed separately.
const NODE_PUBKEY = 'age1ysu8p4akgwu3rj8h5hcqntxmmhum9rxuy5mz9xsxgkju5q42sd4sswf5t2'
const OPERATOR_ID = 42n
// Non-zero, so a verifier ignoring the chain-resolved node id (passing 0, or
// dropping it from the preimage) fails the happy path instead of agreeing with
// the fixture by accident. Byte order is pinned by proto's attest vectors.
const NODE_ID = 0x0102030405060708n

const REPORT_DATA_OFF = 48 + 520

const MINTED = '2026-08-26T00:00:00Z'
const MINTED_MS = Date.parse(MINTED)
const NOW_MS = MINTED_MS + 5 * 60_000

/**
 * Three entries covering all three weights states: a fixture using one would
 * let a verifier ignore the state byte and still agree on every digest. Fresh
 * per call so a test mutating it cannot corrupt the next.
 */
function capturedModels(): ModelEntry[] {
    return [
        {
            model_id: 'qwen3-30b',
            source: 'hf/Qwen/Qwen3-30B',
            weights_digest: 'sha256:aa11',
            weights_state: WeightsState.Measured,
        },
        {
            model_id: 'glm-4.6',
            source: 'hf/zai-org/GLM-4.6',
            weights_digest: 'sha256:bb22',
            weights_state: WeightsState.Declared,
        },
        { model_id: 'grok-4', source: '', weights_digest: '', weights_state: WeightsState.Unverifiable },
    ]
}

/**
 * A copy of the capture whose report_data binds (pubkey, id) in the lower half
 * and the aux binding in the upper. The capture is pre-9.9 (a zero upper
 * half), so splicing the aux binding in is what makes it a 9.9 node at all.
 */
function quoteBoundTo(
    pubkey: string,
    id: bigint,
    models: ModelEntry[] | null = capturedModels(),
    nodeId: bigint = NODE_ID,
    nonce: Uint8Array | null = null,
    posture: unknown = undefined,
): Uint8Array {
    const q = Uint8Array.from(quote)
    q.fill(0, REPORT_DATA_OFF, REPORT_DATA_OFF + 64)
    q.set(reportData(pubkey, id), REPORT_DATA_OFF)
    q.set(auxBinding(nodeId, hApp(models), hPosture(posture), nonce), REPORT_DATA_OFF + 32)
    return q
}

/**
 * A bundle in the decoder's shape: Go zero values for everything absent. The
 * quote commits to over.posture, as a genuine node's would to the posture it
 * publishes, so a posture case reaches the posture step rather than dying on
 * the aux binding.
 */
function bundle(over: Partial<TEEEvidenceBundle> = {}): TEEEvidenceBundle {
    const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID, capturedModels(), NODE_ID, null, over.posture)
    return {
        mode: TEE_MODE_DSTACK_TDX,
        cpu_report: b64(q),
        gpu_eat: '',
        event_log: eventLog,
        app_compose: '',
        posture: undefined,
        node_pubkey: NODE_PUBKEY,
        operator_id: Number(OPERATOR_ID),
        report_data: b64(reportData(NODE_PUBKEY, OPERATOR_ID)),
        app_models: capturedModels(),
        nonce: undefined,
        generated_at: MINTED,
        refresh_seconds: 1200,
        stub: false,
        ...over,
    }
}

function stubBundle(over: Partial<TEEEvidenceBundle> = {}): TEEEvidenceBundle {
    return bundle({ mode: TEE_MODE_STUB, stub: true, cpu_report: '', event_log: '', ...over })
}

function advert(mode: string = TEE_MODE_DSTACK_TDX): TEEAdvertisement {
    return { mode, evidence_url: '/v1/zs/attestation' }
}

function node(over: Partial<Node> = {}): Node {
    return { operatorId: OPERATOR_ID, nodeId: NODE_ID, ephemeralRecipientPubkey: NODE_PUBKEY, ...over }
}

// The literal, not ACCEPTED_TCB_STATUS: returning the constant would make the
// happy path agree with whatever value the constant holds.
const okChain: QuoteChainVerifier = async () => ({ tcbStatus: 'UpToDate', advisoryIds: [] })

const outage = (): never => {
    throw new CollateralUnavailableError(new Error('dial tcp: no route to host'))
}

/**
 * The shared rules without the per-release half, so a fixture that publishes
 * no app_compose, or a synthetic one, is judged on what the case is about
 * rather than refused by the release match.
 */
function shapeOnlyPolicy(): ComposePolicy {
    return { ...zeroSignalComposePolicy(), enforceComposeSkeleton: false }
}

function verifier(over: BundleVerifierOptions = {}): BundleVerifier {
    return new BundleVerifier({
        trustedOSImages: [OS_IMAGE],
        trustedComposeHashes: [COMPOSE_HASH],
        composePolicy: shapeOnlyPolicy(),
        verifyChain: okChain,
        now: () => NOW_MS,
        ...over,
    })
}

function verify(
    b: TEEEvidenceBundle,
    over: BundleVerifierOptions = {},
    n: Node = node(),
    a: TEEAdvertisement = advert(b.mode),
): Promise<Verdict> {
    return verifier(over).verify(a, b, n)
}

/** A logger that keeps the WARN lines, for cases whose verdicts cannot say which rule refused. */
function warnLog(): { log: Logger; warns: string[] } {
    const warns: string[] = []
    const log: Logger = {
        debug() {},
        info() {},
        warn(msg) {
            warns.push(msg)
        },
        error() {},
    }
    return { log, warns }
}

function upstream(over: Partial<UpstreamAttestation> = {}): UpstreamAttestation {
    return {
        protocol: 'aci/1',
        base_url: '',
        report_url: '',
        keyset_digest: '',
        verified_at: '',
        lease_expires_at: '',
        carve_outs: [],
        ...over,
    }
}

// A complete, dated collateral set from Go's collateral vectors: every
// document issued exactly at now_unix_ms.
const freshVector = (
    JSON.parse(readFileSync(testdata('collateral_vectors.json'), 'utf8')) as {
        collateral_fresh: { name: string; collateral: TEECollateral; now_unix_ms: number; fresh: boolean }[]
    }
).collateral_fresh.find((c) => c.name === 'all_now')
if (freshVector === undefined || !freshVector.fresh) throw new Error('collateral_vectors.json lost its all_now case')
const COLLATERAL_ISSUED_MS = freshVector.now_unix_ms
const freshCollateral = (): TEECollateral => ({ ...freshVector.collateral })

/**
 * Runs a case that reaches the carried rung on the collateral vector's clock.
 * The verifier dates the node's documents against the same `now` that bounds
 * the bundle's age, so the bundle is re-dated a minute before it.
 */
function carriedVerify(
    nowMs: number,
    b: Partial<TEEEvidenceBundle> = {},
    over: BundleVerifierOptions = {},
    signal?: AbortSignal,
): Promise<Verdict> {
    const bun = bundle({ generated_at: new Date(nowMs - 60_000).toISOString(), collateral: freshCollateral(), ...b })
    return verifier({ now: () => nowMs, ...over }).verify(advert(), bun, node(), signal)
}
const CARRIED_NOW_MS = COLLATERAL_ISSUED_MS + 60_000

// A cross-implementation agreement, not a local preference: go-tdx-guest
// compares against exactly this string.
it('accepts exactly the TCB status the proxy accepts', () => {
    expect(ACCEPTED_TCB_STATUS).toBe('UpToDate')
})

describe('BundleVerifier: dstack happy path', () => {
    it('verifies a real capture and recovers the replayed measurements', async () => {
        const v = await verify(bundle())

        expect(v.pass).toBe(true)
        expect(v.failureTag).toBe('')
        expect(v.verifierId).toBe('dstack-tdx')
        expect(v.attestedAt).toBe(MINTED_MS)
        expect(v.detail?.tcbStatus).toBe('UpToDate')
        // Read off the REPLAY, and identical to what the Go suite recovers
        // from the same bytes. A self-reported field could not produce these.
        expect(v.detail?.measurements?.composeHash).toBe(COMPOSE_HASH)
        expect(v.detail?.measurements?.osImageHash).toBe(OS_IMAGE)
        expect(v.detail?.measurements?.appId).toBe(APP_ID)
    })

    it('says which reference checks the pass rested on', async () => {
        // The OS image and the whole-document pin were checked; no release
        // match ran, so a caller must not read this as "software we vouch for".
        const v = await verify(bundle())
        expect(v.pass).toBe(true)
        expect(v.detail?.measurementChecks).toEqual({ osImage: true, composeRelease: false, composeHash: true })
    })

    it('refuses an OS image that is not on the trusted list', async () => {
        // The dev-image case: every other check passes identically on a
        // dstack-dev image while the hardening guarantees do not hold. The
        // list is overridden rather than the log mutated, which would fail
        // one step earlier and prove nothing about this one.
        const v = await verify(bundle(), { trustedOSImages: ['00'.repeat(32)] })
        expect(v.pass).toBe(false)
        expect(v.failureTag).toBe('measurement_mismatch')
        // Surfaced for display on the refusal, so a payer can see which image was presented.
        expect(v.detail?.measurements?.osImageHash).toBe(OS_IMAGE)
        // Only a pass says what it rested on.
        expect(v.detail?.measurementChecks).toBeUndefined()
    })

    it('verifies nothing against an empty OS image list', async () => {
        // There is no default list: empty must not read as "accept anything".
        const v = await verify(bundle(), { trustedOSImages: [] })
        expect(v.failureTag).toBe('measurement_mismatch')
    })
})

describe('measurementTrusted', () => {
    it('never matches two nothings', () => {
        // Reachable only when both sides are empty, which a config typo or a
        // trimmed list produces.
        expect(measurementTrusted([], '')).toBe(false)
        expect(measurementTrusted([''], '')).toBe(false)
        // Emptiness is tested after normalizing, on both sides.
        expect(measurementTrusted([''], '0x')).toBe(false)
        expect(measurementTrusted(['0x'], '0x')).toBe(false)
        expect(measurementTrusted(['', '  ', '0x', '0X'], OS_IMAGE)).toBe(false)
    })

    it('folds case and an 0x prefix, as Go does', () => {
        expect(measurementTrusted([OS_IMAGE], OS_IMAGE.toUpperCase())).toBe(true)
        expect(measurementTrusted([OS_IMAGE.toUpperCase()], OS_IMAGE)).toBe(true)
        expect(measurementTrusted([`0x${OS_IMAGE}`], OS_IMAGE)).toBe(true)
        expect(measurementTrusted([OS_IMAGE], `0X${OS_IMAGE.toUpperCase()}`)).toBe(true)
        // A near miss is still a miss.
        expect(measurementTrusted([OS_IMAGE], OS_IMAGE.slice(0, -1))).toBe(false)
        expect(measurementTrusted([OS_IMAGE.slice(0, -1)], OS_IMAGE)).toBe(false)
    })

    it("trims Go's whitespace set, not String.prototype.trim's", () => {
        expect(measurementTrusted([` ${OS_IMAGE}\t`], OS_IMAGE)).toBe(true)
        expect(measurementTrusted([OS_IMAGE], `\n${OS_IMAGE} `)).toBe(true)
        // unicode.IsSpace characters, including U+0085, which trim() keeps.
        for (const c of [0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]) {
            const sp = String.fromCharCode(c)
            expect(measurementTrusted([`${sp}${OS_IMAGE}${sp}`], OS_IMAGE), `U+${c.toString(16)}`).toBe(true)
            expect(measurementTrusted([OS_IMAGE], `${sp}0x${OS_IMAGE}`), `U+${c.toString(16)}`).toBe(true)
        }
        // And not the ones Go does not count as space: U+FEFF, which trim()
        // strips, and the zero-width space.
        for (const c of [0xfeff, 0x200b]) {
            const sp = String.fromCharCode(c)
            expect(measurementTrusted([`${sp}${OS_IMAGE}`], OS_IMAGE), `U+${c.toString(16)}`).toBe(false)
        }
        // A list of blanks in Go's whitespace still matches nothing.
        expect(measurementTrusted([String.fromCharCode(0x3000)], String.fromCharCode(0x85))).toBe(false)
    })
})

describe('BundleVerifier: bundle-level checks', () => {
    it('fails closed with no verified ephemeral to bind to', async () => {
        const v = await verify(bundle(), {}, node({ ephemeralRecipientPubkey: '' }))
        expect(v.failureTag).toBe('key_binding_mismatch')
        expect(v.verifierId).toBe('builtin')
    })

    it.each([
        ['mode disagrees with the advertisement', { mode: TEE_MODE_STUB }],
        ['operator id disagrees with the chain', { operator_id: 43 }],
        ['node_pubkey is not the key we would seal to', { node_pubkey: 'age1someoneelse' }],
    ] as const)('refuses when the %s', async (_name, over) => {
        const v = await verify(bundle(over), {}, node(), advert())
        expect(v.failureTag).toBe('advertisement_mismatch')
    })

    it('catches a mode disagreement where BOTH modes are known', async () => {
        // A stub bundle mode also falls to the switch's default, so the case
        // above is caught twice; here the bundle mode IS a real branch.
        const v = await verify(bundle(), {}, node(), advert(TEE_MODE_STUB))
        expect(v.failureTag).toBe('advertisement_mismatch')
        expect(v.verifierId).toBe('builtin')
    })

    it('reports attestedAt on a failure verdict too, and 0 when absent', async () => {
        const v = await verify(bundle({ operator_id: 43 }))
        expect(v.failureTag).toBe('advertisement_mismatch')
        expect(v.attestedAt).toBe(MINTED_MS)

        const absent = await verify(bundle({ generated_at: '' }))
        expect(absent.failureTag).toBe('stale_evidence')
        expect(absent.attestedAt).toBe(0)

        // Go's zero time, as a Go node with no time set serializes it, is
        // absent too: Go's IsZero, not year 1.
        const zero = await verify(bundle({ generated_at: '0001-01-01T00:00:00Z' }))
        expect(zero.failureTag).toBe('stale_evidence')
        expect(zero.attestedAt).toBe(0)
    })

    it('compares operator ids at full uint64 precision', async () => {
        // 42 vs 43 differ far below 2^53. Under Number() these two are equal.
        const v = await verify(bundle({ operator_id: Number(2n ** 53n) }), {}, node({ operatorId: 2n ** 53n + 1n }))
        expect(v.failureTag).toBe('advertisement_mismatch')
    })

    it('refuses evidence older than twice the advertised cadence', async () => {
        const v = await verify(bundle({ refresh_seconds: 60 }))
        expect(v.failureTag).toBe('stale_evidence')
    })

    it.each(['not-a-date', '', '2026-13-45T99:99:99Z'])(
        'treats generated_at %j as stale rather than skipping the check',
        async (generated_at) => {
            // The operator authors this field, so garbage in it must not be
            // the cheapest bypass of freshness.
            const v = await verify(bundle({ generated_at, refresh_seconds: 60 }))
            expect(v.failureTag).toBe('stale_evidence')
        },
    )

    it('verifies a well-formed timestamp inside the window', async () => {
        // The converse, or the block above passes for a rule that rejects every timestamp.
        const v = await verify(bundle({ refresh_seconds: 600 }))
        expect(v.pass).toBe(true)
    })

    it('refuses evidence dated in the FUTURE', async () => {
        // A one-sided bound never fires on a negative age, so a node minting
        // once with a far-future date would be fresh forever.
        const v = await verify(bundle({ generated_at: '2126-01-01T00:00:00Z', refresh_seconds: 60 }))
        expect(v.failureTag).toBe('stale_evidence')
    })

    it('tolerates small clock skew in both directions', async () => {
        for (const skewMs of [-2000, 2000]) {
            const v = await verify(bundle({ refresh_seconds: 600 }), { now: () => MINTED_MS + skewMs })
            expect(v.pass, `skew ${skewMs}ms`).toBe(true)
        }
    })

    it.each([
        // Inside 2x cadence: pins the multiplier against a tightening to 1x.
        [1.5, true],
        [2.5, false],
    ])('applies the 2x cadence window at %sx', async (multiple, want) => {
        const v = await verify(bundle({ refresh_seconds: 600 }), { now: () => MINTED_MS + multiple * 600_000 })
        expect(v.pass).toBe(want)
    })

    it('does not let a negative cadence rescue an unparseable timestamp', async () => {
        const v = await verify(bundle({ refresh_seconds: -1, generated_at: 'not-a-date' }))
        expect(v.failureTag).toBe('stale_evidence')
    })

    it('lets a negative cadence fall back to the ceiling, not to rejection', async () => {
        // Pins `> 0` against `!== 0`: under the latter the doubled duration is
        // negative and this fresh bundle fails.
        const v = await verify(bundle({ refresh_seconds: -1 }), { now: () => MINTED_MS + 10 * 60_000 })
        expect(v.pass).toBe(true)
    })

    it('pins the ceiling to the literal, and to twice the ephemeral lifetime', () => {
        // A literal on both sides on purpose; the derived relation is what
        // fires when the ephemeral window is retuned.
        expect(EVIDENCE_MAX_AGE_CEILING_MS).toBe(80 * 60 * 1000)
        expect(EVIDENCE_MAX_AGE_CEILING_MS).toBe(2 * MAX_EPHEMERAL_LIFETIME_SEC * 1000)
        expect(EVIDENCE_MAX_AGE_CEILING_MS).toBeGreaterThan((MAX_EPHEMERAL_LIFETIME_SEC + DEFAULT_EPHEMERAL_SKEW_SEC) * 1000)
    })

    // These assert the window ACTUALLY APPLIED, expressed through the
    // constant, so a literal reintroduced at the call site cannot pass the
    // pin above and every behavioural case. The clamped arm is the one that
    // fails when the ceiling stops being a minimum over an advertised value.
    it.each([
        ['no cadence advertised', 0],
        ['a cadence far wider than the ceiling', 86400],
    ])('applies the ceiling as the effective window with %s', async (_label, refresh_seconds) => {
        const inside = await verify(bundle({ refresh_seconds }), {
            now: () => MINTED_MS + EVIDENCE_MAX_AGE_CEILING_MS - 60_000,
        })
        expect(inside.pass, 'one minute inside the ceiling').toBe(true)

        const outside = await verify(bundle({ refresh_seconds }), {
            now: () => MINTED_MS + EVIDENCE_MAX_AGE_CEILING_MS + 60_000,
        })
        expect(outside.failureTag, 'one minute past the ceiling').toBe('stale_evidence')
    })

    it.each([
        ['omitted', 0],
        ['negative', -1],
        ['a day long', 86400],
    ])('refuses a future-dated bundle whose cadence is %s', async (_label, refresh_seconds) => {
        const v = await verify(bundle({ generated_at: '2126-01-01T00:00:00Z', refresh_seconds }))
        expect(v.failureTag).toBe('stale_evidence')
    })

    // The bound is `>`, so evidence aged EXACTLY the window is fresh, in both
    // directions, and one millisecond more is not.
    it.each([
        ['an advertised cadence', 600, 2 * 600 * 1000],
        ['the ceiling', 0, EVIDENCE_MAX_AGE_CEILING_MS],
    ])('holds the window exactly at its edge under %s', async (_label, refresh_seconds, windowMs) => {
        const at = (deltaMs: number) => verify(bundle({ refresh_seconds }), { now: () => MINTED_MS + deltaMs })
        expect((await at(windowMs)).pass, 'aged exactly the window').toBe(true)
        expect((await at(-windowMs)).pass, 'dated exactly the window ahead').toBe(true)
        expect((await at(windowMs + 1)).failureTag, 'one ms past').toBe('stale_evidence')
        expect((await at(-windowMs - 1)).failureTag, 'one ms further ahead').toBe('stale_evidence')
    })

    it('applies the ceiling to a bundle that advertises no cadence at all', async () => {
        // refresh_seconds is the NODE's field, so freshness must not be opt-out by omission.
        const v = await verify(bundle({ refresh_seconds: 0 }), { now: () => Date.parse('2030-01-01T00:00:00Z') })
        expect(v.failureTag).toBe('stale_evidence')
    })

    it('verifies a cadence-less bundle minted inside the ceiling', async () => {
        const v = await verify(bundle({ refresh_seconds: 0 }), { now: () => MINTED_MS + 10 * 60_000 })
        expect(v.pass).toBe(true)
    })

    it('caps a cadence wide enough to outrun the ceiling', async () => {
        const v = await verify(bundle({ refresh_seconds: 86400 }), { now: () => MINTED_MS + 2 * 60 * 60_000 })
        expect(v.failureTag).toBe('stale_evidence')
    })

    // Go computes 2 * refresh_seconds * 1e9 in int64, so a large enough
    // cadence wraps. Float arithmetic would land on a huge positive window
    // and then the ceiling; these pin where Go lands instead.
    it.each([
        ['wraps just past int64', 4_611_686_019],
        ['wraps far past int64', 2 ** 33],
    ])('falls back to the ceiling when the cadence %s', async (_label, refresh_seconds) => {
        const inside = await verify(bundle({ refresh_seconds }), { now: () => MINTED_MS + 10 * 60_000 })
        expect(inside.pass, 'a negative product must not pin maxAge negative').toBe(true)
        const past = await verify(bundle({ refresh_seconds }), {
            now: () => MINTED_MS + EVIDENCE_MAX_AGE_CEILING_MS + 1,
        })
        expect(past.failureTag, 'one ms past the ceiling').toBe('stale_evidence')
    })

    it('reports freshness before the key binding', async () => {
        // Tag precedence, not the accept bit: the tags are telemetry handles,
        // so a reorder relabels a whole class of failures.
        const v = await verify(bundle({ refresh_seconds: 60, report_data: b64(new Uint8Array(32)) }))
        expect(v.failureTag).toBe('stale_evidence')
    })

    it('refuses a self-reported report_data that is not the binding', async () => {
        const v = await verify(bundle({ report_data: b64(new Uint8Array(32)) }))
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it('refuses an unparseable report_data rather than throwing', async () => {
        const v = await verify(bundle({ report_data: '!!!not b64' }))
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it('refuses an unpadded report_data, as Go StdEncoding does', async () => {
        // The right bytes, without the padding. atob accepts this; Go does
        // not, and a lenient decode would pass a node the proxy refuses.
        const padded = b64(reportData(NODE_PUBKEY, OPERATOR_ID))
        expect(padded.endsWith('=')).toBe(true)
        const v = await verify(bundle({ report_data: padded.replace(/=+$/, '') }))
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it('accepts a line-wrapped report_data and cpu_report, as Go StdEncoding does', async () => {
        // Go's decoder skips CR and LF wherever they fall. The converse of
        // the strictness above, or a stricter decoder passes this suite while
        // refusing nodes the proxy admits.
        const b = bundle()
        const wrap = (s: string) => (s.match(/.{1,76}/g) ?? []).join('\r\n')
        const v = await verify({ ...b, report_data: wrap(b.report_data), cpu_report: wrap(b.cpu_report) })
        expect(v.pass, v.failureTag).toBe(true)
    })

    it('compares the LAST byte of the binding too', async () => {
        const off = reportData(NODE_PUBKEY, OPERATOR_ID)
        off[off.length - 1]! ^= 0x01
        const v = await verify(bundle({ report_data: b64(off) }))
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it('refuses a binding of the wrong LENGTH, extended or truncated', async () => {
        const base = reportData(NODE_PUBKEY, OPERATOR_ID)
        const extended = new Uint8Array(base.length + 1)
        extended.set(base)
        const truncated = base.subarray(0, base.length - 1)
        for (const [name, bytes] of [
            ['extended', extended],
            ['truncated', truncated],
        ] as const) {
            const v = await verify(bundle({ report_data: b64(bytes) }))
            expect(v.failureTag, name).toBe('key_binding_mismatch')
        }
    })
})

describe('BundleVerifier: stub gating', () => {
    it('rejects a stub bundle by default', async () => {
        const v = await verify(stubBundle())
        expect(v.failureTag).toBe('stub_not_allowed')
        expect(v.verifierId).toBe('builtin')
    })

    it('accepts a stub bundle only when explicitly opted in, claiming nothing was measured', async () => {
        const b = stubBundle()
        // A well-formed list, which is the point: nothing about its shape is
        // wrong, only that no quote checked it.
        expect(Array.isArray(b.app_models) && b.app_models.length > 0).toBe(true)
        const v = await verify(b, { allowStub: true })
        expect(v.pass).toBe(true)
        expect(v.failureTag).toBe('')
        expect(v.verifierId).toBe('builtin')
        expect(v.attestedAt).toBe(MINTED_MS)
        // A stub replays nothing, so it reports no measurements and no checks,
        // and no ids: they would be the node's own claim presented as verified.
        expect(v.detail).toBeUndefined()
        expect(v).not.toHaveProperty('attestedModelIds')
    })

    it('gates on the stub BOOL, never on mode === "stub"', async () => {
        // A bundle claiming mode stub while saying stub:false names a platform
        // with no verifier; a mode-keyed gate would accept it under allowStub.
        const v = await verify(stubBundle({ stub: false }), { allowStub: true })
        expect(v.pass).toBe(false)
        expect(v.failureTag).toBe('verifier_not_implemented')
    })

    it.each([
        ['builtin', { operator_id: 43 }],
        ['dstack-tdx', { event_log: '[]' }],
    ] as const)('claims no measurement checks on a %s failure verdict', async (verifierId, over) => {
        const v = await verify(bundle(over))
        expect(v.pass).toBe(false)
        expect(v.verifierId).toBe(verifierId)
        expect(v.detail?.measurementChecks).toBeUndefined()
    })

    it('checks the key binding BEFORE the stub short-circuit', async () => {
        // Otherwise a stub bundle could pass while attesting a key we would never seal to.
        const v = await verify(stubBundle({ report_data: b64(new Uint8Array(32)) }), { allowStub: true })
        expect(v.failureTag).toBe('key_binding_mismatch')
    })
})

describe('BundleVerifier: dstack platform checks', () => {
    it('derives the platform from the quote bytes, not the mode string', async () => {
        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID)
        q[4] = 0x00 // tee_type: SGX
        const v = await verify(bundle({ cpu_report: b64(q) }))
        expect(v.failureTag).toBe('vendor_chain_invalid')
        expect(v.verifierId).toBe('dstack-tdx')
    })

    it('refuses a cpu_report that is not base64', async () => {
        const v = await verify(bundle({ cpu_report: '!!!not base64!!!' }))
        expect(v.failureTag).toBe('vendor_chain_invalid')
    })

    it('refuses an unpadded cpu_report, as Go StdEncoding does', async () => {
        // The capture is 5010 bytes, which needs no padding; one more byte
        // past the signed region makes it need two. Padded, the stubbed chain
        // lets it through; unpadded, Go's decoder refuses before any of that.
        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID)
        const longer = new Uint8Array(q.length + 1)
        longer.set(q)
        const padded = b64(longer)
        expect(padded.endsWith('==')).toBe(true)
        expect((await verify(bundle({ cpu_report: padded }))).pass, 'padded control').toBe(true)
        const v = await verify(bundle({ cpu_report: padded.replace(/=+$/, '') }))
        expect(v.failureTag).toBe('vendor_chain_invalid')
    })

    it('refuses every quote when no chain verifier is configured', async () => {
        // There is no default chain verifier in the SDK yet; absent must not
        // read as "the chain is fine".
        const v = await new BundleVerifier({
            trustedOSImages: [OS_IMAGE],
            trustedComposeHashes: [COMPOSE_HASH],
            composePolicy: shapeOnlyPolicy(),
            now: () => NOW_MS,
        }).verify(advert(), bundle(), node())
        expect(v.failureTag).toBe('vendor_chain_invalid')
    })

    it('reports a chain failure as invalid evidence', async () => {
        const v = await verify(bundle(), {
            verifyChain: async () => {
                throw new Error('signature does not verify')
            },
        })
        expect(v.failureTag).toBe('vendor_chain_invalid')
    })

    it('reports OUR collateral outage as its own tag, not as forged evidence', async () => {
        // Collapsing the two stamps "invalid evidence" on the whole fleet
        // during one PCS outage. No carried verifier is configured, so the
        // default last resort refuses and the outage is what is reported.
        const v = await verify(bundle(), { verifyChain: async () => outage() })
        expect(v.failureTag).toBe('collateral_unreachable')
    })

    it.each(['SWHardeningNeeded', 'OutOfDate', 'ConfigurationNeeded', 'Revoked', 'Unknown', 'uptodate'])(
        'refuses TCB status %s',
        async (status) => {
            // Strictly UpToDate, as go-tdx-guest's checkTcbInfoTcbStatus.
            const v = await verify(bundle(), { verifyChain: async () => ({ tcbStatus: status, advisoryIds: [] }) })
            expect(v.failureTag).toBe('vendor_chain_invalid')
            expect(v.detail?.tcbStatus).toBe(status)
        },
    )

    it('refuses a non-UpToDate status from the carried rung as the outage', async () => {
        // In Go the status refusal happens inside VerifyTDXQuoteChainCarried,
        // so the last resort failed and the first rung's outage is reported.
        // Calling it invalid evidence would accuse the node during our outage.
        const v = await carriedVerify(CARRIED_NOW_MS, {}, {
            verifyChain: async () => outage(),
            verifyChainCarried: async () => ({ tcbStatus: 'OutOfDate', advisoryIds: ['INTEL-SA-00837'] }),
        })
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(v.pass).toBe(false)
    })

    it('refuses a non-UpToDate status on our own stale cache as the outage', async () => {
        // ErrStaleCollateralRejected in Go: a verdict reached on our aging
        // document, which neither earns the node's collateral nor accuses it.
        let carriedCalled = false
        const v = await carriedVerify(CARRIED_NOW_MS, {}, {
            verifyChain: async () => ({ tcbStatus: 'OutOfDate', advisoryIds: [], servedStale: true }),
            verifyChainCarried: async () => {
                carriedCalled = true
                return { tcbStatus: 'UpToDate', advisoryIds: [] }
            },
        })
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(carriedCalled).toBe(false)
    })

    it('passes UpToDate on our own stale cache', async () => {
        // A stale pass is a pass in Go; the fallback exists so an outage does
        // not take the fleet out of routing.
        const v = await verify(bundle(), {
            verifyChain: async () => ({ tcbStatus: 'UpToDate', advisoryIds: [], servedStale: true }),
        })
        expect(v.pass, v.failureTag).toBe(true)
    })

    it('treats an outage wrapped in a host error as the outage', async () => {
        // errors.Is walks the chain in Go; a host that wraps must not turn our
        // outage into an accusation.
        const v = await verify(bundle(), {
            verifyChain: async () => {
                throw new Error('pccs fetch failed', { cause: new CollateralUnavailableError('dns') })
            },
        })
        expect(v.failureTag).toBe('collateral_unreachable')
    })

    it('treats a caller abort during the chain step as the outage', async () => {
        // Go's chain check sees a cancelled fetch as ErrCollateralUnavailable,
        // so the node's own collateral is still consulted.
        const ac = new AbortController()
        let carriedCalled = false
        const v = await carriedVerify(
            CARRIED_NOW_MS,
            {},
            {
                verifyChain: async () => {
                    ac.abort()
                    throw new DOMException('aborted', 'AbortError')
                },
                verifyChainCarried: async () => {
                    carriedCalled = true
                    return { tcbStatus: 'UpToDate', advisoryIds: [] }
                },
            },
            ac.signal,
        )
        expect(carriedCalled).toBe(true)
        expect(v.pass, v.failureTag).toBe(true)
    })

    it('keeps a stale-cache refusal a refusal when the caller has also aborted', async () => {
        // Our own document reached a verdict; an abort arriving alongside it
        // must not turn that into an outage that earns the node's collateral.
        const ac = new AbortController()
        ac.abort()
        let carriedCalled = false
        const v = await carriedVerify(
            CARRIED_NOW_MS,
            {},
            {
                verifyChain: async () => {
                    throw new StaleCollateralRejectedError(new Error('pcs down'), new Error('crl expired'))
                },
                verifyChainCarried: async () => {
                    carriedCalled = true
                    return { tcbStatus: 'UpToDate', advisoryIds: [] }
                },
            },
            ac.signal,
        )
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(carriedCalled).toBe(false)
    })

    it('does not read an abort as an outage when no abort happened', async () => {
        // The same AbortError with the caller's signal live is the host's own
        // failure, and stays a vendor-chain refusal.
        const v = await verify(bundle(), {
            verifyChain: async () => {
                throw new DOMException('aborted', 'AbortError')
            },
        })
        expect(v.failureTag).toBe('vendor_chain_invalid')
    })

    // SPEC § 3e's precedence, as a decision table. The row that matters is
    // the stale-cache refusal: it is caused by an outage, but our own cached
    // Intel document reached a verdict, and falling through to the node's
    // set would trade a vintage we chose for one the operator chose.
    it.each([
        {
            name: 'PCS and our cache both empty, the node set verifies',
            chain: () => outage(),
            carried: async (): Promise<ChainResult> => ({ tcbStatus: 'UpToDate', advisoryIds: [] }),
            wantCarried: true,
            wantTag: '',
        },
        {
            // The OUTAGE tag, not a vendor-chain accusation: the verification
            // failed first because we could not reach Intel, and the last
            // resort's complaint describes the node's set.
            name: 'PCS and our cache both empty, the node set does not verify either',
            chain: () => outage(),
            carried: async (): Promise<ChainResult> => {
                throw new Error('chain does not root at Intel')
            },
            wantCarried: true,
            wantTag: 'collateral_unreachable',
        },
        {
            name: 'our own stale document refused the quote',
            chain: (): never => {
                throw new StaleCollateralRejectedError(new Error('pcs down'), new Error('crl expired'))
            },
            carried: async (): Promise<ChainResult> => ({ tcbStatus: 'UpToDate', advisoryIds: [] }),
            wantCarried: false,
            wantTag: 'collateral_unreachable',
        },
        {
            name: 'a verification that ran on current collateral and refused',
            chain: (): never => {
                throw new Error('tdx quote verification: signature mismatch')
            },
            carried: async (): Promise<ChainResult> => ({ tcbStatus: 'UpToDate', advisoryIds: [] }),
            wantCarried: false,
            wantTag: 'vendor_chain_invalid',
        },
    ])('chain precedence: $name', async ({ chain, carried, wantCarried, wantTag }) => {
        let called = false
        const v = await carriedVerify(CARRIED_NOW_MS, {}, {
            verifyChain: async () => chain(),
            verifyChainCarried: async () => {
                called = true
                return carried()
            },
        })
        expect(called).toBe(wantCarried)
        expect(v.failureTag).toBe(wantTag)
        expect(v.pass).toBe(wantTag === '')
    })

    it("hands the carried verifier the bundle's own collateral set", async () => {
        // Anything else would verify one node's quote against another's criteria.
        const own = freshCollateral()
        let got: TEECollateral | undefined
        const v = await carriedVerify(CARRIED_NOW_MS, { collateral: own }, {
            verifyChain: async () => outage(),
            verifyChainCarried: async (_q, c) => {
                got = c
                return { tcbStatus: 'UpToDate', advisoryIds: [] }
            },
        })
        expect(v.pass, v.failureTag).toBe(true)
        expect(got).toBe(own)
    })

    it("carries the caller's signal into both chain rungs", async () => {
        // The chain step is the one that reaches the network, so it is the
        // one a caller's deadline has to bound.
        const signal = new AbortController().signal
        const seen: (AbortSignal | undefined)[] = []
        const v = await carriedVerify(
            CARRIED_NOW_MS,
            {},
            {
                verifyChain: async (_q, s) => {
                    seen.push(s)
                    return outage()
                },
                verifyChainCarried: async (_q, _c, s) => {
                    seen.push(s)
                    return { tcbStatus: 'UpToDate', advisoryIds: [] }
                },
            },
            signal,
        )
        expect(v.pass, v.failureTag).toBe(true)
        expect(seen).toHaveLength(2)
        expect(seen[0]).toBe(signal)
        expect(seen[1]).toBe(signal)
    })

    it('refuses an event log that does not replay to the quote', async () => {
        const tampered = JSON.parse(eventLog) as { event_payload?: string }[]
        const first = tampered.find((e) => e.event_payload)
        if (first) first.event_payload = 'aabb'
        const v = await verify(bundle({ event_log: JSON.stringify(tampered) }))
        expect(v.failureTag).toBe('measurement_mismatch')
    })

    it.each([
        // An empty replay is 48 zero bytes, which equals an unmeasured register.
        ['empty', '[]'],
        ['absent', ''],
        // Appending changes the accumulator, or the log could carry any compose-hash.
        [
            'carrying an appended event',
            eventLog.trim().replace(/\]$/, '') +
                ',{"imr":3,"event_type":134217729,"digest":"","event":"extra","event_payload":"00"}]',
        ],
        // All non-runtime events replay to zero, the same as an unmeasured RTMR3.
        ['extending nothing', '[{"imr":0,"event_type":2147483649,"digest":"","event":"boot","event_payload":"aabb"}]'],
    ])('refuses an event log %s', async (_name, event_log) => {
        const v = await verify(bundle({ event_log }))
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.verifierId).toBe('dstack-tdx')
    })

    it('refuses a quote truncated inside report_data as a key binding failure', async () => {
        // Real DCAP refuses it at the chain; with the chain stubbed it reaches
        // the split, which must not call it a node that needs upgrading.
        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID).subarray(0, 600)
        const v = await verify(bundle({ cpu_report: b64(q) }))
        expect(v.pass).toBe(false)
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it('refuses a quote whose signed binding is not the key we would seal to', async () => {
        // The capture's lower half untouched (it binds the real node's key),
        // with the aux binding spliced in so the quote clears the 9.9 shape
        // check. The self-report is ours, so only the signed value catches it.
        const q = Uint8Array.from(quote)
        q.set(auxBinding(NODE_ID, hApp(capturedModels()), hPosture(undefined), null), REPORT_DATA_OFF + 32)
        const v = await verify(bundle({ cpu_report: b64(q) }))
        expect(v.failureTag).toBe('key_binding_mismatch')
        // ...and it got far enough to have done the real work first.
        expect(v.detail?.tcbStatus).toBe(ACCEPTED_TCB_STATUS)
        expect(v.detail?.measurements?.composeHash).toBe(COMPOSE_HASH)
    })

    it('refuses evidence whose self-report agrees with a substituted key', async () => {
        // The self-reported report_data and node_pubkey both name the other
        // key, so the bundle-level checks pass; the bytes Intel signed do not.
        const other = 'age1someotherrecipient00000000000000000000000000000'
        const b = bundle({ node_pubkey: other, report_data: b64(reportData(other, OPERATOR_ID)) })
        const v = await verify(b, {}, node({ ephemeralRecipientPubkey: other }))
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it('refuses attacker bytes anywhere in the aux binding', async () => {
        // The signature covers all 64 bytes, so every byte left unchecked is
        // attacker-chosen input handed back signed by real hardware.
        for (let i = 32; i < 64; i++) {
            const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID)
            q[REPORT_DATA_OFF + i]! ^= 0xff
            const v = await verify(bundle({ cpu_report: b64(q) }))
            expect(v.pass, `byte ${i} verified`).toBe(false)
            expect(v.failureTag, `byte ${i}`).toBe('aux_binding_mismatch')
        }
    })

    it('refuses a pre-9.9 zero upper half as such, not as a crypto failure', async () => {
        // The fix for a pre-9.9 node is an upgrade, so it must not be tagged
        // as a key problem; and without this the sweep above passes for a
        // verifier that refuses every upper half.
        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID)
        q.fill(0, REPORT_DATA_OFF + 32, REPORT_DATA_OFF + 64)
        const v = await verify(bundle({ cpu_report: b64(q) }))
        expect(v.failureTag).toBe('aux_binding_absent')
        expect(v.detail?.tcbStatus).toBe(ACCEPTED_TCB_STATUS)
        expect(v.detail?.measurements?.composeHash).toBe(COMPOSE_HASH)
    })

    it('checks the key half before calling a zero upper half out of date', async () => {
        // The unmodified capture: a zero upper half, and a lower half binding
        // the captured node's key rather than ours.
        expect(quote.subarray(REPORT_DATA_OFF + 32, REPORT_DATA_OFF + 64).every((b) => b === 0)).toBe(true)
        const v = await verify(bundle({ cpu_report: b64(quote) }))
        expect(v.failureTag).toBe('key_binding_mismatch')
    })

    it("refuses a sibling node's quote: the aux binding hashes this node's id", async () => {
        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID, capturedModels(), NODE_ID + 1n)
        const v = await verify(bundle({ cpu_report: b64(q) }))
        expect(v.failureTag).toBe('aux_binding_mismatch')
    })

    it('binds to the verified ephemeral and chain id, never the self-report', async () => {
        // Called on DstackVerifier directly: through BundleVerifier an earlier
        // check forces the self-report equal to the node's key and id, so a
        // verifier hashing the wrong one is invisible there.
        const dv = new DstackVerifier({
            trustedOSImages: [OS_IMAGE],
            trustedComposeHashes: [COMPOSE_HASH],
            composePolicy: {},
            verifyChain: okChain,
        })
        const b = bundle()
        expect((await dv.verify(b, node())).failureTag, 'baseline').toBe('')

        const moved = await dv.verify(b, node({ ephemeralRecipientPubkey: 'age1differentkey00000000000000000000' }))
        expect(moved.failureTag).toBe('key_binding_mismatch')
        const idMoved = await dv.verify(b, node({ operatorId: 43n }))
        expect(idMoved.failureTag).toBe('key_binding_mismatch')
    })

    // Admission does not depend on these tags; they decide what the operator
    // is told to fix. proto's aux_verify vectors pin the decision.
    it('reports a catalog the node did not publish as missing, not disagreeing', async () => {
        const v = await verify(bundle({ app_models: undefined }))
        expect(v.failureTag).toBe('happ_preimage_missing')
        expect(v.detail?.tcbStatus).toBe(ACCEPTED_TCB_STATUS)
    })

    it('reports a catalog that cannot be hashed as invalid, not disagreeing', async () => {
        const dup = capturedModels()
        dup[1]!.model_id = dup[0]!.model_id
        const v = await verify(bundle({ app_models: dup }))
        expect(v.failureTag).toBe('happ_preimage_invalid')
    })

    it('reports an entry missing its weights_digest key as invalid', async () => {
        // As decoded from the wire: Go's strict decoder marks the entry
        // malformed, since the state/digest rule needs the key present.
        const entries = JSON.parse('[{"model_id":"qwen3-30b","source":"hf/Qwen/Qwen3-30B","weights_state":1}]') as unknown
        const v = await verify(bundle({ app_models: entries }))
        expect(v.failureTag).toBe('happ_preimage_invalid')
    })

    describe('the nonce slot', () => {
        // No challenge is sent, so the echoed nonce is hashed as given. A
        // bundle minted for another caller's ?nonce= must still verify.
        const NONCE = Uint8Array.from({ length: 32 }, (_, i) => i + 0xa0)

        it('hashes an echoed nonce in upper or lower case', async () => {
            const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID, capturedModels(), NODE_ID, NONCE)
            for (const echoed of [hex(NONCE), hex(NONCE).toUpperCase()]) {
                const v = await verify(bundle({ cpu_report: b64(q), nonce: echoed }))
                expect(v.pass, `${echoed}: ${v.failureTag}`).toBe(true)
            }
        })

        it('refuses a malformed nonce rather than hashing it as absent', async () => {
            // The quote is bound with no nonce, so falling back to zeros on an
            // unparseable value would pass these bundles.
            for (const bad of ['zz', hex(NONCE.subarray(0, 16)), hex(NONCE) + '00']) {
                const v = await verify(bundle({ nonce: bad }))
                expect(v.pass, `nonce ${bad}`).toBe(false)
                expect(v.failureTag, `nonce ${bad}`).toBe('aux_binding_mismatch')
            }
        })
    })
})

describe('BundleVerifier: the attested model set', () => {
    // attestedModelIds is how the verified list reaches a model card. On a
    // refusal the list is exactly what failed to check out.
    it('carries the verified ids on a dstack pass', async () => {
        const v = await verify(bundle())
        expect(v.pass).toBe(true)
        expect(v.attestedModelIds).toEqual(['qwen3-30b', 'glm-4.6', 'grok-4'])
    })

    it('carries an empty array for a node attesting it serves nothing', async () => {
        // A signed empty catalog is a checkable claim; absent would read as
        // "no verified list". The key is absent because Go marshals app_models
        // with omitempty, which is what a real node sends.
        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID, [])
        const v = await verify(bundle({ cpu_report: b64(q), app_models: undefined }))
        expect(v.pass).toBe(true)
        expect(v.attestedModelIds).toEqual([])
    })

    it('carries nothing on a refusal, whatever the node published', async () => {
        const other = capturedModels()
        other[0]!.model_id = 'something-else'
        const v = await verify(bundle({ app_models: other }))
        expect(v.failureTag).toBe('aux_binding_mismatch')
        expect(v).not.toHaveProperty('attestedModelIds')
    })

    it.each<[string, () => Promise<Verdict>]>([
        ['key_binding_mismatch', () => verify(bundle(), {}, node({ ephemeralRecipientPubkey: '' }))],
        ['advertisement_mismatch', () => verify(bundle({ operator_id: 43 }))],
        ['stale_evidence', () => verify(bundle({ refresh_seconds: 60 }))],
        ['stub_not_allowed', () => verify(stubBundle())],
        ['verifier_not_implemented', () => verify(bundle({ mode: TEE_MODE_NVIDIA_CC_TDX }))],
        ['vendor_chain_invalid', () => verify(bundle(), { verifyChain: async () => ({ tcbStatus: 'OutOfDate', advisoryIds: [] }) })],
        ['collateral_unreachable', () => verify(bundle(), { verifyChain: async () => outage() })],
        ['measurement_mismatch', () => verify(bundle(), { trustedComposeHashes: [] })],
        ['aux_binding_absent', () => {
            const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID)
            q.fill(0, REPORT_DATA_OFF + 32, REPORT_DATA_OFF + 64)
            return verify(bundle({ cpu_report: b64(q) }))
        }],
        // Checked after the aux binding passed, so the list DID verify here; a
        // verifier setting the ids on reaching the aux step would leak them.
        ['advertisement_mismatch', () =>
            verify(bundle({ posture: { plaintext_terminates: PLAINTEXT_IN_ENCLAVE, upstream_base_url: 'https://x' } }))],
    ])('carries no ids on a %s refusal', async (tag, run) => {
        const v = await run()
        expect(v.failureTag).toBe(tag)
        expect(v).not.toHaveProperty('attestedModelIds')
    })
})

// The checks Go's VerifyTDXQuoteChainCarried makes before verifying. The host
// supplies only the verification, so these run whatever it passes: a bare
// carried verifier must not reach a set the node chose to omit or roll back.
describe('BundleVerifier: carried-collateral guard', () => {
    interface Spy {
        calls: number
        seen: TEECollateral | undefined
        carried: CarriedChainVerifier
    }

    function spy(): Spy {
        const s: Spy = {
            calls: 0,
            seen: undefined,
            carried: async (_q, c): Promise<ChainResult> => {
                s.calls++
                s.seen = c
                return { tcbStatus: 'UpToDate', advisoryIds: [] }
            },
        }
        return s
    }

    const run = (s: Spy, nowMs: number, b: Partial<TEEEvidenceBundle> = {}) =>
        carriedVerify(nowMs, b, { verifyChain: async () => outage(), verifyChainCarried: s.carried })

    it('hands a complete, current set to the host verifier', async () => {
        const s = spy()
        const own = freshCollateral()
        const v = await run(s, CARRIED_NOW_MS, { collateral: own })
        expect(v.pass, v.failureTag).toBe(true)
        expect(s.calls).toBe(1)
        expect(s.seen).toBe(own)
    })

    it('reports an absent set as the outage without calling the host', async () => {
        // The ordinary case: a node on a build that never published collateral.
        const s = spy()
        const { collateral: _omitted, ...b } = bundle({ generated_at: new Date(CARRIED_NOW_MS - 60_000).toISOString() })
        const v = await verifier({
            now: () => CARRIED_NOW_MS,
            verifyChain: async () => outage(),
            verifyChainCarried: s.carried,
        }).verify(advert(), b, node())
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(s.calls).toBe(0)
    })

    it.each<[string, Partial<TEEEvidenceBundle>]>([
        ['missing a member', { collateral: { ...freshCollateral(), pck_crl: '' } }],
        ['missing a signature', { collateral: { ...freshCollateral(), qe_identity_signature: '' } }],
    ])('reports a set %s as the outage without calling the host', async (_name, b) => {
        const s = spy()
        const v = await run(s, CARRIED_NOW_MS, b)
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(s.calls).toBe(0)
    })

    it.each([
        ['older than the floor', COLLATERAL_ISSUED_MS + EMBEDDED_COLLATERAL_MAX_AGE_MS + 1],
        // A future-dated document would otherwise pass any floor.
        ['dated in the future', COLLATERAL_ISSUED_MS - 1],
    ])('reports a set %s as the outage without calling the host', async (_name, nowMs) => {
        const s = spy()
        const v = await run(s, nowMs)
        expect(v.failureTag).toBe('collateral_unreachable')
        expect(s.calls).toBe(0)
    })

    it('admits a set aged exactly the floor', async () => {
        // The other side of the boundary, or the case above passes for a
        // guard that refuses every carried set.
        const s = spy()
        const v = await run(s, COLLATERAL_ISSUED_MS + EMBEDDED_COLLATERAL_MAX_AGE_MS)
        expect(v.pass, v.failureTag).toBe(true)
        expect(s.calls).toBe(1)
    })

    it('dates the documents against the verifier clock, not the wall clock', async () => {
        // With the wall clock a year past the documents, a guard reading
        // Date.now would refuse a set the verifier's clock says is current.
        const s = spy()
        const wall = vi.spyOn(Date, 'now').mockReturnValue(COLLATERAL_ISSUED_MS + 365 * 24 * 60 * 60_000)
        try {
            const v = await run(s, CARRIED_NOW_MS)
            expect(v.pass, v.failureTag).toBe(true)
            expect(s.calls).toBe(1)
        } finally {
            wall.mockRestore()
        }
    })

    it('refuses every carried set when the host supplies no carried verifier', async () => {
        const v = await carriedVerify(CARRIED_NOW_MS, {}, { verifyChain: async () => outage() })
        expect(v.failureTag).toBe('collateral_unreachable')
    })
})

describe('BundleVerifier: compose content', () => {
    // The document the live CVM actually ran, from the same capture the quote
    // and event log came from. One CVM, three files: splitting them across
    // captures would let the hash gate pass while the halves described
    // different machines.
    function capturedAppCompose(): string {
        const info = JSON.parse(readFileSync(testdata('attest/ds_info.json'), 'utf8')) as { tcb_info: string }
        const tcb = JSON.parse(info.tcb_info) as { app_compose: string }
        if (!tcb.app_compose) throw new Error('the capture carries no app_compose')
        return tcb.app_compose
    }

    /** A compose in the shape the deploy recipe publishes. */
    function releaseCompose(image: string, config: string): string {
        return (
            'services:\n' +
            '  zs-node:\n' +
            `    image: ${image}\n` +
            '    volumes:\n' +
            '      - /var/run/dstack.sock:/var/run/dstack.sock\n' +
            '      - zs-node-state:/data\n' +
            '    ports:\n' +
            '      - "9090:9090"\n' +
            '    environment:\n' +
            '      NODE_CONFIG_YAML: |\n' +
            config +
            '      NODE_LLM_OPENAI_API_KEY: ${NODE_LLM_OPENAI_API_KEY}\n' +
            '    restart: always\n' +
            'volumes:\n' +
            '  zs-node-state: {}\n'
        )
    }

    const RELEASE_IMAGE = 'ghcr.io/txnlab/zs-node@sha256:' + 'ab'.repeat(32)
    const OPERATOR_CONFIG = '        zs: { operator_id: 1, node_id: 2 }\n'

    /** A policy-clean app-compose document, as JSON. */
    function cleanDoc(over: Record<string, unknown> = {}): string {
        return JSON.stringify({
            manifest_version: 2,
            name: 'zs-node',
            runner: 'docker-compose',
            docker_compose_file: releaseCompose(RELEASE_IMAGE, OPERATOR_CONFIG),
            pre_launch_script: '',
            allowed_envs: ['NODE_LLM_OPENAI_API_KEY', 'OPERATOR_SIGNING_MNEMONIC'],
            features: [],
            gateway_enabled: true,
            tproxy_enabled: false,
            kms_enabled: true,
            local_key_provider_enabled: false,
            no_instance_id: false,
            secure_time: false,
            public_logs: false,
            public_sysinfo: false,
            public_tcbinfo: true,
            storage_fs: '',
            ...over,
        })
    }

    /**
     * A bundle whose HARDWARE measured doc. Rewriting the document alone would
     * leave the log naming the capture's digest and every case would stop at
     * the hash gate, so the compose-hash event is rewritten, the log replayed
     * and the resulting RTMR3 written into the quote.
     */
    function bundleMeasuring(doc: string): { bundle: TEEEvidenceBundle; composeHash: string } {
        const digest = createHash('sha256').update(doc, 'utf8').digest('hex')
        const events = JSON.parse(eventLog) as Record<string, unknown>[]
        const target = events.find((e) => e['event'] === EVENT_COMPOSE_HASH)
        if (target === undefined) throw new Error('the capture has no compose-hash event to rewrite')
        target['event_payload'] = digest
        const patchedLog = JSON.stringify(events)

        const q = quoteBoundTo(NODE_PUBKEY, OPERATOR_ID)
        const rtmr3 = quoteRTMR(q, 3)
        if (rtmr3 === null) throw new Error('the capture has no RTMR3')
        rtmr3.set(replayRTMR3(parseEventLog(patchedLog)).value)
        return {
            bundle: bundle({ cpu_report: b64(q), event_log: patchedLog, app_compose: doc }),
            composeHash: digest,
        }
    }

    function releasePolicy(published: string): ComposePolicy {
        return {
            ...zeroSignalComposePolicy(),
            enforceComposeSkeleton: true,
            trustedComposeSkeletons: [composeSkeletonDigest(extractComposeSkeleton(published).skeleton)],
            trustedNodeImages: [RELEASE_IMAGE],
        }
    }

    it('pins the root-backdoor rule specifically, not just "the capture fails"', () => {
        // The capture violates the shared policy several ways, so a test
        // asserting only that it is refused stays green with the backdoor rule
        // deleted. The rule is asserted by name here, the refusal below.
        let caught: unknown
        try {
            verifyAppCompose(capturedAppCompose(), { [EVENT_COMPOSE_HASH]: COMPOSE_HASH }, zeroSignalComposePolicy())
        } catch (e) {
            caught = e
        }
        expect(String(caught)).toContain('root_backdoor_env')
        expect(String(caught)).toContain('DSTACK_AUTHORIZED_KEYS')
    })

    it('treats an empty app_compose as absent while the release match is off', async () => {
        const v = await verify(bundle({ app_compose: '' }))
        expect(v.pass).toBe(true)
        expect(v.detail?.measurementChecks?.composeRelease).toBe(false)
    })

    it('refuses the captured compose, which installs an operator-held root key', async () => {
        // Real silicon, a production OS image, a compose hash on the pin list,
        // and `phala deploy` appended the deploying machine's key as
        // DSTACK_AUTHORIZED_KEYS. Only reading the document sees that.
        const v = await verify(bundle({ app_compose: capturedAppCompose() }), { composePolicy: zeroSignalComposePolicy() })
        expect(v.failureTag).toBe('measurement_mismatch')
    })

    it('tells the payer WHICH rule the node broke, as codes', async () => {
        const v = await verify(bundle({ app_compose: capturedAppCompose() }))
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.detail?.composeViolations).toContain('root_backdoor_env')
        // The proxy's env allowlist is threaded too, not just the unconditional rule.
        expect(v.detail?.composeViolations).toContain('env_not_allowed')
        expect(v.detail?.composeViolations?.every((c) => /^[a-z_]+$/.test(c))).toBe(true)
    })

    it('leaves composeViolations unset on a failure that is not the compose', async () => {
        const v = await verify(bundle({ event_log: '[]' }))
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.detail?.composeViolations).toBeUndefined()
    })

    it('refuses a policy-clean document that is not the one measured', async () => {
        // Hashed against the REPLAY, not against anything the node said.
        const { log, warns } = warnLog()
        const v = await verify(bundle({ app_compose: cleanDoc() }), { log })
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(warns.join('\n')).toContain('is not the one this quote measured')
        // A provenance failure carries no policy violations, so its code is
        // the only reason the payer is shown.
        expect(v.detail?.composeViolations).toEqual(['compose_hash_mismatch'])
    })

    it('accepts a document that IS the one measured and satisfies the shape rules', async () => {
        const { bundle: b, composeHash } = bundleMeasuring(cleanDoc())
        const v = await verify(b, { trustedComposeHashes: [composeHash] })
        expect(v.failureTag).toBe('')
        expect(v.pass).toBe(true)
    })

    it('applies the policy it is given, not a permissive default', async () => {
        // The env allowlist exists only when the shared policy is threaded,
        // so this document's sole defect is an env name.
        const { bundle: b, composeHash } = bundleMeasuring(
            cleanDoc({ allowed_envs: ['NODE_LLM_OPENAI_API_KEY', 'NODE_ZS_OPERATOR_ID'] }),
        )
        const shared = await verify(b, { trustedComposeHashes: [composeHash] })
        expect(shared.failureTag).toBe('measurement_mismatch')
        expect(shared.detail?.composeViolations).toEqual(['env_not_allowed'])
        // ...and with the rules removed the same bundle passes, so the refusal
        // came from the policy and not the hash step or an unconditional rule.
        const none = await verify(b, { trustedComposeHashes: [composeHash], composePolicy: {} })
        expect(none.pass).toBe(true)
    })

    it('does not call a passing document a release match without the release half', async () => {
        const { bundle: b, composeHash } = bundleMeasuring(cleanDoc())
        const v = await verify(b, { trustedComposeHashes: [composeHash] })
        expect(v.pass).toBe(true)
        expect(v.detail?.measurementChecks).toEqual({ osImage: true, composeRelease: false, composeHash: true })
    })

    it('reports a release match once the release lists exist', async () => {
        const doc = cleanDoc()
        const { bundle: b } = bundleMeasuring(doc)
        const v = await verify(b, {
            trustedComposeHashes: [],
            composePolicy: releasePolicy(JSON.parse(doc).docker_compose_file as string),
        })
        expect(v.pass, v.failureTag).toBe(true)
        expect(v.detail?.measurementChecks).toEqual({ osImage: true, composeRelease: true, composeHash: false })
    })

    it('refuses a compose that is not the published shape, under the same lists', async () => {
        // What stops the case above being vacuous: a host bind mount, outside
        // both holes the skeleton leaves open.
        const published = releaseCompose(RELEASE_IMAGE, OPERATOR_CONFIG)
        const tampered = published.replace('      - zs-node-state:/data\n', '      - zs-node-state:/data\n      - /:/host\n')
        expect(tampered).not.toBe(published)
        const { bundle: b } = bundleMeasuring(cleanDoc({ docker_compose_file: tampered }))
        const v = await verify(b, { trustedComposeHashes: [], composePolicy: releasePolicy(published) })
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.detail?.composeViolations).toContain('compose_skeleton')
    })

    it('refuses a node that publishes no preimage under the release match', async () => {
        // Omitting app_compose must not skip every content rule once the
        // release lists are the gate. The shipped lists, as a payer gets them.
        const v = await verify(bundle(), {
            trustedComposeHashes: [],
            composePolicy: {
                ...zeroSignalComposePolicy(),
                enforceComposeSkeleton: true,
                trustedComposeSkeletons: trustedComposeSkeletons(),
                trustedNodeImages: trustedNodeImages(),
            },
        })
        expect(v.pass).toBe(false)
        expect(v.failureTag).toBe('measurement_mismatch')
        expect(v.detail?.composeViolations).toEqual(['missing_app_compose'])
    })

    it('skips the preimage when the release match is off', async () => {
        // A guest agent predating proto 9.6 cannot publish one, and reading
        // that as compromised would punish a capability gap.
        const v = await verify(bundle())
        expect(v.pass).toBe(true)
        expect(v.detail?.measurementChecks?.composeRelease).toBe(false)
    })

    // An empty trustedComposeHashes is "no constraint" only under the release
    // match, where it narrows an identified fleet. Without the match it is the
    // only thing identifying a workload, so empty refuses everything. The
    // verdict cannot always say which rule refused, so these read the log.
    describe('the whole-document pin', () => {
        const enforcingBogus = (): ComposePolicy => ({
            enforceComposeSkeleton: true,
            trustedComposeSkeletons: ['cd'.repeat(32)],
            trustedNodeImages: ['ghcr.io/txnlab/zs-node@sha256:' + 'ef'.repeat(32)],
        })

        it('refuses everything when empty and the release match is off', async () => {
            for (const composePolicy of [{}, shapeOnlyPolicy()]) {
                const { log, warns } = warnLog()
                const v = await verify(bundle(), { trustedComposeHashes: [], composePolicy, log })
                expect(v.failureTag).toBe('measurement_mismatch')
                expect(warns).toContain('attestation: compose hash is not in the trusted set')
            }
        })

        it("passes that step when it lists the capture's hash and the release match is off", async () => {
            const { log, warns } = warnLog()
            const v = await verify(bundle(), { trustedComposeHashes: [COMPOSE_HASH], composePolicy: {}, log })
            expect(v.pass, v.failureTag).toBe(true)
            expect(warns).toEqual([])
            // Case and an 0x prefix are folded here as for the OS image.
            const folded = await verify(bundle(), { trustedComposeHashes: [`0X${COMPOSE_HASH.toUpperCase()}`], composePolicy: {} })
            expect(folded.pass).toBe(true)
        })

        it('is skipped when empty under the release match', async () => {
            // A clean measured release passes with no pin at all...
            const doc = cleanDoc()
            const { bundle: b } = bundleMeasuring(doc)
            const v = await verify(b, {
                trustedComposeHashes: [],
                composePolicy: releasePolicy(JSON.parse(doc).docker_compose_file as string),
            })
            expect(v.pass, v.failureTag).toBe(true)
            expect(v.detail?.measurementChecks?.composeHash).toBe(false)

            // ...and a non-release is refused by the release match, not the pin.
            const { log, warns } = warnLog()
            const refused = await verify(bundle({ app_compose: capturedAppCompose() }), {
                trustedComposeHashes: [],
                composePolicy: enforcingBogus(),
                log,
            })
            expect(refused.failureTag).toBe('measurement_mismatch')
            expect(warns).not.toContain('attestation: compose hash is not in the trusted set')
            expect(warns).toContain('attestation: the measured compose violates policy')
        })

        it('still refuses a node outside a populated pin under the release match', async () => {
            // A payer who configured MORE must not end up with LESS: a pin the
            // node fails separates "pin satisfied" from "pin never consulted".
            const doc = cleanDoc()
            const { bundle: b } = bundleMeasuring(doc)
            const { log, warns } = warnLog()
            const v = await verify(b, {
                trustedComposeHashes: ['aa'.repeat(32)],
                composePolicy: releasePolicy(JSON.parse(doc).docker_compose_file as string),
                log,
            })
            expect(v.failureTag).toBe('measurement_mismatch')
            expect(warns).toContain('attestation: compose hash is not in the trusted set')
        })

        it('does not let a matching pin bypass the release match', async () => {
            // The pin narrows; it must never substitute, or "pin your own
            // hash" is a documented route around the release match.
            const v = await verify(bundle({ app_compose: capturedAppCompose() }), {
                trustedComposeHashes: [COMPOSE_HASH],
                composePolicy: enforcingBogus(),
            })
            expect(v.failureTag).toBe('measurement_mismatch')
            expect(v.detail?.composeViolations).toContain('compose_skeleton')
        })

        it('reports composeHash on a pass only when a pin was consulted', async () => {
            const doc = cleanDoc()
            const { bundle: b, composeHash } = bundleMeasuring(doc)
            const v = await verify(b, {
                trustedComposeHashes: [composeHash],
                composePolicy: releasePolicy(JSON.parse(doc).docker_compose_file as string),
            })
            expect(v.detail?.measurementChecks).toEqual({ osImage: true, composeRelease: true, composeHash: true })
        })
    })
})

describe('BundleVerifier: mode dispatch', () => {
    // Both nvidia modes: covering one left the other deletable, and an SNP
    // node falling to a mismatch tag would mislabel "can't check yet" as
    // "this operator is misadvertising".
    it.each([TEE_MODE_NVIDIA_CC_TDX, TEE_MODE_NVIDIA_CC_SEV_SNP])('does not claim to verify %s', async (mode) => {
        const v = await verify(bundle({ mode }))
        expect(v.pass).toBe(false)
        expect(v.failureTag).toBe('verifier_not_implemented')
        expect(v.verifierId).toBe('builtin')
    })

    it('refuses a mode it has never heard of as unimplemented, not as a mismatch', async () => {
        // The advertisement and bundle AGREE, so nothing mismatched.
        const v = await verify(bundle({ mode: 'sev-snp-someday' }))
        expect(v.failureTag).toBe('verifier_not_implemented')
    })
})

describe('checkPosture', () => {
    it('accepts an absent block as no claim', () => {
        expect(checkPosture(undefined, false)).toBe('')
        expect(checkPosture(null, false)).toBe('')
    })

    it('refuses in_enclave that names an upstream', () => {
        expect(
            checkPosture({ plaintext_terminates: PLAINTEXT_IN_ENCLAVE, upstream_base_url: 'https://x' }, false),
        ).toBe('advertisement_mismatch')
    })

    it('accepts in_enclave with no upstream', () => {
        expect(checkPosture({ plaintext_terminates: PLAINTEXT_IN_ENCLAVE }, false)).toBe('')
    })

    it('refuses named_upstream that names nobody', () => {
        // Declining to name a party is not making the one-party claim.
        expect(checkPosture({ plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM }, false)).toBe('advertisement_mismatch')
    })

    it('refuses named_upstream that names nobody but asserts zero_retention', () => {
        // The branch must read upstream_base_url, not zero_retention.
        expect(checkPosture({ plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM, zero_retention: true }, false)).toBe(
            'advertisement_mismatch',
        )
    })

    it('accepts named_upstream xAI with zero-retention enforcement', () => {
        expect(
            checkPosture(
                { plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM, upstream_base_url: 'https://api.x.ai/v1', zero_retention: true },
                false,
            ),
        ).toBe('')
    })

    it('refuses named_upstream xAI without zero-retention enforcement', () => {
        expect(
            checkPosture({ plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM, upstream_base_url: 'https://api.x.ai/v1' }, false),
        ).toBe('posture_upstream_unverifiable')
    })

    it('refuses a lookalike or plain-http upstream even when signed as xAI', () => {
        for (const url of [
            'https://api.x.ai.attacker.example/v1',
            'https://api.x.ai@attacker.example/v1',
            'https://attacker.example/api.x.ai/v1',
            'http://api.x.ai/v1',
        ]) {
            expect(
                checkPosture(
                    { plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM, upstream_base_url: url, zero_retention: true },
                    false,
                ),
                url,
            ).toBe('posture_upstream_unverifiable')
        }
    })

    it('admits a non-xAI named upstream only with the bound bit and an upstream attestation', () => {
        const gateway = {
            plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM,
            upstream_base_url: 'https://gateway.example/v1',
            upstream_attested: true,
        }
        expect(checkPosture(gateway, true)).toBe('')
        expect(checkPosture(gateway, false)).toBe('posture_upstream_unverifiable')
        // The block is unsigned, so a relay can add it; it cannot set the bit.
        expect(checkPosture({ ...gateway, upstream_attested: undefined }, true)).toBe('posture_upstream_unverifiable')
    })

    it('refuses in_enclave claiming an attested upstream', () => {
        expect(checkPosture({ plaintext_terminates: PLAINTEXT_IN_ENCLAVE, upstream_attested: true }, false)).toBe(
            'advertisement_mismatch',
        )
    })

    it('refuses an unrecognized value rather than reading it as no claim', () => {
        // Unknown must never read as the stronger claim.
        expect(checkPosture({ plaintext_terminates: 'in_enclave_but_better' }, false)).toBe('advertisement_mismatch')
        expect(checkPosture({}, false)).toBe('advertisement_mismatch')
    })

    // Only the BOUND bit, and only true, may refuse an in_enclave node. The
    // unbound block and a false/null bit (which hash as absent) are things a
    // relay can add.
    it('does not let relay-addable values refuse an honest in_enclave node', async () => {
        expect(checkPosture({ plaintext_terminates: PLAINTEXT_IN_ENCLAVE }, true)).toBe('')
        const honest = bundle({ posture: { plaintext_terminates: PLAINTEXT_IN_ENCLAVE } })
        const withBlock = await verify({ ...honest, upstream_attestation: upstream() })
        expect(withBlock.pass).toBe(true)
        for (const bit of [false, null]) {
            const got = await verify({
                ...honest,
                posture: { plaintext_terminates: PLAINTEXT_IN_ENCLAVE, upstream_attested: bit },
            })
            expect(got.pass, String(bit)).toBe(true)
        }
    })

    it('surfaces a coherent posture on the verdict', async () => {
        const posture = {
            plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM,
            upstream_base_url: 'https://api.x.ai/v1',
            zero_retention: true,
        }
        const v = await verify(bundle({ posture }))
        expect(v.pass).toBe(true)
        expect(v.detail?.posture).toEqual(posture)
    })

    it('fails a verdict whose posture is incoherent', async () => {
        const v = await verify(
            bundle({ posture: { plaintext_terminates: PLAINTEXT_IN_ENCLAVE, upstream_base_url: 'https://x' } }),
        )
        expect(v.failureTag).toBe('advertisement_mismatch')
        expect(v.detail?.posture).toBeUndefined()
    })

    it('refuses a posture rewritten after the quote committed to another', async () => {
        // An honest node's quote over the genuine xAI posture; a relay then
        // swaps what the payer is shown, or strips it.
        const signed = {
            plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM,
            upstream_base_url: 'https://api.x.ai/v1',
            zero_retention: true,
        }
        const honest = bundle({ posture: signed })
        for (const posture of [
            { ...signed, upstream_base_url: 'https://api.x.ai.attacker.example/v1' },
            { ...signed, zero_retention: false },
            undefined,
        ]) {
            const v = await verify({ ...honest, posture })
            expect(v.pass, JSON.stringify(posture)).toBe(false)
            expect(v.failureTag, JSON.stringify(posture)).toBe('aux_binding_mismatch')
        }
    })

    it('refuses a posture added to a node that committed to none', async () => {
        const v = await verify({ ...bundle(), posture: { plaintext_terminates: PLAINTEXT_IN_ENCLAVE } })
        expect(v.failureTag).toBe('aux_binding_mismatch')
    })

    // The unit cases above pass the attested bit in directly, so they cannot
    // see what the verifier derives it from. Hard-coding true would admit
    // every https gateway; false would de-route every ACI node.
    it('admits a bound gateway posture only with an aci/1 upstream_attestation block', async () => {
        const posture = {
            plaintext_terminates: PLAINTEXT_NAMED_UPSTREAM,
            upstream_base_url: 'https://gateway.example/v1',
            upstream_attested: true,
        }
        const signed = bundle({ posture })
        const cases: [unknown, boolean][] = [
            [upstream({ base_url: 'https://gateway.example/v1' }), true],
            [undefined, false],
            // Unbound, so presence is all a relay has to forge: it must name a
            // protocol this build recognizes.
            [{}, false],
            [upstream({ protocol: 'aci/2' }), false],
            [true, false],
            [[upstream()], false],
        ]
        for (const [block, admitted] of cases) {
            const b = { ...signed } as TEEEvidenceBundle
            if (block === undefined) delete b.upstream_attestation
            else b.upstream_attestation = block as UpstreamAttestation
            const v = await verify(b)
            const label = JSON.stringify(block) ?? 'absent'
            expect(v.pass, label).toBe(admitted)
            if (!admitted) expect(v.failureTag, label).toBe('posture_upstream_unverifiable')
        }
        // A relay setting the bit on a node that signed it clear breaks the binding.
        const unset = bundle({ posture: { ...posture, upstream_attested: undefined } })
        const forged = await verify({ ...unset, posture, upstream_attestation: upstream() })
        expect(forged.failureTag).toBe('aux_binding_mismatch')
    })

    it('refuses a posture that cannot be hashed with its own tag', async () => {
        const honest = bundle()
        for (const posture of [[], 'named_upstream', { zero_retention: 'yes' }]) {
            const v = await verify({ ...honest, posture })
            expect(v.failureTag, JSON.stringify(posture)).toBe('posture_preimage_invalid')
        }
    })
})
