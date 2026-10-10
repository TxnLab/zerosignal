/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The dstack TDX verifier. Mirrors DstackVerifier in proto/go/zs/tee/dstack.go,
// whose godoc carries the reasoning for each step; SPEC § 3e steps 5 to 7 are
// authoritative. The ORDER is load-bearing and is Go's: platform from the quote
// bytes, the vendor chain, the event-log replay, the measurement lists, the
// compose document, both halves of report_data, then the posture.

import {
    ComposeError,
    type ComposePolicy,
    EVENT_APP_ID,
    EVENT_COMPOSE_HASH,
    EVENT_INSTANCE_ID,
    EVENT_OS_IMAGE_HASH,
    AuxBindingAbsentError,
    AttestError,
    type ModelEntry,
    type ReportDataHalves,
    TEE_TYPE_TDX,
    auxFailureTag,
    collateralFreshEnough,
    EMBEDDED_COLLATERAL_MAX_AGE_MS,
    quoteTEEType,
    reportData,
    splitReportData,
    verifyAppCompose,
    verifyAux,
    verifyEventLog,
} from '@txnlab/zs-proto/attest'
import {
    type TEECollateral,
    type TEEEvidenceBundle,
    collateralComplete,
    goTrimSpace,
    namedUpstreamAdmissible,
    upstreamAttested,
} from '@txnlab/zs-proto/inject'
import { decodeGoStdBase64 } from '@txnlab/zs-proto/ticket'

import { type Clock, type Logger, discardLogger } from '../ports.js'
import { bytesEqual } from './bytes.js'
import {
    CollateralUnavailableError,
    NoUsableCarriedCollateralError,
    StaleCollateralRejectedError,
} from './errors.js'
import { carriedChainVerifier, pccsChainVerifier } from './pccs.js'
import { ACCEPTED_TCB_STATUS, FailureTag } from './tags.js'
import type {
    CarriedChainVerifier,
    ChainResult,
    Measurements,
    MeasurementChecks,
    Node,
    QuoteChainVerifier,
    VerdictDetail,
} from './types.js'

/** Where plaintext comes to rest. Mirrors inject.PlaintextInEnclave / PlaintextNamedUpstream. */
export const PLAINTEXT_IN_ENCLAVE = 'in_enclave'
export const PLAINTEXT_NAMED_UPSTREAM = 'named_upstream'

export interface DstackVerifierOptions {
    /** The trusted guest-image list. EMPTY MEANS NOTHING VERIFIES. */
    trustedOSImages: readonly string[]
    /**
     * Whole-document compose pins. They narrow the release match, and empty
     * means "no constraint" only while composePolicy.enforceComposeSkeleton is
     * set; with it off, empty refuses everything (see the guard in verify).
     */
    trustedComposeHashes?: readonly string[]
    /** The compose content rules. `{}` runs none and enforces no release match. */
    composePolicy: ComposePolicy
    /**
     * Verifies the quote against Intel's chain with collateral the verifier
     * obtained. Absent means pccsChainVerifier(), as Go's nil field means the
     * real verification.
     */
    verifyChain?: QuoteChainVerifier
    /**
     * Verifies the quote against the node's carried collateral, the last
     * resort. Absent means carriedChainVerifier(). The completeness and age
     * checks always run before it, as Go's VerifyTDXQuoteChainCarried runs
     * them, so a host cannot reach the node's documents without them; so does
     * a refusal of an aborted call.
     */
    verifyChainCarried?: CarriedChainVerifier
    log?: Logger
    /** Unix milliseconds; dates the carried documents. */
    now?: Clock
}

/** The outcome of DstackVerifier.verify: '' and display detail on a pass. */
export interface DstackOutcome {
    failureTag: string
    detail: VerdictDetail
}

/**
 * Verifies dstack-managed Intel TDX evidence. Never call it directly to judge
 * a node: it skips the advertisement, staleness, self-reported report_data and
 * stub checks, which BundleVerifier runs first (SPEC § 3e steps 0 to 4).
 */
export class DstackVerifier {
    private readonly trustedOSImages: readonly string[]
    private readonly trustedComposeHashes: readonly string[]
    private readonly composePolicy: ComposePolicy
    private readonly verifyChain: QuoteChainVerifier
    private readonly verifyChainCarried: ReturnType<typeof guardCarried>
    private readonly log: Logger

    constructor(opts: DstackVerifierOptions) {
        this.trustedOSImages = opts.trustedOSImages
        this.trustedComposeHashes = opts.trustedComposeHashes ?? []
        this.composePolicy = opts.composePolicy
        const now = opts.now ?? Date.now
        this.verifyChain = opts.verifyChain ?? pccsChainVerifier({ now })
        this.verifyChainCarried = guardCarried(opts.verifyChainCarried ?? carriedChainVerifier({ now }), now)
        this.log = opts.log ?? discardLogger
    }

    /**
     * Runs Go's collateral precedence: our chain verifier (which tries Intel
     * and then its own cache), then the node's carried set. Only an outage
     * reaches the second rung; when it fails too, the first rung's error is
     * the one returned, since it describes our link to Intel rather than the
     * node's evidence.
     *
     * A status other than UpToDate is a refusal inside Go's chain check, so it
     * is classified here by which collateral reached it: on our stale cache it
     * is StaleCollateralRejectedError, on the carried set a failed last
     * resort. Only a status from current collateral of our own is left for
     * the caller to refuse as vendor_chain_invalid.
     */
    private async verifyQuoteChain(
        quote: Uint8Array,
        carried: TEECollateral | undefined,
        operatorId: bigint,
        signal: AbortSignal | undefined,
    ): Promise<ChainResult> {
        let first: unknown
        try {
            const result = await this.verifyChain(quote, signal)
            if (result.servedStale === true && result.tcbStatus !== ACCEPTED_TCB_STATUS) {
                throw new StaleCollateralRejectedError(
                    'Intel PCS was unreachable',
                    `TCB status ${result.tcbStatus}`,
                )
            }
            return result
        } catch (err) {
            // A caller abort reaches Go's chain check as a context error on a
            // fetch, which it reports as ErrCollateralUnavailable.
            if (causedBy(err, CollateralUnavailableError)) first = err
            else if (signal?.aborted === true && !causedBy(err, StaleCollateralRejectedError)) {
                first = new CollateralUnavailableError(err)
            } else throw err
        }
        let result: ChainResult
        try {
            result = await this.verifyChainCarried(quote, carried, signal)
            if (result.tcbStatus !== ACCEPTED_TCB_STATUS) {
                throw new Error(`carried collateral reports TCB status ${result.tcbStatus}`)
            }
        } catch (cerr) {
            this.log.debug('attestation: node-carried collateral did not rescue an unreachable-PCS verification', {
                operator_id: operatorId,
                err: String(cerr),
            })
            throw first
        }
        this.log.warn("attestation: verified a TDX quote against the NODE'S OWN collateral because Intel PCS was unreachable", {
            operator_id: operatorId,
            pcs_err: String(first),
        })
        return result
    }

    /** Runs the dstack branch. op supplies the ephemeral recipient the binding must be to. */
    async verify(bundle: TEEEvidenceBundle, op: Node, signal?: AbortSignal): Promise<DstackOutcome> {
        const detail: VerdictDetail = {}
        const fail = (failureTag: string): DstackOutcome => ({ failureTag, detail })
        const opAttrs = { operator_id: op.operatorId }

        let quote: Uint8Array
        try {
            quote = decodeGoStdBase64(bundle.cpu_report)
        } catch {
            return fail(FailureTag.VendorChainInvalid)
        }
        if (quote.length === 0) return fail(FailureTag.VendorChainInvalid)

        // 1. The platform from the bytes, never from the mode the caller
        // switched on: the mode picks the verifier, the bytes pick the chain.
        const teeType = quoteTEEType(quote)
        if (teeType !== TEE_TYPE_TDX) {
            this.log.debug('attestation: report is not a TDX v4 quote', { ...opAttrs, tee_type: teeType })
            return fail(FailureTag.VendorChainInvalid)
        }

        // 2. The vendor chain.
        let chain: ChainResult
        try {
            chain = await this.verifyQuoteChain(quote, bundle.collateral, op.operatorId, signal)
        } catch (err) {
            const stale = causedBy(err, StaleCollateralRejectedError)
            if (stale || causedBy(err, CollateralUnavailableError)) {
                // The tag is shared, the message is not: SPEC § 3e rule 2 lets
                // a diagnostic surface tell the two apart.
                const msg =
                    stale
                        ? 'attestation: TDX quote refused by our own cached Intel collateral during a PCS outage — cause not attributable from here'
                        : 'attestation: could not reach Intel PCS to verify a TDX quote'
                this.log.warn(msg, { ...opAttrs, err: String(err) })
                return fail(FailureTag.CollateralUnreachable)
            }
            this.log.warn('attestation: TDX quote failed vendor-chain verification', { ...opAttrs, err: String(err) })
            return fail(FailureTag.VendorChainInvalid)
        }
        detail.tcbStatus = chain.tcbStatus
        detail.advisoryIds = chain.advisoryIds
        // go-tdx-guest refuses every status but UpToDate inside the chain
        // check. A chain verifier here reports the status instead; on current
        // collateral of our own the refusal is made at this step, under the
        // same tag.
        if (chain.tcbStatus !== ACCEPTED_TCB_STATUS) {
            this.log.warn('attestation: platform TCB status is not UpToDate', {
                ...opAttrs,
                tcb_status: chain.tcbStatus,
            })
            return fail(FailureTag.VendorChainInvalid)
        }

        // 3 + 4. Replay, then read the measurements off the replay.
        let recovered: Record<string, string>
        try {
            recovered = verifyEventLog(bundle.event_log, quote)
        } catch (err) {
            this.log.warn("attestation: event log does not replay to the quote's RTMR3", { ...opAttrs, err: String(err) })
            return fail(FailureTag.MeasurementMismatch)
        }
        const measurements = measurementsOf(recovered)
        detail.measurements = measurements

        // The whole-document pin. Empty is skipped only under the release
        // match; with the match off, the pin is the only thing identifying a
        // workload, so empty refuses everything.
        const enforceSkeleton = this.composePolicy.enforceComposeSkeleton === true
        const composeHashPinned = this.trustedComposeHashes.length > 0
        if (composeHashPinned || !enforceSkeleton) {
            if (!containsHexFold(this.trustedComposeHashes, recovered[EVENT_COMPOSE_HASH] ?? '')) {
                this.log.warn('attestation: compose hash is not in the trusted set', {
                    ...opAttrs,
                    compose_hash: recovered[EVENT_COMPOSE_HASH] ?? '',
                })
                return fail(FailureTag.MeasurementMismatch)
            }
        }
        if (!containsHexFold(this.trustedOSImages, recovered[EVENT_OS_IMAGE_HASH] ?? '')) {
            this.log.warn('attestation: OS image hash is not in the trusted set', {
                ...opAttrs,
                os_image_hash: recovered[EVENT_OS_IMAGE_HASH] ?? '',
            })
            return fail(FailureTag.MeasurementMismatch)
        }

        // 4c. The compose document itself, after the OS image so a dev image
        // is reported as one. Absent is a refusal under the release match and
        // a skip without it.
        let composeValidated = false
        if (bundle.app_compose === '') {
            if (enforceSkeleton) {
                this.log.warn(
                    'attestation: node published no app_compose, so the release match has nothing to check — refusing rather than skipping',
                    opAttrs,
                )
                // Not a shared ViolationCode: there is no document to have
                // violated anything. Display only.
                detail.composeViolations = ['missing_app_compose']
                return fail(FailureTag.MeasurementMismatch)
            }
        } else {
            try {
                verifyAppCompose(bundle.app_compose, recovered, this.composePolicy)
                composeValidated = true
            } catch (err) {
                if (err instanceof ComposeError) {
                    detail.composeViolations =
                        err.violations.length > 0 ? err.violations.map((v) => v.code) : [err.code]
                }
                // Split by cause: a provenance failure means the document is
                // not the measured compose, so calling it that would misname it.
                const msg =
                    err instanceof ComposeError && err.code === 'compose_policy'
                        ? 'attestation: the measured compose violates policy'
                        : 'attestation: the published compose is not the one this quote measured'
                this.log.warn(msg, { ...opAttrs, err: String(err) })
                return fail(FailureTag.MeasurementMismatch)
            }
        }
        const checks: MeasurementChecks = {
            osImage: true,
            composeRelease: composeValidated && enforceSkeleton,
            composeHash: composeHashPinned,
        }

        // SPEC step 6: both halves of the report_data Intel signed.
        let halves: ReportDataHalves
        let auxAbsent = false
        try {
            halves = splitReportData(quote)
        } catch (err) {
            if (!(err instanceof AuxBindingAbsentError)) {
                this.log.warn('attestation: quote is too short to hold report_data', opAttrs)
                return fail(FailureTag.KeyBindingMismatch)
            }
            // The key half is checked first, so a wrong key on a pre-9.9 node
            // is reported as a key problem.
            halves = { keyBinding: err.keyBinding, auxBinding: new Uint8Array(32) }
            auxAbsent = true
        }

        // 6.1. The lower half: the key we would seal to.
        let expected: Uint8Array
        try {
            expected = reportData(op.ephemeralRecipientPubkey, op.operatorId)
        } catch {
            return fail(FailureTag.KeyBindingMismatch)
        }
        if (!bytesEqual(halves.keyBinding, expected)) {
            this.log.warn('attestation: the quote binds a different key than the one we would seal to', opAttrs)
            return fail(FailureTag.KeyBindingMismatch)
        }
        if (auxAbsent) {
            this.log.warn('attestation: report_data upper half is all zero — node predates proto 9.9', {
                ...opAttrs,
                node_id: op.nodeId,
            })
            return fail(FailureTag.AuxBindingAbsent)
        }

        // 6.2 to 6.5. The upper half, over the chain-resolved node id. No
        // challenge is sent, so this proves no freshness; stale_evidence and
        // ephemeral rotation bound the bundle's age.
        const models = bundle.app_models as readonly ModelEntry[] | null | undefined
        try {
            verifyAux(halves, op.nodeId, models, bundle.posture, bundle.nonce, null)
        } catch (err) {
            const tag = auxFailureTag(err)
            this.log.warn('attestation: aux binding refused', {
                ...opAttrs,
                node_id: op.nodeId,
                tag,
                published_models: Array.isArray(models) ? models.length : 0,
                err: err instanceof AttestError ? err.code : String(err),
            })
            return fail(tag)
        }

        // SPEC step 7: the posture verifyAux just bound.
        const postureTag = checkPosture(bundle.posture, upstreamAttested(bundle.upstream_attestation))
        if (postureTag !== '') {
            this.log.warn('attestation: posture refused', { ...opAttrs, tag: postureTag })
            return fail(postureTag)
        }

        detail.measurementChecks = checks
        if (bundle.posture !== undefined && bundle.posture !== null) detail.posture = bundle.posture
        return { failureTag: '', detail }
    }
}

/**
 * Judges a bound posture block: coherence first, then whether a named
 * upstream is one a payer can hold to its claim. Mirrors
 * DstackVerifier.checkPosture. Call it only with the value verifyAux hashed:
 * hPosture has then established it is absent or an object with fields of the
 * right types, which is what lets an absent field read as its zero value here.
 * An absent posture makes no claim and passes; an unrecognised one is refused,
 * since unknown must never read as the stronger claim.
 */
export function checkPosture(posture: unknown, attested: boolean): string {
    if (posture === undefined || posture === null) return ''
    if (typeof posture !== 'object' || Array.isArray(posture)) return FailureTag.AdvertisementMismatch
    const p = posture as Record<string, unknown>
    const terminates = typeof p['plaintext_terminates'] === 'string' ? p['plaintext_terminates'] : ''
    const url = typeof p['upstream_base_url'] === 'string' ? p['upstream_base_url'] : ''
    switch (terminates) {
        case PLAINTEXT_IN_ENCLAVE:
            if (url !== '' || p['upstream_attested'] === true) return FailureTag.AdvertisementMismatch
            return ''
        case PLAINTEXT_NAMED_UPSTREAM:
            if (url === '') return FailureTag.AdvertisementMismatch
            if (!namedUpstreamAdmissible(posture, attested)) return FailureTag.PostureUpstreamUnverifiable
            return ''
        default:
            return FailureTag.AdvertisementMismatch
    }
}

/**
 * Whether a replayed measurement is in a trust list, comparing lowercased hex
 * with any 0x prefix stripped. Mirrors MeasurementTrusted / containsHexFold.
 * Emptiness is tested after normalizing, on both sides: "0x" or blanks must
 * not match a stray blank entry.
 */
export function measurementTrusted(list: readonly string[], want: string): boolean {
    return containsHexFold(list, want)
}

function containsHexFold(list: readonly string[], want: string): boolean {
    const w = normalizeHex(want)
    if (w === '') return false
    return list.some((v) => {
        const n = normalizeHex(v)
        return n !== '' && n === w
    })
}

function normalizeHex(s: string): string {
    const t = goTrimSpace(s).toLowerCase()
    return t.startsWith('0x') ? t.slice(2) : t
}

// The checks Go's VerifyTDXQuoteChainCarried makes before verifying: all nine
// members present, and every document no older than
// EMBEDDED_COLLATERAL_MAX_AGE_MS and not future-dated.
function guardCarried(
    verify: CarriedChainVerifier,
    now: Clock,
): (quote: Uint8Array, collateral: TEECollateral | undefined, signal?: AbortSignal) => Promise<ChainResult> {
    return async (quote, collateral, signal) => {
        // Go's carried path refuses a cancelled context in its getter. Here
        // the rung is a host seam that may ignore the signal, so the refusal
        // is made before it is reached.
        if (signal?.aborted === true) {
            throw new NoUsableCarriedCollateralError('the caller aborted before the last resort')
        }
        if (!collateralComplete(collateral)) {
            throw new NoUsableCarriedCollateralError('the bundle carries no complete collateral set')
        }
        if (!collateralFreshEnough(collateral, now(), EMBEDDED_COLLATERAL_MAX_AGE_MS)) {
            throw new NoUsableCarriedCollateralError('a carried document is undated, future-dated or too old')
        }
        return verify(quote, collateral, signal)
    }
}

function measurementsOf(recovered: Record<string, string>): Measurements {
    const m: Measurements = {}
    const compose = recovered[EVENT_COMPOSE_HASH]
    const os = recovered[EVENT_OS_IMAGE_HASH]
    const appId = recovered[EVENT_APP_ID]
    const instanceId = recovered[EVENT_INSTANCE_ID]
    if (compose !== undefined) m.composeHash = compose
    if (os !== undefined) m.osImageHash = os
    if (appId !== undefined) m.appId = appId
    if (instanceId !== undefined) m.instanceId = instanceId
    return m
}

// errors.Is for a host that wraps an outage in its own error: walks `cause`.
function causedBy(err: unknown, cls: abstract new (...args: never[]) => Error): boolean {
    for (let e = err, depth = 0; e !== undefined && e !== null && depth < 16; depth++) {
        if (e instanceof cls) return true
        e = e instanceof Error ? e.cause : undefined
    }
    return false
}
