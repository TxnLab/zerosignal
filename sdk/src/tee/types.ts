/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import type { TEEAdvertisement, TEECollateral, TEEEvidenceBundle } from '@txnlab/zs-proto/inject'

/**
 * What a verifier checks evidence against: the node as discovery knows it.
 * Nothing here comes from the bundle. Mirrors tee.Node; the ids are bigints
 * because they are uint64 on chain and the binding hashes them exactly.
 */
export interface Node {
    operatorId: bigint
    /** Chain-resolved. The aux binding uses it, and a bundle-supplied id would
     *  let a node present a sibling's bundle. */
    nodeId: bigint
    /**
     * The age recipient the payer will seal to, already verified against the
     * node's signed advertisement; '' when none is current. The evidence must
     * bind this key rather than the signing key: an operator holding the
     * signing key outside the enclave could otherwise attest it and still seal
     * to an ephemeral whose private half lives on the plain host.
     */
    ephemeralRecipientPubkey: string
}

/**
 * The outcome of one verification. Mirrors tee.Verdict: pass and
 * detail.measurementChecks are the routing inputs (isTeeAttested needs both),
 * failureTag is '' exactly when pass is true, and attestedModelIds is set only
 * on a passing dstack verdict.
 */
export interface Verdict {
    pass: boolean
    failureTag: string
    verifierId: string
    /** The bundle's generated_at in Unix milliseconds, pass or fail; 0 when absent. */
    attestedAt: number
    /**
     * The model ids in the signed catalog, set only when the aux binding
     * matched them. An empty array is a signed empty catalog; undefined is no
     * verified list.
     */
    attestedModelIds?: string[]
    /**
     * The bundle's upstream_attestation.carve_outs on a passing dstack verdict
     * whose bound posture says the node appraises its named upstream: each
     * policy rule that appraisal downgraded rather than enforced (SPEC § 3e).
     * Reported, never routed on. The block is unsigned, so this is the node's
     * own admission and a relay could remove it: a non-empty list caps what
     * the upstream appraisal means, while an absent one proves nothing.
     * Undefined on a refusal, when the posture claims no appraisal, and when
     * the list is empty. Mirrors tee.Verdict.UpstreamCarveOuts.
     */
    upstreamCarveOuts?: string[]
    /**
     * What the verifier saw. Display only, except measurementChecks, which
     * routing reads through probeAttestation's TEEStatus.
     */
    detail?: VerdictDetail
}

/**
 * What the verifier saw. Go logs most of these instead; a browser has nowhere
 * else to put them. measurementChecks is the exception: Go carries it on
 * tee.Verdict.MeasurementChecks, and both SDKs gate routing on it.
 */
export interface VerdictDetail {
    /** Recovered from the event-log replay, never read off a self-reported field. */
    measurements?: Measurements
    /**
     * Which reference checks a passing dstack verdict rested on; absent on a
     * refusal and on a stub pass. A routing input: a node is attested only
     * when osImage and composeRelease are both true (isTeeAttested). Pinned
     * against Go by tee_verdict_vectors.json.
     */
    measurementChecks?: MeasurementChecks
    /** Intel's TCB status for the platform, from the chain step. */
    tcbStatus?: string
    advisoryIds?: string[]
    /** Compose rules the node broke, as stable codes, on a measurement_mismatch. */
    composeViolations?: string[]
    /** The posture the aux binding verified, on a pass. */
    posture?: unknown
}

export interface Measurements {
    composeHash?: string
    osImageHash?: string
    appId?: string
    instanceId?: string
}

export interface MeasurementChecks {
    /** os-image-hash matched a trusted image. */
    osImage: boolean
    /** The compose document matched a published release (the policy's skeleton match). */
    composeRelease: boolean
    /** compose-hash matched a configured whole-document pin. */
    composeHash: boolean
}

/**
 * Verifies an evidence bundle against an advertisement. Mirrors tee.Verifier.
 * A pass routes as attested only when it also sets detail.measurementChecks
 * with osImage and composeRelease true, so an implementation that leaves them
 * out verifies nodes that requireTee traffic never reaches.
 */
export interface Verifier {
    verify(
        advertised: TEEAdvertisement,
        bundle: TEEEvidenceBundle,
        node: Node,
        signal?: AbortSignal,
    ): Promise<Verdict>
}

/** The chain step's answer for a quote that verified against Intel's chain. */
export interface ChainResult {
    tcbStatus: string
    advisoryIds: string[]
    /**
     * Set when any document came from the verifier's own cache past its
     * refresh window because Intel was unreachable. Go refuses a status other
     * than UpToDate inside the chain check, so on such collateral that refusal
     * is ErrStaleCollateralRejected; this flag lets DstackVerifier reach the
     * same tag from a reported status.
     */
    servedStale?: boolean
}

/**
 * Verifies a raw TDX quote against Intel's PCK chain with collateral the
 * verifier fetched. Throws CollateralUnavailableError when the collateral
 * could not be obtained, StaleCollateralRejectedError when our own cached
 * collateral refused the quote during an outage, and any other error for a
 * quote that does not verify. It must also throw for a pass that consulted no
 * collateral at all: that verdict skipped the revocation and TCB checks, which
 * Go refuses in requireCollateralFetched. pccsChainVerifier is the real one.
 */
export type QuoteChainVerifier = (quote: Uint8Array, signal?: AbortSignal) => Promise<ChainResult>

/**
 * QuoteChainVerifier against collateral the node carried. A separate type
 * because the extra argument is the whole difference: no wiring reaches this
 * path without having decided to accept node-supplied criteria. DstackVerifier
 * calls it only with a complete set that passes collateralFreshEnough, so an
 * implementation verifies and need not repeat those checks. carriedChainVerifier is the real one.
 */
export type CarriedChainVerifier = (
    quote: Uint8Array,
    collateral: TEECollateral,
    signal?: AbortSignal,
) => Promise<ChainResult>
