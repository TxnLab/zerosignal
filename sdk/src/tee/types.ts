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
 * The outcome of one verification. Mirrors tee.Verdict: pass is the routing
 * bit, failureTag is '' exactly when pass is true, and attestedModelIds is
 * set only on a passing dstack verdict.
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
    /** What the verifier saw, for display. Never a routing input. */
    detail?: VerdictDetail
}

/** Display detail. Go logs these instead; a browser has nowhere else to put them. */
export interface VerdictDetail {
    /** Recovered from the event-log replay, never read off a self-reported field. */
    measurements?: Measurements
    /** Which reference checks a passing dstack verdict rested on. */
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

/** Verifies an evidence bundle against an advertisement. Mirrors tee.Verifier. */
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
 * Go refuses in requireCollateralFetched.
 */
export type QuoteChainVerifier = (quote: Uint8Array, signal?: AbortSignal) => Promise<ChainResult>

/**
 * QuoteChainVerifier against collateral the node carried. A separate type
 * because the extra argument is the whole difference: no wiring reaches this
 * path without having decided to accept node-supplied criteria. DstackVerifier
 * calls it only with a complete set whose documents are inside
 * EMBEDDED_COLLATERAL_MAX_AGE_MS, so an implementation verifies and need not
 * repeat those checks.
 */
export type CarriedChainVerifier = (
    quote: Uint8Array,
    collateral: TEECollateral,
    signal?: AbortSignal,
) => Promise<ChainResult>
