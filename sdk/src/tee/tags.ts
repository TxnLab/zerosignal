/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Failure tags, verifier ids and the constants a verdict depends on. Mirrors
// the declarations in proto/go/zs/tee/verify.go and dstack.go. The tags are
// the ones SPEC § 3e names step by step; they are telemetry handles, so a
// rename breaks every dashboard that indexes them.

import { AuxFailureTag } from '@txnlab/zs-proto/attest'

export const FailureTag = {
    KeyBindingMismatch: 'key_binding_mismatch',
    StubNotAllowed: 'stub_not_allowed',
    VerifierNotImplemented: 'verifier_not_implemented',
    VendorChainInvalid: 'vendor_chain_invalid',
    NRASUnreachable: 'nras_unreachable',
    AdvertisementMismatch: 'advertisement_mismatch',
    FetchFailed: 'fetch_failed',
    StaleEvidence: 'stale_evidence',
    /**
     * The prober's, not a verdict: the node had no verified ephemeral
     * recipient this cycle, so its evidence was not fetched.
     */
    EphemeralUnavailable: 'ephemeral_unavailable',
    /** A real quote from software this verifier does not recognise. */
    MeasurementMismatch: 'measurement_mismatch',
    /** Intel's collateral could not be reached: a fact about our link, not the node. */
    CollateralUnreachable: 'collateral_unreachable',
    AuxBindingAbsent: AuxFailureTag.AuxBindingAbsent,
    AuxBindingMismatch: AuxFailureTag.AuxBindingMismatch,
    HAppPreimageMissing: AuxFailureTag.HAppPreimageMissing,
    HAppPreimageInvalid: AuxFailureTag.HAppPreimageInvalid,
    PosturePreimageInvalid: AuxFailureTag.PosturePreimageInvalid,
    /** A bound named_upstream posture names an upstream namedUpstreamAdmissible refuses. */
    PostureUpstreamUnverifiable: 'posture_upstream_unverifiable',
} as const

export type FailureTagValue = (typeof FailureTag)[keyof typeof FailureTag]

/** A verdict the bundle-level checks decided alone: no platform chain ran. */
export const VERIFIER_ID_BUILTIN = 'builtin'
/** A verdict DstackVerifier reached. */
export const VERIFIER_ID_DSTACK = 'dstack-tdx'

/**
 * The widest evidence-age window applied, whatever the bundle's
 * refresh_seconds says. Mirrors EvidenceMaxAgeCeiling (80 minutes), whose
 * godoc explains why it cannot refuse an honest node. A literal on both sides
 * on purpose: derived from the ephemeral lifetime, one side would move alone.
 */
export const EVIDENCE_MAX_AGE_CEILING_MS = 80 * 60 * 1000

/**
 * The only TCB status the chain step accepts. go-tdx-guest refuses every
 * other status, SWHardeningNeeded included, so accepting more here would
 * route browser payers to platforms the proxy refuses.
 */
export const ACCEPTED_TCB_STATUS = 'UpToDate'
