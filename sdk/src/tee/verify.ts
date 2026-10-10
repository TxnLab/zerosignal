/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The bundle-level checks every platform shares, then dispatch on mode.
// Mirrors BundleVerifier in proto/go/zs/tee/verify.go, whose godoc carries the
// reasoning; the order below is Go's and is load-bearing. These run before any
// platform verifier because no platform is trusted to do them for itself.

import { type ComposePolicy, reportData } from '@txnlab/zs-proto/attest'
import {
    type TEEAdvertisement,
    type TEEEvidenceBundle,
    TEE_MODE_DSTACK_TDX,
    epochNanosFromMillis,
    parseRFC3339,
} from '@txnlab/zs-proto/inject'
import { decodeGoStdBase64 } from '@txnlab/zs-proto/ticket'

import { type Clock, type Logger, discardLogger } from '../ports.js'
import { bytesEqual } from './bytes.js'
import { DstackVerifier } from './dstack.js'
import { EVIDENCE_MAX_AGE_CEILING_MS, FailureTag, VERIFIER_ID_BUILTIN, VERIFIER_ID_DSTACK } from './tags.js'
import type { CarriedChainVerifier, Node, QuoteChainVerifier, Verdict, Verifier } from './types.js'

const NANOS_PER_MS = 1_000_000n
const EVIDENCE_MAX_AGE_CEILING_NS = BigInt(EVIDENCE_MAX_AGE_CEILING_MS) * NANOS_PER_MS
const GO_ZERO_TIME_NS = -62135596800n * 1_000_000_000n

export interface BundleVerifierOptions {
    /** Dev pipelines only: pass a stub bundle. Production leaves it false. */
    allowStub?: boolean
    /** Handed to the dstack branch; see DstackVerifierOptions. */
    trustedComposeHashes?: readonly string[]
    trustedOSImages?: readonly string[]
    composePolicy?: ComposePolicy
    verifyChain?: QuoteChainVerifier
    verifyChainCarried?: CarriedChainVerifier
    log?: Logger
    /** Unix milliseconds. */
    now?: Clock
}

/**
 * Checks everything about an evidence bundle that does not depend on which TEE
 * produced it, then hands the rest to the platform verifier.
 */
export class BundleVerifier implements Verifier {
    private readonly allowStub: boolean
    private readonly dstack: DstackVerifier
    private readonly now: Clock

    constructor(opts: BundleVerifierOptions = {}) {
        this.allowStub = opts.allowStub === true
        this.now = opts.now ?? Date.now
        this.dstack = new DstackVerifier({
            trustedOSImages: opts.trustedOSImages ?? [],
            trustedComposeHashes: opts.trustedComposeHashes ?? [],
            composePolicy: opts.composePolicy ?? {},
            ...(opts.verifyChain !== undefined && { verifyChain: opts.verifyChain }),
            ...(opts.verifyChainCarried !== undefined && { verifyChainCarried: opts.verifyChainCarried }),
            log: opts.log ?? discardLogger,
            now: this.now,
        })
    }

    async verify(
        advertised: TEEAdvertisement,
        bundle: TEEEvidenceBundle,
        op: Node,
        signal?: AbortSignal,
    ): Promise<Verdict> {
        const generatedAt = parseRFC3339(bundle.generated_at)
        const verdict: Verdict = {
            pass: false,
            failureTag: '',
            verifierId: VERIFIER_ID_BUILTIN,
            // Go's zero time reads as absent, as Go's TEEStatus shows it.
            attestedAt: generatedAt === null || generatedAt === GO_ZERO_TIME_NS ? 0 : Number(generatedAt / NANOS_PER_MS),
        }
        const fail = (tag: string): Verdict => ({ ...verdict, failureTag: tag })

        // The key binding targets the ephemeral recipient discovery already
        // verified, never the signing key: an operator holding the signing key
        // outside the enclave could attest it and still seal elsewhere. With
        // no verified recipient there is nothing to bind to.
        if (op.ephemeralRecipientPubkey === '') return fail(FailureTag.KeyBindingMismatch)

        // The bundle is served by the operator, so whatever it says about
        // itself that disagrees with what we established is a misadvertisement.
        if (bundle.mode !== advertised.mode) return fail(FailureTag.AdvertisementMismatch)
        // operator_id is a JSON number: decodeEvidenceBundle refuses an id
        // above 2^53 that Go accepts, so such an operator cannot be verified
        // here. A hand-built bundle could carry a rounded id, but the
        // report_data binding below hashes the chain's id, so a rounded match
        // still has to bind the right key.
        if (!Number.isInteger(bundle.operator_id) || BigInt(bundle.operator_id) !== op.operatorId) {
            return fail(FailureTag.AdvertisementMismatch)
        }
        if (bundle.node_pubkey !== op.ephemeralRecipientPubkey) return fail(FailureTag.AdvertisementMismatch)

        // Freshness: 2x the node's own cadence, never wider than the ceiling,
        // and absolute, because a future generated_at defeats a one-sided
        // bound forever. Nanoseconds and int64 wrapping, as Go computes it: a
        // refresh_seconds large enough to wrap negative falls to the ceiling
        // through the > 0 test, as SPEC § 3e step 2 specifies. A product that
        // wraps to a small POSITIVE value (2197108676271213 seconds wraps to
        // 1024ns) is not caught: the window is far narrower than SPEC's
        // min(2 x refresh_seconds, ceiling) and the node is refused. That
        // fails closed and is a known divergence from SPEC, kept so the two
        // verifiers reach one verdict.
        if (generatedAt === null) return fail(FailureTag.StaleEvidence)
        let maxAge = EVIDENCE_MAX_AGE_CEILING_NS
        if (Number.isInteger(bundle.refresh_seconds)) {
            const advertisedMaxAge = BigInt.asIntN(64, 2n * BigInt(bundle.refresh_seconds) * 1_000_000_000n)
            if (advertisedMaxAge > 0n && advertisedMaxAge < maxAge) maxAge = advertisedMaxAge
        }
        const skew = epochNanosFromMillis(this.now()) - generatedAt
        if (skew > maxAge || skew < -maxAge) return fail(FailureTag.StaleEvidence)

        // The self-reported report_data. Decoded as Go's StdEncoding decodes
        // it: atob accepts unpadded input Go refuses, and a lenient decode
        // here would pass a node Go refuses.
        let expected: Uint8Array
        let got: Uint8Array
        try {
            expected = reportData(op.ephemeralRecipientPubkey, op.operatorId)
            got = decodeGoStdBase64(bundle.report_data)
        } catch {
            return fail(FailureTag.KeyBindingMismatch)
        }
        if (!bytesEqual(expected, got)) return fail(FailureTag.KeyBindingMismatch)

        // Gated on the bool, after the key binding, so a stub cannot skip it.
        if (bundle.stub) {
            // No attestedModelIds: a stub has no quote, so nothing verified
            // the catalog.
            if (this.allowStub) return { ...verdict, pass: true }
            return fail(FailureTag.StubNotAllowed)
        }

        switch (bundle.mode) {
            case TEE_MODE_DSTACK_TDX: {
                const out = await this.dstack.verify(bundle, op, signal)
                const v: Verdict = { ...verdict, verifierId: VERIFIER_ID_DSTACK, detail: out.detail }
                if (out.failureTag !== '') return { ...v, failureTag: out.failureTag }
                // The list verifyAux just matched, built even when empty: an
                // empty array is a signed empty catalog.
                const models = Array.isArray(bundle.app_models) ? (bundle.app_models as { model_id: string }[]) : []
                return { ...v, pass: true, attestedModelIds: models.map((m) => m.model_id) }
            }
            default:
                // nvidia-cc-* until NRAS lands, and any mode both sides agree
                // on that this build has no verifier for.
                return fail(FailureTag.VerifierNotImplemented)
        }
    }
}

