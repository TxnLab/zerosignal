/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The verifier a payer runs out of the box. Mirrors proto/go/zs/tee/defaults.go.

import {
    type ComposePolicy,
    trustedComposeSkeletons,
    trustedDstackOSImages,
    trustedNodeImages,
    zeroSignalComposePolicy,
} from '@txnlab/zs-proto/attest'

import type { Clock, Logger } from '../ports.js'
import { carriedChainVerifier, pccsChainVerifier } from './pccs.js'
import { BundleVerifier } from './verify.js'

/**
 * The shared compose rules with the published zs-node releases as the only
 * workloads that verify. The release match is enforced, which is what lets
 * defaultVerifier carry no compose hashes: a node is identified by the release
 * it runs, not by a per-deployment digest a payer would collect by hand.
 */
export function defaultComposePolicy(): ComposePolicy {
    return {
        ...zeroSignalComposePolicy(),
        trustedComposeSkeletons: trustedComposeSkeletons(),
        trustedNodeImages: trustedNodeImages(),
        enforceComposeSkeleton: true,
    }
}

export interface DefaultVerifierOptions {
    log?: Logger
    /** Unix milliseconds. */
    now?: Clock
    /** See PccsChainVerifierOptions.pccsUrl. */
    pccsUrl?: string
}

/**
 * Verifies dstack evidence against the production guest images and the
 * zs-node releases this build knows, with the real Intel chain step: the same
 * trust zs-proxy ships with. A node running a release newer than this build is
 * refused until the SDK is updated, because the lists are compiled in: a
 * served list would let whoever serves it decide what counts as attested.
 *
 * Build one and reuse it: the Intel collateral cache lives in the verifier,
 * so a new one starts cold and, during an outage, judges every node on the
 * collateral the node carried.
 */
export function defaultVerifier(opts: DefaultVerifierOptions = {}): BundleVerifier {
    const now = opts.now ?? Date.now
    return new BundleVerifier({
        trustedOSImages: trustedDstackOSImages(),
        composePolicy: defaultComposePolicy(),
        verifyChain: pccsChainVerifier({ now, ...(opts.pccsUrl !== undefined && { pccsUrl: opts.pccsUrl }) }),
        verifyChainCarried: carriedChainVerifier({ now }),
        now,
        ...(opts.log !== undefined && { log: opts.log }),
    })
}
