/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Whether a node's advertised deployment lets this payer route to it. Mirrors
// Go's checkDetailsDeployment (go/zs/fetcher.go), pinned by
// testdata/details_deployment_vectors.json; the reasoning lives there.

import { decodeDeploymentId } from '@txnlab/zs-proto/ticket'
import { usesDeploymentBinding } from '@txnlab/zs-proto/wire'

/** The details fields the check reads; either may be absent. */
export interface DeploymentWireFields {
    deployment?: string | undefined
    proto_version?: string | undefined
}

/**
 * checkDetailsDeployment returns why a node's details refuse it to a payer
 * whose own deployment id is want (undefined: unknown), or undefined when the
 * node may be routed to. A refused node counts as a failed probe.
 */
export function checkDetailsDeployment(details: DeploymentWireFields, want: Uint8Array | undefined): Error | undefined {
    let adv: Uint8Array | undefined
    if (details.deployment) {
        try {
            adv = decodeDeploymentId(details.deployment)
        } catch (err) {
            return new Error(`details: ${err instanceof Error ? err.message : String(err)}`)
        }
    }
    if (want === undefined) return undefined
    if (adv === undefined) {
        return usesDeploymentBinding(details.proto_version ?? '') ? new Error('details: node advertises no escrow deployment') : undefined
    }
    if (adv.length !== want.length || !adv.every((b, i) => b === want[i])) {
        return new Error('details: node serves another escrow deployment')
    }
    return undefined
}
