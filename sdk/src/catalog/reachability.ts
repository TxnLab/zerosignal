/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A node's details probe, read as the catalog's Reachability. The app runs the
// probe on its own scheduler and hands over only where the latest one stands.

import { protoVersionCompatible } from '@txnlab/zs-proto/wire'

import type { Reachability } from './rows.js'

/**
 * Where a node's latest details probe stands.
 * - pending: no probe has finished yet.
 * - failed: it threw. noRelay is the privacy-mode refusal to probe without a
 *   relay, which says nothing about the node.
 * - answered: it returned a details body. unreachable marks the empty answer a
 *   probe gives when no hop reached the node, which is not the node's own.
 */
export type ProbeOutcome =
    | { status: 'pending' }
    | { status: 'failed'; noRelay: boolean }
    | { status: 'answered'; unreachable: boolean; protoVersion: string | undefined }

/**
 * probeReachability maps a probe's outcome to the row's Reachability. Wire
 * compatibility is judged only on an answer the node itself gave, so an
 * unreachable node never reads as 'incompatible'.
 */
export function probeReachability(outcome: ProbeOutcome): Reachability {
    switch (outcome.status) {
        case 'pending':
            return 'probing'
        case 'failed':
            return outcome.noRelay ? 'no-relay' : 'failing'
        case 'answered':
            if (outcome.unreachable) return 'failing'
            return protoVersionCompatible(outcome.protoVersion) ? 'ok' : 'incompatible'
    }
}
