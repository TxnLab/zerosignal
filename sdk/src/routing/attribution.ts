/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What a relayed forward's outcome records against the relay. Mirrors
// relayHopAction and attributeRelayHop in proto/go/zs/dispatch.go, pinned by
// testdata/relay_attribution_vectors.json.

import { isForwardTimeoutStatus } from '@txnlab/zs-proto/steering'
import {
    Attribution,
    type RelayEvidence,
    TRANSPORT_FAILURE_STATUS,
    classify,
    narrowRelayed,
} from '@txnlab/zs-proto/transient'

import { type RelayHop, relayRef, targetRef } from './relay.js'
import type { RelayReputationStore } from './reputation.js'

/** The reputation record one relayed forward earns its relay. */
export type RelayAction =
    | 'none'
    | 'credit'
    | 'strike'
    | 'upstream_unreachable'
    | 'forwarded_target_fault'
    | 'forward_timeout'

/**
 * Decides what a relayed forward's outcome records against the relay. status
 * is the response's (TRANSPORT_FAILURE_STATUS when none arrived), code its
 * error.code, evidence the route evidence.
 *
 *  - The relay failed (a relay hop error, a transport failure, a 9.1+ relay's
 *    unmarked code-less status): strike it.
 *  - The relay claims the target failed: relay_upstream_unreachable is checked
 *    against our own probes both ways; a marked code-less status asserts only
 *    that the relay's handler ran, so it can cost the relay but never credit
 *    it.
 *  - Nobody can be blamed (a pre-9.1 relay's code-less status, an unmarked
 *    gateway timeout): record nothing, except that a timeout we didn't cause
 *    feeds the separate forward-timeout streak.
 *  - Anything else is the relay doing its job: credit it. Never for a
 *    transport failure, where nothing arrived to credit.
 */
export function relayHopAction(status: number, code: string, evidence: RelayEvidence): RelayAction {
    if (status === TRANSPORT_FAILURE_STATUS || status >= 400) {
        const raw = classify(status, code)
        const v = narrowRelayed(raw, status, evidence)
        switch (v.attribution) {
            case Attribution.Relay:
                return 'strike'
            case Attribution.Target:
                return raw.attribution === Attribution.Target ? 'upstream_unreachable' : 'forwarded_target_fault'
            case Attribution.Unknown:
                return isForwardTimeoutStatus(status) && !evidence.callerAborted ? 'forward_timeout' : 'none'
        }
        if (status === TRANSPORT_FAILURE_STATUS) return 'none'
    }
    return 'credit'
}

/** Records action against hop's relay in store, as Go's attributeRelayHop does. */
export function recordRelayHopAction(store: RelayReputationStore, hop: RelayHop, action: RelayAction): void {
    switch (action) {
        case 'strike':
            store.recordRelayOutcome(relayRef(hop), false)
            return
        case 'upstream_unreachable':
            store.recordRelayUpstreamUnreachable(relayRef(hop), targetRef(hop))
            return
        case 'forwarded_target_fault':
            store.recordRelayForwardedTargetFault(relayRef(hop), targetRef(hop))
            return
        case 'forward_timeout':
            store.recordRelayForwardTimeout(relayRef(hop), targetRef(hop))
            return
        case 'credit':
            store.recordRelayOutcome(relayRef(hop), true)
            return
        case 'none':
            return
    }
}
