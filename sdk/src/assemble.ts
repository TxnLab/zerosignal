/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What Client.create builds for the network parts Config leaves out,
// mirroring go/zs assemble.go (buildNetworkParts, newChainSource,
// registryConfig) and the store defaults New takes from the chain source.
// Exported so a host that shares one registry across Clients builds it as a
// Client would.
//
// Differences from Go:
//   - Go's chain source is itself every routing store, so a store the caller
//     supplies is read by dispatch while the source keeps its own. Here the
//     Client resolves each store first and hands the same instance to the
//     source and to dispatch, a supplied one included, so the probes and the
//     requests always build one standing per relay.
//   - Boot waits for the chain read, not for a probe of every node; see
//     registry.ts.
//   - The source, the registry and the built stores run on Config.clock. Go's
//     run on the wall clock, its Config.Clock reaching only affinity. The
//     default is the wall clock, and the TS registry already ran its carry
//     window and cache age on an injected one.
//   - The catalog is saved to Config.storage, which defaults to memory, under
//     a key naming the escrow app. Go saves it only to a CatalogPath the host
//     names. Operator and node ids repeat across networks, so a host that
//     switches networks over one storage must not read another's catalog.

import type algosdk from 'algosdk'

import { retryingAlgod } from './algod-transport.js'
import type { ResolvedConfig } from './config.js'
import type { ResolvedNetwork } from './network.js'
import { ChainOperatorSource } from './registry/chain.js'
import { CATALOG_STORAGE_KEY } from './registry/persist.js'
import { DiscoveryRegistry } from './registry/registry.js'
import { TargetBackoffStore } from './routing/backoff.js'
import { NodeExclusionStore } from './routing/exclusion.js'
import { RelayLatencyStore } from './routing/latency.js'
import { RelayReputationStore } from './routing/reputation.js'

/** The routing stores a built registry's probes record to, for its Clients to route with. */
export interface RoutingStores {
    relayReputation: RelayReputationStore
    relayLatency: RelayLatencyStore
    targetBackoff: TargetBackoffStore
    nodeExclusions: NodeExclusionStore
}

export interface BuiltDiscovery {
    registry: DiscoveryRegistry
    source: ChainOperatorSource
    stores: RoutingStores
}

/** chainAlgod is the one algod client a Client's wallet and discovery share, as Go's New builds one. */
export function chainAlgod(cfg: ResolvedConfig): algosdk.Algodv2 {
    return retryingAlgod({ endpoint: cfg.network.algodEndpoint, token: cfg.network.algodToken, logger: cfg.logger })
}

/**
 * buildDiscovery is the registry a Client builds when Config supplies none,
 * over a chain source reading algod, with every Discovery setting live, and
 * the routing stores its probes record to: Config.stores' own where set. Its
 * boot starts at once; the caller awaits ready, starts it, and stops it. A
 * host sharing it passes the registry and the stores to each Client, with
 * cfg.teeVerifier so the evidence checks share one collateral cache.
 */
export function buildDiscovery(
    cfg: ResolvedConfig,
    algod: algosdk.Algodv2,
    deployment?: Uint8Array,
): BuiltDiscovery {
    const st = cfg.stores
    const d = cfg.discovery
    // A relay's relay_upstream_unreachable claim is judged against the
    // target's last probe, the reachability the source keeps; a store judging
    // it by anything else would charge relays the probes see as fine.
    let source: ChainOperatorSource | undefined
    const stores: RoutingStores = {
        relayReputation:
            st.relayReputation ??
            new RelayReputationStore({ clock: cfg.clock, targetReachable: (t) => source?.recallReachable(t) ?? false }),
        relayLatency: st.relayLatency ?? new RelayLatencyStore({ clock: cfg.clock, maxEntries: d.latencyStateMax }),
        targetBackoff: st.targetBackoff ?? new TargetBackoffStore(cfg.clock),
        nodeExclusions: st.nodeExclusions ?? new NodeExclusionStore(),
    }
    source = new ChainOperatorSource({
        algod,
        escrowAppId: cfg.network.escrowAppId,
        operatorIds: d.operatorIds?.map((id) => BigInt(id)),
        // The probes dial node-registered addresses, so they get the dial
        // guard and no header backstop, as Go's newChainSource.
        fetch: cfg.fetch,
        privacy: cfg.privacy,
        detailsTimeoutMs: d.detailsTimeout,
        detailsConcurrency: d.detailsConcurrency,
        teeVerifier: cfg.teeVerifier,
        relayReputation: stores.relayReputation,
        relayLatency: stores.relayLatency,
        latencyStateMax: d.latencyStateMax,
        logger: cfg.logger,
        clock: cfg.clock,
        deployment,
    })
    const registry = new DiscoveryRegistry({
        source,
        storage: cfg.storage,
        storageKey: catalogStorageKey(cfg.network),
        legacyStorageKey: cfg.network.legacyKey ? catalogStorageKey(cfg.network.legacyKey) : undefined,
        discovery: d,
        // The Client's own, or the discovery aggregates and the per-request
        // gate disagree about which nodes exist.
        allowStaging: cfg.allowStaging,
        logger: cfg.logger,
        clock: cfg.clock,
    })
    return { registry, source, stores }
}

/**
 * catalogStorageKey is where a built registry saves its catalog for a
 * deployment: a ResolvedNetwork, or a key or legacy key of one.
 */
export function catalogStorageKey(d: ResolvedNetwork | string): string {
    return `${CATALOG_STORAGE_KEY}.${typeof d === 'string' ? d : d.key}`
}
