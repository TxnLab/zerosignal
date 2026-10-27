/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: what a Client runs on, kept out of the package exports so a
// caller can't reach the Client's stores or drive its reserve phase directly.

import type { Client } from './client.js'
import type { ResolvedConfig } from './config.js'
import type { DispatchDeps, RunSealed } from './dispatch.js'
import type { EstimatePolicy } from './estimate.js'
import type { RegistryProvider, ReserveClient, TicketJournal, WalletOpener } from './parts.js'
import type { PickDeps } from './pick.js'
import type { Reconciler } from './reconciler.js'
import type { ChainOperatorSource } from './registry/chain.js'
import type { Watchdog } from './refund-watchdog.js'
import type { Settles } from './settles.js'
import type { CreditWallet } from './solana/credits.js'

/**
 * The parts a Client runs on. Routing stores, the spend guard and the logger
 * are read off cfg, where an absent store is no signal; with a built registry
 * every routing store is set.
 */
export interface Parts {
    cfg: ResolvedConfig
    registry: RegistryProvider
    reserveClient: ReserveClient
    wallet: WalletOpener
    /** Candidate selection's view of the Client, the affinity stores always set. */
    pick: PickDeps
    estimatePolicy: EstimatePolicy
    /** Undefined only with a caller's wallet and no Stores.journal. */
    journal: TicketJournal | undefined
    durableJournal: boolean
    refunds: Watchdog
    /** The journal sweep; set only with the SDK's Wallet. */
    reconciler: Reconciler | undefined
    /** The escrow work turns leave running after their replies. */
    settles: Settles
    /** Aborted by close, ending background work that would outlive the Client. */
    life: AbortController
    /**
     * The chain source behind the registry create built; undefined with a
     * supplied registry. Nothing at runtime reads it: tests drive its probes.
     */
    source: ChainOperatorSource | undefined
    /** Stops the registry create built, which close calls; undefined with a supplied one. */
    stopRegistry: (() => Promise<void>) | undefined
    /** Fetches and holds the credits a free Solana reserve carries; undefined carries none. */
    freeCredits: CreditWallet | undefined
}

/** Each Client's parts, set by its constructor. */
export const partsOf = new WeakMap<Client, Parts>()

/** dispatchDepsOf is dispatch's view of c, with the sealed run supplied. */
export function dispatchDepsOf(c: Client, runSealed: RunSealed): DispatchDeps {
    const p = partsOf.get(c)!
    const cfg = p.cfg
    return {
        pick: p.pick,
        reserveClient: p.reserveClient,
        wallet: p.wallet,
        estimatePolicy: p.estimatePolicy,
        privacy: cfg.privacy,
        allowPrivacyOverride: cfg.allowPrivacyOverride,
        requireTeeModels: cfg.requireTeeModels,
        spendGuard: cfg.spendGuard,
        remedies: cfg.remedies,
        network: cfg.network.network,
        rail: cfg.network.rail,
        retryBudget: cfg.retryBudget,
        sweepDelay: cfg.sweepDelay,
        feeRate: () => c.feeRate(),
        runSealed,
        clock: cfg.clock,
        freeCredits: p.freeCredits,
    }
}
