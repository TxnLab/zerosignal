/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Client configuration, mirroring proto/go/zs Config. Durations are
// milliseconds; the defaults are pinned against Go's by
// testdata/sdk_vocabulary_vectors.json.

import { defaultFetch } from '#default-fetch'

import { configError } from './errors.js'
import { withHeaderBackstop } from './header-backstop.js'
import { DEFAULT_STREAM_IDLE, type StreamIdle } from './idle.js'
import type { Network, ResolvedNetwork } from './network.js'
import { resolveNetwork } from './network.js'
import type { RegistryProvider, ReserveClient, Stores, WalletOpener } from './parts.js'
import {
    type CacheAdapter,
    type Clock,
    type Fetch,
    type Logger,
    RESPONSE_HEADER_BACKSTOP_MS,
    type Signer,
    type StorageAdapter,
    discardLogger,
    memoryCache,
    memoryStorage,
} from './ports.js'
import { MAX_TIMER_MS } from './sleep.js'
import type { AffinityPolicy, Privacy } from './types.js'

/** Affinity configures continuation pinning. */
export interface Affinity {
    policy: AffinityPolicy
    /** How long a pin lives, in milliseconds. */
    ttl: number
    max: number
}

/** Discovery tunes operator discovery and the details probes behind routing. */
export interface Discovery {
    refreshInterval: number
    /** One refresh cycle. */
    refreshTimeout: number
    /** Details probes per cycle. */
    probeBudget: number
    /** Targets probed in full per model. */
    targetTopK: number
    maxCacheAge: number
    /** How long a node missing from a cycle stays routable. */
    maxCarryAge: number
    latencyStateMax: number
    detailsTimeout: number
    detailsConcurrency: number
    /** When set, limits discovery to these operators. */
    operatorIds?: number[]
}

/**
 * Remedies are the instructions an error or log line ends with when the fix
 * is the payer's, in the host's own terms: a settings page, a CLI command.
 * Each is a clause that reads after "to fix it, ".
 */
export interface Remedies {
    /** Ends wallet_unfunded and mbr_pool_underfunded. */
    fund: string
    raiseSlots: string
    raiseSpendCap: string
    /** Finishes a ticket the SDK gave up settling or refunding. */
    recoverTicket: string
}

/**
 * SpendGuard is the caller's spending policy, consulted at two checkpoints.
 * Amounts are microUSDC. See proto/go/zs SpendGuard for the full contract:
 * settle and release can arrive more than once for a ticket, so a guard
 * keyed by ticket id counts only the first.
 */
export interface SpendGuard {
    /**
     * Before any reserve, with the lowest max_price any candidate is expected
     * to sign. Advisory: throwing refuses the request with kind spend_cap.
     */
    admit(estimate: number): void
    /**
     * After a node signs a ticket and before escrow opens, with its maxPrice.
     * Throwing moves on to the next candidate; returning records the exposure.
     * Throwing a DuplicateTicketError, or an error whose cause chain holds
     * one, instead ends the request with kind operator_fault.
     */
    reserve(ticketId: string, maxPrice: number): void
    settle(ticketId: string, charged: number): void
    /** Drops a reservation that never became a charge. */
    release(ticketId: string): void
}

/**
 * DuplicateTicketError is a SpendGuard reserve refusal for a ticket id that
 * already has an open reservation. Nodes mint ticket ids, so a repeat is the
 * node's misbehaviour, not the payer's cap. Go's ErrDuplicateTicket: matched
 * by class, so an error that merely reads the same is a spend_cap refusal.
 */
export class DuplicateTicketError extends Error {
    constructor(message = 'ticket id already has an open reservation', options?: ErrorOptions) {
        super(message, options)
        this.name = 'DuplicateTicketError'
    }
}

/** Config configures a Client. signer is required. */
export interface Config {
    signer: Signer
    /** Mainnet when absent. */
    network?: Network

    /** relay_required when absent. */
    privacy?: Privacy
    /**
     * Lets a request's relay preference turn relaying off; without it such an
     * opt-out is ignored. Asking for a relay is always honored.
     */
    allowPrivacyOverride?: boolean
    /** These models route only to attested nodes. */
    requireTeeModels?: string[]
    /** Checks no attestation evidence: every node counts as unattested. */
    disableTee?: boolean

    affinity?: Partial<Affinity>

    /**
     * Caps the output reservation when the request omits max_output_tokens
     * and the node declares none. Any other value than the default routes
     * differently from the Go SDK and zs-proxy for the same request.
     */
    maxOutputCeiling?: number
    maxOutputByModel?: Record<string, number>
    /** Refuses a request that omits max_output_tokens. */
    requireMaxOutput?: boolean

    /** How many tickets the prepaid MBR pool is funded for. */
    concurrentSlots?: number

    discovery?: Partial<Discovery>

    /** Per reserve attempt. */
    reserveTimeout?: number
    /** Bounds one request's retrying of transient failures, all before payment. */
    retryBudget?: number
    /**
     * How long a streamed answer may go without a byte before the turn ends
     * stream_interrupted, caused by a StreamIdleTimeoutError; false for no
     * bound. A browser's fetch has no read timeout and the SDK's Node fetch
     * sets none, so without one a node or relay that stops sending without
     * closing holds the turn until the caller gives up. The Go SDK has no
     * such bound: its callers set their context's deadline. A budget past
     * setTimeout's limit, about 24.8 days, is held to it.
     */
    streamIdle?: Partial<StreamIdle> | false
    /**
     * The wait in ms before the given retry sweep over the candidate list.
     * Set, it also replaces the wait before a busy re-sweep, the node's
     * Retry-After included.
     */
    sweepDelay?: (sweep: number) => number

    /** Development only. */
    allowStaging?: boolean
    /**
     * Route to operators whose URL names a private host, and, in Node, let the
     * default fetch dial a private address. Development only.
     */
    allowPrivateHosts?: boolean

    spendGuard?: SpendGuard
    remedies?: Partial<Remedies>
    stores?: Stores

    /**
     * The network-facing parts: operator discovery, the reserve call, and
     * escrow. The registry is required: this SDK builds no discovery of its
     * own yet, so `Client.create` refuses a config without one. The Client
     * builds an absent reserve client or wallet; a supplied part is used as
     * is, so the settings only a built part reads (reserveTimeout,
     * allowPrivateHosts) do not reach it. A supplied registry lists staging
     * nodes, as Go's does: routing holds them out as targets unless
     * allowStaging, and the relay pool keeps them.
     */
    registry?: RegistryProvider
    reserveClient?: ReserveClient
    wallet?: WalletOpener

    storage?: StorageAdapter
    cache?: CacheAdapter
    logger?: Logger
    clock?: Clock
    /**
     * Carries every request to a node. Unset in Node, a fetch that refuses
     * private addresses unless allowPrivateHosts (nodeFetch from
     * `@txnlab/zerosignal/node`); elsewhere the runtime's own. On either, an
     * inference request gives up on a node whose response headers take
     * RESPONSE_HEADER_BACKSTOP_MS. One supplied here is used as is, guard,
     * backstop or none.
     */
    fetch?: Fetch
}

/** ResolvedConfig is a Config with every default applied. */
export interface ResolvedConfig {
    signer: Signer
    network: ResolvedNetwork
    privacy: Privacy
    allowPrivacyOverride: boolean
    requireTeeModels: string[]
    disableTee: boolean
    affinity: Affinity
    maxOutputCeiling: number
    maxOutputByModel: Record<string, number>
    requireMaxOutput: boolean
    concurrentSlots: number
    discovery: Discovery
    reserveTimeout: number
    retryBudget: number
    /** null for no bound. */
    streamIdle: StreamIdle | null
    sweepDelay: ((sweep: number) => number) | undefined
    allowStaging: boolean
    allowPrivateHosts: boolean
    spendGuard: SpendGuard | undefined
    remedies: Remedies
    /** As given: the defaults depend on which parts the Client builds. */
    stores: Stores
    registry: RegistryProvider | undefined
    reserveClient: ReserveClient | undefined
    wallet: WalletOpener | undefined
    storage: StorageAdapter
    cache: CacheAdapter
    logger: Logger
    clock: Clock
    fetch: Fetch
    /**
     * Carries inference, Go's Config.HTTPClient: fetch, with the header
     * backstop when fetch is the default.
     */
    inferenceFetch: Fetch
    /** Settings that work but are probably mistakes; the Client logs them. */
    warnings: string[]
}

export const defaults = {
    affinity: { policy: 'prefer', ttl: 600_000, max: 1024 } satisfies Affinity,
    maxOutputCeiling: 32768,
    concurrentSlots: 10,
    reserveTimeout: 5_000,
    retryBudget: 60_000,
    discovery: {
        refreshInterval: 300_000,
        refreshTimeout: 30_000,
        probeBudget: 96,
        targetTopK: 8,
        maxCacheAge: 900_000,
        maxCarryAge: 5_400_000,
        latencyStateMax: 4096,
        detailsTimeout: 2_000,
        detailsConcurrency: 24,
    } satisfies Discovery,
} as const

const defaultRemedies: Remedies = {
    fund: 'fund the payer address: ALGO for fees and the ticket pool, and USDC for requests once the address has opted in to the USDC asset',
    raiseSlots: 'raise Config.concurrentSlots and rebuild the Client; the next request funds the larger pool',
    raiseSpendCap: "raise the SpendGuard's limits",
    recoverTicket:
        "read its box from the escrow and, once the deadline passes, call refundInactive on an open ticket or settleLapsed on an operator's claim",
}

// orDefault treats any non-positive value as unset: a negative timeout or
// count is never a meaningful request. NaN and Infinity are unset too, since
// a timer handed Infinity fires at once.
function orDefault(v: number | undefined, def: number): number {
    return v !== undefined && Number.isFinite(v) && v > 0 ? v : def
}

// A budget meant as "never" would otherwise fire at once, as setTimeout does
// past its limit.
function idleBudget(v: number | undefined, def: number): number {
    return Math.min(orDefault(v, def), MAX_TIMER_MS)
}

/** resolveConfig applies the defaults and validates, or throws a ZsError. */
export function resolveConfig(c: Config): ResolvedConfig {
    if (!c.signer) {
        throw configError('signer is required')
    }
    if (!c.signer.address) {
        throw configError('signer has no address')
    }
    // || rather than ??: an empty string is unset in Go, where it is the zero value.
    const privacy = c.privacy || 'relay_required'
    if (privacy !== 'relay_required' && privacy !== 'direct') {
        throw configError(`unknown privacy ${JSON.stringify(privacy)}`)
    }
    const policy = c.affinity?.policy || defaults.affinity.policy
    if (policy !== 'prefer' && policy !== 'strict' && policy !== 'none') {
        throw configError(`unknown affinity.policy ${JSON.stringify(policy)}`)
    }
    const network = resolveNetwork(c.network)
    const warnings = [...network.warnings]

    const requireMaxOutput = c.requireMaxOutput ?? false
    const maxOutputCeiling = orDefault(c.maxOutputCeiling, defaults.maxOutputCeiling)
    if (!requireMaxOutput && maxOutputCeiling !== defaults.maxOutputCeiling) {
        warnings.push(
            `maxOutputCeiling ${maxOutputCeiling} differs from the shared default ${defaults.maxOutputCeiling}: requests that omit max_output_tokens route differently from other payers`,
        )
    }
    const disableTee = c.disableTee ?? false
    const requireTeeModels = c.requireTeeModels ?? []
    if (disableTee && requireTeeModels.length > 0) {
        warnings.push(
            `requireTeeModels ${JSON.stringify(requireTeeModels)} have no route: TEE verification is off, so no node counts as attested`,
        )
    }

    const d = c.discovery ?? {}
    const dd = defaults.discovery
    const clock = c.clock ?? Date.now
    const discovery: Discovery = {
        refreshInterval: orDefault(d.refreshInterval, dd.refreshInterval),
        refreshTimeout: orDefault(d.refreshTimeout, dd.refreshTimeout),
        probeBudget: orDefault(d.probeBudget, dd.probeBudget),
        targetTopK: orDefault(d.targetTopK, dd.targetTopK),
        maxCacheAge: orDefault(d.maxCacheAge, dd.maxCacheAge),
        maxCarryAge: orDefault(d.maxCarryAge, dd.maxCarryAge),
        latencyStateMax: orDefault(d.latencyStateMax, dd.latencyStateMax),
        detailsTimeout: orDefault(d.detailsTimeout, dd.detailsTimeout),
        detailsConcurrency: orDefault(d.detailsConcurrency, dd.detailsConcurrency),
    }
    // Empty is no limit, as in Go, not a limit to no operators.
    if (d.operatorIds?.length) discovery.operatorIds = d.operatorIds

    const allowPrivateHosts = c.allowPrivateHosts ?? false
    const fetch = c.fetch ?? defaultFetch(allowPrivateHosts)
    if (!fetch) {
        throw configError('this runtime has no global fetch: set Config.fetch')
    }
    const inferenceFetch = c.fetch ?? withHeaderBackstop(fetch, RESPONSE_HEADER_BACKSTOP_MS)

    const r = c.remedies ?? {}
    return {
        signer: c.signer,
        network,
        privacy,
        allowPrivacyOverride: c.allowPrivacyOverride ?? false,
        requireTeeModels,
        disableTee,
        affinity: {
            policy,
            ttl: orDefault(c.affinity?.ttl, defaults.affinity.ttl),
            max: orDefault(c.affinity?.max, defaults.affinity.max),
        },
        maxOutputCeiling,
        maxOutputByModel: c.maxOutputByModel ?? {},
        requireMaxOutput,
        concurrentSlots: orDefault(c.concurrentSlots, defaults.concurrentSlots),
        discovery,
        reserveTimeout: orDefault(c.reserveTimeout, defaults.reserveTimeout),
        retryBudget: orDefault(c.retryBudget, defaults.retryBudget),
        streamIdle:
            c.streamIdle === false
                ? null
                : {
                      preStream: idleBudget(c.streamIdle?.preStream, DEFAULT_STREAM_IDLE.preStream),
                      midStream: idleBudget(c.streamIdle?.midStream, DEFAULT_STREAM_IDLE.midStream),
                      toolActive: idleBudget(c.streamIdle?.toolActive, DEFAULT_STREAM_IDLE.toolActive),
                  },
        sweepDelay: c.sweepDelay,
        allowStaging: c.allowStaging ?? false,
        allowPrivateHosts,
        spendGuard: c.spendGuard,
        stores: { ...c.stores },
        registry: c.registry,
        reserveClient: c.reserveClient,
        wallet: c.wallet,
        remedies: {
            fund: r.fund || defaultRemedies.fund,
            raiseSlots: r.raiseSlots || defaultRemedies.raiseSlots,
            raiseSpendCap: r.raiseSpendCap || defaultRemedies.raiseSpendCap,
            recoverTicket: r.recoverTicket || defaultRemedies.recoverTicket,
        },
        storage: c.storage ?? memoryStorage(),
        cache: c.cache ?? memoryCache(clock),
        logger: c.logger ?? discardLogger,
        clock,
        fetch,
        inferenceFetch,
        warnings,
    }
}
