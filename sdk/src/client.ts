/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer, mirroring proto/go/zs Client: routing, reserve, escrow, sealing
// and settlement. One Client serves every concurrent request, so per-request
// state never goes on it; a turn's state lives in the turn.

import algosdk from 'algosdk'

import { type AffinityStore, IDAffinity } from './affinity.js'
import { type Config, type ResolvedConfig, resolveConfig } from './config.js'
import { AlgodEscrowChain } from './escrow/algod.js'
import { configError } from './errors.js'
import type { EstimatePolicy } from './estimate.js'
import { FeeRateCache } from './fee-rate.js'
import {
    type RegistryProvider,
    type ReserveClient,
    type Stores,
    type TicketJournal,
    type WalletOpener,
    httpReserveClient,
    isMemoryJournal,
    memoryJournal,
} from './parts.js'
import { payerBytesSigner } from './ports.js'
import { Wallet } from './wallet.js'

/** Bounds the escrow config read a built wallet needs, as Go's escrowConfigTimeout. */
export const ESCROW_CONFIG_TIMEOUT_MS = 10_000

// Each journal a Client running the SDK's own wallet holds. Two Clients over
// one journal would each read the other's live tickets as nobody's, and both
// submit the same refund or lapse.
const journalsSwept = new WeakSet<TicketJournal>()

/**
 * The parts a Client runs on. Routing stores, the spend guard and the logger
 * are read off cfg, where an absent store is no signal.
 */
interface Parts {
    cfg: ResolvedConfig
    registry: RegistryProvider
    reserveClient: ReserveClient
    wallet: WalletOpener
    /** Both stores are always set: Stores' absent is a fresh IDAffinity. */
    toolAffinity: AffinityStore
    responseAffinity: AffinityStore
    estimatePolicy: EstimatePolicy
    /** Undefined only with a caller's wallet and no Stores.journal. */
    journal: TicketJournal | undefined
    durableJournal: boolean
}

export class Client {
    readonly #p: Parts
    readonly #feeRate = new FeeRateCache()
    /** Whether this Client holds #p.journal against a second sweeper. */
    #claimedJournal: boolean

    private constructor(p: Parts, claimedJournal: boolean) {
        this.#p = p
        this.#claimedJournal = claimedJournal
    }

    /**
     * Builds a Client, and the reserve client and wallet when Config leaves
     * them out. Building the wallet reads the escrow's config from chain
     * (the ticket MBR, the globals and the free-quota term), which must
     * succeed; signal bounds that read only. Config.registry is required: the
     * SDK builds no operator discovery of its own yet.
     */
    static async create(config: Config, signal?: AbortSignal): Promise<Client> {
        const cfg = resolveConfig(config)
        for (const w of cfg.warnings) cfg.logger.warn(w)
        const registry = cfg.registry
        if (!registry) {
            throw configError('Config.registry is required: this SDK builds no operator discovery of its own')
        }
        const reserveClient =
            cfg.reserveClient ??
            httpReserveClient({
                fetch: cfg.fetch,
                signer: payerBytesSigner(cfg.signer),
                timeoutMs: cfg.reserveTimeout,
                clock: cfg.clock,
            })
        const wallet = cfg.wallet ?? (await buildWallet(cfg, signal))

        const st = cfg.stores
        const toolAffinity = st.toolAffinity ?? new IDAffinity(cfg.affinity.max, cfg.affinity.ttl, cfg.clock)
        const responseAffinity = st.responseAffinity ?? new IDAffinity(cfg.affinity.max, cfg.affinity.ttl, cfg.clock)

        // Only the SDK's own wallet runs the sweep that deletes rows; with a
        // caller's wallet a default journal would only grow.
        const sdkWallet = wallet instanceof Wallet
        // Go can't be handed its memory journal; TS exports memoryJournal.
        const durableJournal = st.journal !== undefined && !isMemoryJournal(st.journal)
        let journal = st.journal
        if (journal === undefined && sdkWallet) {
            journal = memoryJournal()
            cfg.logger.info(
                'open tickets are journaled in memory: after a restart, a ticket this process opened is refunded only by hand. Set Stores.journal to keep them',
            )
        }
        let claimedJournal = false
        if (sdkWallet && journal !== undefined) {
            if (journalsSwept.has(journal)) {
                throw configError(
                    'Stores.journal is already swept by another Client in this process: each Client that builds or is handed a Wallet needs its own journal',
                )
            }
            journalsSwept.add(journal)
            claimedJournal = true
        }

        const estimatePolicy: EstimatePolicy = {
            maxOutputByModel: cfg.maxOutputByModel,
            fallbackMaxOutput: cfg.requireMaxOutput ? 0 : cfg.maxOutputCeiling,
        }
        // As Go's New, config reads back the parts built here.
        const stores: Stores = { ...st, toolAffinity, responseAffinity }
        if (journal !== undefined) stores.journal = journal
        const filled: ResolvedConfig = { ...cfg, reserveClient, wallet, stores }
        const c = new Client(
            { cfg: filled, registry, reserveClient, wallet, toolAffinity, responseAffinity, estimatePolicy, journal, durableJournal },
            claimedJournal,
        )
        c.#warmFeeRate()
        return c
    }

    /**
     * Releases this Client's hold on its journal, so another Client may sweep
     * it. Safe to call more than once.
     */
    close(): void {
        if (this.#claimedJournal && this.#p.journal !== undefined) {
            journalsSwept.delete(this.#p.journal)
            this.#claimedJournal = false
        }
    }

    /**
     * Whether open tickets are journaled somewhere that outlives the process:
     * a Stores.journal the caller supplied other than a memoryJournal. False
     * means a ticket a crash leaves open is refunded only by hand.
     */
    get journalDurable(): boolean {
        return this.#p.durableJournal
    }

    /** The configuration with every default applied and the parts create built filled in. */
    get config(): ResolvedConfig {
        return this.#p.cfg
    }

    /** The operator catalog the Client routes from. */
    get registry(): RegistryProvider {
        return this.#p.registry
    }

    /**
     * The protocol fee rate, in basis points on top of an operator's charge,
     * that this payer currently pays. Read from chain in the background, it
     * never waits; null until the first read lands, or when the wallet cannot
     * read it.
     */
    feeRate(): number | null {
        const w = this.#p.wallet
        const read = w.protocolFeeBps?.bind(w)
        if (!read) return null
        return this.#feeRate.get(read)
    }

    /**
     * Starts the first fee read from create, so the catalog is priced before
     * anyone asks: the request that finds the cache cold is the one that
     * misses it, and an OpenAI-compatible client caches the catalog it reads
     * at connect time for minutes. It does not wait, so a request inside the
     * read's round trip still finds it cold. A failed warm is silent and a
     * later read retries, so a catalog that stays price-less points at chain
     * reachability, not pricing.
     */
    #warmFeeRate(): void {
        this.feeRate()
    }
}

/** buildWallet reads the escrow's config and builds the wallet that opens tickets against it. */
async function buildWallet(cfg: ResolvedConfig, signal?: AbortSignal): Promise<Wallet> {
    const n = cfg.network
    // No port argument: algosdk would replace the endpoint's own with it.
    const algod = new algosdk.Algodv2(n.algodToken, n.algodEndpoint)
    const chain = new AlgodEscrowChain({
        algod,
        appId: n.escrowAppId,
        signer: cfg.signer,
        logger: cfg.logger,
        clock: cfg.clock,
    })
    const timeout = AbortSignal.timeout(ESCROW_CONFIG_TIMEOUT_MS)
    try {
        await chain.refreshConfig(signal ? AbortSignal.any([signal, timeout]) : timeout)
    } catch (err) {
        throw new Error(`read escrow config: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    return new Wallet({ chain, signer: cfg.signer, depositSlots: cfg.concurrentSlots, logger: cfg.logger })
}
