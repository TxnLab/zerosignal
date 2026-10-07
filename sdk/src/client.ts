/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer, mirroring proto/go/zs Client: routing, reserve, escrow, sealing
// and settlement. One Client serves every concurrent request, so per-request
// state never goes on it; a turn's state lives in the turn.

import algosdk from 'algosdk'

import { IDAffinity } from './affinity.js'
import { type Parts, partsOf } from './client-parts.js'
import { type Config, type ResolvedConfig, resolveConfig } from './config.js'
import { AlgodEscrowChain } from './escrow/algod.js'
import { configError } from './errors.js'
import type { EstimatePolicy } from './estimate.js'
import { FeeRateCache } from './fee-rate.js'
import {
    type RegistryProvider,
    type Stores,
    type TicketJournal,
    httpReserveClient,
    isMemoryJournal,
    memoryJournal,
} from './parts.js'
import type { PickDeps } from './pick.js'
import { payerBytesSigner } from './ports.js'
import { Reconciler, walletChain } from './reconciler.js'
import { type RefundWatchdog, Watchdog } from './refund-watchdog.js'
import { Wallet } from './wallet.js'

/** Bounds the escrow config read a built wallet needs, as Go's escrowConfigTimeout. */
export const ESCROW_CONFIG_TIMEOUT_MS = 10_000

// Each journal a Client running the SDK's own wallet holds. Two Clients over
// one journal would each read the other's live tickets as nobody's, and both
// submit the same refund or lapse.
const journalsSwept = new WeakSet<TicketJournal>()

export class Client {
    readonly #p: Parts
    readonly #feeRate = new FeeRateCache()
    #closing: Promise<void> | undefined

    private constructor(p: Parts) {
        this.#p = p
        partsOf.set(this, p)
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
        if (sdkWallet && journal !== undefined && journalsSwept.has(journal)) {
            throw configError(
                'Stores.journal is already swept by another Client in this process: each Client that builds or is handed a Wallet needs its own journal',
            )
        }

        const estimatePolicy: EstimatePolicy = {
            maxOutputByModel: cfg.maxOutputByModel,
            fallbackMaxOutput: cfg.requireMaxOutput ? 0 : cfg.maxOutputCeiling,
        }
        // As Go's New, config reads back the parts built here.
        const stores: Stores = { ...st, toolAffinity, responseAffinity }
        if (journal !== undefined) stores.journal = journal
        const filled: ResolvedConfig = { ...cfg, reserveClient, wallet, stores }
        const pick: PickDeps = {
            registry,
            toolAffinity,
            responseAffinity,
            affinityPolicy: cfg.affinity.policy,
            allowStaging: cfg.allowStaging,
            relayLatency: st.relayLatency,
            targetBackoff: st.targetBackoff,
            nodeExclusions: st.nodeExclusions,
            relayReputation: st.relayReputation,
            logger: cfg.logger,
            weightsWarned: new Set(),
        }
        const guard = cfg.spendGuard
        // The watchdog and the sweep time contract deadlines, so they read the
        // wall clock, as Go's do: Config.clock drives affinity and the cache,
        // and a clock running ahead there would send calls the chain reverts.
        const refunds = new Watchdog({
            logger: cfg.logger,
            remedy: cfg.remedies.recoverTicket,
            // A ticket whose request failed after its escrow opened keeps its
            // reservation in dispatch; its refund is what frees it.
            refunded: guard ? (ticketId) => guard.release(ticketId) : undefined,
        })
        // Only the SDK's own wallet runs the sweep, which is what deletes rows.
        const chain = walletChain(wallet)
        let reconciler: Reconciler | undefined
        if (chain !== undefined && journal !== undefined) {
            journalsSwept.add(journal)
            reconciler = new Reconciler({
                journal,
                chain,
                payer: wallet.payerAddr(),
                escrowAppId: cfg.network.escrowAppId,
                watching: (ticketId) => refunds.watching(ticketId),
                spend: guard,
                logger: cfg.logger,
            })
            reconciler.remedy = cfg.remedies.recoverTicket
            let held = true
            reconciler.release = () => {
                if (held) journalsSwept.delete(journal)
                held = false
            }
            // The default journal dies with this Client, so its watchdog stays
            // the only thing that finishes its tickets. A journal the caller
            // supplied, a memoryJournal too, can pass to the next Client, so its
            // tickets go with it (Go's durableJournal, which can't be handed a
            // memory journal).
            reconciler.handOff = st.journal !== undefined
        }
        const c = new Client({
            cfg: filled,
            registry,
            reserveClient,
            wallet,
            pick,
            estimatePolicy,
            journal,
            durableJournal,
            refunds,
            reconciler,
        })
        reconciler?.start()
        c.#warmFeeRate()
        return c
    }

    /**
     * Stops the ticket sweep create started and releases this Client's hold
     * on its journal, so another Client may sweep it. When the Client runs the
     * SDK's Wallet over a journal the caller supplied, it also stops the refund watchdog,
     * waiting out a refund it already sent, and leaves the tickets it watched
     * to the next Client that sweeps that journal, or to the next process; a
     * request still in flight here is then not watched. Safe to call more than
     * once.
     */
    close(): Promise<void> {
        this.#closing ??= (async () => {
            const r = this.#p.reconciler
            if (r === undefined) return
            const refunds = this.#p.refunds
            await r.close(r.handOff ? () => refunds.handOff() : undefined)
        })()
        return this.#closing
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

    /** The watchdog that recovers escrow for tickets whose settlement never arrived. */
    get refunds(): RefundWatchdog {
        return this.#p.refunds
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
