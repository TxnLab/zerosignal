/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer, mirroring proto/go/zs Client: routing, reserve, escrow, sealing
// and settlement. One Client serves every concurrent request, so per-request
// state never goes on it; a turn's state lives in the turn.

import type algosdk from 'algosdk'

import { IDAffinity } from './affinity.js'
import { type BuiltDiscovery, buildDiscovery, chainAlgod } from './assemble.js'
import { type Parts, dispatchDepsOf, partsOf } from './client-parts.js'
import { type Config, type ResolvedConfig, resolveConfig } from './config.js'
import { type RunSealed, dispatch } from './dispatch.js'
import { AlgodEscrowChain } from './escrow/algod.js'
import { configError } from './errors.js'
import type { EstimatePolicy } from './estimate.js'
import { FeeRateCache } from './fee-rate.js'
import { FETCH_BASE_URL, type FetchTarget, openAIFetch } from './fetch/serve.js'
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
import { type PickDeps, relayHopForPool, relayPool } from './pick.js'
import { type Fetch, payerBytesSigner } from './ports.js'
import { guardRecords } from './spend-guard.js'
import type { SettleSlot } from './receipt-check.js'
import { type JournalDeps, Reconciler, journalOpen, journalReceipt, walletChain } from './reconciler.js'
import { type RefundWatchdog, Watchdog } from './refund-watchdog.js'
import { deploymentOrFail, readDeploymentId } from './registry/chain.js'
import { type ResponderDeps, bufferedResponder } from './responder.js'
import { type SealedDeps, runSealed } from './sealed.js'
import { Settles } from './settles.js'
import { untilAborted } from './sleep.js'
import { IdleWatchdog } from './idle.js'
import { type GenComplete, forwardStream, frameFactory } from './stream.js'
import { type Request, type Stream, TurnStream, turnOf } from './turn.js'
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

    /**
     * An OpenAI-compatible endpoint as a fetch function: hand it to an OpenAI
     * client built on baseURL, once, and every request it sends is a turn of
     * this Client, routed to a node per request. The response is the node's,
     * as an OpenAI API would send it; a stream's usage arrives in a zs.usage
     * frame only when the request sets X-Zs-Usage-Frame. openAIFetch builds
     * one with options this one leaves out, such as a funding hint.
     */
    readonly fetch: Fetch

    private constructor(p: Parts) {
        this.#p = p
        partsOf.set(this, p)
        // FetchTarget's config, registry and feeRate are optional, so only
        // this pins that a Client still hands zs.fetch its network and logger
        // and the catalog and fee its model routes read.
        this.fetch = openAIFetch(this satisfies Required<Pick<FetchTarget, 'config' | 'registry' | 'feeRate'>>)
    }

    /** The base URL for an OpenAI client whose fetch is this Client's fetch. */
    get baseURL(): string {
        return FETCH_BASE_URL
    }

    /**
     * Builds a Client, and the registry, reserve client and wallet when Config
     * leaves them out. Building the wallet reads the escrow's config from
     * chain (the ticket MBR, the globals and the free-quota term), which must
     * succeed. Building the registry loads the saved catalog and reads the
     * operators from chain, which may fail: the registry then starts from the
     * saved catalog, or empty, and retries in the background. The first probe
     * of every node runs in the background too, and the first request waits
     * for it. What boot seeds the registry with must hold no duplicate or
     * zero node id, or create rejects. signal bounds these reads only. close
     * stops the registry this builds; one the caller supplied is left running.
     */
    static async create(config: Config, signal?: AbortSignal): Promise<Client> {
        const cfg = resolveConfig(config)
        for (const w of cfg.warnings) cfg.logger.warn(w)
        const algod = cfg.wallet === undefined || cfg.registry === undefined ? chainAlgod(cfg) : undefined
        // The wallet first, as in Go: its read is the one that fails create,
        // so it fails before the slow discovery rather than after.
        const builtWallet = cfg.wallet === undefined
        const wallet = cfg.wallet ?? (await buildWallet(cfg, algod!, signal))
        const deployment =
            algod === undefined
                ? undefined
                : await deploymentOrFail(
                      () => readDeploymentId(algod, cfg.network.escrowAppId, ESCROW_CONFIG_TIMEOUT_MS, signal),
                      builtWallet,
                      cfg.logger,
                      signal,
                  )
        const reserveClient =
            cfg.reserveClient ??
            httpReserveClient({
                fetch: cfg.fetch,
                signer: payerBytesSigner(cfg.signer),
                timeoutMs: cfg.reserveTimeout,
                clock: cfg.clock,
                deployment,
            })

        let st = cfg.stores
        let registry = cfg.registry
        let built: BuiltDiscovery | undefined
        if (registry === undefined) {
            built = buildDiscovery(cfg, algod!, deployment)
            try {
                await untilAborted(built.registry.ready, signal)
            } catch (err) {
                await built.registry.stop()
                if (signal?.aborted) throw err
                throw new Error(`registry: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
            }
            // Not create's signal: that bounds construction, and the refresh
            // timer runs until close.
            built.registry.start()
            registry = built.registry
            st = { ...st, ...built.stores }
        }
        try {
            return Client.#assemble(cfg, registry, st, reserveClient, wallet, built)
        } catch (err) {
            // A started registry left behind would read the chain and probe
            // the fleet for the life of the process.
            await built?.registry.stop()
            throw err
        }
    }

    // The rest of create, which reads nothing: the parts and the Client.
    static #assemble(
        cfg: ResolvedConfig,
        registry: RegistryProvider,
        st: Stores,
        reserveClient: ReserveClient,
        wallet: WalletOpener,
        built: BuiltDiscovery | undefined,
    ): Client {
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
        const filled: ResolvedConfig = { ...cfg, registry, reserveClient, wallet, stores }
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
            refunded: guard ? (ticketId) => guardRecords(cfg.logger, 'release', ticketId, () => guard.release(ticketId)) : undefined,
        })
        const life = new AbortController()
        const settles = new Settles({ logger: cfg.logger, journal, life: life.signal })
        // Only the SDK's own wallet runs the sweep, which is what deletes rows.
        const chain = walletChain(wallet)
        let reconciler: Reconciler | undefined
        if (chain !== undefined && journal !== undefined) {
            journalsSwept.add(journal)
            reconciler = new Reconciler({
                journal,
                chain,
                payer: wallet.payerAddr(),
                deployment: cfg.network,
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
            settles,
            life,
            source: built?.source,
            stopRegistry: built === undefined ? undefined : () => built.registry.stop(),
        })
        reconciler?.start()
        c.#warmFeeRate()
        return c
    }

    /**
     * Returns request as a Stream bound to signal. Aborting signal before the
     * node finishes generating cancels the turn; after it, the receipt is
     * still collected and the ticket settled.
     */
    stream(request: Request, signal?: AbortSignal): Stream {
        const p = this.#p
        const feeRate = () => this.feeRate()
        // Read now, as Go copies its Request: a later change to request
        // must not route the turn one way and decode it another.
        const turn = turnOf(request)
        return new TurnStream(
            (em, slot, sig) => {
                const runSealedTurn: RunSealed = (sem, run, s) => runSealed(sealedDeps(p, feeRate, slot), sem, run, s)
                return dispatch(dispatchDepsOf(this, runSealedTurn), em, turn, sig)
            },
            request,
            signal,
            p.cfg.logger,
        )
    }

    /**
     * Resolves once no background escrow work is running: the submits made
     * after a whole reply, and the watches on atomic settles until each is
     * seen to land, is dropped, or times out. Work that starts while it waits
     * is waited for too. Call it once no new turns start, and before close.
     * When signal aborts first it rejects naming the tickets still being
     * submitted, since a submit that dies with the process is not recovered
     * in-process (the refund watchdog is in-memory too), apart from settles
     * submitted but not yet seen to land, whose journal rows stay for the
     * reconciler.
     */
    waitSettles(signal?: AbortSignal): Promise<void> {
        return this.#p.settles.wait(signal)
    }

    /**
     * Stops the registry create built, if it built one, and the ticket sweep
     * it started, and releases this Client's hold on its journal, so another
     * Client may sweep it. A registry from Config is left running: the caller
     * owns it, and may share it with other Clients. It does not wait for
     * settlements; see waitSettles. It ends any watch on a settle still
     * unconfirmed, leaving that ticket's journal row in place. When the Client
     * runs the SDK's Wallet over a journal the caller supplied, it also stops
     * the refund watchdog, waiting out a refund it already sent, and leaves
     * the tickets it watched to the next Client that sweeps that journal, or
     * to the next process; a request still in flight here is then not
     * watched, so call waitSettles first when no Client follows. Safe to call
     * more than once.
     */
    close(): Promise<void> {
        this.#closing ??= (async () => {
            this.#p.life.abort()
            // Both run whatever the other throws: a registry left running keeps
            // probing, and an unreleased journal claim bars the next Client.
            const r = this.#p.reconciler
            const refunds = this.#p.refunds
            const results = await Promise.allSettled([
                (async () => this.#p.stopRegistry?.())(),
                (async () => r?.close(r.handOff ? () => refunds.handOff() : undefined))(),
            ])
            const failed = results.flatMap((res) => (res.status === 'rejected' ? [res.reason as unknown] : []))
            if (failed.length === 1) throw failed[0]
            if (failed.length > 1) throw new AggregateError(failed, 'closing the registry and the ticket sweep both failed')
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

/**
 * sealedDeps is the sealed run's view of a Client for one turn, whose escrow
 * submit reports through slot.
 */
function sealedDeps(p: Parts, feeRate: () => number | null, slot: SettleSlot): SealedDeps {
    const cfg = p.cfg
    const st = cfg.stores
    const logger = cfg.logger
    // Journal rows carry wall-clock times, as Go's do.
    const journal: JournalDeps = {
        journal: p.journal,
        logger,
        clock: Date.now,
        deployment: cfg.network,
        payer: p.wallet.payerAddr(),
    }
    const responder: ResponderDeps = {
        logger,
        spendGuard: cfg.spendGuard,
        nodeExclusions: st.nodeExclusions,
        journalReceipt: (h, receipt) => journalReceipt(journal, h, receipt),
        resolveRefund: (ticketId) => p.refunds.resolve(ticketId),
        confirmSettled: (ticketId, txId, h) => p.settles.confirmSettled(ticketId, txId, h),
        toolAffinity: p.pick.toolAffinity,
        responseAffinity: p.pick.responseAffinity,
        feeRate,
        afterResponse: (ticketId, submit) => p.settles.afterResponse(ticketId, submit),
    }
    const deps: SealedDeps = {
        wallet: p.wallet,
        spendGuard: cfg.spendGuard,
        remedies: cfg.remedies,
        network: cfg.network.network,
        fetch: cfg.inferenceFetch,
        relayReputation: st.relayReputation,
        logger,
        streamIdle: cfg.streamIdle,
        // With USDC locked on chain, the watchdog recovers it if no settlement
        // resolves the ticket, and the journal keeps it past a restart.
        opened: async (h, ticket) => {
            p.refunds.track(h, ticket.expires_at)
            await journalOpen(journal, h, ticket)
        },
        relays: {
            pool: (signal) => relayPool(p.pick, signal),
            hopFor: (pool, target) => relayHopForPool(p.pick, pool, target),
        },
        buffered: (call) => bufferedResponder(responder, call, slot),
        streamed: (em, out, call, buffered) => {
            const genComplete: GenComplete = { value: false }
            const idle = cfg.streamIdle === null ? undefined : new IdleWatchdog(cfg.streamIdle)
            const frames = frameFactory(responder, call, genComplete, slot, idle)
            return forwardStream(deps, em, out, call, frames, buffered, genComplete, idle)
        },
    }
    return deps
}

/** buildWallet reads the escrow's config and builds the wallet that opens tickets against it. */
async function buildWallet(cfg: ResolvedConfig, algod: algosdk.Algodv2, signal?: AbortSignal): Promise<Wallet> {
    const chain = new AlgodEscrowChain({
        algod,
        appId: cfg.network.escrowAppId,
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
