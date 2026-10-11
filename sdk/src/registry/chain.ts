/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain half of discovery: the escrow app's operator and node boxes, read
// into one Operator per node, and each node's signing-account balance. Mirrors
// go/algod's ListApplicationBoxes (boxes.go), go/escrow's operator and node
// fetchers (operators.go, nodes.go), and the chain read of go/zs's
// ChainOperatorSource (fetcher.go, signer_balance.go). The chain_nodes block of
// testdata/operator_vectors.json pins box bytes to the operator Go resolves.
//
// Differences from Go:
//   - The readonly nextOperatorIdValue call is simulated from the application
//     account, as every readonly call in escrow/algod.ts is, rather than from a
//     payer address the host supplies, so it needs no funded payer. The value
//     returned is the same.
//   - A node box whose base URL is not UTF-8 is skipped and logged. Go keeps
//     the raw bytes, percent-escapes them on the wire and routes the node; a JS
//     string cannot hold them.
//   - Operator and node ids are numbers on Operator, so a node whose operator
//     or node id is past Number.MAX_SAFE_INTEGER is skipped like any other node
//     that won't resolve. nfdAppId, signerSpendableMicroAlgos and the metrics
//     (the latency and throughput EWMAs routing reads among them) narrow with
//     Number() and would round past 2^53, which none reaches.
//   - Retries and deadlines belong to the algod client. Go's algod.NewClient
//     retries a 429, 503 or other 5xx on every read and bounds a read only by
//     the refresh context; here the host's Algodv2 does whatever its
//     BaseHTTPClient does, and each read also carries requestTimeoutMs. Until
//     the SDK builds its Algodv2 on Go's retrying transport, one transient 503
//     on the listing fails the whole read.

import type algosdk from 'algosdk'
import {
    type NodeRecord,
    NodeBaseUrlEncodingError,
    OPERATOR_STATUS_EVICTED,
    type OperatorRecord,
    SECONDS_PER_DAY,
    decodeNodeRecord,
    decodeOperatorRecord,
    nodeBoxKey,
    nodeBoxPrefix,
    nodeIdsFromBoxName,
    operatorBoxKey,
    operatorBoxPrefix,
    operatorIdFromBoxName,
    windowedRingRevenue,
} from '@txnlab/zs-proto/escrow'
import { decodeAlgorandAddress } from '@txnlab/zs-proto/ticket'

import { isNotFound, requestOptions, requestTimeoutOrDefault, simulateReadonly, spendableOf } from '../escrow/algod.js'
import type { ModelCapacity, Operator } from '../operator.js'
import { type Clock, type Logger, discardLogger } from '../ports.js'

/** Where the escrow app's boxes are read from. */
export interface ChainReadOptions {
    algod: algosdk.Algodv2
    appId: bigint
    /** The most one algod request may take; absent, zero or negative is 30 s. */
    requestTimeoutMs?: number | undefined
    logger?: Logger | undefined
}

/**
 * FETCH_BOX_CONCURRENCY caps the box reads in flight against algod: well under
 * its default concurrent-request budget, and enough to hide the round trips
 * for a realistic fleet.
 */
export const FETCH_BOX_CONCURRENCY = 16

// `limit`, not `max`: algod checks `max` against the app's total box count
// before the prefix filter and fails the whole call rather than paging.
const BOX_LIST_PAGE_LIMIT = 1000

/** One box from a listing, name and value. */
export interface ApplicationBox {
    name: Uint8Array
    value: Uint8Array
}

/**
 * BoxValuesUnsupportedError is an algod that listed box names without the
 * values include=values asked for: one too old for the bulk read. The fetchers
 * fall back to reading box by box on it, and on nothing else.
 */
export class BoxValuesUnsupportedError extends Error {
    constructor() {
        super('algod: node did not return box values for include=values')
        this.name = 'BoxValuesUnsupportedError'
    }
}

/**
 * listApplicationBoxes returns every box of the app whose name starts with
 * prefix, values included, paging until algod runs out.
 *
 * No round is pinned across pages. Box data is readable only for the rounds
 * still in the node's lookback, so a pin turns a slow sweep into a failure,
 * while the cursor is a box name in sorted order: a box written or deleted
 * mid-sweep can only be missed or included itself, never shift the others.
 */
export async function listApplicationBoxes(c: ChainReadOptions, prefix: Uint8Array, signal?: AbortSignal): Promise<ApplicationBox[]> {
    const timeoutMs = requestTimeoutOrDefault(c.requestTimeoutMs)
    const out: ApplicationBox[] = []
    let next: string | undefined
    do {
        let page: algosdk.modelsv2.BoxesResponse
        try {
            let req = c.algod.getApplicationBoxes(c.appId).prefix(prefix).include('values').limit(BOX_LIST_PAGE_LIMIT)
            if (next !== undefined) req = req.next(next)
            page = await req.do(undefined, requestOptions(timeoutMs, signal))
        } catch (err) {
            throw new Error(`algod: box-list for app ${c.appId}: ${message(err)}`, { cause: err })
        }
        for (const b of page.boxes) {
            // Escrow boxes are never empty, so a missing value means algod
            // ignored include=values.
            if (b.value === undefined) throw new BoxValuesUnsupportedError()
            out.push({ name: b.name, value: b.value })
        }
        next = page.nextToken ? page.nextToken : undefined
    } while (next !== undefined)
    return out
}

/** readOperatorBox reads one operator's box; undefined once it is gone (unregistered). */
export async function readOperatorBox(c: ChainReadOptions, operatorId: bigint, signal?: AbortSignal): Promise<OperatorRecord | undefined> {
    const value = await readBox(c, operatorBoxKey(operatorId), `operator ${operatorId}`, signal)
    return value === undefined ? undefined : decodeOperatorRecord(operatorId, value)
}

/** readNodeBox reads one node's box; undefined once it is gone (unregistered). */
export async function readNodeBox(
    c: ChainReadOptions,
    operatorId: bigint,
    nodeId: bigint,
    signal?: AbortSignal,
): Promise<NodeRecord | undefined> {
    const value = await readBox(c, nodeBoxKey(operatorId, nodeId), `node ${operatorId}/${nodeId}`, signal)
    return value === undefined ? undefined : decodeNodeRecord(operatorId, nodeId, value)
}

async function readBox(c: ChainReadOptions, name: Uint8Array, what: string, signal?: AbortSignal): Promise<Uint8Array | undefined> {
    try {
        const box = await c.algod
            .getApplicationBoxByName(c.appId, name)
            .do(undefined, requestOptions(requestTimeoutOrDefault(c.requestTimeoutMs), signal))
        return box.value
    } catch (err) {
        if (isNotFound(err)) return undefined
        throw new Error(`fetch ${what} box: ${message(err)}`, { cause: err })
    }
}

/** nextOperatorId is the contract's next operator id: live ids run from 1 to one below it. */
export async function nextOperatorId(c: ChainReadOptions, signal?: AbortSignal): Promise<bigint> {
    const timeoutMs = requestTimeoutOrDefault(c.requestTimeoutMs)
    const v = await simulateReadonly(c.algod, c.appId, timeoutMs, 'nextOperatorIdValue', [], [], signal)
    if (typeof v !== 'bigint') throw new Error(`escrow: nextOperatorIdValue returned ${typeof v}, want uint64`)
    return v
}

/**
 * fetchAllOperators reads every registered operator, sorted by id. One paged
 * listing reads them all; only an algod too old to return values with it
 * falls back to the operator count and a read per id, which skips the
 * unregistered ones.
 */
export async function fetchAllOperators(c: ChainReadOptions, signal?: AbortSignal): Promise<OperatorRecord[]> {
    try {
        return await fetchAllOperatorsBulk(c, signal)
    } catch (err) {
        if (!(err instanceof BoxValuesUnsupportedError)) throw err
    }
    let nextId: bigint
    try {
        nextId = await nextOperatorId(c, signal)
    } catch (err) {
        throw new Error(`escrow: fetch operator count: ${message(err)}`, { cause: err })
    }
    if (nextId <= 1n) return []
    const ids: bigint[] = []
    for (let id = 1n; id < nextId; id++) ids.push(id)
    const slots: (OperatorRecord | undefined)[] = new Array(ids.length)
    await boundedEach(ids, FETCH_BOX_CONCURRENCY, signal, async (id, i, s) => {
        slots[i] = await readOperatorBox(c, id, s)
    })
    return slots.filter((r) => r !== undefined)
}

async function fetchAllOperatorsBulk(c: ChainReadOptions, signal?: AbortSignal): Promise<OperatorRecord[]> {
    const boxes = await listApplicationBoxes(c, operatorBoxPrefix(), signal)
    const out: OperatorRecord[] = []
    for (const b of boxes) {
        const id = operatorIdFromBoxName(b.name)
        if (id === undefined) continue
        out.push(decodeOperatorRecord(id, b.value))
    }
    return out.sort((a, b) => compare(a.id, b.id))
}

/** fetchOperatorsById reads the given operators in the order given; a missing one is an error. */
export async function fetchOperatorsById(c: ChainReadOptions, ids: readonly bigint[], signal?: AbortSignal): Promise<OperatorRecord[]> {
    const slots: OperatorRecord[] = new Array(ids.length)
    await boundedEach(ids, FETCH_BOX_CONCURRENCY, signal, async (id, i, s) => {
        const rec = await readOperatorBox(c, id, s)
        if (rec === undefined) throw new Error(`operator ${id} not found on chain`)
        slots[i] = rec
    })
    return slots
}

/**
 * fetchNodesForOperators reads every live node of the given operators. An
 * evicted operator's nodes are left out, since open() reverts against them.
 * The bulk listing returns them sorted by (operator, node); the box-by-box
 * fallback returns them in the operators' order, then by node, under one
 * limiter so a fleet of many operators never multiplies the reads in flight.
 */
export async function fetchNodesForOperators(
    c: ChainReadOptions,
    ops: readonly OperatorRecord[],
    signal?: AbortSignal,
): Promise<NodeRecord[]> {
    try {
        return await fetchAllNodesBulk(c, ops, signal)
    } catch (err) {
        if (!(err instanceof BoxValuesUnsupportedError)) throw err
    }
    const refs: { opIdx: number; operatorId: bigint; nodeId: bigint }[] = []
    const perOp: (NodeRecord | undefined)[][] = ops.map(() => [])
    ops.forEach((op, opIdx) => {
        if (op.status === OPERATOR_STATUS_EVICTED || op.nextNodeId <= 1n) return
        for (let nodeId = 1n; nodeId < op.nextNodeId; nodeId++) refs.push({ opIdx, operatorId: op.id, nodeId })
    })
    await boundedEach(refs, FETCH_BOX_CONCURRENCY, signal, async (r, _i, s) => {
        const value = await readBox(c, nodeBoxKey(r.operatorId, r.nodeId), `node ${r.operatorId}/${r.nodeId}`, s)
        perOp[r.opIdx]![Number(r.nodeId - 1n)] = value === undefined ? undefined : decodeNodeOrSkip(c, r.operatorId, r.nodeId, value)
    })
    return perOp.flat().filter((r) => r !== undefined)
}

async function fetchAllNodesBulk(c: ChainReadOptions, ops: readonly OperatorRecord[], signal?: AbortSignal): Promise<NodeRecord[]> {
    const eligible = new Set(ops.filter((op) => op.status !== OPERATOR_STATUS_EVICTED).map((op) => op.id))
    const boxes = await listApplicationBoxes(c, nodeBoxPrefix(), signal)
    const out: NodeRecord[] = []
    for (const b of boxes) {
        const ids = nodeIdsFromBoxName(b.name)
        if (ids === undefined || !eligible.has(ids.operatorId)) continue
        const rec = decodeNodeOrSkip(c, ids.operatorId, ids.nodeId, b.value)
        if (rec !== undefined) out.push(rec)
    }
    return out.sort((a, b) => compare(a.operatorId, b.operatorId) || compare(a.nodeId, b.nodeId))
}

function decodeNodeOrSkip(c: ChainReadOptions, operatorId: bigint, nodeId: bigint, value: Uint8Array): NodeRecord | undefined {
    try {
        return decodeNodeRecord(operatorId, nodeId, value)
    } catch (err) {
        if (!(err instanceof NodeBaseUrlEncodingError)) throw err
        ;(c.logger ?? discardLogger).warn('skipping node record whose base URL is not UTF-8', {
            operator_id: String(operatorId),
            node_id: String(nodeId),
        })
        return undefined
    }
}

/**
 * resolveOperatorNode is one node as dispatch routes to it: identity from its
 * operator's box, signing key, base URL, staging flag and track record from
 * its own. Everything a details probe fills is at its empty value, and the
 * node is unreachable until a probe lands. currentDay (Unix seconds / 86400)
 * ends the revenue windows. A signing address that won't decode, a base URL
 * that isn't http(s), or an id a number cannot hold exactly (a RangeError)
 * throws.
 */
export function resolveOperatorNode(op: OperatorRecord, node: NodeRecord, currentDay: bigint): Operator {
    let ticketSigningKey: Uint8Array
    try {
        ticketSigningKey = decodeAlgorandAddress(node.signingAddr)
    } catch (err) {
        throw new Error(`operator ${op.id} node ${node.nodeId}: decode signing addr: ${message(err)}`, { cause: err })
    }
    const baseUrl = node.baseUrl.replace(/\/+$/, '')
    if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
        throw new Error(`operator ${op.id} node ${node.nodeId}: base_url ${JSON.stringify(baseUrl)} must start with http:// or https://`)
    }
    return {
        id: safeId(op.id, 'operator'),
        nodeId: safeId(node.nodeId, 'node'),
        nfdAppId: Number(op.nfdAppId),
        ownerAddr: op.ownerAddr,
        signingAddr: node.signingAddr,
        ticketSigningKey,
        baseUrl,
        models: [],
        modelCapacities: Object.create(null) as Record<string, ModelCapacity>,
        builtinTools: [],
        maxToolIters: 0,
        toolHeadroomPerIteration: 0,
        protoVersion: '',
        reachable: false,
        staging: node.staging !== 0,
        signerSpendableMicroAlgos: undefined,
        ephemeralRecipient: undefined,
        ephemeralExpiry: 0,
        ephemeralIssuedAt: 0,
        tee: undefined,
        minChargeOutputTokens: 0,
        minChargeAlgoTxns: 0,
        minChargeMicroUsdc: 0,
        // The node's own record: the proxy lists nodes, and the operator's is
        // the sum across them.
        metrics: {
            latencyEwmaMs: Number(node.latencyEwmaMs),
            tokensPerSecEwma: Number(node.tokensPerSecEwma),
            lastActivityAt: Number(node.lastActivityAt),
            ticketsOpened: Number(node.ticketsOpened),
            ticketsSettled: Number(node.ticketsSettled),
            ticketsLapsedSettled: Number(node.ticketsLapsedSettled),
            ticketsRefundedInactive: Number(node.ticketsRefundedInactive),
            ticketsProtested: Number(node.ticketsProtested),
            ticketsFrozenDispute: Number(node.ticketsFrozenDispute),
            totalRefundedInactiveUsdc: Number(node.totalRefundedInactiveUsdc),
            totalProtestedUsdc: Number(node.totalProtestedUsdc),
            totalFrozenDisputeUsdc: Number(node.totalFrozenDisputeUsdc),
            latencyTotalMs: Number(node.latencyTotalMs),
            latencySamples: Number(node.latencySamples),
            totalRevenueGross: Number(node.totalRevenueGross),
            revenue24hUsdc: Number(windowedRingRevenue(node.bucketsLastDay, node.revenueBuckets, currentDay, 1n)),
            revenue7dUsdc: Number(windowedRingRevenue(node.bucketsLastDay, node.revenueBuckets, currentDay, 7n)),
            revenue30dUsdc: Number(windowedRingRevenue(node.bucketsLastDay, node.revenueBuckets, currentDay, 30n)),
        },
    }
}

// An id is a routing key, so it may not round the way a display figure may.
function safeId(id: bigint, what: string): number {
    if (id > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError(`${what} id ${id} exceeds Number.MAX_SAFE_INTEGER`)
    return Number(id)
}

/** SIGNER_BALANCE_CONCURRENCY bounds the account reads in flight, for public algod rate limits. */
export const SIGNER_BALANCE_CONCURRENCY = 8

/**
 * SIGNER_BALANCE_TIMEOUT_MS caps a whole balance pass, Go's
 * signerBalanceTimeout, sized there to fit the refresh budget the details
 * probes share. A signer not read in time keeps its last-known value.
 */
export const SIGNER_BALANCE_TIMEOUT_MS = 10_000

export interface ChainOperatorSourceOptions {
    algod: algosdk.Algodv2
    escrowAppId: bigint
    /** Restricts the read to these operators, each of which must exist. Empty reads every one. */
    operatorIds?: readonly bigint[] | undefined
    /** The most one algod request may take; absent, zero or negative is 30 s. */
    requestTimeoutMs?: number | undefined
    logger?: Logger | undefined
    /** Wall clock, Unix ms: the day the revenue windows end on. */
    clock?: Clock | undefined
    /**
     * The most a whole balance pass may take; absent, zero or negative is
     * SIGNER_BALANCE_TIMEOUT_MS. A test seam: Go's is a fixed constant sized
     * to fit inside the refresh timeout, and a host should leave it unset.
     */
    signerBalanceTimeoutMs?: number | undefined
}

/**
 * ChainOperatorSource reads the on-chain operator and node set (Go's
 * ChainOperatorSource.FetchChain). It keeps one thing across reads: each
 * signing account's last successful balance, so a failed read leaves a node
 * judged on what was last seen rather than read as unknown, which would
 * re-admit a node last seen broke.
 *
 * Every signer in the fleet is read on every pass, never just the nodes a
 * request is about to use: a read aimed at one node would announce the choice
 * ahead of it (SPEC § 3f "Signer-funding gate").
 */
export class ChainOperatorSource {
    readonly #algod: algosdk.Algodv2
    readonly #appId: bigint
    readonly #operatorIds: readonly bigint[]
    readonly #timeoutMs: number
    readonly #log: Logger
    readonly #clock: Clock
    readonly #balanceTimeoutMs: number
    readonly #signerSpendable = new Map<string, bigint>()

    constructor(o: ChainOperatorSourceOptions) {
        this.#algod = o.algod
        this.#appId = o.escrowAppId
        this.#operatorIds = o.operatorIds ?? []
        this.#timeoutMs = requestTimeoutOrDefault(o.requestTimeoutMs)
        this.#log = o.logger ?? discardLogger
        this.#clock = o.clock ?? Date.now
        const t = o.signerBalanceTimeoutMs
        this.#balanceTimeoutMs = t !== undefined && Number.isFinite(t) && t > 0 ? t : SIGNER_BALANCE_TIMEOUT_MS
    }

    /**
     * fetchChain returns one Operator per live node, with its signing
     * account's spendable ALGO, unprobed. It fails when algod or the app id is
     * missing, a read fails, or the app has no operators; one node that won't
     * resolve is skipped and logged instead.
     */
    async fetchChain(signal?: AbortSignal): Promise<Operator[]> {
        const ops = await this.#readChainNodes(signal)
        await this.#fillSignerBalances(ops, signal)
        return ops
    }

    async #readChainNodes(signal?: AbortSignal): Promise<Operator[]> {
        // A JavaScript caller can leave out what the type requires.
        if (this.#algod === undefined || this.#algod === null) throw new Error('ChainOperatorSource.algod is not set')
        if (this.#appId === 0n) throw new Error('ChainOperatorSource.escrowAppId is 0')
        const c = this.#chain()
        let records: OperatorRecord[]
        try {
            records =
                this.#operatorIds.length > 0 ? await fetchOperatorsById(c, this.#operatorIds, signal) : await fetchAllOperators(c, signal)
        } catch (err) {
            throw new Error(`fetch operators: ${message(err)}`, { cause: err })
        }
        if (records.length === 0) throw new Error(`no operators found on chain for escrow app ${this.#appId}`)
        return this.#resolveActiveNodes(c, records, signal)
    }

    async #resolveActiveNodes(c: ChainReadOptions, records: OperatorRecord[], signal?: AbortSignal): Promise<Operator[]> {
        // The ring is day-granular, so one day serves the whole batch.
        const currentDay = BigInt(Math.floor(this.#clock() / 1000)) / SECONDS_PER_DAY
        const opById = new Map(records.map((op) => [op.id, op]))
        let nodes: NodeRecord[]
        try {
            nodes = await fetchNodesForOperators(c, records, signal)
        } catch (err) {
            throw new Error(`fetch nodes: ${message(err)}`, { cause: err })
        }
        const out: Operator[] = []
        for (const node of nodes) {
            const op = opById.get(node.operatorId)
            if (op === undefined) continue
            try {
                out.push(resolveOperatorNode(op, node, currentDay))
            } catch (err) {
                // One operator's typo must not blank discovery for the fleet.
                this.#log.warn('skipping unparseable node record', {
                    operator_id: String(node.operatorId),
                    node_id: String(node.nodeId),
                    err: message(err),
                })
            }
        }
        return out
    }

    // Sets signerSpendableMicroAlgos on every op from a fresh read of each
    // distinct signing address, or the last successful reading when this one
    // fails. An address never read successfully stays undefined, which routes.
    // Addresses no longer in ops are forgotten, so a signer that returns is not
    // judged on a reading from before it left.
    async #fillSignerBalances(ops: Operator[], signal?: AbortSignal): Promise<void> {
        const live = new Set<string>()
        for (const op of ops) if (op.signingAddr !== '') live.add(op.signingAddr)
        if (live.size === 0) return
        // Reads queue in this order, so a pass that hits its deadline skips the
        // tail. Chain order would skip the same tail every pass, and a tail
        // signer last read as broke would stay excluded after a top-up.
        const addrs = shuffle([...live])

        const timeout = AbortSignal.timeout(this.#balanceTimeoutMs)
        const pass = signal ? AbortSignal.any([signal, timeout]) : timeout
        const results: ({ spendable: bigint } | { err: unknown })[] = new Array(addrs.length)
        let nextIdx = 0
        const worker = async () => {
            while (nextIdx < addrs.length) {
                const i = nextIdx++
                if (pass.aborted) {
                    results[i] = { err: pass.reason }
                    continue
                }
                try {
                    results[i] = { spendable: await this.#readSpendable(addrs[i]!, pass) }
                } catch (err) {
                    results[i] = { err }
                }
            }
        }
        await Promise.all(Array.from({ length: Math.min(SIGNER_BALANCE_CONCURRENCY, addrs.length) }, worker))

        let failed = 0
        let firstErr: unknown
        addrs.forEach((addr, i) => {
            const r = results[i]!
            if ('err' in r) {
                if (failed++ === 0) firstErr = r.err
                this.#log.debug('signing-account balance read failed; keeping last-known value', {
                    signing_addr: addr,
                    err: message(r.err),
                })
                return
            }
            this.#signerSpendable.set(addr, r.spendable)
        })
        for (const addr of this.#signerSpendable.keys()) if (!live.has(addr)) this.#signerSpendable.delete(addr)
        for (const op of ops) {
            const v = this.#signerSpendable.get(op.signingAddr)
            if (v !== undefined) op.signerSpendableMicroAlgos = Number(v)
        }
        // One line per pass: a rate-limited algod fails a fraction of reads
        // every pass, and those signers route on stale values.
        if (failed > 0) {
            this.#log.warn('signing-account balance reads failed; routing those nodes on last-known values', {
                failed,
                signers: addrs.length,
                err: message(firstErr),
            })
        }
    }

    // exclude=all drops the asset and app lists; algod still computes
    // min-balance from the account totals, so the figure is exact.
    async #readSpendable(addr: string, signal: AbortSignal): Promise<bigint> {
        try {
            const acct = await this.#algod.accountInformation(addr).exclude('all').do(undefined, requestOptions(this.#timeoutMs, signal))
            return spendableOf(BigInt(acct.amount), BigInt(acct.minBalance))
        } catch (err) {
            throw new Error(`account info ${addr}: ${message(err)}`, { cause: err })
        }
    }

    #chain(): ChainReadOptions {
        return { algod: this.#algod, appId: this.#appId, requestTimeoutMs: this.#timeoutMs, logger: this.#log }
    }
}

// Runs fn over items, at most limit at a time. The first failure aborts the
// signal the others were handed and is what this rejects with, as Go's
// errgroup with a limit does.
async function boundedEach<T>(
    items: readonly T[],
    limit: number,
    signal: AbortSignal | undefined,
    fn: (item: T, i: number, signal: AbortSignal) => Promise<void>,
): Promise<void> {
    const group = new AbortController()
    const each = signal ? AbortSignal.any([signal, group.signal]) : group.signal
    let next = 0
    let failure: { err: unknown } | undefined
    const worker = async () => {
        while (failure === undefined && next < items.length) {
            const i = next++
            try {
                await fn(items[i]!, i, each)
            } catch (err) {
                if (failure === undefined) {
                    failure = { err }
                    group.abort(err)
                }
            }
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
    if (failure !== undefined) throw failure.err
}

function shuffle<T>(a: T[]): T[] {
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1))
        ;[a[i], a[j]] = [a[j]!, a[i]!]
    }
    return a
}

function compare(a: bigint, b: bigint): number {
    return a < b ? -1 : a > b ? 1 : 0
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
