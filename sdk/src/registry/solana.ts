/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain half of discovery on Solana: the zs_escrow program's Operator and
// Node accounts, read into the Operators the Algorand box walk builds, field
// for field, so the probes, selection and the routers treat a node alike on
// either rail. Mirrors go/zs's SolanaChainReader (solana_registry.go), pinned
// by testdata/solana_registry_vectors.json; see Go's type comment for where
// the rails' records differ and which side each choice follows.
//
// Differences from Go:
//   - A node whose operator or node id is past Number.MAX_SAFE_INTEGER is
//     skipped like any other node that won't resolve, and the metrics narrow
//     with Number(), as chain.ts's resolveOperatorNode does.
//   - The genesis read is bounded by the caller's signal and Go's 10 s
//     escrowConfigTimeout together; the account reads by the caller's signal
//     alone, as Go's are by the refresh context.
//   - The reader takes its own clock for the revenue windows, as Go's takes
//     its own; a host passing one to ChainOperatorSource passes it here too.
//   - The program id is base58 text, checked to be a key at construction.
//   - A spendable reading narrows to a number on Operator, as
//     signerSpendableMicroAlgos does, which rounds past 2^53 lamports
//     (about nine million SOL), far above the floor it is compared with.

import { SECONDS_PER_DAY, windowedRingRevenue } from '@txnlab/zs-proto/escrow'
import { type PublicKey, decodeBase58, publicKeyBytes } from '@txnlab/zs-proto/solana'
import {
    type Node as SolanaNode,
    type Operator as SolanaOperator,
    OPERATOR_STATUS_EVICTED,
    PROGRAM_ID,
    decodeNode,
    decodeOperator,
    discriminator,
} from '@txnlab/zs-proto/solana/zsescrow'
import { solanaDeploymentId } from '@txnlab/zs-proto/ticket'

import type { ModelCapacity, Operator } from '../operator.js'
import { type Clock, type Logger, discardLogger } from '../ports.js'
import type { Commitment, Filter, KeyedAccount, SolanaRpc } from '../solana/rpc.js'
import { type ChainReader, NoOperatorsError, safeId } from './chain.js'

/** Go's escrowConfigTimeout, which bounds its genesis read. */
const GENESIS_READ_TIMEOUT_MS = 10_000

// Confirmed rather than the RPC's default, finalized, so a key rotation or an
// eviction reaches routing in about a second instead of finalization's dozen
// or so. A confirmed block that never finalizes costs one refresh routed on a
// registry the next read corrects.
const REGISTRY_COMMITMENT: Commitment = 'confirmed'

/**
 * An upper bound on the rent-exempt minimum of a signer's own, empty account,
 * which a spendable reading leaves out of its balance: Go's
 * solanaSignerReserveLamports, where the reason is.
 */
export const SOLANA_SIGNER_RESERVE_LAMPORTS = 890_880n

export interface SolanaChainReaderOptions {
    rpc: SolanaRpc
    /** The zs_escrow program id; absent is PROGRAM_ID, the localnet build's, so a reader on any other cluster names its preset's. */
    programId?: PublicKey | undefined
    /** Restricts the read to these operators, each of which must exist. Empty reads every one. */
    operatorIds?: readonly bigint[] | undefined
    /** Receives the accounts the read skips. */
    logger?: Logger | undefined
    /** Wall clock, Unix ms: the day the revenue windows end on. */
    clock?: Clock | undefined
}

/** SolanaChainReader is Go's SolanaChainReader: a ChainReader over the zs_escrow program. */
export class SolanaChainReader implements ChainReader {
    readonly #rpc: SolanaRpc
    readonly #program: PublicKey
    readonly #operatorIds: readonly bigint[]
    readonly #log: Logger
    readonly #clock: Clock

    constructor(o: SolanaChainReaderOptions) {
        this.#rpc = o.rpc
        this.#program = o.programId ?? PROGRAM_ID
        // Go's is a typed key. A mistyped one here would fail every owner
        // check and read as an empty fleet rather than a bad config.
        publicKeyBytes(this.#program)
        this.#operatorIds = o.operatorIds ?? []
        this.#log = o.logger ?? discardLogger
        this.#clock = o.clock ?? Date.now
    }

    /** readDeployment derives the deployment id from the cluster's genesis hash and the program id. */
    async readDeployment(signal?: AbortSignal): Promise<Uint8Array> {
        const rpc = this.#requireRpc()
        const timeout = AbortSignal.timeout(GENESIS_READ_TIMEOUT_MS)
        let genesis: string
        try {
            genesis = await rpc.getGenesisHash({ signal: signal ? AbortSignal.any([signal, timeout]) : timeout })
        } catch (err) {
            throw new Error(`zs: read genesis hash: ${message(err)}`, { cause: err })
        }
        return solanaDeploymentId(decodeBase58(genesis, 32), publicKeyBytes(this.#program))
    }

    /**
     * readChain reads the operators, then their nodes. A second call for the
     * nodes rather than one for every program account keeps tickets, which
     * outnumber nodes by far, off the wire.
     */
    async readChain(signal?: AbortSignal): Promise<Operator[]> {
        const rpc = this.#requireRpc()
        let ops: Map<bigint, SolanaOperator>
        try {
            const accts = await rpc.getProgramAccounts(this.#program, { commitment: REGISTRY_COMMITMENT, filters: [accountFilter('Operator')], signal })
            ops = solanaOperators(this.#program, accts, this.#operatorIds, this.#log)
        } catch (err) {
            throw new Error(`fetch operators: ${message(err)}`, { cause: err })
        }
        if (ops.size === 0) throw new NoOperatorsError(`zs_escrow program ${this.#program}`)
        const currentDay = BigInt(Math.floor(this.#clock() / 1000)) / SECONDS_PER_DAY
        try {
            const nodes = await rpc.getProgramAccounts(this.#program, { commitment: REGISTRY_COMMITMENT, filters: [accountFilter('Node')], signal })
            return solanaNodes(this.#program, ops, nodes, currentDay, this.#log)
        } catch (err) {
            throw new Error(`fetch nodes: ${message(err)}`, { cause: err })
        }
    }

    /**
     * readSignerSpendableLamports reads addr's balance at the registry's
     * commitment and returns what lies above the account's own reserve, as
     * Go's ReadSignerSpendableLamports.
     */
    async readSignerSpendableLamports(addr: string, signal: AbortSignal): Promise<bigint> {
        const rpc = this.#requireRpc()
        try {
            publicKeyBytes(addr)
        } catch (err) {
            throw new Error(`signing address ${JSON.stringify(addr)}: ${message(err)}`, { cause: err })
        }
        let lamports: bigint
        try {
            lamports = await rpc.getBalance(addr, { commitment: REGISTRY_COMMITMENT, signal })
        } catch (err) {
            throw new Error(`balance ${addr}: ${message(err)}`, { cause: err })
        }
        return lamports < SOLANA_SIGNER_RESERVE_LAMPORTS ? 0n : lamports - SOLANA_SIGNER_RESERVE_LAMPORTS
    }

    // A JavaScript caller can leave out what the type requires.
    #requireRpc(): SolanaRpc {
        if (this.#rpc === undefined || this.#rpc === null) throw new Error('SolanaChainReader.rpc is not set')
        return this.#rpc
    }
}

// Selects one account type by its discriminator alone. A dataSize filter
// would hide an account a later program grew, where the decoder refuses it
// with a warning naming it.
function accountFilter(name: string): Filter {
    return { memcmp: { offset: 0, bytes: discriminator('account', name) } }
}

// The operator accounts by id, restricted to ids when it is non-empty, every
// one of which must be there. An account that won't decode fails the read, as
// a malformed box fails the Algorand one; see Go's solanaOperators for why.
function solanaOperators(
    program: PublicKey,
    accts: readonly KeyedAccount[],
    ids: readonly bigint[],
    log: Logger,
): Map<bigint, SolanaOperator> {
    const byId = new Map<bigint, SolanaOperator>()
    for (const a of accts) {
        if (!programOwns(program, a, log)) continue
        const op = decodeAccount(a, 'operator', decodeOperator)
        byId.set(op.id, op)
    }
    if (ids.length === 0) return byId
    const kept = new Map<bigint, SolanaOperator>()
    for (const id of ids) {
        const op = byId.get(id)
        if (op === undefined) throw new Error(`operator ${id} not found on chain`)
        kept.set(id, op)
    }
    return kept
}

// The nodes of ops, sorted by (operator id, node id) as the Algorand box
// listing returns them. A node whose operator is not in ops (unrequested, or
// with no operator account) is left out silently, as the Algorand read leaves
// out an unrequested operator's. A node account that won't decode fails the
// read, for solanaOperators' reason.
function solanaNodes(
    program: PublicKey,
    ops: ReadonlyMap<bigint, SolanaOperator>,
    accts: readonly KeyedAccount[],
    currentDay: bigint,
    log: Logger,
): Operator[] {
    const out: Operator[] = []
    for (const a of accts) {
        if (!programOwns(program, a, log)) continue
        const node: SolanaNode = decodeAccount(a, 'node', decodeNode)
        const op = ops.get(node.operatorId)
        if (op === undefined || op.status === OPERATOR_STATUS_EVICTED) continue
        try {
            out.push(resolveSolanaNode(op, node, currentDay))
        } catch (err) {
            log.warn('skipping unparseable node record', {
                operator_id: String(node.operatorId),
                node_id: String(node.nodeId),
                err: message(err),
            })
        }
    }
    return out.sort((a, b) => a.id - b.id || a.nodeId - b.nodeId)
}

// What the decoders leave to their caller. getProgramAccounts answers only
// with the program's accounts, so a miss is an RPC answering wrongly, and its
// data is not the program's to trust.
function programOwns(program: PublicKey, a: KeyedAccount, log: Logger): boolean {
    if (a.account.owner === program) return true
    log.warn('skipping registry account the program does not own', { account: a.key, owner: a.account.owner })
    return false
}

function decodeAccount<T>(a: KeyedAccount, what: string, decode: (data: Uint8Array) => T): T {
    try {
        return decode(a.account.data)
    } catch (err) {
        throw new Error(`decode ${what} account ${a.key}: ${message(err)}`, { cause: err })
    }
}

/**
 * resolveSolanaNode is resolveOperatorNode for a Solana node: identity from
 * its operator's account, signing key, base URL, staging flag and track record
 * from its own, with the same base-URL rules. currentDay (Unix seconds /
 * 86400) ends the revenue windows. A base URL that isn't http(s), or an id a
 * number cannot hold exactly (a RangeError), throws.
 */
export function resolveSolanaNode(op: SolanaOperator, node: SolanaNode, currentDay: bigint): Operator {
    // The Algorand decoder trims the zero padding of its fixed-width field;
    // trimming here too reads the same stored string as the same URL.
    const baseUrl = node.baseUrl.replace(/\0+$/, '').replace(/\/+$/, '')
    if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
        throw new Error(`operator ${op.id} node ${node.nodeId}: base_url ${JSON.stringify(baseUrl)} must start with http:// or https://`)
    }
    // The windowed reads are the Algorand ring's: the program writes its ring
    // by the same day-index rule, and 0 is the same never-written sentinel.
    const ringDay = nonNegative(node.ringDay)
    return {
        id: safeId(node.operatorId, 'operator'),
        nodeId: safeId(node.nodeId, 'node'),
        nfdAppId: 0,
        ownerAddr: op.owner,
        signingAddr: node.signing,
        ticketSigningKey: publicKeyBytes(node.signing),
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
        signerSpendableLamports: undefined,
        ephemeralRecipient: undefined,
        ephemeralExpiry: 0,
        ephemeralIssuedAt: 0,
        tee: undefined,
        minChargeOutputTokens: 0,
        minChargeAlgoTxns: 0,
        minChargeMicroUsdc: 0,
        metrics: {
            latencyEwmaMs: Number(node.ttftEwmaMs),
            tokensPerSecEwma: Number(node.decodeTpsEwma),
            lastActivityAt: Number(nonNegative(node.lastActivityAt)),
            ticketsOpened: Number(node.opensTotal),
            ticketsSettled: Number(node.settledCount),
            ticketsLapsedSettled: Number(node.lapsedCount),
            ticketsRefundedInactive: Number(node.refundedCount),
            ticketsProtested: Number(node.protestedCount),
            ticketsFrozenDispute: Number(node.frozenDisputeCount),
            totalRefundedInactiveUsdc: Number(node.refundedTotal),
            totalProtestedUsdc: Number(node.protestedTotal),
            totalFrozenDisputeUsdc: Number(node.frozenDisputeTotal),
            latencyTotalMs: Number(node.latencyTotalMs),
            latencySamples: Number(node.latencySamples),
            totalRevenueGross: Number(node.revenueTotal),
            revenue24hUsdc: Number(windowedRingRevenue(ringDay, node.ringRevenue, currentDay, 1n)),
            revenue7dUsdc: Number(windowedRingRevenue(ringDay, node.ringRevenue, currentDay, 7n)),
            revenue30dUsdc: Number(windowedRingRevenue(ringDay, node.ringRevenue, currentDay, 30n)),
        },
    }
}

// One of the program's i64 times as the Algorand record's u64. The program
// writes only clock times there, so a negative one is a corrupt account, and
// reads as never.
function nonNegative(v: bigint): bigint {
    return v < 0n ? 0n : v
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
