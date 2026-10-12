/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The doctor: what a payer address needs before a request can succeed, read
// without signing anything. Mirrors go/zs/doctor.go: doctorChecks is Go's
// DoctorChecks, pinned by testdata/doctor_vectors.json; diagnose and
// gatherDoctorReadings are Go's Diagnose and gatherDoctorReadings, mirrored
// but unpinned.

import algosdk from 'algosdk'
import { MIN_SIGNER_SPENDABLE_MICROALGOS } from '@txnlab/zs-proto/selection'
import { protoVersionCompatible } from '@txnlab/zs-proto/wire'

import { chainAlgod } from './assemble.js'
import { type Config, type ResolvedConfig, resolveConfig } from './config.js'
import { configError, findError } from './errors.js'
import { AlgodEscrowChain, requestOptions, requestTimeoutOrDefault, spendableOf } from './escrow/algod.js'
import { type PayerDeposit, planMbrDeposit } from './mbr.js'
import type { Operator } from './operator.js'
import type { Signer } from './ports.js'
import { ChainOperatorSource, NoOperatorsError } from './registry/chain.js'

/** One check's verdict. Only 'fail' means a request from the address can't succeed as things stand. */
export type DoctorStatus = 'pass' | 'warn' | 'fail' | 'skip'

/** One line of a doctor report. */
export interface DoctorCheck {
    id: string
    status: DoctorStatus
    message: string
}

/** What diagnose found for one payer address. */
export interface DoctorReport {
    /** Empty for a chain named only by its endpoint. */
    network: string
    address: string
    checks: DoctorCheck[]
    /** Some check failed. */
    failed: boolean
    /** Config settings that work but are probably mistakes. */
    warnings: string[]
}

/** What the operators check reads off one discovered node. */
export interface DoctorNode {
    /** The operator's owner address: a relay must be another's. */
    owner: string
    reachable: boolean
    protoVersion: string
    staging: boolean
    /** Absent when the signing account was never read, which routes, as in selection. */
    signerSpendable?: bigint | undefined
}

/**
 * The readings diagnose gathers and doctorChecks judges. A read that failed
 * carries its error text and leaves its values zero.
 */
export interface DoctorReadings {
    network: string
    address: string
    /** The working set the prepaid pool is funded for. */
    slots: bigint
    /** The config's, which decide which nodes a request could reach. */
    relayRequired: boolean
    allowStaging: boolean

    algodErr?: string | undefined
    lastRound: bigint
    minFee: bigint

    escrowAppId: bigint
    escrowErr?: string | undefined
    ticketMbr: bigint
    /** The free-quota box MBR the pool still has to cover. */
    quotaDue: bigint
    usdcAssetId: bigint

    accountErr?: string | undefined
    amount: bigint
    minBalance: bigint
    usdcOptedIn: boolean
    usdcBalance: bigint
    poolOptedIn: boolean

    poolErr?: string | undefined
    algoBalance: bigint
    openTickets: bigint

    operatorsErr?: string | undefined
    nodes: DoctorNode[]
}

/**
 * doctorChecks judges readings, in order: algod, escrow, algo, usdc_opt_in,
 * usdc_balance, prepaid_pool, operators.
 */
export function doctorChecks(r: DoctorReadings): DoctorCheck[] {
    const net = r.network || 'this network'
    const algodOK = !r.algodErr
    const escrowOK = algodOK && !r.escrowErr && r.ticketMbr > 0n
    const accountOK = algodOK && !r.accountErr
    const out: DoctorCheck[] = []
    const add = (id: string, status: DoctorStatus, message: string) => out.push({ id, status, message })
    const needsAlgod = 'needs algod'

    if (algodOK) add('algod', 'pass', `algod on ${net} answers at round ${r.lastRound}`)
    else add('algod', 'fail', `can't reach algod on ${net}: ${r.algodErr}`)

    if (!algodOK) add('escrow', 'skip', needsAlgod)
    else if (r.escrowErr) add('escrow', 'fail', `can't read escrow app ${r.escrowAppId}: ${r.escrowErr}`)
    else if (r.ticketMbr === 0n) add('escrow', 'fail', `escrow app ${r.escrowAppId} reports no ticket MBR`)
    else add('escrow', 'pass', `escrow app ${r.escrowAppId}: ${micros(r.ticketMbr)} ALGO per ticket, USDC asset ${r.usdcAssetId}`)

    const spendable = spendableOf(r.amount, r.minBalance)
    if (!algodOK) add('algo', 'skip', needsAlgod)
    else if (r.accountErr) add('algo', 'fail', `can't read ${r.address}: ${r.accountErr}`)
    else if (r.amount === 0n) add('algo', 'fail', `${r.address} holds no ALGO on ${net}; fund it with ALGO for fees and the ticket pool`)
    else add('algo', 'pass', `${r.address} holds ${micros(r.amount)} ALGO, ${micros(spendable)} spendable`)

    const needsAccount = 'needs the account and escrow reads'
    if (!accountOK || !escrowOK) add('usdc_opt_in', 'skip', needsAccount)
    else if (r.usdcOptedIn) add('usdc_opt_in', 'pass', `opted in to USDC (asset ${r.usdcAssetId})`)
    else add('usdc_opt_in', 'fail', `not opted in to USDC (asset ${r.usdcAssetId}); opt in before paying for requests`)

    if (!accountOK || !escrowOK || !r.usdcOptedIn) add('usdc_balance', 'skip', 'needs the USDC opt-in')
    else if (r.usdcBalance === 0n) add('usdc_balance', 'warn', 'holds no USDC; requests are paid in USDC')
    else add('usdc_balance', 'pass', `holds ${micros(r.usdcBalance)} USDC`)

    if (!accountOK || !escrowOK) add('prepaid_pool', 'skip', needsAccount)
    else if (r.poolErr) add('prepaid_pool', 'fail', `can't read the prepaid ticket pool: ${r.poolErr}`)
    else add('prepaid_pool', ...poolVerdict(r, spendable))

    if (!algodOK) add('operators', 'skip', needsAlgod)
    else if (r.operatorsErr) add('operators', 'fail', `can't read the operators: ${r.operatorsErr}`)
    else if (r.nodes.length === 0) add('operators', 'fail', `no nodes are registered on ${net}`)
    else add('operators', ...operatorsVerdict(r))
    return out
}

function poolVerdict(r: DoctorReadings, spendable: bigint): [DoctorStatus, string] {
    const p = planMbrDeposit({
        slots: r.slots,
        ticketMbr: r.ticketMbr,
        quotaDue: r.quotaDue,
        deposit: { algoBalance: r.algoBalance, openTickets: r.openTickets },
        optedIn: r.poolOptedIn,
        spendable,
        minFee: r.minFee,
    })
    const backed = r.algoBalance / r.ticketMbr
    const has = `${micros(spendable)} ALGO is spendable`
    const held = `${micros(r.algoBalance)} ALGO deposited, backing ${backed} of ${r.slots} tickets, ${r.openTickets} in use`
    if (!r.poolOptedIn) {
        if (p.unaffordable) return ['fail', `not opted in, and the first request's deposit needs ${micros(p.need)} ALGO; ${has}`]
        return ['warn', `not opted in; the first request deposits ${micros(p.amount)} ALGO`]
    }
    if (p.unaffordable) return ['fail', `the pool backs no ticket and the next deposit needs ${micros(p.need)} ALGO; ${has}`]
    // Every slot held by a live ticket, with nothing the next request would
    // add: its open reverts until one settles or is refunded, and a frozen
    // ticket never is.
    if (p.amount === 0n && backed > 0n && r.openTickets >= backed) {
        return ['warn', `${held}; a new request can't open a ticket until one settles or is refunded`]
    }
    if (p.belowTarget && p.amount === 0n && backed >= r.slots) {
        return ['warn', `the pool backs all ${r.slots} tickets but not the free-quota box, which needs ${micros(p.need)} ALGO; ${has}`]
    }
    if (p.belowTarget && p.amount === 0n) {
        return ['warn', `the pool backs ${backed} of ${r.slots} tickets, and another deposit needs ${micros(p.need)} ALGO; ${has}`]
    }
    if (p.amount > 0n) return ['pass', `${held}; the next request adds ${micros(p.amount)} ALGO`]
    return ['pass', held]
}

function operatorsVerdict(r: DoctorReadings): [DoctorStatus, string] {
    // A relay must belong to another owner, so a fleet of one owner has none
    // to probe through, and its nodes read as unreachable for that alone.
    const oneOwner = new Set(r.nodes.map((n) => n.owner)).size === 1
    let usable = 0
    let noRelay = 0
    let unreachable = 0
    let incompatible = 0
    let staging = 0
    let unfunded = 0
    for (const n of r.nodes) {
        if (!n.reachable && r.relayRequired && oneOwner) noRelay++
        else if (!n.reachable) unreachable++
        else if (!protoVersionCompatible(n.protoVersion)) incompatible++
        else if (n.staging && !r.allowStaging) staging++
        else if (n.signerSpendable !== undefined && n.signerSpendable < BigInt(MIN_SIGNER_SPENDABLE_MICROALGOS)) unfunded++
        else usable++
    }
    const parts: [number, string][] = [
        [noRelay, 'with no relay of another operator'],
        [unreachable, 'unreachable'],
        [incompatible, 'on an incompatible protocol version'],
        [staging, 'staging'],
        [unfunded, 'with a signing account short of fee ALGO'],
    ]
    const why = parts
        .filter(([n]) => n > 0)
        .map(([n, what]) => `${n} ${what}`)
        .join(', ')
    if (usable === 0) return ['fail', `no node can serve a request: ${why}`]
    const served = `${usable} of ${r.nodes.length} nodes can serve a request`
    return ['pass', why === '' ? served : `${served}; the rest: ${why}`]
}

// micros renders a 6-decimal base-unit amount (µALGO, micro-USDC) in whole
// units, with no trailing zeros.
function micros(v: bigint): string {
    const whole = (v / 1_000_000n).toString()
    const frac = v % 1_000_000n
    return frac === 0n ? whole : `${whole}.${frac.toString().padStart(6, '0').replace(/0+$/, '')}`
}

// Go's bootFetchTimeout: the discovery cycle's chain read and probes.
const DISCOVERY_TIMEOUT_MS = 60_000

/**
 * diagnose reads, without signing anything, what a Client paying from address
 * would need: algod, the escrow app, the account's ALGO and USDC, the prepaid
 * ticket pool, and one discovery cycle over the fleet. config is read as
 * Client.create reads it, without a signer. It throws a ZsError for a config
 * it can't run on; every failed read is a check in the report instead.
 */
export async function diagnose(config: Omit<Config, 'signer'>, address: string, signal?: AbortSignal): Promise<DoctorReport> {
    if (!algosdk.isValidAddress(address)) {
        throw configError(`address ${JSON.stringify(address)} is not an Algorand address`)
    }
    const cfg = resolveConfig({ ...config, signer: readOnlySigner(address) })
    const r = await gatherDoctorReadings(algodDoctorChain(cfg, address), doctorBase(cfg, address), signal)
    const checks = doctorChecks(r)
    return { network: r.network, address, checks, failed: checks.some((c) => c.status === 'fail'), warnings: cfg.warnings }
}

/** doctorBase is the readings a resolved config decides before anything is read. */
export function doctorBase(cfg: ResolvedConfig, address: string): DoctorReadings {
    return {
        network: cfg.network.network,
        address,
        slots: BigInt(cfg.concurrentSlots),
        relayRequired: cfg.privacy === 'relay_required',
        allowStaging: cfg.allowStaging,
        lastRound: 0n,
        minFee: 0n,
        escrowAppId: cfg.network.escrowAppId,
        ticketMbr: 0n,
        quotaDue: 0n,
        usdcAssetId: 0n,
        amount: 0n,
        minBalance: 0n,
        usdcOptedIn: false,
        usdcBalance: 0n,
        poolOptedIn: false,
        algoBalance: 0n,
        openTickets: 0n,
        nodes: [],
    }
}

/** What diagnose reads, apart from the reading of it so a test can supply the answers. */
export interface DoctorChain {
    status(signal?: AbortSignal): Promise<{ lastRound: bigint; minFee: bigint }>
    escrowConfig(signal?: AbortSignal): Promise<{ ticketMbr: bigint; usdcAssetId: bigint; quotaDue: bigint }>
    account(signal?: AbortSignal): Promise<algosdk.modelsv2.Account>
    /** Read only after escrowConfig succeeded. */
    payerDeposit(signal?: AbortSignal): Promise<PayerDeposit>
    nodes(signal?: AbortSignal): Promise<Operator[]>
}

/** gatherDoctorReadings fills r from c. A failed algod read ends it, since every other read needs algod. */
export async function gatherDoctorReadings(c: DoctorChain, base: DoctorReadings, signal?: AbortSignal): Promise<DoctorReadings> {
    const r: DoctorReadings = { ...base, nodes: [] }
    try {
        const st = await c.status(signal)
        r.lastRound = st.lastRound
        r.minFee = st.minFee
    } catch (err) {
        r.algodErr = message(err)
        return r
    }

    // Discovery probes every node, the slow part, so it runs beside the rest.
    const fleet = c.nodes(signal).then(
        (ops) => ({ ops, err: undefined as unknown }),
        (err: unknown) => ({ ops: [] as Operator[], err }),
    )

    try {
        const e = await c.escrowConfig(signal)
        r.ticketMbr = e.ticketMbr
        r.usdcAssetId = e.usdcAssetId
        r.quotaDue = e.quotaDue
    } catch (err) {
        r.escrowErr = message(err)
    }
    try {
        const acct = await c.account(signal)
        r.amount = BigInt(acct.amount)
        r.minBalance = BigInt(acct.minBalance)
        for (const h of acct.assets ?? []) {
            if (r.usdcAssetId !== 0n && BigInt(h.assetId) === r.usdcAssetId) {
                r.usdcOptedIn = true
                r.usdcBalance = BigInt(h.amount)
            }
        }
        r.poolOptedIn = (acct.appsLocalState ?? []).some((ls) => BigInt(ls.id) === r.escrowAppId)
    } catch (err) {
        r.accountErr = message(err)
    }
    // Only an opted-in payer has a pool to read.
    if (r.poolOptedIn && !r.escrowErr) {
        try {
            const dep = await c.payerDeposit(signal)
            r.algoBalance = dep.algoBalance
            r.openTickets = dep.openTickets
        } catch (err) {
            r.poolErr = message(err)
        }
    }

    const f = await fleet
    // An empty fleet, which the operators check names as such.
    if (f.err !== undefined && findError(f.err, NoOperatorsError) === undefined) r.operatorsErr = message(f.err)
    r.nodes = f.ops.map((o) => ({
        owner: o.ownerAddr,
        reachable: o.reachable,
        protoVersion: o.protoVersion,
        staging: o.staging,
        signerSpendable: o.signerSpendableMicroAlgos === undefined ? undefined : BigInt(o.signerSpendableMicroAlgos),
    }))
    return r
}

// Reads algod. AlgodEscrowChain's readonly calls simulate as the application
// account, so they answer for a payer that holds no ALGO yet.
function algodDoctorChain(cfg: ResolvedConfig, address: string): DoctorChain {
    const algod = chainAlgod(cfg)
    const appId = cfg.network.escrowAppId
    const chain = new AlgodEscrowChain({ algod, appId, signer: readOnlySigner(address), logger: cfg.logger })
    const opts = (signal?: AbortSignal) => requestOptions(requestTimeoutOrDefault(undefined), signal)
    return {
        async status(signal) {
            const st = await algod.status().do(undefined, opts(signal))
            const sp = await algod.getTransactionParams().do(undefined, opts(signal))
            return { lastRound: BigInt(st.lastRound), minFee: BigInt(sp.minFee) }
        },
        async escrowConfig(signal) {
            await chain.refreshConfig(signal)
            return {
                ticketMbr: await chain.ticketMbr(),
                usdcAssetId: (await chain.config(signal)).usdcAssetId,
                quotaDue: await chain.freeQuotaMbrDue(address),
            }
        },
        account: (signal) => algod.accountInformation(address).do(undefined, opts(signal)),
        payerDeposit: () => chain.readPayerDeposit(address),
        async nodes(signal) {
            const source = new ChainOperatorSource({
                algod,
                escrowAppId: appId,
                operatorIds: cfg.discovery.operatorIds?.map((id) => BigInt(id)),
                fetch: cfg.fetch,
                privacy: cfg.privacy,
                detailsTimeoutMs: cfg.discovery.detailsTimeout,
                detailsConcurrency: cfg.discovery.detailsConcurrency,
                teeVerifier: cfg.teeVerifier,
                latencyStateMax: cfg.discovery.latencyStateMax,
                logger: cfg.logger,
                clock: cfg.clock,
            })
            const bound = AbortSignal.timeout(DISCOVERY_TIMEOUT_MS)
            const s = signal ? AbortSignal.any([signal, bound]) : bound
            const ops = await source.fetchChain(s)
            await source.enrichSubset(ops, null, s)
            return ops
        },
    }
}

class ReadOnlySignerError extends Error {
    override readonly name = 'ReadOnlySignerError'
    constructor() {
        super('diagnose signs nothing')
    }
}

// Names the address diagnose reads for and signs nothing.
function readOnlySigner(address: string): Signer {
    return {
        address,
        signBytes: async () => {
            throw new ReadOnlySignerError()
        },
        signTransactions: async () => {
            throw new ReadOnlySignerError()
        },
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
