/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The doctor on the Solana rail. Mirrors go/zs/solana_doctor.go:
// solanaDoctorChecks is Go's SolanaDoctorChecks, pinned by the solanaCases of
// testdata/doctor_vectors.json; diagnoseSolana and
// gatherSolanaDoctorReadings are Go's diagnoseSolana and
// gatherSolanaDoctorReadings, mirrored but unpinned.

import { type Hash, type PublicKey, TOKEN_PROGRAM_ID, parsePublicKey } from '@txnlab/zs-proto/solana'
import {
    type Config as SolanaConfig,
    Deployment,
    RENT_POOL_SIZE,
    TICKET_SIZE,
    TOKEN_FROZEN,
    type TokenAccount,
    decodeRentPool,
    decodeTokenAccount,
} from '@txnlab/zs-proto/solana/zsescrow'

import { solanaRpc } from '../assemble.js'
import { type Config, type ResolvedConfig, resolveConfig } from '../config.js'
import {
    type DoctorCheck,
    type DoctorNode,
    type DoctorReport,
    type DoctorStatus,
    doctorReport,
    message,
    micros,
    operatorsVerdict,
    readOnlySolanaSigner,
} from '../doctor.js'
import { configError, findError } from '../errors.js'
import type { Operator } from '../operator.js'
import { ChainOperatorSource, NoOperatorsError } from '../registry/chain.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS, SolanaChainReader } from '../registry/solana.js'
import { type RentPoolReading, planRentDeposit, rentPoolGross } from './rent.js'
import type { SolanaRpc } from './rpc.js'
import { readSolanaConfig } from './wallet.js'

/**
 * The readings diagnose gathers on the Solana rail and solanaDoctorChecks
 * judges. A read that failed carries its error text and leaves its values
 * zero.
 */
export interface SolanaDoctorReadings {
    /** The cluster preset, empty for a cluster named only by its endpoint. */
    network: string
    address: string
    slots: bigint
    relayRequired: boolean
    allowStaging: boolean

    rpcErr?: string | undefined
    blockHeight: bigint
    /** The genesis hash of the cluster the RPC serves. */
    genesis: string

    program: string
    configErr?: string | undefined
    /** The genesis hash the program's Config binds every ack digest to. */
    configGenesis: string
    mint: string
    /** The admin's pause, under which every open fails. */
    configPaused: boolean
    /** The cluster's rent-exempt minimums for a ticket and a rent pool account. */
    ticketRent: bigint
    poolRent: bigint

    accountErr?: string | undefined
    lamports: bigint

    /** The payer's associated token account for the Config's mint. */
    usdcErr?: string | undefined
    usdcAccount: boolean
    usdcFrozen: boolean
    usdcBalance: bigint

    poolErr?: string | undefined
    poolExists: boolean
    poolLamports: bigint
    openTickets: bigint

    operatorsErr?: string | undefined
    nodes: DoctorNode[]
}

/**
 * solanaDoctorChecks judges readings, in order: rpc, program, sol,
 * usdc_account, usdc_balance, rent_pool, operators.
 */
export function solanaDoctorChecks(r: SolanaDoctorReadings): DoctorCheck[] {
    const net = r.network || 'this cluster'
    const rpcOK = !r.rpcErr
    const programOK = rpcOK && !r.configErr && r.ticketRent > 0n && r.configGenesis === r.genesis
    const accountOK = rpcOK && !r.accountErr
    const usdcOK = programOK && !r.usdcErr && r.usdcAccount && !r.usdcFrozen
    const out: DoctorCheck[] = []
    const add = (id: string, status: DoctorStatus, message: string) => out.push({ id, status, message })
    const needsRpc = 'needs the RPC'

    if (rpcOK) add('rpc', 'pass', `the Solana RPC for ${net} answers at block height ${r.blockHeight}`)
    else add('rpc', 'fail', `can't reach the Solana RPC for ${net}: ${r.rpcErr}`)

    if (!rpcOK) add('program', 'skip', needsRpc)
    else if (r.configErr) add('program', 'fail', `can't read program ${r.program}'s Config: ${r.configErr}`)
    else if (r.ticketRent === 0n) add('program', 'fail', `the cluster quotes no rent for program ${r.program}'s tickets`)
    // The ack digest binds the Config's genesis hash, so an RPC serving
    // another cluster reads a program nothing here can pay through.
    else if (r.configGenesis !== r.genesis) {
        add('program', 'fail', `program ${r.program}'s Config is for the cluster with genesis ${r.configGenesis}, but the RPC serves genesis ${r.genesis}`)
    }
    // A pause leaves the account readings valid, so it fails only this check
    // and the account checks still run.
    else if (r.configPaused) add('program', 'fail', `program ${r.program} is paused; no ticket can open until its admin unpauses it`)
    else add('program', 'pass', `program ${r.program}: ${lamportsSol(r.ticketRent)} SOL rent per ticket, USDC mint ${r.mint}`)

    const spendable = r.lamports < SOLANA_SIGNER_RESERVE_LAMPORTS ? 0n : r.lamports - SOLANA_SIGNER_RESERVE_LAMPORTS
    if (!rpcOK) add('sol', 'skip', needsRpc)
    else if (r.accountErr) add('sol', 'fail', `can't read ${r.address}: ${r.accountErr}`)
    // Unlike an Algorand account, a Solana payer with no SOL still holds its
    // token account and signs, and the node pays the open's fee, so a pool
    // already at its working set serves; rent_pool judges whether it is.
    else if (r.lamports === 0n) {
        add('sol', 'warn', `${r.address} holds no SOL on ${net}; topping up the ticket rent pool, and the payer's own acks and refunds, pay fees in SOL`)
    }
    else add('sol', 'pass', `${r.address} holds ${lamportsSol(r.lamports)} SOL, ${lamportsSol(spendable)} spendable`)

    if (!programOK) add('usdc_account', 'skip', 'needs the program read')
    else if (r.usdcErr) add('usdc_account', 'fail', `can't read the USDC token account: ${r.usdcErr}`)
    else if (!r.usdcAccount) add('usdc_account', 'fail', `no USDC token account (mint ${r.mint}); create it before paying for requests`)
    else if (r.usdcFrozen) add('usdc_account', 'fail', `the USDC token account (mint ${r.mint}) is frozen; requests can't be paid from it`)
    else add('usdc_account', 'pass', `has a USDC token account (mint ${r.mint})`)

    if (!usdcOK) add('usdc_balance', 'skip', 'needs the USDC token account')
    else if (r.usdcBalance === 0n) add('usdc_balance', 'warn', 'holds no USDC; requests are paid in USDC')
    else add('usdc_balance', 'pass', `holds ${micros(r.usdcBalance)} USDC`)

    if (!accountOK || !programOK) add('rent_pool', 'skip', 'needs the account and program reads')
    else if (r.poolErr) add('rent_pool', 'fail', `can't read the ticket rent pool: ${r.poolErr}`)
    else add('rent_pool', ...rentPoolVerdict(r, spendable))

    if (!rpcOK) add('operators', 'skip', needsRpc)
    else if (r.operatorsErr) add('operators', 'fail', `can't read the operators: ${r.operatorsErr}`)
    else if (r.nodes.length === 0) add('operators', 'fail', `no nodes are registered on ${net}`)
    else add('operators', ...operatorsVerdict(r.nodes, r.relayRequired, r.allowStaging, 'SOL'))
    return out
}

// The prepaid_pool verdict for the rent pool. The pool's own rent is no
// ticket's, so a pool counts what it holds past that, plus the rent its live
// tickets hold, as the wallet's top-up does.
function rentPoolVerdict(r: SolanaDoctorReadings, spendable: bigint): [DoctorStatus, string] {
    const pool: RentPoolReading = { exists: r.poolExists, lamports: r.poolLamports, openTickets: r.openTickets }
    const p = planRentDeposit(r.slots, r.ticketRent, r.poolRent, pool, spendable)
    const gross = rentPoolGross(r.ticketRent, r.poolRent, pool)
    const backed = gross / r.ticketRent
    const has = `${lamportsSol(spendable)} SOL is spendable`
    const held = `${lamportsSol(gross)} SOL deposited, backing ${backed} of ${r.slots} tickets, ${r.openTickets} in use`
    if (!r.poolExists) {
        if (p.unaffordable) return ['fail', `no rent pool yet, and the first request's deposit needs ${lamportsSol(p.need)} SOL; ${has}`]
        return ['warn', `no rent pool yet; the first request deposits ${lamportsSol(p.amount)} SOL`]
    }
    if (p.unaffordable) return ['fail', `the pool backs no ticket and the next deposit needs ${lamportsSol(p.need)} SOL; ${has}`]
    // Every slot held by a live ticket, with nothing the next request would
    // add: its open fails until one settles or is refunded.
    if (p.amount === 0n && backed > 0n && r.openTickets >= backed) {
        return ['warn', `${held}; a new request can't open a ticket until one settles or is refunded`]
    }
    if (p.belowTarget && p.amount === 0n) {
        return ['warn', `the pool backs ${backed} of ${r.slots} tickets, and another deposit needs ${lamportsSol(p.need)} SOL; ${has}`]
    }
    if (p.amount > 0n) return ['pass', `${held}; the next request adds ${lamportsSol(p.amount)} SOL`]
    return ['pass', held]
}

/** lamportsSol renders lamports in whole SOL, with no trailing zeros. */
export function lamportsSol(v: bigint): string {
    const whole = (v / 1_000_000_000n).toString()
    const frac = v % 1_000_000_000n
    return frac === 0n ? whole : `${whole}.${frac.toString().padStart(9, '0').replace(/0+$/, '')}`
}

// Go's doctorReadTimeout, for each read, and bootFetchTimeout, for the
// discovery cycle's chain read and probes.
const DOCTOR_READ_TIMEOUT_MS = 30_000
const DISCOVERY_TIMEOUT_MS = 60_000

/** diagnoseSolana is diagnose on the Solana rail. */
export async function diagnoseSolana(config: Omit<Config, 'signer'>, address: string, signal?: AbortSignal): Promise<DoctorReport> {
    let payer: PublicKey
    try {
        payer = parsePublicKey(address)
    } catch (err) {
        throw configError(`address ${JSON.stringify(address)} is not a Solana address: ${message(err)}`)
    }
    const cfg = resolveConfig({ ...config, signer: undefined, solanaSigner: readOnlySolanaSigner(address) })
    const base = solanaDoctorBase(cfg, address)
    let r: SolanaDoctorReadings
    let rpc: SolanaRpc
    try {
        rpc = solanaRpc(cfg)
    } catch (err) {
        r = { ...base, rpcErr: message(err) }
        return doctorReport(r.network, address, solanaDoctorChecks(r), cfg.warnings)
    }
    r = await gatherSolanaDoctorReadings(rpcDoctorChain(cfg, rpc, payer), base, signal)
    return doctorReport(r.network, address, solanaDoctorChecks(r), cfg.warnings)
}

/** solanaDoctorBase is the readings a resolved config decides before anything is read. */
export function solanaDoctorBase(cfg: ResolvedConfig, address: string): SolanaDoctorReadings {
    return {
        network: cfg.network.network,
        address,
        slots: BigInt(cfg.concurrentSlots),
        relayRequired: cfg.privacy === 'relay_required',
        allowStaging: cfg.allowStaging,
        blockHeight: 0n,
        genesis: '',
        program: cfg.network.program,
        configGenesis: '',
        mint: '',
        configPaused: false,
        ticketRent: 0n,
        poolRent: 0n,
        lamports: 0n,
        usdcAccount: false,
        usdcFrozen: false,
        usdcBalance: 0n,
        poolExists: false,
        poolLamports: 0n,
        openTickets: 0n,
        nodes: [],
    }
}

/** What diagnoseSolana reads, apart from the reading of it so a test can supply the answers. */
export interface SolanaDoctorChain {
    cluster(signal?: AbortSignal): Promise<{ blockHeight: bigint; genesis: Hash }>
    /** The program's Config and the cluster's rent for a ticket and a rent pool. */
    config(signal?: AbortSignal): Promise<{ config: SolanaConfig; ticketRent: bigint; poolRent: bigint }>
    balance(signal?: AbortSignal): Promise<bigint>
    /** The payer's token account for mint, null when there is none. Read only after config succeeded. */
    usdcAccount(mint: PublicKey, signal?: AbortSignal): Promise<TokenAccount | null>
    rentPool(signal?: AbortSignal): Promise<RentPoolReading>
    nodes(signal?: AbortSignal): Promise<Operator[]>
}

/** gatherSolanaDoctorReadings fills r from c. A failed cluster read ends it, since every other read goes through the same RPC. */
export async function gatherSolanaDoctorReadings(c: SolanaDoctorChain, base: SolanaDoctorReadings, signal?: AbortSignal): Promise<SolanaDoctorReadings> {
    const r: SolanaDoctorReadings = { ...base, nodes: [] }
    try {
        const cl = await c.cluster(signal)
        r.blockHeight = cl.blockHeight
        r.genesis = cl.genesis
    } catch (err) {
        r.rpcErr = message(err)
        return r
    }

    // Discovery probes every node, the slow part, so it runs beside the rest.
    const fleet = c.nodes(signal).then(
        (ops) => ({ ops, err: undefined as unknown }),
        (err: unknown) => ({ ops: [] as Operator[], err }),
    )

    let config: SolanaConfig | undefined
    try {
        const got = await c.config(signal)
        config = got.config
        r.configGenesis = config.genesisHash
        r.mint = config.usdcMint
        r.configPaused = config.paused
        r.ticketRent = got.ticketRent
        r.poolRent = got.poolRent
    } catch (err) {
        r.configErr = message(err)
    }
    if (config !== undefined) {
        try {
            const t = await c.usdcAccount(config.usdcMint, signal)
            if (t !== null) {
                r.usdcAccount = true
                r.usdcFrozen = t.state === TOKEN_FROZEN
                r.usdcBalance = t.amount
            }
        } catch (err) {
            r.usdcErr = message(err)
        }
    }
    try {
        r.lamports = await c.balance(signal)
    } catch (err) {
        r.accountErr = message(err)
    }
    try {
        const p = await c.rentPool(signal)
        r.poolExists = p.exists
        r.poolLamports = p.lamports
        r.openTickets = p.openTickets
    } catch (err) {
        r.poolErr = message(err)
    }

    const f = await fleet
    // An empty fleet, which the operators check names as such.
    if (f.err !== undefined && findError(f.err, NoOperatorsError) === undefined) r.operatorsErr = message(f.err)
    r.nodes = f.ops.map((o) => ({
        owner: o.ownerAddr,
        reachable: o.reachable,
        protoVersion: o.protoVersion,
        staging: o.staging,
        signerSpendableLamports: o.signerSpendableLamports === undefined ? undefined : BigInt(o.signerSpendableLamports),
    }))
    return r
}

/** rpcDoctorChain reads the cluster through one RPC client, at the commitment the wallet and the registry read at. */
export function rpcDoctorChain(cfg: ResolvedConfig, rpc: SolanaRpc, payer: PublicKey): SolanaDoctorChain {
    const program = cfg.network.program
    const opts = (signal?: AbortSignal) => ({ commitment: 'confirmed', signal: bound(signal, DOCTOR_READ_TIMEOUT_MS) }) as const
    return {
        async cluster(signal) {
            const s = bound(signal, DOCTOR_READ_TIMEOUT_MS)
            const blockHeight = await rpc.getBlockHeight({ commitment: 'confirmed', signal: s })
            const genesis = await rpc.getGenesisHash({ signal: s })
            return { blockHeight, genesis }
        },
        async config(signal) {
            const s = bound(signal, DOCTOR_READ_TIMEOUT_MS)
            const config = await readSolanaConfig(rpc, new Deployment(program, ''), s)
            let ticketRent, poolRent
            try {
                ticketRent = await rpc.getMinimumBalanceForRentExemption(TICKET_SIZE, { commitment: 'confirmed', signal: s })
            } catch (err) {
                throw new Error(`ticket rent: ${message(err)}`, { cause: err })
            }
            try {
                poolRent = await rpc.getMinimumBalanceForRentExemption(RENT_POOL_SIZE, { commitment: 'confirmed', signal: s })
            } catch (err) {
                throw new Error(`pool rent: ${message(err)}`, { cause: err })
            }
            return { config, ticketRent, poolRent }
        },
        balance: (signal) => rpc.getBalance(payer, opts(signal)),
        async usdcAccount(mint, signal) {
            const key = new Deployment(program, mint).tokenAccount(payer)
            const acct = await rpc.getAccountInfo(key, opts(signal))
            if (acct === null) return null
            if (acct.owner !== TOKEN_PROGRAM_ID) throw new Error(`${key} is not a token account`)
            try {
                return decodeTokenAccount(acct.data)
            } catch (err) {
                throw new Error(`${key}: ${message(err)}`, { cause: err })
            }
        },
        async rentPool(signal) {
            const acct = await rpc.getAccountInfo(new Deployment(program, '').rentPool(payer), opts(signal))
            if (acct === null || acct.owner !== program) return { exists: false, lamports: 0n, openTickets: 0n }
            return { exists: true, lamports: acct.lamports, openTickets: decodeRentPool(acct.data).openTickets }
        },
        async nodes(signal) {
            // The source derives the deployment from the chain before it
            // probes, so the doctor drops a node advertising another one, as
            // a Client does.
            const source = new ChainOperatorSource({
                chain: new SolanaChainReader({
                    rpc,
                    programId: program,
                    operatorIds: cfg.discovery.operatorIds?.map((id) => BigInt(id)),
                    logger: cfg.logger,
                    clock: cfg.clock,
                }),
                fetch: cfg.fetch,
                privacy: cfg.privacy,
                detailsTimeoutMs: cfg.discovery.detailsTimeout,
                detailsConcurrency: cfg.discovery.detailsConcurrency,
                teeVerifier: cfg.teeVerifier,
                latencyStateMax: cfg.discovery.latencyStateMax,
                logger: cfg.logger,
                clock: cfg.clock,
            })
            const s = bound(signal, DISCOVERY_TIMEOUT_MS)
            const ops = await source.fetchChain(s)
            await source.enrichSubset(ops, null, s)
            return ops
        },
    }
}

function bound(signal: AbortSignal | undefined, ms: number): AbortSignal {
    const timeout = AbortSignal.timeout(ms)
    return signal ? AbortSignal.any([signal, timeout]) : timeout
}
