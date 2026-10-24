/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The doctor on the Solana rail: solanaDoctorChecks replaying Go's vectors,
// and diagnose reading a stand-in cluster. The twin of go/zs
// solana_doctor_test.go.

import { readFileSync } from 'node:fs'

import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { TOKEN_PROGRAM_ID, encodeBase58, publicKeyBytes } from '@txnlab/zs-proto/solana'
import {
    Deployment,
    PROGRAM_ID,
    RENT_POOL_SIZE,
    TICKET_SIZE,
    TOKEN_FROZEN,
    TOKEN_INITIALIZED,
    type Config as SolanaConfig,
    type TokenAccount,
    decodeConfig,
} from '@txnlab/zs-proto/solana/zsescrow'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { MIN_SIGNER_SPENDABLE_LAMPORTS } from '@txnlab/zs-proto/selection'

import { solanaRpc } from '../src/assemble.js'
import { readOnlySolanaSigner } from '../src/doctor.js'
import { type DoctorCheck, type Operator, ZsError, diagnose, resolveConfig, solanaDevnet, solanaDoctorChecks, solanaLocalnet } from '../src/index.js'
import { main } from '../src/node/cli.js'
import { NoOperatorsError } from '../src/registry/chain.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS } from '../src/registry/solana.js'
import {
    type SolanaDoctorChain,
    type SolanaDoctorReadings,
    gatherSolanaDoctorReadings,
    lamportsSol,
    rpcDoctorChain,
    solanaDoctorBase,
} from '../src/solana/doctor.js'
import type { RentPoolReading } from '../src/solana/rent.js'

type Raw = Record<string, unknown> & { nodes: Record<string, unknown>[] | null }

const vectors = JSON.parse(readFileSync(new URL('../../testdata/doctor_vectors.json', import.meta.url), 'utf8')) as {
    solanaCases: { name: string; readings: Raw; checks: DoctorCheck[] }[]
}

const BIGINTS = ['slots', 'blockHeight', 'ticketRent', 'poolRent', 'lamports', 'usdcBalance', 'poolLamports', 'openTickets'] as const

function readings(raw: Raw): SolanaDoctorReadings {
    const r = { ...raw } as Record<string, unknown>
    for (const k of BIGINTS) r[k] = BigInt(raw[k] as string)
    r.nodes = (raw.nodes ?? []).map((n) => {
        const { signerSpendableLamports, ...rest } = n
        return signerSpendableLamports === undefined ? rest : { ...rest, signerSpendableLamports: BigInt(signerSpendableLamports as string) }
    })
    return r as unknown as SolanaDoctorReadings
}

describe('solanaDoctorChecks', () => {
    it('has vectors', () => expect(vectors.solanaCases.length).toBeGreaterThan(20))

    it.each(vectors.solanaCases.map((c) => [c.name, c] as const))('%s judges as Go does', (_, c) => {
        expect(solanaDoctorChecks(readings(c.readings))).toEqual(c.checks)
    })
})

// TestLamportsSOL
it.each([
    [0n, '0'],
    [1n, '0.000000001'],
    [1_000_000_000n, '1'],
    [2_282_880n, '0.00228288'],
    [12_500_000_000n, '12.5'],
])('lamportsSol(%s) is %s', (v, want) => expect(lamportsSol(v)).toBe(want))

const BASE: SolanaDoctorReadings = {
    network: '',
    address: '',
    slots: 0n,
    relayRequired: false,
    allowStaging: false,
    blockHeight: 0n,
    genesis: '',
    program: 'P',
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

const key = (n: number) => encodeBase58(new Uint8Array(32).fill(n))

interface FakeChain extends SolanaDoctorChain {
    calls: string[]
    mint?: string
}

function fakeChain(o: {
    clusterErr?: Error
    configErr?: Error
    usdcErr?: Error
    balanceErr?: Error
    poolErr?: Error
    nodesErr?: Error
    usdc?: Partial<TokenAccount> | null
    pool?: RentPoolReading
    ops?: Partial<Operator>[]
}): FakeChain {
    const calls: string[] = []
    const fail = (err: Error | undefined) => {
        if (err) throw err
    }
    const chain: FakeChain = {
        calls,
        async cluster() {
            calls.push('cluster')
            fail(o.clusterErr)
            return { blockHeight: 42n, genesis: key(1) }
        },
        async config() {
            calls.push('config')
            fail(o.configErr)
            return { config: { genesisHash: key(2), usdcMint: key(3), paused: true } as SolanaConfig, ticketRent: 2_000_000n, poolRent: 1_000_000n }
        },
        async balance() {
            calls.push('balance')
            fail(o.balanceErr)
            return 7_000_000n
        },
        async usdcAccount(mint) {
            calls.push('usdc')
            chain.mint = mint
            fail(o.usdcErr)
            return (o.usdc ?? null) as TokenAccount | null
        },
        async rentPool() {
            calls.push('pool')
            fail(o.poolErr)
            return o.pool ?? { exists: false, lamports: 0n, openTickets: 0n }
        },
        async nodes() {
            fail(o.nodesErr)
            return (o.ops ?? []) as Operator[]
        },
    }
    return chain
}

// TestGatherSolanaDoctorReadings_*
describe('gatherSolanaDoctorReadings', () => {
    it('maps each read', async () => {
        const c = fakeChain({
            usdc: { amount: 2_500_000n, state: TOKEN_FROZEN },
            pool: { exists: true, lamports: 9_000_000n, openTickets: 2n },
            ops: [
                // A node carries its own rail's reading; the doctor reads the
                // Solana one.
                { ownerAddr: 'A', reachable: true, protoVersion: '9.13', staging: true, signerSpendableLamports: 20_000, signerSpendableMicroAlgos: 6_000_000 },
                { ownerAddr: 'B', reachable: false, protoVersion: '', staging: false },
            ],
        })
        expect(await gatherSolanaDoctorReadings(c, BASE)).toEqual({
            ...BASE,
            blockHeight: 42n,
            genesis: key(1),
            configGenesis: key(2),
            mint: key(3),
            configPaused: true,
            ticketRent: 2_000_000n,
            poolRent: 1_000_000n,
            lamports: 7_000_000n,
            usdcAccount: true,
            usdcFrozen: true,
            usdcBalance: 2_500_000n,
            poolExists: true,
            poolLamports: 9_000_000n,
            openTickets: 2n,
            nodes: [
                { owner: 'A', reachable: true, protoVersion: '9.13', staging: true, signerSpendableLamports: 20_000n },
                { owner: 'B', reachable: false, protoVersion: '', staging: false, signerSpendableLamports: undefined },
            ],
        })
        expect(c.mint).toBe(key(3))
    })

    it('reads nothing else with the RPC down', async () => {
        const c = fakeChain({ clusterErr: new Error('refused') })
        const r = await gatherSolanaDoctorReadings(c, BASE)
        expect(c.calls).toEqual(['cluster'])
        expect(r).toMatchObject({ rpcErr: 'refused', genesis: '', nodes: [] })
    })

    it('reads no token account without the Config\'s mint', async () => {
        const c = fakeChain({ configErr: new Error('no Config') })
        const r = await gatherSolanaDoctorReadings(c, BASE)
        expect(c.calls).toEqual(['cluster', 'config', 'balance', 'pool'])
        expect(r).toMatchObject({ configErr: 'no Config', mint: '', ticketRent: 0n, lamports: 7_000_000n })
    })

    it('reads no token account as none', async () => {
        const c = fakeChain({})
        const r = await gatherSolanaDoctorReadings(c, BASE)
        expect(c.calls).toEqual(['cluster', 'config', 'usdc', 'balance', 'pool'])
        expect(r.usdcAccount).toBe(false)
        expect(r.usdcErr).toBeUndefined()
    })

    it('keeps nothing from a failed read', async () => {
        const r = await gatherSolanaDoctorReadings(
            fakeChain({
                usdcErr: new Error('HTTP 503'),
                usdc: { amount: 5n, state: TOKEN_INITIALIZED },
                balanceErr: new Error('HTTP 500'),
                poolErr: new Error('HTTP 429'),
                pool: { exists: true, lamports: 5n, openTickets: 0n },
            }),
            BASE,
        )
        expect(r).toMatchObject({
            usdcErr: 'HTTP 503',
            usdcAccount: false,
            usdcBalance: 0n,
            accountErr: 'HTTP 500',
            lamports: 0n,
            poolErr: 'HTTP 429',
            poolExists: false,
            poolLamports: 0n,
        })
    })

    it('reads an empty fleet as no nodes, not as a failed read', async () => {
        const r = await gatherSolanaDoctorReadings(fakeChain({ nodesErr: new NoOperatorsError('zs_escrow program P') }), BASE)
        expect(r.operatorsErr).toBeUndefined()
        expect(r.nodes).toEqual([])
    })

    it('reports a failed fleet read', async () => {
        const r = await gatherSolanaDoctorReadings(fakeChain({ nodesErr: new Error('getProgramAccounts: 503') }), BASE)
        expect(r.operatorsErr).toBe('getProgramAccounts: 503')
    })
})

const accountVectors = JSON.parse(readFileSync(new URL('../../testdata/solana_account_vectors.json', import.meta.url), 'utf8')) as {
    accounts: { name: string; data_base64: string }[]
}
const CONFIG_DATA = accountVectors.accounts.find((a) => a.name === 'config_initialized')!.data_base64
const CONFIG = decodeConfig(base64.decode(CONFIG_DATA))
const ENDPOINT = 'http://rpc.test'
const PAYER = key(7)
const D = new Deployment(PROGRAM_ID, CONFIG.usdcMint)
const ATA = D.tokenAccount(PAYER)
const POOL = D.rentPool(PAYER)
const TICKET_RENT = BigInt((128 + TICKET_SIZE) * 6_960)
const POOL_RENT = BigInt((128 + RENT_POOL_SIZE) * 6_960)
const POOL_LAMPORTS = POOL_RENT + 4n * TICKET_RENT
const LAMPORTS = 50_000_000n
const USDC = 2_500_000n

function tokenAccount(state: number): Uint8Array {
    const b = new Uint8Array(165)
    b.set(publicKeyBytes(CONFIG.usdcMint))
    b.set(publicKeyBytes(PAYER), 32)
    new DataView(b.buffer).setBigUint64(64, USDC, true)
    b[108] = state
    return b
}

function rentPool(open: bigint): Uint8Array {
    const data = new Uint8Array(82)
    data.set(sha256(new TextEncoder().encode('account:RentPool')).slice(0, 8))
    data[8] = 1
    data[9] = 255
    new DataView(data.buffer).setBigUint64(10, open, true)
    data.set(publicKeyBytes(PAYER), 18)
    return data
}

interface StubAccount {
    owner: string
    lamports: bigint
    data: Uint8Array
}

interface RegistryAccount {
    pubkey: string
    owner: string
    lamports: number
    data_base64: string
}

const registry = JSON.parse(readFileSync(new URL('../../testdata/solana_registry_vectors.json', import.meta.url), 'utf8')) as {
    operator_params: [string, { filters: { memcmp: { bytes: string } }[] }]
    node_params: [string, { filters: { memcmp: { bytes: string } }[] }]
    cases: { operators: RegistryAccount[]; nodes: RegistryAccount[]; want: { ownerAddr: string; signingAddr: string; staging: boolean }[] }[]
}

/**
 * Answers diagnose's reads from accounts, by address; one it lacks has no
 * account. The fleet is fleet's, and balances answer getBalance beside the
 * payer's; an address with none gets an RPC error.
 */
function stubCluster(
    genesis: string,
    accounts: Map<string, StubAccount>,
    fleet: { operators: RegistryAccount[]; nodes: RegistryAccount[] } = { operators: [], nodes: [] },
    balances = new Map([[PAYER, LAMPORTS]]),
) {
    const accountList = (list: RegistryAccount[]) =>
        list.map((a) => ({
            pubkey: a.pubkey,
            account: { data: [a.data_base64, 'base64'], executable: false, lamports: a.lamports, owner: a.owner, rentEpoch: 0 },
        }))
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) !== ENDPOINT) return new Response('unexpected url', { status: 400 })
        const req = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }
        let result: unknown
        if (req.method === 'getGenesisHash') result = genesis
        else if (req.method === 'getBlockHeight') result = 1_000
        else if (req.method === 'getMinimumBalanceForRentExemption') result = (128 + (req.params[0] as number)) * 6_960
        else if (req.method === 'getProgramAccounts') {
            const bytes = (req.params[1] as { filters: { memcmp: { bytes: string } }[] }).filters[0]!.memcmp.bytes
            if (bytes === registry.operator_params[1].filters[0]!.memcmp.bytes) result = accountList(fleet.operators)
            else if (bytes === registry.node_params[1].filters[0]!.memcmp.bytes) result = accountList(fleet.nodes)
            else result = []
        } else if (req.method === 'getBalance') {
            const lamports = balances.get(req.params[0] as string)
            if (lamports === undefined) {
                return Response.json({ jsonrpc: '2.0', id: req.id, error: { code: -32602, message: 'unreadable' } })
            }
            result = { context: { slot: 1 }, value: Number(lamports) }
        } else if (req.method === 'getAccountInfo') {
            const a = accounts.get(req.params[0] as string)
            const value = a && { data: [base64.encode(a.data), 'base64'], executable: false, lamports: Number(a.lamports), owner: a.owner, rentEpoch: 0 }
            result = { context: { slot: 1 }, value: value ?? null }
        } else return new Response('unexpected method', { status: 400 })
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }), { headers: { 'content-type': 'application/json' } })
    })
}

afterEach(() => {
    vi.unstubAllGlobals()
})

// TestDiagnose_Solana*
describe('diagnose on Solana', () => {
    const network = { ...solanaLocalnet(), rpcEndpoint: ENDPOINT }

    it('refuses an Algorand address', async () => {
        const err = await diagnose({ network }, 'AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYUCULBOGAZDINRYHI6D4QDTYK3BA').catch((e: unknown) => e)
        expect(err).toBeInstanceOf(ZsError)
        expect((err as ZsError).message).toContain('not a Solana address')
    })

    const defaults = resolveConfig({ network, solanaSigner: { address: PAYER, signBytes: async () => new Uint8Array(), signTransactionMessage: async () => new Uint8Array() } })
    const want: SolanaDoctorReadings = {
        network: 'localnet',
        address: PAYER,
        slots: BigInt(defaults.concurrentSlots),
        relayRequired: defaults.privacy === 'relay_required',
        allowStaging: false,
        blockHeight: 1_000n,
        genesis: CONFIG.genesisHash,
        program: PROGRAM_ID,
        configGenesis: CONFIG.genesisHash,
        mint: CONFIG.usdcMint,
        configPaused: false,
        ticketRent: TICKET_RENT,
        poolRent: POOL_RENT,
        lamports: LAMPORTS,
        usdcAccount: true,
        usdcFrozen: false,
        usdcBalance: USDC,
        poolExists: true,
        poolLamports: POOL_LAMPORTS,
        openTickets: 1n,
        nodes: [],
    }

    it.each<[string, (a: Map<string, StubAccount>) => string | void, Partial<SolanaDoctorReadings>]>([
        ['healthy', () => {}, {}],
        ['a frozen token account', (a) => void a.set(ATA, { owner: TOKEN_PROGRAM_ID, lamports: 1n, data: tokenAccount(TOKEN_FROZEN) }), { usdcFrozen: true }],
        [
            "an account at the token address the token program doesn't own",
            (a) => void a.set(ATA, { owner: PROGRAM_ID, lamports: 1n, data: tokenAccount(TOKEN_INITIALIZED) }),
            { usdcAccount: false, usdcBalance: 0n, usdcErr: `${ATA} is not a token account` },
        ],
        [
            'lamports at the pool address before any deposit',
            (a) => void a.set(POOL, { owner: '11111111111111111111111111111111', lamports: 5_000n, data: new Uint8Array() }),
            { poolExists: false, poolLamports: 0n, openTickets: 0n },
        ],
        [
            'a paused program',
            (a) => {
                const data = base64.decode(CONFIG_DATA)
                data[13] = 1 // Config.paused, after the discriminator and five u8s
                a.set(D.config(), { owner: PROGRAM_ID, lamports: 1n, data })
            },
            { configPaused: true },
        ],
        ['an RPC on another cluster', () => key(9), { genesis: key(9) }],
    ])('reads %s', async (_, edit, readout) => {
        const accounts = new Map<string, StubAccount>([
            [D.config(), { owner: PROGRAM_ID, lamports: 1n, data: base64.decode(CONFIG_DATA) }],
            [ATA, { owner: TOKEN_PROGRAM_ID, lamports: 1n, data: tokenAccount(TOKEN_INITIALIZED) }],
            [POOL, { owner: PROGRAM_ID, lamports: POOL_LAMPORTS, data: rentPool(1n) }],
        ])
        const genesis = edit(accounts) ?? CONFIG.genesisHash
        stubCluster(genesis, accounts)
        // A stray Algorand signer on the config is ignored.
        const signer = { address: 'A', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
        const rep = await diagnose({ network, signer, disableTee: true } as never, PAYER)
        expect(rep.checks).toEqual(solanaDoctorChecks({ ...want, ...readout }))
        // An empty fleet fails it.
        expect(rep).toMatchObject({ network: 'localnet', address: PAYER, failed: true })
    })

    // The command line reaches the same report through --rail solana.
    it('runs from the zerosignal doctor command', async () => {
        stubCluster(
            CONFIG.genesisHash,
            new Map<string, StubAccount>([
                [D.config(), { owner: PROGRAM_ID, lamports: 1n, data: base64.decode(CONFIG_DATA) }],
                [ATA, { owner: TOKEN_PROGRAM_ID, lamports: 1n, data: tokenAccount(TOKEN_INITIALIZED) }],
                [POOL, { owner: PROGRAM_ID, lamports: POOL_LAMPORTS, data: rentPool(1n) }],
            ]),
        )
        let text = ''
        let errText = ''
        const argv = ['doctor', '--rail', 'solana', '--network', 'localnet', '--rpc-url', ENDPOINT, '--address', PAYER, '--json']
        expect(await main(argv, { write: (s: string) => (text += s) }, { write: (s: string) => (errText += s) })).toBe(1)
        expect(JSON.parse(text)).toMatchObject({ network: 'localnet', address: PAYER, checks: solanaDoctorChecks(want) })
        // The endpoint overrides the localnet preset's.
        expect(errText).toContain('zerosignal: warning: Network.rpcEndpoint overrides the localnet preset')
    })

    it('reads an unreadable balance', async () => {
        stubCluster(CONFIG.genesisHash, new Map([[D.config(), { owner: PROGRAM_ID, lamports: 1n, data: base64.decode(CONFIG_DATA) }]]), undefined, new Map())
        const rep = await diagnose({ network, disableTee: true }, PAYER)
        expect(rep.checks.find((c) => c.id === 'sol')).toMatchObject({ status: 'fail', message: expect.stringContaining(`can't read ${PAYER}: `) })
        expect(rep.checks.find((c) => c.id === 'rent_pool')?.status).toBe('skip')
    })

    // TestRPCDoctorChain_ReadsTheFleet: the fleet goes through
    // SolanaChainReader and its lamports balance pass, and the doctor keeps
    // each node's lamports reading. No node answers a probe here.
    it('reads the fleet through the program, with each signer\'s lamports', async () => {
        const c = registry.cases[0]!
        const short = BigInt(MIN_SIGNER_SPENDABLE_LAMPORTS - 1)
        stubCluster(CONFIG.genesisHash, new Map(), c, new Map(c.want.map((w) => [w.signingAddr, SOLANA_SIGNER_RESERVE_LAMPORTS + short])))
        const cfg = resolveConfig({ network: { ...network, program: registry.operator_params[0] }, solanaSigner: readOnlySolanaSigner(PAYER), disableTee: true })
        const r = await gatherSolanaDoctorReadings(rpcDoctorChain(cfg, solanaRpc(cfg), PAYER), solanaDoctorBase(cfg, PAYER))
        expect(r.operatorsErr).toBeUndefined()
        expect(r.nodes).toEqual(c.want.map((w) => ({ owner: w.ownerAddr, reachable: false, protoVersion: '', staging: w.staging, signerSpendableLamports: short })))
    })
})

// TestSolanaDoctorBase
describe('solanaDoctorBase', () => {
    it.each([
        [{}, true, false, 10n],
        [{ privacy: 'relay_required', concurrentSlots: 3 }, true, false, 3n],
        [{ privacy: 'direct', allowStaging: true }, false, true, 10n],
    ] as const)('maps %j', (c, relayRequired, allowStaging, slots) => {
        const cfg = resolveConfig({ ...c, solanaSigner: readOnlySolanaSigner(PAYER), network: solanaDevnet() })
        expect(solanaDoctorBase(cfg, PAYER)).toEqual({
            ...BASE,
            network: 'devnet',
            address: PAYER,
            program: PROGRAM_ID,
            relayRequired,
            allowStaging,
            slots,
        })
    })
})
