/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { type Server, createServer } from 'node:http'
import type { AddressInfo } from 'node:net'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { PROTO_VERSION } from '@txnlab/zs-proto/wire'

import type algosdk from 'algosdk'

import { type DoctorChain, doctorBase, gatherDoctorReadings } from '../src/doctor.js'
import {
    type Config,
    type DoctorCheck,
    type DoctorReadings,
    type DoctorReport,
    type Operator,
    ZsError,
    diagnose,
    doctorChecks,
    resolveConfig,
} from '../src/index.js'
import { main } from '../src/node/cli.js'
import { NoOperatorsError } from '../src/registry/chain.js'

type Raw = Record<string, unknown> & { nodes: (Record<string, unknown> | null)[] | null }

const vectors = JSON.parse(readFileSync(new URL('../../testdata/doctor_vectors.json', import.meta.url), 'utf8')) as {
    protoVersion: string
    cases: { name: string; readings: Raw; checks: DoctorCheck[] }[]
}

const BIGINTS = [
    'slots',
    'lastRound',
    'minFee',
    'escrowAppId',
    'ticketMbr',
    'quotaDue',
    'usdcAssetId',
    'amount',
    'minBalance',
    'usdcBalance',
    'algoBalance',
    'openTickets',
] as const

function readings(raw: Raw): DoctorReadings {
    const r = { ...raw } as Record<string, unknown>
    for (const k of BIGINTS) r[k] = BigInt(raw[k] as string)
    r.nodes = (raw.nodes ?? []).map((n) => {
        const { signerSpendable, ...rest } = n as Record<string, unknown>
        return signerSpendable === undefined ? rest : { ...rest, signerSpendable: BigInt(signerSpendable as string) }
    })
    return r as unknown as DoctorReadings
}

const ADDR = 'AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYUCULBOGAZDINRYHI6D4QDTYK3BA'

describe('doctorChecks', () => {
    // The vectors judge nodes against Go's build; another version would
    // judge their compatibility differently.
    it('judges against this build', () => expect(vectors.protoVersion).toBe(PROTO_VERSION))
    it('has vectors', () => expect(vectors.cases.length).toBeGreaterThan(20))

    it.each(vectors.cases.map((c) => [c.name, c] as const))('%s judges as Go does', (_, c) => {
        expect(doctorChecks(readings(c.readings))).toEqual(c.checks)
    })
})

// TestDoctorBase
describe('doctorBase', () => {
    const signer = { address: 'A', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
    it.each([
        [{}, true, false, 10n],
        [{ privacy: 'relay_required', concurrentSlots: 3 }, true, false, 3n],
        [{ privacy: 'direct', allowStaging: true }, false, true, 10n],
    ] as const)('maps %j', (c, relayRequired, allowStaging, slots) => {
        const cfg = resolveConfig({ ...(c as Partial<Config>), signer, network: { network: 'testnet' } })
        expect(doctorBase(cfg, ADDR)).toMatchObject({
            network: 'testnet',
            address: ADDR,
            escrowAppId: 765860477n,
            relayRequired,
            allowStaging,
            slots,
        })
    })
})

// TestGatherDoctorReadings_*
describe('gatherDoctorReadings', () => {
    const APP = 99n
    const base: DoctorReadings = {
        network: '',
        address: '',
        slots: 0n,
        relayRequired: false,
        allowStaging: false,
        lastRound: 0n,
        minFee: 0n,
        escrowAppId: APP,
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
    const optedIn = {
        amount: 5_000_000n,
        minBalance: 400_000n,
        assets: [
            { assetId: 1n, amount: 9n },
            { assetId: 777n, amount: 2_500_000n },
        ],
        appsLocalState: [{ id: APP + 1n }, { id: APP }],
    } as unknown as algosdk.modelsv2.Account

    function fake(o: { status?: Error; escrow?: Error; account?: algosdk.modelsv2.Account | Error; pool?: Error; nodes?: Operator[] | Error }) {
        const calls: string[] = []
        const fail = <T>(v: T | Error | undefined, ok: T): Promise<T> =>
            v instanceof Error ? Promise.reject(v) : Promise.resolve(v === undefined ? ok : v)
        const chain: DoctorChain = {
            status: () => (calls.push('status'), fail(o.status, { lastRound: 42n, minFee: 1_000n })),
            escrowConfig: () => (calls.push('escrow'), fail(o.escrow, { ticketMbr: 115_000n, usdcAssetId: 777n, quotaDue: 22_500n })),
            account: () => (calls.push('account'), fail(o.account, { amount: 1n } as unknown as algosdk.modelsv2.Account)),
            payerDeposit: () => (calls.push('deposit'), fail(o.pool, { algoBalance: 345_000n, openTickets: 1n })),
            nodes: () => fail(o.nodes, []),
        }
        return { chain, calls }
    }

    it('maps each read', async () => {
        const ops = [
            { ownerAddr: 'A', reachable: true, protoVersion: '9.11', staging: true, signerSpendableMicroAlgos: 6_000_000 },
            { ownerAddr: 'B', reachable: false, protoVersion: '', staging: false },
        ] as Operator[]
        const { chain } = fake({ account: optedIn, nodes: ops })
        expect(await gatherDoctorReadings(chain, base)).toEqual({
            ...base,
            lastRound: 42n,
            minFee: 1_000n,
            ticketMbr: 115_000n,
            usdcAssetId: 777n,
            quotaDue: 22_500n,
            amount: 5_000_000n,
            minBalance: 400_000n,
            usdcOptedIn: true,
            usdcBalance: 2_500_000n,
            poolOptedIn: true,
            algoBalance: 345_000n,
            openTickets: 1n,
            nodes: [
                { owner: 'A', reachable: true, protoVersion: '9.11', staging: true, signerSpendable: 6_000_000n },
                { owner: 'B', reachable: false, protoVersion: '', staging: false, signerSpendable: undefined },
            ],
        })
    })

    it('reads nothing else with algod down', async () => {
        const { chain, calls } = fake({ status: new Error('refused') })
        const r = await gatherDoctorReadings(chain, base)
        expect(calls).toEqual(['status'])
        expect(r.algodErr).toBe('refused')
    })

    it('reads no pool for a payer not opted in', async () => {
        const { chain, calls } = fake({})
        await gatherDoctorReadings(chain, base)
        expect(calls).toEqual(['status', 'escrow', 'account'])
    })

    it('reads no pool without the escrow, and matches no USDC', async () => {
        const { chain, calls } = fake({ escrow: new Error('no app'), account: optedIn })
        const r = await gatherDoctorReadings(chain, base)
        expect(calls).toEqual(['status', 'escrow', 'account'])
        expect(r).toMatchObject({ escrowErr: 'no app', ticketMbr: 0n, usdcAssetId: 0n, usdcOptedIn: false, poolOptedIn: true })
    })

    it('keeps no balance from a failed pool read', async () => {
        const { chain } = fake({ account: optedIn, pool: new Error('simulate') })
        expect(await gatherDoctorReadings(chain, base)).toMatchObject({ poolErr: 'simulate', algoBalance: 0n })
    })

    it('reads an empty fleet as no nodes, not as a failed read', async () => {
        const { chain } = fake({ nodes: new NoOperatorsError(APP) })
        const r = await gatherDoctorReadings(chain, base)
        expect(r.operatorsErr).toBeUndefined()
        expect(r.nodes).toEqual([])
    })

    it('reports a failed fleet read', async () => {
        const { chain } = fake({ nodes: new Error('boxes: 503') })
        expect((await gatherDoctorReadings(chain, base)).operatorsErr).toBe('boxes: 503')
    })
})

// An algod that answers every request 404, so the first read fails.
let server: Server
let algodUrl: string
beforeAll(async () => {
    server = createServer((_, res) => {
        res.statusCode = 404
        res.end('{"message":"not found"}')
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    algodUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
})
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())))

describe('diagnose', () => {
    it('refuses an address it cannot read', async () => {
        const err = await diagnose({ network: { network: 'testnet' } }, 'not-an-address').catch((e: unknown) => e)
        expect(err).toBeInstanceOf(ZsError)
        expect(err).toMatchObject({ code: 'invalid_config' })
    })

    // With algod down every check that needs it is skipped, so the report
    // names the one cause.
    it('skips what needs an algod it cannot reach', async () => {
        const rep = await diagnose({ network: { algodEndpoint: algodUrl, escrowAppId: 1n } }, ADDR)
        expect(rep.failed).toBe(true)
        expect(rep.address).toBe(ADDR)
        expect(rep.checks.map((c) => c.id)).toEqual(['algod', 'escrow', 'algo', 'usdc_opt_in', 'usdc_balance', 'prepaid_pool', 'operators'])
        expect(rep.checks.map((c) => c.status)).toEqual(['fail', 'skip', 'skip', 'skip', 'skip', 'skip', 'skip'])
    })

    it('carries the config warnings', async () => {
        const rep = await diagnose({ network: { network: 'testnet', algodEndpoint: algodUrl } }, ADDR)
        expect(rep.warnings).toHaveLength(1)
        expect(rep.warnings[0]).toContain('escrow app id')
    })
})

describe('zerosignal doctor', () => {
    function sink() {
        let text = ''
        return { write: (s: string) => (text += s), get text() { return text } }
    }

    it('prints its usage on --help', async () => {
        const out = sink()
        expect(await main(['--help'], out, sink())).toBe(0)
        expect(out.text).toContain('usage: zerosignal doctor')
    })

    it.each([
        [[]],
        [['doctor']],
        [['other', '--address', ADDR]],
        [['doctor', '--address', ADDR, '--escrow-app-id', 'x']],
        [['doctor', '--address', ADDR, '--escrow-app-id', '0']],
        [['doctor', '--address', ADDR, '--network', '']],
        [['doctor', '--address', '']],
        [['doctor', '--bogus']],
    ])(
        'refuses %j',
        async (argv) => {
            const err = sink()
            expect(await main(argv, sink(), err)).toBe(2)
            expect(err.text).toContain('zerosignal:')
        },
    )

    it('refuses a config diagnose cannot run on', async () => {
        const err = sink()
        expect(await main(['doctor', '--address', 'nope', '--network', 'testnet'], sink(), err)).toBe(2)
        expect(err.text).toContain('is not an Algorand address')
    })

    it('exits 1 on a failed check, naming it', async () => {
        const out = sink()
        expect(await main(['doctor', '--address', ADDR, '--algod-url', algodUrl, '--escrow-app-id', '1'], out, sink())).toBe(1)
        expect(out.text).toMatch(/FAIL {2}algod/)
        expect(out.text).toContain('a private network')
    })

    // What main hands diagnose, captured rather than run.
    async function configFor(argv: string[]) {
        let got: [Omit<Config, 'signer'>, string] | undefined
        const run = async (config: Omit<Config, 'signer'>, address: string): Promise<DoctorReport> => {
            got = [config, address]
            return { network: '', address, checks: [], failed: false, warnings: [] }
        }
        expect(await main(['doctor', '--address', ADDR, ...argv], sink(), sink(), run)).toBe(0)
        return got!
    }

    it('relays by default and probes directly with --direct', async () => {
        expect((await configFor([]))[0]).toMatchObject({ privacy: 'relay_required', allowStaging: false, allowPrivateHosts: false })
        expect((await configFor(['--direct']))[0].privacy).toBe('direct')
    })

    it('passes each flag to its setting', async () => {
        const [config, address] = await configFor([
            '--network',
            'localnet',
            '--algod-url',
            'http://algod.test',
            '--algod-token',
            'tok',
            '--escrow-app-id',
            '42',
            '--allow-staging',
            '--allow-private-hosts',
        ])
        expect(address).toBe(ADDR)
        expect(config.network).toEqual({ network: 'localnet', algodEndpoint: 'http://algod.test', algodToken: 'tok', escrowAppId: 42n })
        expect(config).toMatchObject({ allowStaging: true, allowPrivateHosts: true })
    })

    it('exits 3 when the doctor itself fails', async () => {
        const err = sink()
        const run = async (): Promise<DoctorReport> => {
            throw new TypeError('boom')
        }
        expect(await main(['doctor', '--address', ADDR], sink(), err, run)).toBe(3)
        expect(err.text).toContain('the doctor failed')
    })

    it('prints the config warnings', async () => {
        const err = sink()
        await main(['doctor', '--address', ADDR, '--network', 'testnet', '--algod-url', algodUrl], sink(), err)
        expect(err.text).toContain('zerosignal: warning:')
    })

    it('prints the report as JSON', async () => {
        const out = sink()
        await main(['doctor', '--address', ADDR, '--algod-url', algodUrl, '--escrow-app-id', '1', '--json'], out, sink())
        const rep = JSON.parse(out.text) as { failed: boolean; checks: DoctorCheck[] }
        expect(rep.failed).toBe(true)
        expect(rep.checks[0]).toMatchObject({ id: 'algod', status: 'fail' })
    })
})
