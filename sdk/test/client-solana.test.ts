/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Client.create on a Solana network, over a stand-in RPC: the wallet on the
// Config's mint, the reserve client signing as the Solana payer with the
// deployment the genesis hash and program name, and discovery through the
// program. The twin of go/zs solana_assemble_test.go.

import { readFileSync } from 'node:fs'

import * as ed25519 from '@noble/ed25519'
import { base64 } from '@scure/base'
import { decodeBase58, encodeBase58 } from '@txnlab/zs-proto/solana'
import { Deployment, PROGRAM_ID, decodeConfig } from '@txnlab/zs-proto/solana/zsescrow'
import { encodeDeploymentId, solanaDeploymentId } from '@txnlab/zs-proto/ticket'
import { DEPLOYMENT_BINDING_MIN_VERSION } from '@txnlab/zs-proto/wire'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { ReserveCall } from '../src/reserve.js'

const h = vi.hoisted(() => ({ reserveCalls: [] as ReserveCall[], readerOpts: [] as unknown[] }))

// Records what create hands the reader: a Discovery setting dropped there is a silent no-op.
vi.mock('../src/registry/solana.js', async (importOriginal) => {
    const m = await importOriginal<typeof import('../src/registry/solana.js')>()
    class RecordingReader extends m.SolanaChainReader {
        constructor(o: ConstructorParameters<typeof m.SolanaChainReader>[0]) {
            super(o)
            h.readerOpts.push(o)
        }
    }
    return { ...m, SolanaChainReader: RecordingReader }
})

vi.mock('../src/reserve.js', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../src/reserve.js')>()),
    reserve: (call: ReserveCall) => {
        h.reserveCalls.push(call)
        return Promise.reject(new Error('captured'))
    },
}))

const { Client, ZsError, solanaLocalnet } = await import('../src/index.js')
const { SolanaWallet } = await import('../src/solana/wallet.js')
const { solanaSigner } = await import('../src/accounts/solana.js')
const { dispatchDepsOf, partsOf } = await import('../src/client-parts.js')
const { CreditWallet } = await import('../src/solana/credits.js')
const { FakeIssuer } = await import('./credit-issuer.js')
const { testOperator } = await import('./fixtures.js')

const accountVectors = JSON.parse(
    readFileSync(new URL('../../testdata/solana_account_vectors.json', import.meta.url), 'utf8'),
) as {
    accounts: { name: string; data_base64: string }[]
}
const CONFIG = accountVectors.accounts.find((a) => a.name === 'config_initialized')!.data_base64
const MINT = decodeConfig(base64.decode(CONFIG)).usdcMint
const CONFIG_ADDR = new Deployment(PROGRAM_ID, '').config()
const GENESIS = encodeBase58(new Uint8Array(32).fill(9))
const ENDPOINT = 'http://rpc.test'

const seed = new Uint8Array(32).fill(3)
const publicKey = ed25519.getPublicKey(seed)
const PAYER = encodeBase58(publicKey)
const signer = solanaSigner({ seed, publicKey, address: PAYER })

/** Answers the reads create makes, keeping each one's method and params; config null is a program with no Config. */
function stubRpc(config: string | null = CONFIG) {
    const seen: { method: string; params: unknown[] }[] = []
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input) !== ENDPOINT) return new Response('unexpected url', { status: 400 })
        const req = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }
        seen.push({ method: req.method, params: req.params })
        let result: unknown
        if (req.method === 'getGenesisHash') result = GENESIS
        else if (req.method === 'getProgramAccounts') result = []
        else if (req.method === 'getAccountInfo' && req.params[0] === CONFIG_ADDR) {
            const value =
                config === null
                    ? null
                    : { data: [config, 'base64'], executable: false, lamports: 1, owner: PROGRAM_ID, rentEpoch: 0 }
            result = { context: { slot: 1 }, value }
        } else return new Response('unexpected method', { status: 400 })
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }), {
            headers: { 'content-type': 'application/json' },
        })
    })
    return seen
}

const network = { ...solanaLocalnet(), rpcEndpoint: ENDPOINT, program: PROGRAM_ID }

afterEach(() => {
    h.reserveCalls.length = 0
    h.readerOpts.length = 0
    vi.unstubAllGlobals()
})

describe('Client.create on Solana', () => {
    it('builds the wallet, the reserve client and discovery from the network alone', async () => {
        const seen = stubRpc()
        const is = new FakeIssuer()
        const c = await Client.create({
            solanaSigner: signer,
            network,
            disableTee: true,
            discovery: { operatorIds: [4] },
            freeCredits: { issuers: { [is.key]: is } },
        })
        try {
            const parts = partsOf.get(c)!
            // A credit wallet over the deployment read, which dispatch is handed.
            expect(parts.freeCredits).toBeInstanceOf(CreditWallet)
            expect(dispatchDepsOf(c, async () => {}).freeCredits).toBe(parts.freeCredits)
            expect(h.readerOpts).toEqual([expect.objectContaining({ programId: PROGRAM_ID, operatorIds: [4n] })])
            expect(parts.cfg.wallet).toBeInstanceOf(SolanaWallet)
            expect(parts.cfg.wallet!.payerAddr()).toBe(PAYER)
            // The wallet checked the Config's mint against the deployment it
            // was built on, so it took the Config's.
            expect(seen.filter((s) => s.method === 'getAccountInfo').map((s) => s.params[0])).toEqual([
                CONFIG_ADDR,
                CONFIG_ADDR,
            ])
            expect(MINT).not.toBe('')
            // Discovery reads the program, not algod.
            expect(seen.filter((s) => s.method === 'getProgramAccounts').every((s) => s.params[0] === PROGRAM_ID)).toBe(
                true,
            )
            expect(seen.some((s) => s.method === 'getProgramAccounts')).toBe(true)

            const op = testOperator({
                ephemeralRecipient: 'age1live',
                ephemeralExpiry: Math.floor(Date.now() / 1000) + 3600,
                protoVersion: DEPLOYMENT_BINDING_MIN_VERSION,
            })
            await expect(
                parts.reserveClient.reserve(op, { model: 'm', input_count: 1, max_output_count: 1 } as never, null),
            ).rejects.toThrow('captured')
            const call = h.reserveCalls[0]!
            expect(call.request.deployment).toBe(
                encodeDeploymentId(solanaDeploymentId(decodeBase58(GENESIS, 32), decodeBase58(PROGRAM_ID, 32))),
            )
            const msg = new Uint8Array([1, 2, 3])
            expect(await ed25519.verifyAsync(await call.signer!.signBytes(PAYER, msg), msg, publicKey)).toBe(true)
            await expect(call.signer!.signBytes('OTHER', msg)).rejects.toThrow()

            expect(parts.cfg.network).toMatchObject({
                rail: 'solana',
                network: 'localnet',
                rpcEndpoint: ENDPOINT,
                program: PROGRAM_ID,
            })
            expect(parts.cfg.network.key).toBe(`solana-localnet-${PROGRAM_ID}`)
        } finally {
            c.close()
        }
    })

    // As an unreadable escrow app does on Algorand: the wallet cannot check
    // an offer without the mint.
    it('fails without a Config', async () => {
        stubRpc(null)
        await expect(Client.create({ solanaSigner: signer, network, disableTee: true })).rejects.toThrow(
            'has no Config',
        )
    })

    it("refuses an endpoint that is not http(s) as the caller's config", async () => {
        const err = await Client.create({
            solanaSigner: signer,
            network: { ...network, rpcEndpoint: 'ftp://rpc.test' },
            disableTee: true,
        }).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(ZsError)
        expect((err as InstanceType<typeof ZsError>).code).toBe('invalid_config')
    })
})
