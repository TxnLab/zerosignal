/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A localnet preset whose loopback endpoint answers with a public chain's
// genesis is a tunnel to it: create and diagnose refuse the defaults they
// would have loosened, and a payer that set both settings itself is not
// checked. The twin of go/zs local_test.go.

import { readFileSync } from 'node:fs'

import * as ed25519 from '@noble/ed25519'
import { encodeBase58 } from '@txnlab/zs-proto/solana'
import { Deployment, PROGRAM_ID } from '@txnlab/zs-proto/solana/zsescrow'
import algosdk from 'algosdk'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { type Config, Client, ZsError, diagnose, localnet, solanaLocalnet } from '../src/index.js'

const accountVectors = JSON.parse(
    readFileSync(new URL('../../testdata/solana_account_vectors.json', import.meta.url), 'utf8'),
) as { accounts: { name: string; data_base64: string }[] }
const CONFIG = accountVectors.accounts.find((a) => a.name === 'config_initialized')!.data_base64
const CONFIG_ADDR = new Deployment(PROGRAM_ID, '').config()

const DEVNET = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'
const LOCAL = encodeBase58(new Uint8Array(32).fill(9))
const RPC = 'http://127.0.0.1:8899'
const ALGOD = 'http://127.0.0.1:4001'
const TESTNET = 'SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI='

const seed = new Uint8Array(32).fill(3)
const publicKey = ed25519.getPublicKey(seed)
const PAYER = encodeBase58(publicKey)
const signer = solanaSigner({ seed, publicKey, address: PAYER })

/** A cluster at RPC serving genesis, the program's Config and no operators; anything else fails its read. */
function stubCluster(genesis: string) {
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        if (!String(input).startsWith(RPC)) return new Response('unexpected url', { status: 400 })
        const req = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }
        let result: unknown
        if (req.method === 'getGenesisHash') result = genesis
        else if (req.method === 'getProgramAccounts') result = []
        else if (req.method === 'getAccountInfo' && req.params[0] === CONFIG_ADDR) {
            result = { context: { slot: 1 }, value: { data: [CONFIG, 'base64'], executable: false, lamports: 1, owner: PROGRAM_ID, rentEpoch: 0 } }
        } else return new Response('unexpected method', { status: 400 })
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }), { headers: { 'content-type': 'application/json' } })
    })
}

/** An algod at ALGOD whose params carry testnet's genesis; nothing else answers. */
function stubTestnetAlgod() {
    vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
        if (!String(input).startsWith(`${ALGOD}/v2/transactions/params`)) return new Response('not found', { status: 404 })
        return new Response(
            JSON.stringify({ 'consensus-version': 'v1', 'genesis-hash': TESTNET, 'genesis-id': 'testnet-v1.0', 'last-round': 1, 'min-fee': 1000 }),
            { headers: { 'content-type': 'application/json' } },
        )
    })
}

async function refusal(p: Promise<unknown>): Promise<string | undefined> {
    try {
        const c = await p
        if (c instanceof Client) await c.close()
        return undefined
    } catch (e) {
        return e instanceof ZsError && e.code === 'invalid_config' ? e.message : `other: ${String(e)}`
    }
}

afterEach(() => vi.unstubAllGlobals())

describe('the local defaults on a public chain', () => {
    const network = { ...solanaLocalnet(), rpcEndpoint: RPC }
    it.each<[string, string, Partial<Config>, boolean]>([
        ['devnet genesis, defaults', DEVNET, {}, true],
        ['devnet genesis, only privacy set', DEVNET, { privacy: 'relay_required' }, true],
        ['devnet genesis, only private hosts set', DEVNET, { allowPrivateHosts: false }, true],
        ['devnet genesis, both set', DEVNET, { privacy: 'direct', allowPrivateHosts: true }, false],
        ['a local genesis, defaults', LOCAL, {}, false],
    ])('%s', async (_name, genesis, set, refused) => {
        stubCluster(genesis)
        const config = { network, disableTee: true, ...set }
        const created = await refusal(Client.create({ ...config, solanaSigner: signer }))
        const diagnosed = await refusal(diagnose(config, PAYER))
        for (const got of [created, diagnosed]) {
            if (refused) expect(got).toMatch(/serves devnet/)
            else expect(got).toBeUndefined()
        }
    })

    it('reads the Algorand genesis from algod', async () => {
        stubTestnetAlgod()
        const net = { ...localnet(), algodEndpoint: ALGOD, escrowAppId: 1006n }
        const algoSigner = { address: algosdk.generateAccount().addr.toString(), signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
        expect(await refusal(Client.create({ network: net, signer: algoSigner, disableTee: true }))).toMatch(/serves testnet/)
        expect(await refusal(diagnose({ network: net, disableTee: true }, algoSigner.address))).toMatch(/serves testnet/)
    })
})
