/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The chain half of discovery on Solana against a fake RPC behind an injected
// fetch: testdata/solana_registry_vectors.json, which go/zs's
// TestSolanaRegistryVectors generates, with its signer_balance block through
// ChainOperatorSource's balance pass, then ChainOperatorSource over a
// ChainReader, ported from go/zs's solana_registry_test.go.

import { readFileSync } from 'node:fs'

import { MIN_SIGNER_SPENDABLE_LAMPORTS, signerUnderfunded } from '@txnlab/zs-proto/selection'
import { decodeNode, decodeOperator, OPERATOR_STATUS_EVICTED } from '@txnlab/zs-proto/solana/zsescrow'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { ChainOperatorSource, type ChainReader, type LogAttrs, type Logger, type Operator, SolanaChainReader } from '../src/index.js'
import { selectionOf } from '../src/operator.js'
import { NoOperatorsError } from '../src/registry/index.js'
import { advertisable } from '../src/registry/registry.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS } from '../src/registry/solana.js'
import { SolanaRpcClient } from '../src/solana/rpc.js'

interface VectorAccount {
    pubkey: string
    owner: string
    lamports: number
    data_base64: string
}

interface VectorCase {
    name: string
    current_day: number
    operator_ids?: number[]
    operators: VectorAccount[]
    nodes: VectorAccount[]
    want: Record<string, unknown>[]
    skipped: { account: string; reason: string }[]
    error: string
}

interface SignerPass {
    balances: { signing_addr: string; lamports: number | null }[]
    sent: unknown[][]
    want: { operator_id: number; node_id: number; signing_addr: string; signer_spendable_lamports: number | null; underfunded: boolean }[]
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/solana_registry_vectors.json', import.meta.url), 'utf8')) as {
    program_id: string
    genesis_hash: string
    deployment_hex: string
    operator_params: unknown
    node_params: unknown
    cases: VectorCase[]
    signer_balance: {
        min_signer_spendable_lamports: number
        signer_reserve_lamports: number
        operators: VectorAccount[]
        cases: { name: string; nodes: VectorAccount[]; passes: SignerPass[] }[]
    }
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const bytesOf = (s: string) => new Uint8Array(Buffer.from(s, 'base64'))

// The fake tells the two reads apart by the discriminator each filters on;
// that the reader sends these params is checked per case.
const OPERATOR_DISC = memcmpBytes(vectors.operator_params)
const NODE_DISC = memcmpBytes(vectors.node_params)

function memcmpBytes(params: unknown): string {
    return ((params as unknown[])[1] as { filters: { memcmp: { bytes: string } }[] }).filters[0]!.memcmp.bytes
}

/**
 * An RPC answering getGenesisHash and the two registry reads, keeping the
 * params each sent. getBalance answers from balances, with an RPC error
 * neither client retries for an address it has no lamports for.
 */
function fakeRpc(operators: VectorAccount[], nodes: VectorAccount[], balances = new Map<string, number | null>()) {
    const seen: { method: string; params: unknown }[] = []
    const fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        const req = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }
        seen.push({ method: req.method, params: req.params })
        if (init?.signal?.aborted) throw init.signal.reason
        let result: unknown
        if (req.method === 'getGenesisHash') result = vectors.genesis_hash
        else if (req.method === 'getBalance') {
            const lamports = balances.get(String(req.params[0])) ?? null
            if (lamports === null) {
                const error = { code: -32602, message: 'unreadable' }
                return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, error }), { headers: { 'content-type': 'application/json' } })
            }
            result = { context: { slot: 1 }, value: lamports }
        } else if (req.method === 'getProgramAccounts') {
            const disc = memcmpBytes(req.params)
            const accts = disc === OPERATOR_DISC ? operators : disc === NODE_DISC ? nodes : []
            result = accts.map((a) => ({
                pubkey: a.pubkey,
                account: { data: [a.data_base64, 'base64'], executable: false, lamports: a.lamports, owner: a.owner, rentEpoch: 0 },
            }))
        } else return new Response('unexpected method', { status: 400 })
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: req.id, result }), { headers: { 'content-type': 'application/json' } })
    }) as typeof globalThis.fetch
    return { rpc: new SolanaRpcClient({ endpoint: 'http://rpc.test', fetch, maxRetries: 0 }), seen }
}

function recordingLogger() {
    const lines: { msg: string; attrs: LogAttrs | undefined }[] = []
    const at = (msg: string, attrs?: LogAttrs): void => {
        lines.push({ msg, attrs })
    }
    const logger: Logger = { debug: () => {}, info: () => {}, warn: at, error: at }
    return { logger, lines }
}

function chainFields(o: Operator) {
    return {
        id: o.id,
        nodeId: o.nodeId,
        nfdAppId: o.nfdAppId,
        ownerAddr: o.ownerAddr,
        signingAddr: o.signingAddr,
        ticketSigningKeyHex: hex(o.ticketSigningKey),
        baseUrl: o.baseUrl,
        staging: o.staging,
        metrics: o.metrics,
    }
}

// Why each account the read left out was left out: from its log line where it
// logs one, else from the account's operator, as Go's generator decides.
function skipsOf(c: VectorCase, ops: Operator[], lines: { msg: string; attrs: LogAttrs | undefined }[]) {
    const skipped: { account: string; reason: string }[] = []
    const baseUrl = new Set<string>()
    for (const l of lines) {
        const a = l.attrs ?? {}
        if (l.msg === 'skipping registry account the program does not own') skipped.push({ account: String(a.account), reason: 'foreign_owner' })
        else if (l.msg === 'skipping unparseable node record') {
            expect(String(a.err)).toContain('base_url')
            baseUrl.add(`${String(a.operator_id)}/${String(a.node_id)}`)
        } else throw new Error(`unexpected log line ${l.msg}`)
    }
    const gone = new Set(skipped.map((s) => s.account))
    const operators = new Map<bigint, number>()
    for (const a of c.operators) {
        if (gone.has(a.pubkey)) continue
        const o = decodeOperator(bytesOf(a.data_base64))
        operators.set(o.id, o.status)
    }
    const built = new Set(ops.map((o) => `${o.id}/${o.nodeId}`))
    for (const a of c.nodes) {
        if (gone.has(a.pubkey)) continue
        const n = decodeNode(bytesOf(a.data_base64))
        const id = `${n.operatorId}/${n.nodeId}`
        if (built.has(id)) continue
        const status = operators.get(n.operatorId)
        let reason: string
        if (baseUrl.has(id)) reason = 'base_url'
        else if (status === undefined) reason = 'no_operator'
        else if (c.operator_ids !== undefined && !c.operator_ids.includes(Number(n.operatorId))) reason = 'unrequested'
        else if (status === OPERATOR_STATUS_EVICTED) reason = 'evicted'
        else throw new Error(`node ${a.pubkey} left out for no reason the vectors name`)
        skipped.push({ account: a.pubkey, reason })
    }
    return skipped.sort((a, b) => (a.account < b.account ? -1 : a.account > b.account ? 1 : 0))
}

describe('Solana registry vectors', () => {
    it('covers every case', () => expect(vectors.cases.length).toBeGreaterThan(0))

    it.each(vectors.cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
        const { rpc, seen } = fakeRpc(c.operators, c.nodes)
        const { logger, lines } = recordingLogger()
        // Late in the day, so a clock read as seconds or rounded up would land
        // on the next one.
        const nowMs = (c.current_day * 86_400 + 86_399) * 1000
        const reader = new SolanaChainReader({
            rpc,
            programId: vectors.program_id,
            operatorIds: c.operator_ids?.map((id) => BigInt(id)),
            logger,
            clock: () => nowMs,
        })
        const read = reader.readChain()
        if (c.error !== '') {
            expect(c.want).toEqual([])
            if (c.error === 'account_version') {
                await expect(read).rejects.toThrow(/^fetch (operators|nodes): decode (operator|node) account \w+: zsescrow: unknown account version/)
                return
            }
            if (c.error === 'no_operators') await expect(read).rejects.toBeInstanceOf(NoOperatorsError)
            else {
                expect(c.error).toBe('operator_not_found')
                await expect(read).rejects.toThrow(/^fetch operators: operator \d+ not found on chain$/)
            }
            // The nodes are not read once the operators fail.
            expect(seen.map((s) => s.params)).toEqual([vectors.operator_params])
            return
        }
        const ops = await read
        expect(ops.map(chainFields)).toEqual(c.want)
        expect(skipsOf(c, ops, lines)).toEqual(c.skipped)
        expect(seen.map((s) => s.params)).toEqual([vectors.operator_params, vectors.node_params])
    })

    it('derives the deployment from the genesis hash and the program id', async () => {
        const { rpc, seen } = fakeRpc([], [])
        const d = await new SolanaChainReader({ rpc, programId: vectors.program_id }).readDeployment()
        expect(hex(d)).toBe(vectors.deployment_hex)
        expect(seen.map((s) => [s.method, s.params])).toEqual([['getGenesisHash', []]])
    })

    it('refuses a program id that is not a key at construction', () => {
        const { rpc } = fakeRpc([], [])
        expect(() => new SolanaChainReader({ rpc, programId: `${vectors.program_id}0` })).toThrow()
    })

    it('refuses to read without an RPC', async () => {
        const reader = new SolanaChainReader({} as never)
        await expect(reader.readChain()).rejects.toThrow('SolanaChainReader.rpc is not set')
        await expect(reader.readDeployment()).rejects.toThrow('SolanaChainReader.rpc is not set')
    })
})

describe('Solana signer-balance vectors', () => {
    const block = vectors.signer_balance

    it('prices the floor and the reserve as Go does', () => {
        expect(MIN_SIGNER_SPENDABLE_LAMPORTS).toBe(block.min_signer_spendable_lamports)
        expect(SOLANA_SIGNER_RESERVE_LAMPORTS).toBe(BigInt(block.signer_reserve_lamports))
    })

    it('covers every case', () => expect(block.cases.length).toBeGreaterThan(0))

    it.each(block.cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
        const balances = new Map<string, number | null>()
        const { rpc, seen } = fakeRpc(block.operators, c.nodes, balances)
        const source = new ChainOperatorSource({ chain: new SolanaChainReader({ rpc, programId: vectors.program_id }) })
        for (const p of c.passes) {
            balances.clear()
            for (const b of p.balances) balances.set(b.signing_addr, b.lamports)
            seen.length = 0
            const ops = await source.fetchChain()
            const sent = seen
                .filter((s) => s.method === 'getBalance')
                .map((s) => s.params as unknown[])
                .sort((a, b) => (String(a[0]) < String(b[0]) ? -1 : String(a[0]) > String(b[0]) ? 1 : 0))
            expect(sent).toEqual(p.sent)
            expect(ops.every((o) => o.signerSpendableMicroAlgos === undefined)).toBe(true)
            expect(
                ops.map((o) => ({
                    operator_id: o.id,
                    node_id: o.nodeId,
                    signing_addr: o.signingAddr,
                    signer_spendable_lamports: o.signerSpendableLamports ?? null,
                    underfunded: signerUnderfunded(selectionOf(o)),
                })),
            ).toEqual(p.want)
        }
    })

    // The discovery aggregates hold out what dispatch refuses, on either rail.
    it('holds a node below the lamports floor out of the discovery aggregates', async () => {
        const { rpc } = fakeRpc(vectors.cases[0]!.operators, vectors.cases[0]!.nodes)
        const [op] = await new SolanaChainReader({ rpc, programId: vectors.program_id }).readChain()
        const probed = { ...op!, probed: true, reachable: true, protoVersion: PROTO_VERSION }
        const at = (signerSpendableLamports: number) => advertisable({ ...probed, signerSpendableLamports }, 0, false, 60_000)
        expect([at(MIN_SIGNER_SPENDABLE_LAMPORTS), at(MIN_SIGNER_SPENDABLE_LAMPORTS - 1)]).toEqual([true, false])
    })

    it('refuses a signing address that is not a key without asking the RPC', async () => {
        const { rpc, seen } = fakeRpc([], [])
        const reader = new SolanaChainReader({ rpc, programId: vectors.program_id })
        await expect(reader.readSignerSpendableLamports('not-a-key', new AbortController().signal)).rejects.toThrow(/^signing address "not-a-key"/)
        expect(seen).toEqual([])
    })
})

/** A ChainReader that counts its calls. */
class FakeChainReader implements ChainReader {
    ops: Operator[] = []
    readErr: Error | undefined
    deployment = new Uint8Array(32).fill(1)
    deploymentErr: Error | undefined
    reads = 0
    derives = 0

    async readChain(): Promise<Operator[]> {
        this.reads++
        if (this.readErr) throw this.readErr
        return this.ops
    }

    async readDeployment(): Promise<Uint8Array> {
        this.derives++
        if (this.deploymentErr) throw this.deploymentErr
        return this.deployment
    }
}

describe('ChainOperatorSource over a ChainReader', () => {
    it('reads through the reader, derives the deployment once, and reads no algod balance', async () => {
        const { rpc } = fakeRpc(vectors.cases[0]!.operators, vectors.cases[0]!.nodes)
        const chain = new FakeChainReader()
        chain.ops = await new SolanaChainReader({ rpc, programId: vectors.program_id }).readChain()
        // No algod at all: the balance pass would throw for want of one. This
        // reader reads no balance of its own, so the signers stay unread.
        const source = new ChainOperatorSource({ chain })
        const ops = await source.fetchChain()
        expect(ops.map((o) => [o.id, o.nodeId])).toEqual([
            [1, 1],
            [1, 2],
        ])
        expect(ops.every((o) => o.signerSpendableMicroAlgos === undefined && o.signerSpendableLamports === undefined)).toBe(true)
        await source.fetchChain()
        expect([chain.reads, chain.derives]).toEqual([2, 1])
    })

    it('does not read a supplied deployment', async () => {
        const chain = new FakeChainReader()
        await new ChainOperatorSource({ chain, deployment: new Uint8Array(32).fill(2) }).fetchChain()
        expect(chain.derives).toBe(0)
    })

    it('retries a failed deployment read on the next chain read, without failing the read', async () => {
        const chain = new FakeChainReader()
        chain.deploymentErr = new Error('rpc down')
        const { logger, lines } = recordingLogger()
        const source = new ChainOperatorSource({ chain, logger })
        await expect(source.fetchChain()).resolves.toEqual([])
        expect(lines.map((l) => l.msg)).toEqual(['could not derive the escrow deployment; checking ephemeral signatures on the legacy layout'])
        chain.deploymentErr = undefined
        await source.fetchChain()
        await source.fetchChain()
        expect(chain.derives).toBe(2)
    })

    it('fails a failed chain read before the deployment read', async () => {
        const chain = new FakeChainReader()
        chain.readErr = new Error('rpc down')
        await expect(new ChainOperatorSource({ chain }).fetchChain()).rejects.toThrow('rpc down')
        expect(chain.derives).toBe(0)
    })
})
