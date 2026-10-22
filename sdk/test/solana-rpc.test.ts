/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Solana RPC client: testdata/solana_rpc_vectors.json, which go/solana/rpc
// generates, then the retry loop and the decoders against an injected fetch,
// ported from go/solana/rpc client_test.go.

import { readFileSync } from 'node:fs'

import { hex } from '@scure/base'
import { encodeBase58 } from '@txnlab/zs-proto/solana'
import { describe, expect, it } from 'vitest'

import {
    type Account,
    type Commitment,
    type Filter,
    type KeyedAccount,
    type SignatureStatus,
    SOLANA_RPC_MAX_RETRIES,
    SOLANA_RPC_RETRY_WAIT_MAX_MS,
    SOLANA_RPC_RETRY_WAIT_MIN_MS,
    SolanaHttpError,
    SolanaRpcClient,
    SolanaRpcError,
    solanaRpcBackoffMs,
    solanaRpcShouldRetry,
    txErrorName,
} from '../src/solana/rpc.js'

interface RequestArgs {
    key?: string
    commitment?: Commitment
    filters?: { data_size?: number; memcmp_offset?: number; memcmp_bytes_hex?: string }[]
    tx_hex?: string
    skip_preflight?: boolean
    preflight_commitment?: Commitment
    max_retries?: number
    signatures?: string[]
    search_history?: boolean
    data_len?: number
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/solana_rpc_vectors.json', import.meta.url), 'utf8')) as {
    max_retries: number
    wait_min_ms: number
    wait_max_ms: number
    statuses: { status: number; retry: boolean }[]
    rpc_errors: { method: string; status: number; code: number; data: unknown; retry: boolean; tx_err_name: string }[]
    tx_error_names: { err: unknown; name: string }[]
    schedule_ms: number[]
    now_unix_ms: number
    backoff: { attempt: number; retry_after: string; wait_ms: number }[]
    requests: { method: string; args: RequestArgs; params: unknown }[]
    answers: { method: string; args: RequestArgs; result: unknown; refused: boolean; want: unknown }[]
}

// ---- a fake RPC behind an injected fetch ----

type Reply = () => Response | Promise<Response>

interface Seen {
    method: string
    params: unknown
    body: string
    headers: Headers
    url: string
}

/** A fetch answering each call with the next reply, the last one repeating. */
function fakeRpc(...replies: Reply[]) {
    const seen: Seen[] = []
    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const body = String(init?.body)
        const req = JSON.parse(body) as { method: string; params: unknown }
        seen.push({ method: req.method, params: req.params, body, headers: new Headers(init?.headers), url: String(input) })
        if (init?.signal?.aborted) throw init.signal.reason
        return replies[Math.min(seen.length - 1, replies.length - 1)]!()
    }) as typeof globalThis.fetch
    return { fetch, seen }
}

const result = (v: unknown): Reply => () => Response.json({ jsonrpc: '2.0', id: 1, result: v })
const rawResult = (v: string): Reply => () => new Response(`{"jsonrpc":"2.0","id":1,"result":${v}}`)
const rpcError =
    (code: number, data?: unknown): Reply =>
    () =>
        Response.json({ jsonrpc: '2.0', id: 1, error: { code, message: 'refused', ...(data !== undefined && { data }) } })
const status =
    (code: number, headers: Record<string, string> = {}): Reply =>
    () =>
        new Response('{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"Too many requests"}}', { status: code, headers })
const noAnswer: Reply = () => Promise.reject(new TypeError('fetch failed'))
// A body that fails mid-read.
const cutOff: Reply = () =>
    new Response(
        new ReadableStream({
            start(c) {
                c.enqueue(new TextEncoder().encode('{"jsonrpc":"2.0",'))
                c.error(new TypeError('terminated'))
            },
        }),
    )

const quick = { maxRetries: 2, retryWaitMinMs: 5, retryWaitMaxMs: 20 }

function client(f: { fetch: typeof globalThis.fetch }, o: Partial<ConstructorParameters<typeof SolanaRpcClient>[0]> = {}) {
    return new SolanaRpcClient({ endpoint: 'https://rpc.example/rpc?api-key=secret', fetch: f.fetch, ...quick, ...o })
}

const KEY = encodeBase58(new Uint8Array(32).fill(0x5a))
const PROGRAM = '2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1'
const SIG = encodeBase58(new Uint8Array(64).fill(0x11))
const HASH = encodeBase58(new Uint8Array(32).fill(0x33))

const accountJson = (data: Uint8Array, lamports: number) => ({
    data: [Buffer.from(data).toString('base64'), 'base64'],
    executable: false,
    lamports,
    owner: PROGRAM,
    rentEpoch: 0,
    space: data.length,
})

// ---- vectors ----

const CANNED: Record<string, unknown> = {
    getAccountInfo: { context: { slot: 1 }, value: null },
    getProgramAccounts: [],
    getBalance: { context: { slot: 1 }, value: 0 },
    getLatestBlockhash: { context: { slot: 1 }, value: { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 0 } },
    getBlockHeight: 0,
    getGenesisHash: '11111111111111111111111111111111',
    getMinimumBalanceForRentExemption: 0,
    sendTransaction: '1111111111111111111111111111111111111111111111111111111111111111',
}

async function issue(c: SolanaRpcClient, method: string, a: RequestArgs): Promise<unknown> {
    const commitment = a.commitment
    switch (method) {
        case 'getAccountInfo':
            return c.getAccountInfo(a.key!, { commitment })
        case 'getProgramAccounts': {
            const filters = a.filters?.map(
                (f): Filter => (f.data_size !== undefined ? { dataSize: f.data_size } : { memcmp: { offset: f.memcmp_offset!, bytes: hex.decode(f.memcmp_bytes_hex!) } }),
            )
            return c.getProgramAccounts(a.key!, { commitment, filters })
        }
        case 'getBalance':
            return c.getBalance(a.key!, { commitment })
        case 'getLatestBlockhash':
            return c.getLatestBlockhash({ commitment })
        case 'getBlockHeight':
            return c.getBlockHeight({ commitment })
        case 'getGenesisHash':
            return c.getGenesisHash()
        case 'getMinimumBalanceForRentExemption':
            return c.getMinimumBalanceForRentExemption(a.data_len!, { commitment })
        case 'sendTransaction':
            return c.sendTransaction(hex.decode(a.tx_hex!), {
                skipPreflight: a.skip_preflight,
                preflightCommitment: a.preflight_commitment,
                maxRetries: a.max_retries,
            })
        case 'getSignatureStatuses':
            return c.getSignatureStatuses(a.signatures!, { searchHistory: a.search_history })
    }
    throw new Error(`unknown method ${method}`)
}

describe('solana_rpc vectors', () => {
    it("keeps Go's DefaultRetry budget", () => {
        expect([SOLANA_RPC_MAX_RETRIES, SOLANA_RPC_RETRY_WAIT_MIN_MS, SOLANA_RPC_RETRY_WAIT_MAX_MS]).toEqual([
            vectors.max_retries,
            vectors.wait_min_ms,
            vectors.wait_max_ms,
        ])
    })

    it.each(vectors.statuses.map((c) => [c.status, c.retry] as const))('status %i: retried %s', (s, retry) => {
        expect(solanaRpcShouldRetry('getAccountInfo', s === 0 ? undefined : s, undefined)).toBe(retry)
    })

    it('has rpc error cases', () => expect(vectors.rpc_errors.length).toBeGreaterThan(40))

    it.each(vectors.rpc_errors.map((c) => [c.method, c.status, c.code, c.data, c.retry, c.tx_err_name] as const))(
        '%s %i code %i data %j: retried %s, variant %j',
        (method, s, code, data, retry, name) => {
            const e = new SolanaRpcError(method, code, 'm', data === null ? undefined : data)
            expect(e.txErrName).toBe(name)
            expect(solanaRpcShouldRetry(method, s, e)).toBe(retry)
        },
    )

    it.each(vectors.tx_error_names.map((c) => [c.err, c.name] as const))('variant of %j is %j', (err, name) => {
        expect(txErrorName(err)).toBe(name)
    })

    it('waits the linear schedule with no Retry-After', () => {
        expect(vectors.schedule_ms).toHaveLength(SOLANA_RPC_MAX_RETRIES)
        expect(vectors.schedule_ms.map((_, i) => solanaRpcBackoffMs(i, null, vectors.now_unix_ms))).toEqual(vectors.schedule_ms)
    })

    it.each(vectors.backoff.map((c) => [c.attempt, c.retry_after, c.wait_ms] as const))(
        'after attempt %i with Retry-After %j: waits %d ms',
        (attempt, retryAfter, waitMs) => {
            expect(solanaRpcBackoffMs(attempt, retryAfter, vectors.now_unix_ms)).toBe(waitMs)
        },
    )

    it.each(vectors.requests.map((c) => [c.method, c.args, c.params] as const))('%s %j sends the params Go sends', async (method, args, params) => {
        const reply =
            method === 'getSignatureStatuses' ? result({ context: { slot: 1 }, value: args.signatures!.map(() => null) }) : result(CANNED[method])
        const f = fakeRpc(reply)
        await issue(client(f), method, args)
        expect(f.seen).toHaveLength(1)
        expect(f.seen[0]!.method).toBe(method)
        expect(f.seen[0]!.params).toEqual(params)
    })

    it('has answer cases', () => expect(vectors.answers.length).toBeGreaterThan(0))

    it.each(vectors.answers.map((c) => [c.method, c.result, c.args, c.refused, c.want] as const))(
        '%s reads %j as Go does',
        async (method, res, args, refused, want) => {
            const call = issue(client(fakeRpc(result(res))), method, args)
            if (refused) {
                const err = await call.catch((e: unknown) => e)
                expect(err).toBeInstanceOf(Error)
                expect((err as Error).name).toBe('SolanaRpcMalformedAnswer')
                return
            }
            expect(rendered(method, await call)).toEqual(want)
        },
    )
})

/** What a call decoded, in the vectors' want form. */
function rendered(method: string, got: unknown): unknown {
    const account = (a: Account) => ({ lamports: Number(a.lamports), owner: a.owner, data_hex: hex.encode(a.data), executable: a.executable })
    switch (method) {
        case 'getAccountInfo':
            return got === null ? null : account(got as Account)
        case 'getProgramAccounts':
            return (got as KeyedAccount[]).map((k) => ({ pubkey: k.key, account: account(k.account) }))
        case 'getSignatureStatuses':
            return (got as (SignatureStatus | null)[]).map((s) =>
                s === null
                    ? null
                    : {
                          slot: Number(s.slot),
                          confirmations: s.confirmations === null ? null : Number(s.confirmations),
                          err: s.err,
                          confirmation_status: s.confirmationStatus ?? '',
                      },
            )
    }
    throw new Error(`no rendering for ${method}`)
}

// ---- the client ----

describe('SolanaRpcClient', () => {
    it('reads an account and sends a JSON-RPC 2.0 envelope', async () => {
        const data = new Uint8Array([1, 2, 3, 4])
        const f = fakeRpc(result({ context: { apiVersion: '4.3.0', slot: 9 }, value: accountJson(data, 1_752_600) }))
        const a = await client(f, { headers: { 'X-Api-Key': 'k1' } }).getAccountInfo(KEY, { commitment: 'confirmed' })
        expect(a).toEqual({ lamports: 1_752_600n, owner: PROGRAM, data, executable: false })
        const s = f.seen[0]!
        expect(s.headers.get('content-type')).toBe('application/json')
        expect(s.headers.get('x-api-key')).toBe('k1')
        expect(s.url).toBe('https://rpc.example/rpc?api-key=secret')
        expect(JSON.parse(s.body)).toMatchObject({ jsonrpc: '2.0', method: 'getAccountInfo' })
    })

    it('answers null for an account that does not exist', async () => {
        expect(await client(fakeRpc(result({ context: { slot: 9 }, value: null }))).getAccountInfo(KEY)).toBeNull()
    })

    it.each([[['AQID', 'base58']], [['AQID']], [['!!', 'base64']], ['AQID']])('refuses account data %j', async (data) => {
        const f = fakeRpc(result({ context: { slot: 9 }, value: { data, executable: false, lamports: 1, owner: PROGRAM } }))
        await expect(client(f).getAccountInfo(KEY)).rejects.toThrow()
    })

    it('reads program accounts', async () => {
        const other = encodeBase58(new Uint8Array(32).fill(0x22))
        const f = fakeRpc(
            result([
                { pubkey: KEY, account: accountJson(new Uint8Array([9]), 5) },
                { pubkey: other, account: accountJson(new Uint8Array(), 6) },
            ]),
        )
        const got = await client(f).getProgramAccounts(PROGRAM, { commitment: 'confirmed', filters: [{ dataSize: 1 }] })
        expect(got.map((g) => [g.key, g.account.lamports, [...g.account.data]])).toEqual([
            [KEY, 5n, [9]],
            [other, 6n, []],
        ])
    })

    it('reads balances and heights', async () => {
        expect(await client(fakeRpc(result({ context: { slot: 9 }, value: 2 ** 53 - 1 }))).getBalance(KEY)).toBe(2n ** 53n - 1n)
        // JSON.parse would round it, so it is refused rather than misread.
        await expect(client(fakeRpc(rawResult('{"context":{"slot":9},"value":18446744073709551615}'))).getBalance(KEY)).rejects.toThrow('2^53')
        expect(
            await client(fakeRpc(result({ context: { slot: 9 }, value: { blockhash: HASH, lastValidBlockHeight: 300 } }))).getLatestBlockhash({
                commitment: 'finalized',
            }),
        ).toEqual({ blockhash: HASH, lastValidBlockHeight: 300n })
        await expect(
            client(fakeRpc(result({ context: { slot: 9 }, value: { blockhash: 'not-base58', lastValidBlockHeight: 300 } }))).getLatestBlockhash(),
        ).rejects.toThrow()
        expect(await client(fakeRpc(result(287))).getBlockHeight()).toBe(287n)
        expect(await client(fakeRpc(result(HASH))).getGenesisHash()).toBe(HASH)
    })

    it('sends a transaction as base64', async () => {
        const f = fakeRpc(result(SIG))
        expect(await client(f).sendTransaction(new Uint8Array([1, 2, 3]), { preflightCommitment: 'processed' })).toBe(SIG)
        expect((f.seen[0]!.params as unknown[])[0]).toBe('AQID')
    })

    it('reads signature statuses', async () => {
        const f = fakeRpc(
            result({
                context: { slot: 9 },
                value: [
                    null,
                    { slot: 7, confirmations: null, err: null, status: { Ok: null }, confirmationStatus: 'finalized' },
                    { slot: 8, confirmations: 3, err: { InstructionError: [1, { Custom: 6001 }] }, status: { Err: {} }, confirmationStatus: 'confirmed' },
                ],
            }),
        )
        const got = await client(f).getSignatureStatuses([SIG, SIG, SIG], { searchHistory: true })
        expect(got[0]).toBeNull()
        expect(got[1]).toEqual({ slot: 7n, confirmations: null, err: null, confirmationStatus: 'finalized' })
        expect(got[2]).toMatchObject({ slot: 8n, confirmations: 3n, confirmationStatus: 'confirmed' })
        expect(txErrorName(got[2]!.err)).toBe('InstructionError')

        await expect(client(fakeRpc(result({ context: { slot: 9 }, value: [null] }))).getSignatureStatuses([SIG, SIG])).rejects.toThrow('1 statuses for 2')
    })

    it.each([
        ['503', status(503)],
        ['429', status(429)],
        ['502', status(502)],
        ['node behind', rpcError(-32005, { numSlotsBehind: 12 })],
        ['no answer', noAnswer],
        ['cut-off body', cutOff],
    ])('retries %s', async (_name, first) => {
        const f = fakeRpc(first, result(287))
        expect(await client(f).getBlockHeight()).toBe(287n)
        expect(f.seen).toHaveLength(2)
    })

    it.each([
        ['400', status(400)],
        ['401', status(401)],
        ['403', status(403)],
        ['404', status(404)],
        ['invalid params', rpcError(-32602)],
        ['internal', rpcError(-32603)],
        ['scan', rpcError(-32012)],
        ['not json', () => new Response('{"jsonrpc":"2.0","id":1,"result":}')],
        ['null result', rawResult('null')],
    ])('answers %s at once', async (_name, first) => {
        const f = fakeRpc(first, result(287))
        await expect(client(f).getBlockHeight()).rejects.toThrow()
        expect(f.seen).toHaveLength(1)
    })

    it('resends a submit whose simulation found no blockhash, unchanged', async () => {
        const f = fakeRpc(rpcError(-32002, { err: 'BlockhashNotFound', logs: [] }), result(SIG))
        await client(f).sendTransaction(new Uint8Array([1, 2, 3]))
        expect(f.seen).toHaveLength(2)
        expect(f.seen[1]!.body).toBe(f.seen[0]!.body)
    })

    it.each(['AlreadyProcessed', 'InsufficientFundsForFee'])('answers a %s simulation at once', async (name) => {
        const f = fakeRpc(rpcError(-32002, { err: name, logs: ['Program log: x'] }), result(SIG))
        const err = await client(f)
            .sendTransaction(new Uint8Array([1]))
            .catch((e: unknown) => e)
        expect(err).toBeInstanceOf(SolanaRpcError)
        expect(err).toMatchObject({ code: -32002, txErrName: name, method: 'sendTransaction' })
        expect(f.seen).toHaveLength(1)
    })

    it('gives up after maxRetries, with the last failure', async () => {
        const f = fakeRpc(status(503))
        const err = await client(f)
            .getBlockHeight()
            .catch((e: unknown) => e)
        expect(err).toBeInstanceOf(SolanaHttpError)
        expect((err as SolanaHttpError).status).toBe(503)
        expect((err as SolanaHttpError).body).toContain('Too many requests')
        expect(f.seen).toHaveLength(quick.maxRetries + 1)
    })

    it('rethrows a transport failure once the retries run out', async () => {
        await expect(client(fakeRpc(noAnswer)).getBlockHeight()).rejects.toThrow('fetch failed')
    })

    it('waits out a Retry-After longer than the schedule, held to the cap', async () => {
        const f = fakeRpc(status(429, { 'Retry-After': '5' }), result(1))
        const started = Date.now()
        await client(f, { maxRetries: 1, retryWaitMinMs: 5, retryWaitMaxMs: 150 }).getBlockHeight()
        const waited = Date.now() - started
        expect(waited).toBeGreaterThanOrEqual(140)
        expect(waited).toBeLessThan(2_000)
    })

    it("stops on the call's signal, mid-wait, without another attempt", async () => {
        const f = fakeRpc(status(503))
        const ac = new AbortController()
        const p = client(f, { maxRetries: 5, retryWaitMinMs: 10_000, retryWaitMaxMs: 10_000 }).getBlockHeight({ signal: ac.signal })
        await new Promise((r) => setTimeout(r, 30))
        ac.abort(new Error('caller left'))
        await expect(p).rejects.toThrow('caller left')
        expect(f.seen).toHaveLength(1)
    })

    // A caller that ended the call while an attempt was out gets that
    // attempt's failure, not its signal's reason, and no retry is logged or made.
    it("returns the attempt's failure once the caller has ended the call", async () => {
        const ac = new AbortController()
        let attempts = 0
        // It ignores its signal, as a fetch whose answer was already in hand does.
        const fetch = (async () => {
            attempts++
            ac.abort(new Error('caller left'))
            return status(503)()
        }) as typeof globalThis.fetch
        const logged: string[] = []
        const logger = { debug: (msg: string) => logged.push(msg), info: () => {}, warn: () => {}, error: () => {} }
        const err = await client({ fetch }, { maxRetries: 5, retryWaitMinMs: 10_000, retryWaitMaxMs: 10_000, logger })
            .getBlockHeight({ signal: ac.signal })
            .catch((e: unknown) => e)
        expect(err).toBeInstanceOf(SolanaHttpError)
        expect((err as SolanaHttpError).status).toBe(503)
        expect(attempts).toBe(1)
        expect(logged).toEqual([])
    })

    it.each(['ws://rpc.example/?api-key=secret', 'rpc.example/?api-key=secret', 'https://user:secret@rpc.example/'])(
        'refuses the endpoint %s without spelling it',
        (endpoint) => {
            let err: unknown
            try {
                new SolanaRpcClient({ endpoint })
            } catch (e) {
                err = e
            }
            expect(err).toBeInstanceOf(Error)
            expect((err as Error).message).not.toContain('secret')
        },
    )

    // Each half of the userinfo is refused on its own.
    it.each(['https://:secret@rpc.example/', 'https://secret@rpc.example/'])('refuses the credentials in %s without spelling them', (endpoint) => {
        let err: unknown
        try {
            new SolanaRpcClient({ endpoint })
        } catch (e) {
            err = e
        }
        expect(err).toBeInstanceOf(Error)
        expect((err as Error).message).toContain('carries credentials')
        expect((err as Error).message).not.toContain('secret')
    })

    it('keeps the endpoint out of a failed call', async () => {
        const f = fakeRpc(noAnswer)
        const err = await client(f)
            .getBlockHeight()
            .catch((e: unknown) => e)
        expect(f.seen[0]!.url).toContain('secret')
        expect((err as Error).message).not.toContain('secret')
        const http = await client(fakeRpc(status(403)))
            .getBlockHeight()
            .catch((e: unknown) => e)
        expect((http as Error).message).not.toContain('secret')
    })
})
