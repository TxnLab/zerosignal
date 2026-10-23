/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A thin Solana JSON-RPC client: the methods the payer rail calls, with a
// retry policy for the RPC's weather. The twin of go/solana/rpc (client.go,
// methods.go, retry.go). The retry budget, which outcomes retry, the wait
// before each retry and the params each method sends are pinned by
// testdata/solana_rpc_vectors.json. Account data comes back as bytes for
// @txnlab/zs-proto/solana/zsescrow's decoders.
//
// Hand-rolled rather than @solana/kit, for the reason ts/src/solana is: one
// set of vectors holds Go and TS to the same bytes.
//
// Differences from Go:
//   - A u64 the RPC sends past 2^53 (a balance above ~9 million SOL) is an
//     error: JSON.parse would round it. Go reads every u64 exactly.
//   - getAccountInfo answers null for an account that does not exist, where
//     Go returns ErrNotFound.
//   - The answer's keys are read exactly; Go's encoding/json also matches
//     them case-insensitively. An Agave node sends them in one case.
//   - A lamports of 5.0 or 5e0 reads as 5, which Go refuses, and account data
//     with a line break in its base64 is refused, which Go's decoder skips.
//     So does a TransactionError's instruction index or Custom code
//     (txCustomError). An Agave node sends neither.
//   - The transport is the runtime's. A browser's fetch speaks HTTP/2 where
//     the endpoint offers it; Node's speaks HTTP/1.1, so there concurrent
//     calls each hold a connection, against the public endpoints' cap of 40
//     new connections per IP per 10 s that Go's HTTP/2 pool is built for.
//   - The wait is bounded by the call's signal, as algod-transport.ts's is.
//     Retry lines go to the logger the client is given.
//   - In a browser, Retry-After is unreadable on a cross-origin RPC unless it
//     exposes the header (Access-Control-Expose-Headers), so the linear
//     schedule applies.

import { base64 } from '@scure/base'
import { type Hash, type PublicKey, decodeBase58 } from '@txnlab/zs-proto/solana'

import { algodBackoffMs } from '../algod-transport.js'
import { quietLogger } from '../log.js'
import { type Fetch, type Logger, discardLogger } from '../ports.js'
import { sleep } from '../sleep.js'

/** SOLANA_RPC_MAX_RETRIES is how many retries follow the first attempt, Go's DefaultRetry MaxRetries. */
export const SOLANA_RPC_MAX_RETRIES = 8
/** SOLANA_RPC_RETRY_WAIT_MIN_MS is the wait before the first retry and the step each later one adds. */
export const SOLANA_RPC_RETRY_WAIT_MIN_MS = 500
/** SOLANA_RPC_RETRY_WAIT_MAX_MS caps every wait, a server's Retry-After included: the public endpoints' 10 s rate window. */
export const SOLANA_RPC_RETRY_WAIT_MAX_MS = 10_000

// Agave's rpc-client-api/src/custom_error.rs, as Go's retry.go cites it.
/** sendTransaction's failed simulation; its data's err names the TransactionError. */
export const CODE_PREFLIGHT_FAILURE = -32002
/** A node behind the cluster, or not yet knowing whether it is. */
export const CODE_NODE_UNHEALTHY = -32005
/** A node that has not reached the minContextSlot a read asked for. */
export const CODE_MIN_CONTEXT_SLOT_NOT_REACHED = -32016

/** How settled the state a call reads must be; absent sends none, so the RPC applies its default, finalized. */
export type Commitment = 'processed' | 'confirmed' | 'finalized'

/**
 * txErrorName is the variant of a TransactionError as the RPC spells it: a
 * unit variant as its name, any other as an object of one key. '' for null and
 * anything else. Go's TxErrName.
 */
export function txErrorName(err: unknown): string {
    if (typeof err === 'string') return err
    if (typeof err === 'object' && err !== null && !Array.isArray(err)) {
        const keys = Object.keys(err)
        if (keys.length === 1) return keys[0]!
    }
    return ''
}

/**
 * txCustomError is the code a program returned, when the TransactionError is
 * {InstructionError: [index, {Custom: code}]}: an Anchor program's error code,
 * which names why it refused. null for any other error. Go's TxCustomError.
 */
export function txCustomError(err: unknown): number | null {
    const one = (v: unknown, key: string): unknown => {
        if (typeof v !== 'object' || v === null || Array.isArray(v)) return undefined
        const keys = Object.keys(v)
        return keys.length === 1 && keys[0] === key ? (v as Record<string, unknown>)[key] : undefined
    }
    const ie = one(err, 'InstructionError')
    if (!Array.isArray(ie) || ie.length !== 2) return null
    const [index, custom] = ie as [unknown, unknown]
    if (!Number.isInteger(index) || (index as number) < 0 || (index as number) > 0xff) return null
    const code = one(custom, 'Custom')
    if (!Number.isInteger(code) || (code as number) < 0 || (code as number) > 0xffffffff) return null
    return code as number
}

/** A JSON-RPC error in a 2xx answer. */
export class SolanaRpcError extends Error {
    constructor(
        readonly method: string,
        readonly code: number,
        readonly rpcMessage: string,
        /** The error's data member, undefined when absent. */
        readonly data: unknown,
    ) {
        super(`solana rpc ${method}: ${code} ${rpcMessage}`)
        this.name = 'SolanaRpcError'
    }

    /**
     * The variant of a failed simulation's TransactionError, '' for any other
     * error. A resend of a transaction that already landed fails its
     * simulation as "AlreadyProcessed": the cluster has it.
     */
    get txErrName(): string {
        return txErrorName(this.txErr)
    }

    /** A failed simulation's TransactionError as sent, undefined for any other error. */
    get txErr(): unknown {
        if (this.code !== CODE_PREFLIGHT_FAILURE) return undefined
        const d = this.data
        if (typeof d !== 'object' || d === null || Array.isArray(d)) return undefined
        return (d as Record<string, unknown>).err
    }
}

/** A non-2xx answer. */
export class SolanaHttpError extends Error {
    constructor(
        readonly method: string,
        readonly status: number,
        /** The answer's start, for a log line. */
        readonly body: string,
    ) {
        super(`solana rpc ${method}: HTTP ${status}: ${body}`)
        this.name = 'SolanaHttpError'
    }
}

const ERROR_BODY_EXCERPT = 512

/**
 * solanaRpcShouldRetry is whether an outcome is retried: status undefined is
 * a request that got no answer, rpcError the JSON-RPC error of a 2xx answer.
 * Go's shouldRetry, whose comment gives the reasons.
 */
export function solanaRpcShouldRetry(method: string, status: number | undefined, rpcError: SolanaRpcError | undefined): boolean {
    if (status === undefined) return true
    if (status === 429 || (status >= 500 && status <= 599)) return true
    if (status < 200 || status > 299 || rpcError === undefined) return false
    switch (rpcError.code) {
        case CODE_NODE_UNHEALTHY:
            return true
        case CODE_PREFLIGHT_FAILURE:
            return method === 'sendTransaction' && rpcError.txErrName === 'BlockhashNotFound'
        case CODE_MIN_CONTEXT_SLOT_NOT_REACHED:
            return method === 'getAccountInfo'
    }
    return false
}

/**
 * solanaRpcBackoffMs is the wait before the retry that follows attempt
 * (0-based): algod's schedule under Solana's bounds, one function as Go's
 * httpx.LinearBackoff is, so algod_retry_vectors.json pins its Retry-After
 * parse for both.
 */
export function solanaRpcBackoffMs(
    attempt: number,
    retryAfter: string | null | undefined,
    nowMs: number,
    minMs: number = SOLANA_RPC_RETRY_WAIT_MIN_MS,
    maxMs: number = SOLANA_RPC_RETRY_WAIT_MAX_MS,
): number {
    return algodBackoffMs(attempt, retryAfter, nowMs, minMs, maxMs)
}

/** An account as the RPC reports it. The owner is the caller's to check before it trusts data. */
export interface Account {
    lamports: bigint
    owner: PublicKey
    data: Uint8Array
    executable: boolean
}

export interface KeyedAccount {
    key: PublicKey
    account: Account
}

/** A slot-aware account read: the account, null when it does not exist, and the slot the answer is as of. */
export interface AccountAt {
    account: Account | null
    slot: bigint
}

/** A getProgramAccounts filter: data exactly dataSize bytes, or holding bytes (at most 128) at offset. */
export type Filter = { dataSize: number } | { memcmp: { offset: number; bytes: Uint8Array } }

export interface Blockhash {
    blockhash: Hash
    /** The last block height a transaction naming it can land at. */
    lastValidBlockHeight: bigint
}

export interface SignatureStatus {
    slot: bigint
    /** null once the block is rooted. */
    confirmations: bigint | null
    /** The TransactionError it landed with, null for a success (see txErrorName). */
    err: unknown
    confirmationStatus: Commitment | undefined
}

export interface CallOptions {
    commitment?: Commitment | undefined
    signal?: AbortSignal | undefined
}

export interface SendOptions {
    skipPreflight?: boolean | undefined
    /** The state the simulation runs against; absent is the RPC's default, finalized. */
    preflightCommitment?: Commitment | undefined
    /** How often the RPC itself resends; absent leaves its default, until the blockhash expires. */
    maxRetries?: number | undefined
    signal?: AbortSignal | undefined
}

/** The RPC surface the rail depends on; SolanaRpcClient backs it, a test hands in a fake. */
export interface SolanaRpc {
    getAccountInfo(key: PublicKey, o?: CallOptions): Promise<Account | null>
    /**
     * getAccountInfo from a node at minContextSlot or later (absent or 0n asks
     * for none), with the slot the answer is as of. A node behind a load
     * balancer can be slots behind the one that answered the last read, so an
     * account a read saw can read as missing on the next; a caller that acts on
     * its absence asks for the slot it saw it at. SolanaRpcClient has it; a
     * SolanaRpc need not. Go's AccountAtReader.
     */
    getAccountInfoAt?(key: PublicKey, o?: CallOptions & { minContextSlot?: bigint | undefined }): Promise<AccountAt>
    getProgramAccounts(program: PublicKey, o?: CallOptions & { filters?: Filter[] | undefined }): Promise<KeyedAccount[]>
    getBalance(key: PublicKey, o?: CallOptions): Promise<bigint>
    getLatestBlockhash(o?: CallOptions): Promise<Blockhash>
    getBlockHeight(o?: CallOptions): Promise<bigint>
    getGenesisHash(o?: { signal?: AbortSignal | undefined }): Promise<Hash>
    /** The lamports an account of dataLen bytes must hold to stay rent-exempt, at the cluster's current rate. */
    getMinimumBalanceForRentExemption(dataLen: number, o?: CallOptions): Promise<bigint>
    /** Submits signed transaction bytes; resolves to the base58 signature the RPC reports. */
    sendTransaction(tx: Uint8Array, o?: SendOptions): Promise<string>
    getSignatureStatuses(
        signatures: string[],
        o?: { searchHistory?: boolean | undefined; signal?: AbortSignal | undefined },
    ): Promise<(SignatureStatus | null)[]>
}

export interface SolanaRpcOptions {
    /** An http or https URL, with any path and query a provider needs. */
    endpoint: string
    /** Sent with every request, for a provider that takes its API key in one. */
    headers?: Record<string, string> | undefined
    /** Absent is the runtime's global fetch, read at each request: the RPC is the host's chosen endpoint. */
    fetch?: Fetch | undefined
    /** Retry lines are logged at debug. */
    logger?: Logger | undefined
    maxRetries?: number | undefined
    retryWaitMinMs?: number | undefined
    retryWaitMaxMs?: number | undefined
}

class MalformedAnswer extends Error {
    constructor(method: string, what: string) {
        super(`solana rpc ${method}: ${what}`)
        this.name = 'SolanaRpcMalformedAnswer'
    }
}

function u64(method: string, v: unknown, what: string): bigint {
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) throw new MalformedAnswer(method, `${what} is not a u64 below 2^53`)
    return BigInt(v)
}

function obj(method: string, v: unknown, what: string): Record<string, unknown> {
    if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new MalformedAnswer(method, `${what} is not an object`)
    return v as Record<string, unknown>
}

function str(method: string, v: unknown, what: string): string {
    if (typeof v !== 'string') throw new MalformedAnswer(method, `${what} is not a string`)
    return v
}

function base58Of(method: string, v: unknown, size: number, what: string): string {
    const s = str(method, v, what)
    try {
        decodeBase58(s, size)
    } catch {
        throw new MalformedAnswer(method, `${what} is not ${size} bytes of base58`)
    }
    return s
}

function account(method: string, v: unknown): Account {
    const a = obj(method, v, 'account')
    const d = a.data
    if (!Array.isArray(d) || d.length !== 2 || d[1] !== 'base64' || typeof d[0] !== 'string') {
        throw new MalformedAnswer(method, 'account data is not [data, "base64"]')
    }
    let data: Uint8Array
    try {
        data = base64.decode(d[0])
    } catch {
        throw new MalformedAnswer(method, 'account data is not base64')
    }
    if (a.executable !== undefined && typeof a.executable !== 'boolean') throw new MalformedAnswer(method, 'executable is not a boolean')
    return { lamports: u64(method, a.lamports, 'lamports'), owner: base58Of(method, a.owner, 32, 'owner'), data, executable: a.executable === true }
}

function commitmentConfig(c: Commitment | undefined): Record<string, unknown> {
    return c === undefined ? {} : { commitment: c }
}

/**
 * SolanaRpcClient is the JSON-RPC client over fetch. A transport failure, a
 * 429, a 5xx and the JSON-RPC weather solanaRpcShouldRetry names are retried
 * up to maxRetries times, waiting the linear schedule or a longer Retry-After,
 * both capped. Every method retries, sendTransaction included: the cluster
 * processes a signature once. An aborted signal ends the call at once, also
 * mid-wait.
 */
export class SolanaRpcClient implements SolanaRpc {
    readonly #endpoint: string
    readonly #headers: Record<string, string>
    readonly #fetch: Fetch | undefined
    readonly #log: Logger
    readonly #maxRetries: number
    readonly #waitMin: number
    readonly #waitMax: number
    #id = 0

    constructor(o: SolanaRpcOptions) {
        // No error spells the endpoint: a provider's API key often rides in its query.
        let u: URL
        try {
            u = new URL(o.endpoint)
        } catch {
            throw new Error('solana rpc: endpoint is not a URL')
        }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('solana rpc: endpoint is not http or https')
        // fetch refuses such a URL, naming it in its error, on every attempt.
        if (u.username !== '' || u.password !== '') throw new Error('solana rpc: endpoint carries credentials; pass them in headers')
        this.#endpoint = o.endpoint
        this.#headers = { ...o.headers, 'content-type': 'application/json' }
        this.#fetch = o.fetch
        this.#log = quietLogger(o.logger ?? discardLogger)
        this.#maxRetries = o.maxRetries ?? SOLANA_RPC_MAX_RETRIES
        this.#waitMin = o.retryWaitMinMs ?? SOLANA_RPC_RETRY_WAIT_MIN_MS
        this.#waitMax = o.retryWaitMaxMs ?? SOLANA_RPC_RETRY_WAIT_MAX_MS
    }

    async getAccountInfo(key: PublicKey, o: CallOptions = {}): Promise<Account | null> {
        const m = 'getAccountInfo'
        const r = obj(m, await this.#call(m, [key, { encoding: 'base64', ...commitmentConfig(o.commitment) }], o.signal), 'result')
        return r.value === null ? null : account(m, r.value)
    }

    async getAccountInfoAt(key: PublicKey, o: CallOptions & { minContextSlot?: bigint | undefined } = {}): Promise<AccountAt> {
        const m = 'getAccountInfo'
        const cfg: Record<string, unknown> = { encoding: 'base64', ...commitmentConfig(o.commitment) }
        if (o.minContextSlot !== undefined && o.minContextSlot !== 0n) {
            // A slot past 2^53 would go as another number; this client reads none.
            if (o.minContextSlot < 0n || o.minContextSlot > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`solana rpc ${m}: minContextSlot out of range`)
            cfg.minContextSlot = Number(o.minContextSlot)
        }
        const r = obj(m, await this.#call(m, [key, cfg], o.signal), 'result')
        // Refused rather than read as 0, which any later comparison would pass
        // as no older than the slot asked for.
        const slot = u64(m, obj(m, r.context, 'context').slot, 'context slot')
        return { account: r.value === null ? null : account(m, r.value), slot }
    }

    async getProgramAccounts(program: PublicKey, o: CallOptions & { filters?: Filter[] | undefined } = {}): Promise<KeyedAccount[]> {
        const m = 'getProgramAccounts'
        const cfg: Record<string, unknown> = { encoding: 'base64', ...commitmentConfig(o.commitment) }
        if (o.filters !== undefined && o.filters.length > 0) {
            cfg.filters = o.filters.map((f) =>
                'dataSize' in f ? { dataSize: f.dataSize } : { memcmp: { offset: f.memcmp.offset, bytes: base64.encode(f.memcmp.bytes), encoding: 'base64' } },
            )
        }
        const r = await this.#call(m, [program, cfg], o.signal)
        if (!Array.isArray(r)) throw new MalformedAnswer(m, 'result is not an array')
        return r.map((e) => {
            const ka = obj(m, e, 'entry')
            return { key: base58Of(m, ka.pubkey, 32, 'pubkey'), account: account(m, ka.account) }
        })
    }

    async getBalance(key: PublicKey, o: CallOptions = {}): Promise<bigint> {
        const m = 'getBalance'
        const r = obj(m, await this.#call(m, [key, commitmentConfig(o.commitment)], o.signal), 'result')
        return u64(m, r.value, 'value')
    }

    async getLatestBlockhash(o: CallOptions = {}): Promise<Blockhash> {
        const m = 'getLatestBlockhash'
        const r = obj(m, await this.#call(m, [commitmentConfig(o.commitment)], o.signal), 'result')
        const v = obj(m, r.value, 'value')
        return { blockhash: base58Of(m, v.blockhash, 32, 'blockhash'), lastValidBlockHeight: u64(m, v.lastValidBlockHeight, 'lastValidBlockHeight') }
    }

    async getBlockHeight(o: CallOptions = {}): Promise<bigint> {
        const m = 'getBlockHeight'
        return u64(m, await this.#call(m, [commitmentConfig(o.commitment)], o.signal), 'result')
    }

    async getGenesisHash(o: { signal?: AbortSignal | undefined } = {}): Promise<Hash> {
        const m = 'getGenesisHash'
        return base58Of(m, await this.#call(m, [], o.signal), 32, 'result')
    }

    async getMinimumBalanceForRentExemption(dataLen: number, o: CallOptions = {}): Promise<bigint> {
        const m = 'getMinimumBalanceForRentExemption'
        return u64(m, await this.#call(m, [dataLen, commitmentConfig(o.commitment)], o.signal), 'result')
    }

    async sendTransaction(tx: Uint8Array, o: SendOptions = {}): Promise<string> {
        const m = 'sendTransaction'
        const cfg: Record<string, unknown> = { encoding: 'base64' }
        if (o.skipPreflight === true) cfg.skipPreflight = true
        if (o.preflightCommitment !== undefined) cfg.preflightCommitment = o.preflightCommitment
        if (o.maxRetries !== undefined) cfg.maxRetries = o.maxRetries
        return base58Of(m, await this.#call(m, [base64.encode(tx), cfg], o.signal), 64, 'result')
    }

    async getSignatureStatuses(
        signatures: string[],
        o: { searchHistory?: boolean | undefined; signal?: AbortSignal | undefined } = {},
    ): Promise<(SignatureStatus | null)[]> {
        const m = 'getSignatureStatuses'
        const r = obj(m, await this.#call(m, [signatures, o.searchHistory === true ? { searchTransactionHistory: true } : {}], o.signal), 'result')
        const v = r.value
        if (!Array.isArray(v) || v.length !== signatures.length) {
            throw new MalformedAnswer(m, `${Array.isArray(v) ? v.length : 'no'} statuses for ${signatures.length} signatures`)
        }
        return v.map((e) => {
            if (e === null) return null
            const s = obj(m, e, 'status')
            const cs = s.confirmationStatus
            if (cs !== undefined && cs !== null && cs !== 'processed' && cs !== 'confirmed' && cs !== 'finalized') {
                throw new MalformedAnswer(m, 'confirmationStatus is not a commitment')
            }
            return {
                slot: u64(m, s.slot, 'slot'),
                confirmations: s.confirmations === null || s.confirmations === undefined ? null : u64(m, s.confirmations, 'confirmations'),
                err: s.err ?? null,
                confirmationStatus: cs ?? undefined,
            }
        })
    }

    async #call(method: string, params: unknown[], signal: AbortSignal | undefined): Promise<unknown> {
        const body = JSON.stringify({ jsonrpc: '2.0', id: ++this.#id, method, params })
        const fetch = this.#fetch ?? globalThis.fetch
        for (let attempt = 0; ; attempt++) {
            let status: number | undefined
            let retryAfter: string | null = null
            let err: unknown
            try {
                const res = await fetch(this.#endpoint, { method: 'POST', headers: this.#headers, body, ...(signal !== undefined && { signal }) })
                // A body cut off mid-read is the connection's failure, not the
                // RPC's answer, so status and Retry-After stay unset until it
                // is whole.
                const text = await res.text()
                status = res.status
                retryAfter = res.headers.get('retry-after')
                return answer(method, status, text)
            } catch (e) {
                err = e
            }
            // A call the caller ended is not a transient failure.
            if (signal?.aborted) throw err
            const rpcError = err instanceof SolanaRpcError ? err : undefined
            if (!solanaRpcShouldRetry(method, status, rpcError) || attempt >= this.#maxRetries) throw err

            const wait = solanaRpcBackoffMs(attempt, retryAfter, Date.now(), this.#waitMin, this.#waitMax)
            this.#log.debug('solana rpc retry', {
                method,
                err: err instanceof Error ? err.message : String(err),
                status: status ?? 0,
                wait_ms: wait,
                attempt: attempt + 1,
                max: this.#maxRetries + 1,
            })
            if (!(await sleep(wait, signal))) throw signal!.reason
        }
    }
}

// One complete answer: its result, or the error it carries.
function answer(method: string, status: number, text: string): unknown {
    if (status < 200 || status > 299) throw new SolanaHttpError(method, status, text.slice(0, ERROR_BODY_EXCERPT))
    let r: unknown
    try {
        r = JSON.parse(text)
    } catch {
        throw new MalformedAnswer(method, 'answer is not JSON')
    }
    const env = obj(method, r, 'answer')
    if (env.error !== undefined && env.error !== null) {
        const e = obj(method, env.error, 'error')
        if (typeof e.code !== 'number' || !Number.isInteger(e.code)) throw new MalformedAnswer(method, 'error code is not an integer')
        if (e.message !== undefined && typeof e.message !== 'string') throw new MalformedAnswer(method, 'error message is not a string')
        throw new SolanaRpcError(method, e.code, e.message ?? '', e.data)
    }
    // None of these methods answers a null result, and reading one would
    // leave a value that looks like a real answer.
    if (env.result === undefined || env.result === null) throw new MalformedAnswer(method, 'answer has neither result nor error')
    return env.result
}
