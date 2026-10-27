/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's half of free credits (SPEC.md § 3a "Free credits"): fetching
// them from the issuers a host names, keeping them until a free Solana reserve
// carries one, and choosing which reserve does. Mirrors proto/go/zs
// free_credits.go; creditIssuersFor is pinned by testdata/operator_vectors.json.

import {
    CODE_CREDITS_EXHAUSTED,
    type Credit,
    DAY_KEY_PATH,
    type DayKey,
    type DayKeyCert,
    ISSUE_PATH,
    type IssueResponse,
    MAX_ISSUE_BATCH,
    type PendingCredit,
    blindCredit,
    epochAt,
    epochStartMs,
    parseCredit,
    parseIssuerKey,
    verifyDayKey,
} from '@txnlab/zs-proto/freecredit'
import { base64 } from '@scure/base'

import { configError } from '../errors.js'
import { readLimited } from '../http.js'
import type { Rail } from '../network.js'
import type { ModelCapacity, Operator } from '../operator.js'
import { servesImageEdit, servesImageGen } from '../operator.js'
import type { Clock, Fetch, Logger } from '../ports.js'
import { parseRetryAfter } from '../reserve.js'

/** Go's DefaultFreeCreditBatch and its fetch timeout and failure backoff, pinned by sdk_vocabulary_vectors.json. */
export const FREE_CREDIT_DEFAULTS = {
    /**
     * How many credits one fetch asks an issuer for. More than one, so a
     * node's next free turns need no fetch and an issuer can't time each fetch
     * against the turn that follows it; few, so a node that goes down that day
     * wastes little.
     */
    batch: 3,
    /** One fetch, the day key and the signatures together. The turn waits on it, and goes without a credit past it. */
    fetchTimeout: 5_000,
    /** How long an issuer that failed is skipped, so a down issuer costs one timeout a minute rather than one a turn. */
    failureBackoff: 60_000,
} as const

const DAY_MS = 86_400_000
// An issuer's answer: twenty 4096-bit signatures in base64 are under 15 KiB.
const MAX_BODY_BYTES = 1 << 20

/**
 * FreeCredits configures free credits: an issuer's blind signature that a
 * free Solana reserve carries, which lets a node that trusts the issuer tell
 * this payer's free turn from a sybil's. With no issuers a payer fetches none
 * and is served on each node's own free budget. Go's zs.FreeCredits.
 */
export interface FreeCredits {
    /**
     * An issuer's key, standard base64 of its Ed25519 public key as cluster
     * presets and node details spell it, to how to reach it. A reserve carries
     * a credit only from an issuer here that the node advertises trusting.
     */
    issuers: Record<string, CreditIssuer>
    /** Keeps credits fetched and not yet spent; memoryCreditStore() when absent. */
    store?: CreditStore
    /** How many credits one fetch asks for, at most MAX_ISSUE_BATCH. */
    batch?: number
}

/** One issuer's side of the issue wire. httpCreditIssuer speaks it over HTTP. */
export interface CreditIssuer {
    /** The issuer's certified day key for deployment and epoch. */
    dayKey(deployment: Uint8Array, epoch: number, signal?: AbortSignal): Promise<DayKeyCert>
    /** The issuer's blind signatures over blinded, in order. It may return fewer than asked: the first few. */
    issue(deployment: Uint8Array, epoch: number, blinded: Uint8Array[], signal?: AbortSignal): Promise<Uint8Array[]>
}

/** An issuer's 429 credits_exhausted: the caller's credits for the day are spent until retryAfterMs, 0 when it gave none. */
export class CreditsExhaustedError extends Error {
    constructor(readonly retryAfterMs: number) {
        super(`free credit issuer: ${CODE_CREDITS_EXHAUSTED} (retry after ${retryAfterMs}ms)`)
        this.name = 'CreditsExhaustedError'
    }
}

export interface HttpCreditIssuerOptions {
    /** The issuer's base URL, the paths appended to it. */
    url: string
    /** Sends the requests; the global fetch when absent. */
    fetch?: Fetch
    /**
     * Adds what the issuer's gate asks of a caller, such as proof of a check it
     * passed, to each request's headers.
     */
    headers?: (h: Headers, signal?: AbortSignal) => void | Promise<void>
}

/** A CreditIssuer over the issue wire at opts.url. Go's HTTPCreditIssuer. */
export function httpCreditIssuer(opts: HttpCreditIssuerOptions): CreditIssuer {
    const base = opts.url.replace(/\/+$/, '')
    const post = async (path: string, body: unknown, signal?: AbortSignal): Promise<unknown> => {
        const headers = new Headers({ 'Content-Type': 'application/json' })
        try {
            await opts.headers?.(headers, signal)
        } catch (err) {
            throw new Error(`free credit issuer: ${(err as Error).message}`, { cause: err })
        }
        const fetch = opts.fetch ?? globalThis.fetch
        const resp = await fetch(base + path, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            ...(signal ? { signal } : {}),
        })
        const text = await readCapped(resp)
        if (resp.status !== 200) {
            const code = errorCode(text)
            if (resp.status === 429 && code === CODE_CREDITS_EXHAUSTED) {
                throw new CreditsExhaustedError(parseRetryAfter(resp.headers.get('Retry-After')))
            }
            throw new Error(`free credit issuer: ${path} answered ${resp.status} ${code}`)
        }
        try {
            return JSON.parse(text) as unknown
        } catch (err) {
            throw new Error(`free credit issuer: ${path}: ${(err as Error).message}`, { cause: err })
        }
    }
    return {
        async dayKey(deployment, epoch, signal) {
            // Read as Go reads a DayKeyCert: the credit's rules, its own
            // fields left empty.
            const c = parseCredit(await post(DAY_KEY_PATH, { deployment: base64.encode(deployment), epoch }, signal))
            return { issuer: c.issuer, epoch: c.epoch, day_key: c.day_key, day_key_sig: c.day_key_sig }
        },
        async issue(deployment, epoch, blinded, signal) {
            const v = (await post(
                ISSUE_PATH,
                { deployment: base64.encode(deployment), epoch, blinded: blinded.map((b) => base64.encode(b)) },
                signal,
            )) as IssueResponse
            if (!Array.isArray(v?.signatures)) throw new Error('free credit issuer: no signatures')
            return v.signatures.map((s) => base64.decode(s))
        },
    }
}

async function readCapped(resp: Response): Promise<string> {
    return new TextDecoder().decode(await readLimited(resp, MAX_BODY_BYTES))
}

function errorCode(body: string): string {
    try {
        const v = JSON.parse(body) as { error?: { code?: unknown } }
        return typeof v?.error?.code === 'string' ? v.error.code : ''
    } catch {
        return ''
    }
}

/** The credits a store keeps together: one issuer's, for one node, on one day. */
export interface CreditKey {
    /** The deployment id, standard base64. */
    deployment: string
    op: number
    node: number
    epoch: number
    /** The issuer's key as FreeCredits.issuers spells it. */
    issuer: string
}

/**
 * Keeps credits fetched and not yet spent. A lost credit costs only its payer a
 * fetch, so a store need not be durable. One that outlives the page saves a
 * reload its fetches, and the payer's turns their timing.
 */
export interface CreditStore {
    /** Removes one credit kept under key and returns it. */
    take(key: CreditKey): Promise<Credit | undefined>
    put(key: CreditKey, credits: Credit[]): Promise<void>
}

const keyString = (k: CreditKey): string => JSON.stringify([k.deployment, k.op, k.node, k.epoch, k.issuer])
const nodeKey = (n: { op: number; node: number }): string => `${n.op}:${n.node}`

// Resolves true once p settles, or false when signal aborts first.
function raceAbort(p: Promise<void>, signal: AbortSignal | undefined): Promise<boolean> {
    if (signal === undefined) return p.then(() => true)
    if (signal.aborted) return Promise.resolve(false)
    return new Promise((resolve) => {
        const onAbort = () => resolve(false)
        signal.addEventListener('abort', onAbort, { once: true })
        void p.then(() => {
            signal.removeEventListener('abort', onAbort)
            resolve(!signal.aborted)
        })
    })
}

/** A CreditStore in memory. It forgets each day's credits once a later day's are put. */
export function memoryCreditStore(): CreditStore {
    const credits = new Map<string, { epoch: number; credits: Credit[] }>()
    return {
        async take(key) {
            const k = keyString(key)
            const e = credits.get(k)
            const c = e?.credits.pop()
            if (e !== undefined && e.credits.length === 0) credits.delete(k)
            return c
        },
        async put(key, cs) {
            // A node accepts yesterday's credits only in the grace after
            // midnight, so anything older is dead weight.
            for (const [k, e] of credits) if (e.epoch + 1 < key.epoch) credits.delete(k)
            const k = keyString(key)
            const e = credits.get(k) ?? { epoch: key.epoch, credits: [] }
            e.credits.push(...cs)
            credits.set(k, e)
        },
    }
}

/** Checks FreeCredits as Go's Config.validate does, or throws a ZsError. */
export function checkFreeCredits(f: FreeCredits | undefined): void {
    if (f === undefined) return
    if (f.issuers === null || typeof f.issuers !== 'object') throw configError('freeCredits.issuers is not set')
    if (f.batch !== undefined && f.batch > MAX_ISSUE_BATCH) {
        throw configError(`freeCredits.batch ${f.batch} is above ${MAX_ISSUE_BATCH}`)
    }
    for (const [k, port] of Object.entries(f.issuers)) {
        try {
            parseIssuerKey(k)
        } catch (err) {
            throw configError(`freeCredits.issuers: ${(err as Error).message}`)
        }
        if (port === undefined || port === null)
            throw configError(`freeCredits.issuers[${JSON.stringify(k)}] is not set`)
    }
}

/**
 * creditIssuersFor is the issuers a reserve for model at op may carry a credit
 * from: the ones the node advertises, on Solana, for a model it prices at
 * nothing. Anything priced, an image route or a priced tool included, is a
 * paid reserve, whose ticket opens on chain and needs no credit. Go's
 * creditIssuersFor.
 */
export function creditIssuersFor(
    rail: Rail | undefined,
    op: Pick<Operator, 'freeCreditIssuers' | 'modelCapacities'>,
    model: string,
): readonly string[] | undefined {
    if (rail !== 'solana' || !op.freeCreditIssuers?.length) return undefined
    const c = Object.hasOwn(op.modelCapacities, model) ? op.modelCapacities[model] : undefined
    if (c === undefined || !pricesNothing(c)) return undefined
    return op.freeCreditIssuers
}

function pricesNothing(c: ModelCapacity): boolean {
    const zero = (v: number | undefined) => v === undefined || v === 0
    const tools = Object.values(c.toolCallRatesMicroUsdc ?? {}).every((r) => r === 0)
    return (
        c.inputUsdPer1m === 0 &&
        c.outputUsdPer1m === 0 &&
        zero(c.cacheReadUsdPer1m) &&
        zero(c.longContextInputUsdPer1m) &&
        zero(c.longContextOutputUsdPer1m) &&
        zero(c.longContextCacheReadUsdPer1m) &&
        !servesImageGen(c) &&
        !servesImageEdit(c) &&
        c.imageToolRateMicroUsdc === 0 &&
        c.imageEditToolRateMicroUsdc === 0 &&
        tools &&
        c.vendorToolCatchAllMicroUsdc === 0
    )
}

/** A credit a reserve carries. It goes back to the store unless the turn reached the node or the node refused the credit itself. */
export class HeldCredit {
    #done = false
    constructor(
        private readonly wallet: CreditWallet,
        readonly key: CreditKey,
        readonly credit: Credit,
    ) {}

    /** The sealed turn is on its way to the node, which consumes it. */
    spend(): void {
        this.#done = true
    }

    /** Discards a credit the node refused. */
    drop(): void {
        this.#done = true
    }

    /** Returns an unused credit to the store, for the node's next turn. */
    async giveBack(): Promise<void> {
        if (this.#done) return
        this.#done = true
        // Bounded, so a stuck host store can't hold the turn; the put goes on
        // without it.
        let timer: ReturnType<typeof setTimeout> | undefined
        await Promise.race([
            this.wallet.keep(this.key, [this.credit], 'free credit could not be kept for the next turn'),
            new Promise<void>((r) => (timer = setTimeout(r, this.wallet.fetchTimeout))),
        ])
        clearTimeout(timer)
    }
}

interface IssuerState {
    key: Uint8Array
    port: CreditIssuer
    skipUntil: number
    /** The verified day key per epoch: a payer blinds every credit of a day to the one key it fetched first. */
    dayKeys: Map<number, DayKey>
}

/**
 * CreditWallet fetches credits on demand, a node at a time, and holds them
 * until a reserve carries one. Go's creditWallet.
 */
export class CreditWallet {
    readonly #deployment: Uint8Array
    readonly #deploymentB64: string
    readonly #issuers = new Map<string, IssuerState>()
    readonly #store: CreditStore
    readonly #batch: number
    readonly #clock: Clock
    readonly #logger: Logger
    readonly #flights = new Map<string, Promise<void>>()
    /**
     * The day each node last refused a credit on. It is sent none for the rest
     * of that day: a node that won't take this payer's credits, with a clock
     * past the grace or an issuer it no longer trusts, or that answers refusals
     * to burn them, costs one or two credits a day, not a batch a turn.
     */
    readonly #refused = new Map<string, number>()
    /** FREE_CREDIT_DEFAULTS.fetchTimeout, shorter in tests. */
    fetchTimeout: number = FREE_CREDIT_DEFAULTS.fetchTimeout

    constructor(cfg: FreeCredits, deployment: Uint8Array, clock: Clock, logger: Logger) {
        this.#deployment = deployment
        this.#deploymentB64 = base64.encode(deployment)
        this.#store = cfg.store ?? memoryCreditStore()
        this.#batch = cfg.batch !== undefined && cfg.batch > 0 ? cfg.batch : FREE_CREDIT_DEFAULTS.batch
        this.#clock = clock
        this.#logger = logger
        for (const [k, port] of Object.entries(cfg.issuers)) {
            this.#issuers.set(k, { key: parseIssuerKey(k), port, skipUntil: 0, dayKeys: new Map() })
        }
    }

    /**
     * A wallet for cfg on deployment, or undefined when cfg names no issuer, the
     * rail is not Solana, or the deployment is unknown: a credit is minted for
     * one deployment.
     */
    static for(
        cfg: FreeCredits | undefined,
        rail: Rail | undefined,
        deployment: Uint8Array | undefined,
        clock: Clock,
        logger: Logger,
    ): CreditWallet | undefined {
        if (cfg === undefined || Object.keys(cfg.issuers).length === 0 || rail !== 'solana' || deployment === undefined)
            return undefined
        if (deployment.every((b) => b === 0)) return undefined
        return new CreditWallet(cfg, deployment, clock, logger)
    }

    /** When the issuer is skipped until, in unix ms; 0 when it isn't. For tests. */
    skippedUntil(issuer: string): number {
        return this.#issuers.get(issuer)?.skipUntil ?? 0
    }

    /**
     * A credit for node from the first of issuers that has one, kept or fetched
     * now, or undefined. Undefined is never an error: the reserve goes out
     * without a credit and the node serves it on its own budget.
     */
    async take(
        issuers: readonly string[],
        node: { op: number; node: number },
        signal?: AbortSignal,
    ): Promise<HeldCredit | undefined> {
        if (issuers.length === 0) return undefined
        const epoch = epochAt(this.#clock())
        if (this.#refused.get(nodeKey(node)) === epoch) return undefined
        for (const k of issuers) {
            const is = this.#issuers.get(k)
            if (is === undefined) continue
            const key: CreditKey = { deployment: this.#deploymentB64, op: node.op, node: node.node, epoch, issuer: k }
            const kept = await this.#stored(key)
            if (kept !== undefined) return kept
            const fetched = await this.#fetch(is, key, signal)
            if (fetched !== undefined) return fetched
        }
        return undefined
    }

    /** Sends node no credit for the rest of today. */
    refuse(node: { op: number; node: number }): void {
        this.#refused.set(nodeKey(node), epochAt(this.#clock()))
    }

    async keep(key: CreditKey, credits: Credit[], what: string): Promise<void> {
        try {
            await this.#store.put(key, credits)
        } catch (err) {
            this.#logger.warn(what, { err: (err as Error).message })
        }
    }

    async #stored(key: CreditKey): Promise<HeldCredit | undefined> {
        let c: Credit | undefined
        try {
            c = await this.#store.take(key)
        } catch (err) {
            this.#logger.warn('free credit store could not be read', { err: (err as Error).message })
            return undefined
        }
        return c === undefined ? undefined : new HeldCredit(this, key, c)
    }

    // One fetch per key at a time: a turn that finds one running waits for it
    // and takes from what it kept.
    async #fetch(is: IssuerState, key: CreditKey, signal?: AbortSignal): Promise<HeldCredit | undefined> {
        if (this.#clock() < is.skipUntil) return undefined
        const k = keyString(key)
        const running = this.#flights.get(k)
        if (running !== undefined) {
            if (!(await raceAbort(running, signal))) return undefined
            return this.#stored(key)
        }
        let done!: () => void
        this.#flights.set(k, new Promise<void>((r) => (done = r)))
        try {
            let credits: Credit[]
            try {
                credits = await this.#mint(is, key, signal)
            } catch (err) {
                if (signal?.aborted) return undefined
                this.#skip(is, err)
                return undefined
            }
            if (credits.length > 1)
                await this.keep(key, credits.slice(1), 'free credits could not be kept for later turns')
            return new HeldCredit(this, key, credits[0]!)
        } finally {
            this.#flights.delete(k)
            done()
        }
    }

    // Benches is after err: until the issuer's Retry-After once its cap is
    // spent, else the failure backoff.
    #skip(is: IssuerState, err: unknown): void {
        const now = this.#clock()
        let wait: number = FREE_CREDIT_DEFAULTS.failureBackoff
        if (err instanceof CreditsExhaustedError) {
            // The cap counts per day, so with no hint it holds until the next.
            wait = err.retryAfterMs > 0 ? Math.min(err.retryAfterMs, DAY_MS) : epochStartMs(epochAt(now) + 1) - now
            wait = Math.max(wait, FREE_CREDIT_DEFAULTS.failureBackoff)
        }
        is.skipUntil = now + wait
        this.#logger.info('free credit issuer skipped; turns go without its credits meanwhile', {
            for_ms: wait,
            err: err instanceof Error ? err.message : String(err),
        })
    }

    async #mint(is: IssuerState, key: CreditKey, signal?: AbortSignal): Promise<Credit[]> {
        const timeout = AbortSignal.timeout(this.fetchTimeout)
        const sig = signal === undefined ? timeout : AbortSignal.any([signal, timeout])
        const dk = await this.#dayKey(is, key.epoch, sig)
        const node = { op: key.op, node: key.node }
        const blinded: Uint8Array[] = []
        const pending: PendingCredit[] = []
        for (let i = 0; i < this.#batch; i++) {
            const b = await blindCredit(dk, this.#deployment, node)
            blinded.push(b.blinded)
            pending.push(b.pending)
        }
        const sigs = await is.port.issue(this.#deployment, key.epoch, blinded, sig)
        if (sigs.length > blinded.length)
            throw new Error(`free credit issuer: ${sigs.length} signatures for ${blinded.length} messages`)
        const out: Credit[] = []
        for (const [i, s] of sigs.entries()) {
            // finalize verifies, so a signature under another key is never kept.
            try {
                out.push(await pending[i]!.finalize(s))
            } catch (err) {
                throw new Error(`free credit issuer: signature ${i}: ${(err as Error).message}`, { cause: err })
            }
        }
        if (out.length === 0) throw new Error('free credit issuer: signed none')
        return out
    }

    async #dayKey(is: IssuerState, epoch: number, signal: AbortSignal): Promise<DayKey> {
        const kept = is.dayKeys.get(epoch)
        if (kept !== undefined) return kept
        const cert = await is.port.dayKey(this.#deployment, epoch, signal)
        if (cert?.epoch !== epoch)
            throw new Error(`free credit issuer: day key for epoch ${cert?.epoch}, asked for ${epoch}`)
        let dk: DayKey
        try {
            dk = await verifyDayKey([is.key], this.#deployment, cert)
        } catch (err) {
            throw new Error(`free credit issuer: day key: ${(err as Error).message}`, { cause: err })
        }
        // A concurrent fetch for another node got there first; keep one key.
        const raced = is.dayKeys.get(epoch)
        if (raced !== undefined) return raced
        for (const e of is.dayKeys.keys()) if (e + 1 < epoch) is.dayKeys.delete(e)
        is.dayKeys.set(epoch, dk)
        return dk
    }
}
