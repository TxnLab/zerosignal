/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The real chain step: Intel's PCK chain, checked by @phala/dcap-qvl against
// collateral fetched from a PCCS or carried by the node. Mirrors
// VerifyTDXQuoteChain, cachingGetter and VerifyTDXQuoteChainCarried in
// proto/go/zs/tee; the caching and outage rules are the browser client's,
// which reach the same verdicts through a library that has no getter seam.
//
// dcap-qvl bundles Intel's root CA, so every document is checked against a
// pinned anchor. That does not reduce the PCCS to an availability dependency:
// it chooses which Intel-signed vintage to serve, and a CRL or TCB info from
// before a revocation still verifies inside its nextUpdate window, so a
// revoked platform can pass with no outage anywhere. Go fetches from Intel's
// PCS directly. The default here is Phala's mirror, so a payer on the default
// trusts Phala for the currency of the documents. The mirror sends CORS
// headers (since 2026-10-31) and Intel's PCS does not, so a browser payer on
// Intel's URL, or on the mirror while it is down, fails every fetch as an
// outage and its verdicts rest on the node's carried collateral under attest's
// collateralFreshEnough.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { TEECollateral } from '@txnlab/zs-proto/inject'

import type { Clock } from '../ports.js'
import { CollateralUnavailableError, StaleCollateralRejectedError } from './errors.js'
import type { CarriedChainVerifier, ChainResult, QuoteChainVerifier } from './types.js'

/**
 * Bounds one verification's PCCS traffic. Mirrors Go's CollateralTimeout, so a
 * marginal network produces the same verdict in both SDKs. getCollateral makes
 * several round trips and has no deadline of its own.
 */
export const COLLATERAL_TIMEOUT_MS = 8_000

/**
 * How long fetched collateral is reused before a re-fetch. Mirrors Go's
 * collateralTTL. A cached document is re-checked against the pinned root on
 * every use, but it can have been superseded: for up to this long a
 * revocation Intel has since published is not seen, and that is what this
 * bounds. It can also make a good quote fail when the node moved platform,
 * which is why a refusal on fresh cached collateral is followed by a re-fetch.
 */
export const COLLATERAL_TTL_MS = 60 * 60_000

/**
 * How far past its fetch a cached entry may be served when the PCCS cannot be
 * reached. Mirrors Go's collateralStaleMax. Tried before the node's carried
 * set because we fetched this vintage and the operator did not choose it.
 * dcap-qvl still enforces each document's own validity window on top.
 */
export const COLLATERAL_STALE_MAX_MS = 7 * 24 * 60 * 60_000

export interface PccsChainVerifierOptions {
    /** Defaults to dcap-qvl's PHALA_PCCS_URL; see the file header for what that trusts. */
    pccsUrl?: string
    timeoutMs?: number
    /** Unix milliseconds. */
    now?: Clock
    /** false fetches on every verification. */
    cache?: boolean
}

/**
 * Fetches collateral from a PCCS and verifies the quote against it, falling
 * back to this verifier's own cache during an outage. Only the fetch is
 * classified: a throw out of the verification is a refusal and propagates as
 * it is, so forged evidence never reads as an outage.
 *
 * Deliberate differences from Go:
 *  - A PCCS that answers with a non-outage status (404 included) is a
 *    refusal, not an outage. The FMSPC that selects the document comes from
 *    the node's own quote, so calling it an outage would let a node on an
 *    unpublished platform reach its own collateral. Go calls any non-200 an
 *    outage.
 *  - A refusal on fresh cached collateral re-fetches before it is the
 *    answer, since the node may have moved platform. Go answers from the
 *    cache.
 *  - The cache lives in memory, in this verifier only. Go persists its cache
 *    (collateral_store.go), so a restart keeps it; here a reload or a second
 *    verifier starts cold, and an outage before the first successful fetch
 *    judges every node on its own carried set. Build one verifier and reuse it.
 */
export function pccsChainVerifier(opts: PccsChainVerifierOptions = {}): QuoteChainVerifier {
    const timeoutMs = opts.timeoutMs ?? COLLATERAL_TIMEOUT_MS
    const now = opts.now ?? Date.now
    // Per verifier, so two verifiers never share an entry and a test needs no
    // reset hook. Two concurrent verifications of one platform may both
    // fetch, and a slow one may report a refusal from an entry its twin has
    // just refreshed; both fail closed, so neither is guarded against.
    const cache = opts.cache === false ? undefined : new Map<string, CacheEntry>()

    return async (quote, signal) => {
        let qvl: Qvl
        try {
            qvl = await loadQvl()
        } catch (err) {
            throw new CollateralUnavailableError(err)
        }
        const pccsUrl = opts.pccsUrl ?? qvl.PHALA_PCCS_URL
        const attempt = (collateral: unknown): ChainResult =>
            chainResult(qvl.verify(quote, collateral, Math.floor(now() / 1000)))

        const slot = cache === undefined ? undefined : cacheSlot(qvl, pccsUrl, quote)
        const usable = slot === undefined ? undefined : cache?.get(slot)
        const quoteId = slot === undefined ? '' : bytesToHex(sha256(quote))
        const refusedHere = usable !== undefined && usable.refused.has(quoteId)

        // A negative age is not freshness: a clock stepped backwards would
        // otherwise skip the re-fetch and never reach the stale bound, so
        // both bounds go off at once. Mirrors Go's `age >= 0`. An aborted
        // call skips the serve, as Go's getter refuses every Get on a
        // cancelled context.
        const freshAge = usable === undefined ? Number.NaN : now() - usable.at
        let freshRefusal: unknown
        if (usable !== undefined && !refusedHere && freshAge >= 0 && freshAge < COLLATERAL_TTL_MS
            && signal?.aborted !== true) {
            try {
                return attempt(usable.collateral)
            } catch (rejected) {
                freshRefusal = rejected
                // Kept, not evicted. Collateral describes a platform, so the
                // refusal may be about the one we cached and is re-checked by
                // the fetch below. But if that fetch fails, our own
                // Intel-signed document has said no, and an eviction would
                // turn that into a plain outage, which hands the quote to the
                // node's own collateral (SPEC § 3e rule 2).
                markRefused(usable, quoteId)
            }
        }

        let collateral: unknown
        try {
            collateral = await bounded(() => qvl.getCollateral(pccsUrl, quote), timeoutMs, signal)
        } catch (err) {
            // Rethrown as it is: a PCCS that answered is not one that is down.
            if (!isCollateralServiceOutage(err)) throw err
            // No `>= 0` here, unlike the fresh arm: the fetch has already
            // failed, so refusing a clock-stepped entry would take every node
            // out over a clock step. Clamped to say so. Past the stale bound
            // an entry answers nothing, refusal included, as Go's cache does
            // not serve it.
            const staleAge = usable === undefined ? Number.NaN : Math.max(0, now() - usable.at)
            if (usable !== undefined && staleAge < COLLATERAL_STALE_MAX_MS) {
                // Our cache already answered no, here or on an earlier call;
                // only a refusal made here has a verdict to report.
                if (usable.refused.has(quoteId)) throw new StaleCollateralRejectedError(err, freshRefusal)
                if (!(err instanceof CollateralAbortError)) {
                    let result: ChainResult
                    try {
                        result = attempt(usable.collateral)
                    } catch (rejected) {
                        markRefused(usable, quoteId)
                        throw new StaleCollateralRejectedError(err, rejected)
                    }
                    return { ...result, servedStale: true }
                }
            }
            throw new CollateralUnavailableError(err)
        }
        // Seated whatever the verdict, as Go caches every successful fetch. A
        // refusal on current documents is the strongest answer there is, and
        // without an entry the next outage would report "we could not check"
        // and hand the quote to the node's own collateral.
        const entry: CacheEntry = { at: now(), collateral: platformOnly(collateral), refused: new Set() }
        let out: ChainResult
        try {
            out = attempt(collateral)
        } catch (rejected) {
            if (slot !== undefined) {
                markRefused(entry, quoteId)
                cache?.set(slot, entry)
            }
            throw rejected
        }
        if (slot !== undefined) cache?.set(slot, entry)
        return out
    }
}

export interface CarriedChainVerifierOptions {
    /** Unix milliseconds. */
    now?: Clock
}

/**
 * Verifies a quote against the collateral the node carried, fetching nothing.
 * The last resort, and it has no fallback of its own: asking yet another
 * source after a refusal is how a verifier talks itself into a pass.
 * DstackVerifier refuses an aborted call before reaching any carried
 * verifier; the check here is for a host calling this directly.
 */
export function carriedChainVerifier(opts: CarriedChainVerifierOptions = {}): CarriedChainVerifier {
    const now = opts.now ?? Date.now
    return async (quote: Uint8Array, collateral: TEECollateral, signal?: AbortSignal): Promise<ChainResult> => {
        if (signal?.aborted === true) throw new CollateralAbortError(signal.reason)
        const qvl = await loadQvl()
        return chainResult(qvl.verify(quote, collateralMembers(collateral), Math.floor(now() / 1000)))
    }
}

const COLLATERAL_MEMBERS = [
    'pck_crl_issuer_chain',
    'root_ca_crl',
    'pck_crl',
    'tcb_info_issuer_chain',
    'tcb_info',
    'tcb_info_signature',
    'qe_identity_issuer_chain',
    'qe_identity',
    'qe_identity_signature',
] as const satisfies readonly (keyof TEECollateral)[]

/**
 * The nine members and nothing else, values untouched (the wire shape is the
 * library's). A set parsed straight from a bundle could carry a
 * pck_certificate_chain, which dcap-qvl would verify against in place of the
 * quote's own.
 */
function collateralMembers(c: TEECollateral): TEECollateral {
    const out: Partial<Record<keyof TEECollateral, string>> = {}
    for (const k of COLLATERAL_MEMBERS) out[k] = c[k]
    return out as TEECollateral
}

interface CacheEntry {
    at: number
    /** The platform's documents, with nothing particular to the quote that fetched them. */
    collateral: unknown
    /**
     * SHA-256s of the quotes this document refused. Only an optimisation: the
     * mark is consulted only where an unmarked quote would be judged by the
     * same document, and verification is deterministic for a quote, document
     * and clock, so it spares re-running a verdict already reached. It can
     * differ only where a clock step would reverse that verdict, and then it
     * errs toward refusal; under an abort it changes only which error reports
     * the outcome, since DstackVerifier refuses the carried rung either way.
     * Per quote because an entry is shared by every machine with this FMSPC,
     * and one node's refusal must not change how another's quote is judged.
     */
    refused: Set<string>
}

// Bounds what forged quotes can make an entry hold. Dropping a mark costs one
// re-verification, which reaches the same refusal.
const MAX_REFUSED_PER_ENTRY = 256

function markRefused(entry: CacheEntry, quoteId: string): void {
    if (entry.refused.size >= MAX_REFUSED_PER_ENTRY) {
        const oldest = entry.refused.values().next().value
        if (oldest !== undefined) entry.refused.delete(oldest)
    }
    entry.refused.add(quoteId)
}

/**
 * The fetched set without pck_certificate_chain, which getCollateral copies
 * out of the quote that asked. dcap-qvl verifies against that chain in
 * preference to the quote's own, so a cached copy carrying it would judge
 * every later quote on the platform by the first one's certificate.
 */
function platformOnly(collateral: unknown): unknown {
    if (typeof collateral !== 'object' || collateral === null || !('pck_certificate_chain' in collateral)) {
        return collateral
    }
    const { pck_certificate_chain: _quoteOwn, ...platform } = collateral as Record<string, unknown>
    return platform
}

/** The slice of @phala/dcap-qvl used here. verify takes Unix SECONDS. */
interface Qvl {
    verify(quote: Uint8Array, collateral: unknown, nowSecs: number): { status: unknown; advisory_ids?: string[] | null }
    getCollateral(pccsUrl: string, quote: Uint8Array): Promise<unknown>
    PHALA_PCCS_URL: string
    Quote: { parse(quote: Uint8Array): ParsedQuote }
    intel: { getFmspc(quote: ParsedQuote): Uint8Array; getCa(quote: ParsedQuote): string }
}

interface ParsedQuote {
    header: { teeType: number }
}

// How long a failed import is held before it is retried. It must outlast one
// verification: a failure is an outage to the first rung, and a carried rung
// that re-imported successfully would judge the quote on the node's documents
// without our cache ever having been consulted.
const LOAD_FAILURE_HOLD_MS = 60_000

let qvlLoad: { promise: Promise<Qvl>; failedAt?: number } | undefined

// Lazy, so a host that never meets a TEE node never loads the library. It is
// CommonJS: Node's ESM loader puts module.exports on `default`, a bundler may
// not. A failure is retried after the hold, so a browser's failed chunk fetch
// does not last the life of the page.
function loadQvl(): Promise<Qvl> {
    if (qvlLoad?.failedAt !== undefined) {
        const age = Date.now() - qvlLoad.failedAt
        if (!(age >= 0 && age < LOAD_FAILURE_HOLD_MS)) qvlLoad = undefined
    }
    if (qvlLoad === undefined) {
        const load: { promise: Promise<Qvl>; failedAt?: number } = { promise: Promise.resolve() as never }
        load.promise = import('@phala/dcap-qvl').then(
            (m) => {
                const mod = m as unknown as Qvl & { default?: Qvl }
                return mod.default ?? mod
            },
            (err: unknown) => {
                load.failedAt = Date.now()
                throw err
            },
        )
        qvlLoad = load
    }
    return qvlLoad.promise
}

function chainResult(r: { status: unknown; advisory_ids?: string[] | null }): ChainResult {
    return { tcbStatus: String(r.status), advisoryIds: r.advisory_ids ?? [] }
}

const FMSPC_LEN = 6

/**
 * The cache slot: the PCCS, the TEE type, and the FMSPC and CA type of the
 * quote's leaf PCK certificate, read by the same dcap-qvl functions
 * getCollateral selects documents by. So the slot names exactly the documents
 * a fetch would return, as Go's artifact-URL key does. Not the chain's bytes:
 * those sit outside the quote's signature, and a node could pad them into a
 * fresh, empty slot and turn our cached refusal into an outage. The FMSPC and
 * CA are fields of an Intel-signed certificate. Undefined, so uncached, when
 * they cannot be read. That includes a quote carrying no PCK chain (cert type
 * 2 or 3), for which dcap-qvl fetches the certificate on every call; the
 * traffic is bounded by the probe rate.
 */
function cacheSlot(qvl: Qvl, pccsUrl: string, quote: Uint8Array): string | undefined {
    try {
        const parsed = qvl.Quote.parse(quote)
        const fmspc = Uint8Array.from(qvl.intel.getFmspc(parsed))
        if (fmspc.length !== FMSPC_LEN) return undefined
        const ca = qvl.intel.getCa(parsed)
        return `${pccsUrl}|${parsed.header.teeType}|${bytesToHex(fmspc).toUpperCase()}|${ca}`
    } catch {
        return undefined
    }
}

/** Our own deadline, a type so the outage test needs no message match. */
class CollateralTimeoutError extends Error {
    constructor(ms: number) {
        super(`timed out after ${ms}ms`)
        this.name = 'CollateralTimeoutError'
    }
}

/** The caller gave up. An outage to the classifier, but never a stale serve. */
class CollateralAbortError extends Error {
    constructor(reason: unknown) {
        super(`aborted: ${String(reason)}`, { cause: reason })
        this.name = 'CollateralAbortError'
    }
}

// getCollateral takes no signal, so this bounds how long we WAIT; the request
// itself runs on.
function bounded<T>(start: () => Promise<T>, ms: number, signal: AbortSignal | undefined): Promise<T> {
    if (signal?.aborted === true) return Promise.reject(new CollateralAbortError(signal.reason))
    const p = start()
    let timer: ReturnType<typeof setTimeout> | undefined
    let onAbort: (() => void) | undefined
    const stop = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new CollateralTimeoutError(ms)), ms)
        onAbort = () => reject(new CollateralAbortError(signal?.reason))
        signal?.addEventListener('abort', onAbort, { once: true })
    })
    return Promise.race([p, stop]).finally(() => {
        clearTimeout(timer)
        if (onAbort !== undefined) signal?.removeEventListener('abort', onAbort)
    })
}

/**
 * dcap-qvl's report of a PCCS that answered with a non-200: "Failed to fetch
 * TCB info: 404", or "... from <url>: 404". Judged by the status alone.
 */
const QVL_HTTP_STATUS = /^Failed to fetch .*: (\d{3})$/

/**
 * What fetch rejects with when no response arrived, per engine: Chrome,
 * undici, Safari, Firefox, React Native. Only these make a TypeError an
 * outage: a TypeError is also what parsing a 200 with a missing field throws.
 */
const FETCH_NETWORK_FAILURE = /^(failed to fetch|fetch failed|load failed|networkerror\b|network request failed)/i

/** A Node socket error surfaced as a plain Error: "connect ECONNREFUSED 10.0.0.1:443". */
const TRANSPORT_FAILURE = /^(connect|getaddrinfo|read|write) (ECONNREFUSED|ECONNRESET|ENOTFOUND|ETIMEDOUT|EAI_AGAIN)\b/

/**
 * Whether a fetch failure is about the PCCS's health rather than this
 * platform. Only an outage may reach the node's carried collateral: the
 * FMSPC in a 404'd URL comes from the node's own quote, so treating "the
 * mirror answered 404" as an outage would let a node on an unpublished
 * platform earn the fallback deterministically. An unrecognized failure is
 * therefore a refusal.
 */
function isCollateralServiceOutage(err: unknown): boolean {
    if (err instanceof CollateralTimeoutError || err instanceof CollateralAbortError) return true
    const msg = String(err instanceof Error ? err.message : err)
    const status = QVL_HTTP_STATUS.exec(msg)
    if (status !== null) {
        const code = Number(status[1])
        return code === 429 || (code >= 500 && code <= 599)
    }
    if (err instanceof TypeError) return FETCH_NETWORK_FAILURE.test(msg)
    return TRANSPORT_FAILURE.test(msg)
}
