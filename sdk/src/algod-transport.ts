/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The algod transport the SDK builds its chain client on: algosdk's
// BaseHTTPClient with go/algod's RetryRoundTripper (transport.go) inside it.
// Hosted algod providers answer bursts with 429 and restarts with 503, and a
// chain read that fails on the first one fails a whole discovery cycle or a
// payer's escrow open. The budget, which outcomes retry and the wait before
// each retry, Retry-After included, are pinned by
// testdata/algod_retry_vectors.json.
//
// Differences from Go:
//   - The wait is bounded by the request's signal, which the SDK's chain calls
//     set to their per-request timeout as well as the caller's signal. Go
//     bounds a read only by its context, which the caller sets. A read that
//     carries no caller signal (the escrow chain's account and free-quota
//     reads, and its shared config reads after start-up) is bounded only by
//     that timeout. The wait's timer holds a Node process open, as a request
//     a caller awaits must: an unref'd one let `await Client.create(...)`
//     end the process mid-retry with the promise unsettled. Client.create's
//     own config reads run under its signal (refreshConfig), so they don't
//     outlive it.
//   - Retry lines go to the logger the transport is given (a Client's
//     Config.logger), not to a process-wide default as Go's slog.Default();
//     a logger that throws is ignored rather than ending the retry.
//   - In a browser, Retry-After is unreadable on a cross-origin algod unless
//     it sends Access-Control-Expose-Headers naming it, so the linear
//     schedule applies.
//   - A Retry-After HTTP-date with a zone abbreviation other than GMT or UTC
//     reads as UTC. Go first looks the abbreviation up in the machine's local
//     zone, so there the answer depends on the machine.
//   - A response carrying Retry-After more than once reads as no Retry-After:
//     fetch joins the values with ", ", where Go reads the first.
//   - Every body is a Uint8Array, so every request can be replayed; Go refuses
//     to retry one whose body can't be.
//   - A non-2xx answer throws as algosdk's own client does, but with the
//     response headers keyed by name: algosdk 3.6 builds that map inverted.

import algosdk from 'algosdk'

import { quietLogger } from './log.js'
import { type Fetch, type Logger, discardLogger } from './ports.js'
import { sleep } from './sleep.js'

/** ALGOD_MAX_RETRIES is how many retries follow the first attempt, Go's DefaultTransport MaxRetries. */
export const ALGOD_MAX_RETRIES = 20
/** ALGOD_RETRY_WAIT_MIN_MS is the wait before the first retry and the step each later one adds. */
export const ALGOD_RETRY_WAIT_MIN_MS = 1_000
/** ALGOD_RETRY_WAIT_MAX_MS caps every wait, a server's Retry-After included. */
export const ALGOD_RETRY_WAIT_MAX_MS = 30_000

/**
 * algodShouldRetry is whether an outcome is retried: a transport failure
 * (status undefined), a 429, or any 5xx. Go's shouldRetry.
 */
export function algodShouldRetry(status: number | undefined): boolean {
    if (status === undefined) return true
    return status === 429 || (status >= 500 && status <= 599)
}

/**
 * algodBackoffMs is the wait before the retry that follows attempt (0-based):
 * linear in minMs, capped at maxMs, and raised to a longer Retry-After (also
 * capped) read at nowMs. Go's backoff.
 */
export function algodBackoffMs(
    attempt: number,
    retryAfter: string | null | undefined,
    nowMs: number,
    minMs: number = ALGOD_RETRY_WAIT_MIN_MS,
    maxMs: number = ALGOD_RETRY_WAIT_MAX_MS,
): number {
    // In nanoseconds, as Go's Durations are, so its int64 arithmetic carries over.
    const min = msToNs(minMs)
    const max = msToNs(maxMs)
    let wait = BigInt.asIntN(64, BigInt(attempt + 1) * min)
    if (wait > max) wait = max
    let ra = retryAfterNs(retryAfter ?? '', msToNs(nowMs))
    if (ra > wait) {
        if (ra > max) ra = max
        wait = ra
    }
    return Number(wait) / 1e6
}

// Whole milliseconds converted exactly: a Unix time in ns is past 2^53.
function msToNs(ms: number): bigint {
    const whole = Math.trunc(ms)
    return BigInt(whole) * 1_000_000n + BigInt(Math.round((ms - whole) * 1e6))
}

const NS_PER_SEC = 1_000_000_000n
const INT64_MAX = (1n << 63n) - 1n

// Go's retryAfter: a count of seconds as strconv.Atoi reads one, or an
// HTTP-date as http.ParseTime reads one; anything else is no wait.
function retryAfterNs(v: string, nowNs: bigint): bigint {
    if (v === '') return 0n
    const secs = atoi64(v)
    // time.Duration(secs) * time.Second, wrapping as Go's int64 does.
    if (secs !== undefined && secs >= 0n) return BigInt.asIntN(64, secs * NS_PER_SEC)
    const t = parseHttpTime(v)
    if (t !== undefined) {
        const d = t - nowNs
        if (d > 0n) return d
    }
    return 0n
}

// strconv.Atoi: an optional sign, then decimal digits, within int64.
function atoi64(s: string): bigint | undefined {
    if (!/^[+-]?[0-9]+$/.test(s)) return undefined
    const n = BigInt(s.startsWith('+') ? s.slice(1) : s)
    return n > INT64_MAX || n < -INT64_MAX - 1n ? undefined : n
}

// ---- http.ParseTime ----

type Std = 'weekday' | 'longWeekday' | 'month' | 'zeroDay' | 'underDay' | 'longYear' | 'year' | 'hour' | 'zeroMinute' | 'zeroSecond' | 'tz'
type Chunk = Std | { lit: string }

// http.TimeFormat, time.RFC850 and time.ANSIC, in the order http.ParseTime tries them.
const LAYOUTS: Chunk[][] = [
    ['weekday', { lit: ', ' }, 'zeroDay', { lit: ' ' }, 'month', { lit: ' ' }, 'longYear', { lit: ' ' }, 'hour', { lit: ':' }, 'zeroMinute', { lit: ':' }, 'zeroSecond', { lit: ' GMT' }],
    ['longWeekday', { lit: ', ' }, 'zeroDay', { lit: '-' }, 'month', { lit: '-' }, 'year', { lit: ' ' }, 'hour', { lit: ':' }, 'zeroMinute', { lit: ':' }, 'zeroSecond', { lit: ' ' }, 'tz'],
    ['weekday', { lit: ' ' }, 'month', { lit: ' ' }, 'underDay', { lit: ' ' }, 'hour', { lit: ':' }, 'zeroMinute', { lit: ':' }, 'zeroSecond', { lit: ' ' }, 'longYear'],
]

const SHORT_DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const LONG_DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
const SHORT_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** parseHttpTime is the instant v names in Unix nanoseconds, or undefined, as Go's http.ParseTime reads it. */
function parseHttpTime(v: string): bigint | undefined {
    for (const layout of LAYOUTS) {
        const t = parseLayout(layout, v)
        if (t !== undefined) return t
    }
    return undefined
}

// Go's time.Parse for one of the layouts above, which name no zone offset, so
// the wall time is UTC.
function parseLayout(layout: Chunk[], value: string): bigint | undefined {
    let year = 0
    let month = 0
    let day = 0
    let hour = 0
    let min = 0
    let sec = 0
    let nsec = 0n
    let rest = value
    for (const chunk of layout) {
        if (typeof chunk === 'object') {
            const r = skip(rest, chunk.lit)
            if (r === undefined) return undefined
            rest = r
            continue
        }
        switch (chunk) {
            case 'weekday':
            case 'longWeekday': {
                const r = lookup(chunk === 'weekday' ? SHORT_DAYS : LONG_DAYS, rest)
                if (r === undefined) return undefined
                rest = r.rest
                break
            }
            case 'month': {
                const r = lookup(SHORT_MONTHS, rest)
                if (r === undefined) return undefined
                month = r.index + 1
                rest = r.rest
                break
            }
            case 'zeroDay':
            case 'underDay': {
                if (chunk === 'underDay' && rest.startsWith(' ')) rest = rest.slice(1)
                const r = getnum(rest, chunk === 'zeroDay')
                if (r === undefined) return undefined
                ;[day, rest] = [r.n, r.rest]
                break
            }
            case 'longYear': {
                if (rest.length < 4 || !isDigit(rest, 0)) return undefined
                const y = atoi(rest.slice(0, 4))
                if (y === undefined) return undefined
                ;[year, rest] = [y, rest.slice(4)]
                break
            }
            case 'year': {
                if (rest.length < 2) return undefined
                const y = atoi(rest.slice(0, 2))
                if (y === undefined) return undefined
                year = y >= 69 ? y + 1900 : y + 2000
                rest = rest.slice(2)
                break
            }
            case 'hour': {
                const r = getnum(rest, false)
                if (r === undefined || r.n >= 24) return undefined
                ;[hour, rest] = [r.n, r.rest]
                break
            }
            case 'zeroMinute': {
                const r = getnum(rest, true)
                if (r === undefined || r.n >= 60) return undefined
                ;[min, rest] = [r.n, r.rest]
                break
            }
            case 'zeroSecond': {
                const r = getnum(rest, true)
                if (r === undefined || r.n >= 60) return undefined
                ;[sec, rest] = [r.n, r.rest]
                // A fractional second the layout does not name is still read.
                if (rest.length >= 2 && (rest[0] === '.' || rest[0] === ',') && isDigit(rest, 1)) {
                    let n = 2
                    while (n < rest.length && isDigit(rest, n)) n++
                    const digits = rest.slice(1, Math.min(n, 10))
                    nsec = BigInt(digits) * 10n ** BigInt(9 - digits.length)
                    rest = rest.slice(n)
                }
                break
            }
            case 'tz': {
                if (rest.startsWith('UTC')) {
                    rest = rest.slice(3)
                    break
                }
                const n = timeZoneLength(rest)
                if (n === 0) return undefined
                rest = rest.slice(n)
                break
            }
        }
    }
    if (rest !== '') return undefined
    if (day < 1 || day > daysIn(month, year)) return undefined
    const days = BigInt(daysFromCivil(year, month, day))
    return (days * 86_400n + BigInt(hour * 3600 + min * 60 + sec)) * NS_PER_SEC + nsec
}

// Go's skip: a space in the layout matches any run of spaces, or the end.
function skip(value: string, prefix: string): string | undefined {
    let v = value
    let p = prefix
    while (p.length > 0) {
        if (p[0] === ' ') {
            if (v.length > 0 && v[0] !== ' ') return undefined
            p = p.replace(/^ +/, '')
            v = v.replace(/^ +/, '')
            continue
        }
        if (v.length === 0 || v[0] !== p[0]) return undefined
        p = p.slice(1)
        v = v.slice(1)
    }
    return v
}

// Go's lookup: the first name value starts with, ASCII letters matched in either case.
function lookup(tab: readonly string[], value: string): { index: number; rest: string } | undefined {
    for (let i = 0; i < tab.length; i++) {
        const name = tab[i]!
        if (value.length >= name.length && value.slice(0, name.length).toLowerCase() === name.toLowerCase() && /^[A-Za-z]*$/.test(value.slice(0, name.length))) {
            return { index: i, rest: value.slice(name.length) }
        }
    }
    return undefined
}

// Go's getnum: one or two digits, exactly two when fixed.
function getnum(s: string, fixed: boolean): { n: number; rest: string } | undefined {
    if (!isDigit(s, 0)) return undefined
    if (!isDigit(s, 1)) return fixed ? undefined : { n: Number(s[0]), rest: s.slice(1) }
    return { n: Number(s.slice(0, 2)), rest: s.slice(2) }
}

// The time package's atoi: an optional sign, then digits, all of s.
function atoi(s: string): number | undefined {
    const m = /^([+-]?)([0-9]*)$/.exec(s)
    if (m === null) return undefined
    const n = m[2] === '' ? 0 : Number(m[2])
    return m[1] === '-' ? -n : n
}

function isDigit(s: string, i: number): boolean {
    const c = s.charCodeAt(i)
    return c >= 48 && c <= 57
}

// Go's parseTimeZone: how much of value is a zone name, 0 when none.
function timeZoneLength(value: string): number {
    if (value.length < 3) return 0
    if (value.startsWith('ChST') || value.startsWith('MeST')) return 4
    if (value.startsWith('GMT')) return 3 + signedOffsetLength(value.slice(3))
    if (value[0] === '+' || value[0] === '-') return signedOffsetLength(value)
    let upper = 0
    while (upper < 6 && upper < value.length && value[upper]! >= 'A' && value[upper]! <= 'Z') upper++
    switch (upper) {
        case 3:
            return 3
        case 4:
            return value[3] === 'T' || value.startsWith('WITA') ? 4 : 0
        case 5:
            return value[4] === 'T' ? 5 : 0
        default:
            return 0
    }
}

// Go's parseSignedOffset: a sign and an hour count up to 23, or 0.
function signedOffsetLength(value: string): number {
    const m = /^[+-]([0-9]+)/.exec(value)
    if (m === null || Number(m[1]) > 23) return 0
    return m[0].length
}

function daysIn(month: number, year: number): number {
    if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28
    return [31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] ?? 0
}

// Days since 1970-01-01 for a proleptic Gregorian date. Date.UTC maps years
// 0 to 99 onto the 1900s, so it can't stand in.
function daysFromCivil(y: number, m: number, d: number): number {
    const yy = m <= 2 ? y - 1 : y
    const era = Math.floor(yy / 400)
    const yoe = yy - era * 400
    const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
    const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
    return era * 146_097 + doe - 719_468
}

// ---- the transport ----

// algosdk's Query, which its root does not export.
type Query = Record<string, unknown>

export interface AlgodTransportOptions {
    /** The algod base URL, path included. */
    endpoint: string
    /** Sent as X-Algo-API-Token when non-empty. */
    token?: string | undefined
    /**
     * Absent is the runtime's global fetch, read at each request: algod is
     * the host's chosen endpoint, a localnet's included, so the node dial
     * guard in Config.fetch does not apply.
     */
    fetch?: Fetch | undefined
    /** Retry lines are logged at debug. */
    logger?: Logger | undefined
    /** ALGOD_MAX_RETRIES when absent. */
    maxRetries?: number | undefined
    /** ALGOD_RETRY_WAIT_MIN_MS when absent. */
    retryWaitMinMs?: number | undefined
    /** ALGOD_RETRY_WAIT_MAX_MS when absent. */
    retryWaitMaxMs?: number | undefined
}

/** An HTTP failure in the shape algosdk's clients throw and read back. */
export class AlgodHTTPError extends Error {
    constructor(
        message: string,
        readonly response: algosdk.BaseHTTPClientResponse,
    ) {
        super(message)
        this.name = 'AlgodHTTPError'
    }
}

/**
 * RetryingAlgodClient is algosdk's BaseHTTPClient with Go's retrying
 * transport: a transport failure, a 429 or a 5xx is retried up to maxRetries
 * times, waiting the linear schedule or a longer Retry-After, both capped at
 * retryWaitMaxMs. Every method retries, writes included: algod deduplicates a
 * resent transaction by its id. An aborted request signal ends the request at
 * once, also mid-wait.
 */
export class RetryingAlgodClient implements algosdk.BaseHTTPClient {
    readonly #base: URL
    readonly #token: string
    readonly #fetch: Fetch | undefined
    readonly #log: Logger
    readonly #maxRetries: number
    readonly #waitMin: number
    readonly #waitMax: number

    constructor(o: AlgodTransportOptions) {
        this.#base = new URL(o.endpoint.endsWith('/') ? o.endpoint : `${o.endpoint}/`)
        this.#token = o.token ?? ''
        this.#fetch = o.fetch
        this.#log = quietLogger(o.logger ?? discardLogger)
        this.#maxRetries = o.maxRetries ?? ALGOD_MAX_RETRIES
        this.#waitMin = o.retryWaitMinMs ?? ALGOD_RETRY_WAIT_MIN_MS
        this.#waitMax = o.retryWaitMaxMs ?? ALGOD_RETRY_WAIT_MAX_MS
    }

    get(
        relativePath: string,
        query?: Query,
        requestHeaders?: Record<string, string>,
        customOptions?: Record<string, unknown>,
    ): Promise<algosdk.BaseHTTPClientResponse> {
        return this.#send('GET', relativePath, undefined, query, requestHeaders, customOptions)
    }

    post(
        relativePath: string,
        data: Uint8Array,
        query?: Query,
        requestHeaders?: Record<string, string>,
        customOptions?: Record<string, unknown>,
    ): Promise<algosdk.BaseHTTPClientResponse> {
        return this.#send('POST', relativePath, data, query, requestHeaders, customOptions)
    }

    delete(
        relativePath: string,
        data?: Uint8Array,
        query?: Query,
        requestHeaders?: Record<string, string>,
        customOptions?: Record<string, unknown>,
    ): Promise<algosdk.BaseHTTPClientResponse> {
        return this.#send('DELETE', relativePath, data, query, requestHeaders, customOptions)
    }

    async #send(
        method: string,
        relativePath: string,
        body: Uint8Array | undefined,
        query: Query | undefined,
        requestHeaders: Record<string, string> | undefined,
        customOptions: Record<string, unknown> | undefined,
    ): Promise<algosdk.BaseHTTPClientResponse> {
        const url = this.#url(relativePath, query)
        const headers: Record<string, string> = { ...requestHeaders }
        if (this.#token !== '') headers['X-Algo-API-Token'] = this.#token
        const signal = customOptions?.signal as AbortSignal | undefined
        const fetch = this.#fetch ?? globalThis.fetch
        for (let attempt = 0; ; attempt++) {
            let res: Response | undefined
            let err: unknown
            try {
                res = await fetch(url, { ...customOptions, method, headers, ...(body !== undefined && { body }) })
            } catch (e) {
                err = e
            }
            const last = attempt >= this.#maxRetries
            if (res === undefined) {
                // A request the caller ended is not a transient failure.
                if (signal?.aborted || last) throw err
            } else if (!algodShouldRetry(res.status) || last) {
                return finish(res)
            }

            const wait = algodBackoffMs(attempt, res?.headers.get('retry-after'), Date.now(), this.#waitMin, this.#waitMax)
            this.#log.debug('algod transport retry', {
                method,
                url,
                ...(err !== undefined && { err: err instanceof Error ? err.message : String(err) }),
                status: res?.status ?? 0,
                wait_ms: wait,
                attempt: attempt + 1,
                max: this.#maxRetries + 1,
            })
            // Read to the end so the connection goes back to the pool for the retry.
            await res?.arrayBuffer().catch(() => {})
            if (!(await sleep(wait, signal))) throw signal!.reason
        }
    }

    // As algosdk's URLTokenBaseHTTPClient builds it.
    #url(relativePath: string, query: Query | undefined): string {
        const rel = relativePath.startsWith('./') ? relativePath : relativePath.startsWith('/') ? `.${relativePath}` : `./${relativePath}`
        const u = new URL(rel, this.#base)
        for (const [k, v] of Object.entries(query ?? {})) u.searchParams.set(k, String(v))
        return u.toString()
    }
}

async function finish(res: Response): Promise<algosdk.BaseHTTPClientResponse> {
    const headers: Record<string, string> = {}
    res.headers.forEach((value, name) => {
        headers[name] = value
    })
    const body = new Uint8Array(await res.arrayBuffer())
    if (res.ok) return { body, status: res.status, headers }
    let detail = ''
    try {
        const parsed = JSON.parse(new TextDecoder().decode(body)) as { message?: unknown }
        if (parsed.message) detail = `: ${String(parsed.message)}`
    } catch {}
    throw new AlgodHTTPError(`Network request error. Received status ${res.status} (${res.statusText})${detail}`, { body, status: res.status, headers })
}

/**
 * retryingAlgod is an algosdk client over RetryingAlgodClient: the client a
 * Client builds for its wallet and discovery, for a host that builds its own
 * discovery to share.
 */
export function retryingAlgod(o: AlgodTransportOptions): algosdk.Algodv2 {
    // algosdk ignores the base server when handed a client; its type still asks for one.
    return new algosdk.Algodv2(new RetryingAlgodClient(o), '')
}
