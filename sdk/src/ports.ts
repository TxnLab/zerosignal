/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The ports: everything the SDK needs from its host, passed in through Config
// rather than reached for. The SDK reads no environment and no global
// singleton, so the same code runs in a browser tab, a worker and Node.

import type { TransactionSigner } from 'algosdk'
import type { BytesSigner } from '@txnlab/zs-proto/ticket'

/**
 * Signer holds the payer's key, for one address.
 *
 * `signBytes` is raw Ed25519 over the bytes given: the SDK hands it a 32-byte
 * sha256 digest of a domain-tagged canonical body. It is NOT go-algorand-sdk's
 * `SignBytes` (which prepends "MX") and not ARC-1 `signData`; a wallet whose
 * sign-bytes flow tags or prefixes the message cannot implement it.
 *
 * `signTransactions` signs Algorand transactions (escrow open, settle,
 * refund), with algosdk's TransactionSigner contract.
 */
export interface Signer extends BytesSigner {
    readonly address: string
    signTransactions: TransactionSigner
}

/** Thrown when the SDK is asked to sign for an address other than the payer's. */
export class SignerAddressError extends Error {
    constructor(
        readonly want: string,
        readonly got: string,
    ) {
        super(`signer holds ${want}, asked to sign for ${got}`)
        this.name = 'SignerAddressError'
    }
}

/**
 * payerBytesSigner refuses to sign for any address but the signer's own. A
 * signer backed by several keys would otherwise sign a reserve with whichever
 * one it was asked for, and the node would bind the ticket to that account.
 */
export function payerBytesSigner(signer: Signer): BytesSigner {
    return {
        signBytes(address, msg) {
            if (address !== signer.address) {
                return Promise.reject(new SignerAddressError(signer.address, address))
            }
            return signer.signBytes(address, msg)
        },
    }
}

/**
 * StorageAdapter is durable key-value storage for state that should survive a
 * reload: the operator catalog, open tickets. Values are strings the SDK
 * encodes itself. Keys are namespaced by the SDK; an adapter shared with the
 * host app needs no prefix of its own.
 */
export interface StorageAdapter {
    get(key: string): Promise<string | undefined>
    set(key: string, value: string): Promise<void>
    delete(key: string): Promise<void>
}

/**
 * CacheAdapter holds fetched values (operator details, chain reads) so that
 * concurrent and repeated asks share one fetch. Keys are arrays compared
 * element-wise. A host with its own query cache (TanStack Query, say) adapts
 * it here so the SDK's fetches show up in it; memoryCache is the default.
 */
export interface CacheAdapter {
    /**
     * fetch returns the cached value when it is younger than staleTimeMs, and
     * otherwise calls load once however many callers are waiting. A load that
     * throws caches nothing.
     */
    fetch<T>(key: readonly unknown[], load: () => Promise<T>, opts: { staleTimeMs: number }): Promise<T>
    /** peek returns a cached value of any age, without fetching. */
    peek<T>(key: readonly unknown[]): T | undefined
    /** invalidate drops every entry whose key starts with prefix. */
    invalidate(prefix: readonly unknown[]): void
}

/** Structured attributes on a log line. Never prompt or response content. */
export type LogAttrs = Record<string, unknown>

/**
 * Logger receives the SDK's diagnostics. It mirrors slog's levels; the
 * default discards everything.
 */
export interface Logger {
    debug(msg: string, attrs?: LogAttrs): void
    info(msg: string, attrs?: LogAttrs): void
    warn(msg: string, attrs?: LogAttrs): void
    error(msg: string, attrs?: LogAttrs): void
}

/** Clock returns the current time in Unix milliseconds. */
export type Clock = () => number

/** Fetch is the WHATWG fetch the SDK sends node and chain traffic through. */
export type Fetch = typeof globalThis.fetch

export const discardLogger: Logger = {
    debug() {},
    info() {},
    warn() {},
    error() {},
}

/** consoleLogger writes to the console, for development. */
export function consoleLogger(prefix = 'zs'): Logger {
    const line = (msg: string) => `${prefix}: ${msg}`
    return {
        debug: (msg, attrs) => console.debug(line(msg), attrs ?? ''),
        info: (msg, attrs) => console.info(line(msg), attrs ?? ''),
        warn: (msg, attrs) => console.warn(line(msg), attrs ?? ''),
        error: (msg, attrs) => console.error(line(msg), attrs ?? ''),
    }
}

/** memoryStorage keeps everything in a Map: nothing survives the process. */
export function memoryStorage(): StorageAdapter {
    const m = new Map<string, string>()
    return {
        get: (k) => Promise.resolve(m.get(k)),
        set: (k, v) => {
            m.set(k, v)
            return Promise.resolve()
        },
        delete: (k) => {
            m.delete(k)
            return Promise.resolve()
        },
    }
}

// cacheKeyId encodes a cache key for Map lookup. JSON alone throws on a
// bigint (the SDK's app ids are bigints) and reads undefined as null, so both
// are tagged first.
function cacheKeyId(key: readonly unknown[]): string {
    return JSON.stringify(key, (_, v: unknown) =>
        typeof v === 'bigint' ? { $bigint: v.toString() } : v === undefined ? { $undefined: true } : v,
    )
}

/**
 * memoryCache is the default CacheAdapter: a Map with single-flight loads.
 * Keys are compared by their JSON encoding, with bigints and undefined kept
 * distinct.
 */
export function memoryCache(clock: Clock = Date.now): CacheAdapter {
    type Load = { key: readonly unknown[]; p: Promise<unknown> }
    const entries = new Map<string, { key: readonly unknown[]; value: unknown; at: number }>()
    const inflight = new Map<string, Load>()
    const id = cacheKeyId
    const under = (key: readonly unknown[], prefix: readonly unknown[]) =>
        key.length >= prefix.length && id(key.slice(0, prefix.length)) === id(prefix)
    return {
        fetch<T>(key: readonly unknown[], load: () => Promise<T>, opts: { staleTimeMs: number }) {
            const k = id(key)
            const hit = entries.get(k)
            if (hit && clock() - hit.at < opts.staleTimeMs) {
                return Promise.resolve(hit.value as T)
            }
            const pending = inflight.get(k)
            if (pending) {
                return pending.p as Promise<T>
            }
            // Registered before load runs: a load that throws synchronously
            // reaches the finally below before the async body first yields,
            // and must find itself there to clear itself.
            const self: Load = { key, p: Promise.resolve() }
            inflight.set(k, self)
            self.p = (async () => {
                try {
                    const value = await load()
                    // An invalidate during the load dropped this one: its value
                    // predates the invalidation and must not be cached.
                    if (inflight.get(k) === self) {
                        entries.set(k, { key, value, at: clock() })
                    }
                    return value
                } finally {
                    if (inflight.get(k) === self) {
                        inflight.delete(k)
                    }
                }
            })()
            return self.p as Promise<T>
        },
        peek<T>(key: readonly unknown[]) {
            return entries.get(id(key))?.value as T | undefined
        },
        invalidate(prefix: readonly unknown[]) {
            for (const [k, e] of entries) {
                if (under(e.key, prefix)) entries.delete(k)
            }
            for (const [k, l] of inflight) {
                if (under(l.key, prefix)) inflight.delete(k)
            }
        },
    }
}
