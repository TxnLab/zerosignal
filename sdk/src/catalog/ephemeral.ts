/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What a probe's ephemeral advertisement leaves a node with. Mandatory forward
// secrecy seals only to a node's signed, live ephemeral age recipient; there is
// no on-chain fallback, so anything short of 'verified' leaves the node with no
// seal target this cycle. Mirrors Go's checkEphemeral (go/zs/fetcher.go),
// pinned by testdata/ephemeral_verdict_vectors.json.

import { bytesToHex } from '@noble/hashes/utils.js'
import { bech32 } from '@scure/base'
import {
    DEFAULT_EPHEMERAL_SKEW_SEC,
    EphemeralExpiredError,
    ephemeralStale,
    verifyEphemeral,
} from '@txnlab/zs-proto/ticket'

import type { Clock } from '../ports.js'
import type { NodeRef } from '../types.js'

/** The advertisement's fields as /v1/zs/details carries them; any may be absent. */
export interface EphemeralWireFields {
    ephemeral_age_pubkey?: string | undefined
    ephemeral_expiry?: number | undefined
    ephemeral_issued_at?: number | undefined
    ephemeral_sig?: string | undefined
}

/** The chain-resolved node the advertisement must have been signed for. */
export interface EphemeralTarget {
    op: bigint | number
    node: bigint | number
}

/**
 * - absent: the node advertised no ephemeral key this cycle.
 * - verified: genuine, live, and a parseable age X25519 recipient.
 * - expired: genuine but past its expiry; routine near a rotation, not an attack.
 * - rejected: a bad or missing signature, the wrong (operator, node), or a
 *   window over the lifetime cap or issued in the future. Someone tried to
 *   substitute or over-extend a seal key.
 * - unparseable: a genuine signature over a recipient that is not an age
 *   X25519 key.
 */
export type EphemeralVerdict =
    | { outcome: 'absent' | 'expired' }
    | {
          outcome: 'verified'
          recipient: string
          expiry: number
          issuedAt: number
          /** Older than the freshness target: the relay that served it gets the blame. */
          stale: boolean
      }
    | { outcome: 'rejected' | 'unparseable'; error: Error }

export type EphemeralOutcome = EphemeralVerdict['outcome']

/**
 * checkEphemeralAdvertisement verifies one probe's advertisement under the
 * node's on-chain Ed25519 signing key, for the chain-resolved target, never the
 * wire's ids. A missing field reads as Go's zero value.
 */
export function checkEphemeralAdvertisement(
    target: EphemeralTarget,
    signingPubKey: Uint8Array,
    wire: EphemeralWireFields,
    nowSec: number,
): EphemeralVerdict {
    const recipient: unknown = wire.ephemeral_age_pubkey
    if (recipient === undefined || recipient === '') return { outcome: 'absent' }
    // Go's typed decode refuses a mistyped field before any check runs. Here a
    // string expiry would still sign the same bytes and then never expire
    // ("1800000000" + 60 concatenates), so anything off-type is refused.
    const expiry = intField(wire.ephemeral_expiry)
    const issuedAt = intField(wire.ephemeral_issued_at)
    const sig = stringField(wire.ephemeral_sig)
    if (typeof recipient !== 'string' || expiry === null || issuedAt === null || sig === null) {
        return { outcome: 'rejected', error: new Error('ephemeral advertisement: a field has the wrong type') }
    }
    const adv = {
        ephemeral_age_pubkey: recipient,
        ephemeral_expiry: expiry,
        ephemeral_issued_at: issuedAt,
        ephemeral_sig: sig,
    }
    try {
        verifyEphemeral(target.op, target.node, adv, signingPubKey, nowSec, DEFAULT_EPHEMERAL_SKEW_SEC)
    } catch (err) {
        if (err instanceof EphemeralExpiredError) return { outcome: 'expired' }
        return { outcome: 'rejected', error: asError(err) }
    }
    const parseError = ageX25519RecipientError(recipient)
    if (parseError !== null) return { outcome: 'unparseable', error: parseError }
    return {
        outcome: 'verified',
        recipient,
        expiry: adv.ephemeral_expiry,
        issuedAt: adv.ephemeral_issued_at,
        stale: ephemeralStale(adv, nowSec),
    }
}

/**
 * ageX25519RecipientError is why s is not an age X25519 recipient, or null when
 * it is: lower-case bech32 (not bech32m) under the "age" prefix, carrying a
 * 32-byte point. That is age's ParseX25519Recipient, which reads an upper-case
 * prefix as a different type.
 */
export function ageX25519RecipientError(s: string): Error | null {
    if (s !== s.toLowerCase()) return new Error('malformed recipient: not lower case')
    let decoded: { prefix: string; words: number[] }
    let point: Uint8Array
    try {
        decoded = bech32.decode(s as `${string}1${string}`)
        point = bech32.fromWords(decoded.words)
    } catch (err) {
        return new Error(`malformed recipient: ${asError(err).message}`)
    }
    if (decoded.prefix !== 'age') return new Error(`malformed recipient: invalid type ${JSON.stringify(decoded.prefix)}`)
    if (point.length !== 32) return new Error('malformed recipient: invalid X25519 public key')
    return null
}

/** The relay-reputation records a verified block feeds. */
export interface EphemeralStalenessSink {
    recordRelayStaleEphemeral(relay: NodeRef): void
    recordRelayFreshEphemeral(relay: NodeRef): void
}

/**
 * recordEphemeralStaleness attributes a verified block's age to the relay that
 * carried it: a stale block counts against the relay, a fresh one clears its
 * streak. A direct probe (relay null) and any unverified block record nothing,
 * since an honest node's key ages toward its expiry on its own.
 */
export function recordEphemeralStaleness(
    sink: EphemeralStalenessSink,
    relay: NodeRef | null,
    verdict: EphemeralVerdict,
): void {
    if (relay === null || verdict.outcome !== 'verified') return
    if (verdict.stale) sink.recordRelayStaleEphemeral(relay)
    else sink.recordRelayFreshEphemeral(relay)
}

export interface EphemeralVerifyCacheOptions<T extends EphemeralTarget = EphemeralTarget> {
    /** Milliseconds since the epoch; defaults to Date.now. */
    clock?: Clock
    /** Seconds a verdict is reused for, so an expiry still lands within one. Default 15. */
    bucketSec?: number
    /** Entries kept before the cache starts over. Default 512. */
    maxEntries?: number
    /**
     * Called with each verdict the cache computes, not with one it reuses, so an
     * app can log a refused block once rather than on every rebuild. It gets the
     * target exactly as passed to check, with whatever else the app put on it.
     */
    onVerdict?: (target: T, verdict: EphemeralVerdict) => void
}

/**
 * EphemeralVerifyCache reuses a verdict for the same node and advertisement
 * within one time bucket. An app that rebuilds its rows often (a React render
 * per streamed token) would otherwise run an Ed25519 verify per node per
 * rebuild.
 */
export class EphemeralVerifyCache<T extends EphemeralTarget = EphemeralTarget> {
    readonly #clock: Clock
    readonly #bucketSec: number
    readonly #maxEntries: number
    readonly #onVerdict: ((target: T, verdict: EphemeralVerdict) => void) | undefined
    readonly #entries = new Map<string, EphemeralVerdict>()

    constructor(opts: EphemeralVerifyCacheOptions<T> = {}) {
        this.#clock = opts.clock ?? Date.now
        this.#bucketSec = opts.bucketSec ?? 15
        this.#maxEntries = opts.maxEntries ?? 512
        this.#onVerdict = opts.onVerdict
    }

    check(target: T, signingPubKey: Uint8Array, wire: EphemeralWireFields): EphemeralVerdict {
        const nowSec = Math.floor(this.#clock() / 1000)
        // Keyed by the exact node and its signing key: a sibling's
        // advertisement replayed into this node must verify under this node's
        // key, and ids repeat across networks and outlive a key rotation, so a
        // verdict under one key never answers for another. issued_at is in the
        // key because the staleness flag reads it. Each wire field carries its
        // type, so a string "123" never shares a verdict with the number 123.
        // JSON-quoting each part keeps a separator inside a node-authored string
        // from making two different blocks share a key.
        const field = (v: unknown) => `${typeof v}:${String(v)}`
        const key = JSON.stringify([
            `${target.op}:${target.node}`,
            bytesToHex(signingPubKey),
            field(wire.ephemeral_age_pubkey),
            field(wire.ephemeral_expiry),
            field(wire.ephemeral_issued_at),
            field(wire.ephemeral_sig),
            Math.floor(nowSec / this.#bucketSec),
        ])
        const cached = this.#entries.get(key)
        if (cached !== undefined) return cached
        const verdict = checkEphemeralAdvertisement(target, signingPubKey, wire, nowSec)
        // Bucketing leaves superseded keys behind; bound them.
        if (this.#entries.size >= this.#maxEntries) this.#entries.clear()
        this.#entries.set(key, verdict)
        this.#onVerdict?.(target, verdict)
        return verdict
    }

    clear(): void {
        this.#entries.clear()
    }
}

// A missing field reads as Go's zero value; a present one must have its type.
function intField(v: unknown): number | null {
    if (v === undefined) return 0
    return Number.isSafeInteger(v) ? (v as number) : null
}

function stringField(v: unknown): string | null {
    if (v === undefined) return ''
    return typeof v === 'string' ? v : null
}

function asError(err: unknown): Error {
    return err instanceof Error ? err : new Error(String(err))
}
