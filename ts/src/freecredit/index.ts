/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Free credits: an RSA blind signature (RFC 9474,
// RSABSSA-SHA384-PSS-Deterministic) by an issuer's day key over a message
// naming one deployment, one node and one UTC day, which a payer spends on a
// free Solana turn. The issuer's long-lived Ed25519 key certifies each day key
// for its day and deployment. Mirrors proto/go/freecredit, pinned by
// testdata/free_credit_vectors.json. See SPEC.md "Free credits".
//
// There is no signer here: issuing is the issuer's business, and an issuer in
// TS signs through node:crypto, whose RSA is constant-time where this
// library's software path is not.

import { RSABSSA } from '@cloudflare/blindrsa-ts'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'

import { ed25519 } from '../util/ed25519.js'

const MESSAGE_TAG = new TextEncoder().encode('zs-free-credit-v1\x00')
const DAY_KEY_TAG = new TextEncoder().encode('zs-free-credit-day-key-v1\x00')
const DEPLOYMENT_ID_SIZE = 32
const ISSUER_KEY_SIZE = 32
const CERT_SIG_SIZE = 64

export const NONCE_SIZE = 32
export const MESSAGE_SIZE = MESSAGE_TAG.length + DEPLOYMENT_ID_SIZE + 8 + 8 + 4 + NONCE_SIZE
export const EPOCH_SECONDS = 86400
/** How near midnight the neighbouring day is accepted too. Go's Grace. */
export const GRACE_MS = 10 * 60 * 1000
const MIN_KEY_BITS = 2048
const MAX_KEY_BITS = 4096
const MAX_EPOCH = 0xffffffff

// supportsRSARAW false: no platform offers the raw RSA operation, so the
// library computes it in software. The payer's half (blind, unblind) and
// verify need only the public key.
const suite = () => RSABSSA.SHA384.PSS.Deterministic({ supportsRSARAW: false })
const ALGORITHM = { name: 'RSA-PSS', hash: 'SHA-384' } as const

/** The epoch a unix time in milliseconds falls in: its UTC day. A time before 1970 is epoch 0. */
export function epochAt(unixMs: number): number {
    if (unixMs < 0) return 0
    return Math.floor(Math.floor(unixMs / 1000) / EPOCH_SECONDS)
}

/** The first instant of epoch e, in unix milliseconds. */
export function epochStartMs(e: number): number {
    return e * EPOCH_SECONDS * 1000
}

/**
 * The epochs an issuer certifies and signs for, and a node accepts credits for, at nowMs:
 * the current day, and within GRACE_MS of midnight the day on the other side of it. A
 * payer mints for epochAt(nowMs).
 */
export function acceptedEpochs(nowMs: number): number[] {
    const e = epochAt(nowMs)
    const out = [e]
    if (nowMs - epochStartMs(e) < GRACE_MS && e > 0) out.push(e - 1)
    if (epochStartMs(e + 1) - nowMs <= GRACE_MS && e < MAX_EPOCH) out.push(e + 1)
    return out
}

/** The node a credit is spendable at, by its routing pair. */
export interface CreditNode {
    op: number | bigint
    node: number | bigint
}

function u64(v: number | bigint, what: string): bigint {
    const b = typeof v === 'bigint' ? v : Number.isSafeInteger(v) ? BigInt(v) : -1n
    if (b < 0n || b >= 1n << 64n) throw new Error(`free credit: ${what} ${String(v)} is not a u64`)
    return b
}

function u32(e: number): number {
    if (!Number.isInteger(e) || e < 0 || e > MAX_EPOCH) throw new Error(`free credit: epoch ${e} is not a u32`)
    return e
}

function deploymentId(d: Uint8Array): Uint8Array {
    if (d.length !== DEPLOYMENT_ID_SIZE) throw new Error('free credit: deployment id must be 32 bytes')
    return d
}

/**
 * The bytes the issuer blindly signs:
 *
 *     "zs-free-credit-v1\x00" ‖ deployment_id[32] ‖ u64be(operator_id) ‖ u64be(node_id) ‖ u32be(epoch) ‖ nonce[32]
 */
export function creditMessage(deployment: Uint8Array, node: CreditNode, epoch: number, nonce: Uint8Array): Uint8Array {
    deploymentId(deployment)
    if (nonce.length !== NONCE_SIZE) throw new FreeCreditRefusal('malformed')
    const m = new Uint8Array(MESSAGE_SIZE)
    const dv = new DataView(m.buffer)
    let o = 0
    m.set(MESSAGE_TAG, o)
    o += MESSAGE_TAG.length
    m.set(deployment, o)
    o += DEPLOYMENT_ID_SIZE
    dv.setBigUint64(o, u64(node.op, 'operator id'))
    o += 8
    dv.setBigUint64(o, u64(node.node, 'node id'))
    o += 8
    dv.setUint32(o, u32(epoch))
    o += 4
    m.set(nonce, o)
    return m
}

/**
 * What the issuer's master key signs to certify a day key:
 *
 *     "zs-free-credit-day-key-v1\x00" ‖ deployment_id[32] ‖ u32be(epoch) ‖ sha256(day_key_spki)
 */
export function dayKeyCertMessage(deployment: Uint8Array, epoch: number, spki: Uint8Array): Uint8Array {
    deploymentId(deployment)
    const m = new Uint8Array(DAY_KEY_TAG.length + DEPLOYMENT_ID_SIZE + 4 + 32)
    m.set(DAY_KEY_TAG, 0)
    m.set(deployment, DAY_KEY_TAG.length)
    new DataView(m.buffer).setUint32(DAY_KEY_TAG.length + DEPLOYMENT_ID_SIZE, u32(epoch))
    m.set(sha256(spki), DAY_KEY_TAG.length + DEPLOYMENT_ID_SIZE + 4)
    return m
}

/** An issuer's certificate for one day key, as it travels: the byte fields standard base64. */
export interface DayKeyCert {
    issuer: string
    epoch: number
    day_key: string
    day_key_sig: string
}

/** A credit as it travels, inside the payer's sealed reserve request. */
export interface Credit extends DayKeyCert {
    nonce: string
    signature: string
}

export type FreeCreditReason = 'malformed' | 'unknown_issuer' | 'wrong_epoch' | 'bad_day_key' | 'bad_signature'

/** One of verifyCredit's refusals. */
export class FreeCreditRefusal extends Error {
    constructor(
        readonly reason: FreeCreditReason,
        detail?: string,
    ) {
        super(detail === undefined ? `free credit: ${reason}` : `free credit: ${reason}: ${detail}`)
        this.name = 'FreeCreditRefusal'
    }
}

/** The reason slug of one of verifyCredit's refusals, and '' for anything else. */
export function refusalReason(err: unknown): FreeCreditReason | '' {
    return err instanceof FreeCreditRefusal ? err.reason : ''
}

// strictBase64 is Go's Bytes: @scure/base refuses line breaks and set unused
// bits, so each value has one spelling, as a node's spent set needs.
function strictBase64(s: unknown): Uint8Array {
    if (s === undefined || s === null) return new Uint8Array(0)
    if (typeof s !== 'string') throw new FreeCreditRefusal('malformed', 'a byte field is not a string')
    try {
        return base64.decode(s)
    } catch {
        throw new FreeCreditRefusal('malformed', 'not standard base64')
    }
}

/** Reads an issuer's public key, standard base64 of its 32 Ed25519 bytes, as presets and node details name it. */
export function parseIssuerKey(s: string): Uint8Array {
    let b: Uint8Array
    try {
        b = strictBase64(s)
    } catch {
        b = new Uint8Array(0)
    }
    if (b.length !== ISSUER_KEY_SIZE) throw new Error(`free credit issuer key ${JSON.stringify(s)}: want standard base64 of 32 bytes`)
    return b
}

/**
 * Reads a credit's decoded JSON, refusing a malformed one as FreeCreditRefusal('malformed').
 * An absent or null field reads as Go's zero value, so the lengths verifyCredit checks
 * refuse it there.
 */
export function parseCredit(value: unknown): Credit {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new FreeCreditRefusal('malformed', 'not an object')
    const o = value as Record<string, unknown>
    const epoch = o.epoch === undefined || o.epoch === null ? 0 : o.epoch
    if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 0 || epoch > MAX_EPOCH) {
        throw new FreeCreditRefusal('malformed', 'epoch is not a u32')
    }
    const field = (k: string): string => {
        const b = strictBase64(o[k])
        return base64.encode(b)
    }
    return {
        issuer: field('issuer'),
        epoch,
        day_key: field('day_key'),
        day_key_sig: field('day_key_sig'),
        nonce: field('nonce'),
        signature: field('signature'),
    }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((x, i) => x === b[i])
}

function bytesToBigInt(b: Uint8Array): bigint {
    let x = 0n
    for (const v of b) x = (x << 8n) | BigInt(v)
    return x
}

function base64UrlDecode(s: string): Uint8Array {
    const std = s.replace(/-/g, '+').replace(/_/g, '/')
    return base64.decode(std + '='.repeat((4 - (std.length % 4)) % 4))
}

function exponentIs65537(e: Uint8Array): boolean {
    let i = 0
    while (i < e.length && e[i] === 0) i++
    const rest = e.subarray(i)
    return rest.length === 3 && rest[0] === 0x01 && rest[1] === 0x00 && rest[2] === 0x01
}

/** A day key's public half, read through parseDayKeySPKI. */
export interface DayKeyPublic {
    readonly key: CryptoKey
    readonly modulus: bigint
    /** The modulus size in bytes, which every signature under the key has. */
    readonly size: number
}

/**
 * Reads a day key from its SPKI DER. Refuses anything but an RSA key of 2048 to 4096 bits
 * with exponent 65537 in the canonical encoding, as Go's ParseDayKeySPKI does: WebCrypto's
 * own export is that encoding, so a key that does not export to its input bytes, such as
 * one with a trailing byte, is refused.
 */
export async function parseDayKeySPKI(spki: Uint8Array): Promise<DayKeyPublic> {
    let key: CryptoKey
    try {
        key = await crypto.subtle.importKey('spki', spki.slice(), ALGORITHM, true, ['verify'])
    } catch (e) {
        throw new Error(`free credit day key: ${(e as Error).message}`)
    }
    const alg = key.algorithm as RsaHashedKeyAlgorithm
    if (alg.modulusLength < MIN_KEY_BITS || alg.modulusLength > MAX_KEY_BITS) {
        throw new Error(`free credit day key: ${alg.modulusLength}-bit modulus, want ${MIN_KEY_BITS} to ${MAX_KEY_BITS}`)
    }
    if (!exponentIs65537(alg.publicExponent)) throw new Error('free credit day key: exponent is not 65537')
    if (!sameBytes(new Uint8Array(await crypto.subtle.exportKey('spki', key)), spki)) {
        throw new Error('free credit day key: not the canonical SPKI encoding')
    }
    const jwk = await crypto.subtle.exportKey('jwk', key)
    return { key, modulus: bytesToBigInt(base64UrlDecode(jwk.n!)), size: Math.ceil(alg.modulusLength / 8) }
}

/** A certified day key: what a payer blinds a credit to and a node verifies one with. */
export interface DayKey extends DayKeyPublic {
    /** The certificate, as it travels. */
    readonly cert: DayKeyCert
}

/**
 * Accepts cert if one of trusted issued it for deployment, and its key meets the policy.
 * It does not check the epoch against the clock: a payer compares it with the day it
 * asked for, and verifyCredit with the epochs it accepts.
 */
export async function verifyDayKey(trusted: readonly Uint8Array[], deployment: Uint8Array, cert: DayKeyCert): Promise<DayKey> {
    const issuer = strictBase64(cert.issuer)
    const dayKey = strictBase64(cert.day_key)
    const certSig = strictBase64(cert.day_key_sig)
    if (issuer.length !== ISSUER_KEY_SIZE || certSig.length !== CERT_SIG_SIZE || dayKey.length === 0) {
        throw new FreeCreditRefusal('malformed')
    }
    const k = trusted.find((t) => sameBytes(t, issuer))
    if (k === undefined) throw new FreeCreditRefusal('unknown_issuer')
    let ok = false
    try {
        ok = ed25519.verify(certSig, dayKeyCertMessage(deployment, cert.epoch, dayKey), k)
    } catch {
        ok = false
    }
    if (!ok) throw new FreeCreditRefusal('bad_day_key')
    let pub: DayKeyPublic
    try {
        pub = await parseDayKeySPKI(dayKey)
    } catch (e) {
        throw new FreeCreditRefusal('bad_day_key', (e as Error).message)
    }
    return { ...pub, cert: { issuer: cert.issuer, epoch: cert.epoch, day_key: cert.day_key, day_key_sig: cert.day_key_sig } }
}

/**
 * Accepts c if a trusted issuer certified its day key for this deployment and one of
 * epochs, and that key signed it for this node; throws a FreeCreditRefusal otherwise. A
 * credit meant for another node or operator refuses as bad_signature, and one for another
 * deployment as bad_day_key: the message rebuilt here differs from the one signed. It
 * says nothing about whether c was spent.
 */
export async function verifyCredit(
    trusted: readonly Uint8Array[],
    deployment: Uint8Array,
    node: CreditNode,
    epochs: readonly number[],
    c: Credit,
): Promise<void> {
    const issuer = strictBase64(c.issuer)
    const nonce = strictBase64(c.nonce)
    const sig = strictBase64(c.signature)
    if (
        issuer.length !== ISSUER_KEY_SIZE ||
        strictBase64(c.day_key_sig).length !== CERT_SIG_SIZE ||
        strictBase64(c.day_key).length === 0 ||
        nonce.length !== NONCE_SIZE ||
        sig.length === 0
    ) {
        throw new FreeCreditRefusal('malformed')
    }
    if (!trusted.some((t) => sameBytes(t, issuer))) throw new FreeCreditRefusal('unknown_issuer')
    if (!epochs.includes(c.epoch)) throw new FreeCreditRefusal('wrong_epoch')
    const key = await verifyDayKey(trusted, deployment, c)
    const msg = creditMessage(deployment, node, c.epoch, nonce)
    // WebCrypto already refuses s >= N; the check is here so the refusal does not rest on
    // the platform, and to match Go, whose library checks only the length.
    if (sig.length !== key.size || bytesToBigInt(sig) >= key.modulus) throw new FreeCreditRefusal('bad_signature')
    let ok = false
    try {
        ok = await suite().verify(key.key, sig, msg)
    } catch {
        ok = false
    }
    if (!ok) throw new FreeCreditRefusal('bad_signature')
}

/** A credit the payer has blinded and the issuer has yet to sign. It holds the unblinding factor, so it never leaves the payer. */
export class PendingCredit {
    constructor(
        private readonly key: DayKey,
        private readonly msg: Uint8Array,
        private readonly inv: Uint8Array,
        private readonly nonce: Uint8Array,
    ) {}

    /**
     * Unblinds the issuer's signature into a Credit. The library verifies the result
     * first, so an issuer that signed with another key, or signed something else, yields
     * a refusal rather than a credit every node refuses.
     */
    async finalize(blindSig: Uint8Array): Promise<Credit> {
        let sig: Uint8Array
        try {
            sig = await suite().finalize(this.key.key, this.msg, blindSig, this.inv)
        } catch {
            throw new FreeCreditRefusal('bad_signature')
        }
        return { ...this.key.cert, nonce: base64.encode(this.nonce), signature: base64.encode(sig) }
    }
}

/** Starts one credit for node under a certified day key, for the key's day: draws the nonce and returns the blinded message to send the issuer. */
export async function blindCredit(key: DayKey, deployment: Uint8Array, node: CreditNode): Promise<{ blinded: Uint8Array; pending: PendingCredit }> {
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
    const s = suite()
    const msg = s.prepare(creditMessage(deployment, node, key.cert.epoch, nonce))
    const { blindedMsg, inv } = await s.blind(key.key, msg)
    return { blinded: blindedMsg, pending: new PendingCredit(key, msg, inv, nonce) }
}

// The issue wire, which every issuer speaks so a payer can use any of them.
// Both calls are POSTs of JSON to the issuer's base URL: DAY_KEY_PATH takes a
// DayKeyRequest and answers a DayKeyCert, ISSUE_PATH takes an IssueRequest and
// answers an IssueResponse. An issuer answers only for the epochs
// acceptedEpochs gives at its clock, and 400 epoch_not_issuable for any
// other. It may sign the first few messages only, when the caller's cap for
// the epoch is nearly spent, and answers 429 credits_exhausted with a
// Retry-After once it is.
export const DAY_KEY_PATH = '/v1/zs/credits/key'
export const ISSUE_PATH = '/v1/zs/credits'
export const MAX_ISSUE_BATCH = 20
export const CODE_CREDITS_EXHAUSTED = 'credits_exhausted'
export const CODE_EPOCH_NOT_ISSUABLE = 'epoch_not_issuable'

// A node's refusals of the credit a free reserve carries. A node serves a free
// reserve that carries none on its own budget, so these answer only a credit
// that was sent. free_credit_invalid (400) is a credit verifyCredit refuses,
// which the payer drops; free_credit_spent (409) is one the node already
// consumed, which a payer's store holds only when it went stale, so the payer
// drops it and asks that node once more with another.
export const CODE_FREE_CREDIT_INVALID = 'free_credit_invalid'
export const CODE_FREE_CREDIT_SPENT = 'free_credit_spent'

export interface DayKeyRequest {
    deployment: string
    epoch: number
}

export interface IssueRequest {
    deployment: string
    epoch: number
    blinded: string[]
}

export interface IssueResponse {
    signatures: string[]
}
