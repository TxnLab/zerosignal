/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The transaction message codec, legacy and v0 without lookup tables (a v0
// message with lookups decodes, so a verifier can see and refuse it).
// Mirrors proto/go/solana/message.go, pinned by solana_tx_vectors.json (the
// program's own transactions) and solana_codec_vectors.json (the refusals).
// @solana/kit's compiler is not used: it sorts keys by a collation of their
// base58 strings, not by their bytes as the runtime's compiler does, so the
// same instructions would give other bytes than Go's and Rust's.

import { ed25519 } from '../util/ed25519.js'
import { type Hash, type PublicKey, compareKeys, decodeBase58, encodeBase58, publicKeyBytes, publicKeyFromBytes } from './key.js'
import { verifyStrict } from './verify.js'

/** The largest serialized transaction a validator accepts: an IPv6 MTU less its headers. */
export const MAX_TRANSACTION_SIZE = 1232

export type MessageVersion = 'legacy' | 'v0'

// Marks a versioned message: a legacy message starts with its signature
// count, which is under 128, so a set high bit can't be one.
const VERSION_PREFIX = 0x80

export interface AccountMeta {
    publicKey: PublicKey
    isSigner: boolean
    isWritable: boolean
}

/**
 * An instruction before compiling, with each account's privileges. A compiled
 * message keeps only the union of each key's privileges, in its header.
 */
export interface Instruction {
    programId: PublicKey
    accounts: AccountMeta[]
    data: Uint8Array
}

export interface MessageHeader {
    numRequiredSignatures: number
    numReadonlySignedAccounts: number
    numReadonlyUnsignedAccounts: number
}

/**
 * Indexes the message's keys: its static keys, then a v0 message's looked-up
 * writable addresses, then its looked-up readonly ones.
 */
export interface CompiledInstruction {
    programIdIndex: number
    accounts: number[]
    data: Uint8Array
}

export interface AddressTableLookup {
    accountKey: PublicKey
    writableIndexes: number[]
    readonlyIndexes: number[]
}

export interface Message {
    version: MessageVersion
    header: MessageHeader
    accountKeys: PublicKey[]
    recentBlockhash: Hash
    instructions: CompiledInstruction[]
    addressTableLookups: AddressTableLookup[]
}

export class MalformedMessageError extends Error {
    constructor(detail: string) {
        super(`solana: malformed message: ${detail}`)
        this.name = 'MalformedMessageError'
    }
}

function lookedUp(m: Message): { writable: number; total: number } {
    let writable = 0
    let total = 0
    for (const l of m.addressTableLookups) {
        writable += l.writableIndexes.length
        total += l.writableIndexes.length + l.readonlyIndexes.length
    }
    return { writable, total }
}

// Throws on an index no instruction of a parsed message can hold: answering
// for it would hand a verifier a privilege for a key that isn't there.
function checkIndex(m: Message, i: number): void {
    const total = m.accountKeys.length + lookedUp(m).total
    if (!Number.isInteger(i) || i < 0 || i >= total) throw new RangeError(`solana: account index ${i} of ${total}`)
}

/** isSigner reports whether account i must sign: a static key the header counts among the signers. A looked-up address never signs. */
export function isSigner(m: Message, i: number): boolean {
    checkIndex(m, i)
    return i < m.header.numRequiredSignatures
}

/**
 * isWritable reports whether the message grants account i write access: by
 * the header for a static key, and by its lookup list for a looked-up
 * address, the writable ones coming first. The runtime also demotes a
 * program id or a reserved account to readonly, which this does not model:
 * a verifier that asks whether a key may be written must treat this as the
 * most it can get.
 */
export function isWritable(m: Message, i: number): boolean {
    checkIndex(m, i)
    const h = m.header
    const n = m.accountKeys.length
    if (i < h.numRequiredSignatures) return i < h.numRequiredSignatures - h.numReadonlySignedAccounts
    if (i < n) return i < n - h.numReadonlyUnsignedAccounts
    return i < n + lookedUp(m).writable
}

/** feePayer is the first signer, who pays the fee and must be writable. */
export function feePayer(m: Message): PublicKey {
    return m.accountKeys[0]!
}

/** encodeMessage writes the bytes every signer signs. */
export function encodeMessage(m: Message): Uint8Array {
    sanitize(m)
    const w = new Writer()
    if (m.version === 'v0') w.byte(VERSION_PREFIX)
    w.byte(m.header.numRequiredSignatures)
    w.byte(m.header.numReadonlySignedAccounts)
    w.byte(m.header.numReadonlyUnsignedAccounts)
    w.compactU16(m.accountKeys.length)
    for (const k of m.accountKeys) w.bytes(publicKeyBytes(k))
    w.bytes(decodeBase58(m.recentBlockhash, 32))
    w.compactU16(m.instructions.length)
    for (const ix of m.instructions) {
        w.byte(ix.programIdIndex)
        w.compactU16(ix.accounts.length)
        for (const a of ix.accounts) w.byte(a)
        w.compactU16(ix.data.length)
        w.bytes(ix.data)
    }
    if (m.version === 'v0') {
        w.compactU16(m.addressTableLookups.length)
        for (const l of m.addressTableLookups) {
            w.bytes(publicKeyBytes(l.accountKey))
            w.compactU16(l.writableIndexes.length)
            for (const i of l.writableIndexes) w.byte(i)
            w.compactU16(l.readonlyIndexes.length)
            for (const i of l.readonlyIndexes) w.byte(i)
        }
    }
    return w.done()
}

/**
 * parseMessage decodes a message and refuses one the runtime would refuse to
 * load: trailing bytes, a header that claims more keys than there are, a
 * duplicate key, an index past the keys, or a program called from a lookup
 * table or from the fee payer. Every length is a canonical compact-u16, so a
 * parsed message re-encodes to exactly the bytes that were signed.
 */
export function parseMessage(b: Uint8Array): Message {
    const r = new Reader(b)
    let version: MessageVersion = 'legacy'
    if (b.length > 0 && (b[0]! & VERSION_PREFIX) !== 0) {
        const v = b[0]! & ~VERSION_PREFIX
        if (v !== 0) throw new MalformedMessageError(`message version ${v}`)
        version = 'v0'
        r.off++
    }
    const h = r.bytes(3)
    const header = { numRequiredSignatures: h[0]!, numReadonlySignedAccounts: h[1]!, numReadonlyUnsignedAccounts: h[2]! }
    const accountKeys: PublicKey[] = []
    for (let n = r.compactU16(); n > 0; n--) accountKeys.push(publicKeyFromBytes(r.bytes(32)))
    const recentBlockhash = encodeBase58(r.bytes(32))
    const instructions: CompiledInstruction[] = []
    for (let n = r.compactU16(); n > 0; n--) {
        const programIdIndex = r.bytes(1)[0]!
        const accounts = Array.from(r.bytes(r.compactU16()))
        const data = r.bytes(r.compactU16()).slice()
        instructions.push({ programIdIndex, accounts, data })
    }
    const addressTableLookups: AddressTableLookup[] = []
    if (version === 'v0') {
        for (let n = r.compactU16(); n > 0; n--) {
            const accountKey = publicKeyFromBytes(r.bytes(32))
            const writableIndexes = Array.from(r.bytes(r.compactU16()))
            const readonlyIndexes = Array.from(r.bytes(r.compactU16()))
            addressTableLookups.push({ accountKey, writableIndexes, readonlyIndexes })
        }
    }
    if (r.off !== b.length) throw new MalformedMessageError(`${b.length - r.off} trailing bytes`)
    const m: Message = { version, header, accountKeys, recentBlockhash, instructions, addressTableLookups }
    sanitize(m)
    return m
}

// The runtime's Message::sanitize plus its duplicate-key check.
function sanitize(m: Message): void {
    const h = m.header
    const n = m.accountKeys.length
    if (h.numRequiredSignatures === 0) throw new MalformedMessageError('no signers')
    if (h.numReadonlySignedAccounts >= h.numRequiredSignatures) throw new MalformedMessageError('the fee payer must be writable')
    if (h.numRequiredSignatures + h.numReadonlyUnsignedAccounts > n) {
        throw new MalformedMessageError(`header claims ${h.numRequiredSignatures}+${h.numReadonlyUnsignedAccounts} keys of ${n}`)
    }
    if (n > 256) throw new MalformedMessageError(`${n} keys`)
    if (m.version !== 'legacy' && m.version !== 'v0') throw new MalformedMessageError(`message version ${String(m.version)}`)
    if (m.version === 'legacy' && m.addressTableLookups.length > 0) throw new MalformedMessageError('a legacy message has lookups')
    let lookedUp = 0
    m.addressTableLookups.forEach((l, i) => {
        const loads = l.writableIndexes.length + l.readonlyIndexes.length
        if (loads === 0) throw new MalformedMessageError(`lookup ${i} loads nothing`)
        lookedUp += loads
    })
    const total = n + lookedUp
    if (total > 256) throw new MalformedMessageError(`${total} keys with lookups`)
    if (new Set(m.accountKeys).size !== n) throw new MalformedMessageError('duplicate key')
    m.instructions.forEach((ix, i) => {
        // Programs come only from static keys, and never the fee payer.
        if (ix.programIdIndex === 0 || ix.programIdIndex >= n) {
            throw new MalformedMessageError(`instruction ${i} program index ${ix.programIdIndex}`)
        }
        for (const a of ix.accounts) {
            if (a >= total) throw new MalformedMessageError(`instruction ${i} account index ${a} of ${total}`)
        }
    })
}

/**
 * compileMessage builds a message the way the Solana SDK's compiler does, so
 * the bytes match a transaction the program's tests built from the same
 * instructions: the fee payer first, then writable signers, readonly
 * signers, writable and readonly non-signers, each group in byte order of
 * its keys, every key carrying the union of the privileges its instructions
 * ask. A v0 message compiles with no lookup tables.
 */
export function compileMessage(payer: PublicKey, blockhash: Hash, ixs: Instruction[], version: MessageVersion): Message {
    const privs = new Map<PublicKey, { signer: boolean; writable: boolean }>([[payer, { signer: true, writable: true }]])
    const note = (k: PublicKey, signer: boolean, writable: boolean) => {
        publicKeyBytes(k)
        const p = privs.get(k) ?? { signer: false, writable: false }
        p.signer ||= signer
        p.writable ||= writable
        privs.set(k, p)
    }
    for (const ix of ixs) {
        note(ix.programId, false, false)
        for (const a of ix.accounts) note(a.publicKey, a.isSigner, a.isWritable)
    }
    const groups: PublicKey[][] = [[], [], [], []]
    for (const [k, p] of privs) {
        if (k === payer) continue
        groups[p.signer ? (p.writable ? 0 : 1) : p.writable ? 2 : 3]!.push(k)
    }
    for (const g of groups) g.sort(compareKeys)
    const accountKeys = [payer, ...groups.flat()]
    if (accountKeys.length > 256) throw new MalformedMessageError(`${accountKeys.length} keys`)
    const index = new Map(accountKeys.map((k, i) => [k, i]))
    const m: Message = {
        version,
        header: {
            numRequiredSignatures: 1 + groups[0]!.length + groups[1]!.length,
            numReadonlySignedAccounts: groups[1]!.length,
            numReadonlyUnsignedAccounts: groups[3]!.length,
        },
        accountKeys,
        recentBlockhash: blockhash,
        instructions: ixs.map((ix) => ({
            programIdIndex: index.get(ix.programId)!,
            accounts: ix.accounts.map((a) => index.get(a.publicKey)!),
            data: ix.data.slice(),
        })),
        addressTableLookups: [],
    }
    decodeBase58(blockhash, 32)
    sanitize(m)
    return m
}

/** A message and one signature per required signer, in signer order. An unsigned slot is all zeros. */
export interface Transaction {
    signatures: Uint8Array[]
    message: Message
}

/** newTransaction gives m an empty signature slot per required signer. */
export function newTransaction(m: Message): Transaction {
    return { signatures: Array.from({ length: m.header.numRequiredSignatures }, () => new Uint8Array(64)), message: m }
}

/**
 * signTransaction signs the message with each 32-byte ed25519 secret and puts
 * the signature in that key's slot, leaving the others as they are, so
 * signers can sign in any order.
 */
export function signTransaction(t: Transaction, ...secrets: Uint8Array[]): void {
    const msg = encodeMessage(t.message)
    const signers = t.message.accountKeys.slice(0, t.message.header.numRequiredSignatures)
    for (const secret of secrets) {
        const pub = publicKeyFromBytes(ed25519.getPublicKey(secret))
        const i = signers.indexOf(pub)
        if (i < 0) throw new Error(`solana: ${pub} is not a signer of this message`)
        t.signatures[i] = ed25519.sign(msg, secret)
    }
}

/** verifySignatures checks every required signature over the message's bytes. */
export function verifySignatures(t: Transaction): void {
    const msg = encodeMessage(t.message)
    if (t.signatures.length !== t.message.header.numRequiredSignatures) {
        throw new MalformedMessageError(`${t.signatures.length} signatures for ${t.message.header.numRequiredSignatures} signers`)
    }
    t.signatures.forEach((sig, i) => {
        const k = t.message.accountKeys[i]!
        if (!verifyStrict(k, msg, sig)) throw new Error(`solana: bad signature for ${k}`)
    })
}

/** encodeTransaction refuses a transaction over MAX_TRANSACTION_SIZE, which no validator would take. */
export function encodeTransaction(t: Transaction): Uint8Array {
    const msg = encodeMessage(t.message)
    if (t.signatures.length !== t.message.header.numRequiredSignatures) {
        throw new MalformedMessageError(`${t.signatures.length} signatures for ${t.message.header.numRequiredSignatures} signers`)
    }
    const w = new Writer()
    w.compactU16(t.signatures.length)
    for (const s of t.signatures) {
        if (s.length !== 64) throw new MalformedMessageError('a signature of other than 64 bytes')
        w.bytes(s)
    }
    w.bytes(msg)
    const out = w.done()
    if (out.length > MAX_TRANSACTION_SIZE) throw new MalformedMessageError(`a transaction of ${out.length} bytes`)
    return out
}

/**
 * parseTransaction decodes a transaction. Its signatures are not checked: a
 * verifier inspects an offer it has not signed yet. One over
 * MAX_TRANSACTION_SIZE is refused, as a validator would refuse it.
 */
export function parseTransaction(b: Uint8Array): Transaction {
    if (b.length > MAX_TRANSACTION_SIZE) throw new MalformedMessageError(`a transaction of ${b.length} bytes`)
    const r = new Reader(b)
    const signatures: Uint8Array[] = []
    for (let n = r.compactU16(); n > 0; n--) signatures.push(r.bytes(64).slice())
    const message = parseMessage(b.subarray(r.off))
    if (signatures.length !== message.header.numRequiredSignatures) {
        throw new MalformedMessageError(`${signatures.length} signatures for ${message.header.numRequiredSignatures} signers`)
    }
    return { signatures, message }
}

class Writer {
    private parts: number[] = []
    byte(v: number): void {
        if (!Number.isInteger(v) || v < 0 || v > 255) throw new MalformedMessageError(`byte ${v}`)
        this.parts.push(v)
    }
    bytes(b: Uint8Array): void {
        for (const v of b) this.parts.push(v)
    }
    /** Solana's short_vec length: seven bits per byte, low first, the high bit set on every byte but the last. */
    compactU16(n: number): void {
        if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new MalformedMessageError(`length ${n}`)
        for (;;) {
            const c = n & 0x7f
            n >>= 7
            if (n === 0) {
                this.parts.push(c)
                return
            }
            this.parts.push(c | 0x80)
        }
    }
    done(): Uint8Array {
        return Uint8Array.from(this.parts)
    }
}

class Reader {
    off = 0
    constructor(private readonly b: Uint8Array) {}
    bytes(n: number): Uint8Array {
        if (this.off + n > this.b.length) throw new MalformedMessageError(`short read at ${this.off}`)
        const out = this.b.subarray(this.off, this.off + n)
        this.off += n
        return out
    }
    /**
     * Refuses an encoding the runtime refuses: more than three bytes, a value
     * over u16, or a longer spelling of a value a shorter one holds.
     */
    compactU16(): number {
        let v = 0
        for (let i = 0; i < 3; i++) {
            const c = this.bytes(1)[0]!
            v |= (c & 0x7f) << (7 * i)
            if ((c & 0x80) === 0) {
                if (i > 0 && c === 0) throw new MalformedMessageError(`non-canonical length at ${this.off - 1}`)
                if (v > 0xffff) throw new MalformedMessageError(`length over u16 at ${this.off - 1}`)
                return v
            }
        }
        throw new MalformedMessageError(`length over three bytes at ${this.off}`)
    }
}
