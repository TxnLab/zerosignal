/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// @txnlab/zerosignal/accounts/solana: a recovery phrase's Solana key, derived
// at m/44'/501'/0'/0' as Phantom and Solflare derive it by default, so the
// phrase the chat app exports shows the same Solana address there.
// solana-keygen agrees only at that path (prompt://?key=0/0); its plain
// `new` / `recover` use no path. The twin of Go's
// keystore SolanaKeyFromPhrase and Slip10Ed25519, pinned by the slip10 and
// solana rows of testdata/account_vectors.json.
//
// Needs the optional peer dependency @scure/bip39.

import * as ed25519 from '@noble/ed25519'
import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { encodeBase58 } from '@txnlab/zs-proto/solana'

import { configError } from '../errors.js'
import { SignerAddressError, type SolanaSigner } from '../ports.js'
import { phraseWords } from './words.js'

export { phraseWords }

// As in algosdk.ts: the sync API needs this hook where crypto.subtle is absent.
ed25519.etc.sha512Sync ??= (...m) => sha512(ed25519.etc.concatBytes(...m))

/** m/44'/501'/0'/0', every index hardened: Phantom's and Solflare's default account. */
export const SOLANA_PATH: readonly number[] = Object.freeze([44, 501, 0, 0])

const HARDENED = 0x80000000
const ED25519_SEED = new TextEncoder().encode('ed25519 seed')
const WORD_COUNTS = new Set([12, 15, 18, 21, 24])
const words = new Set(wordlist)

/**
 * slip10Ed25519 derives the SLIP-0010 Ed25519 key and chain code at path from
 * seed. Ed25519 has only hardened children, so every index is taken hardened
 * whatever its top bit. An index must be a uint32, as Go's path is: anything
 * else would wrap to some other child.
 */
export function slip10Ed25519(seed: Uint8Array, path: readonly number[]): { key: Uint8Array; chainCode: Uint8Array } {
    for (const index of path) {
        if (!Number.isInteger(index) || index < 0 || index >= 2 ** 32) {
            throw configError(`slip10: index ${index} is not a uint32`)
        }
    }
    let i = hmac(sha512, ED25519_SEED, seed)
    for (const index of path) {
        const data = new Uint8Array(37)
        data.set(i.subarray(0, 32), 1)
        new DataView(data.buffer).setUint32(33, (index | HARDENED) >>> 0)
        const next = hmac(sha512, i.subarray(32), data)
        data.fill(0)
        i.fill(0)
        i = next
    }
    const out = { key: i.slice(0, 32), chainCode: i.slice(32) }
    i.fill(0)
    return out
}

/**
 * SolanaKey is a Solana account's key: the 32-byte Ed25519 seed (the first
 * half of the 64-byte secret key a wallet exports), and its address.
 */
export interface SolanaKey {
    seed: Uint8Array
    publicKey: Uint8Array
    /** base58 */
    address: string
}

function keyFromSentence(sentence: string): SolanaKey {
    const bip39Seed = mnemonicToSeedSync(sentence)
    const { key, chainCode } = slip10Ed25519(bip39Seed, SOLANA_PATH)
    bip39Seed.fill(0)
    chainCode.fill(0)
    const publicKey = ed25519.getPublicKey(key)
    return { seed: key, publicKey, address: encodeBase58(publicKey) }
}

/**
 * solanaKeyFromPhrase loads a phrase as Go's keystore does: any BIP-39 length
 * from 12 to 24 words, any whitespace between them, and each an English
 * BIP-39 word as written, so case and Unicode look-alikes are refused rather
 * than normalized to a word. A bad word or checksum throws a ZsError
 * (invalid_request) that quotes no word of the phrase.
 */
export function solanaKeyFromPhrase(phrase: string): SolanaKey {
    const ws = phraseWords(phrase)
    if (!WORD_COUNTS.has(ws.length)) {
        throw configError(`solana: unsupported word count ${ws.length} (want a 12- to 24-word BIP-39 phrase)`)
    }
    const sentence = ws.join(' ')
    // validateMnemonic NFKD-normalizes first, so a full-width word would pass
    // as its ASCII twin; Go's lookup is exact.
    if (!ws.every((w) => words.has(w)) || !validateMnemonic(sentence, wordlist)) {
        throw configError(`solana: invalid ${ws.length}-word BIP-39 phrase (bad word or checksum)`)
    }
    return keyFromSentence(sentence)
}

/**
 * solanaKeyFromEntropy derives the Solana account of the 24-word phrase that
 * 32 bytes of entropy are, the same phrase xhdRootFromEntropy derives the
 * Algorand account from, so one exported phrase recovers both.
 */
export function solanaKeyFromEntropy(entropy: Uint8Array): SolanaKey {
    if (entropy.length !== 32) {
        throw configError(`solana: want 32 bytes of entropy, got ${entropy.length}`)
    }
    return keyFromSentence(entropyToMnemonic(entropy, wordlist))
}

/**
 * solanaSigner signs as key's account, refusing any other address: raw Ed25519
 * over the bytes given for `signBytes`, and over a transaction's message for
 * `signTransactionMessage`. It holds its own copy of the seed, so a caller
 * that wipes key.seed afterwards doesn't leave it signing with zeros, and
 * refuses a key whose address isn't its seed's: a host that rebuilt one from
 * stored fields would otherwise advertise one account and sign as another.
 */
export function solanaSigner(key: SolanaKey): SolanaSigner {
    const seed = key.seed.slice()
    const address = encodeBase58(ed25519.getPublicKey(seed))
    if (address !== key.address) {
        seed.fill(0)
        throw configError(`solana: key address ${key.address} is not its seed's (${address})`)
    }
    const sign = async (addr: string, msg: Uint8Array) => {
        if (addr !== address) throw new SignerAddressError(address, addr)
        return ed25519.sign(msg, seed)
    }
    return { address, signBytes: sign, signTransactionMessage: sign }
}
