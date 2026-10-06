/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// @txnlab/zerosignal/accounts/xhd: a Signer for a BIP-39 / ARC-52 xHD
// account, the form the ZeroSignal chat app derives from a passkey and exports
// as a 24-word recovery phrase. The twin of Go's keystore hdKey, pinned by the
// 24-word rows of testdata/account_vectors.json.
//
// Needs the optional peer dependencies @algorandfoundation/xhd-wallet-api and
// @scure/bip39. xhd-wallet-api imports Node's crypto and util and reads the
// global Buffer, so a browser bundle has to polyfill all three.

import { fromSeed, KeyContext, XHDWalletAPI } from '@algorandfoundation/xhd-wallet-api'
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
// Not algosdk's encodeAddress: this subpath runs in the chat app's key-holding
// worker, which carries no algosdk.
import { encodeAlgorandAddress } from '@txnlab/zs-proto/ticket'

import { configError } from '../errors.js'
import { type Signer, SignerAddressError } from '../ports.js'
import { phraseWords } from './words.js'

export { phraseWords }

/**
 * XhdRoot is an xHD account's root key and the account it signs as: the first
 * address key, m/44'/283'/0'/0/0, Peikert derivation.
 */
export interface XhdRoot {
    /** The extended root key: the whole tree's secret, not just this account's. */
    rootKey: Uint8Array
    /** The account's 32-byte Ed25519 public key. */
    publicKey: Uint8Array
    address: string
}

const wallet = new XHDWalletAPI()
const words = new Set(wordlist)

async function rootFromSentence(sentence: string): Promise<XhdRoot> {
    const seed = mnemonicToSeedSync(sentence)
    // fromSeed is typed for a Node Buffer but reads only the bytes.
    const rootKey = fromSeed(seed as unknown as Parameters<typeof fromSeed>[0])
    seed.fill(0)
    const publicKey = await wallet.keyGen(rootKey, KeyContext.Address, 0, 0)
    return { rootKey, publicKey, address: encodeAlgorandAddress(publicKey) }
}

/**
 * xhdRootFromEntropy derives the account for 32 secret, uniformly random bytes
 * (the chat app takes a passkey's PRF output; never a credential id or public
 * key, which are public). The entropy is the 24-word phrase, so exporting
 * entropyToMnemonic(entropy) recovers the same account here, in Go's keystore,
 * and in any ARC-52 wallet.
 */
export async function xhdRootFromEntropy(entropy: Uint8Array): Promise<XhdRoot> {
    if (entropy.length !== 32) {
        throw configError(`xhd: want 32 bytes of entropy, got ${entropy.length}`)
    }
    return rootFromSentence(entropyToMnemonic(entropy, wordlist))
}

/**
 * xhdRootFromPhrase loads a 24-word phrase as Go's keystore does: any
 * whitespace separates words, and each must be an English BIP-39 word as
 * written, so case and Unicode look-alikes are refused rather than normalized
 * to a word. A bad word or checksum throws a ZsError (invalid_request) that
 * quotes no word of the phrase.
 */
export async function xhdRootFromPhrase(phrase: string): Promise<XhdRoot> {
    const ws = phraseWords(phrase)
    if (ws.length === 25) {
        throw configError('xhd: a 25-word phrase is an Algorand mnemonic; load it with @txnlab/zerosignal/accounts/mnemonic')
    }
    if (ws.length !== 24) {
        throw configError(`xhd: unsupported word count ${ws.length} (want a 24-word BIP-39 phrase)`)
    }
    const sentence = ws.join(' ')
    // validateMnemonic NFKD-normalizes first, so a full-width word would pass
    // as its ASCII twin; Go's lookup is exact.
    if (!ws.every((w) => words.has(w)) || !validateMnemonic(sentence, wordlist)) {
        throw configError('xhd: invalid 24-word BIP-39 phrase (bad word or checksum)')
    }
    return rootFromSentence(sentence)
}

/**
 * xhdSigner signs as root's account. signBytes is raw Ed25519 over the bytes
 * given, with no Algorand domain-tag check, and refuses to sign for any other
 * address. The signer holds its own copy of the root key for its lifetime, as
 * Go's hdKey does: the library signs only through the root.
 */
export function xhdSigner(root: XhdRoot): Signer {
    const { address } = root
    // A caller that wipes root.rootKey after building the signer must not leave
    // it signing with zeros.
    const rootKey = root.rootKey.slice()
    // Under Node the library's signature is a view into Buffer's shared pool,
    // which also holds copies of the root and leaf keys; anything that clones or
    // posts sig.buffer would carry them. Copy into memory of its own.
    const sign = async (msg: Uint8Array) =>
        new Uint8Array(await wallet.signAlgoTransaction(rootKey, KeyContext.Address, 0, 0, msg))
    return {
        address,
        async signBytes(addr, msg) {
            if (addr !== address) throw new SignerAddressError(address, addr)
            return sign(msg)
        },
        async signTransactions(txns, indexes) {
            const out: Uint8Array[] = []
            for (const i of indexes) {
                const txn = txns[i]!
                out.push(txn.attachSignature(address, await sign(txn.bytesToSign())))
            }
            return out
        },
    }
}
