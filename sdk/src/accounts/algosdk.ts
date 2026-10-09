/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// @txnlab/zerosignal/accounts/algosdk: a Signer over an algosdk Account, the
// key in memory. The twin of Go's keystore stdKey.

import * as ed25519 from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2.js'
import { type Account, makeBasicAccountTransactionSigner } from 'algosdk'

import { type Signer, SignerAddressError } from '../ports.js'

// The sync API hashes through this hook. Without it signAsync needs
// crypto.subtle, which a page on plain http and some runtimes lack, while the
// transaction half (algosdk) works: a signer that half-works.
ed25519.etc.sha512Sync ??= (...m) => sha512(ed25519.etc.concatBytes(...m))

/**
 * algosdkSigner signs as `account`. signBytes is raw Ed25519 over the bytes
 * given, not algosdk's signBytes (which prepends "MX"), and refuses to sign
 * for any other address.
 */
export function algosdkSigner(account: Account): Signer {
    const address = account.addr.toString()
    // An algosdk secret key is the 32-byte seed followed by the public key.
    const seed = account.sk.slice(0, 32)
    return {
        address,
        async signBytes(addr, msg) {
            if (addr !== address) throw new SignerAddressError(address, addr)
            return ed25519.sign(msg, seed)
        },
        signTransactions: makeBasicAccountTransactionSigner(account),
    }
}
