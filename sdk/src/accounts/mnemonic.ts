/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// @txnlab/zerosignal/accounts/mnemonic: a Signer from a 25-word Algorand
// mnemonic, as Go's keystore loads one. A 24-word phrase is an xHD account,
// which needs the optional deps @txnlab/zerosignal/accounts/xhd carries.

import { mnemonicToSecretKey } from 'algosdk'

import { configError } from '../errors.js'
import type { Signer } from '../ports.js'
import { algosdkSigner } from './algosdk.js'
import { phraseWords } from './words.js'

export { phraseWords }

/**
 * mnemonicSigner loads a 25-word Algorand mnemonic. Any whitespace separates
 * words; case does not fold. A bad word or checksum throws a ZsError
 * (invalid_request) that quotes no word of the phrase.
 */
export function mnemonicSigner(phrase: string): Signer {
    const words = phraseWords(phrase)
    if (words.length === 24) {
        throw configError('mnemonic: a 24-word phrase is an xHD account; load it with @txnlab/zerosignal/accounts/xhd')
    }
    if (words.length !== 25) {
        throw configError(`mnemonic: unsupported word count ${words.length} (want a 25-word Algorand mnemonic)`)
    }
    let account
    try {
        account = mnemonicToSecretKey(words.join(' '))
    } catch {
        // Not the cause: algosdk's message can name the word it did not know.
        throw configError('mnemonic: invalid 25-word Algorand mnemonic (bad word or checksum)')
    }
    return algosdkSigner(account)
}
