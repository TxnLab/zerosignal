/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go's unicode.IsSpace, the separator strings.Fields splits a phrase on in
// go/keystore. JS's \s differs at two code points: it matches U+FEFF, which
// Go keeps as part of a word, and misses U+0085 (NEL), which Go splits on.
const GO_SPACE = /[\t\n\v\f\r \x85\xa0\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}]+/u

/**
 * phraseWords splits a recovery phrase into its words as Go's keystore does.
 * Separators are not part of a phrase: both forms are derived from the words
 * rejoined by single spaces, and a BIP-39 seed is PBKDF2 over that sentence.
 */
export function phraseWords(phrase: string): string[] {
    return phrase.split(GO_SPACE).filter((w) => w !== '')
}
