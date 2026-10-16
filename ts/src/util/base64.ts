/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { base64 } from '@scure/base'

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/**
 * decodeGoStdBase64 reads base64 as Go's base64.StdEncoding does, which is not
 * strict: it skips CR and LF wherever they fall, and ignores the unused low
 * bits of the last character before the padding. @scure/base refuses both, so
 * without this a value Go accepts would fail closed here. It requires the
 * padding Go requires, which atob does not. Throws on anything Go refuses.
 */
export function decodeGoStdBase64(s: string): Uint8Array {
    let t = s.replace(/[\r\n]/g, '')
    const pad = t.endsWith('==') ? 2 : t.endsWith('=') ? 1 : 0
    const last = t.length - pad - 1
    if (pad > 0 && last >= 0) {
        const v = BASE64_ALPHABET.indexOf(t.charAt(last))
        // Before "==" the last character carries 2 bits of data, before "=" 4.
        if (v >= 0) t = t.slice(0, last) + BASE64_ALPHABET.charAt(v & (pad === 2 ? 0x30 : 0x3c)) + t.slice(last + 1)
    }
    return base64.decode(t)
}
