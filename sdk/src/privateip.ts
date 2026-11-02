/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The dial-time half of the SSRF guard: whether a RESOLVED address may be
// dialed, as Go's httpx dial hook decides it (blockPrivateControl over
// IsPrivateIP). hostguard.ts is the other half, a check of the registered
// hostname that a browser can make without a resolver; this one judges the
// address a socket is about to connect to, so it also catches a name that
// resolves into private space, and a rebind, which the literal check can't.
//
// The ranges are Go's, not the literal check's: Go allows 0.0.0.1, 240/4 and
// the broadcast address, and judges an IPv4-mapped address by its IPv4 half,
// as it judges a NAT64, SIIT or 6to4 address by the IPv4 address it carries.
// Pinned by testdata/private_target_vectors.json, which Go generates.

/**
 * parseIP is Go's net.ParseIP: dotted-decimal IPv4 without leading zeros, or
 * IPv6 with an optional embedded IPv4 in its last 32 bits and no zone. It
 * returns the 16-byte form (IPv4 as ::ffff:a.b.c.d), or null.
 */
function parseIP(s: string): Uint8Array | null {
    for (const c of s) {
        if (c === '.') return parseIPv4(s)
        if (c === ':') return parseIPv6(s)
        if (c === '%') return null
    }
    return null
}

function v4Mapped(a: number, b: number, c: number, d: number): Uint8Array {
    const ip = new Uint8Array(16)
    ip[10] = 0xff
    ip[11] = 0xff
    ip.set([a, b, c, d], 12)
    return ip
}

function parseIPv4(s: string): Uint8Array | null {
    const f = parseIPv4Fields(s)
    return f && v4Mapped(f[0]!, f[1]!, f[2]!, f[3]!)
}

function parseIPv4Fields(s: string): number[] | null {
    const parts = s.split('.')
    if (parts.length !== 4) return null
    const out: number[] = []
    for (const p of parts) {
        if (!/^[0-9]{1,3}$/.test(p)) return null
        if (p.length > 1 && p[0] === '0') return null
        const v = Number(p)
        if (v > 255) return null
        out.push(v)
    }
    return out
}

function isHex(c: string): boolean {
    return /^[0-9a-fA-F]$/.test(c)
}

// netip's parseIPv6, less the zone: ParseIP refuses any address with one.
function parseIPv6(in6: string): Uint8Array | null {
    if (in6.includes('%')) return null
    const ip = new Uint8Array(16)
    let s = in6
    let ellipsis = -1
    if (s.startsWith('::')) {
        ellipsis = 0
        s = s.slice(2)
        if (s === '') return ip
    }
    let i = 0
    while (i < 16) {
        let off = 0
        let acc = 0
        for (; off < s.length && isHex(s[off]!); off++) {
            if (off > 3) return null
            acc = acc * 16 + parseInt(s[off]!, 16)
        }
        if (off === 0) return null
        if (off < s.length && s[off] === '.') {
            // An IPv4 tail replaces the final two groups, and only those.
            if (ellipsis < 0 && i !== 12) return null
            if (i + 4 > 16) return null
            const f = parseIPv4Fields(s)
            if (!f) return null
            ip.set(f, i)
            i += 4
            s = ''
            break
        }
        ip[i] = acc >> 8
        ip[i + 1] = acc & 0xff
        i += 2
        s = s.slice(off)
        if (s === '') break
        if (s[0] !== ':' || s.length === 1) return null
        s = s.slice(1)
        if (s[0] === ':') {
            if (ellipsis >= 0) return null
            ellipsis = i
            s = s.slice(1)
            if (s === '') break
        }
    }
    if (s !== '') return null
    if (i < 16) {
        if (ellipsis < 0) return null
        const n = 16 - i
        ip.copyWithin(ellipsis + n, ellipsis, i)
        ip.fill(0, ellipsis, ellipsis + n)
    } else if (ellipsis >= 0) {
        // :: must stand for at least one group of zeros.
        return null
    }
    return ip
}

// to4 is Go's IP.To4 on the 16-byte form: the IPv4 half of an IPv4-mapped
// address, or null.
function to4(ip: Uint8Array): Uint8Array | null {
    for (let k = 0; k < 10; k++) if (ip[k] !== 0) return null
    return ip[10] === 0xff && ip[11] === 0xff ? ip.subarray(12) : null
}

// Go's IsPrivateIP: loopback, RFC 1918 and ULA, link-local unicast and
// multicast, unspecified, multicast, and CGNAT 100.64/10; and an IPv6 address
// that carries such an IPv4 address, or can't be judged.
function isPrivateIP(ip: Uint8Array): boolean {
    const v4 = to4(ip)
    if (v4) return isPrivateIPv4(v4)
    const zeroTo = (n: number) => ip.subarray(0, n).every((x) => x === 0)
    if (
        zeroTo(12) || // IPv4-compatible ::/96, with loopback ::1 and unspecified ::
        (ip[0]! & 0xfe) === 0xfc || // ULA fc00::/7
        (ip[0] === 0xfe && (ip[1]! & 0xc0) === 0x80) || // link-local fe80::/10
        ip[0] === 0xff || // multicast ff00::/8, link-local multicast with it
        startsWith(ip, [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]) || // local-use NAT64 64:ff9b:1::/48
        startsWith(ip, [0x20, 0x01, 0x00, 0x00]) // Teredo 2001::/32
    ) {
        return true
    }
    // A translator or a 6to4 relay delivers these to the IPv4 address inside.
    if (startsWith(ip, [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0])) return isPrivateIPv4(ip.subarray(12)) // NAT64 64:ff9b::/96
    if (startsWith(ip, [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0])) return isPrivateIPv4(ip.subarray(12)) // SIIT ::ffff:0:0:0/96
    if (startsWith(ip, [0x20, 0x02])) return isPrivateIPv4(ip.subarray(2, 6)) // 6to4 2002::/16
    return false
}

function isPrivateIPv4(v4: Uint8Array): boolean {
    const [a, b, c, d] = [v4[0]!, v4[1]!, v4[2]!, v4[3]!]
    return (
        a === 127 ||
        a === 10 ||
        (a === 172 && (b & 0xf0) === 16) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254) ||
        (a === 224 && b === 0 && c === 0) ||
        (a === 0 && b === 0 && c === 0 && d === 0) ||
        (a & 0xf0) === 0xe0 ||
        (a === 100 && (b & 0xc0) === 64)
    )
}

function startsWith(ip: Uint8Array, prefix: readonly number[]): boolean {
    return prefix.every((x, k) => ip[k] === x)
}

/**
 * isPrivateAddress reports whether a dial to address must be refused: it is in
 * a private, loopback, link-local, unspecified, multicast or CGNAT range, it is
 * IPv6 that reaches one (NAT64, SIIT, 6to4) or can't be judged (::/96,
 * local-use NAT64, Teredo), or it is not an IP address at all (a name nobody
 * resolved fails closed).
 */
export function isPrivateAddress(address: string): boolean {
    const ip = parseIP(address)
    return ip === null || isPrivateIP(ip)
}

/** isLoopbackAddress is Go's net.IP.IsLoopback: 127/8, in either form, or ::1. */
export function isLoopbackAddress(address: string): boolean {
    const ip = parseIP(address)
    if (ip === null) return false
    const v4 = to4(ip)
    if (v4) return v4[0] === 127
    return ip.subarray(0, 15).every((x) => x === 0) && ip[15] === 1
}
