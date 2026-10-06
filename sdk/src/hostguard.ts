/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// SSRF guard for operator base URLs. An operator publishes its URL on-chain and
// the payer dials it, as a target and as a relay hop, so a URL naming localhost
// or a private range would turn the payer's own machine against itself or its
// LAN. Such operators are kept out of routing unless Config.allowPrivateHosts
// is set, for localnet development.
//
// This is a literal-host check: a browser can't resolve DNS. It catches
// localhost and *.localhost, mDNS *.local, literal private IPv4 and IPv6, and
// the unspecified address, which are the shapes an attacker can register. A
// name that resolves to a private address gets past it. In a browser that
// residue is the price of having no resolver. In Node the default fetch closes
// it as Go's httpx dial guard does, judging every address it is about to dial
// behind the same setting (node/fetch.ts, privateip.ts).
//
// It classifies URL.hostname, the WHATWG parser's canonical form, never the
// registered string. The parser rewrites an embedded IPv4 in hex
// ([::ffff:127.0.0.1] becomes [::ffff:7f00:1]), so a dotted-quad match on a v6
// host would never fire, and it keeps a trailing root dot (localhost.), which
// resolves like the bare name.

function ipv4Octets(host: string): [number, number, number, number] | null {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
    if (!m) return null
    const o = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as [number, number, number, number]
    return o.some((n) => n > 255) ? null : o
}

function isPrivateIPv4([a, b]: [number, number, number, number]): boolean {
    return (
        a === 127 || // loopback 127/8
        a === 10 || // 10/8
        (a === 172 && b >= 16 && b <= 31) || // 172.16/12
        (a === 192 && b === 168) || // 192.168/16
        (a === 169 && b === 254) || // link-local 169.254/16
        (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64/10
        a === 0 || // 0/8, with the unspecified address
        a >= 224 // multicast 224/4, reserved 240/4, broadcast
    )
}

// Blocks all of ::/96 (unspecified, loopback, IPv4-compatible, IPv4-mapped),
// ULA fc00::/7, link-local fe80::/10 and multicast ff00::/8.
function isPrivateIPv6(host: string): boolean {
    const h = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
    if (!h.includes(':')) return false
    // A mapped address can't be judged by its v4 half once the parser has
    // hex-encoded it, so the whole ::/96 goes. Its canonical form always starts
    // "::", and anything starting "::" is reserved 0::/8, never global unicast,
    // including a mapped public v4 that no public operator has reason to use.
    if (h.startsWith('::')) return true
    const first = parseInt(h.split(':')[0]!, 16)
    if (Number.isNaN(first)) return false
    return (
        (first >= 0xfc00 && first <= 0xfdff) || // ULA
        (first >= 0xfe80 && first <= 0xfebf) || // link-local
        first >= 0xff00 // multicast
    )
}

/**
 * isBlockedOperatorUrl reports whether baseUrl names localhost or a private
 * literal host. An unparseable URL is blocked.
 */
export function isBlockedOperatorUrl(baseUrl: string): boolean {
    let host: string
    try {
        host = new URL(baseUrl).hostname
    } catch {
        return true
    }
    const h = host.toLowerCase().replace(/\.$/, '')
    if (h === 'localhost' || h.endsWith('.localhost')) return true
    if (h.endsWith('.local')) return true
    const v4 = ipv4Octets(h)
    if (v4) return isPrivateIPv4(v4)
    return isPrivateIPv6(h)
}

/** operatorUrlAllowed is the routing policy: a private operator URL only with allowPrivateHosts. */
export function operatorUrlAllowed(baseUrl: string, allowPrivateHosts: boolean): boolean {
    return allowPrivateHosts || !isBlockedOperatorUrl(baseUrl)
}
