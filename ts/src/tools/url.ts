/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Which URLs a consumer may render as a link. Mirrors linkableURL in
// proto/go/tools/tool_action.go, pinned by testdata/tools_vectors.json.

// Characters Go's URL parser refuses outright (C0 controls, DEL) plus the
// backslash, which WHATWG reads as a slash in an http(s) URL. Refusing those
// rather than letting the parser normalize them means a URL is accepted only
// when the string handed back is the one the node fetched.
const REWRITTEN_OR_REFUSED = /[\x00-\x1f\x7f\\]/ // eslint-disable-line no-control-regex

// A '%' that does not start a two-hex-digit escape; Go refuses it, WHATWG keeps it.
const BAD_ESCAPE = /%(?![0-9A-Fa-f]{2})/

/**
 * Whether s is an http(s) URL with a host that a consumer can safely turn into
 * a link. Consumers receive these from operators they don't control, so check
 * every URL with this before it becomes an href.
 *
 * Built on the WHATWG URL parser, so it refuses a few URLs Go accepts and no
 * browser could open: a port above 65535, a host whose last label is numeric
 * but not an IPv4 address (`256.1.1.1`, `example.123`), and `<` / `>` in a host.
 */
export function isLinkableUrl(s: unknown): s is string {
    if (typeof s !== 'string' || !/^https?:\/\//i.test(s)) return false
    if (REWRITTEN_OR_REFUSED.test(s) || BAD_ESCAPE.test(s)) return false
    try {
        const u = new URL(s)
        return u.protocol === 'http:' || u.protocol === 'https:'
    } catch {
        return false
    }
}
