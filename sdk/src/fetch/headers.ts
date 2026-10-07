/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The node's response headers as the caller sees them, mirroring proto/go/zs
// handler/headers.go.

// Per-hop headers that must not be forwarded end to end. Headers keys are lowercase.
const HOP_BY_HOP = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
])

const isZs = (name: string) => name.toLowerCase().startsWith('x-zs-')

/**
 * stripZsHeaders deletes every X-Zs-* header (SPEC §5.2 step 4): the caller
 * sees no response key, receipt or settle group. Nothing the node set
 * reaches the caller; the SDK's own usage headers are set after it.
 */
export function stripZsHeaders(h: Headers): void {
    const names: string[] = []
    h.forEach((_v, k) => {
        if (isZs(k)) names.push(k)
    })
    for (const k of names) h.delete(k)
}

/**
 * snapshotZsHeaders copies the X-Zs-* headers the SDK set on h before the node
 * answered, such as the max_output clamp marker. Snapshot and restore rather
 * than an allow-list inside the strip, because the strip is a security
 * control: the node's headers are copied first, so a node answering with the
 * same name has already replaced the SDK's value by the time the strip runs,
 * and exempting the name would hand the node's value to the caller.
 */
export function snapshotZsHeaders(h: Headers): [string, string][] {
    const saved: [string, string][] = []
    h.forEach((v, k) => {
        if (isZs(k)) saved.push([k, v])
    })
    return saved
}

/** stripNodeZsHeaders drops every node-set X-Zs-* from h and puts the SDK's own back. */
export function stripNodeZsHeaders(h: Headers, saved: [string, string][]): void {
    stripZsHeaders(h)
    for (const [k, v] of saved) h.set(k, v)
}

/**
 * copyResponseHeaders copies src onto dst, each name replacing dst's. It
 * skips the hop-by-hop headers, and Access-Control-*: those describe the CORS
 * contract between a browser and whoever answers it, which is the caller's
 * surface, not the node.
 */
export function copyResponseHeaders(dst: Headers, src: Headers): void {
    const copied: [string, string][] = []
    src.forEach((v, k) => {
        if (HOP_BY_HOP.has(k) || k.startsWith('access-control-')) return
        copied.push([k, v])
    })
    for (const [k] of copied) dst.delete(k)
    for (const [k, v] of copied) dst.append(k, v)
}
