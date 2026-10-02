/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Source icons on a tool-round action: the mime allowlist, the size budget, the
// host key the icons map is keyed by, and the magic-number sniff. Mirrors
// proto/go/tools/tool_icon.go.
//
// A node fetches each site's favicon and inlines the bytes so the consumer never
// contacts the site: an <img src> pointing at it would hand every host in a
// search result the reader's IP and a timestamp.

import { isLinkableUrl } from './url.js'

// The allowlist. image/svg+xml is absent on purpose: SVG is an active document,
// and these are third-party bytes a consumer inlines into its own page.
export const ICON_MIME_ICO = 'image/x-icon'
export const ICON_MIME_PNG = 'image/png'
export const ICON_MIME_GIF = 'image/gif'
export const ICON_MIME_JPEG = 'image/jpeg'
export const ICON_MIME_WEBP = 'image/webp'

const ICON_MIMES: ReadonlySet<string> = new Set([
    ICON_MIME_ICO,
    ICON_MIME_PNG,
    ICON_MIME_GIF,
    ICON_MIME_JPEG,
    ICON_MIME_WEBP,
])

/** Bound on one icon's decoded bytes. */
export const MAX_ICON_RAW_BYTES = 16 << 10
/** Bound on the base64 of all icons on one action, as it rides the sealed frame. */
export const MAX_ICONS_TOTAL_B64_BYTES = 96 << 10
/** Bound on how many hosts one action may carry an icon for. */
export const MAX_ICON_HOSTS = 12

/** One site's favicon: base64 bytes and the raster mime a node sniffed from them. */
export interface SourceIcon {
    mime: string
    data_b64: string
}

/** Whether mime is one of the raster formats an icon may carry. */
export function isIconMime(mime: unknown): mime is string {
    return typeof mime === 'string' && ICON_MIMES.has(mime)
}

/**
 * The key a URL's icon is filed under in ToolAction.icons: the WHATWG
 * `URL.hostname` (lowercase, no port, IDN in punycode, IPv6 bracketed in its
 * WHATWG form), or null for a URL isLinkableUrl refuses.
 *
 * "www." is not stripped. A display layer that trims it must still look icons
 * up by this key, since that is the key the node derived.
 */
export function iconHostKey(rawUrl: string): string | null {
    return isLinkableUrl(rawUrl) ? new URL(rawUrl).hostname : null
}

function startsWith(b: Uint8Array, prefix: readonly number[], at = 0): boolean {
    if (b.length < at + prefix.length) return false
    return prefix.every((v, i) => b[at + i] === v)
}

const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))

/**
 * The canonical mime for raw icon bytes, from their magic number, or "" when
 * they are not a format an icon may carry. The bytes decide, not a
 * Content-Type a third-party site chose.
 */
export function iconMimeFromBytes(b: Uint8Array): string {
    if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return ICON_MIME_PNG
    if (startsWith(b, [0xff, 0xd8, 0xff])) return ICON_MIME_JPEG
    if (startsWith(b, ascii('GIF87a')) || startsWith(b, ascii('GIF89a'))) return ICON_MIME_GIF
    if (startsWith(b, ascii('RIFF')) && startsWith(b, ascii('WEBP'), 8)) return ICON_MIME_WEBP
    // 00 00 02 00 is a cursor in the same container, which is not an image to render.
    if (startsWith(b, [0x00, 0x00, 0x01, 0x00])) return ICON_MIME_ICO
    return ''
}

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/

/** The exact decoded size of standard padded base64, or -1 if s isn't that. */
export function base64DecodedLength(s: string): number {
    if (s.length === 0 || s.length % 4 !== 0 || !BASE64_RE.test(s)) return -1
    const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0
    return (s.length / 4) * 3 - pad
}

/**
 * The mime sniffed from the first bytes of valid padded base64, enough for
 * every magic number iconMimeFromBytes knows, or "" for anything else.
 */
export function sniffBase64Mime(b64: string): string {
    if (base64DecodedLength(b64) <= 0) return ''
    const head = atob(b64.slice(0, 16))
    return iconMimeFromBytes(Uint8Array.from(head, (c) => c.charCodeAt(0)))
}

/**
 * A data: URL for an icon, or null if the icon breaks any rule a node is held
 * to — including bytes that are not the format the mime claims, which a node
 * never sends because it sniffs. Accepts a missing icon, since a node leaves
 * out a host it already sent on the stream.
 */
export function iconDataUrl(icon: SourceIcon | null | undefined): string | null {
    if (typeof icon !== 'object' || icon === null || !isIconMime(icon.mime)) return null
    if (typeof icon.data_b64 !== 'string') return null
    const raw = base64DecodedLength(icon.data_b64)
    if (raw <= 0 || raw > MAX_ICON_RAW_BYTES || sniffBase64Mime(icon.data_b64) !== icon.mime) return null
    return `data:${icon.mime};base64,${icon.data_b64}`
}

// The shape a key must have before it is worth parsing: WHATWG hostnames are
// ASCII after IDNA, with brackets and colons for IPv6 and the underscore WHATWG
// permits. The length bound is DNS's.
const HOST_KEY_RE = /^[a-z0-9._\-:[\]]{1,253}$/

/**
 * Applies the node's icon rules to an icons map from the wire: a key that is
 * its own WHATWG hostname, an icon iconDataUrl accepts, at most MAX_ICON_HOSTS
 * entries, and first-fit within the total budget in the order the map arrived.
 * Null when nothing survives.
 *
 * The result has no prototype, so a host named `__proto__` is an ordinary
 * entry; look entries up with Object.hasOwn or a plain index, not `in`.
 */
export function sanitizeIcons(raw: unknown): Record<string, SourceIcon> | null {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
    const out = Object.create(null) as Record<string, SourceIcon>
    let n = 0
    let total = 0
    for (const [host, value] of Object.entries(raw as Record<string, unknown>)) {
        if (n === MAX_ICON_HOSTS) break
        if (!HOST_KEY_RE.test(host) || iconHostKey(`https://${host}/`) !== host) continue
        if (typeof value !== 'object' || value === null) continue
        const { mime, data_b64: b64 } = value as Record<string, unknown>
        if (typeof b64 !== 'string' || typeof mime !== 'string') continue
        const icon = { mime, data_b64: b64 }
        if (iconDataUrl(icon) === null) continue
        if (total + b64.length > MAX_ICONS_TOTAL_B64_BYTES) continue
        total += b64.length
        out[host] = icon
        n++
    }
    return n > 0 ? out : null
}
