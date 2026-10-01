/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// TypeScript mirror of proto/go/tokenize/imagedims.go. See that file for the
// full rationale; the short version:
//
// v1 prices every image at the 2048x2048 high-detail fallback (2805 tokens)
// because no client sets width/height on an image part — and none should, since
// they aren't standard fields and a strict upstream rejects unknown keys.
// Measured against the corpus that is 3.7x-11x the true cost. But the bytes are
// already in the body: a pasted image rides as a `data:image/...;base64,...`
// URL, so the bound reads the dimensions out of the image HEADER and the
// client, proxy and node all derive the same number from the same body.
//
// Two hard rules, because the node runs this on attacker-controlled input:
// HEADER ONLY (never decode an image — that is a decompression-bomb vector) and
// BOUNDED READ (a 50 MB data URL costs the same as a 50 KB one). Anything
// unrecognised falls through to the 2048x2048 fallback: the failure direction is
// always "charge more".

import { base64, base64nopad } from '@scure/base'

/** Decoded bytes examined. Past this, the fallback applies. Large enough to
 *  clear a JPEG's EXIF/ICC blocks before its SOF marker. */
export const IMAGE_HEADER_SCAN_BYTES = 64 * 1024

/** base64 encodes 3 bytes per 4 characters. */
const BASE64_CHARS_PER_SCAN = (Math.floor(IMAGE_HEADER_SCAN_BYTES / 3) + 1) * 4

/** Clamp for a header-declared dimension — headers are attacker-controlled and
 *  PNG stores 32-bit width/height, so an unclamped tile count would overflow. */
export const IMAGE_MAX_DIMENSION_PX = 16384

export interface ImageDims {
  width: number
  height: number
}

/** Pixel dimensions encoded in a data: URL's image header, or null. */
export function imageDimsFromUrl(url: string): ImageDims | null {
  const raw = decodeImageHeader(url)
  if (!raw) return null
  return sniffImageDims(raw)
}

function decodeImageHeader(url: string): Uint8Array | null {
  if (!url.startsWith('data:')) return null
  const idx = url.indexOf(';base64,')
  if (idx < 0) return null
  let payload = stripAsciiWhitespace(url.slice(idx + ';base64,'.length))
  if (payload.length > BASE64_CHARS_PER_SCAN) payload = payload.slice(0, BASE64_CHARS_PER_SCAN)
  // Truncating mid-quantum leaves a length that isn't a multiple of 4; drop the
  // partial group so the decode stays strict and cheap.
  payload = payload.slice(0, payload.length - (payload.length % 4))
  if (payload === '') return null
  try {
    const raw = base64.decode(payload)
    return raw.length > 0 ? raw : null
  } catch {
    try {
      const raw = base64nopad.decode(trimTrailingPadding(payload))
      return raw.length > 0 ? raw : null
    } catch {
      return null
    }
  }
}

/**
 * Removes the whitespace a line-wrapping base64 encoder inserts. Go's
 * encoding/base64 silently skips \r and \n; @scure/base rejects them outright,
 * so without this a MIME-wrapped data URL — what Java's Base64.getMimeEncoder,
 * Python's base64.encodebytes and the openssl base64 CLI all emit by default —
 * reads its true dimensions on the node and the 2048x2048 fallback on the
 * client, and the node then rejects an honest request.
 */
function stripAsciiWhitespace(s: string): string {
  // Deliberately not a regex, and neither is trimTrailingPadding: this runs on
  // an attacker-controlled ~87 KB string on the browser's main thread.
  let out = ''
  let start = 0
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 32 || c === 9 || c === 10 || c === 13 || c === 11 || c === 12) {
      out += s.slice(start, i)
      start = i + 1
    }
  }
  return start === 0 ? s : out + s.slice(start)
}

/**
 * Drops trailing '=' padding with a linear scan.
 *
 * This replaced `payload.replace(/=+$/, '')`, which is catastrophic
 * backtracking: on `'='.repeat(N) + 'A'` the greedy `=+` retries from every
 * start position, O(N^2). At the 87,384-char scan cap that measured 2.8 SECONDS
 * per image part on the main thread — and the input is reachable, since a node's
 * returned image is stored as a data URL and replayed on every later turn of the
 * conversation.
 */
function trimTrailingPadding(s: string): string {
  let end = s.length
  while (end > 0 && s.charCodeAt(end - 1) === 61) end--
  return end === s.length ? s : s.slice(0, end)
}

/** Bounds-checked byte read. Out-of-range reads yield 0, mirroring the explicit
 *  length guards on the Go side. */
function at(b: Uint8Array, i: number): number {
  return i >= 0 && i < b.length ? (b[i] as number) : 0
}

function ascii(b: Uint8Array, start: number, end: number): string {
  let s = ''
  for (let i = start; i < end && i < b.length; i++) s += String.fromCharCode(at(b, i))
  return s
}

/**
 * Dispatches on the format's magic bytes.
 *
 * GIF is deliberately ABSENT. Its Logical Screen Descriptor — the only size
 * field in the header — is not the size a decoder reports: PIL, and therefore
 * the transformers/vLLM image path, use the per-frame Image Descriptor. The two
 * may legally disagree, and the LSD is four payer-controlled bytes, so patching
 * them to 1x1 dropped a real 4096x4096 GIF from 11012 tokens to 302 — a 36x
 * under-reserve the node cannot detect, because it re-measures with this same
 * function. Every other format's header IS authoritative for real decoders, so
 * only GIF has the gap.
 */
function sniffImageDims(b: Uint8Array): ImageDims | null {
  if (b.length >= 24 && ascii(b, 0, 8) === '\x89PNG\r\n\x1a\n' && ascii(b, 12, 16) === 'IHDR') {
    return { width: be32(b, 16), height: be32(b, 20) }
  }
  if (b.length >= 12 && ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'WEBP') {
    return webpDims(b)
  }
  if (b.length >= 4 && at(b, 0) === 0xff && at(b, 1) === 0xd8) {
    return jpegDims(b)
  }
  return null
}

/** All three WebP chunk layouts: extended (VP8X), lossy (VP8 ), lossless (VP8L). */
function webpDims(b: Uint8Array): ImageDims | null {
  if (b.length < 16) return null
  switch (ascii(b, 12, 16)) {
    case 'VP8X':
      // 24-bit little-endian (canvas width - 1, canvas height - 1) at +24.
      if (b.length < 30) return null
      return { width: le24(b, 24) + 1, height: le24(b, 27) + 1 }
    case 'VP8 ':
      // Keyframe header: 3-byte frame tag, 3-byte start code, then 14-bit
      // width and height.
      if (b.length < 30 || at(b, 23) !== 0x9d || at(b, 24) !== 0x01 || at(b, 25) !== 0x2a) return null
      return { width: le16(b, 26) & 0x3fff, height: le16(b, 28) & 0x3fff }
    case 'VP8L': {
      // Signature byte 0x2f, then 14 bits of (width - 1) and 14 of (height - 1).
      if (b.length < 25 || at(b, 20) !== 0x2f) return null
      const bits = (at(b, 21) | (at(b, 22) << 8) | (at(b, 23) << 16) | (at(b, 24) << 24)) >>> 0
      return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 }
    }
  }
  return null
}

/** JPEG puts no dimensions at a fixed offset — they live in whichever SOFn
 *  arrives after an arbitrary run of application and quantisation segments. */
function jpegDims(b: Uint8Array): ImageDims | null {
  let i = 2
  while (i + 3 < b.length) {
    if (at(b, i) !== 0xff) {
      // Not at a marker boundary: resynchronise rather than trusting a length
      // field we may have mis-read.
      i++
      continue
    }
    const marker = at(b, i + 1)
    if (marker === 0xff) {
      // Fill byte; markers may be padded with any number of 0xff.
      i++
      continue
    }
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      // Standalone markers carry no length field.
      i += 2
      continue
    }
    if (marker === 0xda || marker === 0xd9) {
      // Start of scan / end of image: entropy-coded data follows.
      return null
    }
    const segLen = be16(b, i + 2)
    if (segLen < 2) return null
    // SOF0..SOF15, excluding DHT (0xc4), JPG (0xc8) and DAC (0xcc).
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      if (i + 9 > b.length) return null
      // Segment layout: length(2) precision(1) height(2) width(2).
      return { width: be16(b, i + 7), height: be16(b, i + 5) }
    }
    i += 2 + segLen
  }
  return null
}

function be16(b: Uint8Array, o: number): number {
  if (o + 2 > b.length) return 0
  return (at(b, o) << 8) | at(b, o + 1)
}

function be32(b: Uint8Array, o: number): number {
  if (o + 4 > b.length) return 0
  // >>> 0 keeps a high bit set in byte 0 from turning the result negative.
  return ((at(b, o) << 24) | (at(b, o + 1) << 16) | (at(b, o + 2) << 8) | at(b, o + 3)) >>> 0
}

function le16(b: Uint8Array, o: number): number {
  if (o + 2 > b.length) return 0
  return at(b, o) | (at(b, o + 1) << 8)
}

function le24(b: Uint8Array, o: number): number {
  if (o + 3 > b.length) return 0
  return at(b, o) | (at(b, o + 1) << 8) | (at(b, o + 2) << 16)
}
