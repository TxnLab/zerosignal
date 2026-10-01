/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// TypeScript mirror of proto/go/tokenize/bound_v2.go — bound version 2, which is
// v1's text treatment plus TRUE image dimensions.
//
// v1 prices every image part the caller didn't annotate at a 2048x2048
// high-detail fallback (2805 tokens), because no client sets width/height on an
// image part and none should: they aren't standard OpenAI fields and a strict
// upstream rejects unknown keys. That fallback is wrong in both directions —
// 3.7x-11x too high for the ordinary 512x512 / 1024x768 paste, and materially
// too LOW above 2048x2048 (a 4096x4096 image really costs ~11k tokens). v2 reads
// the real dimensions out of the image header instead (see image-dims.ts).
//
// The TEXT term is deliberately IDENTICAL to v1. An earlier draft also replaced
// it with a character-class run classifier calibrated against
// proto/testdata/tokenize_corpus; that was withdrawn because the constants were
// derived from the same samples they were validated against, and the first
// unseen shapes under-counted by up to 3x. v1's known text-side under-counts
// (base64, hex, emoji, embedded JSON) therefore persist unchanged in v2 — they
// are pre-existing, not introduced here.
//
// Because the image term moves in BOTH directions, v2 is not uniformly smaller
// or larger than v1, which is why the version is negotiated explicitly on the
// wire rather than inferred.
//
// The node re-computes this bound to enforce the reserve, so any Go/TS
// disagreement rejects an honest client's request. Three sources of
// disagreement are closed deliberately — see the BOM strip, the non-finite
// number handling, and MAX_IMAGE_WALK_DEPTH.

import { FLAT_MARGIN, BYTES_PER_TOKEN, inputTokenBound } from './bound.js'
import { imageDimsFromUrl, IMAGE_MAX_DIMENSION_PX } from './image-dims.js'

const IMAGE_TOKENS_LOW = 85
const IMAGE_TOKENS_HIGH_BASE = 85
const IMAGE_TOKENS_HIGH_TILE = 170
const IMAGE_TILE_EDGE_PX = 512
const IMAGE_DEFAULT_WIDTH_PX = 2048
const IMAGE_DEFAULT_HEIGHT_PX = 2048

/**
 * Bounds the recursive search for image parts.
 *
 * Exists for parity, not just safety: JS blows its call stack around 4,000
 * frames and throws, while Go's encoding/json refuses to decode past ~10,000
 * nesting levels and returns an error instead. Left alone, a deeply nested body
 * makes one implementation throw and the other fall back. Capping well below
 * both limits makes them agree by construction, and removes an uncaught
 * RangeError from the client's send path.
 */
const MAX_IMAGE_WALK_DEPTH = 256

/** Bound versions. The version a caller sizes with rides on the reserve request
 *  and the node enforces with that same version, because v2's image term moves
 *  in both directions relative to v1 and cannot be inferred. */
export const BOUND_VERSION_1 = 1
export const BOUND_VERSION_2 = 2
export const DEFAULT_BOUND_VERSION = BOUND_VERSION_1

/** Whether v is a bound version this build implements (0 = unspecified). */
export function supportedBoundVersion(v: number): boolean {
  return v === 0 || v === BOUND_VERSION_1 || v === BOUND_VERSION_2
}

/**
 * Computes the bound for an explicit version. The node uses it to measure a
 * request with the same function the caller sized it with; an unknown version
 * falls back to v1 so an unrecognised value can never under-charge on the text
 * term.
 */
export function inputTokenBoundVersion(body: Uint8Array | string, version: number): number {
  return version === BOUND_VERSION_2 ? inputTokenBoundV2(body) : inputTokenBound(body)
}

type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue }

function ceilDiv(a: number, b: number): number {
  return Math.ceil(a / b)
}

/**
 * Strips a leading UTF-8 BOM. TextDecoder removes it implicitly before
 * JSON.parse while Go's encoding/json rejects it, so both sides now remove it
 * explicitly — and, importantly, both measure the text term over the
 * POST-strip byte length.
 */
function stripBom(bytes: Uint8Array): Uint8Array {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return bytes.subarray(3)
  }
  return bytes
}

/**
 * Safe upper bound on the input tokens a request body will consume:
 * ceil(textBytes / 2) + imageTileTokens + FLAT_MARGIN, with the tile tokens
 * derived from each image's true pixel dimensions where the body carries the
 * bytes to determine them.
 */
export function inputTokenBoundV2(body: Uint8Array | string): number {
  const raw = typeof body === 'string' ? new TextEncoder().encode(body) : body
  const bytes = stripBom(raw)
  if (bytes.byteLength === 0) return FLAT_MARGIN

  const stats = imageStatsV2(bytes)
  if (stats === null) {
    // Unparseable, or nested past the walk cap: charge every byte as text.
    // Never smaller than the parsed answer, so this direction is safe.
    return ceilDiv(bytes.byteLength, BYTES_PER_TOKEN) + FLAT_MARGIN
  }

  const textBytes =
    stats.urlBytes < bytes.byteLength ? bytes.byteLength - stats.urlBytes : 0
  return ceilDiv(textBytes, BYTES_PER_TOKEN) + stats.tileTokens + FLAT_MARGIN
}

interface ImageStats {
  urlBytes: number
  tileTokens: number
}

/** Walks the body for image content parts. null means the body could not be
 *  walked and the caller must fall back to the raw-byte bound. */
function imageStatsV2(bytes: Uint8Array): ImageStats | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: false }).decode(bytes))
  } catch {
    return null
  }
  const stats: ImageStats = { urlBytes: 0, tileTokens: 0 }
  return walkForImagesV2(parsed as JsonValue, 0, stats) ? stats : null
}

/** Returns false if the structure is nested past MAX_IMAGE_WALK_DEPTH, which the
 *  caller turns into a raw-byte fallback. */
function walkForImagesV2(v: JsonValue, depth: number, stats: ImageStats): boolean {
  if (depth > MAX_IMAGE_WALK_DEPTH) return false
  if (Array.isArray(v)) {
    for (const child of v) {
      if (!walkForImagesV2(child, depth + 1, stats)) return false
    }
    return true
  }
  if (v === null || typeof v !== 'object') return true

  const obj = v as Record<string, JsonValue>
  const typ = typeof obj.type === 'string' ? lowerAscii(obj.type) : ''
  if (typ === 'image_url' || typ === 'input_image') {
    stats.tileTokens += imageTokensFromObjectV2(obj)
    stats.urlBytes += new TextEncoder().encode(imageUrlStringFromObject(obj)).byteLength
    return true
  }
  for (const child of Object.values(obj)) {
    if (!walkForImagesV2(child, depth + 1, stats)) return false
  }
  return true
}

/**
 * Reads a caller-declared width/height.
 *
 * One shared semantic, mirrored exactly in Go: anything that is not a finite
 * number, or is below 1, reads as ABSENT (0) rather than as a dimension. That
 * matters because a nested `image_url: {"width": 0}` must not erase a valid
 * outer value — Go used to adopt any numeric value including 0, negatives and
 * fractions, while TS only adopted positives, so the same body produced the
 * 2048x2048 fallback on one side and a real size on the other. Values above the
 * clamp are clamped rather than converted, so no out-of-range value ever reaches
 * an integer conversion (which is implementation-defined in Go).
 */
function imageDimField(obj: Record<string, JsonValue>, key: string): number {
  const v = obj[key]
  if (typeof v !== 'number' || Number.isNaN(v)) return 0
  // +Infinity is what JSON.parse yields for a literal outside float64 range;
  // Go's decoder reports the same overflow and both clamp.
  if (v === Number.POSITIVE_INFINITY) return IMAGE_MAX_DIMENSION_PX
  if (!Number.isFinite(v) || v < 1) return 0
  if (v > IMAGE_MAX_DIMENSION_PX) return IMAGE_MAX_DIMENSION_PX
  return Math.trunc(v)
}

/**
 * Prices one image content part with OpenAI's vision tile math. Explicit
 * caller-declared dimensions win; otherwise the true dimensions are recovered
 * from the image header. Only when both fail does it charge v1's 2048x2048
 * fallback.
 */
export function imageTokensFromObjectV2(obj: Record<string, JsonValue>): number {
  let detail = typeof obj.detail === 'string' ? lowerAscii(obj.detail) : ''
  let width = imageDimField(obj, 'width')
  let height = imageDimField(obj, 'height')

  const nested = obj.image_url
  if (nested !== null && typeof nested === 'object' && !Array.isArray(nested)) {
    const inner = nested as Record<string, JsonValue>
    if (typeof inner.detail === 'string' && inner.detail !== '') detail = lowerAscii(inner.detail)
    const w = imageDimField(inner, 'width')
    if (w > 0) width = w
    const h = imageDimField(inner, 'height')
    if (h > 0) height = h
  }

  if (detail === '' || detail === 'auto') detail = 'high'
  if (detail === 'low') return IMAGE_TOKENS_LOW

  if (width <= 0 || height <= 0) {
    const dims = imageDimsFromUrl(imageUrlStringFromObject(obj))
    if (dims && dims.width > 0 && dims.height > 0) {
      width = dims.width
      height = dims.height
    }
  }
  if (width <= 0) width = IMAGE_DEFAULT_WIDTH_PX
  if (height <= 0) height = IMAGE_DEFAULT_HEIGHT_PX
  if (width > IMAGE_MAX_DIMENSION_PX) width = IMAGE_MAX_DIMENSION_PX
  if (height > IMAGE_MAX_DIMENSION_PX) height = IMAGE_MAX_DIMENSION_PX

  const tilesX = Math.max(1, Math.ceil(width / IMAGE_TILE_EDGE_PX))
  const tilesY = Math.max(1, Math.ceil(height / IMAGE_TILE_EDGE_PX))
  return IMAGE_TOKENS_HIGH_BASE + IMAGE_TOKENS_HIGH_TILE * tilesX * tilesY
}

function imageUrlStringFromObject(obj: Record<string, JsonValue>): string {
  const v = obj.image_url
  if (typeof v === 'string') return v
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    const url = (v as Record<string, JsonValue>).url
    if (typeof url === 'string') return url
  }
  return ''
}

/** Lowercases ASCII letters only. String.toLowerCase applies full Unicode case
 *  folding, which is not identical to the Go mirror's behaviour for every input;
 *  restricting to ASCII removes the question for the discriminants this is used
 *  on. */
function lowerAscii(s: string): string {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}
