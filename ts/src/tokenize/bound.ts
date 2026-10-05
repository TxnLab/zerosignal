/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// TypeScript mirror of proto/go/tokenize/bound.go — the model-agnostic
// input-token UPPER bound used to size a reserve's max_price and to enforce
// that bound at inference time. The node re-computes the SAME bound over the
// decrypted body to check it against the reserved input_count, so this
// implementation and the Go one MUST agree byte-for-byte — both sides assert
// against proto/testdata/tokenize_vectors.json. If they drift, an honest
// client's request would be rejected / cut off by the node.

export const BYTES_PER_TOKEN = 2
export const FLAT_MARGIN = 32
export const IMAGE_TOKENS_LOW = 85
export const IMAGE_TOKENS_HIGH_BASE = 85
export const IMAGE_TOKENS_HIGH_TILE = 170
export const IMAGE_TILE_EDGE_PX = 512
export const IMAGE_DEFAULT_WIDTH_PX = 2048
export const IMAGE_DEFAULT_HEIGHT_PX = 2048
export const IMAGE_DEFAULT_DETAIL = 'high'

/**
 * Safe upper bound on the input tokens a request body will consume:
 * ceil(textBytes / 2) + imageTileTokens + FLAT_MARGIN, where textBytes
 * excludes the bytes of any image-URL strings (scored by the tile formula
 * instead). A body that doesn't parse as JSON still gets the raw-byte text
 * bound (images contribute 0).
 */
export function inputTokenBound(body: Uint8Array | string): number {
  const byteLength =
    typeof body === 'string' ? new TextEncoder().encode(body).byteLength : body.byteLength
  const { tileTokens, urlBytes } = imageStatsIn(body)
  const textBytes = urlBytes < byteLength ? byteLength - urlBytes : 0
  const textTokens = Math.ceil(textBytes / BYTES_PER_TOKEN)
  return textTokens + tileTokens + FLAT_MARGIN
}

/**
 * Input-token count to commit to a reserve: the tight body bound plus a
 * tool-loop headroom term (zero unless the request carries tools), floored to
 * a sane minimum and — when the operator declares a context window — capped at
 * context_window − max_output (today's worst case). The cap is applied LAST so
 * the result always satisfies input + max_output ≤ context_window.
 *
 * Mirrors proto/go/tokenize.ReserveInputCount. All arithmetic stays within the
 * safe-integer range for any realistic body/headroom (< 2^53), matching Go's
 * uint64 exactly.
 */
export function reserveInputCount(args: {
  bodyBound: number
  carriesTools: boolean
  maxToolIterations: number
  perIterHeadroom: number
  maxOutput: number
  contextWindow: number
  floor: number
}): number {
  const headroom = args.carriesTools
    ? Math.max(0, Math.floor(args.maxToolIterations)) * Math.max(0, Math.floor(args.perIterHeadroom))
    : 0
  let want = Math.max(0, Math.floor(args.bodyBound)) + headroom
  if (want < args.floor) {
    want = args.floor
  }
  // Cap last: a declared context window is the authoritative ceiling and must
  // win over the floor so FitsContextWindow always holds.
  if (args.contextWindow > 0) {
    const ceil = args.contextWindow > args.maxOutput ? args.contextWindow - args.maxOutput : 0
    if (want > ceil) {
      want = ceil
    }
  }
  return want
}

/**
 * Whether the body carries a non-empty previous_response_id — a server-side
 * response chain whose accumulated history the node cannot see, so the caller
 * must reserve worst-case for it.
 */
export function bodyHasPreviousResponseId(body: Uint8Array | string): boolean {
  const parsed = tryParse(body)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false
  const v = (parsed as Record<string, unknown>).previous_response_id
  return typeof v === 'string' && v.length > 0
}

/**
 * Whether the body carries a non-empty top-level tools array — the signal a
 * caller uses to add tool-loop headroom to the reserve.
 */
export function bodyHasTools(body: Uint8Array | string): boolean {
  const parsed = tryParse(body)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false
  const v = (parsed as Record<string, unknown>).tools
  return Array.isArray(v) && v.length > 0
}

function tryParse(body: Uint8Array | string): unknown {
  const text = typeof body === 'string' ? body : tryDecodeUtf8(body)
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function imageStatsIn(body: Uint8Array | string): { tileTokens: number; urlBytes: number } {
  const parsed = tryParse(body)
  if (parsed === null) return { tileTokens: 0, urlBytes: 0 }
  let tileTokens = 0
  let urlBytes = 0
  walkForImages(parsed, (tile, urlBytesForPart) => {
    tileTokens += tile
    urlBytes += urlBytesForPart
  })
  return { tileTokens, urlBytes }
}

function tryDecodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  } catch {
    return null
  }
}

function walkForImages(value: unknown, add: (tileTokens: number, urlBytes: number) => void): void {
  if (value === null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const child of value) walkForImages(child, add)
    return
  }
  const obj = value as Record<string, unknown>
  const typ = typeof obj.type === 'string' ? obj.type.toLowerCase() : ''
  if (typ === 'image_url' || typ === 'input_image') {
    add(imageTokensFromObject(obj), imageURLBytesFromObject(obj))
    return
  }
  for (const child of Object.values(obj)) walkForImages(child, add)
}

function imageURLBytesFromObject(obj: Record<string, unknown>): number {
  const v = obj.image_url
  if (typeof v === 'string') {
    return new TextEncoder().encode(v).byteLength
  }
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const url = (v as Record<string, unknown>).url
    if (typeof url === 'string') {
      return new TextEncoder().encode(url).byteLength
    }
  }
  return 0
}

function imageTokensFromObject(obj: Record<string, unknown>): number {
  let detail = stringField(obj, 'detail')
  let width = numField(obj, 'width')
  let height = numField(obj, 'height')

  const nested = obj.image_url
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    const inner = nested as Record<string, unknown>
    const innerDetail = stringField(inner, 'detail')
    if (innerDetail) detail = innerDetail
    const innerW = numField(inner, 'width')
    if (innerW > 0) width = innerW
    const innerH = numField(inner, 'height')
    if (innerH > 0) height = innerH
  }

  const normalizedDetail = !detail || detail === 'auto' ? IMAGE_DEFAULT_DETAIL : detail
  if (normalizedDetail === 'low') return IMAGE_TOKENS_LOW

  if (width <= 0) width = IMAGE_DEFAULT_WIDTH_PX
  if (height <= 0) height = IMAGE_DEFAULT_HEIGHT_PX
  const tilesX = Math.max(1, Math.ceil(width / IMAGE_TILE_EDGE_PX))
  const tilesY = Math.max(1, Math.ceil(height / IMAGE_TILE_EDGE_PX))
  return IMAGE_TOKENS_HIGH_BASE + IMAGE_TOKENS_HIGH_TILE * tilesX * tilesY
}

function stringField(obj: Record<string, unknown>, key: string): string {
  const v = obj[key]
  return typeof v === 'string' ? v.toLowerCase() : ''
}

function numField(obj: Record<string, unknown>, key: string): number {
  const v = obj[key]
  if (typeof v === 'number' && Number.isFinite(v)) return v
  return 0
}
