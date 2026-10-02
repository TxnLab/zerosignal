/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The request-body mutators a payer applies before sealing: dropRoutingPreferences,
// dropPromptCacheKey, dropEmptyTools and clampMaxOutput. Mirrors the functions of
// the same names in proto/go/inject; their godoc carries the reasons for each.
// The other Go mutators (store default, safety_identifier, stream_options,
// reasoning, upstream privacy) are applied by the node and have no TS port.
//
// Run them BEFORE sealing: the admission tag commits to sha256 of the sealed
// body, so a body changed afterwards is a different request.
//
// Go decodes the top level into a map of raw values and re-marshals it. These
// splice the original text instead, so every kept value stays byte for byte —
// JSON.parse plus JSON.stringify would round an integer above 2^53 (a `seed`,
// say) and reformat numbers. Bytes are spliced as bytes, so a body carrying
// invalid UTF-8 inside a string is still edited, and its bad bytes pass through
// untouched as they do in Go. The result keeps one entry per key, the last, as
// Go's map round trip does: RFC 8259 leaves repeated names to the reader, and
// some readers take the first or refuse the body. So the two outputs differ in
// bytes, key order and inter-entry whitespace but carry the same members, which
// is what proto/testdata/payer_mutator_vectors.json compares.
//
// Each returns its input unchanged (the same object) when there is nothing to
// do, when the body is not valid JSON, and when its top level is not an object,
// as Go does. One known divergence: Go refuses JSON nested past 10,000 levels and
// so leaves such a body unchanged, while JSON.parse accepts it and these edit it.

interface Entry {
  key: string
  // [start, valueStart) is `"key" :` with its inner whitespace; the value runs
  // to end.
  start: number
  valueStart: number
  end: number
}

// The body as code units: a string's UTF-16 units or a Uint8Array's bytes.
// Every structural JSON character is ASCII, and neither encoding uses an ASCII
// value inside a multi-unit character, so one scanner serves both.
interface Source {
  length: number
  at(i: number): number
  text(a: number, b: number): string
}

interface ParsedObject {
  src: Source
  open: number
  close: number
  entries: Entry[]
}

const QUOTE = 0x22
const BACKSLASH = 0x5c
const COMMA = 0x2c
const LBRACE = 0x7b
const RBRACE = 0x7d
const LBRACKET = 0x5b
const RBRACKET = 0x5d

function isWS(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d
}

function skipWS(s: Source, i: number): number {
  while (i < s.length && isWS(s.at(i))) i++
  return i
}

// Index just past the string token starting at a quote.
function skipString(s: Source, i: number): number {
  for (i++; i < s.length; i++) {
    const c = s.at(i)
    if (c === BACKSLASH) i++
    else if (c === QUOTE) return i + 1
  }
  throw new Error('unterminated string')
}

// Index just past the value starting at i. Only called on text JSON.parse
// already accepted, so it only has to find the end, not validate.
function skipValue(s: Source, i: number): number {
  const c = s.at(i)
  if (c === QUOTE) return skipString(s, i)
  if (c === LBRACE || c === LBRACKET) {
    let depth = 0
    while (i < s.length) {
      const ch = s.at(i)
      if (ch === QUOTE) {
        i = skipString(s, i)
        continue
      }
      if (ch === LBRACE || ch === LBRACKET) depth++
      else if (ch === RBRACE || ch === RBRACKET) {
        depth--
        if (depth === 0) return i + 1
      }
      i++
    }
    throw new Error('unterminated container')
  }
  while (i < s.length) {
    const ch = s.at(i)
    if (isWS(ch) || ch === COMMA || ch === RBRACE || ch === RBRACKET) break
    i++
  }
  return i
}

// A lenient decode is safe for validation: the replacement character never
// absorbs an ASCII byte, so the decoded text has the same structure as the bytes.
const lenientUTF8 = new TextDecoder('utf-8', { ignoreBOM: true })

function sourceOf(body: string | Uint8Array): { src: Source; whole: string } {
  if (typeof body === 'string') {
    return {
      src: { length: body.length, at: (i) => body.charCodeAt(i), text: (a, b) => body.slice(a, b) },
      whole: body,
    }
  }
  return {
    src: { length: body.length, at: (i) => body[i]!, text: (a, b) => lenientUTF8.decode(body.subarray(a, b)) },
    whole: lenientUTF8.decode(body),
  }
}

// The top-level entries of body, or null when body is not a JSON object.
function parseObject(body: string | Uint8Array): ParsedObject | null {
  if (body.length === 0) return null
  const { src, whole } = sourceOf(body)
  let parsed: unknown
  try {
    parsed = JSON.parse(whole)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null

  const open = skipWS(src, 0)
  const entries: Entry[] = []
  let i = skipWS(src, open + 1)
  while (src.at(i) !== RBRACE) {
    const start = i
    const keyEnd = skipString(src, i)
    const key = JSON.parse(src.text(start, keyEnd)) as string
    const valueStart = skipWS(src, skipWS(src, keyEnd) + 1)
    const end = skipValue(src, valueStart)
    entries.push({ key, start, valueStart, end })
    i = skipWS(src, end)
    if (src.at(i) === COMMA) i = skipWS(src, i + 1)
  }
  return { src, open, close: i, entries }
}

// The last entry for key, the one a last-wins reader and Go's map decode see.
function lastEntry(obj: ParsedObject, key: string): Entry | undefined {
  let found: Entry | undefined
  for (const e of obj.entries) if (e.key === key) found = e
  return found
}

type Piece = [number, number] | string

// Re-joins the object from pieces of the original rather than serializing a
// parsed copy, which is what keeps every untouched value exact. Only the last
// entry per key survives, and only if keep says so.
function rebuild(
  body: string | Uint8Array,
  obj: ParsedObject,
  keep: (e: Entry) => boolean,
  replace: (e: Entry) => string | undefined = () => undefined,
): string | Uint8Array {
  const pieces: Piece[] = [[0, obj.open + 1]]
  let first = true
  for (const e of obj.entries) {
    if (lastEntry(obj, e.key) !== e || !keep(e)) continue
    if (!first) pieces.push(',')
    first = false
    const value = replace(e)
    if (value === undefined) pieces.push([e.start, e.end])
    else pieces.push([e.start, e.valueStart], value)
  }
  pieces.push([obj.close, body.length])

  if (typeof body === 'string') {
    return pieces.map((p) => (typeof p === 'string' ? p : body.slice(p[0], p[1]))).join('')
  }
  const enc = new TextEncoder()
  const parts = pieces.map((p) => (typeof p === 'string' ? enc.encode(p) : body.subarray(p[0], p[1])))
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

function dropKeys(body: string | Uint8Array, toDrop: (obj: ParsedObject) => ReadonlySet<string>): string | Uint8Array {
  const obj = parseObject(body)
  if (obj === null) return body
  const drop = toDrop(obj)
  if (!obj.entries.some((e) => drop.has(e.key))) return body
  return rebuild(body, obj, (e) => !drop.has(e.key))
}

const PROVIDER: ReadonlySet<string> = new Set(['provider'])
const PROMPT_CACHE_KEY: ReadonlySet<string> = new Set(['prompt_cache_key'])
const TOOLS_AND_CHOICE: ReadonlySet<string> = new Set(['tools', 'tool_choice'])
const NOTHING: ReadonlySet<string> = new Set()

/**
 * Removes the top-level `provider` routing-preference object. Parse the
 * caller's preferences out of it first; it must never reach the node.
 */
export function dropRoutingPreferences(body: string): string
export function dropRoutingPreferences(body: Uint8Array): Uint8Array
export function dropRoutingPreferences(body: string | Uint8Array): string | Uint8Array {
  return dropKeys(body, () => PROVIDER)
}

/**
 * Removes the top-level `prompt_cache_key`, a session-stable token that would
 * let any operator or relay on the path join one payer's turns exactly.
 */
export function dropPromptCacheKey(body: string): string
export function dropPromptCacheKey(body: Uint8Array): Uint8Array
export function dropPromptCacheKey(body: string | Uint8Array): string | Uint8Array {
  return dropKeys(body, () => PROMPT_CACHE_KEY)
}

/**
 * Removes `tools` when it is an empty array or null, and `tool_choice` with it.
 * Strict upstreams reject an empty tools array. Any other `tools` value leaves
 * the body untouched.
 */
export function dropEmptyTools(body: string): string
export function dropEmptyTools(body: Uint8Array): Uint8Array
export function dropEmptyTools(body: string | Uint8Array): string | Uint8Array {
  return dropKeys(body, (obj) => {
    const tools = lastEntry(obj, 'tools')
    if (tools === undefined) return NOTHING
    const raw = obj.src.text(tools.valueStart, tools.end)
    // Go decodes null into a nil slice, which it treats as empty.
    const empty = raw === 'null' || (raw.startsWith('[') && raw.slice(1, -1).trim() === '')
    return empty ? TOOLS_AND_CHOICE : NOTHING
  })
}

const MAX_OUTPUT_FIELDS = ['max_completion_tokens', 'max_tokens', 'max_output_tokens'] as const
const UINT64_MAX = 0xffff_ffff_ffff_ffffn

/** The output-ceiling field names clampMaxOutput lowers. A fresh copy each call. */
export function maxOutputFields(): string[] {
  return [...MAX_OUTPUT_FIELDS]
}

// The value as a uint64, or undefined for anything Go's uint64 decode refuses:
// strings, fractions, exponents, negatives and out-of-range integers. null also
// reads as undefined; Go decodes it as 0, which never exceeds a ceiling.
function asUint64(raw: string): bigint | undefined {
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) return undefined
  const n = BigInt(raw)
  return n <= UINT64_MAX ? n : undefined
}

export interface ClampResult<T extends string | Uint8Array> {
  body: T
  /** The largest value lowered, or 0n when nothing was. Worth logging, not more. */
  requested: bigint
}

/**
 * Lowers every top-level output-ceiling field above `ceiling` to `ceiling`. It
 * never raises a value or adds a field. A ceiling of 0 means no cap is known and
 * changes nothing; a field value that is not a plain non-negative integer is left
 * for the upstream to reject.
 */
export function clampMaxOutput(body: string, ceiling: number | bigint): ClampResult<string>
export function clampMaxOutput(body: Uint8Array, ceiling: number | bigint): ClampResult<Uint8Array>
export function clampMaxOutput(
  body: string | Uint8Array,
  ceiling: number | bigint,
): ClampResult<string | Uint8Array> {
  const cap = BigInt(ceiling)
  if (cap < 0n || cap > UINT64_MAX) throw new RangeError(`ceiling out of uint64 range: ${ceiling}`)
  const unchanged = { body, requested: 0n }
  if (cap === 0n) return unchanged
  const obj = parseObject(body)
  if (obj === null) return unchanged

  let requested = 0n
  const lowered = new Set<Entry>()
  for (const field of MAX_OUTPUT_FIELDS) {
    const e = lastEntry(obj, field)
    if (e === undefined) continue
    const n = asUint64(obj.src.text(e.valueStart, e.end))
    if (n === undefined || n <= cap) continue
    lowered.add(e)
    if (n > requested) requested = n
  }
  if (lowered.size === 0) return unchanged
  return {
    body: rebuild(
      body,
      obj,
      () => true,
      (e) => (lowered.has(e) ? cap.toString() : undefined),
    ),
    requested,
  }
}
