/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Mirror of proto/go/inject InferDialect / HostMatchesDomain, pinned by
// proto/testdata/dialect_vectors.json.
//
// A TEE verifier needs this: an attested_passthrough node is admissible only
// when the upstream bound into its report_data is xAI, and the verifier must
// classify that URL exactly as the node did. That is also why this does NOT use
// WHATWG `URL`. It and Go's url.Parse disagree at the edges (a backslash, a
// percent-escaped host, a scheme-relative "//host"), so both sides accept one
// narrow subset — a scheme, no userinfo, a plain letters-digits-dots-hyphens
// host with no escapes, and no control byte or malformed escape anywhere — and
// call everything else generic.

export type Dialect = 'generic' | 'openai' | 'xai' | 'moonshot' | 'zai' | 'openrouter'

export const DialectGeneric: Dialect = 'generic'
export const DialectOpenAI: Dialect = 'openai'
export const DialectXAI: Dialect = 'xai'
export const DialectMoonshot: Dialect = 'moonshot'
export const DialectZAI: Dialect = 'zai'
export const DialectOpenRouter: Dialect = 'openrouter'

const DIALECT_DOMAINS: ReadonlyArray<readonly [string, Dialect]> = [
  ['x.ai', DialectXAI],
  ['openai.com', DialectOpenAI],
  ['moonshot.ai', DialectMoonshot],
  ['moonshot.cn', DialectMoonshot],
  ['kimi.ai', DialectMoonshot],
  ['kimi.com', DialectMoonshot],
  ['z.ai', DialectZAI],
  ['bigmodel.cn', DialectZAI],
  ['openrouter.ai', DialectOpenRouter],
]

// ASCII whitespace only, matching the Go side's strings.Trim set. String.trim
// would also strip U+FEFF and U+00A0, which Go's url.Parse then refuses.
const ASCII_WS_EDGES = /^[ \t\n\r\v\f]+|[ \t\n\r\v\f]+$/g
// Refused anywhere in the URL; the Go side checks explicitly, since url.Parse
// alone lets one through in the fragment.
const CONTROL = /[\x00-\x1f\x7f]/
const SCHEME_AUTHORITY = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)/
const HOST_PORT = /^([^:]*)(?::(\d*))?$/
const LDH = /^[A-Za-z0-9.-]+$/
// Go's url.Parse refuses a malformed escape in the path or fragment; this
// parser never looks there, so both sides refuse one anywhere in the string.
const MALFORMED_ESCAPE = /%(?![0-9A-Fa-f]{2})/
const NON_ASCII = /[^\x00-\x7f]/

/**
 * Whether host is domain or a subdomain of it, case-insensitively on DNS label
 * boundaries, ignoring one trailing dot. host must be a bare hostname. A
 * non-ASCII host or domain never matches, because toLowerCase and Go's
 * strings.ToLower fold some non-ASCII letters differently.
 */
export function hostMatchesDomain(host: string, domain: string): boolean {
  if (NON_ASCII.test(host) || NON_ASCII.test(domain)) return false
  let h = host.toLowerCase()
  if (h.endsWith('.')) h = h.slice(0, -1)
  const d = domain.toLowerCase()
  if (h === '' || d === '') return false
  return h === d || h.endsWith('.' + d)
}

function upstreamOrigin(raw: string): { scheme: string; host: string } | null {
  const s = raw.replace(ASCII_WS_EDGES, '')
  if (CONTROL.test(s) || MALFORMED_ESCAPE.test(s)) return null
  const m = SCHEME_AUTHORITY.exec(s)
  if (!m) return null
  const authority = m[2] ?? ''
  if (/[@%\\]/.test(authority)) return null
  const hp = HOST_PORT.exec(authority)
  if (!hp) return null
  const host = hp[1] ?? ''
  if (host === '' || !LDH.test(host)) return null
  return { scheme: (m[1] ?? '').toLowerCase(), host }
}

/**
 * The host an https base_url dials, or null when the URL is not https or falls
 * outside the accepted subset. Mirrors Go's inject.HTTPSUpstreamHost.
 */
export function httpsUpstreamHost(baseURL: string): string | null {
  const o = upstreamOrigin(baseURL)
  return o !== null && o.scheme === 'https' ? o.host : null
}

/**
 * The verifier's judgement of a named_upstream posture. Mirrors Go's
 * inject.NamedUpstreamAdmissible, whose godoc carries the reasoning; the
 * named_upstream_admissible vectors pin the two together.
 *
 * posture is the bundle's posture as parsed, and MUST be the value the aux
 * binding verified. attested is upstreamAttested of the bundle's
 * upstream_attestation value, which is unsigned; the posture's bound
 * upstream_attested bit must also be set.
 */
export function namedUpstreamAdmissible(posture: unknown, attested: boolean): boolean {
  if (typeof posture !== 'object' || posture === null || Array.isArray(posture)) return false
  const p = posture as Record<string, unknown>
  if (p['plaintext_terminates'] !== 'named_upstream') return false
  const url = p['upstream_base_url']
  if (typeof url !== 'string' || httpsUpstreamHost(url) === null) return false
  // Both: the bound bit stops a relay adding a block, the block's absence
  // means the node's own appraisal of the upstream has lapsed.
  if (p['upstream_attested'] === true && attested) return true
  return p['zero_retention'] === true && inferDialect(url) === DialectXAI
}

/**
 * Whether a bundle's raw upstream_attestation value counts for
 * namedUpstreamAdmissible: an object whose protocol this build recognizes.
 * Mirrors Go's inject.UpstreamAttested, where a value that is not an object
 * fails the bundle decode instead; both refuse it.
 */
export function upstreamAttested(block: unknown): boolean {
  if (typeof block !== 'object' || block === null || Array.isArray(block)) return false
  return (block as Record<string, unknown>)['protocol'] === 'aci/1'
}

/**
 * The upstream vendor a base_url names, by the host it dials. Anything that is
 * not a recognized vendor domain — or not a URL in the accepted subset — is
 * 'generic'.
 */
export function inferDialect(baseURL: string): Dialect {
  const host = upstreamOrigin(baseURL)?.host ?? null
  if (host === null) return DialectGeneric
  for (const [domain, dialect] of DIALECT_DOMAINS) {
    if (hostMatchesDomain(host, domain)) return dialect
  }
  return DialectGeneric
}
