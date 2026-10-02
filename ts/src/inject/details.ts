/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The discovery response, GET /v1/zs/details: the types, a parser, and the
// retention helpers. Mirrors proto/go/inject/details.go, retention.go and the
// TEEAdvertisement half of tee.go. SPEC.md § 3c is authoritative for every
// field; the Go godoc carries the trust caveats and is not repeated here.
//
// proto/testdata/details_vectors.json pins the field names and the retention
// helpers to Go. The parser's leniency is TS-only, see parseOperatorDetails.

/** Content-Type of the details response. Plaintext: it is a public advertisement. */
export const DETAILS_CONTENT_TYPE = 'application/json'

// TEE modes a node may advertise. Empty and TEE_MODE_NONE both mean "no TEE".
export const TEE_MODE_NONE = 'none'
export const TEE_MODE_STUB = 'stub'
export const TEE_MODE_NVIDIA_CC_TDX = 'nvidia-cc-tdx'
export const TEE_MODE_NVIDIA_CC_SEV_SNP = 'nvidia-cc-snp'
export const TEE_MODE_DSTACK_TDX = 'dstack-tdx'

// Upstream data-retention tiers, strongest evidence first. Every tier below
// tee_attested describes the destination, not the node; read retention
// together with the TEE advertisement, never alone.
export const RETENTION_TEE_ATTESTED = 'tee_attested'
export const RETENTION_UPSTREAM_CONFIRMED = 'upstream_confirmed'
export const RETENTION_UPSTREAM_ENFORCED = 'upstream_enforced'
export const RETENTION_NO_UPSTREAM = 'no_upstream'
export const RETENTION_OPERATOR_DECLARED = 'operator_declared'

export const KNOWN_RETENTION_TIERS: readonly string[] = Object.freeze([
  RETENTION_TEE_ATTESTED,
  RETENTION_UPSTREAM_CONFIRMED,
  RETENTION_UPSTREAM_ENFORCED,
  RETENTION_NO_UPSTREAM,
  RETENTION_OPERATOR_DECLARED,
])

/**
 * Whether s names a retention tier this package defines. An unrecognized value
 * is unknown, the same as empty: the field is node-authored, and showing an
 * unknown label verbatim would let a node mint its own reassuring one.
 */
export function isKnownRetention(s: unknown): s is string {
  return typeof s === 'string' && KNOWN_RETENTION_TIERS.includes(s)
}

/**
 * The strongest tier true of both routes, for a model whose prompt reaches both
 * (a chat model with image tools, say). Not simply the weaker by rank: the
 * prompt stays local only if both routes keep it local, so a local tier paired
 * with a leaving one yields the leaving one. Unknown on either side is unknown.
 */
export function combineRetention(a: string, b: string): string {
  if (!isKnownRetention(a) || !isKnownRetention(b)) return ''
  if (a === b) return a
  const localA = retentionStaysLocal(a)
  const localB = retentionStaysLocal(b)
  if (localA && !localB) return b
  if (localB && !localA) return a
  return KNOWN_RETENTION_TIERS.indexOf(a) >= KNOWN_RETENTION_TIERS.indexOf(b) ? a : b
}

function retentionStaysLocal(s: string): boolean {
  return s === RETENTION_TEE_ATTESTED || s === RETENTION_NO_UPSTREAM
}

/** One `builtin_tools[]` entry: type only, the node's own `zs_*` tools. */
export interface BuiltinToolAdvert {
  type: string
}

/** The compact TEE claim on details. The evidence itself is at evidence_url. */
export interface TEEAdvertisement {
  mode: string
  /** RFC 3339. Absent when the node has never minted a bundle. */
  attested_at?: string
  /** Absent means /v1/zs/attestation. */
  evidence_url?: string
}

export interface ModelReasoning {
  supported: boolean
  allowed_efforts?: string[]
  default_effort?: string
}

export interface ModelCoordinates {
  family?: string
  parameters?: number
  active_parameters?: number
  quantization?: string
  variant?: string
}

/** One entry of OperatorDetails.models. Rates are advertised USD per 1M tokens. */
export interface OperatorDetailsModel {
  id: string
  input_rate_usd_per_1m: number
  output_rate_usd_per_1m: number
  /** Present only when cached reads are discounted; 0 means free. */
  cache_read_rate_usd_per_1m?: number
  /** Tier presence keys off this, never off the rates. */
  long_context_threshold_tokens?: number
  long_context_input_rate_usd_per_1m?: number
  long_context_output_rate_usd_per_1m?: number
  long_context_cache_read_rate_usd_per_1m?: number
  context_window?: number
  max_output_tokens?: number
  input_modalities?: string[]
  output_modalities?: string[]
  reasoning?: ModelReasoning
  tool_use?: boolean
  tags?: string[]
  coordinates?: ModelCoordinates
  source?: string
  canonical_id?: string
  retention?: string
  weights_digest?: string
  weights_unverifiable?: boolean
  weights_unverifiable_reason?: string
  weights_digest_trust?: string
  weights_declaration_conflict?: boolean
  weights_registry_match?: string
  weights_registry_path?: string
  weights_mismatch?: boolean
  image_tool_rate_micro_usdc?: number
  image_edit_tool_rate_micro_usdc?: number
  image_tool_base_micro_usdc?: number
  image_edit_tool_base_micro_usdc?: number
  image_rate_micro_usdc?: number
  image_edit_rate_micro_usdc?: number
  image_default_micro_usdc?: number
  image_edit_default_micro_usdc?: number
  image_cap_micro_usdc?: number
  image_edit_cap_micro_usdc?: number
  serves_image_gen?: boolean
  serves_image_edit?: boolean
  tool_call_rates_micro_usdc?: Record<string, number>
  vendor_tool_catchall_micro_usdc?: number
  vendor_tool_call_cap?: number
  vendor_tool_tokens_per_call?: number
}

/** The GET /v1/zs/details response body. */
export interface OperatorDetails {
  operator_id?: number
  node_id?: number
  owner_addr?: string
  signing_addr?: string
  /** A seal target needs all four ephemeral fields; any missing means none. */
  ephemeral_age_pubkey?: string
  ephemeral_expiry?: number
  ephemeral_issued_at?: number
  ephemeral_sig?: string
  models: OperatorDetailsModel[]
  oracle_source?: string
  oracle_healthy: boolean
  algo_usd_price?: number
  /** RFC 3339. */
  algo_usd_at?: string
  min_charge_output_tokens?: number
  min_charge_algo_txns?: number
  min_charge_microusdc?: number
  builtin_tools?: BuiltinToolAdvert[]
  max_tool_iterations?: number
  tool_headroom_per_iteration?: number
  /** Informational build id. Never parse it to drive routing or settlement. */
  version?: string
  proto_version?: string
  config_hash?: string
  tee?: TEEAdvertisement
}

type Obj = Record<string, unknown>

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined
}

function uint(v: unknown): number | undefined {
  return Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : undefined
}

function rate(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : undefined
}

function bool(v: unknown): boolean | undefined {
  return typeof v === 'boolean' ? v : undefined
}

function strings(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined
  const out = v.filter((x): x is string => typeof x === 'string')
  return out.length > 0 ? out : undefined
}

// Go's time.Time has no omitempty, so a node that never set one writes the zero
// time rather than leaving the field out. Reading it as a date would show
// "year 1"; it means absent.
function time(v: unknown): string | undefined {
  const s = str(v)
  if (s === undefined || s.startsWith('0001-01-01T00:00:00') || Number.isNaN(Date.parse(s))) return undefined
  return s
}

// Assigns each defined value, so an absent or rejected field is left out of the
// result rather than carried as an explicit undefined.
function setDefined<T extends object>(target: T, fields: { [K in keyof T]?: T[K] | undefined }): void {
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) (target as Obj)[k] = v
  }
}

function parseReasoning(v: unknown): ModelReasoning | undefined {
  if (!isObj(v) || typeof v.supported !== 'boolean') return undefined
  const out: ModelReasoning = { supported: v.supported }
  setDefined(out, { allowed_efforts: strings(v.allowed_efforts), default_effort: str(v.default_effort) })
  return out
}

function parseCoordinates(v: unknown): ModelCoordinates | undefined {
  if (!isObj(v)) return undefined
  const out: ModelCoordinates = {}
  setDefined(out, {
    family: str(v.family),
    parameters: uint(v.parameters),
    active_parameters: uint(v.active_parameters),
    quantization: str(v.quantization),
    variant: str(v.variant),
  })
  return Object.keys(out).length > 0 ? out : undefined
}

function parseToolRates(v: unknown): Record<string, number> | undefined {
  if (!isObj(v)) return undefined
  const out: Record<string, number> = {}
  for (const [k, raw] of Object.entries(v)) {
    const n = uint(raw)
    if (n !== undefined) out[k] = n
  }
  return Object.keys(out).length > 0 ? out : undefined
}

// A model entry is dropped, not repaired, when a field that routing or pricing
// reads is present but malformed: a garbled modality list must not read as
// "text only", and a garbled rate must not read as free.
function parseModel(v: unknown): OperatorDetailsModel | null {
  if (!isObj(v)) return null
  const id = str(v.id)
  if (id === undefined) return null
  for (const k of ['input_modalities', 'output_modalities'] as const) {
    if (v[k] !== undefined && !Array.isArray(v[k])) return null
  }
  const input = v.input_rate_usd_per_1m === undefined ? 0 : rate(v.input_rate_usd_per_1m)
  const output = v.output_rate_usd_per_1m === undefined ? 0 : rate(v.output_rate_usd_per_1m)
  if (input === undefined || output === undefined) return null

  const out: OperatorDetailsModel = { id, input_rate_usd_per_1m: input, output_rate_usd_per_1m: output }
  setDefined(out, {
    cache_read_rate_usd_per_1m: rate(v.cache_read_rate_usd_per_1m),
    long_context_threshold_tokens: uint(v.long_context_threshold_tokens),
    long_context_input_rate_usd_per_1m: rate(v.long_context_input_rate_usd_per_1m),
    long_context_output_rate_usd_per_1m: rate(v.long_context_output_rate_usd_per_1m),
    long_context_cache_read_rate_usd_per_1m: rate(v.long_context_cache_read_rate_usd_per_1m),
    context_window: uint(v.context_window),
    max_output_tokens: uint(v.max_output_tokens),
    input_modalities: strings(v.input_modalities),
    output_modalities: strings(v.output_modalities),
    reasoning: parseReasoning(v.reasoning),
    tool_use: bool(v.tool_use),
    tags: strings(v.tags),
    coordinates: parseCoordinates(v.coordinates),
    source: str(v.source),
    canonical_id: str(v.canonical_id),
    retention: isKnownRetention(v.retention) ? v.retention : undefined,
    weights_digest: str(v.weights_digest),
    weights_unverifiable: bool(v.weights_unverifiable),
    weights_unverifiable_reason: str(v.weights_unverifiable_reason),
    weights_digest_trust: str(v.weights_digest_trust),
    weights_declaration_conflict: bool(v.weights_declaration_conflict),
    weights_registry_match: str(v.weights_registry_match),
    weights_registry_path: str(v.weights_registry_path),
    weights_mismatch: bool(v.weights_mismatch),
    image_tool_rate_micro_usdc: uint(v.image_tool_rate_micro_usdc),
    image_edit_tool_rate_micro_usdc: uint(v.image_edit_tool_rate_micro_usdc),
    image_tool_base_micro_usdc: uint(v.image_tool_base_micro_usdc),
    image_edit_tool_base_micro_usdc: uint(v.image_edit_tool_base_micro_usdc),
    image_rate_micro_usdc: uint(v.image_rate_micro_usdc),
    image_edit_rate_micro_usdc: uint(v.image_edit_rate_micro_usdc),
    image_default_micro_usdc: uint(v.image_default_micro_usdc),
    image_edit_default_micro_usdc: uint(v.image_edit_default_micro_usdc),
    image_cap_micro_usdc: uint(v.image_cap_micro_usdc),
    image_edit_cap_micro_usdc: uint(v.image_edit_cap_micro_usdc),
    serves_image_gen: bool(v.serves_image_gen),
    serves_image_edit: bool(v.serves_image_edit),
    tool_call_rates_micro_usdc: parseToolRates(v.tool_call_rates_micro_usdc),
    vendor_tool_catchall_micro_usdc: uint(v.vendor_tool_catchall_micro_usdc),
    vendor_tool_call_cap: uint(v.vendor_tool_call_cap),
    vendor_tool_tokens_per_call: uint(v.vendor_tool_tokens_per_call),
  })
  return out
}

// A mode is a dispatch key a verifier must answer for, so an unrecognized one
// is carried through: dropping it would render a newer node as advertising no
// TEE at all, where "cannot verify this mode" is the honest answer.
function parseTEE(v: unknown): TEEAdvertisement | undefined {
  if (!isObj(v)) return undefined
  const mode = str(v.mode)
  if (mode === undefined) return undefined
  const out: TEEAdvertisement = { mode }
  setDefined(out, { attested_at: time(v.attested_at), evidence_url: str(v.evidence_url) })
  return out
}

function parseBuiltinTools(v: unknown): BuiltinToolAdvert[] | undefined {
  if (!Array.isArray(v)) return undefined
  return v
    .filter((t): t is { type: string } => isObj(t) && typeof t.type === 'string' && t.type.startsWith('zs_'))
    .map((t) => ({ type: t.type }))
}

/**
 * Parses a details body already decoded from JSON. Returns null when the body
 * is not a JSON object.
 *
 * Deliberately more lenient than Go, whose decoder rejects the whole body over
 * one wrong-typed field: here a malformed field is dropped and the rest parses,
 * so one bad advertisement doesn't hide a node. Two exceptions skip a model
 * entry rather than a field — see parseModel. Values are also checked beyond
 * their JSON type (integers must be non-negative safe integers, rates
 * non-negative and finite, retention a known tier, built-in tools `zs_*`), and
 * the empty-string, zero-time and empty-collection forms Go would have omitted
 * read as absent.
 */
export function parseOperatorDetails(body: unknown): OperatorDetails | null {
  if (!isObj(body)) return null
  const models = Array.isArray(body.models)
    ? body.models.map(parseModel).filter((m): m is OperatorDetailsModel => m !== null)
    : []
  const out: OperatorDetails = { models, oracle_healthy: body.oracle_healthy === true }
  setDefined(out, {
    operator_id: uint(body.operator_id),
    node_id: uint(body.node_id),
    owner_addr: str(body.owner_addr),
    signing_addr: str(body.signing_addr),
    ephemeral_age_pubkey: str(body.ephemeral_age_pubkey),
    ephemeral_expiry: uint(body.ephemeral_expiry),
    ephemeral_issued_at: uint(body.ephemeral_issued_at),
    ephemeral_sig: str(body.ephemeral_sig),
    oracle_source: str(body.oracle_source),
    algo_usd_price: rate(body.algo_usd_price),
    algo_usd_at: time(body.algo_usd_at),
    min_charge_output_tokens: uint(body.min_charge_output_tokens),
    min_charge_algo_txns: uint(body.min_charge_algo_txns),
    min_charge_microusdc: uint(body.min_charge_microusdc),
    builtin_tools: parseBuiltinTools(body.builtin_tools),
    max_tool_iterations: uint(body.max_tool_iterations),
    tool_headroom_per_iteration: uint(body.tool_headroom_per_iteration),
    version: str(body.version),
    proto_version: str(body.proto_version),
    config_hash: str(body.config_hash),
    tee: parseTEE(body.tee),
  })
  return out
}
