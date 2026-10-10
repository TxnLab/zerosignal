/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The body of GET /v1/zs/attestation: the evidence bundle, its collateral set,
// and a decode that refuses what Go's refuses. Mirrors the bundle half of
// proto/go/inject/tee.go, whose godoc carries the trust reasoning for each
// field; SPEC.md § 3e is authoritative.
//
// The decode has to agree with Go's on which bodies fail. A body one payer
// decodes and the other refuses is a node one of them can route to, and the
// fixture proto/testdata/tee_bundle_vectors.json pins every outcome to Go's.
// Three differences remain, all in what JSON.parse hides:
//   - Number literals. Go refuses 1.0 and 1e0 for an integer field and accepts
//     integers past 2^53; this sees only the parsed number, so it accepts the
//     first two and refuses the last.
//   - Escapes in a timestamp. Go parses the raw bytes between the quotes, so a
//     JSON escape (backslash, u, 005a) written for the Z fails there and
//     passes here.
//   - Lone surrogate escapes, which Go replaces with U+FFFD and JSON.parse keeps.
// An honest node emits none of these, and none changes a value a verifier
// compares: the operator id still has to equal the chain's.

import { withinGoNestingDepth } from './json-depth.js'
import { parseRFC3339 } from './rfc3339.js'

/** Content-Type of the attestation response. Plaintext, like discovery. */
export const ATTESTATION_CONTENT_TYPE = 'application/json'

/**
 * The Intel-signed collateral for a quote's platform, spelled as Intel's QVL
 * collateral structure (and @phala/dcap-qvl) spells it. Mirrors
 * inject.TEECollateral. A partial set is an absent set: see collateralComplete.
 */
export interface TEECollateral {
  /** Percent-decoded PEM chain that signs pck_crl. */
  pck_crl_issuer_chain: string
  /** Hex-encoded DER. */
  root_ca_crl: string
  /** Hex-encoded DER. */
  pck_crl: string
  tcb_info_issuer_chain: string
  /** The signed bytes verbatim; re-serializing breaks the signature. */
  tcb_info: string
  /** Hex-encoded. */
  tcb_info_signature: string
  qe_identity_issuer_chain: string
  /** The signed bytes verbatim. */
  qe_identity: string
  /** Hex-encoded. */
  qe_identity_signature: string
}

/** The node's appraisal of the enclave it forwards to. Mirrors inject.UpstreamAttestation. */
export interface UpstreamAttestation {
  protocol: string
  base_url: string
  report_url: string
  keyset_digest: string
  /** RFC 3339, or '' when absent. */
  verified_at: string
  /** RFC 3339, or '' when absent. */
  lease_expires_at: string
  carve_outs: string[]
}

/**
 * A decoded attestation bundle. Mirrors inject.TEEEvidenceBundle, with Go's
 * zero values: an absent or null string is '', a number 0, a boolean false.
 *
 * posture, app_models and nonce are the values as received, of any JSON type,
 * because they are inputs to the aux binding and verifyAux refuses a wrongly
 * typed one with the tag that names it. Go reaches the same tags by
 * substituting values VerifyAux refuses; the aux_verify vectors pin both. Read
 * them only after verifyAux has passed on these exact values.
 */
export interface TEEEvidenceBundle {
  mode: string
  /** Base64 TDX or SEV-SNP report. */
  cpu_report: string
  gpu_eat: string
  event_log: string
  /** dstack app-compose.json verbatim: the compose-hash preimage. */
  app_compose: string
  posture: unknown
  node_pubkey: string
  operator_id: number
  report_data: string
  app_models: unknown
  nonce: unknown
  /** RFC 3339, or '' when absent: Go's zero time, which is never fresh. */
  generated_at: string
  refresh_seconds: number
  stub: boolean
  upstream_attestation?: UpstreamAttestation
  collateral?: TEECollateral
}

/** The body is not a bundle Go would decode. */
export class EvidenceBundleDecodeError extends Error {
  constructor(message: string) {
    super(`inject: evidence bundle: ${message}`)
    this.name = 'EvidenceBundleDecodeError'
  }
}

/**
 * collateralComplete reports whether all nine members are present. Mirrors
 * TEECollateral.Complete: a verifier calls it before believing a set, because
 * accepting eight of nine is a check that silently does not run.
 */
export function collateralComplete(c: TEECollateral | null | undefined): c is TEECollateral {
  if (!c) return false
  // typeof as well, for a caller holding an object that never went through
  // decodeEvidenceBundle: a missing member would otherwise pass, and the
  // freshness floor would throw on it instead of refusing.
  return COLLATERAL_KEYS.every((k) => typeof c[k] === 'string' && c[k] !== '')
}

/**
 * decodeEvidenceBundle decodes a /v1/zs/attestation body as Go's
 * json.Unmarshal into inject.TEEEvidenceBundle does, and throws
 * EvidenceBundleDecodeError where Go returns an error.
 *
 * Invalid UTF-8 is refused rather than replaced: Go and TextDecoder replace
 * bad bytes with different numbers of U+FFFD, so a model id would hash
 * differently in each. A byte-order mark is refused too, as Go refuses it.
 * Keys are read exactly; a case variant is ignored, as Go's decodeExact
 * ignores it.
 */
export function decodeEvidenceBundle(body: Uint8Array | ArrayBuffer): TEEEvidenceBundle {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body)
  } catch {
    throw new EvidenceBundleDecodeError('not valid UTF-8')
  }
  if (!withinGoNestingDepth(text)) throw new EvidenceBundleDecodeError('nested too deeply')
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (e) {
    throw new EvidenceBundleDecodeError(`not JSON: ${(e as Error).message}`)
  }
  // Go hands a top-level null to UnmarshalJSON, which leaves the zero bundle.
  const r = raw === null ? {} : object(raw, 'the body')

  const upstream = field(r, 'upstream_attestation')
  const collateral = field(r, 'collateral')
  const out: TEEEvidenceBundle = {
    mode: str(r, 'mode'),
    cpu_report: str(r, 'cpu_report'),
    gpu_eat: str(r, 'gpu_eat'),
    event_log: str(r, 'event_log'),
    app_compose: str(r, 'app_compose'),
    posture: field(r, 'posture'),
    node_pubkey: str(r, 'node_pubkey'),
    operator_id: uint(r, 'operator_id'),
    report_data: str(r, 'report_data'),
    app_models: field(r, 'app_models'),
    nonce: field(r, 'nonce'),
    generated_at: time(r, 'generated_at'),
    refresh_seconds: int(r, 'refresh_seconds'),
    stub: bool(r, 'stub'),
  }
  if (upstream !== undefined && upstream !== null) {
    out.upstream_attestation = decodeUpstream(object(upstream, 'upstream_attestation'))
  }
  if (collateral !== undefined && collateral !== null) {
    out.collateral = decodeCollateral(object(collateral, 'collateral'))
  }
  return out
}

const COLLATERAL_KEYS = [
  'pck_crl_issuer_chain',
  'root_ca_crl',
  'pck_crl',
  'tcb_info_issuer_chain',
  'tcb_info',
  'tcb_info_signature',
  'qe_identity_issuer_chain',
  'qe_identity',
  'qe_identity_signature',
] as const satisfies readonly (keyof TEECollateral)[]

function decodeCollateral(r: Record<string, unknown>): TEECollateral {
  const out = {} as TEECollateral
  for (const k of COLLATERAL_KEYS) out[k] = str(r, k, 'collateral.')
  return out
}

function decodeUpstream(r: Record<string, unknown>): UpstreamAttestation {
  const p = 'upstream_attestation.'
  const carve = field(r, 'carve_outs')
  let carveOuts: string[] = []
  if (carve !== undefined && carve !== null) {
    if (!Array.isArray(carve)) throw wrongType(`${p}carve_outs`, 'an array')
    carveOuts = carve.map((v, i) => {
      if (v === null) return ''
      if (typeof v !== 'string') throw wrongType(`${p}carve_outs[${i}]`, 'a string')
      return v
    })
  }
  return {
    protocol: str(r, 'protocol', p),
    base_url: str(r, 'base_url', p),
    report_url: str(r, 'report_url', p),
    keyset_digest: str(r, 'keyset_digest', p),
    verified_at: time(r, 'verified_at', p),
    lease_expires_at: time(r, 'lease_expires_at', p),
    carve_outs: carveOuts,
  }
}

// An own property only: a key like "constructor" must not read through to
// Object.prototype.
function field(r: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(r, key) ? r[key] : undefined
}

function object(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new EvidenceBundleDecodeError(`${what} is not an object`)
  }
  return v as Record<string, unknown>
}

function wrongType(name: string, want: string): EvidenceBundleDecodeError {
  return new EvidenceBundleDecodeError(`${name} is not ${want}`)
}

function str(r: Record<string, unknown>, key: string, prefix = ''): string {
  const v = field(r, key)
  if (v === undefined || v === null) return ''
  if (typeof v !== 'string') throw wrongType(prefix + key, 'a string')
  return v
}

function bool(r: Record<string, unknown>, key: string): boolean {
  const v = field(r, key)
  if (v === undefined || v === null) return false
  if (typeof v !== 'boolean') throw wrongType(key, 'a boolean')
  return v
}

// Go's ParseUint refuses -0, and of the literals it refuses that JSON.parse
// turns into a safe integer, -0 is the only one still distinguishable after.
function uint(r: Record<string, unknown>, key: string): number {
  const v = field(r, key)
  if (v === undefined || v === null) return 0
  if (!Number.isSafeInteger(v) || (v as number) < 0 || Object.is(v, -0)) {
    throw wrongType(key, 'a non-negative integer')
  }
  return v as number
}

function int(r: Record<string, unknown>, key: string): number {
  const v = field(r, key)
  if (v === undefined || v === null) return 0
  if (!Number.isSafeInteger(v)) throw wrongType(key, 'an integer')
  return (v as number) + 0 // -0 reads as 0, as ParseInt reads "-0"
}

function time(r: Record<string, unknown>, key: string, prefix = ''): string {
  const v = field(r, key)
  if (v === undefined || v === null) return ''
  if (typeof v !== 'string') throw wrongType(prefix + key, 'an RFC 3339 string')
  if (parseRFC3339(v) === null) throw wrongType(prefix + key, 'an RFC 3339 time')
  return v
}
