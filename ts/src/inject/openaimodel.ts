/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The GET /v1/models entry, mirroring proto/go/inject/openaimodel.go and pinned
// with the SDK's use of it by testdata/openai_model_vectors.json. OpenAI's
// four official fields carry no window, price or capability, so the rest
// follows OpenRouter's model object, which is what a client reading past `id`
// parses. Go's file has why each field is or is not emitted.

import type { ModelReasoning, OperatorDetailsModel } from './details.js'
import { goTrimSpace } from './gostrings.js'

export interface OpenAIModel {
  id: string
  object: 'model'
  created: number
  owned_by: string
  /** Set only when there is no hugging_face_id. */
  canonical_slug?: string
  hugging_face_id?: string
  context_length?: number
  architecture?: OpenAIModelArchitecture
  pricing?: OpenAIModelPricing
  top_provider?: OpenAIModelTopProvider
  reasoning?: ModelReasoning
  /** Absent: unadvertised, which is not false. */
  tool_use?: boolean
}

export interface OpenAIModelList {
  object: 'list'
  data: OpenAIModel[]
}

export interface OpenAIModelArchitecture {
  input_modalities?: string[]
  output_modalities?: string[]
}

/**
 * USD per token as decimal strings, OpenRouter's units and type. Prompt and
 * completion are always present, "0" included; input_cache_read is absent
 * when cached reads are not discounted and "0" when they are free.
 */
export interface OpenAIModelPricing {
  prompt: string
  completion: string
  input_cache_read?: string
}

export interface OpenAIModelTopProvider {
  context_length?: number
  max_completion_tokens?: number
}

/**
 * openAIModelFromDetails projects one advertised model onto the /v1/models
 * entry shape. ownedBy and created are the caller's. Like Go's, the result
 * shares d's reasoning and modality lists rather than copying them.
 */
export function openAIModelFromDetails(d: OperatorDetailsModel, ownedBy: string, created: number): OpenAIModel {
  const m: OpenAIModel = { id: d.id, object: 'model', created, owned_by: ownedBy }
  const hf = huggingFaceRepo(d.source ?? '')
  if (hf !== '') m.hugging_face_id = hf
  else if (d.canonical_id) m.canonical_slug = d.canonical_id
  if (d.context_window) m.context_length = d.context_window
  const inputs = d.input_modalities ?? []
  const outputs = d.output_modalities ?? []
  if (inputs.length > 0 || outputs.length > 0) {
    m.architecture = {}
    if (inputs.length > 0) m.architecture.input_modalities = inputs
    if (outputs.length > 0) m.architecture.output_modalities = outputs
  }
  if (!pricedOffThisShape(d)) {
    m.pricing = { prompt: usdPerToken(d.input_rate_usd_per_1m), completion: usdPerToken(d.output_rate_usd_per_1m) }
    if (d.cache_read_rate_usd_per_1m !== undefined) m.pricing.input_cache_read = usdPerToken(d.cache_read_rate_usd_per_1m)
  }
  if (d.context_window || d.max_output_tokens) {
    m.top_provider = {}
    if (d.context_window) m.top_provider.context_length = d.context_window
    if (d.max_output_tokens) m.top_provider.max_completion_tokens = d.max_output_tokens
  }
  if (d.reasoning !== undefined) m.reasoning = d.reasoning
  if (d.tool_use !== undefined) m.tool_use = d.tool_use
  return m
}

/**
 * pricedOffThisShape is whether token rates would misdescribe what the model
 * costs: a dedicated image route, billed per image, or a free-token model
 * that charges per in-loop image or per tool call.
 */
function pricedOffThisShape(d: OperatorDetailsModel): boolean {
  if (d.serves_image_gen || d.serves_image_edit) return true
  if (d.input_rate_usd_per_1m !== 0 || d.output_rate_usd_per_1m !== 0) return false
  return (
    (d.image_tool_rate_micro_usdc ?? 0) > 0 ||
    (d.image_edit_tool_rate_micro_usdc ?? 0) > 0 ||
    Object.keys(d.tool_call_rates_micro_usdc ?? {}).length > 0
  )
}

/**
 * usdPerToken renders a USD-per-1M rate as a USD-per-token decimal string.
 * The divide by 1e6 shifts the decimal point across the rate's own shortest
 * digits, as Go's does: 0.1 / 1e6 in binary floating point is not the double
 * nearest 1e-7, and its shortest form would publish a rate nobody declared.
 * Anything not a positive finite number renders "0".
 */
export function usdPerToken(usdPer1M: number): string {
  if (!(usdPer1M > 0) || !Number.isFinite(usdPer1M)) return '0'
  // With no argument toExponential gives the shortest digits that round-trip,
  // the digits Go's FormatFloat(v, 'f', -1, 64) writes.
  const [mantissa, exponent] = usdPer1M.toExponential().split('e') as [string, string]
  const digits = mantissa.replace('.', '')
  // Where the point lands once moved six places left; <= 0 needs zero padding.
  const point = Number(exponent) + 1 - 6
  let whole = '0'
  let frac: string
  if (point > 0) {
    whole = point >= digits.length ? digits + '0'.repeat(point - digits.length) : digits.slice(0, point)
    frac = point >= digits.length ? '' : digits.slice(point)
  } else {
    frac = '0'.repeat(-point) + digits
  }
  frac = frac.replace(/0+$/, '')
  return frac === '' ? whole : `${whole}.${frac}`
}

/**
 * huggingFaceRepo is the bare "org/model" of an "hf:org/model[@revision]"
 * source, or "" for anything else. It runs on a remote operator's unvalidated
 * advertisement and a consumer renders it as a link, so each segment must be
 * a Hugging Face id: letters, digits, '.', '_' and '-'.
 */
export function huggingFaceRepo(source: string): string {
  const s = goTrimSpace(source)
  if (!s.startsWith('hf:')) return ''
  let rest = s.slice(3)
  const at = rest.indexOf('@')
  if (at >= 0) rest = rest.slice(0, at)
  const slash = rest.indexOf('/')
  if (slash < 0) return ''
  const org = rest.slice(0, slash)
  const model = rest.slice(slash + 1)
  if (!isHuggingFaceSegment(org) || !isHuggingFaceSegment(model)) return ''
  return `${org}/${model}`
}

const HF_SEGMENT = /^[A-Za-z0-9._-]+$/

function isHuggingFaceSegment(s: string): boolean {
  return HF_SEGMENT.test(s)
}
