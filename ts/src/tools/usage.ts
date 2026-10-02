/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The upstream `usage` objects and the arithmetic a receipt's output leg rests
// on. Mirrors ChatUsage / ResponsesUsage and GeneratedOutputTokens in
// proto/go/tools/tools.go, where the reasons are written up.

/** The `usage` object on a /v1/chat/completions response or terminal chunk. */
export interface ChatUsage {
    prompt_tokens?: number
    completion_tokens?: number
    total_tokens?: number
    prompt_tokens_details?: { cached_tokens?: number }
    /** DeepSeek's top-level spelling of the cache-read count. */
    prompt_cache_hit_tokens?: number
    completion_tokens_details?: { reasoning_tokens?: number }
}

/** The `usage` object on a /v1/responses body or `response.completed` event. */
export interface ResponsesUsage {
    input_tokens?: number
    output_tokens?: number
    total_tokens?: number
    input_tokens_details?: { cached_tokens?: number }
    output_tokens_details?: { reasoning_tokens?: number }
}

// A token count, or 0 for anything that isn't a non-negative safe integer.
// Go is stricter: a negative or fractional count fails the uint64 decode and
// with it the whole body. JSON.parse can't tell 5.0 from 5, so this reads a
// field at a time and keeps the rest.
function n(v: unknown): number {
    return Number.isSafeInteger(v) && (v as number) >= 0 ? (v as number) : 0
}

/**
 * The tokens the model actually generated, reasoning included: what the output
 * leg of a receipt bills. Providers disagree on whether completion counts
 * reasoning, so reasoning is added only when the reported total corroborates
 * that completion excludes it; a missing or inconsistent total leaves
 * completion alone, under-billing rather than over-billing. Idempotent.
 *
 * Each argument is read as a token count, so a negative or non-integer one
 * counts as 0. No overflow guard is needed: completion + reasoning can round
 * only past 2^53, where it already exceeds any safe total and leaves completion.
 */
export function generatedOutputTokens(prompt: number, completion: number, reasoning: number, total: number): number {
    const [p, c, r, t] = [n(prompt), n(completion), n(reasoning), n(total)]
    if (r === 0 || t < p) return c
    return t - p >= c + r ? c + r : c
}

/** The cache-read count. The nested spelling wins over DeepSeek's whenever it is present, even at 0. */
export function chatCachedTokens(u: ChatUsage): number {
    return u.prompt_tokens_details != null ? n(u.prompt_tokens_details.cached_tokens) : n(u.prompt_cache_hit_tokens)
}

export function chatReasoningTokens(u: ChatUsage): number {
    return n(u.completion_tokens_details?.reasoning_tokens)
}

/** The billable output count. Use it rather than completion_tokens for anything charged. */
export function chatGeneratedOutputTokens(u: ChatUsage): number {
    return generatedOutputTokens(n(u.prompt_tokens), n(u.completion_tokens), chatReasoningTokens(u), n(u.total_tokens))
}

export function responsesCachedTokens(u: ResponsesUsage): number {
    return n(u.input_tokens_details?.cached_tokens)
}

export function responsesReasoningTokens(u: ResponsesUsage): number {
    return n(u.output_tokens_details?.reasoning_tokens)
}

/** The billable output count. Use it rather than output_tokens for anything charged. */
export function responsesGeneratedOutputTokens(u: ResponsesUsage): number {
    return generatedOutputTokens(
        n(u.input_tokens),
        n(u.output_tokens),
        responsesReasoningTokens(u),
        n(u.total_tokens),
    )
}
