/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The message for a request no operator can size: refused by the sizing
// filter, by the nodes at reserve time, or both. Mirror of proto/go/zs
// dispatch.go's formatNoFitMessage and formatReserveSizeFailureMessage. Callers
// match on the head line up to input_tokens, in either case.

import type { SizingMiss } from '@txnlab/zs-proto/selection'

import type { SizingRequest } from './sizing.js'

/** One operator's sizing refusal at reserve time, as the node worded it. */
export interface ReserveSizeRejection {
    operatorId: number
    code: string
    message: string
}

/** noFitMessage is the message for candidates the sizing filter refused, each with its reason. */
export function noFitMessage(model: string, sizing: SizingRequest, misses: readonly SizingMiss[]): string {
    return reserveSizeFailureMessage(model, sizing, [], misses)
}

/**
 * reserveSizeFailureMessage is the message for a request refused for size,
 * listing the nodes' own reasons first and then the filter's.
 */
export function reserveSizeFailureMessage(
    model: string,
    sizing: SizingRequest,
    rejections: readonly ReserveSizeRejection[],
    preFilter: readonly SizingMiss[],
): string {
    const label = sizing.deriveMaxOutput ? 'derived-per-operator' : String(sizing.maxOutputTokens)
    let out = `no operator serves ${model} with input_tokens=${sizing.inputTokens} max_output_tokens=${label}`
    if (rejections.length > 0) {
        out += '\n  operators rejected the request at reserve time:'
        for (const r of rejections) out += `\n  - ${describeRejection(r)}`
    }
    if (preFilter.length > 0) {
        out += '\n  operators advertising this model:'
        for (const m of preFilter) out += `\n  - ${describeMiss(m)}`
    }
    return out
}

function describeRejection(r: ReserveSizeRejection): string {
    if (r.message !== '') return `op ${r.operatorId}: ${r.message} (${r.code})`
    if (r.code !== '') return `op ${r.operatorId}: ${r.code}`
    return `op ${r.operatorId}: refused for size (no detail)`
}

// describeMiss blames the limit the filter checked first, from the filter's own
// reading: the input count and max_output it charged the operator, and its
// verdict on the window (a node deferring fit upstream passes some requests
// whose input plus max_output exceeds the window).
function describeMiss(m: SizingMiss): string {
    if (m.context_window_exceeded) {
        return `op ${m.operator_id}: context_window=${m.context_window} (request needs ${m.input_tokens + m.effective_max_output} = input ${m.input_tokens} + max_output ${m.effective_max_output})`
    }
    if (m.max_output_tokens > 0 && m.effective_max_output > m.max_output_tokens) {
        return `op ${m.operator_id}: max_output_tokens=${m.max_output_tokens} (over by ${m.effective_max_output - m.max_output_tokens})`
    }
    return `op ${m.operator_id}: declared capacity does not fit (context_window=${m.context_window}, max_output_tokens=${m.max_output_tokens})`
}
