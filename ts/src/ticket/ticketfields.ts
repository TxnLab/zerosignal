/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Not re-exported from the package: parseTicketJSON and
// parseReserveResponseJSON share it.

import type { FieldReader } from '../util/strictjson.js'
import { decodeDeploymentId } from './deployment.js'
import type { Ticket } from './ticket.js'
import type { UsageType } from './usagetype.js'

export function readTicket(f: FieldReader): Ticket {
    const usage = (name: string) => f.uint(name, 255) as UsageType
    const sig = f.str('sig')
    const deployment = f.str('deployment')
    // Refused here, as Go's UnmarshalText refuses it, rather than at verify.
    // A present "" is malformed too: unbound is spelled by omitting the field.
    if (f.present('deployment')) decodeDeploymentId(deployment)
    return {
        ticket_id: f.str('ticket_id'),
        operator_id: f.uint('operator_id'),
        node_id: f.uint('node_id'),
        input_count: f.uint('input_count'),
        max_output_count: f.uint('max_output_count'),
        input_rate: f.uint('input_rate'),
        output_rate: f.uint('output_rate'),
        max_price: f.uint('max_price'),
        min_price: f.uint('min_price'),
        expires_at: f.int('expires_at'),
        model: f.str('model'),
        stream: f.bool('stream'),
        commit_k: f.str('commit_k'),
        input_usage_type: usage('input_usage_type'),
        output_usage_type: usage('output_usage_type'),
        cache_read_rate: f.uint('cache_read_rate'),
        ...(deployment ? { deployment } : {}),
        // Absent, not '', when unsigned: sig is optional on Ticket.
        ...(sig ? { sig } : {}),
    }
}
