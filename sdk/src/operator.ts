/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The routing descriptor dispatch works from, mirroring proto/go/zs Operator:
// one running node, addressed by (id, nodeId), with what its details probe
// advertised. Fields only Go's registry reads (refresh times, the carry
// window, the build id) stay in whichever registry builds these.

import type { ModelCoordinates, ModelReasoning, OperatorDetails, OperatorDetailsModel } from '@txnlab/zs-proto/inject'
import { isKnownRetention } from '@txnlab/zs-proto/inject'
import type { ModelCapacity as SelectionModelCapacity, Operator as SelectionOperator } from '@txnlab/zs-proto/selection'

import { NoEphemeralError } from './reserve.js'
import type { VerdictDetail } from './tee/types.js'
import type { NodeRef } from './types.js'

/** One advertised built-in tool. */
export interface BuiltinToolDef {
    type: string
}

/**
 * ModelCapacity is one model as a node advertised it. Rates are informational:
 * the authoritative per-request rate is what the node signs into the ticket.
 * A 0 rate is undeclared.
 */
export interface ModelCapacity {
    contextWindow: number
    /** 0: no cap beyond contextWindow. */
    maxOutputTokens: number
    /** Undefined: undeclared. */
    inputModalities?: string[] | undefined
    outputModalities?: string[] | undefined
    inputUsdPer1m: number
    outputUsdPer1m: number
    cacheReadUsdPer1m?: number | undefined
    longContextThresholdTokens: number
    longContextInputUsdPer1m?: number | undefined
    longContextOutputUsdPer1m?: number | undefined
    longContextCacheReadUsdPer1m?: number | undefined
    reasoning?: ModelReasoning | undefined
    toolUse?: boolean | undefined
    tags?: string[] | undefined
    coordinates?: ModelCoordinates | undefined
    weightsDigest: string
    weightsUnverifiable: boolean
    source: string
    canonicalId: string
    /** '' when the tier is one this build does not know. */
    retention: string
    imageToolRateMicroUsdc: number
    imageEditToolRateMicroUsdc: number
    imageToolBaseMicroUsdc: number
    imageEditToolBaseMicroUsdc: number
    imageRateMicroUsdc: number
    imageEditRateMicroUsdc: number
    imageDefaultMicroUsdc: number
    imageEditDefaultMicroUsdc: number
    imageCapMicroUsdc: number
    imageEditCapMicroUsdc: number
    advertisesImageGen: boolean
    advertisesImageEdit: boolean
    toolCallRatesMicroUsdc?: Record<string, number> | undefined
    vendorToolCatchAllMicroUsdc: number
    vendorToolCallCap: number
    vendorToolTokensPerCall: number
}

/**
 * The node's own on-chain track record (its NodeRecord, not the operator's
 * rollup across its nodes); 0 when it has none. Routing reads the two EWMAs.
 * The rest are for display, set by the SDK's chain read and optional so a host
 * that builds operators itself can leave them out. Amounts are microUSDC.
 */
export interface OperatorMetrics {
    /** Co-signed TTFT EWMA (NodeRecord.latencyEwmaMs). */
    latencyEwmaMs: number
    tokensPerSecEwma: number
    /** Unix seconds of the node's last ticket-touching state change. */
    lastActivityAt?: number | undefined
    ticketsOpened?: number | undefined
    ticketsSettled?: number | undefined
    ticketsLapsedSettled?: number | undefined
    ticketsRefundedInactive?: number | undefined
    ticketsProtested?: number | undefined
    ticketsFrozenDispute?: number | undefined
    totalRefundedInactiveUsdc?: number | undefined
    totalProtestedUsdc?: number | undefined
    totalFrozenDisputeUsdc?: number | undefined
    /** Summed over token-output settles only; divide by latencySamples, never the settle counts. */
    latencyTotalMs?: number | undefined
    latencySamples?: number | undefined
    totalRevenueGross?: number | undefined
    /** Windows of the daily revenue ring, ending on the day the chain was read. */
    revenue24hUsdc?: number | undefined
    revenue7dUsdc?: number | undefined
    revenue30dUsdc?: number | undefined
}

/** The payer's own verdict on the node's attestation evidence. */
export interface TEEStatus {
    mode: string
    /** Unix milliseconds: when the verified evidence was generated. */
    attestedAt: number
    verifierId: string
    verified: boolean
    /** '' when verified. */
    failureTag: string
    attestedModelIds?: string[] | undefined
    /** What the verifier saw, for display. Never a routing input; Go logs it instead. */
    detail?: VerdictDetail | undefined
}

export interface Operator {
    id: number
    nodeId: number
    /** The operator's NFD app id, 0 when it has none; display only. */
    nfdAppId?: number | undefined
    ownerAddr: string
    signingAddr: string
    /** The ed25519 key tickets are signed with, from the chain. */
    ticketSigningKey: Uint8Array
    baseUrl: string
    models: string[]
    staging: boolean
    /** Undefined: never read, which routes as funded. */
    signerSpendableMicroAlgos?: number | undefined
    /**
     * The node's signed ephemeral age recipient, set only once its
     * advertisement verified against ticketSigningKey. Undefined leaves the
     * node with no seal target: forward secrecy is mandatory, so dispatch
     * skips it.
     */
    ephemeralRecipient?: string | undefined
    /** Unix seconds. */
    ephemeralExpiry: number
    ephemeralIssuedAt: number
    modelCapacities: Record<string, ModelCapacity>
    builtinTools: BuiltinToolDef[]
    /** 0: unknown, and a tool-carrying reserve adds no headroom. */
    maxToolIters: number
    toolHeadroomPerIteration: number
    /** "<major>.<minor>"; '' when the node never said. */
    protoVersion: string
    reachable: boolean
    /** Undefined: the node advertises no TEE. */
    tee?: TEEStatus | undefined
    metrics: OperatorMetrics
    minChargeOutputTokens: number
    minChargeAlgoTxns: number
    minChargeMicroUsdc: number
}

export function refOf(o: Pick<Operator, 'id' | 'nodeId'>): NodeRef {
    return { op: o.id, node: o.nodeId }
}

export function isTeeAttested(o: Pick<Operator, 'tee'>): boolean {
    return o.tee?.verified === true
}

export function servesImageGen(c: ModelCapacity): boolean {
    return c.advertisesImageGen || c.imageRateMicroUsdc > 0
}

export function servesImageEdit(c: ModelCapacity): boolean {
    return c.advertisesImageEdit || c.imageEditRateMicroUsdc > 0
}

/**
 * sealRecipientOf is the recipient a reserve or inference envelope must be
 * sealed to, or a NoEphemeralError. It re-checks expiry without re-verifying:
 * the advertisement was verified when the operator was built, which can be
 * minutes before the request, and the node may already have erased the key.
 */
export function sealRecipientOf(o: Pick<Operator, 'ephemeralRecipient' | 'ephemeralExpiry'>, nowMs: number): string {
    if (o.ephemeralRecipient && nowMs < o.ephemeralExpiry * 1000) {
        return o.ephemeralRecipient
    }
    throw new NoEphemeralError()
}

/** modelCapacityOf is one advertised model as the registry keeps it. */
export function modelCapacityOf(m: OperatorDetailsModel): ModelCapacity {
    return {
        contextWindow: m.context_window ?? 0,
        maxOutputTokens: m.max_output_tokens ?? 0,
        inputModalities: m.input_modalities,
        outputModalities: m.output_modalities,
        inputUsdPer1m: m.input_rate_usd_per_1m ?? 0,
        outputUsdPer1m: m.output_rate_usd_per_1m ?? 0,
        cacheReadUsdPer1m: m.cache_read_rate_usd_per_1m,
        longContextThresholdTokens: m.long_context_threshold_tokens ?? 0,
        longContextInputUsdPer1m: m.long_context_input_rate_usd_per_1m,
        longContextOutputUsdPer1m: m.long_context_output_rate_usd_per_1m,
        longContextCacheReadUsdPer1m: m.long_context_cache_read_rate_usd_per_1m,
        reasoning: m.reasoning,
        toolUse: m.tool_use,
        tags: m.tags,
        coordinates: m.coordinates,
        weightsDigest: m.weights_digest ?? '',
        weightsUnverifiable: m.weights_unverifiable ?? false,
        source: m.source ?? '',
        canonicalId: m.canonical_id ?? '',
        // Node-authored and shown to the payer, so an unknown tier is dropped
        // rather than passed through as a label the node invented.
        retention: isKnownRetention(m.retention) ? m.retention : '',
        imageToolRateMicroUsdc: m.image_tool_rate_micro_usdc ?? 0,
        imageEditToolRateMicroUsdc: m.image_edit_tool_rate_micro_usdc ?? 0,
        imageToolBaseMicroUsdc: m.image_tool_base_micro_usdc ?? 0,
        imageEditToolBaseMicroUsdc: m.image_edit_tool_base_micro_usdc ?? 0,
        imageRateMicroUsdc: m.image_rate_micro_usdc ?? 0,
        imageEditRateMicroUsdc: m.image_edit_rate_micro_usdc ?? 0,
        imageDefaultMicroUsdc: m.image_default_micro_usdc ?? 0,
        imageEditDefaultMicroUsdc: m.image_edit_default_micro_usdc ?? 0,
        imageCapMicroUsdc: m.image_cap_micro_usdc ?? 0,
        imageEditCapMicroUsdc: m.image_edit_cap_micro_usdc ?? 0,
        advertisesImageGen: m.serves_image_gen ?? false,
        advertisesImageEdit: m.serves_image_edit ?? false,
        toolCallRatesMicroUsdc: m.tool_call_rates_micro_usdc,
        vendorToolCatchAllMicroUsdc: m.vendor_tool_catchall_micro_usdc ?? 0,
        vendorToolCallCap: m.vendor_tool_call_cap ?? 0,
        vendorToolTokensPerCall: m.vendor_tool_tokens_per_call ?? 0,
    }
}

/**
 * The advertised fields Go's details probe copies onto an operator. The
 * ephemeral recipient and the TEE verdict are not among them: each needs a
 * verification the registry runs before setting it.
 */
export type DetailsFields = Pick<
    Operator,
    | 'models'
    | 'modelCapacities'
    | 'builtinTools'
    | 'maxToolIters'
    | 'toolHeadroomPerIteration'
    | 'protoVersion'
    | 'minChargeOutputTokens'
    | 'minChargeAlgoTxns'
    | 'minChargeMicroUsdc'
>

// A record keyed by node-chosen model ids. No prototype, so an id such as
// "__proto__" is an entry, as in Go's map, rather than a prototype swap.
function idRecord<V>(): Record<string, V> {
    return Object.create(null) as Record<string, V>
}

export function detailsFieldsOf(d: OperatorDetails): DetailsFields {
    const modelCapacities = idRecord<ModelCapacity>()
    for (const m of d.models) modelCapacities[m.id] = modelCapacityOf(m)
    return {
        models: d.models.map((m) => m.id),
        modelCapacities,
        builtinTools: (d.builtin_tools ?? []).map((t) => ({ type: t.type })),
        maxToolIters: d.max_tool_iterations ?? 0,
        toolHeadroomPerIteration: d.tool_headroom_per_iteration ?? 0,
        protoVersion: d.proto_version ?? '',
        minChargeOutputTokens: d.min_charge_output_tokens ?? 0,
        minChargeAlgoTxns: d.min_charge_algo_txns ?? 0,
        minChargeMicroUsdc: d.min_charge_microusdc ?? 0,
    }
}

/**
 * selectionOf projects an operator onto the descriptor the shared selection
 * policy ranks. Rates are projected because the policy price-sorts on them;
 * they are only ever compared, so Go↔TS parity holds.
 */
export function selectionOf(o: Operator): SelectionOperator {
    // The optional fields are left out where Go's omitempty drops them, so the
    // two descriptors serialize alike.
    const model_capacities = idRecord<SelectionModelCapacity>()
    for (const [m, c] of Object.entries(o.modelCapacities)) {
        const cap: SelectionModelCapacity = {
            context_window: c.contextWindow,
            max_output_tokens: c.maxOutputTokens,
            serves_image_gen: servesImageGen(c),
            serves_image_edit: servesImageEdit(c),
            offers_image_gen_tool: c.imageToolRateMicroUsdc > 0,
            offers_image_edit_tool: c.imageEditToolRateMicroUsdc > 0,
            input_usd_per_1m: c.inputUsdPer1m,
            output_usd_per_1m: c.outputUsdPer1m,
            image_rate_micro_usdc: c.imageRateMicroUsdc,
            image_edit_rate_micro_usdc: c.imageEditRateMicroUsdc,
        }
        // Dormant, but a serialized field the selection vectors pin.
        if (c.reasoning?.supported === true) cap.reasoning_supported = true
        model_capacities[m] = cap
    }
    const out: SelectionOperator = {
        id: o.id,
        node_id: o.nodeId,
        owner_addr: o.ownerAddr,
        base_url: o.baseUrl,
        proto_version: o.protoVersion,
        reachable: o.reachable,
        tee_attested: isTeeAttested(o),
        models: o.models,
        model_capacities,
        builtin_tools: o.builtinTools.map((t) => t.type),
    }
    if (o.staging) out.staging = true
    if (o.signerSpendableMicroAlgos !== undefined) out.signer_spendable_microalgos = o.signerSpendableMicroAlgos
    return out
}
