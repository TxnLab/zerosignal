/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The names this package shares with proto/go/zs, checked against
// testdata/sdk_vocabulary_vectors.json, which Go generates from its own
// declarations. Each list below is also checked against the TypeScript type
// it describes, at compile time (pnpm typecheck), so a field added to either
// side without the other fails one of the two.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import {
    type AffinityPolicy,
    type Attribution,
    type Endpoint,
    type Event,
    type EventType,
    type Item,
    type Kind,
    type NodeRef,
    type Privacy,
    type ProviderError,
    type ReceiptViolation,
    type RelayHopReason,
    type Settlement,
    type SettleArgs,
    type SettleKind,
    type Ticket,
    type TicketRecord,
    type TicketStatus,
    type ToolState,
    type ZsErrorInit,
    DEFAULT_ATTESTATION_TIMEOUT_MS,
    DEFAULT_LAPSE_FALLBACK_MS,
    ESCROW_CONFIG_TIMEOUT_MS,
    FEE_RATE_CACHE_TTL_MS,
    FEE_RATE_REFRESH_TIMEOUT_MS,
    RESPONSE_HEADER_BACKSTOP_MS,
    SETTLE_PENDING_GRACE_MS,
    defaults,
    kinds,
    localnet,
    networkNames,
    receiptViolations,
    resolveNetwork,
} from '../src/index.js'

interface Vocabulary {
    events: Record<string, string[]>
    records: Record<string, string[]>
    enums: Record<string, string[]>
    networks: Record<string, { algod_endpoint: string; algod_token: string; escrow_app_id: number; fee_sink: string }>
    defaults: Record<string, number>
}

const vocab: Vocabulary = JSON.parse(
    readFileSync(new URL('../../testdata/sdk_vocabulary_vectors.json', import.meta.url), 'utf8'),
)

// Every member of T appears in L.
type Covers<T, L extends readonly unknown[]> = [Exclude<T, L[number]>] extends [never] ? true : false

type FieldsOf<E> = Exclude<keyof E, 'type'>
type EventOf<K extends EventType> = Extract<Event, { type: K }>

const eventFields = {
    'route.candidates': ['model', 'candidates'],
    'relay.hop': ['relay', 'target', 'reason'],
    'reserve.started': ['target', 'relay', 'attempt'],
    'reserve.retrying': ['target', 'status', 'code', 'attribution', 'wait', 'attempt'],
    'reserve.succeeded': ['ticketId', 'target', 'maxPrice', 'expiresAt'],
    'payment.committed': ['ticketId', 'openTxId', 'feesMicroAlgos'],
    'max_output.clamped': ['ceiling'],
    'response.started': ['status', 'header', 'streaming'],
    frame: ['event', 'id', 'data', 'comment', 'retry', 'sealed'],
    'item.opened': ['item'],
    'item.closed': ['item'],
    'delta.text': ['itemId', 'delta'],
    'delta.reasoning': ['itemId', 'delta'],
    'delta.tool_call': ['itemId', 'callId', 'name', 'argumentsDelta'],
    'annotation.added': ['itemId', 'annotation'],
    'tool.status': ['itemId', 'callId', 'name', 'state', 'action', 'icons'],
    'image.progress': ['itemId', 'value', 'max'],
    'image.partial': ['itemId', 'b64', 'mime'],
    usage: ['inputTokens', 'outputTokens', 'reasoningTokens', 'source'],
    'receipt.verified': [
        'receipt',
        'ticket',
        'target',
        'ownerAddr',
        'openFeesMicroAlgos',
        'settleFeesMicroAlgos',
        'algoUsd',
        'feeBps',
        'feeBpsKnown',
    ],
    'receipt.violated': ['violation', 'protestTxId'],
    'settle.submitted': ['ticketId', 'txId', 'feesMicroAlgos', 'atomic'],
    'node.excluded': ['node', 'reason'],
    done: ['finishReason', 'incompleteReason', 'empty'],
} as const satisfies { [K in EventType]: readonly FieldsOf<EventOf<K>>[] }

type MissingEventField = {
    [K in EventType]: Exclude<FieldsOf<EventOf<K>>, (typeof eventFields)[K][number]>
}[EventType]
const eventFieldsComplete: [MissingEventField] extends [never] ? true : false = true

// Each list is checked both ways: satisfies refuses a name the type lacks,
// and Covers below refuses a field the list lacks. Go's Error.Err is the
// standard `cause` here.
const errorFields = [
    'kind',
    'code',
    'message',
    'retryable',
    'retryAfter',
    'paid',
    'ticket',
    'cause',
] as const satisfies readonly (keyof ZsErrorInit)[]
const nodeRefFields = ['op', 'node'] as const satisfies readonly (keyof NodeRef)[]
const itemFields = ['id', 'type', 'raw'] as const satisfies readonly (keyof Item)[]
const ticketFields = ['id', 'signed', 'target'] as const satisfies readonly (keyof Ticket)[]
const settlementFields = ['ticketId', 'kind', 'txId', 'feesMicroAlgos'] as const satisfies readonly (keyof Settlement)[]
const providerErrorFields = ['code', 'message', 'status'] as const satisfies readonly (keyof ProviderError)[]
// What ProviderError adds to Error, plus the message Go declares as a field.
type ProviderErrorOwn = Exclude<keyof ProviderError, keyof Error> | 'message'
const ticketRecordFields = [
    'ticketId',
    'openTxId',
    'escrowAppId',
    'target',
    'payer',
    'maxPrice',
    'expiresAt',
    'status',
    'createdAt',
    'updatedAt',
    'settle',
] as const satisfies readonly (keyof TicketRecord)[]
const settleArgsFields = [
    'amountCharged',
    'receiptDigest',
    'ttftMs',
    'decodeMs',
    'inputTokens',
    'outputTokens',
    'outputUsageType',
    'auxOutputUsageType',
    'auxOutputCount',
] as const satisfies readonly (keyof SettleArgs)[]
const recordsComplete: [
    Covers<keyof ZsErrorInit, typeof errorFields>,
    Covers<keyof NodeRef, typeof nodeRefFields>,
    Covers<keyof Item, typeof itemFields>,
    Covers<keyof Ticket, typeof ticketFields>,
    Covers<keyof Settlement, typeof settlementFields>,
    Covers<ProviderErrorOwn, typeof providerErrorFields>,
    Covers<keyof TicketRecord, typeof ticketRecordFields>,
    Covers<keyof SettleArgs, typeof settleArgsFields>,
] = [true, true, true, true, true, true, true, true]

const privacies = ['relay_required', 'direct'] as const satisfies readonly Privacy[]
const affinityPolicies = ['prefer', 'strict', 'none'] as const satisfies readonly AffinityPolicy[]
const relayHopReasons = ['chosen', 'rotated'] as const satisfies readonly RelayHopReason[]
const toolStates = ['in_progress', 'completed'] as const satisfies readonly ToolState[]
const ticketStatuses = ['open', 'settle_pending'] as const satisfies readonly TicketStatus[]
const settleKinds = ['', 'atomic', 'payer_ack', 'protest'] as const satisfies readonly SettleKind[]
const endpoints = [
    '/v1/chat/completions',
    '/v1/responses',
    '/v1/images/generations',
    '/v1/images/edits',
] as const satisfies readonly Endpoint[]
const attributions = ['', 'relay', 'target', 'unknown'] as const satisfies readonly Attribution[]
const enumsComplete: [
    Covers<Kind, typeof kinds>,
    Covers<Privacy, typeof privacies>,
    Covers<AffinityPolicy, typeof affinityPolicies>,
    Covers<RelayHopReason, typeof relayHopReasons>,
    Covers<ToolState, typeof toolStates>,
    Covers<TicketStatus, typeof ticketStatuses>,
    Covers<SettleKind, typeof settleKinds>,
    Covers<Endpoint, typeof endpoints>,
    Covers<Attribution, typeof attributions>,
    Covers<ReceiptViolation, typeof receiptViolations>,
] = [true, true, true, true, true, true, true, true, true, true]

describe('vocabulary shared with the Go SDK', () => {
    it('is complete at compile time', () => {
        expect(eventFieldsComplete).toBe(true)
        expect(recordsComplete.every(Boolean)).toBe(true)
        expect(enumsComplete.every(Boolean)).toBe(true)
    })

    it('names every event and its fields as Go does', () => {
        expect(eventFields).toEqual(vocab.events)
    })

    it('names the record fields as Go does', () => {
        const errorGo = vocab.records.Error!.map((f) => (f === 'err' ? 'cause' : f))
        expect(errorFields).toEqual(errorGo)
        expect(nodeRefFields).toEqual(vocab.records.NodeRef)
        expect(itemFields).toEqual(vocab.records.Item)
        expect(ticketFields).toEqual(vocab.records.Ticket)
        expect(settlementFields).toEqual(vocab.records.Settlement)
        expect(providerErrorFields).toEqual(vocab.records.ProviderError)
        expect(ticketRecordFields).toEqual(vocab.records.TicketRecord)
        expect(settleArgsFields).toEqual(vocab.records.SettleArgs)
    })

    it('spells every enum as Go does', () => {
        expect(kinds).toEqual(vocab.enums.Kind)
        expect(privacies).toEqual(vocab.enums.Privacy)
        expect(affinityPolicies).toEqual(vocab.enums.AffinityPolicy)
        expect(relayHopReasons).toEqual(vocab.enums.RelayHopReason)
        expect(toolStates).toEqual(vocab.enums.ToolState)
        expect(ticketStatuses).toEqual(vocab.enums.TicketStatus)
        expect(settleKinds).toEqual(vocab.enums.SettleKind)
        expect(endpoints).toEqual(vocab.enums.Endpoint)
        expect(attributions).toEqual(vocab.enums.Attribution)
        expect(receiptViolations).toEqual(vocab.enums.ReceiptViolation)
        expect(Object.keys(vocab.enums).sort()).toEqual(
            [
                'AffinityPolicy',
                'Attribution',
                'Endpoint',
                'Kind',
                'Privacy',
                'ReceiptViolation',
                'RelayHopReason',
                'SettleKind',
                'TicketStatus',
                'ToolState',
            ].sort(),
        )
    })

    it('resolves the network presets as Go does', () => {
        for (const [name, want] of Object.entries(vocab.networks)) {
            const net =
                name === 'localnet'
                    ? resolveNetwork({ ...localnet(), escrowAppId: 1n })
                    : resolveNetwork({ network: name as 'testnet' | 'mainnet' })
            expect(net.algodEndpoint, name).toBe(want.algod_endpoint)
            expect(net.algodToken, name).toBe(want.algod_token)
            expect(net.feeSink, name).toBe(want.fee_sink)
            expect(net.escrowAppId, name).toBe(name === 'localnet' ? 1n : BigInt(want.escrow_app_id))
        }
        // A preset on one side only fails here.
        expect([...networkNames].sort()).toEqual(Object.keys(vocab.networks).sort())
        // localnet embeds none, which is why it needs one passed above.
        expect(vocab.networks.localnet!.escrow_app_id).toBe(0)
    })

    it('defaults Config as Go does', () => {
        const d = defaults.discovery
        expect({
            affinityMax: defaults.affinity.max,
            affinityTtlMs: defaults.affinity.ttl,
            concurrentSlots: defaults.concurrentSlots,
            detailsConcurrency: d.detailsConcurrency,
            detailsFetchTimeoutMs: d.detailsTimeout,
            attestationFetchTimeoutMs: DEFAULT_ATTESTATION_TIMEOUT_MS,
            latencyStateMax: d.latencyStateMax,
            maxCacheAgeMs: d.maxCacheAge,
            maxCarryAgeMs: d.maxCarryAge,
            maxOutputCeiling: defaults.maxOutputCeiling,
            probeBudget: d.probeBudget,
            refreshIntervalMs: d.refreshInterval,
            refreshTimeoutMs: d.refreshTimeout,
            reserveTimeoutMs: defaults.reserveTimeout,
            retryBudgetMs: defaults.retryBudget,
            targetTopK: d.targetTopK,
            settlePendingGraceMs: SETTLE_PENDING_GRACE_MS,
            lapseFallbackMs: DEFAULT_LAPSE_FALLBACK_MS,
            feeRateCacheTtlMs: FEE_RATE_CACHE_TTL_MS,
            feeRateRefreshMs: FEE_RATE_REFRESH_TIMEOUT_MS,
            escrowConfigTimeoutMs: ESCROW_CONFIG_TIMEOUT_MS,
            responseHeaderBackstopMs: RESPONSE_HEADER_BACKSTOP_MS,
        }).toEqual(vocab.defaults)
    })
})
