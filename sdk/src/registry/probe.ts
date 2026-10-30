/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The probe half of discovery: each node's /v1/zs/details, and its evidence
// where it advertises a TEE, applied to the Operator the chain read built.
// Mirrors the probe pass of go/zs's ChainOperatorSource (fetcher.go: enrich,
// probeOne, buildSelAll, applyEphemeralAdvertisement, ReprobeEphemeral) and
// the cross-cycle reachability it keeps (recallReachable, recordReachable).
// What an outcome writes onto the node is pinned by
// testdata/registry_probe_vectors.json; the rotation, ephemeral and
// attestation steps it calls are pinned where they live.
//
// Differences from Go:
//   - Go's routing stores are fields of its source. Here the reputation and
//     latency stores can be handed in, and a Client that builds its registry
//     hands in the ones it routes with, so it sees the probe's records. A
//     supplied reputation store judges a relay's relay_upstream_unreachable
//     claim by its own targetReachable callback, which must answer from
//     recallReachable for the claim to be read against the probes as Go reads
//     it; the store built here, and the one a Client builds, are wired that
//     way.
//   - probeDetails reports to a relay-health store that Go has no twin of.
//     Its records land where Go's do: a relay that failed the hop is
//     remembered unreachable, a forward through one records no reachability,
//     and the reputation and latency calls go through as made.
//   - fetchDetails cannot see whether a relay accepted the connection, so a
//     relayed probe that hits its own deadline charges the relay nothing
//     either way. Go charges one that never accepted it, as a dead endpoint,
//     and that is the common shape of a relay whose host is gone: its dropped
//     SYNs run out the deadline before any connect error. Here such a relay
//     is demoted only once its own probe, routed through another relay,
//     fails.
//   - An abort during the attestation probe records fetch_failed, as Go does
//     for a cancelled fetch. Go's verifier answers a verification cancelled
//     part way with a failing verdict of its own instead; both are
//     unverified. A verifier that throws anything else leaves no TEE
//     verdict, with a warning; Go's verifier cannot fail that way.
//   - Host log calls on the probe path are made through a wrapper that drops
//     a logger's throw, so a broken logger cannot change a probe's outcome.
//   - Privacy is the SDK's Privacy, defaulting as Config does to
//     relay_required. Go's source takes a bool whose zero is direct.
//   - The fetch is the host's. Absent, it is the default Config uses with
//     private hosts refused, resolved at the first probe: under Node that
//     refuses private addresses as the Go client New() builds does; in a
//     browser it refuses a URL whose host is literally private. A localnet
//     host passes its own fetch.
//   - The probe set is keyed by nodeRefString, and the node's build id is not
//     kept, since the SDK's Operator does not carry one.

import { defaultFetch } from '#default-fetch'
import type { OperatorDetails } from '@txnlab/zs-proto/inject'
import type { Operator as SelectionOperator } from '@txnlab/zs-proto/selection'
import { knownDeployment } from '@txnlab/zs-proto/ticket'
import { bootstrapProtoVersion } from '@txnlab/zs-proto/wire'

import { fetchFailedStatus, probeAttestation } from '../attestation.js'
import { checkDetailsDeployment } from '../catalog/deployment.js'
import { checkEphemeralAdvertisement, recordEphemeralStaleness } from '../catalog/ephemeral.js'
import { defaults } from '../config.js'
import { DEFAULT_DETAILS_TIMEOUT_MS, type DetailsProbeStores, RelayHopError, RelayUpstreamUnreachableError, probeDetails } from '../details.js'
import { type Operator, detailsFieldsOf, refOf, selectionOf } from '../operator.js'
import { quietLogger } from '../log.js'
import { type Clock, type Fetch, type Logger, discardLogger } from '../ports.js'
import { RelayLatencyStore } from '../routing/latency.js'
import { type RelayHop, randomRelaySeed, relayRef, selectRelayHopWeighted } from '../routing/relay.js'
import { RelayReputationStore } from '../routing/reputation.js'
import type { Verifier } from '../tee/types.js'
import { type NodeRef, type Privacy, nodeRefString } from '../types.js'

/** DEFAULT_DETAILS_CONCURRENCY is Go's DefaultDetailsConcurrency. */
export const DEFAULT_DETAILS_CONCURRENCY = defaults.discovery.detailsConcurrency

/**
 * How one details probe ended, as far as what it says about the target:
 * - no_relay: privacy on and no eligible relay, so nothing was sent.
 * - cancelled: the caller's signal ended it.
 * - hop_failed: every relay tried failed at the hop; the target is unknown.
 * - target_failed: the target answered with a failure, or every relay that
 *   worked said it was down, or (direct) it could not be reached.
 * - succeeded: the target's advertisement arrived.
 */
export type ProbeOutcome = 'no_relay' | 'cancelled' | 'hop_failed' | 'target_failed' | 'succeeded'

/**
 * classifyProbeFailure sorts what probeDetails threw. A fired signal outranks
 * a hop error, since a probe cut short learned nothing about either hop.
 */
export function classifyProbeFailure(err: unknown, signal: AbortSignal | undefined): 'cancelled' | 'hop_failed' | 'target_failed' {
    if (signal?.aborted) return 'cancelled'
    if (err instanceof RelayHopError) return 'hop_failed'
    return 'target_failed'
}

/** The fields applyProbeOutcome writes. */
export type ProbeOutcomeFields = Pick<
    Operator,
    'reachable' | 'probed' | 'lastRefreshAt' | 'reachableAsOf' | 'ephemeralRecipient' | 'ephemeralExpiry' | 'ephemeralIssuedAt' | 'tee'
>

/**
 * applyProbeOutcome writes onto op what outcome says about its target, at
 * nowMs, and returns the reachability to remember for it, or undefined to
 * leave the remembered one alone. On success it also voids the ephemeral
 * recipient and the TEE verdict, which only that probe's own advertisement may
 * set again. Go's applyProbeOutcome.
 */
export function applyProbeOutcome(op: ProbeOutcomeFields, outcome: ProbeOutcome, nowMs: number): boolean | undefined {
    switch (outcome) {
        case 'no_relay':
        case 'hop_failed':
            // Nothing reached the target, so its reachability and capabilities
            // stand for the registry to carry; only the attempt is stamped.
            op.lastRefreshAt = nowMs
            return undefined
        case 'cancelled':
            return undefined
        case 'target_failed':
            // The models stay: whether last-known capabilities carry is the
            // registry's call, and a node whose reserve path is up can still
            // serve them.
            op.reachable = false
            op.probed = true
            op.lastRefreshAt = nowMs
            return false
        case 'succeeded':
            op.ephemeralRecipient = undefined
            op.ephemeralExpiry = 0
            op.ephemeralIssuedAt = 0
            op.tee = undefined
            op.reachable = true
            op.probed = true
            op.lastRefreshAt = nowMs
            // Only a success moves the carry clock, so a node that stops
            // answering ages out of the carry window on schedule.
            op.reachableAsOf = nowMs
            return true
    }
}

/**
 * The source's probe settings. A Client-built source passes Config's resolved
 * values for each; the defaults are for a source a host builds on its own, and
 * each fails safe rather than following Config.
 */
export interface ProbeOptions {
    /**
     * Every probe's fetch: Config.fetch as resolved. Absent is the default
     * Config uses with private hosts refused, so a localnet host passes its own.
     */
    fetch?: Fetch | undefined
    /**
     * relay_required when absent, whatever the network: a source left at a
     * direct default would show the payer's IP to every node it probes. A
     * Client hands its source Config's resolved privacy, which is direct on a
     * local chain.
     */
    privacy?: Privacy | undefined
    /** One details probe, and the attestation probe after it; absent, zero or negative is DEFAULT_DETAILS_TIMEOUT_MS. */
    detailsTimeoutMs?: number | undefined
    /** Probes in flight at once; absent, zero or negative is DEFAULT_DETAILS_CONCURRENCY. */
    detailsConcurrency?: number | undefined
    /**
     * Config.teeVerifier as resolved. Absent checks no evidence, unlike
     * Config, which builds a default verifier: that fails closed, every TEE
     * node reading as unattested, rather than have the source build a second
     * verifier with its own collateral cache beside the Client's.
     */
    teeVerifier?: Verifier | undefined
    /** Shared with a Client; absent builds one judging claims by recallReachable. */
    relayReputation?: RelayReputationStore | undefined
    /** Shared with a Client; absent builds one capped at latencyStateMax. */
    relayLatency?: RelayLatencyStore | undefined
    latencyStateMax?: number | undefined
    logger?: Logger | undefined
    /** Wall clock, Unix ms. */
    clock?: Clock | undefined
    /**
     * The payer's own deployment id, which a node's bound ephemeral signature
     * must name. Absent, a ChainOperatorSource derives it from algod's genesis
     * hash at its first chain read, as Go's zero ChainOperatorSource.Deployment;
     * until then only the legacy signature is checked.
     */
    deployment?: Uint8Array | undefined
}

/**
 * NodeProber runs the details probes for a ChainOperatorSource and keeps what
 * outlives a cycle: each node's last probe outcome, and the relay reputation
 * and latency the probes record.
 */
export class NodeProber {
    #fetch: Fetch | undefined
    readonly #privacy: boolean
    readonly #timeoutMs: number
    readonly #concurrency: number
    readonly #verifier: Verifier | undefined
    readonly #reputation: RelayReputationStore
    readonly #latency: RelayLatencyStore
    readonly #log: Logger
    readonly #clock: Clock
    #deployment: Uint8Array | undefined
    // Each node's most recent probe outcome across cycles, keyed by
    // nodeRefString: an operator's nodes are up and down independently. The
    // fresh rows a cycle probes all start unreachable, so this is what lets
    // the relay pool prefer a relay that answered last cycle.
    readonly #lastReachable = new Map<string, boolean>()
    readonly #stores: DetailsProbeStores

    /** The id bound ephemeral signatures are checked against; undefined checks legacy only. */
    get deployment(): Uint8Array | undefined {
        return this.#deployment
    }

    set deployment(d: Uint8Array | undefined) {
        this.#deployment = knownDeployment(d)
    }

    constructor(o: ProbeOptions = {}) {
        // The default is built at the first probe: under Node it allocates a
        // guarded dispatcher, and throws where dials can't be guarded, which a
        // source built only to read the chain must not pay for.
        this.#fetch = o.fetch
        this.#privacy = (o.privacy ?? 'relay_required') !== 'direct'
        this.#timeoutMs = positiveOr(o.detailsTimeoutMs, DEFAULT_DETAILS_TIMEOUT_MS)
        // Floored first, so a fraction under one is the default rather than no workers.
        this.#concurrency = positiveOr(
            o.detailsConcurrency === undefined ? undefined : Math.floor(o.detailsConcurrency),
            DEFAULT_DETAILS_CONCURRENCY,
        )
        this.#verifier = o.teeVerifier
        // Wrapped once here, so every log call on the probe path, details.ts's
        // and attestation.ts's included, drops a logger's throw: one thrown
        // between a probe's steps would read as the target's failure, or leave
        // a node half applied.
        this.#log = quietLogger(o.logger ?? discardLogger)
        this.#clock = o.clock ?? Date.now
        this.#deployment = knownDeployment(o.deployment)
        this.#reputation =
            o.relayReputation ??
            new RelayReputationStore({ clock: this.#clock, targetReachable: (t) => this.recallReachable(t) })
        this.#latency =
            o.relayLatency ??
            new RelayLatencyStore({
                clock: this.#clock,
                ...(o.latencyStateMax !== undefined && { maxEntries: o.latencyStateMax }),
            })
        this.#stores = {
            health: {
                markRelayUnreachable: (relay) => this.#recordReachable(relay, false),
                // As in Go, a forward through a relay raises only its
                // reputation: its remembered reachability comes from its own
                // probe, which a failed hop may lower but a forward never sets.
                markRelayReachable: () => {},
                recordRelayTransportFailure: (relay) => {
                    this.#recordReachable(relay, false)
                    this.#reputation.recordRelayOutcome(relay, false)
                },
            },
            reputation: this.#reputation,
            latency: this.#latency,
        }
    }

    get relayReputation(): RelayReputationStore {
        return this.#reputation
    }

    get relayLatency(): RelayLatencyStore {
        return this.#latency
    }

    /** recallReachable is the node's last probe outcome; false when never probed. */
    recallReachable(ref: NodeRef): boolean {
        return this.#lastReachable.get(nodeRefString(ref)) ?? false
    }

    #recordReachable(ref: NodeRef, reachable: boolean): void {
        this.#lastReachable.set(nodeRefString(ref), reachable)
    }

    /**
     * enrichSubset probes the nodes of ops whose nodeRefString is in probeSet,
     * every node when it is null, and updates them in place. The rest are left
     * as the caller seeded them. A probe's failure is written onto its node,
     * never thrown. An abort leaves the nodes it cut off as they were, except
     * that a node with no eligible relay is still stamped, as in Go: no relay
     * is decided before anything is sent.
     */
    async enrichSubset(ops: Operator[], probeSet: ReadonlySet<string> | null, signal?: AbortSignal): Promise<void> {
        const fetch = this.#requireFetch()
        // Built once from the pre-probe rows, so a probe never routes through
        // a relay on what another probe of this cycle just learned.
        const selAll = this.#privacy ? this.buildSelAll(ops) : null
        const now = this.#clock()
        // Bounded: a large fleet probing at once cannot finish inside the
        // refresh timeout, and every probe the deadline cuts off learns
        // nothing.
        const queue = probeSet === null ? ops : ops.filter((op) => probeSet.has(nodeRefString(refOf(op))))
        let next = 0
        const worker = async () => {
            while (next < queue.length) {
                const op = queue[next++]!
                try {
                    await this.#probeOne(fetch, selAll, op, now, signal)
                } catch (err) {
                    // Only a host-supplied store can get here. One node's probe
                    // must not reject the cycle while the other workers are
                    // still writing to ops.
                    this.#log.warn('operator details probe threw', { ...nodeAttrs(op), err: message(err) })
                }
            }
        }
        await Promise.all(Array.from({ length: Math.min(this.#concurrency, queue.length) }, worker))
    }

    /**
     * reprobeEphemeral probes target live and returns a copy with its probed
     * state refreshed, for dispatch to retry a node it skipped for a stale
     * ephemeral. all is only the relay pool. The registry's snapshot is left
     * to the next scheduled cycle, so this never races it.
     */
    async reprobeEphemeral(all: readonly Operator[], target: Operator, signal?: AbortSignal): Promise<Operator> {
        const fetch = this.#requireFetch()
        const selAll = this.#privacy ? this.buildSelAll(all) : null
        const op = { ...target }
        await this.#probeOne(fetch, selAll, op, this.#clock(), signal)
        return op
    }

    /**
     * buildSelAll projects ops onto the relay pool the probes route through.
     * A relay is reachable when its last probe answered and its reputation
     * does not demote it, which moves it to the fallback tier rather than out,
     * so a cold start can still pick one. An unprobed relay is seeded this
     * build's major with minor 0: same major keeps it eligible, and minor 0
     * claims no capability it never showed, such as setting the relay-hop
     * header it would otherwise be charged for omitting.
     */
    buildSelAll(ops: readonly Operator[]): SelectionOperator[] {
        return ops.map((op) => {
            const sel = selectionOf(op)
            if (sel.proto_version === '') sel.proto_version = bootstrapProtoVersion()
            const ref = refOf(op)
            // Go's order: a relay never seen up does not age its reputation.
            sel.reachable = this.recallReachable(ref) && !this.#reputation.relayDownranked(ref)
            return sel
        })
    }

    async #probeOne(fetch: Fetch, selAll: SelectionOperator[] | null, op: Operator, now: number, signal?: AbortSignal): Promise<void> {
        const target = refOf(op)
        const latencyOf = (relay: NodeRef) => this.#latency.relayLatencyForTarget(relay, target)
        const sel = selectionOf(op)
        let hop: RelayHop | null = null
        let outcome: ProbeOutcome | undefined
        if (selAll !== null) {
            hop = selectRelayHopWeighted(selAll, sel, randomRelaySeed(), latencyOf)
            // Skipped rather than sent direct: a direct probe reveals the
            // payer's IP to the node.
            if (hop === null) outcome = 'no_relay'
        }

        let result: { details: OperatorDetails; hop: RelayHop | null } | undefined
        let err: unknown
        if (outcome === undefined) {
            try {
                result = await probeDetails({
                    baseUrl: op.baseUrl,
                    target,
                    hop,
                    ...(selAll !== null && {
                        nextHop: (excluded: ReadonlySet<string>) => {
                            hop = selectRelayHopWeighted(selAll, sel, randomRelaySeed(), latencyOf, excluded)
                            return hop
                        },
                    }),
                    stores: this.#stores,
                    fetch,
                    timeoutMs: this.#timeoutMs,
                    ...(signal !== undefined && { signal }),
                    clock: this.#clock,
                    logger: this.#log,
                })
                outcome = 'succeeded'
            } catch (e) {
                err = e
                outcome = classifyProbeFailure(e, signal)
            }
            // A node issuing tickets for another deployment refuses every
            // reserve this payer sends it, so its answer counts as the target
            // failing: it is neither listed nor sealable this cycle. Go's
            // probeOne has the relayed case.
            const refusal = result === undefined ? undefined : checkDetailsDeployment(result.details, this.#deployment)
            if (refusal !== undefined) {
                err = refusal
                result = undefined
                outcome = classifyProbeFailure(refusal, signal)
            }
        }

        const reachable = applyProbeOutcome(op, outcome, now)
        if (result === undefined) {
            if (reachable !== undefined) this.#recordReachable(target, reachable)
            // A target-side error is thrown from the last relay sent to, which
            // reached the target; a give-up names the relay that claimed it down.
            const via = err instanceof RelayUpstreamUnreachableError ? err.relay : hop === null ? null : relayRef(hop)
            this.#logFailure(op, outcome, err, via)
            return
        }

        this.#applyEphemeral(op, result.details, result.hop)
        Object.assign(op, detailsFieldsOf(result.details))
        if (reachable !== undefined) this.#recordReachable(target, reachable)

        // A verdict that fails, or a fetch that does, leaves the node routable
        // for requests that do not require a TEE.
        try {
            op.tee = await probeAttestation({
                operator: op,
                advertised: result.details.tee,
                verifier: this.#verifier,
                hop: result.hop,
                fetch,
                timeoutMs: this.#timeoutMs,
                ...(signal !== undefined && { signal }),
                log: this.#log,
            })
        } catch (e) {
            const advertised = result.details.tee
            if (!signal?.aborted || advertised === undefined) {
                this.#log.warn('operator attestation probe threw', { ...nodeAttrs(op), err: message(e) })
                return
            }
            // The registry stores a cycle its deadline cut short, so the node
            // needs the status Go's cancelled fetch leaves, not none.
            this.#log.warn('operator attestation probe failed', {
                ...nodeAttrs(op),
                ...hopAttrs(result.hop),
                base_url: op.baseUrl,
                mode: advertised.mode,
                err: message(e),
            })
            op.tee = fetchFailedStatus(advertised)
        }
    }

    // The ephemeral recipient is set only from an advertisement that verifies
    // under the node's on-chain key, for its chain-resolved ids: the details
    // body is untrusted, and anything short of verified leaves the node with
    // no seal target, so dispatch fails closed for it.
    #applyEphemeral(op: Operator, details: OperatorDetails, hop: RelayHop | null): void {
        op.ephemeralRecipient = undefined
        op.ephemeralExpiry = 0
        op.ephemeralIssuedAt = 0
        const v = checkEphemeralAdvertisement(
            { op: op.id, node: op.nodeId, deployment: this.#deployment },
            op.ticketSigningKey,
            details,
            Math.floor(this.#clock() / 1000),
        )
        switch (v.outcome) {
            case 'verified':
                op.ephemeralRecipient = v.recipient
                op.ephemeralExpiry = v.expiry
                op.ephemeralIssuedAt = v.issuedAt
                // A separate streak from the forward credit probeDetails just
                // gave this relay, or that credit would clear the staleness
                // every cycle.
                recordEphemeralStaleness(this.#reputation, hop === null ? null : relayRef(hop), v)
                break
            case 'unparseable':
                this.#log.warn('operator advertised an unparseable ephemeral age recipient; no seal target (fail closed)', {
                    ...nodeAttrs(op),
                    ...hopAttrs(hop),
                    err: v.error.message,
                })
                break
            case 'rejected':
                // Someone tried to substitute or over-extend a seal key.
                this.#log.warn('operator ephemeral sealing-key advertisement failed verification; no seal target (fail closed)', {
                    ...nodeAttrs(op),
                    ...hopAttrs(hop),
                    err: v.error.message,
                })
                break
            // expired is routine near a rotation and stays silent; absent is
            // a node offering none this cycle.
        }
    }

    #logFailure(op: Operator, outcome: ProbeOutcome, err: unknown, via: NodeRef | null): void {
        switch (outcome) {
            case 'no_relay':
                this.#log.debug('privacy mode: no eligible relay to probe operator; skipping details probe', nodeAttrs(op))
                return
            case 'cancelled':
                this.#log.debug('operator details probe cancelled', { ...nodeAttrs(op), err: message(err) })
                return
            case 'hop_failed':
                this.#log.warn('operator details probe: all relay hops failed this cycle; target status unknown', {
                    ...nodeAttrs(op),
                    base_url: op.baseUrl,
                    err: message(err),
                })
                return
            default:
                this.#log.warn('operator details probe failed', {
                    ...nodeAttrs(op),
                    base_url: op.baseUrl,
                    ...(via !== null && { relay_operator_id: via.op, relay_node_id: via.node }),
                    err: message(err),
                })
        }
    }

    #requireFetch(): Fetch {
        this.#fetch ??= defaultFetch(false)
        if (this.#fetch === undefined) throw new Error('this runtime has no global fetch: set the source fetch')
        return this.#fetch
    }
}


function positiveOr(v: number | undefined, fallback: number): number {
    return v !== undefined && Number.isFinite(v) && v > 0 ? v : fallback
}

function nodeAttrs(op: Operator): Record<string, number> {
    return { operator_id: op.id, node_id: op.nodeId }
}

function hopAttrs(hop: RelayHop | null): Record<string, number> {
    return hop === null ? {} : { relay_operator_id: hop.relayId, relay_node_id: hop.relayNodeId }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
