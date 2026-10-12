/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The attestation probe: GET a node's evidence bundle, directly or through a
// relay hop, and turn the verifier's verdict into the operator's TEEStatus.
// Mirrors proto/go/zs's AttestationClient.Fetch (attestation_client.go) and
// probeAttestation (fetcher.go). A host's registry calls probeAttestation
// after a successful details probe, with that probe's hop.
//
// Differences from Go:
//  - As in fetchDetails, the caller's abort is rethrown as is, from the fetch
//    or the verification, rather than recorded as fetch_failed or a failing
//    verdict, since a TypeScript caller tells an abort apart by its own signal.
//    Go's registry stores a cycle its deadline cut short, so the caller still
//    records a status: registry/probe.ts records fetchFailedStatus.
//  - The status carries the verdict's display detail, which Go logs instead.
//    The measurement checks inside it are also copied to osImageChecked and
//    composeReleaseChecked, which is where routing reads them in both SDKs.
//  - An evidence URL that Go's url.Parse refuses but WHATWG URL accepts (such
//    as "/%zz") is fetched here and fetch_failed in Go. Where the bundle comes
//    from changes nothing it has to prove, so this is left alone.

import {
    ATTESTATION_CONTENT_TYPE,
    type TEEAdvertisement,
    type TEEEvidenceBundle,
    decodeEvidenceBundle,
    parseRFC3339,
} from '@txnlab/zs-proto/inject'

import { readLimited } from './http.js'
import { type Operator, type TEEStatus, isTeeAttested } from './operator.js'
import { type Fetch, type Logger, discardLogger } from './ports.js'
import { type RelayHop, applyRelay } from './routing/relay.js'
import { FailureTag, VERIFIER_ID_BUILTIN } from './tee/tags.js'
import type { Verifier } from './tee/types.js'

export const ATTESTATION_PATH = '/v1/zs/attestation'

/**
 * Go's DefaultAttestationFetchTimeout. A registry passes its details timeout,
 * as Go's does, since the two probes share the per-node deadline.
 */
export const DEFAULT_ATTESTATION_TIMEOUT_MS = 2_000

/**
 * An attestation fetch that failed: no response, an error status, or a body
 * that is not a bundle. Go returns these as plain errors and records them all
 * as fetch_failed; status says which one it was, for a log.
 */
export class AttestationFetchError extends Error {
    override readonly name = 'AttestationFetchError'
    /** The endpoint's error status; 0 when it answered none. */
    readonly status: number

    constructor(message: string, opts: { status?: number; cause?: unknown } = {}) {
        super(message, { cause: opts.cause })
        this.status = opts.status ?? 0
    }
}

export interface AttestationCall {
    /** The target node's root. */
    baseUrl: string
    /** The advertisement's evidence_url; absent or '' means ATTESTATION_PATH. */
    evidenceUrl?: string | undefined
    /**
     * The relay to probe through; null or absent probes directly. A relay
     * forwards only to ATTESTATION_PATH, so a node advertising any other
     * evidence URL is probed there.
     */
    hop?: RelayHop | null
    fetch: Fetch
    /** Bounds the probe; DEFAULT_ATTESTATION_TIMEOUT_MS when absent. */
    timeoutMs?: number
    signal?: AbortSignal
}

/**
 * fetchAttestation fetches and decodes one node's evidence bundle. It throws
 * AttestationFetchError for any failure, or the caller's abort reason when
 * call.signal fired. The body is read to 256 KiB, as Go's LimitReader: a
 * longer one fails to decode rather than being judged in part.
 */
export async function fetchAttestation(call: AttestationCall): Promise<TEEEvidenceBundle> {
    const endpoint = joinAttestationUrl(call.baseUrl, call.evidenceUrl ?? '')
    const req = applyRelay(call.hop ?? null, endpoint, 'GET', { Accept: ATTESTATION_CONTENT_TYPE }, ATTESTATION_PATH)
    const timeout = AbortSignal.timeout(call.timeoutMs ?? DEFAULT_ATTESTATION_TIMEOUT_MS)
    const signal = call.signal ? AbortSignal.any([call.signal, timeout]) : timeout

    let resp: Response
    try {
        // Evidence is re-minted on the node's own schedule, so a cached copy
        // would be judged stale or mask the current one.
        resp = await call.fetch(req.url, { method: req.method, headers: req.headers, signal, cache: 'no-store' })
    } catch (err) {
        if (call.signal?.aborted) throw call.signal.reason
        throw new AttestationFetchError(`attestation request: ${message(err)}`, { cause: err })
    }
    if (resp.status >= 400) {
        await resp.body?.cancel().catch(() => {})
        throw new AttestationFetchError(`attestation endpoint returned ${resp.status}`, { status: resp.status })
    }
    let raw: Uint8Array
    try {
        raw = await readLimited(resp)
    } catch (err) {
        if (call.signal?.aborted) throw call.signal.reason
        throw new AttestationFetchError(`read attestation body: ${message(err)}`, { cause: err })
    }
    try {
        return decodeEvidenceBundle(raw)
    } catch (err) {
        throw new AttestationFetchError(`decode attestation: ${message(err)}`, { cause: err })
    }
}

/**
 * joinAttestationUrl resolves an advertised evidence URL against the node's
 * base URL, as Go's joinAttestationURL: empty is the standard path, an
 * http(s) URL is used as is, anything else is a path on the base. Only those
 * two schemes pass as absolute, so a node cannot point the probe at another
 * scheme; anything else, such as "file:...", becomes a path on the base.
 */
export function joinAttestationUrl(baseUrl: string, evidenceUrl: string): string {
    const base = baseUrl.replace(/\/+$/, '')
    if (base === '') throw new AttestationFetchError('empty operator base_url')
    if (evidenceUrl === '') return base + ATTESTATION_PATH
    if (evidenceUrl.startsWith('http://') || evidenceUrl.startsWith('https://')) return evidenceUrl
    return base + (evidenceUrl.startsWith('/') ? evidenceUrl : `/${evidenceUrl}`)
}

export interface AttestationProbe {
    /**
     * The row after its details probe applied the ephemeral advertisement, so
     * ephemeralRecipient is the verified one; expiry is not re-checked, as Go's
     * TEENode does not.
     */
    operator: Pick<Operator, 'id' | 'nodeId' | 'baseUrl' | 'ephemeralRecipient'>
    /** The tee field of the node's details; undefined when it advertises none. */
    advertised: TEEAdvertisement | undefined
    /** Config.teeVerifier as resolved; undefined when disableTee. */
    verifier: Verifier | undefined
    /** The hop the details probe succeeded through; null or absent for direct. */
    hop?: RelayHop | null
    fetch: Fetch
    /** The registry's details timeout; DEFAULT_ATTESTATION_TIMEOUT_MS when absent. */
    timeoutMs?: number
    signal?: AbortSignal
    log?: Logger
}

/**
 * probeAttestation fetches a node's evidence and verifies it, returning the
 * TEEStatus to set on the operator. undefined, which routes as unattested,
 * when the node advertises no TEE or verification is off. For a node with
 * no verified ephemeral recipient its evidence is not fetched, and the status
 * has failureTag ephemeral_unavailable. A failed fetch is a status with failureTag
 * fetch_failed. A node that fails any way stays routable for requests that
 * do not require a TEE.
 */
export async function probeAttestation(p: AttestationProbe): Promise<TEEStatus | undefined> {
    if (p.advertised === undefined || p.verifier === undefined) return undefined
    const log = p.log ?? discardLogger
    const op = p.operator
    const relay =
        p.hop == null ? {} : { relay_operator_id: p.hop.relayId, relay_node_id: p.hop.relayNodeId }

    // The verifier would fail step 0 before reading the bundle, and
    // key_binding_mismatch reads as the node attesting the wrong key.
    if (op.ephemeralRecipient === undefined || op.ephemeralRecipient === '') {
        return unfetchedStatus(p.advertised, FailureTag.EphemeralUnavailable)
    }
    const recipient = op.ephemeralRecipient

    let bundle: TEEEvidenceBundle
    try {
        bundle = await fetchAttestation({
            baseUrl: op.baseUrl,
            evidenceUrl: p.advertised.evidence_url,
            hop: p.hop ?? null,
            fetch: p.fetch,
            ...(p.timeoutMs !== undefined && { timeoutMs: p.timeoutMs }),
            ...(p.signal !== undefined && { signal: p.signal }),
        })
    } catch (err) {
        if (p.signal?.aborted) throw p.signal.reason
        log.warn('operator attestation probe failed', {
            operator_id: op.id,
            node_id: op.nodeId,
            ...relay,
            base_url: op.baseUrl,
            mode: p.advertised.mode,
            err: message(err),
        })
        return fetchFailedStatus(p.advertised)
    }

    const verdict = await p.verifier.verify(
        p.advertised,
        bundle,
        {
            operatorId: BigInt(op.id),
            nodeId: BigInt(op.nodeId),
            ephemeralRecipientPubkey: recipient,
        },
        p.signal,
    )
    // The verifier reports an abort as an unreachable collateral service.
    if (p.signal?.aborted) throw p.signal.reason
    if (!verdict.pass) {
        log.warn('operator attestation verification failed', {
            operator_id: op.id,
            node_id: op.nodeId,
            ...relay,
            mode: p.advertised.mode,
            failure_tag: verdict.failureTag,
        })
    }
    const checks = verdict.detail?.measurementChecks
    const status: TEEStatus = {
        mode: p.advertised.mode,
        attestedAt: verdict.attestedAt,
        verifierId: verdict.verifierId,
        verified: verdict.pass,
        failureTag: verdict.failureTag,
        osImageChecked: checks?.osImage === true,
        composeReleaseChecked: checks?.composeRelease === true,
        ...(verdict.attestedModelIds !== undefined && { attestedModelIds: verdict.attestedModelIds }),
        ...(verdict.detail !== undefined && { detail: verdict.detail }),
    }
    if (verdict.pass && !isTeeAttested({ tee: status })) {
        // Without this a pass that routing refuses is silent: a stub node, or a
        // verifier with a compose-hash pin and the release match off, verifies
        // cleanly and then never receives requireTee traffic.
        log.warn('operator attestation passed but is not attested for routing', {
            operator_id: op.id,
            node_id: op.nodeId,
            ...relay,
            mode: p.advertised.mode,
            os_image_checked: status.osImageChecked,
            compose_release_checked: status.composeReleaseChecked,
        })
    }
    return status
}

/**
 * fetchFailedStatus is the TEEStatus of a node whose evidence never arrived:
 * unverified, with the time the node advertised.
 */
export function fetchFailedStatus(advertised: TEEAdvertisement): TEEStatus {
    return unfetchedStatus(advertised, FailureTag.FetchFailed)
}

// A node whose evidence was never verified: the prober's tag, with the time
// the node advertised.
function unfetchedStatus(advertised: TEEAdvertisement, failureTag: string): TEEStatus {
    return {
        mode: advertised.mode,
        attestedAt: unixMillis(advertised.attested_at),
        verifierId: VERIFIER_ID_BUILTIN,
        verified: false,
        failureTag,
        osImageChecked: false,
        composeReleaseChecked: false,
    }
}

// Go's zero time.Time, which a node with no bundle yet advertises.
const GO_ZERO_TIME_NS = -62135596800n * 1_000_000_000n

// Unix milliseconds of an RFC 3339 time; 0 when absent, unreadable or Go's
// zero time, as Go's IsZero.
function unixMillis(rfc3339: string | undefined): number {
    const ns = parseRFC3339(rfc3339 ?? '')
    return ns === null || ns === GO_ZERO_TIME_NS ? 0 : Number(ns / 1_000_000n)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
