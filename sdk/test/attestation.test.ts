/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The attestation probe. The verdict as it lands on the operator is checked
// against the probe_attestation scenarios in testdata/operator_vectors.json,
// which Go's probeAttestation generates; the fetch's own rules are below.

import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'

import { type TEEAdvertisement, type TEEEvidenceBundle, parseOperatorDetails } from '@txnlab/zs-proto/inject'
import { RELAY_PATH, RELAY_PATH_HEADER, RELAY_TARGET_HEADER } from '@txnlab/zs-proto/wire'

import {
    ATTESTATION_PATH,
    AttestationFetchError,
    fetchAttestation,
    joinAttestationUrl,
    probeAttestation,
} from '../src/attestation.js'
import { isTeeAttested } from '../src/operator.js'
import type { RelayHop } from '../src/routing/index.js'
import type { Node, Verdict, Verifier } from '../src/tee/index.js'

interface ProbeScenario {
    name: string
    operator_id: number
    node_id: number
    ephemeral_recipient: string
    advertised: { evidence_url?: string } | null
    relayed: boolean
    verdict: {
        pass: boolean
        failure_tag: string
        verifier_id: string
        attested_at_ms: number
        attested_model_ids: string[] | null
        measurement_checks: { os_image: boolean; compose_release: boolean; compose_hash: boolean } | null
    } | null
    endpoint_status: number
    endpoint_body: string
    request_method: string
    request_path: string
    request_relay_path: string
    request_relay_target: string
    verified_node: { operatorId: number; nodeId: number; ephemeralRecipientPubkey: string } | null
    want: unknown
    attested: boolean
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/operator_vectors.json', import.meta.url), 'utf8')) as {
    probe_attestation: ProbeScenario[]
}

const BASE = 'https://node.example'
const BUNDLE = '{"mode":"dstack-tdx","generated_at":"2026-10-01T00:00:00Z","refresh_seconds":1200}'

// The advertisement as discovery parses it off the details, zero time and all.
function advertisedOf(v: unknown): TEEAdvertisement | undefined {
    return parseOperatorDetails({ models: [], tee: v ?? undefined })?.tee
}

function stubVerifier(verdict: Verdict) {
    const calls: { advertised: TEEAdvertisement; bundle: TEEEvidenceBundle; node: Node; signal?: AbortSignal }[] = []
    const verifier: Verifier = {
        verify: async (advertised, bundle, node, signal) => {
            calls.push({ advertised, bundle, node, ...(signal !== undefined && { signal }) })
            return verdict
        },
    }
    return { verifier, calls }
}

function answering(status: number, body: string) {
    const seen: { url: string; init: RequestInit }[] = []
    const fetch = (async (url: string, init: RequestInit) => {
        seen.push({ url, init })
        return new Response(body, { status })
    }) as typeof globalThis.fetch
    return { fetch, seen }
}

// A fetch that never answers, rejecting when its signal fires, as fetch does.
const hangs = (async (_url: string, init: RequestInit) =>
    new Promise<Response>((_, reject) => {
        init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })
    })) as typeof globalThis.fetch

// p, or a rejection naming the wait if p takes longer than ms.
function within<T>(p: Promise<T>, ms: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const late = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`still pending after ${ms}ms`)), ms)
    })
    return Promise.race([p, late]).finally(() => clearTimeout(timer))
}

const hop: RelayHop = {
    baseUrl: 'https://relay.example',
    targetId: 7,
    targetNodeId: 2,
    relayId: 9,
    relayNodeId: 1,
    relayProtoVersion: '9.10',
}

describe('probe_attestation vectors', () => {
    it('covers every scenario', () => expect(vectors.probe_attestation.length).toBeGreaterThan(0))
    it.each(vectors.probe_attestation.map((s) => [s.name, s] as const))('%s', async (_name, sc) => {
        const { fetch, seen } = answering(sc.endpoint_status, sc.endpoint_body)
        const stub =
            sc.verdict === null
                ? undefined
                : stubVerifier({
                      pass: sc.verdict.pass,
                      failureTag: sc.verdict.failure_tag,
                      verifierId: sc.verdict.verifier_id,
                      attestedAt: sc.verdict.attested_at_ms,
                      ...(sc.verdict.attested_model_ids !== null && { attestedModelIds: sc.verdict.attested_model_ids }),
                      ...(sc.verdict.measurement_checks !== null && {
                          detail: {
                              measurementChecks: {
                                  osImage: sc.verdict.measurement_checks.os_image,
                                  composeRelease: sc.verdict.measurement_checks.compose_release,
                                  composeHash: sc.verdict.measurement_checks.compose_hash,
                              },
                          },
                      }),
                  })
        const advertised =
            sc.advertised === null
                ? null
                : { ...sc.advertised, evidence_url: sc.advertised.evidence_url?.replace('{base}', BASE) }
        const got = await probeAttestation({
            operator: {
                id: sc.operator_id,
                nodeId: sc.node_id,
                baseUrl: BASE,
                ephemeralRecipient: sc.ephemeral_recipient === '' ? undefined : sc.ephemeral_recipient,
            },
            advertised: advertisedOf(advertised),
            verifier: stub?.verifier,
            ...(sc.relayed && {
                hop: { baseUrl: BASE, targetId: sc.operator_id, targetNodeId: sc.node_id, relayId: 9, relayNodeId: 1, relayProtoVersion: '9.10' },
            }),
            fetch,
        })

        const requests = seen.map((s) => {
            const h = (s.init.headers ?? {}) as Record<string, string>
            return [s.init.method, new URL(s.url).pathname, h[RELAY_PATH_HEADER] ?? '', h[RELAY_TARGET_HEADER] ?? '']
        })
        expect(requests).toEqual(
            sc.request_path === '' ? [] : [[sc.request_method, sc.request_path, sc.request_relay_path, sc.request_relay_target]],
        )
        const node = stub?.calls[0]?.node
        expect(
            node === undefined
                ? null
                : { operatorId: Number(node.operatorId), nodeId: Number(node.nodeId), ephemeralRecipientPubkey: node.ephemeralRecipientPubkey },
        ).toEqual(sc.verified_node)
        // detail is display data Go does not carry; the checks it held are
        // compared through osImageChecked and composeReleaseChecked.
        const status = got === undefined ? null : (({ detail: _d, ...rest }) => rest)(got)
        expect(status === null ? null : { ...status, attestedModelIds: status.attestedModelIds ?? null }).toStrictEqual(sc.want)
        expect(isTeeAttested({ tee: got })).toBe(sc.attested)
    })
})

describe('probeAttestation', () => {
    const operator = { id: 7, nodeId: 2, baseUrl: BASE, ephemeralRecipient: 'age1recipient' }
    const advertised: TEEAdvertisement = { mode: 'dstack-tdx' }
    const PASS: Verdict = { pass: true, failureTag: '', verifierId: 'dstack-tdx', attestedAt: 1 }

    it('hands the verifier the decoded bundle, the advertisement and the caller signal', async () => {
        const { fetch } = answering(200, BUNDLE)
        const { verifier, calls } = stubVerifier(PASS)
        const ac = new AbortController()
        await probeAttestation({ operator, advertised, verifier, fetch, signal: ac.signal })
        expect(calls[0]!.bundle.generated_at).toBe('2026-10-01T00:00:00Z')
        expect(calls[0]!.bundle.refresh_seconds).toBe(1200)
        expect(calls[0]!.advertised).toBe(advertised)
        expect(calls[0]!.signal).toBe(ac.signal)
    })

    it('probes through the hop the details probe used', async () => {
        const { fetch, seen } = answering(200, BUNDLE)
        await probeAttestation({ operator, advertised, verifier: stubVerifier(PASS).verifier, fetch, hop })
        expect(seen[0]!.url).toBe(hop.baseUrl + RELAY_PATH)
    })

    it('carries the verdict detail for display', async () => {
        const detail = { measurementChecks: { osImage: true, composeRelease: true, composeHash: false } }
        const { verifier } = stubVerifier({ ...PASS, detail })
        const got = await probeAttestation({ operator, advertised, verifier, fetch: answering(200, BUNDLE).fetch })
        expect(got?.detail).toBe(detail)
    })

    it('warns about a pass that routing will not count as attested, and not about one it will', async () => {
        const warn = vi.fn()
        const log = { debug() {}, info() {}, warn, error() {} }
        const fetch = answering(200, BUNDLE).fetch
        const both = { detail: { measurementChecks: { osImage: true, composeRelease: true, composeHash: false } } }
        await probeAttestation({ operator, advertised, verifier: stubVerifier({ ...PASS, ...both }).verifier, fetch, log })
        expect(warn).not.toHaveBeenCalled()
        await probeAttestation({ operator, advertised, verifier: stubVerifier(PASS).verifier, fetch, log })
        expect(warn.mock.calls[0]![0]).toBe('operator attestation passed but is not attested for routing')
        expect(warn.mock.calls[0]![1]).toMatchObject({ os_image_checked: false, compose_release_checked: false })
        // The release check alone is not enough either.
        const releaseOnly = { detail: { measurementChecks: { osImage: false, composeRelease: true, composeHash: false } } }
        await probeAttestation({ operator, advertised, verifier: stubVerifier({ ...PASS, ...releaseOnly }).verifier, fetch, log })
        expect(warn).toHaveBeenCalledTimes(2)
        expect(warn.mock.calls[1]![0]).toBe('operator attestation passed but is not attested for routing')
        expect(warn.mock.calls[1]![1]).toMatchObject({ os_image_checked: false, compose_release_checked: true })
    })

    it("reports no time for Go's zero time, which a node with no bundle advertises", async () => {
        const zero: TEEAdvertisement = { mode: 'dstack-tdx', attested_at: '0001-01-01T00:00:00Z' }
        const got = await probeAttestation({ operator, advertised: zero, verifier: stubVerifier(PASS).verifier, fetch: answering(500, '').fetch })
        expect(got?.attestedAt).toBe(0)
    })

    // The verifier answers an abort with a failing verdict (the chain step
    // reads it as an unreachable PCS); a host storing that would de-route the
    // node for an abort it caused.
    it('rethrows a caller abort during verification rather than a failing status', async () => {
        const ac = new AbortController()
        const reason = new Error('caller left')
        const warn = vi.fn()
        const verifier: Verifier = {
            verify: async () => {
                ac.abort(reason)
                return { pass: false, failureTag: 'collateral_unreachable', verifierId: 'dstack-tdx', attestedAt: 1 }
            },
        }
        const probe = probeAttestation({
            operator,
            advertised,
            verifier,
            fetch: answering(200, BUNDLE).fetch,
            signal: ac.signal,
            log: { debug() {}, info() {}, warn, error() {} },
        })
        await expect(probe).rejects.toBe(reason)
        expect(warn).not.toHaveBeenCalled()
    })

    it('bounds the fetch with the registry timeout it is given', async () => {
        const got = await within(
            probeAttestation({ operator, advertised, verifier: stubVerifier(PASS).verifier, fetch: hangs, timeoutMs: 20 }),
            500,
        )
        expect(got?.failureTag).toBe('fetch_failed')
    })

    it('hands the caller signal to the fetch, so an abort stops a hung one', async () => {
        const ac = new AbortController()
        const reason = new Error('caller left')
        setTimeout(() => ac.abort(reason), 10)
        const probe = probeAttestation({
            operator,
            advertised,
            verifier: stubVerifier(PASS).verifier,
            fetch: hangs,
            timeoutMs: 60_000,
            signal: ac.signal,
        })
        await expect(within(probe, 500)).rejects.toBe(reason)
    })

    it('rethrows the caller abort rather than recording fetch_failed', async () => {
        const ac = new AbortController()
        const reason = new Error('caller left')
        const fetch = (async () => {
            ac.abort(reason)
            throw new TypeError('aborted')
        }) as typeof globalThis.fetch
        const { verifier, calls } = stubVerifier(PASS)
        await expect(probeAttestation({ operator, advertised, verifier, fetch, signal: ac.signal })).rejects.toBe(reason)
        expect(calls).toHaveLength(0)
    })

    it('logs a failed fetch and a failed verdict, with no bundle content', async () => {
        const warn = vi.fn()
        const log = { debug() {}, info() {}, warn, error() {} }
        await probeAttestation({ operator, advertised, verifier: stubVerifier(PASS).verifier, fetch: answering(500, '').fetch, log })
        expect(warn.mock.calls[0]![0]).toBe('operator attestation probe failed')
        expect(warn.mock.calls[0]![1]).toMatchObject({ operator_id: 7, node_id: 2, mode: 'dstack-tdx' })
        const fail: Verdict = { pass: false, failureTag: 'measurement_mismatch', verifierId: 'dstack-tdx', attestedAt: 1 }
        await probeAttestation({ operator, advertised, verifier: stubVerifier(fail).verifier, fetch: answering(200, BUNDLE).fetch, log, hop })
        expect(warn.mock.calls[1]![0]).toBe('operator attestation verification failed')
        expect(warn.mock.calls[1]![1]).toEqual({
            operator_id: 7,
            node_id: 2,
            relay_operator_id: 9,
            relay_node_id: 1,
            mode: 'dstack-tdx',
            failure_tag: 'measurement_mismatch',
        })
    })
})

describe('fetchAttestation', () => {
    it('asks for JSON, never from an HTTP cache', async () => {
        const { fetch, seen } = answering(200, BUNDLE)
        await fetchAttestation({ baseUrl: BASE, fetch })
        expect(seen[0]!.url).toBe(BASE + ATTESTATION_PATH)
        expect(seen[0]!.init.method).toBe('GET')
        expect((seen[0]!.init.headers as Record<string, string>).Accept).toBe('application/json')
        expect(seen[0]!.init.cache).toBe('no-store')
    })

    // A relay forwards only the standard path, as Go's ApplyRelay.
    it('relays to the standard path whatever evidence URL was advertised', async () => {
        const { fetch, seen } = answering(200, BUNDLE)
        await fetchAttestation({ baseUrl: BASE, evidenceUrl: 'https://elsewhere.example/evidence', hop, fetch })
        const headers = seen[0]!.init.headers as Record<string, string>
        expect(seen[0]!.url).toBe(hop.baseUrl + RELAY_PATH)
        expect(seen[0]!.init.method).toBe('POST')
        expect(headers[RELAY_PATH_HEADER]).toBe(ATTESTATION_PATH)
        expect(headers[RELAY_TARGET_HEADER]).toBe('7')
    })

    it('reads at most 256 KiB, so a longer body fails to decode', async () => {
        const padded = BUNDLE.slice(0, -1) + `,"gpu_eat":"${'x'.repeat(256 << 10)}"}`
        await expect(fetchAttestation({ baseUrl: BASE, fetch: answering(200, padded).fetch })).rejects.toBeInstanceOf(
            AttestationFetchError,
        )
        const fits = BUNDLE.slice(0, -1) + `,"gpu_eat":"${'x'.repeat((256 << 10) - BUNDLE.length - 20)}"}`
        expect((await fetchAttestation({ baseUrl: BASE, fetch: answering(200, fits).fetch })).mode).toBe('dstack-tdx')
    })

    // 400 is the first status Go treats as an error.
    it.each([400, 404])('reports a %d with its status, without decoding the body', async (status) => {
        const err: unknown = await fetchAttestation({ baseUrl: BASE, fetch: answering(status, BUNDLE).fetch }).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(AttestationFetchError)
        expect((err as AttestationFetchError).status).toBe(status)
    })

    // An unread body holds its connection until it is collected.
    it('releases the body of an error status', async () => {
        const cancel = vi.fn()
        const body = new ReadableStream<Uint8Array>({ cancel })
        const fetch = (async () => new Response(body, { status: 500 })) as typeof globalThis.fetch
        await expect(fetchAttestation({ baseUrl: BASE, fetch })).rejects.toBeInstanceOf(AttestationFetchError)
        expect(cancel).toHaveBeenCalled()
    })

    it('decodes the body of any status below 400, as Go does', async () => {
        expect((await fetchAttestation({ baseUrl: BASE, fetch: answering(203, BUNDLE).fetch })).mode).toBe('dstack-tdx')
    })

    // Both well under the 2s default, so only the caller's own bound can end them in time.
    it('bounds the fetch with the deadline it is given', async () => {
        await expect(within(fetchAttestation({ baseUrl: BASE, fetch: hangs, timeoutMs: 20 }), 500)).rejects.toBeInstanceOf(
            AttestationFetchError,
        )
    })

    it('stops a hung fetch when the caller aborts, and rethrows the reason', async () => {
        const ac = new AbortController()
        const reason = new Error('caller left')
        setTimeout(() => ac.abort(reason), 10)
        await expect(within(fetchAttestation({ baseUrl: BASE, fetch: hangs, timeoutMs: 60_000, signal: ac.signal }), 500)).rejects.toBe(reason)
    })

    it('rethrows the caller abort when the request or the body read fails after it', async () => {
        const ac = new AbortController()
        const reason = new Error('caller left')
        ac.abort(reason)
        const throws = (async () => {
            throw new TypeError('aborted')
        }) as typeof globalThis.fetch
        await expect(fetchAttestation({ baseUrl: BASE, fetch: throws, signal: ac.signal })).rejects.toBe(reason)

        const late = new AbortController()
        const body = new ReadableStream<Uint8Array>({
            pull(c) {
                late.abort(reason)
                c.error(new TypeError('body stream aborted'))
            },
        })
        const midBody = (async () => new Response(body, { status: 200 })) as typeof globalThis.fetch
        await expect(fetchAttestation({ baseUrl: BASE, fetch: midBody, signal: late.signal })).rejects.toBe(reason)
    })

    it('refuses an empty base URL', async () => {
        const { fetch, seen } = answering(200, BUNDLE)
        await expect(fetchAttestation({ baseUrl: '/', fetch })).rejects.toBeInstanceOf(AttestationFetchError)
        expect(seen).toHaveLength(0)
    })
})

describe('joinAttestationUrl', () => {
    it.each([
        ['', `${BASE}/v1/zs/attestation`],
        ['/custom', `${BASE}/custom`],
        ['custom', `${BASE}/custom`],
        ['https://tls.example/evidence', 'https://tls.example/evidence'],
        ['http://plain.example/evidence', 'http://plain.example/evidence'],
        // Only http(s) is absolute, so a node cannot steer the probe to another scheme.
        ['file:///etc/passwd', `${BASE}/file:///etc/passwd`],
        ['javascript:alert(1)', `${BASE}/javascript:alert(1)`],
    ])('joins %j onto the base', (evidence, want) => {
        expect(joinAttestationUrl(`${BASE}//`, evidence)).toBe(want)
    })
})
