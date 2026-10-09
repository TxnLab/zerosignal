/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest'
import { RelayErrorCode } from '@txnlab/zs-proto/relay'
import {
    RELAY_HOP_HEADER,
    RELAY_PATH,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
} from '@txnlab/zs-proto/wire'

import {
    DEFAULT_DETAILS_TIMEOUT_MS,
    DETAILS_PATH,
    DetailsBodyError,
    DetailsHTTPError,
    type DetailsProbeStores,
    DetailsTransportError,
    MAX_DISCOVERY_RELAY_ATTEMPTS,
    RelayHopError,
    RelayUpstreamUnreachableError,
    detailsQuery,
    fetchDetails,
    probeDetails,
} from '../src/details.js'
import type { RelayHop } from '../src/routing/index.js'
import type { NodeRef } from '../src/types.js'

const BASE = 'https://node.example/'
const TARGET: NodeRef = { op: 7, node: 1 }
const DETAILS = { models: [{ id: 'm', input_rate_usd_per_1m: 1, output_rate_usd_per_1m: 2 }], oracle_healthy: true }

function hop(relayId: number, relayProtoVersion = '9.1'): RelayHop {
    return {
        baseUrl: `https://relay${relayId}.example`,
        targetId: TARGET.op,
        targetNodeId: TARGET.node,
        relayId,
        relayNodeId: 0,
        relayProtoVersion,
    }
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json', ...headers },
    })
}

function relayError(status: number, code: string, headers: Record<string, string> = {}): Response {
    return json(status, { error: { type: 'proxy_error', code, message: 'm' } }, headers)
}

interface Seen {
    url: string
    init: RequestInit
}

// A fetch answering by the URL it is sent to, recording each request.
function fetchBy(answer: (url: string, init: RequestInit) => Response | Promise<Response>) {
    const seen: Seen[] = []
    const fetch = (async (url: string, init: RequestInit) => {
        seen.push({ url, init })
        return answer(url, init)
    }) as typeof globalThis.fetch
    return { fetch, seen }
}

// A fetch that never answers, rejecting when its signal fires, as fetch does.
const hangs = (async (_url: string, init: RequestInit) =>
    new Promise<Response>((_, reject) => {
        init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })
    })) as typeof globalThis.fetch

// A fetch whose response sends its status and part of a body, then stalls,
// failing the body read when the request's signal fires, as fetch does.
function stallsMidBody(status: number, partial: string): typeof globalThis.fetch {
    return (async (_url: string, init: RequestInit) => {
        const body = new ReadableStream<Uint8Array>({
            start(ctl) {
                ctl.enqueue(new TextEncoder().encode(partial))
                init.signal!.addEventListener('abort', () => ctl.error(init.signal!.reason), { once: true })
            },
        })
        return new Response(body, { status, headers: { 'Content-Type': 'application/json' } })
    }) as typeof globalThis.fetch
}

// A response whose body sends part, then fails, with no signal involved: a
// connection reset mid-body.
function breaksMidBody(status: number, partial: string): Response {
    const body = new ReadableStream<Uint8Array>({
        start(ctl) {
            ctl.enqueue(new TextEncoder().encode(partial))
            ctl.error(new TypeError('network error'))
        },
    })
    return new Response(body, { status, headers: { 'Content-Type': 'application/json' } })
}

describe('detailsQuery', () => {
    it('is empty for the lean probe and escapes a model id', () => {
        expect(detailsQuery()).toBe('')
        expect(detailsQuery(undefined, [])).toBe('')
        expect(detailsQuery('Qwen/Qwen2.5-7B', ['coordinates', 'digest'])).toBe(
            '?model=Qwen%2FQwen2.5-7B&expand=coordinates%2Cdigest',
        )
        expect(detailsQuery(undefined, ['digest'])).toBe('?expand=digest')
    })
})

describe('fetchDetails', () => {
    it('GETs the details route directly and parses the advertisement', async () => {
        const { fetch, seen } = fetchBy(() => json(200, DETAILS))
        const got = await fetchDetails({ baseUrl: BASE, fetch })
        expect(got.models.map((m) => m.id)).toEqual(['m'])
        expect(seen).toHaveLength(1)
        expect(seen[0]!.url).toBe(`https://node.example${DETAILS_PATH}`)
        expect(seen[0]!.init.method).toBe('GET')
        expect(seen[0]!.init.headers).toMatchObject({ Accept: 'application/json' })
        // A cached copy would freeze the rotating ephemeral key.
        expect(seen[0]!.init.cache).toBe('no-store')
    })

    // The relay joins the inner path to the target's own base URL, so it is the
    // route alone, and a deep probe keeps its scoping across the hop.
    it('rides a relay with the route and query as the inner path', async () => {
        const { fetch, seen } = fetchBy(() => json(200, DETAILS))
        await fetchDetails({
            baseUrl: 'https://node.example/api/zs',
            hop: hop(3),
            model: 'a/b',
            expand: ['digest'],
            fetch,
        })
        expect(seen[0]!.url).toBe(`https://relay3.example${RELAY_PATH}`)
        expect(seen[0]!.init.method).toBe('POST')
        expect(seen[0]!.init.headers).toMatchObject({
            Accept: 'application/json',
            [RELAY_TARGET_HEADER]: '7',
            [RELAY_TARGET_NODE_HEADER]: '1',
            [RELAY_PATH_HEADER]: `${DETAILS_PATH}?model=a%2Fb&expand=digest`,
        })
    })

    it('puts a deep probe query on the direct URL', async () => {
        const { fetch, seen } = fetchBy(() => json(200, DETAILS))
        await fetchDetails({ baseUrl: BASE, model: 'x', fetch })
        expect(seen[0]!.url).toBe(`https://node.example${DETAILS_PATH}?model=x`)
    })

    it('refuses an empty base URL', async () => {
        const { fetch, seen } = fetchBy(() => json(200, DETAILS))
        await expect(fetchDetails({ baseUrl: '/', fetch })).rejects.toThrow(/empty operator base_url/)
        expect(seen).toHaveLength(0)
    })

    it("bounds the probe at Go's 2s by default, or the caller's own", async () => {
        expect(DEFAULT_DETAILS_TIMEOUT_MS).toBe(2_000)
        const timeout = vi.spyOn(AbortSignal, 'timeout')
        try {
            const { fetch } = fetchBy(() => json(200, DETAILS))
            await fetchDetails({ baseUrl: BASE, fetch })
            expect(timeout).toHaveBeenLastCalledWith(2_000)
            await fetchDetails({ baseUrl: BASE, fetch, timeoutMs: 750 })
            expect(timeout).toHaveBeenLastCalledWith(750)
        } finally {
            timeout.mockRestore()
        }
    })

    describe('direct', () => {
        it('reads no response as a transport error', async () => {
            const { fetch } = fetchBy(() => Promise.reject(new TypeError('fetch failed')))
            const err = await fetchDetails({ baseUrl: BASE, fetch }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(DetailsTransportError)
            expect(err).toMatchObject({ timedOut: false })
        })

        it('marks its own timeout', async () => {
            const err = await fetchDetails({ baseUrl: BASE, fetch: hangs, timeoutMs: 10 }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(DetailsTransportError)
            expect(err).toMatchObject({ timedOut: true })
        })

        // Directly there is no relay to attribute to: a relay_ code is the
        // node's own body.
        it('reads any error status as the target answering', async () => {
            const { fetch } = fetchBy(() => relayError(503, RelayErrorCode.Busy))
            const err = await fetchDetails({ baseUrl: BASE, fetch }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(DetailsHTTPError)
            expect(err).toMatchObject({ status: 503 })
        })
    })

    it("rethrows the caller's abort, directly and through a relay", async () => {
        for (const h of [null, hop(3)]) {
            const ctl = new AbortController()
            const reason = new Error('caller left')
            setTimeout(() => ctl.abort(reason), 5)
            const err = await fetchDetails({ baseUrl: BASE, hop: h, fetch: hangs, signal: ctl.signal }).catch(
                (e: unknown) => e,
            )
            expect(err).toBe(reason)
        }
    })

    describe("a relay's error body cut short", () => {
        // The code is unknown, so neither hop is blamed.
        it('by our deadline reads as a timeout', async () => {
            const err = await fetchDetails({
                baseUrl: BASE,
                hop: hop(3),
                fetch: stallsMidBody(502, '{"error":'),
                timeoutMs: 20,
            }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(RelayHopError)
            expect((err as RelayHopError).timedOut).toBe(true)
        })

        // Neither deadline nor abort: the code is unreadable, so the status decides.
        it('by a broken stream reads as no code', async () => {
            const preFloor = await fetchDetails({
                baseUrl: BASE,
                hop: hop(3, '9.0'),
                fetch: async () => breaksMidBody(503, '{"error":'),
            }).catch((e: unknown) => e)
            expect(preFloor).toBeInstanceOf(DetailsHTTPError)
            const marking = await fetchDetails({
                baseUrl: BASE,
                hop: hop(3),
                fetch: async () => breaksMidBody(503, '{"error":'),
            }).catch((e: unknown) => e)
            expect(marking).toBeInstanceOf(RelayHopError)
        })

        it("by the caller's abort rethrows it", async () => {
            const ctl = new AbortController()
            const reason = new Error('caller left')
            setTimeout(() => ctl.abort(reason), 5)
            const err = await fetchDetails({
                baseUrl: BASE,
                hop: hop(3),
                fetch: stallsMidBody(502, '{"error":'),
                signal: ctl.signal,
            }).catch((e: unknown) => e)
            expect(err).toBe(reason)
        })
    })

    describe('through a relay', () => {
        it('reads no response as the relay unreachable', async () => {
            const { fetch } = fetchBy(() => Promise.reject(new TypeError('fetch failed')))
            const err = await fetchDetails({ baseUrl: BASE, hop: hop(3), fetch }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(RelayHopError)
            expect(err).toMatchObject({ relay: { op: 3, node: 0 }, relayUrl: 'https://relay3.example' })
            expect(err).toMatchObject({ transport: true, timedOut: false })
        })

        // The relay is silent while it waits on a slow target, so a timeout is
        // neither a dead endpoint nor the relay's fault.
        it('marks its own timeout and not as a dead endpoint', async () => {
            const err = await fetchDetails({ baseUrl: BASE, hop: hop(3), fetch: hangs, timeoutMs: 10 }).catch(
                (e: unknown) => e,
            )
            expect(err).toBeInstanceOf(RelayHopError)
            expect(err).toMatchObject({ transport: false, timedOut: true })
        })

        type Want = 'hop' | 'upstream' | 'target'
        const rows: Array<[string, () => Response, string, Want]> = [
            ['relay_busy', () => relayError(503, RelayErrorCode.Busy), '9.1', 'hop'],
            ['relay_unknown_target', () => relayError(404, RelayErrorCode.UnknownTarget), '', 'hop'],
            ['relay_bad_method', () => relayError(400, RelayErrorCode.BadMethod), '', 'hop'],
            ['relay_build_request', () => relayError(502, RelayErrorCode.BuildRequest), '', 'hop'],
            ['relay_upstream_unreachable', () => relayError(502, RelayErrorCode.UpstreamUnreachable), '', 'upstream'],
            // The relay's handler wrote the code, so it wins over a missing marker.
            [
                'relay_upstream_unreachable unmarked from a marking relay',
                () => relayError(502, RelayErrorCode.UpstreamUnreachable),
                '9.1',
                'upstream',
            ],
            ['unmarked 502 from a marking relay', () => new Response('<html>', { status: 502 }), '9.1', 'hop'],
            ['unmarked 521 from a marking relay', () => new Response('', { status: 521 }), '9.1', 'hop'],
            // An empty marker is no marker, as in Go.
            [
                'empty-marked 503 from a marking relay',
                () => new Response('', { status: 503, headers: { [RELAY_HOP_HEADER]: '' } }),
                '9.1',
                'hop',
            ],
            // Status first: a front door's own coded answer is still the front door.
            ['unmarked coded 429 from a marking relay', () => relayError(429, 'rate_limited'), '9.1', 'hop'],
            [
                'marked 502: the relay forwarded the target answer',
                () => new Response('', { status: 502, headers: { [RELAY_HOP_HEADER]: '1' } }),
                '9.1',
                'target',
            ],
            // A timeout status is ambiguous: the relay may have been waiting on the target.
            ['unmarked 504 from a marking relay', () => new Response('', { status: 504 }), '9.1', 'target'],
            ['unmarked 524 from a marking relay', () => new Response('', { status: 524 }), '9.1', 'target'],
            // A relay that owes no marker proves nothing by its absence.
            ['unmarked 502 from a pre-marker relay', () => new Response('', { status: 502 }), '9.0', 'target'],
            ['unmarked 502 from an unprobed relay', () => new Response('', { status: 502 }), '', 'target'],
            ['unmarked 404 from a marking relay', () => new Response('', { status: 404 }), '9.1', 'target'],
            ["the target's own coded error", () => relayError(400, 'bad_request'), '9.1', 'target'],
        ]
        for (const [name, answer, version, want] of rows) {
            it(`reads ${name} as ${want}`, async () => {
                const { fetch } = fetchBy(answer)
                const status = answer().status
                const err = await fetchDetails({ baseUrl: BASE, hop: hop(3, version), fetch }).catch(
                    (e: unknown) => e,
                )
                if (want === 'hop') {
                    expect(err).toBeInstanceOf(RelayHopError)
                    expect(err).toMatchObject({ relay: { op: 3, node: 0 }, transport: false, timedOut: false })
                } else if (want === 'upstream') {
                    expect(err).toBeInstanceOf(RelayUpstreamUnreachableError)
                    expect(err).toMatchObject({ relay: { op: 3, node: 0 }, status })
                } else {
                    expect(err).toBeInstanceOf(DetailsHTTPError)
                    expect(err).toMatchObject({ status })
                }
            })
        }
    })

    describe('a 2xx body', () => {
        for (const [name, body] of [
            ['not JSON', 'not json'],
            ['a JSON array', '[]'],
            ['JSON null', 'null'],
            ['empty', ''],
        ] as const) {
            it(`reads ${name} as a body error`, async () => {
                const { fetch } = fetchBy(() => new Response(body, { status: 200 }))
                await expect(fetchDetails({ baseUrl: BASE, fetch })).rejects.toBeInstanceOf(DetailsBodyError)
            })
        }

        // A deadline mid-body is a slow read, not a body the target got wrong:
        // a body error would credit the relay and show the target up but broken.
        it('reads a deadline mid-body as a timeout, directly and through a relay', async () => {
            const fetch = stallsMidBody(200, '{"models":[')
            const direct = await fetchDetails({ baseUrl: BASE, fetch, timeoutMs: 20 }).catch((e: unknown) => e)
            expect(direct).toBeInstanceOf(DetailsTransportError)
            expect((direct as DetailsTransportError).timedOut).toBe(true)
            const relayed = await fetchDetails({ baseUrl: BASE, hop: hop(3), fetch, timeoutMs: 20 }).catch(
                (e: unknown) => e,
            )
            expect(relayed).toBeInstanceOf(RelayHopError)
            expect((relayed as RelayHopError).timedOut).toBe(true)
        })

        it("rethrows the caller's abort mid-body", async () => {
            const ctl = new AbortController()
            const reason = new Error('caller left')
            setTimeout(() => ctl.abort(reason), 5)
            const err = await fetchDetails({
                baseUrl: BASE,
                hop: hop(3),
                fetch: stallsMidBody(200, '{"models":['),
                signal: ctl.signal,
            }).catch((e: unknown) => e)
            expect(err).toBe(reason)
        })

        it('reads at most 256 KiB, so a longer body fails to decode', async () => {
            const pad = 'x'.repeat(256 << 10)
            const { fetch } = fetchBy(() => new Response(JSON.stringify({ ...DETAILS, pad }), { status: 200 }))
            await expect(fetchDetails({ baseUrl: BASE, fetch })).rejects.toBeInstanceOf(DetailsBodyError)
            const fits = fetchBy(() => new Response(JSON.stringify({ ...DETAILS, pad: pad.slice(0, 1000) })))
            await expect(fetchDetails({ baseUrl: BASE, fetch: fits.fetch })).resolves.toMatchObject({
                oracle_healthy: true,
            })
        })
    })
})

// Records every store call in order, as "method:args".
function fakeStores(): { stores: DetailsProbeStores; calls: string[] } {
    const calls: string[] = []
    const ref = (r: NodeRef) => `${r.op}/${r.node}`
    const stores: DetailsProbeStores = {
        health: {
            markRelayUnreachable: (r) => void calls.push(`unreachable:${ref(r)}`),
            markRelayReachable: (r) => void calls.push(`reachable:${ref(r)}`),
            recordRelayTransportFailure: (r) => void calls.push(`transport:${ref(r)}`),
        },
        reputation: {
            recordRelayOutcome: (r, ok) => void calls.push(`outcome:${ref(r)}:${ok}`),
            recordRelayUpstreamUnreachable: (r, t) => void calls.push(`upstream:${ref(r)}:${ref(t)}`),
        },
        latency: {
            recordRelayedRtt: (r, t, ms) => void calls.push(`relayedRtt:${ref(r)}:${ref(t)}:${ms}`),
            recordDirectRtt: (t, ms) => void calls.push(`directRtt:${ref(t)}:${ms}`),
        },
    }
    return { stores, calls }
}

// A clock that advances 40ms per reading, so a round trip reads as 40ms.
function steppingClock(): () => number {
    let t = 1_000
    return () => (t += 40)
}

// Answers per relay id; any relay not listed returns the details.
function relays(answers: Record<number, () => Response | Promise<Response>>) {
    return fetchBy((url) => {
        const m = /^https:\/\/relay(\d+)\.example/.exec(url)
        const answer = m ? answers[Number(m[1])] : undefined
        return answer ? answer() : json(200, DETAILS)
    })
}

// Offers each listed relay in turn that isn't excluded, recording the
// excluded set it was handed.
function nextFrom(ids: number[]) {
    const handed: string[][] = []
    const next = (excluded: ReadonlySet<string>) => {
        handed.push([...excluded])
        const id = ids.find((i) => !excluded.has(`${i}/0`))
        return id === undefined ? null : hop(id)
    }
    return { next, handed }
}

describe('probeDetails', () => {
    it('probes directly once and records the direct round trip', async () => {
        const { stores, calls } = fakeStores()
        const { fetch, seen } = fetchBy(() => json(200, DETAILS))
        const got = await probeDetails({ baseUrl: BASE, target: TARGET, hop: null, stores, fetch, clock: steppingClock() })
        expect(got.hop).toBeNull()
        expect(got.details.models).toHaveLength(1)
        expect(seen).toHaveLength(1)
        expect(calls).toEqual(['directRtt:7/1:40'])
    })

    it("hands a direct failure back as fetchDetails' error, recording nothing", async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = fetchBy(() => new Response('', { status: 404 }))
        await expect(probeDetails({ baseUrl: BASE, target: TARGET, hop: null, stores, fetch })).rejects.toBeInstanceOf(
            DetailsHTTPError,
        )
        expect(calls).toEqual([])
    })

    it('credits the relay that carried it and records the relayed round trip', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({})
        const got = await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            stores,
            fetch,
            clock: steppingClock(),
        })
        expect(got.hop?.relayId).toBe(3)
        expect(calls).toEqual(['reachable:3/0', 'outcome:3/0:true', 'relayedRtt:3/0:7/1:40'])
    })

    it('parks a relay it could not reach and rotates past it', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({ 3: () => Promise.reject(new TypeError('fetch failed')) })
        const { next, handed } = nextFrom([3, 4])
        const got = await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            nextHop: next,
            stores,
            fetch,
            clock: steppingClock(),
        })
        expect(got.hop?.relayId).toBe(4)
        expect(handed).toEqual([['3/0']])
        expect(calls).toEqual(['transport:3/0', 'reachable:4/0', 'outcome:4/0:true', 'relayedRtt:4/0:7/1:40'])
    })

    it('marks a relay that failed the hop and charges it a strike', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({ 3: () => relayError(503, RelayErrorCode.Busy) })
        const { next } = nextFrom([4])
        await probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), nextHop: next, stores, fetch })
        expect(calls.slice(0, 2)).toEqual(['unreachable:3/0', 'outcome:3/0:false'])
    })

    it('charges nothing for its own timeout, yet tries another relay', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = fetchBy((url, init) => (url.includes('relay3') ? hangs(url, init) : json(200, DETAILS)))
        const { next } = nextFrom([4])
        const got = await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            nextHop: next,
            stores,
            fetch,
            timeoutMs: 20,
        })
        expect(got.hop?.relayId).toBe(4)
        expect(calls.filter((c) => c.includes('3/0'))).toEqual([])
    })

    it("tries another relay past an upstream claim, and charges the claim that relay disproves", async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({ 3: () => relayError(502, RelayErrorCode.UpstreamUnreachable) })
        const { next } = nextFrom([4])
        const got = await probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), nextHop: next, stores, fetch })
        expect(got.hop?.relayId).toBe(4)
        expect(calls.filter((c) => c.includes('3/0'))).toEqual(['outcome:3/0:false'])
    })

    it("charges a claim the target's own error status disproves", async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({
            3: () => relayError(502, RelayErrorCode.UpstreamUnreachable),
            4: () => new Response('', { status: 404 }),
        })
        const { next } = nextFrom([4])
        await expect(
            probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), nextHop: next, stores, fetch }),
        ).rejects.toBeInstanceOf(DetailsHTTPError)
        expect(calls).toEqual(['outcome:3/0:false'])
    })

    it('judges a lone claim no other relay could check by our last view of the target', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({
            3: () => relayError(502, RelayErrorCode.UpstreamUnreachable),
            4: () => Promise.reject(new TypeError('fetch failed')),
        })
        const { next } = nextFrom([4])
        await probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), nextHop: next, stores, fetch }).catch(
            () => undefined,
        )
        expect(calls.filter((c) => c.includes('3/0'))).toEqual(['upstream:3/0:7/1'])
    })

    it('credits relays that agree the target is down, and gives up with the last claim', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({
            3: () => relayError(502, RelayErrorCode.UpstreamUnreachable),
            4: () => relayError(502, RelayErrorCode.UpstreamUnreachable),
        })
        const { next } = nextFrom([4])
        const err = (await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            nextHop: next,
            stores,
            fetch,
        }).catch((e: unknown) => e)) as RelayUpstreamUnreachableError
        expect(err).toBeInstanceOf(RelayUpstreamUnreachableError)
        expect(err.relay).toEqual({ op: 4, node: 0 })
        expect(calls).toEqual(['outcome:3/0:true', 'outcome:4/0:true'])
    })

    it('gives up with the target down when every relay that worked said so', async () => {
        for (const order of [
            [3, 4],
            [4, 3],
        ]) {
            const { stores } = fakeStores()
            const { fetch } = relays({
                3: () => relayError(502, RelayErrorCode.UpstreamUnreachable),
                4: () => Promise.reject(new TypeError('fetch failed')),
            })
            const { next } = nextFrom(order)
            const err = (await probeDetails({
                baseUrl: BASE,
                target: TARGET,
                hop: hop(order[0]!),
                nextHop: next,
                stores,
                fetch,
            }).catch((e: unknown) => e)) as RelayUpstreamUnreachableError
            expect(err).toBeInstanceOf(RelayUpstreamUnreachableError)
            expect(err.relay).toEqual({ op: 3, node: 0 })
            expect(err.attempts?.map((a) => `${a.relay.op}:${a.reason}`)).toEqual(
                order.map((id) => (id === 3 ? '3:upstream-unreachable' : '4:unreachable')),
            )
        }
    })

    it('gives up with the last hop error when no relay reached the target', async () => {
        const { stores } = fakeStores()
        const { fetch } = relays({
            3: () => Promise.reject(new TypeError('fetch failed')),
            4: () => relayError(503, RelayErrorCode.Busy),
        })
        const { next } = nextFrom([3, 4])
        const err = (await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            nextHop: next,
            stores,
            fetch,
        }).catch((e: unknown) => e)) as RelayHopError
        expect(err).toBeInstanceOf(RelayHopError)
        expect(err.relay).toEqual({ op: 4, node: 0 })
        expect(err.attempts).toEqual([
            { relay: { op: 3, node: 0 }, relayUrl: 'https://relay3.example', reason: 'unreachable' },
            { relay: { op: 4, node: 0 }, relayUrl: 'https://relay4.example', reason: 'hop' },
        ])
    })

    it('records a relay its own deadline cut off as a timeout', async () => {
        const { stores } = fakeStores()
        const err = (await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            stores,
            fetch: hangs,
            timeoutMs: 10,
        }).catch((e: unknown) => e)) as RelayHopError
        expect(err.attempts).toEqual([
            { relay: { op: 3, node: 0 }, relayUrl: 'https://relay3.example', reason: 'timeout' },
        ])
    })

    it(`tries at most ${MAX_DISCOVERY_RELAY_ATTEMPTS} relays, or the caller's bound`, async () => {
        for (const [max, want] of [
            [undefined, MAX_DISCOVERY_RELAY_ATTEMPTS],
            [1, 1],
            [0, 1],
            [-1, 1],
            [Number.NaN, 1],
        ] as const) {
            const { stores } = fakeStores()
            const { fetch, seen } = fetchBy(() => relayError(503, RelayErrorCode.Busy))
            let n = 10
            let picks = 0
            const err = await probeDetails({
                baseUrl: BASE,
                target: TARGET,
                hop: hop(n),
                nextHop: () => (picks++, hop(++n)),
                stores,
                fetch,
                ...(max !== undefined ? { maxRelayAttempts: max } : {}),
            }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(RelayHopError)
            expect(seen).toHaveLength(want)
            // No relay is picked, or a retry logged, after the last attempt.
            expect(picks).toBe(want - 1)
        }
    })

    it('ends with the first failure when there is no other relay to try', async () => {
        const { stores } = fakeStores()
        const { fetch, seen } = relays({ 3: () => relayError(503, RelayErrorCode.Busy) })
        await expect(
            probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), stores, fetch }),
        ).rejects.toBeInstanceOf(RelayHopError)
        expect(seen).toHaveLength(1)
    })

    // The relay forwarded the target's 2xx; what the body held is the target's.
    it('credits the relay for a 2xx with a bad body, then fails without rotating', async () => {
        const { stores, calls } = fakeStores()
        const { fetch, seen } = relays({ 3: () => new Response('not json', { status: 200 }) })
        const { next } = nextFrom([4])
        await expect(
            probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), nextHop: next, stores, fetch, clock: steppingClock() }),
        ).rejects.toBeInstanceOf(DetailsBodyError)
        expect(seen).toHaveLength(1)
        expect(calls).toEqual(['reachable:3/0', 'outcome:3/0:true', 'relayedRtt:3/0:7/1:40'])
    })

    it("neither credits nor rotates on the target's own error status", async () => {
        const { stores, calls } = fakeStores()
        const { fetch, seen } = relays({ 3: () => new Response('', { status: 404 }) })
        const { next } = nextFrom([4])
        await expect(
            probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), nextHop: next, stores, fetch }),
        ).rejects.toBeInstanceOf(DetailsHTTPError)
        expect(seen).toHaveLength(1)
        expect(calls).toEqual([])
    })

    // Go scores a claim at its give-up even when cancelled; so must the SDK.
    it("still scores a claim made before the caller's abort", async () => {
        const { stores, calls } = fakeStores()
        const ctl = new AbortController()
        const reason = new Error('caller left')
        setTimeout(() => ctl.abort(reason), 5)
        const { fetch } = fetchBy((url, init) =>
            url.includes('relay3') ? relayError(502, RelayErrorCode.UpstreamUnreachable) : hangs(url, init),
        )
        const { next } = nextFrom([4])
        const err = await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            nextHop: next,
            stores,
            fetch,
            signal: ctl.signal,
        }).catch((e: unknown) => e)
        expect(err).toBe(reason)
        expect(calls).toEqual(['upstream:3/0:7/1'])
    })

    // A body that breaks off (not by our deadline) is still a 2xx the relay forwarded.
    it('credits the relay for a 2xx whose body breaks off', async () => {
        const { stores, calls } = fakeStores()
        const { fetch } = relays({ 3: () => breaksMidBody(200, '{"models":[') })
        await expect(
            probeDetails({ baseUrl: BASE, target: TARGET, hop: hop(3), stores, fetch, clock: steppingClock() }),
        ).rejects.toBeInstanceOf(DetailsBodyError)
        expect(calls).toContain('outcome:3/0:true')
    })

    it("stops on the caller's abort, charging no relay", async () => {
        const { stores, calls } = fakeStores()
        const ctl = new AbortController()
        const reason = new Error('caller left')
        setTimeout(() => ctl.abort(reason), 5)
        const { next } = nextFrom([4])
        const err = await probeDetails({
            baseUrl: BASE,
            target: TARGET,
            hop: hop(3),
            nextHop: next,
            stores,
            fetch: hangs,
            signal: ctl.signal,
        }).catch((e: unknown) => e)
        expect(err).toBe(reason)
        expect(calls).toEqual([])
    })

    it('refuses a hop that names another node', async () => {
        const { stores } = fakeStores()
        const { fetch, seen } = relays({})
        await expect(
            probeDetails({ baseUrl: BASE, target: { op: 7, node: 2 }, hop: hop(3), stores, fetch }),
        ).rejects.toThrow(/names node \(7, 1\), not the probed \(7, 2\)/)
        expect(seen).toHaveLength(0)
    })
})
