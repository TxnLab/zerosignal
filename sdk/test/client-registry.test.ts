/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Client.create building its own registry, as Go's New does, over a fake
// algod (the global fetch the SDK's algod client dials) and a fake fleet (the
// Config.fetch the probes dial): the wiring from Config to discovery, the boot
// it waits for, who stops the registry, and the routing stores the probes and
// the requests share.

import {
    BASE_URL_MAX,
    NODE_RECORD_SIZE,
    OPERATOR_RECORD_SIZE,
    OPERATOR_STATUS_ACTIVE,
    decodeNodeRecord,
    decodeOperatorRecord,
    nodeBoxKey,
    operatorBoxKey,
} from '@txnlab/zs-proto/escrow'
import { ephemeralSigDigest } from '@txnlab/zs-proto/ticket'
import { PROTO_VERSION, RELAY_PATH, RELAY_PATH_HEADER, RELAY_TARGET_HEADER, RELAY_TARGET_NODE_HEADER } from '@txnlab/zs-proto/wire'
import * as ed25519 from '@noble/ed25519'
import { base64, bech32 } from '@scure/base'
import algosdk from 'algosdk'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
    CATALOG_STORAGE_KEY,
    ChainOperatorSource,
    Client,
    type Config,
    DiscoveryRegistry,
    type EscrowChain,
    type Signer,
    Wallet,
    type WalletOpener,
    isTeeAttested,
    memoryJournal,
    memoryStorage,
    resolveNetwork,
    testnet,
} from '../src/index.js'
import { partsOf } from '../src/client-parts.js'
import type { Verifier } from '../src/tee/types.js'
import { testOperator } from './fixtures.js'
import { relayHopForPool, relayPool } from '../src/pick.js'
import { relayRef } from '../src/routing/relay.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import { type NodeRef, nodeRefString } from '../src/types.js'

const APP = resolveNetwork(testnet()).escrowAppId
const T: NodeRef = { op: 1, node: 1 }
const R2: NodeRef = { op: 2, node: 1 }
const R3: NodeRef = { op: 3, node: 1 }
const FLEET = [T, R2, R3]
const host = (r: NodeRef) => `https://n${r.op}-${r.node}.example`
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')

const signer: Signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
const callerWallet: WalletOpener = { open: () => Promise.reject(new Error('unused')), payerAddr: () => 'PAYER' }

// ---- the chain ----

function operatorBox(id: number): Uint8Array {
    const b = new Uint8Array(OPERATOR_RECORD_SIZE)
    // Each operator its own owner, or none could relay for another.
    b.set(algosdk.generateAccount().addr.publicKey, 0)
    b[32] = OPERATOR_STATUS_ACTIVE
    new DataView(b.buffer).setBigUint64(41, 2n)
    expect(decodeOperatorRecord(BigInt(id), b).nextNodeId).toBe(2n)
    return b
}

// The Ed25519 seed of each node's on-chain signing key, by host, as the
// latest fakeAlgod wrote it.
const signingSeeds = new Map<string, Uint8Array>()

function nodeBox(r: NodeRef, staging: boolean): Uint8Array {
    const b = new Uint8Array(NODE_RECORD_SIZE)
    const url = new TextEncoder().encode(host(r))
    const signing = algosdk.generateAccount()
    signingSeeds.set(host(r), signing.sk.slice(0, 32))
    b[0] = 1
    b.set(signing.addr.publicKey, 1)
    b[33] = url.length
    b.set(url, 34)
    b[NODE_RECORD_SIZE - 33] = staging ? 1 : 0
    expect(url.length).toBeLessThanOrEqual(BASE_URL_MAX)
    const rec = decodeNodeRecord(BigInt(r.op), BigInt(r.node), b)
    expect([rec.baseUrl, rec.staging]).toEqual([host(r), staging ? 1 : 0])
    return b
}

interface FakeAlgodOptions {
    /** Every request waits on it. */
    gate?: (signal: AbortSignal | null | undefined) => Promise<void>
    /** Operators whose node is staging. */
    staging?: number[]
}

/** algod as discovery reads it: the box listing and box reads; every account read 404s. */
function fakeAlgod(refs: NodeRef[], o: FakeAlgodOptions = {}) {
    const { gate } = o
    const boxes = new Map<string, Uint8Array>()
    for (const r of refs) {
        boxes.set(hex(operatorBoxKey(BigInt(r.op))), operatorBox(r.op))
        boxes.set(hex(nodeBoxKey(BigInt(r.op), BigInt(r.node))), nodeBox(r, o.staging?.includes(r.op) ?? false))
    }
    const paths: string[] = []
    const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const u = new URL(String(input))
        paths.push(u.pathname)
        await gate?.(init?.signal)
        const name = (k: string) => hex(Buffer.from(u.searchParams.get(k)!.replace(/^b64:/, ''), 'base64'))
        if (u.pathname === `/v2/applications/${APP}/boxes`) {
            const prefix = name('prefix')
            const page = [...boxes.keys()].filter((n) => n.startsWith(prefix)).sort()
            const b64 = (n: string) => Buffer.from(n, 'hex').toString('base64')
            return Response.json({ round: 1, boxes: page.map((n) => ({ name: b64(n), value: Buffer.from(boxes.get(n)!).toString('base64') })) })
        }
        if (u.pathname === `/v2/applications/${APP}/box`) {
            const v = boxes.get(name('name'))
            if (v !== undefined) return Response.json({ name: u.searchParams.get('name'), round: 1, value: Buffer.from(v).toString('base64') })
        }
        return Response.json({ message: 'not found' }, { status: 404 })
    })
    return { fetch, paths }
}

// ---- the fleet ----

interface Call {
    /** The node the request reached: the relay when relayed. */
    to: string
    target: string
    path: string
}

function fleet(answer: (c: Call, signal: AbortSignal | null | undefined) => Response | Promise<Response>) {
    const calls: Call[] = []
    const fetch = (async (url: string, init: RequestInit) => {
        const u = new URL(url)
        const h = (init.headers ?? {}) as Record<string, string>
        const call =
            u.pathname === RELAY_PATH
                ? {
                      to: u.origin,
                      target: host({ op: Number(h[RELAY_TARGET_HEADER]), node: Number(h[RELAY_TARGET_NODE_HEADER]) }),
                      path: h[RELAY_PATH_HEADER]!,
                  }
                : { to: u.origin, target: u.origin, path: u.pathname }
        calls.push(call)
        return answer(call, init.signal)
    }) as typeof globalThis.fetch
    return { fetch, calls }
}

const details = (over: Record<string, unknown> = {}) =>
    Response.json({ models: [{ id: 'm' }], oracle_healthy: true, proto_version: PROTO_VERSION, ...over })
/** Every node answers its details probe. */
const serve = () => details()

/** The ephemeral advertisement the node at target signs under its on-chain key. */
async function ephemeralOf(target: string): Promise<Record<string, unknown>> {
    const r = FLEET.find((f) => host(f) === target)!
    const now = Math.floor(Date.now() / 1000)
    const adv = {
        ephemeral_age_pubkey: bech32.encode('age', bech32.toWords(new Uint8Array(32).fill(r.op))),
        ephemeral_expiry: now + 600,
        ephemeral_issued_at: now,
        ephemeral_sig: '',
    }
    adv.ephemeral_sig = base64.encode(await ed25519.signAsync(ephemeralSigDigest(r.op, r.node, adv), signingSeeds.get(target)!))
    return adv
}

const clients: Client[] = []
afterEach(async () => {
    await Promise.all(clients.splice(0).map((c) => c.close()))
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
})

// Each DiscoveryRegistry.stop from now on, true once its wait has ended.
function spyStops(): boolean[] {
    const stopped: boolean[] = []
    const stop = DiscoveryRegistry.prototype.stop
    vi.spyOn(DiscoveryRegistry.prototype, 'stop').mockImplementation(function (this: DiscoveryRegistry) {
        const i = stopped.push(false) - 1
        return stop.call(this).then(() => {
            stopped[i] = true
        })
    })
    return stopped
}

// Never answers; rejects when its signal fires, as fetch does.
const hang = (signal: AbortSignal | null | undefined) =>
    new Promise<never>((_, reject) => signal?.addEventListener('abort', () => reject(signal.reason), { once: true }))

async function clientOver(answer: (c: Call, signal: AbortSignal | null | undefined) => Response | Promise<Response>, over: Partial<Config> = {}, chain: FakeAlgodOptions = {}) {
    const algod = fakeAlgod(FLEET, chain)
    vi.stubGlobal('fetch', algod.fetch)
    const net = fleet(answer)
    const c = await Client.create({ signer, network: testnet(), wallet: callerWallet, fetch: net.fetch, disableTee: true, ...over })
    clients.push(c)
    return { c, p: partsOf.get(c)!, net, algod, registry: c.registry as DiscoveryRegistry }
}

describe('Client.create building the registry', () => {
    it('reads the fleet from the configured escrow and probes it', async () => {
        const storage = memoryStorage()
        const { c, registry, algod } = await clientOver(serve, { storage })
        expect(registry).toBeInstanceOf(DiscoveryRegistry)
        expect(c.config.registry).toBe(registry)
        expect(algod.paths).toContain(`/v2/applications/${APP}/boxes`)
        const ops = await registry.allOperators()
        expect(ops.map((o) => [o.id, o.nodeId, o.baseUrl, o.reachable, o.models])).toEqual(FLEET.map((r) => [r.op, r.node, host(r), true, ['m']]))
        // The catalog goes to Config.storage for the next start, under the
        // escrow app, since node ids repeat across networks.
        expect(await storage.get(`${CATALOG_STORAGE_KEY}.${APP}`)).toContain(host(T))
        expect(await storage.get(CATALOG_STORAGE_KEY)).toBeUndefined()
    })

    it('probes direct under privacy direct, and through a relay by default', async () => {
        const direct = await clientOver(() => details(), { privacy: 'direct' })
        await direct.registry.allOperators()
        expect(direct.net.calls.length).toBeGreaterThan(0)
        expect(direct.net.calls.every((call) => call.to === call.target)).toBe(true)

        const relayed = await clientOver(() => details())
        await relayed.registry.allOperators()
        expect(relayed.net.calls.length).toBeGreaterThan(0)
        expect(relayed.net.calls.every((call) => call.to !== call.target)).toBe(true)
    })

    it("checks TEE evidence with Config.teeVerifier, which routing then reads", async () => {
        const verified: unknown[] = []
        const teeVerifier: Verifier = {
            verify: async (_a, _b, node) => {
                verified.push(node)
                return {
                    pass: true,
                    failureTag: '',
                    verifierId: 'dstack-tdx',
                    attestedAt: 5,
                    detail: { measurementChecks: { osImage: true, composeRelease: true, composeHash: false } },
                }
            },
        }
        const { registry } = await clientOver(
            async (call) =>
                call.path === '/v1/zs/attestation'
                    ? new Response('{"mode":"dstack-tdx","generated_at":"2026-10-01T00:00:00Z"}')
                    : details({ tee: { mode: 'dstack-tdx' }, ...(await ephemeralOf(call.target)) }),
            { privacy: 'direct', disableTee: false, teeVerifier },
        )
        const ops = await registry.allOperators()
        expect(verified).toHaveLength(FLEET.length)
        expect(ops.every((o) => isTeeAttested(o))).toBe(true)
    })

    // The verifier would refuse it before reading the evidence; the probe
    // says why instead, and spends no request on it.
    it('fetches no evidence for a node with no verified ephemeral key', async () => {
        const verified: unknown[] = []
        const teeVerifier: Verifier = {
            verify: async (_a, _b, node) => {
                verified.push(node)
                return { pass: true, failureTag: '', verifierId: 'dstack-tdx', attestedAt: 5 }
            },
        }
        const { registry, net } = await clientOver(() => details({ tee: { mode: 'dstack-tdx' } }), {
            privacy: 'direct',
            disableTee: false,
            teeVerifier,
        })
        const ops = await registry.allOperators()
        expect(verified).toHaveLength(0)
        expect(net.calls.filter((c) => c.path === '/v1/zs/attestation')).toHaveLength(0)
        expect(ops.map((o) => o.tee?.failureTag)).toEqual(FLEET.map(() => 'ephemeral_unavailable'))
    })

    it('advertises a staging node only under allowStaging', async () => {
        const perNode = (call: Call) => details({ models: [{ id: `m-${new URL(call.target).hostname.split('.')[0]}` }] })
        const held = await clientOver(perNode, { privacy: 'direct' }, { staging: [3] })
        expect((await held.registry.allModels()).sort()).toEqual(['m-n1-1', 'm-n2-1'])
        const allowed = await clientOver(perNode, { privacy: 'direct', allowStaging: true }, { staging: [3] })
        expect((await allowed.registry.allModels()).sort()).toEqual(['m-n1-1', 'm-n2-1', 'm-n3-1'])
    })

    it('times each probe out at discovery.detailsTimeout', async () => {
        const { registry } = await clientOver((_call, signal) => hang(signal), { privacy: 'direct', discovery: { detailsTimeout: 30 } })
        const started = Date.now()
        const ops = await registry.allOperators()
        expect(Date.now() - started).toBeLessThan(1_000)
        expect(ops.every((o) => !o.reachable && o.probed)).toBe(true)
    })

    it('waits for the chain read but not the first probe, which reads wait for', async () => {
        let release!: () => void
        const held = new Promise<void>((r) => (release = r))
        const { registry } = await clientOver(async () => {
            await held
            return details()
        })
        const seeded = registry.snapshot()!.operators
        expect(seeded.map((o) => o.id)).toEqual([1, 2, 3])
        expect(seeded.every((o) => !o.reachable)).toBe(true)
        let read = false
        const ops = registry.allOperators().then((v) => {
            read = true
            return v
        })
        await new Promise((r) => setTimeout(r, 20))
        expect(read).toBe(false)
        release()
        expect((await ops).every((o) => o.reachable)).toBe(true)
    })

    it('reads only discovery.operatorIds when set', async () => {
        const { registry, algod } = await clientOver(serve, { discovery: { operatorIds: [2] } })
        expect(registry.snapshot()!.operators.map((o) => o.id)).toEqual([2])
        expect(algod.paths).toContain(`/v2/applications/${APP}/box`)
    })

    // Go's ids are uint64; a JS number is exact only up to MAX_SAFE_INTEGER,
    // and above it the BigInt the chain read keys by would be a different id.
    it.each([[1.5], [-1], [Number.MAX_SAFE_INTEGER + 2]])('refuses %s, which no operator id can be', async (id) => {
        await expect(
            Client.create({ signer, network: testnet(), wallet: callerWallet, discovery: { operatorIds: [id] } }),
        ).rejects.toMatchObject({ code: 'invalid_config', message: expect.stringContaining('discovery.operatorIds') })
    })

    it('accepts operator id 0', async () => {
        const { c, algod } = await clientOver(serve, { discovery: { operatorIds: [0] } })
        expect(c.config.discovery.operatorIds).toEqual([0])
        expect(algod.paths).toContain(`/v2/applications/${APP}/box`)
    })

    it('probes at most discovery.detailsConcurrency nodes at once', async () => {
        let inFlight = 0
        let most = 0
        const { registry } = await clientOver(
            async () => {
                most = Math.max(most, ++inFlight)
                await new Promise((r) => setTimeout(r, 20))
                inFlight--
                return details()
            },
            { privacy: 'direct', discovery: { detailsConcurrency: 1 } },
        )
        const ops = await registry.allOperators()
        expect(ops.filter((o) => o.reachable)).toHaveLength(FLEET.length)
        expect(most).toBe(1)
    })

    it('stops the registry it built on close', async () => {
        const { c, registry } = await clientOver(serve)
        const stop = vi.spyOn(registry, 'stop')
        await c.close()
        expect(stop).toHaveBeenCalledTimes(1)
    })

    it("stops the boot, and waits for it to stop, when create's signal aborts", async () => {
        const stopped = spyStops()
        const algod = fakeAlgod(FLEET, { gate: hang })
        vi.stubGlobal('fetch', algod.fetch)
        const ac = new AbortController()
        const p = Client.create({ signer, network: testnet(), wallet: callerWallet, fetch: fleet(() => details()).fetch, disableTee: true }, ac.signal)
        await new Promise((r) => setTimeout(r, 20))
        ac.abort(new Error('caller left'))
        await expect(p).rejects.toThrow('caller left')
        expect(stopped).toEqual([true])
    })

    it("doesn't hold an abort on a save of the catalog boot just loaded", async () => {
        const saved = memoryStorage()
        const warm = await clientOver(serve, { storage: saved })
        await warm.registry.allOperators()
        expect(await saved.get(`${CATALOG_STORAGE_KEY}.${APP}`)).toBeDefined()

        // A storage whose writes never land, over a chain read that never answers.
        const set = vi.fn(() => new Promise<void>(() => {}))
        const storage = { get: (k: string) => saved.get(k), set, delete: (k: string) => saved.delete(k) }
        const stopped = spyStops()
        vi.stubGlobal('fetch', fakeAlgod(FLEET, { gate: hang }).fetch)
        const ac = new AbortController()
        const p = Client.create({ signer, network: testnet(), wallet: callerWallet, fetch: warm.net.fetch, storage }, ac.signal)
        await new Promise((r) => setTimeout(r, 20))
        const aborted = Date.now()
        ac.abort(new Error('caller left'))
        await expect(p).rejects.toThrow('caller left')
        expect(Date.now() - aborted).toBeLessThan(1_000)
        expect(stopped).toEqual([true])
        expect(set).not.toHaveBeenCalled()
    })

    it('fails, stopping the registry, on a boot fleet holding a duplicate node', async () => {
        const stopped = spyStops()
        vi.spyOn(ChainOperatorSource.prototype, 'fetchChain').mockImplementation(async () => {
            const op = testOperator({ id: 1, nodeId: 1 })
            return [op, { ...op }]
        })
        vi.stubGlobal('fetch', fakeAlgod(FLEET).fetch)
        const err = await Client.create({ signer, network: testnet(), wallet: callerWallet, fetch: fleet(() => details()).fetch }).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect((err as Error).message).toMatch(/^registry: .*duplicate node/)
        expect(stopped).toEqual([true])
    })

    it("stops the registry it started when a later check fails create", async () => {
        const chain = { protocolFeeBps: async () => 0 } as unknown as EscrowChain
        const journal = memoryJournal()
        const first = await clientOver(() => details(), { wallet: new Wallet({ chain, signer }), stores: { journal } })
        const stopped = spyStops()
        await expect(
            Client.create({ signer, network: testnet(), wallet: new Wallet({ chain, signer }), stores: { journal }, fetch: first.net.fetch }),
        ).rejects.toMatchObject({ code: 'invalid_config' })
        expect(stopped).toEqual([true])
    })

    it('leaves a supplied registry running, reads no chain for it, and builds no routing store', async () => {
        const algod = fakeAlgod(FLEET)
        vi.stubGlobal('fetch', algod.fetch)
        const registry = new DiscoveryRegistry({ source: { fetchChain: async () => [], enrichSubset: async () => {} } })
        await registry.ready
        const stop = vi.spyOn(registry, 'stop')
        const c = await Client.create({ signer, network: testnet(), wallet: callerWallet, registry })
        await c.close()
        expect(stop).not.toHaveBeenCalled()
        expect(algod.fetch).not.toHaveBeenCalled()
        const st = c.config.stores
        expect([st.relayReputation, st.relayLatency, st.targetBackoff, st.nodeExclusions]).toEqual([undefined, undefined, undefined, undefined])
        expect(partsOf.get(c)!.source).toBeUndefined()
        await registry.stop()
    })
})

describe('the routing stores a built registry shares', () => {
    it('are the same instances in the probes, dispatch and the config', async () => {
        const { c, p } = await clientOver(serve)
        const st = c.config.stores
        expect(p.source!.relayReputation).toBe(st.relayReputation)
        expect(p.source!.relayLatency).toBe(st.relayLatency)
        expect(p.pick.relayReputation).toBe(st.relayReputation)
        expect(p.pick.relayLatency).toBe(st.relayLatency)
        expect(p.pick.targetBackoff).toBe(st.targetBackoff)
        expect(p.pick.nodeExclusions).toBe(st.nodeExclusions)
        expect(st.targetBackoff).toBeDefined()
        expect(st.nodeExclusions).toBeDefined()
    })

    it('include a store the host supplies, which the probes then record to', async () => {
        const relayReputation = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const { c, p } = await clientOver(serve, { stores: { relayReputation } })
        expect(p.source!.relayReputation).toBe(relayReputation)
        expect(p.pick.relayReputation).toBe(relayReputation)
        expect(c.config.stores.relayReputation).toBe(relayReputation)
    })

    it("downrank a relay the probes charge in dispatch's relay choice", async () => {
        const { c, p } = await clientOver((call) => {
            if (call.to === host(R2) && call.target !== host(R2)) throw new TypeError('connection refused')
            return details()
        })
        const registry = c.registry as DiscoveryRegistry
        await registry.allOperators()
        const rep = p.pick.relayReputation!
        expect(rep.relayDownranked(R2)).toBe(false)
        const before = await relayPool(p.pick)
        expect(before.find((s) => s.id === R2.op)!.reachable).toBe(true)
        // A probe that tries R2 first charges it, and marks it down until its
        // own probe answers again; the draw is random.
        for (let i = 0; i < 100 && !rep.relayDownranked(R2); i++) {
            await p.source!.enrichSubset(await registry.allOperators(), null)
        }
        expect(rep.relayDownranked(R2)).toBe(true)

        const pool = await relayPool(p.pick)
        expect(pool.find((s) => s.id === R2.op)!.reachable).toBe(false)
        expect(pool.find((s) => s.id === R3.op)!.reachable).toBe(true)
        const target = (await registry.resolve(T))!
        for (let i = 0; i < 20; i++) expect(relayRef(relayHopForPool(p.pick, pool, target)!)).toEqual(R3)
    })

    it('keep the probes off a relay dispatch charged', async () => {
        const { c, p, net } = await clientOver(serve)
        const registry = c.registry as DiscoveryRegistry
        await registry.allOperators()
        // What dispatch records when a forward through the relay fails.
        for (let i = 0; i < 3; i++) p.pick.relayReputation!.recordRelayOutcome(R3, false)
        expect(p.source!.relayReputation.relayDownranked(R3)).toBe(true)
        net.calls.length = 0
        for (let i = 0; i < 20; i++) await p.source!.enrichSubset(await registry.allOperators(), new Set([nodeRefString(T)]))
        expect(net.calls.filter((call) => call.target === host(T)).map((call) => call.to)).toEqual(Array(20).fill(host(R2)))
    })

    it("judge a relay's claim that its target is down by the probes' reachability", async () => {
        const { c, p } = await clientOver(serve)
        await (c.registry as DiscoveryRegistry).allOperators()
        const rep = p.pick.relayReputation!
        // T answered its probe, so the claim is contradicted.
        rep.recordRelayUpstreamUnreachable(R2, T)
        expect(rep.standing(R2).failures).toBe(1)
        // A node never seen up: the relay may be right, and is credited.
        rep.recordRelayOutcome(R3, false)
        rep.recordRelayUpstreamUnreachable(R3, { op: 9, node: 9 })
        expect(rep.standing(R3).failures).toBe(0)
    })
})
