/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The sealed run's open and send, porting go/zs open_errors_test.go,
// forward_test.go and forward_relay_attribution_test.go, and the open-failure
// cases of go/zs/handler dispatch_test.go and spend_dispatch_test.go. Go drives
// the last through a fake node over HTTP; here the wallet and fetch are faked
// directly, and the node's side is zs-proto's decryptRequest.

import { describe, expect, it, vi } from 'vitest'

import type { Ticket } from '@txnlab/zs-proto/ticket'
import { TRANSPORT_FAILURE_STATUS } from '@txnlab/zs-proto/transient'
import {
    ENCRYPTED_CONTENT_TYPE,
    PROTO_VERSION,
    RELAY_HOP_HEADER,
    RELAY_METHOD_HEADER,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
    computeAdmissionTag,
    decryptRequest,
    generateEphemeralIdentity,
} from '@txnlab/zs-proto/wire'

import type { Remedies, SpendGuard } from '../src/config.js'
import type { SealedRun } from '../src/dispatch.js'
import type { ZsError } from '../src/errors.js'
import { APPROVAL_ASSERT, ApprovalError, approvalErrorMessages } from '../src/escrow/revert.js'
import { ESCROW_METHOD_SIGNATURES } from '../src/escrow/generated/abi.js'
import { MbrDepositUnaffordableError } from '../src/mbr.js'
import type { Operator } from '../src/operator.js'
import type { OpenHandle, Reserved, WalletOpener } from '../src/parts.js'
import type { RelayHop } from '../src/routing/relay.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import {
    type BufferedResponder,
    MBR_POOL_EXHAUSTED_RETRY_AFTER_MS,
    type Outbound,
    type SealedCall,
    type SealedDeps,
    attributeRelayHop,
    forwardBuffered,
    isPoolExhaustedOpenError,
    isUnderfundedOpenError,
    nodeHeader,
    operatorHeaders,
    relayEvidence,
    runSealed,
} from '../src/sealed.js'
import { BelowTargetError, OpenTopUpError } from '../src/wallet.js'
import { testOperator } from './fixtures.js'

const POOL_ASSERTS = [
    APPROVAL_ASSERT.insufficientMbrDeposit,
    APPROVAL_ASSERT.insufficientMbrDepositFreeQuota,
    APPROVAL_ASSERT.payerHasNoMbrDeposit,
]

// The shape Wallet.open returns for a contract revert: the escrow client names
// the assert, the wallet wraps it with its text.
const revertFrom = (method: string, assert: string, pc = 1234) => {
    const revert = new ApprovalError(method, pc, assert, new Error(`logic eval error: assert failed pc=${pc}`))
    return new Error(`wallet: submit presigned open group: ${revert.message}`, { cause: revert })
}
const openRevert = (assert: string) => revertFrom('open', assert)

describe('isUnderfundedOpenError', () => {
    it('reads algod’s ledger-eval text for a payer who can’t pay', () => {
        for (const m of [
            'TransactionPool.Remember: transaction ABC: overspend (account XYZ, data {...})',
            'account XYZ balance 99000 below min 100000',
            'underflow on subtracting 5000000 from sender for asset 10458941',
            'asset 10458941 missing from XYZ',
        ]) {
            expect(isUnderfundedOpenError(new Error(`wallet: submit presigned open group: ${m}`)), m).toBe(true)
        }
        for (const e of [
            undefined,
            null,
            new Error('algod unreachable'),
            new Error('context deadline exceeded'),
            new Error('dial tcp: connection refused'),
            new Error('escrow submit returned 2 txids, want 3'),
        ]) {
            expect(isUnderfundedOpenError(e), String(e)).toBe(false)
        }
    })
})

describe('isPoolExhaustedOpenError', () => {
    it('matches open()’s three pool guards, through the wallet’s wrap, and nothing else', () => {
        for (const m of POOL_ASSERTS) {
            const err = openRevert(m)
            expect(isPoolExhaustedOpenError(err), m).toBe(true)
            // Disjoint from a balance shortfall, which dispatch checks after.
            expect(isUnderfundedOpenError(err), m).toBe(false)
        }
        for (const e of [
            undefined,
            new Error('algod unreachable'),
            new Error('wallet: submit presigned open group: account XYZ balance 99000 below min 100000'),
            // Another revert sharing the vocabulary.
            openRevert('no MBR deposit'),
            // A method sharing open's prefix, and the top-up's own revert.
            revertFrom('openFree', APPROVAL_ASSERT.insufficientMbrDeposit),
            revertFrom('depositMbr', APPROVAL_ASSERT.insufficientMbrDeposit),
            // Exact match, not a prefix.
            openRevert(`${APPROVAL_ASSERT.insufficientMbrDeposit} for the operator stake box`),
            // A revert the ARC-56 couldn't name.
            revertFrom('open', '', 999_999),
        ]) {
            expect(isPoolExhaustedOpenError(e), String(e)).toBe(false)
        }
    })

    it('admits exactly the three guards over every assert and every method of the contract', () => {
        const matched = new Set<string>()
        const nearMisses = new Set(['no MBR deposit', 'deposit must be positive'])
        for (const msg of approvalErrorMessages()) {
            nearMisses.delete(msg)
            const want = POOL_ASSERTS.includes(msg as (typeof POOL_ASSERTS)[number])
            expect(isPoolExhaustedOpenError(openRevert(msg)), msg).toBe(want)
            if (want) matched.add(msg)
        }
        expect(matched.size).toBe(3)
        // The sweep covered the near misses, so it is still the whole contract.
        expect([...nearMisses]).toEqual([])

        const methods = Object.keys(ESCROW_METHOD_SIGNATURES)
        expect(methods).toContain('open')
        for (const name of methods) {
            if (name === 'open') continue
            for (const msg of POOL_ASSERTS) expect(isPoolExhaustedOpenError(revertFrom(name, msg)), `${name}: ${msg}`).toBe(false)
        }
    })
})

describe('operatorHeaders', () => {
    it('advertises both media types for a sealed request, JSON otherwise', () => {
        expect(operatorHeaders(ENCRYPTED_CONTENT_TYPE)).toEqual({
            'Content-Type': ENCRYPTED_CONTENT_TYPE,
            Accept: `${ENCRYPTED_CONTENT_TYPE}, application/json`,
        })
        expect(operatorHeaders('application/json')).toEqual({ 'Content-Type': 'application/json', Accept: 'application/json' })
    })

    it('forwards a caller’s header but never auth or a hop-by-hop one', () => {
        const h = operatorHeaders('application/json', {
            'X-Request-ID': 'r1',
            authorization: 'Bearer leaked',
            Authorization: 'Bearer client-key',
            Connection: 'keep-alive',
            'Keep-Alive': 'timeout=5',
            'Transfer-Encoding': 'chunked',
            Upgrade: 'websocket',
            'Proxy-Authenticate': 'x',
            'proxy-authorization': 'x',
            TE: 'trailers',
            Trailers: 'x',
        })
        expect(h).toEqual({ 'Content-Type': 'application/json', Accept: 'application/json', 'X-Request-ID': 'r1' })
    })

    it('lets an extra header replace one already set, under any spelling', () => {
        expect(operatorHeaders('application/json', { 'content-type': 'text/plain', ACCEPT: '*/*' })).toEqual({
            'content-type': 'text/plain',
            ACCEPT: '*/*',
        })
    })
})

describe('nodeHeader', () => {
    it('drops every X-Zs- field, in any case, and keeps the rest', () => {
        const h = new Headers({
            'Content-Type': 'application/json',
            'X-Zs-Response-Key': 'k',
            'x-zs-receipt': 'r',
            'X-ZS-Settle-Group': 'g',
            'X-Zs-Future': 'f',
            'X-Request-Id': 'r1',
        })
        const kept: [string, string][] = []
        nodeHeader(h).forEach((v, k) => kept.push([k, v]))
        expect(kept).toEqual([
            ['content-type', 'application/json'],
            ['x-request-id', 'r1'],
        ])
    })
})

const ENDPOINT = '/v1/chat/completions'
const MODEL = 'gpt-test'

const hopOf = (over: Partial<RelayHop> = {}): RelayHop => ({
    baseUrl: 'https://relay.example.com',
    targetId: 9,
    targetNodeId: 1,
    relayId: 5,
    relayNodeId: 0,
    relayProtoVersion: PROTO_VERSION,
    ...over,
})

function reputation() {
    const store = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
    const r = {
        store,
        outcome: vi.spyOn(store, 'recordRelayOutcome'),
        upstream: vi.spyOn(store, 'recordRelayUpstreamUnreachable'),
        forwarded: vi.spyOn(store, 'recordRelayForwardedTargetFault'),
        timeout: vi.spyOn(store, 'recordRelayForwardTimeout'),
        /** Every record method that was called; the differentials call recordRelayOutcome themselves. */
        recorded(): string[] {
            const out: string[] = []
            for (const k of ['upstream', 'forwarded', 'timeout'] as const) if (r[k].mock.calls.length > 0) out.push(k)
            if (out.length === 0 && r.outcome.mock.calls.length > 0) out.push('outcome')
            return out
        },
    }
    return r
}

class Recorder {
    order: string[] = []
    failed?: ZsError
    committedArgs?: [string, string, number]
    note() {}
    clamped() {}
    reserved(r: Reserved, op: Operator) {
        this.order.push(`reserved ${r.ticket.ticket_id} ${op.id}`)
    }
    committed(ticketId: string, txId: string, fees: number) {
        this.order.push('committed')
        this.committedArgs = [ticketId, txId, fees]
    }
    fail(err: ZsError) {
        if (this.failed) throw new Error(`failed twice: ${this.failed.code}, then ${err.code}`)
        this.order.push(`fail ${err.code}`)
        this.failed = err
    }
    reply() {
        throw new Error('a test responder records its own reply')
    }
    open(): boolean {
        throw new Error('a test stream records its own frames')
    }
    frame(): number {
        throw new Error('a test stream records its own frames')
    }
    interrupt() {
        throw new Error('a test stream records its own frames')
    }
}

describe('relayEvidence and attributeRelayHop', () => {
    it('reads the hop marker, the relay’s version and our own abort', () => {
        const hop = hopOf()
        expect(relayEvidence(null, new Headers({ [RELAY_HOP_HEADER]: '1' }))).toEqual({
            relayed: false,
            hopMarker: false,
            relayMarksHops: false,
            callerAborted: false,
        })
        expect(relayEvidence(hop, new Headers({ [RELAY_HOP_HEADER]: '1' }))).toEqual({
            relayed: true,
            hopMarker: true,
            relayMarksHops: true,
            callerAborted: false,
        })
        // Present but empty is no marker, as Go's Header.Get(...) != "".
        expect(relayEvidence(hop, new Headers({ [RELAY_HOP_HEADER]: '' })).hopMarker).toBe(false)
        expect(relayEvidence(hopOf({ relayProtoVersion: '9.0' }), null).relayMarksHops).toBe(false)
        const ac = new AbortController()
        ac.abort()
        expect(relayEvidence(hop, null, ac.signal).callerAborted).toBe(true)
        expect(relayEvidence(hop, null, new AbortController().signal).callerAborted).toBe(false)
    })

    it('strikes, credits or abstains by the verdict, and records nothing for a direct route', () => {
        const hop = hopOf()
        const relay = { op: 5, node: 0 }
        const json = (o: unknown) => new TextEncoder().encode(JSON.stringify(o))

        let r = reputation()
        attributeRelayHop(r.store, hop, undefined, 200, new Headers(), json({ ok: true }))
        expect(r.outcome.mock.calls).toEqual([[relay, true]])

        r = reputation()
        attributeRelayHop(r.store, hop, undefined, 503, new Headers(), json({ error: { code: 'relay_busy' } }))
        expect(r.outcome.mock.calls).toEqual([[relay, false]])

        // The relay's claim about its target goes through the differential.
        r = reputation()
        attributeRelayHop(r.store, hop, undefined, 502, new Headers(), json({ error: { code: 'relay_upstream_unreachable' } }))
        expect(r.upstream.mock.calls).toEqual([[relay, { op: 9, node: 1 }]])

        // A success body is never parsed for a code.
        r = reputation()
        attributeRelayHop(r.store, hop, undefined, 200, new Headers(), json({ error: { code: 'relay_busy' } }))
        expect(r.outcome.mock.calls).toEqual([[relay, true]])

        // An unmarked gateway timeout feeds only the timeout streak.
        r = reputation()
        attributeRelayHop(r.store, hop, undefined, 504, new Headers(), new Uint8Array())
        expect(r.outcome).not.toHaveBeenCalled()
        expect(r.timeout).toHaveBeenCalledTimes(1)

        // The bottom of the error range: a relay's own 400 strikes it.
        r = reputation()
        attributeRelayHop(r.store, hop, undefined, 400, new Headers(), json({ error: { code: 'relay_bad_target' } }))
        expect(r.outcome.mock.calls).toEqual([[relay, false]])

        r = reputation()
        attributeRelayHop(r.store, hop, undefined, TRANSPORT_FAILURE_STATUS, null, null)
        expect(r.outcome.mock.calls).toEqual([[relay, false]])

        const ac = new AbortController()
        ac.abort()
        for (const [status, headers] of [
            [TRANSPORT_FAILURE_STATUS, null],
            [504, new Headers()],
            [502, new Headers({ [RELAY_HOP_HEADER]: '1' })],
        ] as const) {
            r = reputation()
            attributeRelayHop(r.store, hop, ac.signal, status, headers, status === TRANSPORT_FAILURE_STATUS ? null : new Uint8Array())
            expect(r.recorded(), String(status)).toEqual([])
        }

        r = reputation()
        attributeRelayHop(r.store, null, undefined, TRANSPORT_FAILURE_STATUS, null, null)
        attributeRelayHop(undefined, hop, undefined, TRANSPORT_FAILURE_STATUS, null, null)
        expect(r.outcome).not.toHaveBeenCalled()
    })

    it('reads a marked code-less error as the target’s, an unmarked one as the relay’s', () => {
        const relay = { op: 5, node: 0 }
        let r = reputation()
        attributeRelayHop(r.store, hopOf(), undefined, 502, new Headers({ [RELAY_HOP_HEADER]: '1' }), new Uint8Array())
        expect(r.forwarded.mock.calls).toEqual([[relay, { op: 9, node: 1 }]])

        r = reputation()
        attributeRelayHop(r.store, hopOf(), undefined, 502, new Headers(), new Uint8Array())
        expect(r.recorded()).toEqual(['outcome'])
        expect(r.outcome.mock.calls).toEqual([[relay, false]])

        // A relay too old to mark proves nothing either way.
        r = reputation()
        attributeRelayHop(r.store, hopOf({ relayProtoVersion: '9.0' }), undefined, 502, new Headers(), new Uint8Array())
        expect(r.recorded()).toEqual([])
    })
})

describe('forwardBuffered', () => {
    const out: Outbound = { url: 'https://n.example.com/v1/chat/completions', body: new Uint8Array([1, 2]), headers: { A: 'b' } }
    const logger = { debug() {}, info() {}, warn() {}, error() {} }
    const ok: BufferedResponder = async () => {}

    it('posts the sealed body and hands the whole answer to the responder', async () => {
        const fetch = vi.fn(async () => new Response('{"answer":1}', { status: 200, headers: { 'X-Zs-Receipt': 'r' } }))
        const seen: [number, string, string | null][] = []
        const em = new Recorder()
        const ac = new AbortController()
        await forwardBuffered({ fetch, logger }, em, out, { endpoint: ENDPOINT, hop: null, signal: ac.signal }, async (_e, resp, body) => {
            seen.push([resp.status, new TextDecoder().decode(body), resp.headers.get('X-Zs-Receipt')])
        })
        expect(fetch).toHaveBeenCalledWith(out.url, { method: 'POST', headers: out.headers, body: out.body, signal: ac.signal })
        expect(seen).toEqual([[200, '{"answer":1}', 'r']])
        expect(em.failed).toBeUndefined()
    })

    it('fails upstream_unreachable when nothing arrives, charging an unreachable relay', async () => {
        const r = reputation()
        const em = new Recorder()
        const hop = hopOf()
        await forwardBuffered(
            { fetch: async () => Promise.reject(new TypeError('fetch failed')), relayReputation: r.store, logger },
            em,
            out,
            { endpoint: ENDPOINT, hop },
            ok,
        )
        expect(em.failed).toMatchObject({ code: 'upstream_unreachable', kind: 'interrupted', message: 'fetch failed' })
        expect(r.outcome.mock.calls).toEqual([[{ op: 5, node: 0 }, false]])
    })

    it('charges no relay for a request the payer hung up on', async () => {
        const r = reputation()
        const ac = new AbortController()
        const fetch = async () => {
            ac.abort()
            throw new DOMException('aborted', 'AbortError')
        }
        await forwardBuffered({ fetch, relayReputation: r.store, logger }, new Recorder(), out, { endpoint: ENDPOINT, hop: hopOf(), signal: ac.signal }, ok)
        expect(r.recorded()).toEqual([])
    })

    it('reads the response’s hop marker when attributing', async () => {
        const r = reputation()
        await forwardBuffered(
            {
                fetch: async () => new Response('<html>bad gateway</html>', { status: 502, headers: { [RELAY_HOP_HEADER]: '1' } }),
                relayReputation: r.store,
                logger,
            },
            new Recorder(),
            out,
            { endpoint: ENDPOINT, hop: hopOf() },
            ok,
        )
        expect(r.forwarded.mock.calls).toEqual([[{ op: 5, node: 0 }, { op: 9, node: 1 }]])
    })

    it('fails build_request for a URL that won’t parse, sending nothing and charging no relay', async () => {
        const r = reputation()
        const fetch = vi.fn(async () => new Response('{}'))
        const em = new Recorder()
        await forwardBuffered({ fetch, relayReputation: r.store, logger }, em, { ...out, url: 'not a url/v1/chat/completions' }, { endpoint: ENDPOINT, hop: hopOf() }, ok)
        expect(em.failed).toMatchObject({ code: 'build_request', kind: 'operator_fault' })
        expect(fetch).not.toHaveBeenCalled()
        expect(r.outcome).not.toHaveBeenCalled()
    })

    it('attributes the relay from the response before the responder runs', async () => {
        const r = reputation()
        const order: string[] = []
        r.outcome.mockImplementation(() => {
            order.push('attributed')
        })
        await forwardBuffered(
            { fetch: async () => new Response('{}'), relayReputation: r.store, logger },
            new Recorder(),
            out,
            { endpoint: ENDPOINT, hop: hopOf() },
            async () => {
                order.push('responded')
            },
        )
        expect(order).toEqual(['attributed', 'responded'])
    })

    it('fails read_upstream when the body won’t read, and response_handler when the responder throws', async () => {
        const broken = new Response(
            new ReadableStream({
                pull(c) {
                    c.error(new Error('connection reset'))
                },
            }),
        )
        let em = new Recorder()
        const responder = vi.fn(ok)
        await forwardBuffered({ fetch: async () => broken, logger }, em, out, { endpoint: ENDPOINT, hop: null }, responder)
        expect(em.failed).toMatchObject({ code: 'read_upstream', kind: 'interrupted', message: 'connection reset' })
        expect(responder).not.toHaveBeenCalled()

        em = new Recorder()
        const errors: unknown[] = []
        await forwardBuffered(
            { fetch: async () => new Response('{}'), logger: { ...logger, error: (m: string, a?: unknown) => errors.push([m, a]) } },
            em,
            out,
            { endpoint: ENDPOINT, hop: null },
            async () => {
                throw new Error('commit_k mismatch')
            },
        )
        expect(em.failed).toMatchObject({
            code: 'response_handler',
            kind: 'operator_fault',
            message: 'operator response could not be processed',
        })
        expect(errors).toEqual([['response handling failed', { endpoint: ENDPOINT, err: 'commit_k mismatch' }]])
    })
})

describe('runSealed', () => {
    const remedies: Remedies = { fund: 'fund it', raiseSlots: 'raise slots', raiseSpendCap: 'raise cap', recoverTicket: 'recover' }

    function ticketOf(): Ticket {
        return {
            ticket_id: 'TKT1',
            operator_id: 9,
            node_id: 1,
            model: MODEL,
            input_count: 10,
            max_output_count: 20,
            max_price: 5000,
            expires_at: 2_000_000_000,
        } as unknown as Ticket
    }

    async function setup(o: { openErr?: unknown; hop?: RelayHop | null; stream?: boolean; body?: string | Uint8Array; responseKey?: Uint8Array } = {}) {
        const pinned = await generateEphemeralIdentity()
        const current = await generateEphemeralIdentity()
        const identity = await generateEphemeralIdentity()
        const responseKey = o.responseKey ?? new Uint8Array(32).fill(3)
        const op = testOperator({ id: 9, nodeId: 1, baseUrl: 'https://n9.example.com', ephemeralRecipient: current.recipient } as Partial<Operator>)
        const reserved = {
            ticket: ticketOf(),
            responseKey,
            identity,
            presignedOpenTxn: 'OPENGROUP',
            sealRecipient: pinned.recipient,
            algoUsdPrice: 0.2,
        } as unknown as Reserved
        const handle = {
            appCallTxId: 'APPCALLTXID',
            groupId: 'GROUPID',
            ticketId: 'TKT1',
            openFeesMicroalgos: 2000,
        } as unknown as OpenHandle
        const opens: unknown[][] = []
        const wallet: WalletOpener = {
            payerAddr: () => 'PAYERADDR',
            async open(...args) {
                opens.push(args)
                if (o.openErr !== undefined) throw o.openErr
                return handle
            },
        }
        const released: string[] = []
        const spendGuard: SpendGuard = { admit() {}, reserve() {}, settle() {}, release: (id) => released.push(id) }
        const sent: { url: string; init: RequestInit }[] = []
        const opened: unknown[][] = []
        const calls: SealedCall[] = []
        const streamed: [Outbound, SealedCall, BufferedResponder][] = []
        const responses: [number, string][] = []
        const em = new Recorder()
        const deps: SealedDeps = {
            wallet,
            spendGuard,
            remedies,
            network: 'testnet',
            fetch: async (url, init) => {
                sent.push({ url: String(url), init: init! })
                return new Response('{"done":true}')
            },
            logger: { debug() {}, info() {}, warn() {}, error() {} },
            opened: (h, t) => {
                em.order.push('opened')
                opened.push([h, t])
            },
            buffered: (call) => {
                calls.push(call)
                return async (_e, resp, body) => {
                    responses.push([resp.status, new TextDecoder().decode(body)])
                }
            },
            streamed: async (_e, out, call, buffered) => {
                streamed.push([out, call, buffered])
            },
        }
        const run: SealedRun = {
            endpoint: ENDPOINT,
            model: MODEL,
            body: o.body ?? `{"model":"${MODEL}"}`,
            op,
            reserved,
            stream: o.stream ?? false,
            hop: o.hop ?? null,
        }
        return { deps, em, run, pinned, current, identity, handle, opens, released, sent, opened, calls, streamed, responses }
    }

    it('opens escrow, seals to the pinned recipient with the app-call txid, and sends it direct', async () => {
        const s = await setup()
        const ac = new AbortController()
        await runSealed(s.deps, s.em, s.run, ac.signal)

        expect(s.opens).toEqual([[s.run.reserved.ticket, s.run.op, 'OPENGROUP', ac.signal]])
        expect(s.em.order).toEqual(['reserved TKT1 9', 'opened', 'committed'])
        expect(s.em.committedArgs).toEqual(['TKT1', 'APPCALLTXID', 2000])
        expect(s.opened).toEqual([[s.handle, s.run.reserved.ticket]])
        expect(s.released).toEqual([])

        expect(s.sent).toHaveLength(1)
        const { url, init } = s.sent[0]!
        expect(url).toBe(`https://n9.example.com${ENDPOINT}`)
        expect(init.method).toBe('POST')
        expect(init.signal).toBe(ac.signal)
        expect(init.headers).toEqual({ 'Content-Type': ENCRYPTED_CONTENT_TYPE, Accept: `${ENCRYPTED_CONTENT_TYPE}, application/json` })

        // Only the recipient the reserve pinned opens it, not the operator's current one.
        const body = new TextEncoder().encode(s.run.body as string)
        const dec = await decryptRequest(init.body as Uint8Array, s.pinned.secret)
        expect(dec.body).toEqual(body)
        expect(dec.algorandTxID).toBe('APPCALLTXID')
        expect(dec.ticketID).toBe('TKT1')
        expect(dec.replyToRecipient).toBe(s.identity.recipient)
        expect(dec.admissionTag).toEqual(computeAdmissionTag(s.run.reserved.responseKey, 'TKT1', 'APPCALLTXID', body))
        await expect(decryptRequest(init.body as Uint8Array, s.current.secret)).rejects.toThrow()

        expect(s.calls).toEqual([
            { endpoint: ENDPOINT, model: MODEL, op: s.run.op, reserved: s.run.reserved, handle: s.handle, txId: 'APPCALLTXID', hop: null, signal: ac.signal },
        ])
        expect(s.responses).toEqual([[200, '{"done":true}']])
        expect(s.em.failed).toBeUndefined()
    })

    it('still reports the payment and sends when the open hook throws', async () => {
        const s = await setup()
        s.deps.opened = () => {
            s.em.order.push('opened')
            throw new Error('journal down')
        }
        await runSealed(s.deps, s.em, s.run)
        expect(s.em.order).toEqual(['reserved TKT1 9', 'opened', 'committed'])
        expect(s.sent).toHaveLength(1)
        expect(s.em.failed).toBeUndefined()
    })

    // Go journals the open before the request goes out, so the open row is
    // written before a receipt row can follow and overwrite it.
    it('waits for the open hook before reporting the payment and sending', async () => {
        for (const outcome of ['resolves', 'rejects'] as const) {
            const s = await setup()
            s.deps.opened = async () => {
                await new Promise((r) => setTimeout(r, 10))
                s.em.order.push(`opened ${s.sent.length}`)
                if (outcome === 'rejects') throw new Error('journal down')
            }
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.order, outcome).toEqual(['reserved TKT1 9', 'opened 0', 'committed'])
            expect(s.sent).toHaveLength(1)
        }
    })

    it('seals a byte body as it came', async () => {
        const bytes = new TextEncoder().encode(`{"model":"${MODEL}","x":1}`)
        const s = await setup({ body: bytes })
        await runSealed(s.deps, s.em, s.run)
        expect((await decryptRequest(s.sent[0]!.init.body as Uint8Array, s.pinned.secret)).body).toEqual(bytes)
    })

    it('sends a relayed request to the relay’s route, the inner request in its headers', async () => {
        const hop = hopOf({ baseUrl: 'https://relay.example.com/', targetId: 9, targetNodeId: 1 })
        const s = await setup({ hop })
        // A path on the node's base URL stays out of the inner path, as in Go.
        s.run.op = { ...s.run.op, baseUrl: 'https://n9.example.com/api' }
        await runSealed(s.deps, s.em, s.run)
        const { url, init } = s.sent[0]!
        expect(url).toBe('https://relay.example.com/v1/zs/relay')
        expect(init.headers).toEqual({
            'Content-Type': ENCRYPTED_CONTENT_TYPE,
            Accept: `${ENCRYPTED_CONTENT_TYPE}, application/json`,
            [RELAY_TARGET_HEADER]: '9',
            [RELAY_TARGET_NODE_HEADER]: '1',
            [RELAY_PATH_HEADER]: ENDPOINT,
            [RELAY_METHOD_HEADER]: 'POST',
        })
        expect(s.calls[0]!.hop).toBe(hop)
        // Still sealed to the target: the relay can't open it.
        expect((await decryptRequest(init.body as Uint8Array, s.pinned.secret)).ticketID).toBe('TKT1')
    })

    it('hands a streamed request to the streamed forward, with the buffered responder as its fallback', async () => {
        const s = await setup({ stream: true })
        await runSealed(s.deps, s.em, s.run)
        expect(s.sent).toEqual([])
        expect(s.streamed).toHaveLength(1)
        const [out, call, buffered] = s.streamed[0]!
        expect(out.url).toBe(`https://n9.example.com${ENDPOINT}`)
        expect((await decryptRequest(out.body, s.pinned.secret)).algorandTxID).toBe('APPCALLTXID')
        expect(call).toBe(s.calls[0])
        await buffered(s.em, new Response('x', { status: 502 }), new TextEncoder().encode('x'))
        expect(s.responses).toEqual([[502, 'x']])
    })

    it('fails wrap_request, after paying, when the request won’t seal, and sends nothing', async () => {
        const s = await setup({ responseKey: new Uint8Array(31) })
        await runSealed(s.deps, s.em, s.run)
        expect(s.em.order).toEqual(['reserved TKT1 9', 'opened', 'committed', 'fail wrap_request'])
        expect(s.em.failed).toMatchObject({ code: 'wrap_request', kind: 'internal', message: 'request could not be wrapped' })
        expect(s.sent).toEqual([])
        expect(s.calls).toEqual([])
        expect(s.released).toEqual([])
    })

    describe('a failed open', () => {
        const unaffordable = () => new MbrDepositUnaffordableError(1n, 4n, 577_000n, 489_000n)
        // As Wallet.open wraps a pool it couldn't fund.
        const ensureFailed = () => {
            const u = unaffordable()
            return new Error(`wallet: ensure MBR deposit: ${u.message}`, { cause: u })
        }
        const noPool = () => openRevert(APPROVAL_ASSERT.payerHasNoMbrDeposit)

        it.each([
            ['a plain failure', () => new Error('algod unreachable'), 'wallet_open', 'internal', undefined],
            ['an overspend', () => new Error('wallet: submit presigned open group: overspend (account XYZ)'), 'wallet_unfunded', 'funds', undefined],
            ['an unaffordable deposit', ensureFailed, 'mbr_pool_underfunded', 'funds', undefined],
            ['a deposit below target', () => new BelowTargetError(50_000n), 'mbr_pool_underfunded', 'funds', undefined],
            ['every slot in flight', () => openRevert(APPROVAL_ASSERT.insufficientMbrDeposit), 'mbr_pool_exhausted', 'busy', MBR_POOL_EXHAUSTED_RETRY_AFTER_MS],
            // No pool after a top-up that couldn't fund one: only more ALGO helps.
            ['no pool and a failed top-up', () => new OpenTopUpError(noPool(), unaffordable()), 'mbr_pool_underfunded', 'funds', undefined],
            // No pool, but nothing to top up: another request funded it, so waiting clears it.
            ['no pool and no top-up', noPool, 'mbr_pool_exhausted', 'busy', MBR_POOL_EXHAUSTED_RETRY_AFTER_MS],
        ] as const)('ends the turn on %s, releasing the reservation and sending nothing', async (_name, err, code, kind, retryAfter) => {
            const s = await setup({ openErr: err() })
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.order).toEqual(['reserved TKT1 9', `fail ${code}`])
            expect(s.em.failed).toMatchObject({ code, kind })
            expect(s.em.failed!.retryAfter).toBe(retryAfter)
            expect(s.released).toEqual(['TKT1'])
            expect(s.opened).toEqual([])
            expect(s.sent).toEqual([])
        })

        it('names the payer, the network, the shortfall and the remedy', async () => {
            let s = await setup({ openErr: ensureFailed() })
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed!.message).toBe(
                'zerosignal wallet PAYERADDR needs more ALGO (not USDC) to fund the prepaid ticket-MBR pool on testnet — wallet: ensure MBR deposit: insufficient ALGO to fund the prepaid MBR pool: it backs 1 of 4 slot(s); the next deposit needs 577000 µALGO, have 489000 spendable — add ALGO to the wallet. To fix it, fund it.',
            )
            // A failed top-up's shortfall reaches the caller too.
            s = await setup({ openErr: new OpenTopUpError(noPool(), unaffordable()) })
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed!.message).toContain('the next deposit needs 577000 µALGO, have 489000 spendable')

            s = await setup({ openErr: openRevert(APPROVAL_ASSERT.insufficientMbrDeposit) })
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed!.message).toBe(
                'zerosignal wallet PAYERADDR has all concurrent ticket slots in use by in-flight requests on testnet — retry once in-flight requests settle, or to allow more at once, raise slots.',
            )

            s = await setup({ openErr: new Error('overspend') })
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed!.message).toBe("zerosignal wallet PAYERADDR can't pay for this request on testnet. To fix it, fund it.")

            s = await setup({ openErr: new Error('algod unreachable') })
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed!.message).toBe('payment group could not be submitted')
        })

        it('needs no spend guard', async () => {
            const s = await setup({ openErr: new Error('algod unreachable') })
            delete s.deps.spendGuard
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed!.code).toBe('wallet_open')
        })
    })
})
