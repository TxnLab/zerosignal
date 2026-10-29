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
    NODE_SUBMITS_OPEN_MIN_VERSION,
    PROTO_VERSION,
    RAIL_NEUTRAL_NAMES_MIN_VERSION,
    RELAY_HOP_HEADER,
    RELAY_METHOD_HEADER,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
    RESPONSE_KEY_HEADER,
    SEALED_SETTLE_ACK_CONTENT_TYPE,
    SETTLE_ACK_MIN_VERSION,
    SETTLE_ACK_PATH,
    type SettleAck,
    computeAdmissionTag,
    decryptRequest,
    generateEphemeralIdentity,
    openReserveResponse,
    openSettleAck,
} from '@txnlab/zs-proto/wire'
import type { Operator as SelectionOperator } from '@txnlab/zs-proto/selection'

import type { Remedies, SpendGuard } from '../src/config.js'
import { withHeaderBackstop } from '../src/header-backstop.js'
import type { SealedRun } from '../src/dispatch.js'
import type { ZsError } from '../src/errors.js'
import { APPROVAL_ASSERT, ApprovalError, approvalErrorMessages } from '../src/escrow/revert.js'
import { ESCROW_METHOD_SIGNATURES } from '../src/escrow/generated/abi.js'
import { MbrDepositUnaffordableError } from '../src/mbr.js'
import type { Operator } from '../src/operator.js'
import type { OpenHandle, Reserved, WalletOpener } from '../src/parts.js'
import type { Fetch } from '../src/ports.js'
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
    openFailure,
    operatorHeaders,
    relayEvidence,
    runSealed,
    settleAckPoster,
} from '../src/sealed.js'
import { RentDepositBelowTargetError, RentDepositUnaffordableError } from '../src/solana/rent.js'
import { BelowTargetError, NoSettleAckRouteError, OpenTopUpError } from '../src/wallet.js'
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

    // Go's header backstop fires on a context the caller didn't end, so the
    // relay is charged, the residue Go's relayEvidence names.
    it('charges the relay when the default fetch’s header backstop gives up', async () => {
        const r = reputation()
        const em = new Recorder()
        const silent: Fetch = (_, init) =>
            new Promise((_, reject) => init!.signal!.addEventListener('abort', () => reject(init!.signal!.reason), { once: true }))
        const caller = new AbortController()
        await forwardBuffered(
            { fetch: withHeaderBackstop(silent, 10), relayReputation: r.store, logger },
            em,
            out,
            { endpoint: ENDPOINT, hop: hopOf(), signal: caller.signal },
            ok,
        )
        expect(em.failed).toMatchObject({ code: 'upstream_unreachable', message: 'timeout awaiting response headers' })
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

    it('reads the body under the idle bound and the size cap', async () => {
        const silent = new Response(
            new ReadableStream({
                start(c) {
                    c.enqueue(new TextEncoder().encode('{"partial":'))
                },
            }),
        )
        let em = new Recorder()
        const bound = { preStream: 60_000, midStream: 30, toolActive: 60_000 }
        await forwardBuffered({ fetch: async () => silent, logger, streamIdle: bound }, em, out, { endpoint: ENDPOINT, hop: null }, ok)
        expect(em.failed).toMatchObject({ code: 'read_upstream' })
        expect(em.failed?.cause).toMatchObject({ name: 'StreamIdleTimeoutError', timeoutMs: 30 })

        for (const [body, whole] of [
            ['{"a":12}', true],
            ['{"a":123}', false],
        ] as const) {
            em = new Recorder()
            let got: string | undefined
            await forwardBuffered({ fetch: async () => new Response(body), logger, maxReplyBytes: 8 }, em, out, { endpoint: ENDPOINT, hop: null }, async (_e, _r, b) => {
                got = new TextDecoder().decode(b)
            })
            if (whole) expect([em.failed, got]).toEqual([undefined, body])
            else expect([em.failed?.code, got]).toEqual(['read_upstream', undefined])
        }
    })

    it('logs a request the caller ended at debug', async () => {
        const logged: string[] = []
        const ac = new AbortController()
        const fetch = async () => {
            ac.abort()
            throw new DOMException('aborted', 'AbortError')
        }
        const log = {
            ...logger,
            debug: (m: string) => logged.push(`debug ${m}`),
            warn: (m: string) => logged.push(`warn ${m}`),
            error: (m: string) => logged.push(`error ${m}`),
        }
        await forwardBuffered({ fetch, logger: log }, new Recorder(), out, { endpoint: ENDPOINT, hop: null, signal: ac.signal }, ok)
        await forwardBuffered({ fetch: async () => Promise.reject(new TypeError('fetch failed')), logger: log }, new Recorder(), out, { endpoint: ENDPOINT, hop: null }, ok)
        // This request rides the caller's signal, so a caller who leaves
        // mid-body ends it.
        const leaving = new AbortController()
        const midBody = async () =>
            new Response(
                new ReadableStream({
                    start(c) {
                        c.enqueue(new TextEncoder().encode('{"partial":'))
                        leaving.abort()
                        c.error(new DOMException('aborted', 'AbortError'))
                    },
                }),
            )
        await forwardBuffered({ fetch: midBody, logger: log }, new Recorder(), out, { endpoint: ENDPOINT, hop: null, signal: leaving.signal }, ok)
        expect(logged).toEqual(['debug operator request failed', 'error operator request failed', 'debug operator reply read failed'])
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

    async function setup(
        o: {
            openErr?: unknown
            hop?: RelayHop | null
            stream?: boolean
            body?: string | Uint8Array
            responseKey?: Uint8Array
            protoVersion?: string
            /** Give the wallet openForNode (a NodeOpener). */
            nodeOpener?: boolean
            reply?: () => Response
        } = {},
    ) {
        const pinned = await generateEphemeralIdentity()
        const current = await generateEphemeralIdentity()
        const identity = await generateEphemeralIdentity()
        const responseKey = o.responseKey ?? new Uint8Array(32).fill(3)
        const op = testOperator({
            id: 9,
            nodeId: 1,
            baseUrl: 'https://n9.example.com',
            ephemeralRecipient: current.recipient,
            ...(o.protoVersion !== undefined ? { protoVersion: o.protoVersion } : {}),
        } as Partial<Operator>)
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
        const handOffs: unknown[][] = []
        const rechecks = { count: 0 }
        const wallet: WalletOpener = {
            payerAddr: () => 'PAYERADDR',
            async open(...args) {
                opens.push(args)
                if (o.openErr !== undefined) throw o.openErr
                return handle
            },
            recheckDeposit: () => {
                rechecks.count++
            },
        }
        if (o.nodeOpener) {
            wallet.openForNode = async (...args) => {
                handOffs.push(args)
                if (o.openErr !== undefined) throw o.openErr
                handle.openGroup = 'COMPLETEDGROUP'
                return handle
            }
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
                return o.reply ? o.reply() : new Response('{"done":true}')
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
        return { deps, em, run, pinned, current, identity, handle, opens, handOffs, rechecks, released, sent, opened, calls, streamed, responses }
    }

    // Go's settleAckPoster is set on the handle by runSealed; only a node
    // that serves the route gets one.
    it.each([
        [SETTLE_ACK_MIN_VERSION, true],
        ['9.11', false],
        ['', false],
    ] as const)('gives a %s node a settle-ack poster: %s', async (version, want) => {
        const s = await setup({ protoVersion: version })
        await runSealed(s.deps, s.em, s.run)
        expect(typeof s.handle.deliverAck === 'function').toBe(want)
    })

    // The poster runSealed wires must follow the request's own route: a
    // relayed request's ack sent direct would show the target the payer's IP
    // beside a group naming the payer, and a direct request needs no relay.
    it.each([
        ['relayed', true, 'https://relay.example.com/v1/zs/relay'],
        ['direct', false, `https://n9.example.com${SETTLE_ACK_PATH}`],
    ] as const)('sends a %s request’s settle ack the same way', async (_name, relayed, wantUrl) => {
        const s = await setup({ protoVersion: SETTLE_ACK_MIN_VERSION, hop: relayed ? hopOf() : null })
        s.deps.relays = {
            pool: async () => [
                { operator_id: 5, node_id: 0, proto_version: SETTLE_ACK_MIN_VERSION, reachable: true } as unknown as SelectionOperator,
            ],
            hopFor: () => hopOf(),
        }
        await runSealed(s.deps, s.em, s.run)
        s.sent.length = 0
        // The fake answers 200, which the poster refuses; only the route is in question.
        await s.handle.deliverAck!({ ticket_id: 'TKT1', settle_group: 'G' }).catch(() => {})
        expect(s.sent.map((r) => r.url)).toEqual([wantUrl])
    })

    // A free Solana turn opens nothing: the wallet is never asked, the
    // envelope names no open and the tag binds an empty tx id, nothing is
    // journaled or watched, and the reservation is released at once. Hosts
    // still get the committed line once the turn is sealed, with no open to
    // name.
    it('opens nothing for a free Solana turn', async () => {
        for (const nodeOpener of [false, true]) {
            const s = await setup({ protoVersion: PROTO_VERSION, nodeOpener })
            s.deps.rail = 'solana'
            ;(s.run.reserved.ticket as { max_price: number }).max_price = 0
            await runSealed(s.deps, s.em, s.run)
            expect(s.opens).toEqual([])
            expect(s.handOffs).toEqual([])
            expect(s.opened).toEqual([])
            expect(s.released).toEqual(['TKT1'])
            expect(s.em.committedArgs).toEqual(['TKT1', '', 0])
            expect(s.em.order).toEqual(['reserved TKT1 9', 'committed'])
            expect(s.em.failed).toBeUndefined()

            const dec = await decryptRequest(s.sent[0]!.init.body as Uint8Array, s.pinned.secret)
            expect(dec.openGroup).toBe('')
            expect(dec.algorandTxID).toBe('')
            expect(dec.admissionTag).toEqual(computeAdmissionTag(new Uint8Array(32).fill(3), 'TKT1', '', dec.body))
            // No handle, so the receipt check has no ack or protest to send.
            expect(s.calls).toHaveLength(1)
            expect(s.calls[0]!.handle).toBeNull()
        }
    })

    // The same ticket on Algorand, or a priced one on Solana, opens as before.
    it.each([
        ['algorand', 0],
        ['solana', 5000],
    ] as const)('opens a %s ticket at max_price %d', async (rail, maxPrice) => {
        const s = await setup()
        s.deps.rail = rail
        ;(s.run.reserved.ticket as { max_price: number }).max_price = maxPrice
        await runSealed(s.deps, s.em, s.run)
        expect(s.opens).toHaveLength(1)
        expect(s.released).toEqual([])
        expect(s.em.committedArgs).toEqual(['TKT1', 'APPCALLTXID', 2000])
    })

    describe('handing the open to the node', () => {
        // TestDispatch_WalletPath_HandsOpenToNodeByVersion: a group handed to
        // an older node loses the turn, since it ignores the field and waits
        // for an open nobody submitted.
        it.each([
            [NODE_SUBMITS_OPEN_MIN_VERSION, true, true, false],
            [RAIL_NEUTRAL_NAMES_MIN_VERSION, true, true, true],
            [PROTO_VERSION, true, true, true],
            ['9.11', true, false, false],
            ['', true, false, false],
            // A wallet without openForNode keeps submitting, whatever the node.
            [NODE_SUBMITS_OPEN_MIN_VERSION, false, false, false],
        ] as const)('node %s, openForNode %s: hands off %s, neutral names %s', async (version, nodeOpener, handOff, neutral) => {
            const s = await setup({ protoVersion: version, nodeOpener })
            const ac = new AbortController()
            await runSealed(s.deps, s.em, s.run, ac.signal)
            const args = [s.run.reserved.ticket, s.run.op, 'OPENGROUP', ac.signal]
            expect(s.handOffs).toEqual(handOff ? [args] : [])
            expect(s.opens).toEqual(handOff ? [] : [args])

            const dec = await decryptRequest(s.sent[0]!.init.body as Uint8Array, s.pinned.secret)
            expect(dec.openGroup).toBe(handOff ? 'COMPLETEDGROUP' : '')
            // The app call's txid either way, and the tag binds it as before.
            expect(dec.algorandTxID).toBe('APPCALLTXID')
            // Under the names this node reads: an older one sees no tx id under payment_ref.
            expect(dec.neutralNames).toBe(neutral)
            expect(dec.admissionTag).toEqual(computeAdmissionTag(new Uint8Array(32).fill(3), 'TKT1', 'APPCALLTXID', dec.body))
            // Journal and watchdog are armed exactly as after a payer submit.
            expect(s.opened).toEqual([[s.handle, s.run.reserved.ticket]])
            expect(s.em.order).toEqual(['reserved TKT1 9', 'opened', 'committed'])
        })

        it('backs the reservation out when the hand-off fails', async () => {
            const s = await setup({ protoVersion: NODE_SUBMITS_OPEN_MIN_VERSION, nodeOpener: true, openErr: new Error('algod unreachable') })
            await runSealed(s.deps, s.em, s.run)
            expect(s.handOffs).toHaveLength(1)
            expect(s.released).toEqual(['TKT1'])
            expect(s.opened).toEqual([])
            expect(s.sent).toEqual([])
        })

        const refused = () =>
            new Response(
                '{"error":{"message":"payment verification failed: open group rejected by algod","type":"invalid_request_error","code":"payment_verification_failed"}}',
                { status: 402, headers: { 'Content-Type': 'application/json' } },
            )

        // TestDispatch_WalletPath_RefusedHandOffRechecksDeposit: with the node
        // submitting, its 402 is the only sign of a pool shortfall, and a
        // payer-submitted open already proved the pool.
        it.each([
            ['a handed-off open', NODE_SUBMITS_OPEN_MIN_VERSION, 1],
            ['a payer-submitted open', '9.11', 0],
        ] as const)('rechecks the deposit when the node refuses %s', async (_name, version, want) => {
            const s = await setup({ protoVersion: version, nodeOpener: true, reply: refused })
            await runSealed(s.deps, s.em, s.run)
            expect(s.rechecks.count).toBe(want)
            // The refusal still reaches the responder as it came.
            expect(s.responses).toHaveLength(1)
            expect(s.responses[0]![0]).toBe(402)
        })

        // TestRunSealed_FreeSolanaTurnRefusalRechecksNoDeposit: a free turn's
        // refusal is about no open.
        it('rechecks no deposit when the node refuses a free Solana turn', async () => {
            const s = await setup({ protoVersion: NODE_SUBMITS_OPEN_MIN_VERSION, nodeOpener: true, reply: refused })
            s.deps.rail = 'solana'
            ;(s.run.reserved.ticket as { max_price: number }).max_price = 0
            await runSealed(s.deps, s.em, s.run)
            expect(s.rechecks.count).toBe(0)
            expect(s.responses).toHaveLength(1)
            expect(s.responses[0]![0]).toBe(402)
        })

        it('rechecks on nothing but a plaintext 402 payment_verification_failed', async () => {
            const body = (code: string) => `{"error":{"message":"x","code":"${code}"}}`
            for (const reply of [
                () => new Response(body('ticket_invalid'), { status: 402 }),
                () => new Response(body('payment_verification_failed'), { status: 400 }),
                // A sealed answer is the node's own reply, not a pre-envelope refusal.
                () => new Response(body('payment_verification_failed'), { status: 402, headers: { [RESPONSE_KEY_HEADER]: 'K' } }),
                () => new Response('not json', { status: 402 }),
                () => new Response('{"done":true}'),
            ]) {
                const s = await setup({ protoVersion: NODE_SUBMITS_OPEN_MIN_VERSION, nodeOpener: true, reply })
                await runSealed(s.deps, s.em, s.run)
                expect(s.rechecks.count).toBe(0)
                expect(s.responses).toHaveLength(1)
            }
        })

        // The streamed forward's plain-body fallback is the same responder, as
        // Go hands forwardRawStream the wrapped nonStreamRespond.
        it('rechecks through the streamed forward’s buffered fallback too', async () => {
            const s = await setup({ protoVersion: NODE_SUBMITS_OPEN_MIN_VERSION, nodeOpener: true, stream: true })
            await runSealed(s.deps, s.em, s.run)
            const [, , buffered] = s.streamed[0]!
            const r = refused()
            await buffered(s.em, r, new Uint8Array(await r.arrayBuffer()))
            expect(s.rechecks.count).toBe(1)
        })
    })

    it('opens escrow, seals to the pinned recipient with the app-call txid, and sends it direct', async () => {
        const s = await setup()
        const ac = new AbortController()
        const key = s.run.reserved.responseKey.slice()
        await runSealed(s.deps, s.em, s.run, ac.signal)
        // SPEC § 3: the key is wiped once the turn is done with it.
        expect(s.run.reserved.responseKey).toEqual(new Uint8Array(key.length))

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
        expect(dec.admissionTag).toEqual(computeAdmissionTag(key, 'TKT1', 'APPCALLTXID', body))
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

    // A free turn has no open to say it committed, so the seal does: one that
    // won't seal never reached its node.
    it('reports no commit for a free Solana turn that won’t seal', async () => {
        const s = await setup({ responseKey: new Uint8Array(31) })
        s.deps.rail = 'solana'
        ;(s.run.reserved.ticket as { max_price: number }).max_price = 0
        await runSealed(s.deps, s.em, s.run)
        expect(s.em.order).toEqual(['reserved TKT1 9', 'fail wrap_request'])
        expect(s.em.committedArgs).toBeUndefined()
        expect(s.em.failed).toMatchObject({ code: 'wrap_request', paid: false })
        expect(s.sent).toEqual([])
        expect(s.released).toEqual(['TKT1'])
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

        // The guard is host code: one that throws while the failed open is
        // backed out still leaves the turn failed with the open's own error.
        it('fails the turn with the open error when the guard throws on release', async () => {
            const s = await setup({ openErr: noPool() })
            s.deps.spendGuard = {
                admit() {},
                reserve() {},
                settle() {},
                release() {
                    throw new Error('guard bug')
                },
            }
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.order).toEqual(['reserved TKT1 9', 'fail mbr_pool_exhausted'])
            expect(s.sent).toEqual([])
        })

        // A Solana payer funds SOL for ticket rent. Go's
        // TestOpenFailure_NamesTheRailsCoinAndPool.
        it("names a Solana payer's coin and pool", () => {
            const remedies = { fund: 'fund it' } as Remedies
            const short = new RentDepositUnaffordableError(1n, 4n, 2_000_000n, 5n, 'rent 1995000 + fee 5000')
            expect(openFailure('PAYER', 'devnet', remedies, short, 'solana').message).toBe(
                `zerosignal wallet PAYER needs more SOL (not USDC) to fund the prepaid ticket rent pool on devnet — ${short.message}. To fix it, fund it.`,
            )
            const below = new RentDepositBelowTargetError(7n)
            expect(openFailure('PAYER', 'devnet', remedies, below, 'solana').message).toBe(
                `zerosignal wallet PAYER needs more SOL (not USDC) to fund the prepaid ticket rent pool on devnet — ${below.message}. To fix it, fund it.`,
            )
            expect(openFailure('PAYER', 'testnet', remedies, below, 'algorand').message).toBe(
                `zerosignal wallet PAYER needs more ALGO (not USDC) to fund the prepaid ticket-MBR pool on testnet — ${below.message}. To fix it, fund it.`,
            )
        })

        // The sealed run hands its own rail to the message.
        it("names a Solana payer's coin and pool from the run's rail", async () => {
            const s = await setup({ openErr: new RentDepositUnaffordableError(1n, 4n, 2_000_000n, 5n, 'rent 1995000 + fee 5000') })
            s.deps.rail = 'solana'
            await runSealed(s.deps, s.em, s.run)
            expect(s.em.failed?.code).toBe('mbr_pool_underfunded')
            expect(s.em.failed!.message).toContain('needs more SOL (not USDC) to fund the prepaid ticket rent pool')
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

// TestSettleAckPoster
describe('settleAckPoster', () => {
    const ack: SettleAck = { ticket_id: 'TKT', settle_group: 'GROUP' }

    // A node's settle-ack route: it opens what arrives with its identity and
    // answers status.
    async function ackNode(status: number) {
        const id = await generateEphemeralIdentity()
        const got: { url: string; headers: Record<string, string>; ack: SettleAck }[] = []
        const fetch: Fetch = async (url, init) => {
            const headers = init!.headers as Record<string, string>
            // Which name the group came under is pinned by its own test below.
            const { neutralNames: _names, ...opened } = await openSettleAck(init!.body as Uint8Array, id.secret)
            got.push({ url: String(url), headers, ack: opened })
            return new Response(status === 202 ? null : '{"error":{"message":"x","code":"ticket_settled"}}', { status })
        }
        return { id, got, fetch }
    }

    const target = (protoVersion: string) =>
        testOperator({ id: 1, nodeId: 1, baseUrl: 'https://target.example.com', protoVersion } as Partial<Operator>)
    const relayOf = (id: number, proto_version: string) =>
        ({ operator_id: id, node_id: 1, proto_version, reachable: true }) as unknown as SelectionOperator

    it('builds no poster for an older node, so the payer broadcasts', async () => {
        const n = await ackNode(202)
        expect(settleAckPoster({ fetch: n.fetch }, target('9.11'), n.id.recipient, false)).toBeUndefined()
        expect(settleAckPoster({ fetch: n.fetch }, target(''), n.id.recipient, false)).toBeUndefined()
        expect(settleAckPoster({ fetch: n.fetch }, target(SETTLE_ACK_MIN_VERSION), '', false)).toBeUndefined()
    })

    it('posts the sealed ack straight to the node on a direct request', async () => {
        const n = await ackNode(202)
        const post = settleAckPoster({ fetch: n.fetch }, target(SETTLE_ACK_MIN_VERSION), n.id.recipient, false)!
        await post(ack)
        expect(n.got).toEqual([
            {
                url: `https://target.example.com${SETTLE_ACK_PATH}`,
                headers: { 'Content-Type': SEALED_SETTLE_ACK_CONTENT_TYPE, Accept: 'application/json' },
                ack,
            },
        ])
    })

    it.each([
        [SETTLE_ACK_MIN_VERSION, 'settle_group'],
        [RAIL_NEUTRAL_NAMES_MIN_VERSION, 'payment_settle'],
    ])('names the group for a %s node as %s', async (version, key) => {
        const id = await generateEphemeralIdentity()
        const plaintexts: Record<string, unknown>[] = []
        const fetch: Fetch = async (_url, init) => {
            const plain = await openReserveResponse(init!.body as Uint8Array, id)
            plaintexts.push(JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>)
            return new Response(null, { status: 202 })
        }
        await settleAckPoster({ fetch }, target(version), id.recipient, false)!(ack)
        expect(plaintexts).toEqual([{ ticket_id: 'TKT', [key]: 'GROUP' }])
    })

    it('treats a refusal as final, not a reason to broadcast', async () => {
        const n = await ackNode(409)
        const post = settleAckPoster({ fetch: n.fetch }, target(SETTLE_ACK_MIN_VERSION), n.id.recipient, false)!
        const err = await post(ack).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect(err).not.toBeInstanceOf(NoSettleAckRouteError)
        expect(String(err)).toMatch(/node answered 409 ticket_settled/)
        // 200 is not 202: the node did not take the ack.
        const ok = await ackNode(200)
        const post200 = settleAckPoster({ fetch: ok.fetch }, target(SETTLE_ACK_MIN_VERSION), ok.id.recipient, false)!
        await expect(post200(ack)).rejects.not.toBeInstanceOf(NoSettleAckRouteError)
    })

    it('reports a transport failure as final too', async () => {
        const fetch: Fetch = () => Promise.reject(new Error('connection reset'))
        const id = await generateEphemeralIdentity()
        const err = await settleAckPoster({ fetch }, target(SETTLE_ACK_MIN_VERSION), id.recipient, false)!(ack).catch((e: unknown) => e)
        expect(String(err)).toMatch(/settle ack: connection reset/)
        expect(err).not.toBeInstanceOf(NoSettleAckRouteError)
    })

    it('sends nothing on a relayed request when no relay serves the route', async () => {
        const n = await ackNode(202)
        const pools: SelectionOperator[][] = []
        const relays = {
            pool: async () => [relayOf(2, '9.11'), relayOf(3, '')],
            hopFor: (pool: SelectionOperator[]) => {
                pools.push(pool)
                return pool.length > 0 ? hopOf() : null
            },
        }
        const post = settleAckPoster({ fetch: n.fetch, relays }, target(SETTLE_ACK_MIN_VERSION), n.id.recipient, true)!
        await expect(post(ack)).rejects.toBeInstanceOf(NoSettleAckRouteError)
        // Only capable relays are offered to the picker.
        expect(pools).toEqual([[]])
        expect(n.got).toEqual([])

        // Without a relay source at all, the same: never a direct send.
        const bare = settleAckPoster({ fetch: n.fetch }, target(SETTLE_ACK_MIN_VERSION), n.id.recipient, true)!
        await expect(bare(ack)).rejects.toBeInstanceOf(NoSettleAckRouteError)
        expect(n.got).toEqual([])
    })

    it('rides a capable relay on a relayed request, still sealed to the target', async () => {
        const n = await ackNode(202)
        const capable = relayOf(4, SETTLE_ACK_MIN_VERSION)
        const pools: SelectionOperator[][] = []
        const hop = hopOf({ baseUrl: 'https://relay.example.com', targetId: 1, targetNodeId: 1, relayId: 4 })
        const relays = {
            pool: async () => [relayOf(2, '9.11'), capable],
            hopFor: (pool: SelectionOperator[], t: Operator) => {
                pools.push(pool)
                expect(t.id).toBe(1)
                return hop
            },
        }
        const post = settleAckPoster({ fetch: n.fetch, relays }, target(SETTLE_ACK_MIN_VERSION), n.id.recipient, true)!
        await post(ack)
        expect(pools).toEqual([[capable]])
        expect(n.got).toEqual([
            {
                url: 'https://relay.example.com/v1/zs/relay',
                headers: {
                    'Content-Type': SEALED_SETTLE_ACK_CONTENT_TYPE,
                    Accept: 'application/json',
                    [RELAY_TARGET_HEADER]: '1',
                    [RELAY_TARGET_NODE_HEADER]: '1',
                    [RELAY_PATH_HEADER]: SETTLE_ACK_PATH,
                    [RELAY_METHOD_HEADER]: 'POST',
                },
                ack,
            },
        ])
    })
})
