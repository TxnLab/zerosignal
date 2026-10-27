/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's credit wallet and the HTTP issuer, porting go/zs
// free_credits_test.go. Which reserve carries a credit is pinned by
// operator_vectors.json (operator.test.ts); dispatch's use of the wallet is in
// dispatch.test.ts.

import { describe, expect, it } from 'vitest'

import {
    CODE_CREDITS_EXHAUSTED,
    type Credit,
    DAY_KEY_PATH,
    ISSUE_PATH,
    MAX_ISSUE_BATCH,
    acceptedEpochs,
    epochAt,
    verifyCredit,
} from '@txnlab/zs-proto/freecredit'
import { base64 } from '@scure/base'

import { resolveConfig } from '../src/config.js'
import { ZsError } from '../src/errors.js'
import { testnet } from '../src/network.js'
import type { Logger, Signer } from '../src/ports.js'
import {
    type CreditIssuer,
    type CreditKey,
    type CreditStore,
    CreditWallet,
    CreditsExhaustedError,
    FREE_CREDIT_DEFAULTS,
    type HeldCredit,
    checkFreeCredits,
    httpCreditIssuer,
    memoryCreditStore,
} from '../src/solana/credits.js'
import { FakeIssuer, creditDep, noon } from './credit-issuer.js'

const quiet: Logger = { debug() {}, info() {}, warn() {}, error() {} }
const node = { op: 7, node: 2 }
const BATCH = FREE_CREDIT_DEFAULTS.batch
const MINUTE = 60_000
const HOUR = 60 * MINUTE

/** A memory store that counts what it holds. */
function countingStore(): CreditStore & { held(): number } {
    const inner = memoryCreditStore()
    let n = 0
    return {
        held: () => n,
        async take(key: CreditKey) {
            const c = await inner.take(key)
            if (c !== undefined) n--
            return c
        },
        async put(key: CreditKey, cs: Credit[]) {
            n += cs.length
            await inner.put(key, cs)
        },
    }
}

function wallet(issuers: Record<string, CreditIssuer>) {
    let now = noon
    const store = countingStore()
    const w = CreditWallet.for({ issuers, store }, 'solana', creditDep, () => now, quiet)!
    return {
        w,
        store,
        now: () => now,
        add(ms: number) {
            now += ms
        },
    }
}

async function verifies(h: HeldCredit | undefined, is: FakeIssuer, n = node): Promise<Credit> {
    expect(h).toBeDefined()
    await verifyCredit([is.publicKey], creditDep, n, acceptedEpochs(noon), h!.credit)
    return h!.credit
}

describe('the credit wallet', () => {
    it('fetches a batch for later turns', async () => {
        const is = new FakeIssuer()
        const { w } = wallet({ [is.key]: is })
        const seen = new Set<string>()
        for (let i = 0; i < BATCH; i++) {
            const h = await w.take([is.key], node)
            const c = await verifies(h, is)
            expect(seen.has(c.nonce)).toBe(false)
            seen.add(c.nonce)
            h!.spend()
        }
        expect([is.dayKeys, is.issues]).toEqual([1, 1])
        await verifies(await w.take([is.key], node), is)
        // The day key kept, and a second issue.
        expect([is.dayKeys, is.issues]).toEqual([1, 2])
    })

    it("keeps each node's credits apart", async () => {
        const is = new FakeIssuer()
        const { w } = wallet({ [is.key]: is })
        ;(await w.take([is.key], node))!.spend()
        const other = { op: 7, node: 3 }
        await verifies(await w.take([is.key], other), is, other)
        expect(is.issues).toBe(2)
    })

    it('fetches one batch at a time per node, which a burst shares', async () => {
        const is = new FakeIssuer()
        let open!: () => void
        is.gate = new Promise((r) => (open = r))
        const { w } = wallet({ [is.key]: is })
        const turns = Array.from({ length: 5 }, () => w.take([is.key], node))
        await new Promise((r) => setTimeout(r, 50))
        open()
        const got = (await Promise.all(turns)).filter((h) => h !== undefined)
        for (const h of got) await verifies(h, is)
        expect(is.issues).toBe(1)
        expect(got).toHaveLength(BATCH)
    })

    it('skips a failing issuer for a minute', async () => {
        const is = new FakeIssuer()
        is.err = new Error('down')
        const { w, add } = wallet({ [is.key]: is })
        expect(await w.take([is.key], node)).toBeUndefined()
        add(FREE_CREDIT_DEFAULTS.failureBackoff - 1000)
        await w.take([is.key], node)
        expect(is.dayKeys).toBe(1)
        add(1000)
        is.err = undefined
        await verifies(await w.take([is.key], node), is)
    })

    it.each([
        ['its Retry-After', 2 * HOUR, 2 * HOUR],
        ['no Retry-After: the next day', 0, 12 * HOUR],
        ['at least the failure backoff', 1000, FREE_CREDIT_DEFAULTS.failureBackoff],
        ['at most a day', 72 * HOUR, 24 * HOUR],
    ])('skips an exhausted issuer until %s', async (_name, retryAfter, want) => {
        const is = new FakeIssuer()
        is.exhausted = new CreditsExhaustedError(retryAfter)
        const { w, now } = wallet({ [is.key]: is })
        await w.take([is.key], node)
        expect(w.skippedUntil(is.key) - now()).toBe(want)
    })

    it('falls through to the next issuer', async () => {
        const down = new FakeIssuer()
        const up = new FakeIssuer()
        down.err = new Error('down')
        const { w } = wallet({ [down.key]: down, [up.key]: up })
        const unknown = base64.encode(new Uint8Array(32))
        await verifies(await w.take([unknown, down.key, up.key], node), up)
    })

    const impostor = new FakeIssuer()
    const otherDayKey = new FakeIssuer().signer(epochAt(noon)).key
    const otherDay = (f: FakeIssuer, days: number) => {
        const s = f.signer(epochAt(noon) + days)
        f.certFor = () => s.cert
        f.signWith = s.key
    }
    it.each<[string, (f: FakeIssuer) => void]>([
        ['a day key another issuer certified', (f) => (f.certFor = () => impostor.signer(epochAt(noon)).cert)],
        // Signed under the day key served, so only the epoch check refuses it.
        ["yesterday's day key", (f) => otherDay(f, -1)],
        ['a day key for another day', (f) => otherDay(f, 1)],
        [
            'a tampered certificate',
            (f) =>
                (f.certFor = (c) => {
                    const sig = base64.decode(c.day_key_sig)
                    sig[0]! ^= 1
                    return { ...c, day_key_sig: base64.encode(sig) }
                }),
        ],
        ['signatures under another day key', (f) => (f.signWith = otherDayKey)],
    ])('refuses %s, and benches the issuer', async (_name, set) => {
        const is = new FakeIssuer()
        set(is)
        const { w, store, now } = wallet({ [is.key]: is })
        expect(await w.take([is.key], node)).toBeUndefined()
        expect(store.held()).toBe(0)
        expect(w.skippedUntil(is.key)).toBeGreaterThan(now())
    })

    it('keeps a partial batch', async () => {
        const is = new FakeIssuer()
        is.signOnly = 2
        const { w, store } = wallet({ [is.key]: is })
        await verifies(await w.take([is.key], node), is)
        expect(store.held()).toBe(1)
    })

    it('takes back a credit the turn did not use, but not one spent or refused', async () => {
        const is = new FakeIssuer()
        const { w, store } = wallet({ [is.key]: is })
        let h = (await w.take([is.key], node))!
        await h.giveBack()
        await h.giveBack()
        expect(store.held()).toBe(BATCH)
        h = (await w.take([is.key], node))!
        h.spend()
        await h.giveBack()
        h = (await w.take([is.key], node))!
        h.drop()
        await h.giveBack()
        expect(store.held()).toBe(BATCH - 2)
    })

    it("mints under each day's key", async () => {
        const is = new FakeIssuer()
        const { w, add } = wallet({ [is.key]: is })
        const first = (await w.take([is.key], node))!
        add(24 * HOUR)
        const second = await w.take([is.key], node)
        expect(second?.credit.epoch).toBe(first.credit.epoch + 1)
        expect(is.dayKeys).toBe(2)
    })

    it('sends a node that refused a credit none for the rest of the day', async () => {
        const is = new FakeIssuer()
        const { w, add } = wallet({ [is.key]: is })
        w.refuse(node)
        expect(await w.take([is.key], node)).toBeUndefined()
        expect(is.dayKeys).toBe(0)
        await verifies(await w.take([is.key], { op: 7, node: 3 }), is, { op: 7, node: 3 })
        add(24 * HOUR)
        expect(await w.take([is.key], node)).toBeDefined()
    })

    it("bounds a fetch, and doesn't bench the issuer for the caller's abort", async () => {
        const is = new FakeIssuer()
        is.gate = new Promise(() => {})
        const { w, now } = wallet({ [is.key]: is })
        w.fetchTimeout = 20
        expect(await w.take([is.key], node, AbortSignal.timeout(5))).toBeUndefined()
        expect(w.skippedUntil(is.key)).toBe(0)
        const start = Date.now()
        expect(await w.take([is.key], node)).toBeUndefined()
        expect(Date.now() - start).toBeLessThan(1000)
        expect(w.skippedUntil(is.key)).toBeGreaterThan(now())
    })

    it('lets a turn waiting on another fetch go when its caller aborts', async () => {
        const is = new FakeIssuer()
        let open!: () => void
        is.gate = new Promise((r) => (open = r))
        const { w } = wallet({ [is.key]: is })
        const leader = w.take([is.key], node)
        await new Promise((r) => setTimeout(r, 20))
        const start = Date.now()
        expect(await w.take([is.key], node, AbortSignal.timeout(10))).toBeUndefined()
        expect(Date.now() - start).toBeLessThan(1000)
        open()
        await verifies(await leader, is)
    })
})

describe('the memory credit store', () => {
    it('forgets a day once a day two later is put', async () => {
        const s = memoryCreditStore()
        const key: CreditKey = { deployment: 'd', op: 7, node: 2, epoch: 100, issuer: 'k' }
        const c = { nonce: 'n' } as Credit
        await s.put(key, [c])
        const yesterday = key
        await s.put({ ...key, epoch: 101 }, [c])
        expect(await s.take(yesterday)).toBeDefined()
        await s.put(yesterday, [c])
        await s.put({ ...key, epoch: 102 }, [c])
        expect(await s.take(yesterday)).toBeUndefined()
    })
})

describe('the HTTP issuer', () => {
    it('speaks the issue wire, carries the gate, and reads a spent cap with its Retry-After', async () => {
        const is = new FakeIssuer()
        let exhausted = false
        const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
            const url = new URL(String(input))
            if (new Headers(init?.headers).get('X-Gate') !== 'token') return new Response('no gate', { status: 403 })
            const req = JSON.parse(String(init?.body)) as { deployment: string; epoch: number; blinded?: string[] }
            if (req.deployment !== base64.encode(creditDep)) return new Response('bad request', { status: 400 })
            switch (url.pathname) {
                case DAY_KEY_PATH:
                    return Response.json(await is.dayKey(creditDep, req.epoch))
                case ISSUE_PATH: {
                    if (exhausted) {
                        return Response.json(
                            { error: { code: CODE_CREDITS_EXHAUSTED, message: 'spent' } },
                            { status: 429, headers: { 'Retry-After': '120' } },
                        )
                    }
                    const sigs = await is.issue(
                        creditDep,
                        req.epoch,
                        req.blinded!.map((b) => base64.decode(b)),
                    )
                    return Response.json({ signatures: sigs.map((s) => base64.encode(s)) })
                }
            }
            return new Response('not found', { status: 404 })
        }
        const port = httpCreditIssuer({
            url: 'https://issuer.example/',
            fetch,
            headers: (h) => h.set('X-Gate', 'token'),
        })
        const { w } = wallet({ [is.key]: port })
        await verifies(await w.take([is.key], node), is)

        exhausted = true
        const err = await port.issue(creditDep, epochAt(noon), [new Uint8Array([1])]).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(CreditsExhaustedError)
        expect((err as CreditsExhaustedError).retryAfterMs).toBe(2 * MINUTE)
        await expect(httpCreditIssuer({ url: 'https://issuer.example', fetch }).dayKey(creditDep, 1)).rejects.toThrow(
            /403/,
        )
        const gate = new Error('no token yet')
        const hooked = httpCreditIssuer({
            url: 'https://issuer.example',
            fetch,
            headers: () => {
                throw gate
            },
        })
        await expect(hooked.dayKey(creditDep, 1)).rejects.toMatchObject({ cause: gate })
    })

    // Go's TestHTTPCreditIssuer_CapsTheAnswerAndReadsOnlyA429AsExhausted.
    it('reads no more than its cap, and takes only a 429 for a spent cap', async () => {
        // Valid base64 past the cap: read whole, it would parse.
        const big = 'A'.repeat((1 << 20) + 16)
        const fetch = async (input: RequestInfo | URL): Promise<Response> =>
            new URL(String(input)).pathname === ISSUE_PATH
                ? new Response(`{"signatures":["${big}"]}`)
                : Response.json({ error: { code: CODE_CREDITS_EXHAUSTED, message: 'no' } }, { status: 500 })
        const port = httpCreditIssuer({ url: 'https://issuer.example', fetch })
        await expect(port.issue(creditDep, 1, [new Uint8Array([1])])).rejects.toThrow()
        const err = await port.dayKey(creditDep, 1).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect(err).not.toBeInstanceOf(CreditsExhaustedError)
        const key = new FakeIssuer().key
        const { w, now } = wallet({ [key]: port })
        await w.take([key], node)
        expect(w.skippedUntil(key) - now()).toBe(FREE_CREDIT_DEFAULTS.failureBackoff)
    })
})

describe('a held credit', () => {
    // Go's TestHeldCredit_GiveBackOutlivesTheCallerButNotAStuckStore.
    it('is given back within the fetch bound, even to a store that never answers', async () => {
        const is = new FakeIssuer()
        let stuck = false
        const inner = memoryCreditStore()
        const store: CreditStore = {
            take: (k) => inner.take(k),
            put: (k, cs) => (stuck ? new Promise(() => {}) : inner.put(k, cs)),
        }
        const w = CreditWallet.for({ issuers: { [is.key]: is }, store }, 'solana', creditDep, () => noon, quiet)!
        w.fetchTimeout = 20
        const h = (await w.take([is.key], node))!
        stuck = true
        const start = Date.now()
        await h.giveBack()
        expect(Date.now() - start).toBeLessThan(1000)
    })
})

describe('the config', () => {
    const is = new FakeIssuer()

    it.each<[string, Parameters<typeof checkFreeCredits>[0], RegExp]>([
        ['a key that is not 32 bytes', { issuers: { AAAA: is } }, /32 bytes/],
        ['no way to reach the issuer', { issuers: { [is.key]: undefined as unknown as CreditIssuer } }, /not set/],
        ['a batch past the issue cap', { issuers: {}, batch: MAX_ISSUE_BATCH + 1 }, /batch/],
    ])('refuses %s', (_name, fc, want) => {
        let err: unknown
        try {
            checkFreeCredits(fc)
        } catch (e) {
            err = e
        }
        expect(err).toBeInstanceOf(ZsError)
        expect((err as Error).message).toMatch(want)
    })

    it('warns that credits are Solana’s, and builds no wallet off Solana or without a deployment', () => {
        const signer: Signer = {
            address: 'PAYER',
            signBytes: async () => new Uint8Array(),
            signTransactions: async () => [],
        }
        const cfg = { issuers: { [is.key]: is } }
        // The issue cap itself is a batch an issuer answers.
        expect(() => checkFreeCredits({ ...cfg, batch: MAX_ISSUE_BATCH })).not.toThrow()
        const c = resolveConfig({ signer, network: testnet(), freeCredits: cfg })
        expect(c.warnings.join('\n')).toMatch(/freeCredits/)
        expect(CreditWallet.for(cfg, 'algorand', creditDep, Date.now, quiet)).toBeUndefined()
        expect(CreditWallet.for(cfg, 'solana', new Uint8Array(32), Date.now, quiet)).toBeUndefined()
        expect(CreditWallet.for(cfg, 'solana', undefined, Date.now, quiet)).toBeUndefined()
        expect(CreditWallet.for({ issuers: {} }, 'solana', creditDep, Date.now, quiet)).toBeUndefined()
    })
})
