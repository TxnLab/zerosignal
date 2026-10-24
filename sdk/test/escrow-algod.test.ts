/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// AlgodEscrowChain against a fake algod, porting go/escrow client_test.go's
// composer cases: what reaches the wire is decoded and read back, so the
// fee, the references and the ABI args are the ones algod would see.

import { readFileSync } from 'node:fs'

import algosdk, { ABIMethod, OnApplicationComplete, type ABIValue } from 'algosdk'
import {
    NODE_RECORD_SIZE,
    OPERATOR_RECORD_SIZE,
    SECONDS_PER_DAY,
    TICKET_RECORD_SIZE,
    decodeNodeRecord,
    decodeOperatorRecord,
    decodeTicketRecord,
    freeQuotaBoxKey,
    nodeBoxKey,
    operatorBoxKey,
    ticketBoxKey,
} from '@txnlab/zs-proto/escrow'
import { beforeEach, describe, expect, it } from 'vitest'

import { RESOLVE_FROZEN_SIGNATURE, programHasMethod, settleOutcomeOf } from '../src/escrow/algod.js'
import { ESCROW_METHOD_SIGNATURES } from '../src/escrow/generated/abi.js'
import { APP_SPEC } from '../src/escrow/generated/ZeroSignalEscrowClient.js'
import {
    APPROVAL_ASSERT,
    AlgodEscrowChain,
    ApprovalError,
    ProtestReason,
    SignerAddressError,
    type Signer,
    approvalErrorMessage,
} from '../src/index.js'

const APP = 1234n
const USDC = 31566704n
const MIN_FEE = 1000n
const NOW_MS = 1_780_000_000_000
const TODAY = BigInt(Math.floor(NOW_MS / 1000)) / SECONDS_PER_DAY

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const utf8 = (s: string) => new TextEncoder().encode(s)
const RETURN_PREFIX = new Uint8Array([0x15, 0x1f, 0x7c, 0x75])

type Global = { type: 1; bytes: Uint8Array } | { type: 2; uint: bigint }

function httpError(status: number, message: string) {
    return Object.assign(new Error(`Network request error. Received status ${status}: ${message}`), {
        response: { status, body: utf8(JSON.stringify({ message })), headers: {} },
    })
}

const json = (v: unknown) => ({ status: 200, body: utf8(JSON.stringify(v)), headers: { 'content-type': 'application/json' } })

/** A readonly's answer: a return value, or the group's eval failure. */
type SimAnswer = { value?: ABIValue; failure?: string }

/** algod as the chain reaches it, with every request it saw. */
class FakeAlgod implements algosdk.BaseHTTPClient {
    globals = new Map<string, Global>()
    approvalProgram = new Uint8Array()
    /** Box values by base64 name; a number is the status a read fails with. */
    boxes = new Map<string, Uint8Array | number>()
    accounts = new Map<string, { amount: bigint; minBalance: bigint; apps: bigint[] }>()
    sent: Uint8Array[] = []
    sendError: string | undefined
    simAnswers: Record<string, SimAnswer> = {}
    simulated: { method: string; sender: string; accounts: string[] }[] = []
    /** Pool answers by txid; a number is the status a read fails with. */
    pending = new Map<string, { confirmedRound?: bigint; poolError: string } | number>()
    paths: string[] = []
    /** Each request's signal, as fetch would get it. */
    signals: (AbortSignal | undefined)[] = []
    /** While set, every request waits for it, or for its signal, as fetch does. */
    gate: Promise<void> | undefined

    async #enter(path: string, opts?: Record<string, unknown>) {
        this.paths.push(path)
        const signal = opts?.signal as AbortSignal | undefined
        this.signals.push(signal)
        if (this.gate === undefined) return
        const gate = this.gate
        await new Promise<void>((resolve, reject) => {
            signal?.addEventListener('abort', () => reject(signal.reason), { once: true })
            void gate.then(resolve)
        })
    }

    async get(path: string, query?: Record<string, string>, _h?: unknown, opts?: Record<string, unknown>) {
        await this.#enter(path, opts)
        if (path === '/v2/transactions/params') {
            return json({
                'consensus-version': 'future',
                fee: 0,
                'genesis-hash': b64(new Uint8Array(32)),
                'genesis-id': 'dev-v1',
                'last-round': 100,
                'min-fee': Number(MIN_FEE),
            })
        }
        if (path === `/v2/applications/${APP}/box`) {
            const name = String(query?.name).replace(/^b64:/, '')
            const v = this.boxes.get(name)
            if (v === undefined) throw httpError(404, 'box not found')
            if (typeof v === 'number') throw httpError(v, 'algod unavailable')
            return json({ name, round: 100, value: b64(v) })
        }
        const pending = /^\/v2\/transactions\/pending\/([A-Z2-7]+)$/.exec(path)
        if (pending) {
            const p = this.pending.get(pending[1]!)
            if (p === undefined) throw httpError(404, 'txn not found')
            if (typeof p === 'number') throw httpError(p, 'algod unavailable')
            const resp = new algosdk.modelsv2.PendingTransactionResponse({ ...p, txn: pendingTxn() })
            return { status: 200, body: algosdk.encodeMsgpack(resp), headers: { 'content-type': 'application/msgpack' } }
        }
        if (path === `/v2/applications/${APP}`) {
            const state = [...this.globals].map(([k, v]) => ({
                key: b64(utf8(k)),
                value: v.type === 1 ? { type: 1, bytes: b64(v.bytes), uint: 0 } : { type: 2, bytes: '', uint: Number(v.uint) },
            }))
            const params = { 'approval-program': b64(this.approvalProgram), 'clear-state-program': '', creator: OTHER, 'global-state': state }
            return json({ id: Number(APP), params })
        }
        const acct = /^\/v2\/accounts\/([A-Z2-7]+)$/.exec(path)
        if (acct) {
            const a = this.accounts.get(acct[1]!) ?? { amount: 0n, minBalance: 100_000n, apps: [] }
            return json({
                address: acct[1],
                amount: Number(a.amount),
                'amount-without-pending-rewards': Number(a.amount),
                'min-balance': Number(a.minBalance),
                'pending-rewards': 0,
                rewards: 0,
                round: 100,
                status: 'Offline',
                'total-apps-opted-in': a.apps.length,
                'total-assets-opted-in': 0,
                'total-created-apps': 0,
                'total-created-assets': 0,
                'apps-local-state': a.apps.map((id) => ({ id: Number(id), schema: { 'num-byte-slice': 0, 'num-uint': 6 } })),
            })
        }
        throw httpError(404, `no route ${path}`)
    }

    async post(path: string, data: Uint8Array, _q?: unknown, _h?: unknown, opts?: Record<string, unknown>) {
        await this.#enter(path, opts)
        if (path === '/v2/transactions') {
            this.sent.push(data)
            if (this.sendError !== undefined) throw httpError(400, this.sendError)
            return json({ txId: 'SENT' })
        }
        if (path === '/v2/transactions/simulate') return this.#simulate(data)
        throw httpError(404, `no route ${path}`)
    }

    async delete(): Promise<never> {
        throw new Error('unused')
    }

    #simulate(data: Uint8Array) {
        const req = algosdk.decodeMsgpack(data, algosdk.modelsv2.SimulateRequest)
        const stxn = req.txnGroups[0]!.txns[0]!
        const call = stxn.txn.applicationCall!
        const [name, m] = methodBySelector(call.appArgs[0]!)
        this.simulated.push({
            method: name,
            sender: stxn.txn.sender.toString(),
            accounts: call.accounts.map((a) => a.toString()),
        })
        const answer = this.simAnswers[name] ?? {}
        const logs =
            answer.value === undefined || m.returns.type === 'void'
                ? []
                : [concat(RETURN_PREFIX, m.returns.type.encode(answer.value))]
        const resp = new algosdk.modelsv2.SimulateResponse({
            version: 2,
            lastRound: 100,
            txnGroups: [
                new algosdk.modelsv2.SimulateTransactionGroupResult({
                    ...(answer.failure === undefined ? {} : { failureMessage: answer.failure }),
                    txnResults: [
                        new algosdk.modelsv2.SimulateTransactionResult({
                            txnResult: new algosdk.modelsv2.PendingTransactionResponse({ poolError: '', txn: stxn, logs }),
                        }),
                    ],
                }),
            ],
        })
        return { status: 200, body: algosdk.encodeMsgpack(resp), headers: { 'content-type': 'application/msgpack' } }
    }
}

/** Any signed transaction: the pool answer carries one, and settleOutcome reads none of it. */
function pendingTxn(): algosdk.SignedTransaction {
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: PAYER,
        receiver: PAYER,
        amount: 0,
        suggestedParams: { fee: 0, flatFee: true, minFee: MIN_FEE, firstValid: 1, lastValid: 2, genesisHash: new Uint8Array(32), genesisID: 'dev-v1' },
    })
    return new algosdk.SignedTransaction({ txn })
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length + b.length)
    out.set(a)
    out.set(b, a.length)
    return out
}

function methodBySelector(sel: Uint8Array): [string, ABIMethod] {
    for (const [name, sig] of Object.entries(ESCROW_METHOD_SIGNATURES)) {
        const m = ABIMethod.fromSignature(sig)
        if (b64(m.getSelector()) === b64(sel)) return [name, m]
    }
    throw new Error('unknown selector')
}

/** The signed txns of one submit, split from algod's concatenated body. */
function decodeSent(raw: Uint8Array): algosdk.SignedTransaction[] {
    const out: algosdk.SignedTransaction[] = []
    let rest = raw
    while (rest.length > 0) {
        let n = 1
        for (; n <= rest.length; n++) {
            try {
                out.push(algosdk.decodeSignedTransaction(rest.subarray(0, n)))
                break
            } catch {
                // Not a whole txn yet.
            }
        }
        rest = rest.subarray(n)
    }
    return out
}

const lastSent = (fake: FakeAlgod) => decodeSent(fake.sent.at(-1)!)
const argsOf = (t: algosdk.Transaction) => t.applicationCall!.appArgs
const decodeArg = (m: string, i: number, raw: Uint8Array) => {
    const arg = ABIMethod.fromSignature(ESCROW_METHOD_SIGNATURES[m]!).args[i]!
    return (arg.type as algosdk.ABIType).decode(raw)
}

const PAYER_ACCT = algosdk.generateAccount()
const PAYER = PAYER_ACCT.addr.toString()
const OWNER = algosdk.generateAccount().addr.toString()
const OTHER = algosdk.generateAccount().addr.toString()
const TREASURY = algosdk.generateAccount().addr.toString()
const TICKET = utf8('ticket-id-16byte')
const DIGEST = utf8('digest-32-bytes-receipt-xxxxxxxx')

const signer: Signer = {
    address: PAYER,
    signTransactions: algosdk.makeBasicAccountTransactionSigner(PAYER_ACCT),
    signBytes: () => Promise.reject(new Error('unused')),
}

let fake: FakeAlgod
let chain: AlgodEscrowChain

beforeEach(() => {
    fake = new FakeAlgod()
    fake.globals.set('usdc', { type: 2, uint: USDC })
    fake.globals.set('trea', { type: 1, bytes: algosdk.decodeAddress(TREASURY).publicKey })
    fake.globals.set('pfee', { type: 2, uint: 250n })
    chain = newChain()
})

function newChain(over: { signer?: Signer; requestTimeoutMs?: number } = {}): AlgodEscrowChain {
    // The server URL is unused once a BaseHTTPClient is given.
    return new AlgodEscrowChain({ algod: new algosdk.Algodv2(fake, ''), appId: APP, signer, clock: () => NOW_MS, ...over })
}

function deferred() {
    let resolve!: () => void
    const promise = new Promise<void>((r) => {
        resolve = r
    })
    return { promise, resolve }
}

// A box value with one u64 written at off, checked against the decoder so a
// layout change fails here rather than testing the wrong field.
function u64At(size: number, off: number, v: bigint): Uint8Array {
    const b = new Uint8Array(size)
    new DataView(b.buffer).setBigUint64(off, v)
    return b
}

function ticketBox(pendingAmount: bigint, maxPrice: bigint, owner: string): Uint8Array {
    const b = new Uint8Array(TICKET_RECORD_SIZE)
    const v = new DataView(b.buffer)
    b.set(algosdk.decodeAddress(owner).publicKey, 48)
    v.setBigUint64(112, maxPrice)
    v.setBigUint64(145, pendingAmount)
    const rec = decodeTicketRecord(b)
    expect([rec.pendingAmount, rec.maxPrice, rec.operatorOwnerAddr]).toEqual([pendingAmount, maxPrice, owner])
    return b
}

function nodeBox(bucketsLastDay: bigint): Uint8Array {
    const b = u64At(NODE_RECORD_SIZE, 386, bucketsLastDay)
    expect(decodeNodeRecord(7n, 1n, b).bucketsLastDay).toBe(bucketsLastDay)
    return b
}

function operatorBox(bucketsLastDay: bigint): Uint8Array {
    const b = u64At(OPERATOR_RECORD_SIZE, 161, bucketsLastDay)
    expect(decodeOperatorRecord(7n, b).bucketsLastDay).toBe(bucketsLastDay)
    return b
}

const settleArgs = {
    amountCharged: 50_000n,
    receiptDigest: DIGEST,
    ttftMs: 1200n,
    decodeMs: 300n,
    inputTokens: 250n,
    outputTokens: 750n,
    outputUsageType: 1,
    auxOutputUsageType: 0,
    auxOutputCount: 0n,
}
const settleCall = (over: Partial<{ amountCharged: bigint; maxPrice: bigint }> = {}) => ({
    ticketIdRaw: TICKET,
    args: { ...settleArgs, amountCharged: over.amountCharged ?? settleArgs.amountCharged },
    maxPrice: over.maxPrice ?? 100_000n,
    payer: PAYER,
    operatorOwnerAddr: OWNER,
    operatorId: 7n,
    nodeId: 1n,
})

// Go's settleOutcomeOf, case for case: the journal row goes only once the
// settle is confirmed, and a pool error leaves it for the sweep.
describe('settleOutcomeOf', () => {
    it('reads the pool answer as Go does', () => {
        expect(settleOutcomeOf({ poolError: '' })).toBe('pending')
        expect(settleOutcomeOf({ confirmedRound: 0n, poolError: '' })).toBe('pending')
        expect(settleOutcomeOf({ confirmedRound: 1n, poolError: '' })).toBe('landed')
        expect(settleOutcomeOf({ poolError: 'overspend' })).toBe('dropped')
        expect(settleOutcomeOf({ confirmedRound: 1n, poolError: 'overspend' })).toBe('landed')
    })
})

// TestOpenHandle_SettleOutcome: the txid reaches algod's pool read, the
// caller's signal rides it, and a failed read is no outcome.
describe('AlgodEscrowChain settleOutcome', () => {
    const TXID = 'A'.repeat(52)

    it('reads the pool answer for the settle it was given', async () => {
        fake.pending.set(TXID, { confirmedRound: 7n, poolError: '' })
        const ac = new AbortController()
        expect(await chain.settleOutcome(TXID, ac.signal)).toBe('landed')
        expect(fake.paths).toEqual([`/v2/transactions/pending/${TXID}`])
        ac.abort()
        expect(fake.signals.at(-1)?.aborted).toBe(true)
        fake.pending.set(TXID, { poolError: 'overspend' })
        expect(await chain.settleOutcome(TXID)).toBe('dropped')
    })

    it('passes a failed read on', async () => {
        fake.pending.set(TXID, 503)
        await expect(chain.settleOutcome(TXID)).rejects.toThrow(/503/)
    })
})

describe('AlgodEscrowChain config', () => {
    it('reads the deployment from the globals once', async () => {
        fake.globals.set('grace', { type: 2, uint: 600n })
        expect(await chain.config()).toEqual({
            appId: APP,
            appAddress: algosdk.getApplicationAddress(APP).toString(),
            usdcAssetId: USDC,
            settlementGraceDefault: 600n,
            resolvesFrozen: false,
        })
        await chain.config()
        expect(fake.paths.filter((p) => p === `/v2/applications/${APP}`)).toHaveLength(1)
    })

    // Go's TestResolveFrozenSelector: pinned as a literal, since Go derives
    // its own from the same signature.
    it('derives the resolveFrozen selector Go does', () => {
        expect(Buffer.from(ABIMethod.fromSignature(RESOLVE_FROZEN_SIGNATURE).getSelector()).toString('hex')).toBe('5825a047')
    })

    // Go's TestReadGlobals_ProbesResolveFrozen: the same application read
    // answers whether the program routes resolveFrozen.
    it.each([
        ['routes resolveFrozen', true, true],
        ['routes other methods only', false, false],
    ] as const)('probes the approval program for resolveFrozen: %s', async (_name, withIt, want) => {
        const sel = (sig: string) => [0x80, 0x04, ...ABIMethod.fromSignature(sig).getSelector()]
        const settle = sel(ESCROW_METHOD_SIGNATURES.settle!)
        fake.approvalProgram = Uint8Array.from([0x0a, 0x31, 0x1b, 0x41, ...settle, ...(withIt ? sel(RESOLVE_FROZEN_SIGNATURE) : [])])
        expect((await newChain().config()).resolvesFrozen).toBe(want)
    })

    // Go's TestProgramHasMethod_EmbeddedApprovalRoutesResolveFrozen: the
    // shared ARC-56 is the deployed program, compiled as it ships. The
    // generated client is minimal and carries no byteCode, so read the file.
    it('finds resolveFrozen in the shipped approval program', () => {
        const spec = JSON.parse(readFileSync(new URL('../../go/escrow/ZeroSignalEscrow.arc56.json', import.meta.url), 'utf8')) as {
            byteCode?: { approval?: string }
        }
        const approval = Buffer.from(spec.byteCode?.approval ?? '', 'base64')
        expect(approval.length).toBeGreaterThan(0)
        expect(programHasMethod(new Uint8Array(approval), RESOLVE_FROZEN_SIGNATURE)).toBe(true)
    })

    it('finds a method only where its whole selector sits', () => {
        const s = ABIMethod.fromSignature(RESOLVE_FROZEN_SIGNATURE).getSelector()
        expect(programHasMethod(undefined, RESOLVE_FROZEN_SIGNATURE)).toBe(false)
        expect(programHasMethod(new Uint8Array(), RESOLVE_FROZEN_SIGNATURE)).toBe(false)
        expect(programHasMethod(s.slice(0, 3), RESOLVE_FROZEN_SIGNATURE)).toBe(false)
        expect(programHasMethod(Uint8Array.from([...s.slice(0, 3), 0, s[3]!]), RESOLVE_FROZEN_SIGNATURE)).toBe(false)
        expect(programHasMethod(s, RESOLVE_FROZEN_SIGNATURE)).toBe(true)
        expect(programHasMethod(Uint8Array.from([1, 2, ...s]), RESOLVE_FROZEN_SIGNATURE)).toBe(true)
    })

    // Go's readGlobals: an absent grace reads 0, a mistyped one is fatal.
    it('reads an absent grace as 0 and refuses a mistyped one', async () => {
        expect((await chain.config()).settlementGraceDefault).toBe(0n)
        fake.globals.set('grace', { type: 1, bytes: new Uint8Array(8) })
        await expect(newChain().config()).rejects.toThrow('escrow: settlementGraceDefault global has type 1, want 2 (uint)')
    })

    it('refuses a deployment missing usdc or the treasury, and reads again after a failure', async () => {
        fake.globals.delete('trea')
        await expect(chain.config()).rejects.toThrow(`escrow: treasury global not found on app ${APP}`)
        fake.globals.set('trea', { type: 2, uint: 1n })
        await expect(chain.config()).rejects.toThrow('escrow: treasury global has type 2, want 1 (bytes)')
        fake.globals.set('trea', { type: 1, bytes: new Uint8Array(31) })
        await expect(chain.config()).rejects.toThrow('escrow: treasury raw bytes len = 31, want 32')
        fake.globals.set('trea', { type: 1, bytes: algosdk.decodeAddress(TREASURY).publicKey })
        fake.globals.set('usdc', { type: 2, uint: 0n })
        await expect(chain.config()).rejects.toThrow('escrow: usdcAssetId global is 0')
        fake.globals.set('usdc', { type: 1, bytes: new Uint8Array(8) })
        await expect(chain.config()).rejects.toThrow('escrow: usdcAssetId global has type 1, want 2 (uint)')
        fake.globals.delete('usdc')
        await expect(chain.config()).rejects.toThrow(`escrow: usdcAssetId global not found on app ${APP}`)
        fake.globals.set('usdc', { type: 2, uint: USDC })
        expect((await chain.config()).usdcAssetId).toBe(USDC)
    })

    // Go's RefreshConfig: each read is fatal but a quota-less app's, and kept.
    it('refreshConfig reads the ticket MBR, the globals and the quota term, and keeps them', async () => {
        fake.simAnswers.mbrForTicket = { value: 0n }
        fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
        await expect(chain.refreshConfig()).rejects.toThrow('escrow: mbrForTicket returned 0')
        fake.simAnswers.mbrForTicket = { value: 115_300n }
        fake.globals.delete('usdc')
        await expect(chain.refreshConfig()).rejects.toThrow('usdcAssetId global not found')
        fake.globals.set('usdc', { type: 2, uint: USDC })
        fake.simAnswers.mbrForFreeQuota = { failure: 'txn dead' }
        await expect(chain.refreshConfig()).rejects.toThrow('txn dead')
        fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
        await chain.refreshConfig()
        const before = fake.simulated.length
        await chain.ticketMbr()
        expect(await chain.freeQuotaMbrDue(PAYER)).toBe(22_500n)
        await chain.config()
        expect(fake.simulated.length).toBe(before)

        const c = newChain()
        fake.simAnswers.mbrForFreeQuota = { failure: 'logic eval error: err opcode executed. Details: app=1234, pc=512' }
        await c.refreshConfig()
        await expect(c.refreshConfig(AbortSignal.abort(new Error('stop')))).rejects.toThrow('stop')
    })

    // The MBR reads take no signal of their own, so only the wait can stop.
    it('refreshConfig stops waiting on its signal while a read is in flight', async () => {
        fake.simAnswers.mbrForTicket = { value: 115_300n }
        fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
        const stalled = deferred()
        // First stalled in the ticket MBR read; then, with it and the globals
        // already kept, in the free-quota read.
        for (const warm of [false, true]) {
            const c = newChain()
            if (warm) {
                await c.ticketMbr()
                await c.config()
            }
            fake.gate = stalled.promise
            const ctrl = new AbortController()
            const p = c.refreshConfig(ctrl.signal)
            await new Promise((r) => setTimeout(r, 0))
            ctrl.abort(new Error('stop'))
            await expect(p).rejects.toThrow('stop')
            fake.gate = undefined
        }
        stalled.resolve()
    })

    // A fee rotation reaches the next read; zero or absent is no fee.
    it('reads the protocol fee live', async () => {
        expect(await chain.protocolFeeBps()).toBe(250)
        fake.globals.set('pfee', { type: 2, uint: 300n })
        expect(await chain.protocolFeeBps()).toBe(300)
        fake.globals.delete('pfee')
        expect(await chain.protocolFeeBps()).toBe(0)
        fake.globals.set('pfee', { type: 1, bytes: new Uint8Array(8) })
        await expect(chain.protocolFeeBps()).rejects.toThrow('protocolFeeBps global has type 1')
    })

    // As Go's TestReadGlobals_Paused: absent is not paused, and a slot of the
    // wrong type is a config error rather than a guess.
    it('reads the paused flag with the globals', async () => {
        expect(await chain.paused()).toBe(false)
        fake.globals.set('paus', { type: 2, uint: 1n })
        expect(await newChain().paused()).toBe(true)
        fake.globals.set('paus', { type: 2, uint: 2n })
        expect(await newChain().paused()).toBe(true)
        fake.globals.set('paus', { type: 2, uint: 0n })
        expect(await newChain().paused()).toBe(false)
        fake.globals.set('paus', { type: 1, bytes: new Uint8Array([1]) })
        await expect(newChain().paused()).rejects.toThrow('paused global has type 1')
        await expect(newChain().config()).rejects.toThrow('paused global has type 1')
    })

    // As Go's TestPausedKeyMatchesARC56: a renamed global would otherwise read
    // as never paused.
    it('reads the paused key the contract declares', () => {
        expect(APP_SPEC.state.keys.global.paused).toMatchObject({ key: 'cGF1cw==', valueType: 'AVMUint64' })
    })
})

describe('AlgodEscrowChain pool reads', () => {
    // Simulated as the app account: a payer holding no ALGO yet can't pay
    // a simulate's fee, and is the one whose pool is being read.
    it('reads the payer deposit as the application account, the payer referenced', async () => {
        fake.simAnswers.payerDeposit = { value: [922_400n, 3n] }
        expect(await chain.readPayerDeposit(PAYER)).toEqual({ algoBalance: 922_400n, openTickets: 3n })
        expect(fake.simulated).toEqual([
            { method: 'payerDeposit', sender: algosdk.getApplicationAddress(APP).toString(), accounts: [PAYER] },
        ])
    })

    it('names a simulate failure', async () => {
        fake.simAnswers.payerDeposit = { failure: 'logic eval error: boom' }
        await expect(chain.readPayerDeposit(PAYER)).rejects.toThrow(
            `escrow: simulate payerDeposit failed (app=${APP} sender=${algosdk.getApplicationAddress(APP)}): logic eval error: boom`,
        )
    })

    it('keeps the ticket MBR once read, refuses 0, and reads again after a failure', async () => {
        fake.simAnswers.mbrForTicket = { failure: 'txn dead' }
        await expect(chain.ticketMbr()).rejects.toThrow('txn dead')
        fake.simAnswers.mbrForTicket = { value: 0n }
        await expect(chain.ticketMbr()).rejects.toThrow('escrow: mbrForTicket returned 0')
        fake.simAnswers.mbrForTicket = { value: 115_300n }
        expect(await chain.ticketMbr()).toBe(115_300n)
        expect(await chain.ticketMbr()).toBe(115_300n)
        expect(fake.simulated.filter((s) => s.method === 'mbrForTicket')).toHaveLength(3)
    })

    describe('free-quota term', () => {
        const box = b64(freeQuotaBoxKey(PAYER))

        it('is owed until the payer has the box, and nothing once it does', async () => {
            fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
            expect(await chain.freeQuotaMbrDue(PAYER)).toBe(22_500n)
            fake.boxes.set(box, new Uint8Array(16))
            expect(await chain.freeQuotaMbrDue(PAYER)).toBe(0n)
            expect(fake.simulated.filter((s) => s.method === 'mbrForFreeQuota')).toHaveLength(1)
        })

        // Over-funding by a withdrawable sliver beats a first free open that reverts.
        it('fails open to the full term when the box read fails', async () => {
            fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
            fake.boxes.set(box, 503)
            expect(await chain.freeQuotaMbrDue(PAYER)).toBe(22_500n)
        })

        // TestReadFreeQuotaMbr_ClassifiesOnlyEvalRejectAsUnsupported
        it('reads only an ABI-router reject as an app without the quota', async () => {
            fake.simAnswers.mbrForFreeQuota = { failure: 'logic eval error: err opcode executed. Details: app=1234, pc=512' }
            expect(await chain.freeQuotaMbrDue(PAYER)).toBe(0n)
            fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
            expect(await chain.freeQuotaMbrDue(PAYER)).toBe(0n)
            expect(fake.paths.some((p) => p.endsWith('/box'))).toBe(false)

            for (const failure of ['overspend (account ABC, data {MicroAlgos:{Raw:0}})', 'txn dead: round 100 outside of 90--100']) {
                const c = newChain()
                fake.simAnswers.mbrForFreeQuota = { failure }
                await expect(c.freeQuotaMbrDue(PAYER)).rejects.toThrow(failure)
                fake.simAnswers.mbrForFreeQuota = { value: 22_500n }
                expect(await c.freeQuotaMbrDue(PAYER)).toBe(22_500n)
            }
        })
    })

    it('reads opt-in, spendable ALGO and the min fee from the account and params', async () => {
        fake.accounts.set(PAYER, { amount: 1_000_000n, minBalance: 100_000n, apps: [99n] })
        expect(await chain.isPayerOptedIn(PAYER)).toBe(false)
        expect(await chain.spendableMicroAlgos(PAYER)).toBe(900_000n)
        fake.accounts.set(PAYER, { amount: 50_000n, minBalance: 100_000n, apps: [99n, APP] })
        expect(await chain.isPayerOptedIn(PAYER)).toBe(true)
        expect(await chain.spendableMicroAlgos(PAYER)).toBe(0n)
        expect(await chain.minTxnFee()).toBe(MIN_FEE)
    })
})

describe('AlgodEscrowChain pool writes', () => {
    // TestComposeDepositMbr_BuildsOptInGroup
    it('deposits with a fee-0 payment and an app call pooling both fees', async () => {
        const txid = await chain.depositMbr(PAYER, 922_400n, true)
        const [pay, call] = lastSent(fake)
        expect(pay!.txn.type).toBe('pay')
        expect(pay!.txn.fee).toBe(0n)
        expect(pay!.txn.payment!.receiver.toString()).toBe(algosdk.getApplicationAddress(APP).toString())
        expect(pay!.txn.payment!.amount).toBe(922_400n)
        expect(call!.txn.fee).toBe(2n * MIN_FEE)
        expect(call!.txn.applicationCall!.onComplete).toBe(OnApplicationComplete.OptInOC)
        expect(call!.txn.sender.toString()).toBe(PAYER)
        expect(txid).toBe(call!.txn.txID())

        await chain.depositMbr(PAYER, 115_300n, false)
        expect(lastSent(fake)[1]!.txn.applicationCall!.onComplete).toBe(OnApplicationComplete.NoOpOC)
        await expect(chain.depositMbr(PAYER, 0n, false)).rejects.toThrow('escrow: depositMbr amount must be > 0')
    })

    // TestComposeWithdrawAndClose_Fees
    it('withdraws and closes with one inner refund pooled', async () => {
        await chain.withdrawMbr(PAYER, 230_600n)
        let [t] = lastSent(fake)
        expect(t!.txn.fee).toBe(2n * MIN_FEE)
        expect(decodeArg('withdrawMbr', 0, argsOf(t!.txn)[1]!)).toBe(230_600n)
        await expect(chain.withdrawMbr(PAYER, 0n)).rejects.toThrow('escrow: withdrawMbr amount must be > 0')

        await chain.closeDeposit(PAYER)
        ;[t] = lastSent(fake)
        expect(t!.txn.fee).toBe(2n * MIN_FEE)
        expect(t!.txn.applicationCall!.onComplete).toBe(OnApplicationComplete.CloseOutOC)
    })

    it('signs only as its own payer', async () => {
        await expect(chain.withdrawMbr(OTHER, 1n)).rejects.toBeInstanceOf(SignerAddressError)
        await expect(chain.depositMbr(OTHER, 1n, false)).rejects.toBeInstanceOf(SignerAddressError)
        expect(fake.sent).toEqual([])
    })
})

describe('AlgodEscrowChain settle calls', () => {
    // TestComposeSettleStandalone_IncludesTreasuryRef
    it('settles standalone as the payer, referencing every disbursement receiver', async () => {
        const r = await chain.settleStandalone(settleCall())
        const [t] = lastSent(fake)
        const call = t!.txn.applicationCall!
        expect(t!.txn.sender.toString()).toBe(PAYER)
        expect(call.accounts.map(String)).toEqual([PAYER, OWNER, TREASURY])
        expect(call.foreignAssets).toEqual([USDC])
        expect(call.boxes.map((b) => b64(b.name))).toEqual(
            [ticketBoxKey(TICKET), operatorBoxKey(7n), nodeBoxKey(7n, 1n)].map(b64),
        )
        // Payout, fee and refund, finalize's op-up, the outer call.
        expect(t!.txn.fee).toBe(5n * MIN_FEE)
        expect(r).toEqual({ txid: t!.txn.txID(), payerFeeMicroalgos: 5n * MIN_FEE })
        const args = argsOf(t!.txn)
        expect(decodeArg('settle', 1, args[2]!)).toBe(50_000n)
        expect(decodeArg('settle', 10, args[11]!)).toBe(false)
    })

    it('sizes the settle fee to what it disburses and to the revenue-ring catch-up', async () => {
        await chain.settleStandalone(settleCall({ amountCharged: 0n, maxPrice: 0n }))
        expect(lastSent(fake)[0]!.txn.fee).toBe(2n * MIN_FEE)
        // 4 + 14 catch-up iterations at 40 opcodes each: two 700-opcode op-ups.
        fake.boxes.set(b64(nodeBoxKey(7n, 1n)), nodeBox(TODAY - 5n))
        fake.boxes.set(b64(operatorBoxKey(7n)), operatorBox(TODAY - 15n))
        await chain.settleStandalone(settleCall({ amountCharged: 0n, maxPrice: 0n }))
        expect(lastSent(fake)[0]!.txn.fee).toBe(4n * MIN_FEE)
    })

    // TestComposeSettleStandalone_FreezePaysTheOuterCallOnly: the contract's
    // freeze branch, like a first half on an open box, fires no disbursement
    // and no op-up, whatever the ring.
    it('pays for the outer call alone on a call that cannot finalize', async () => {
        fake.boxes.set(b64(nodeBoxKey(7n, 1n)), nodeBox(TODAY - 5n))
        fake.boxes.set(b64(operatorBoxKey(7n)), operatorBox(TODAY - 15n))
        const r = await chain.settleStandalone({ ...settleCall(), outerFeeOnly: true })
        expect(lastSent(fake)[0]!.txn.fee).toBe(MIN_FEE)
        expect(r.payerFeeMicroalgos).toBe(MIN_FEE)
    })

    it('checks the settle inputs before reaching the chain', async () => {
        await expect(chain.settleStandalone({ ...settleCall(), ticketIdRaw: new Uint8Array(15) })).rejects.toThrow(
            'escrow: settle ticket id must be 16 bytes (got 15)',
        )
        await expect(chain.settleStandalone({ ...settleCall(), args: { ...settleArgs, receiptDigest: new Uint8Array(31) } })).rejects.toThrow(
            'escrow: settle receipt digest must be 32 bytes (got 31)',
        )
        await expect(chain.settleStandalone({ ...settleCall(), operatorOwnerAddr: 'NOPE' })).rejects.toThrow('operator owner addr')
        await expect(chain.refundInactive({ ticketIdRaw: new Uint8Array(15), operatorId: 7n, nodeId: 1n, payer: PAYER })).rejects.toThrow(
            'refundInactive ticket id must be 16 bytes',
        )
        await expect(
            chain.settleLapsed({ ticketIdRaw: TICKET, operatorId: 7n, nodeId: 1n, operatorOwnerAddr: OWNER, payer: 'NOPE' }),
        ).rejects.toThrow('settleLapsed payer addr')
        expect(fake.paths).toEqual([])
    })

    // TestComposeSettle_GuardsMissingTreasury
    it('refuses to settle or lapse without the treasury', async () => {
        fake.globals.delete('trea')
        await expect(chain.settleStandalone(settleCall())).rejects.toThrow('treasury global not found')
        await expect(
            chain.settleLapsed({ ticketIdRaw: TICKET, operatorId: 7n, nodeId: 1n, operatorOwnerAddr: OWNER, payer: PAYER }),
        ).rejects.toThrow('treasury global not found')
        expect(fake.sent).toEqual([])
    })

    describe('readTicketBox', () => {
        it('decodes a live box, reads a missing one as gone, and wraps any other failure', async () => {
            fake.boxes.set(b64(ticketBoxKey(TICKET)), ticketBox(1n, 100_000n, OWNER))
            const ac = new AbortController()
            expect(await chain.readTicketBox(TICKET, ac.signal)).toMatchObject({ maxPrice: 100_000n, pendingAmount: 1n, operatorOwnerAddr: OWNER })
            // The request carried the caller's signal.
            ac.abort()
            expect(fake.signals.at(-1)?.aborted).toBe(true)
            fake.boxes.delete(b64(ticketBoxKey(TICKET)))
            expect(await chain.readTicketBox(TICKET)).toBeNull()
            fake.boxes.set(b64(ticketBoxKey(TICKET)), 503)
            await expect(chain.readTicketBox(TICKET)).rejects.toThrow(/^escrow: fetch ticket box: .*503/)
        })

        it('refuses an id that is not 16 bytes', async () => {
            await expect(chain.readTicketBox(new Uint8Array(15))).rejects.toThrow('escrow: ticket id must be 16 bytes (got 15)')
            expect(fake.paths).toEqual([])
        })
    })

    describe('settleLapsed', () => {
        const lapse = { ticketIdRaw: TICKET, operatorId: 7n, nodeId: 1n, operatorOwnerAddr: OWNER, payer: PAYER }

        // The box's owner is the one the contract pays; a caller's copy can
        // predate an owner rotation.
        it("references the box's owner and sizes the fee from its claim", async () => {
            const boxOwner = algosdk.generateAccount().addr.toString()
            fake.boxes.set(b64(ticketBoxKey(TICKET)), ticketBox(100_000n, 100_000n, boxOwner))
            await chain.settleLapsed(lapse)
            const [t] = lastSent(fake)
            expect(t!.txn.applicationCall!.accounts.map(String)).toEqual([boxOwner, PAYER, TREASURY])
            expect(t!.txn.applicationCall!.foreignAssets).toEqual([USDC])
            // Payout and fee, no refund, the base op-up, the outer call.
            expect(t!.txn.fee).toBe(4n * MIN_FEE)
        })

        // TestComposeSettleLapsed_FeeFailSafe
        it("takes the caller's owner and the most inners when the box can't be read", async () => {
            await chain.settleLapsed(lapse)
            const [t] = lastSent(fake)
            expect(t!.txn.applicationCall!.accounts.map(String)).toEqual([OWNER, PAYER, TREASURY])
            expect(t!.txn.fee).toBe(5n * MIN_FEE)
        })

        // A long-idle node's lapse runs the catch-up too; a short fee reverts every retry.
        it('funds the revenue-ring catch-up', async () => {
            fake.boxes.set(b64(nodeBoxKey(7n, 1n)), nodeBox(TODAY - 5n))
            fake.boxes.set(b64(operatorBoxKey(7n)), operatorBox(TODAY - 15n))
            await chain.settleLapsed(lapse)
            expect(lastSent(fake)[0]!.txn.fee).toBe(7n * MIN_FEE)
        })
    })

    it('protests with the receipt and a non-zero reason, freezing without inner transfers', async () => {
        const call = {
            ticketIdRaw: TICKET,
            amountCharged: 50_000n,
            receiptDigest: DIGEST,
            receiptSig: new Uint8Array(64).fill(5),
            disputeExcerpt: utf8('excerpt'),
            reason: ProtestReason.bodyHash,
            operatorId: 7n,
            nodeId: 1n,
            payer: PAYER,
        }
        const r = await chain.protest(call)
        const [t] = lastSent(fake)
        expect(t!.txn.fee).toBe(4n * MIN_FEE)
        expect(r).toEqual({ txId: t!.txn.txID(), feeMicroalgos: 4000 })
        expect(t!.txn.applicationCall!.accounts).toEqual([])
        expect(t!.txn.applicationCall!.foreignAssets).toEqual([])
        expect(decodeArg('protest', 5, argsOf(t!.txn)[6]!)).toBe(1n)
        await expect(chain.protest({ ...call, reason: 0 as never })).rejects.toThrow('reason code must be non-zero')
        await expect(chain.protest({ ...call, receiptSig: new Uint8Array(63) })).rejects.toThrow('receipt sig must be 64 bytes')
        expect(fake.sent).toHaveLength(1)
    })

    // The treasury receives the refund when the payer's USDC holding can't.
    it('refunds an inactive ticket with the payer, treasury and USDC referenced', async () => {
        const txid = await chain.refundInactive({ ticketIdRaw: TICKET, operatorId: 7n, nodeId: 1n, payer: PAYER })
        const [t] = lastSent(fake)
        expect(txid).toBe(t!.txn.txID())
        expect(t!.txn.fee).toBe(2n * MIN_FEE)
        expect(t!.txn.applicationCall!.accounts.map(String)).toEqual([PAYER, TREASURY])
        expect(t!.txn.applicationCall!.foreignAssets).toEqual([USDC])
    })

    it('stops on an aborted signal before submitting', async () => {
        const ac = new AbortController()
        ac.abort()
        await expect(chain.withdrawMbr(PAYER, 1n, ac.signal)).rejects.toBe(ac.signal.reason)
        await expect(chain.sendGroup(new Uint8Array([1]), 'open', ac.signal)).rejects.toBe(ac.signal.reason)
        expect(fake.sent).toEqual([])
    })

    // A cancel during the wallet prompt is the caller's, and nothing is sent after it.
    it('sends nothing when the caller aborts while the payer signs', async () => {
        const ac = new AbortController()
        const signing = {
            ...signer,
            signTransactions: async (txns: algosdk.Transaction[], idx: number[]) => {
                ac.abort(new Error('cancelled'))
                return signer.signTransactions(txns, idx)
            },
        }
        const err = await newChain({ signer: signing })
            .withdrawMbr(PAYER, 1n, ac.signal)
            .catch((e: unknown) => e)
        expect(err).toBe(ac.signal.reason)
        expect(fake.sent).toEqual([])
    })

    it("reports a signer's refusal as signing, before anything is sent", async () => {
        const refusing = { ...signer, signTransactions: () => Promise.reject(new Error('user declined')) }
        await expect(newChain({ signer: refusing }).withdrawMbr(PAYER, 1n)).rejects.toThrow(
            'escrow: gather signatures for withdrawMbr: user declined',
        )
        expect(fake.sent).toEqual([])
    })
})

describe('AlgodEscrowChain requests', () => {
    // Go passes its ctx into every algod call; a request in flight stops with the caller.
    it("carries the caller's signal into each request, under the deadline", async () => {
        const ac = new AbortController()
        await chain.withdrawMbr(PAYER, 1n, ac.signal)
        await chain.sendGroup(new Uint8Array([1]), 'settle', ac.signal)
        expect(fake.signals).toHaveLength(fake.paths.length)
        expect(fake.signals.every((s) => s !== undefined && !s.aborted)).toBe(true)
        ac.abort()
        expect(fake.signals.every((s) => s!.aborted)).toBe(true)
    })

    it('aborts a request in flight when the caller does', async () => {
        fake.gate = new Promise(() => {})
        const ac = new AbortController()
        const sent = chain.sendGroup(new Uint8Array([1]), 'open', ac.signal).catch((e: unknown) => e)
        await new Promise((r) => setTimeout(r, 0))
        ac.abort(new Error('cancelled'))
        expect(String(await sent)).toMatch(/escrow: submit open: cancelled/)
    })

    // The pool calls run under the wallet's deposit lock with no signal of
    // their own: a stalled algod must not hold every open behind it.
    it('bounds the pool calls with the request timeout', async () => {
        fake.gate = new Promise(() => {})
        const c = newChain({ requestTimeoutMs: 20 })
        await expect(c.readPayerDeposit(PAYER)).rejects.toThrow(/suggested params/)
        await expect(c.isPayerOptedIn(PAYER)).rejects.toThrow(/account info for opt-in check/)
        await expect(c.minTxnFee()).rejects.toThrow(/suggested params/)
    })

    // A timeout of 0 would abort every request at once; it means the default.
    it('reads a request timeout that is not a positive number as the default', async () => {
        for (const requestTimeoutMs of [0, -1, Number.POSITIVE_INFINITY, Number.NaN]) {
            fake.gate = new Promise((r) => setTimeout(r, 10))
            await expect(newChain({ requestTimeoutMs }).config(), String(requestTimeoutMs)).resolves.toMatchObject({ usdcAssetId: USDC })
        }
    })

    // One globals read serves every caller; one caller leaving doesn't fail the rest.
    it("lets a caller stop waiting on the shared config read without failing another's", async () => {
        const gate = deferred()
        fake.gate = gate.promise
        const ac = new AbortController()
        const first = chain.config(ac.signal)
        const second = chain.config()
        ac.abort(new Error('cancelled'))
        await expect(first).rejects.toThrow('cancelled')
        fake.gate = undefined
        gate.resolve()
        expect((await second).usdcAssetId).toBe(USDC)
        expect(fake.paths.filter((p) => p === `/v2/applications/${APP}`)).toHaveLength(1)
    })
})

describe('AlgodEscrowChain reverts', () => {
    const pcOf = (assert: string) => {
        for (let pc = 0; pc < 1 << 16; pc++) if (approvalErrorMessage(pc) === assert) return pc
        throw new Error(`no pc for ${assert}`)
    }

    // TestSubmitPresignedOpenGroup_RevertIsTyped: a drained pool reads as one.
    it('names a reverted group by its method and assert', async () => {
        const pc = pcOf(APPROVAL_ASSERT.insufficientMbrDeposit)
        fake.sendError = `TransactionPool.Remember: logic eval error: assert failed pc=${pc}. Details: pc=${pc}`
        const err = await chain.sendGroup(new Uint8Array([1]), 'open').catch((e: unknown) => e)
        expect(err).toBeInstanceOf(ApprovalError)
        expect(err).toMatchObject({ method: 'open', pc, assert: APPROVAL_ASSERT.insufficientMbrDeposit })
    })

    // TestSubmitSingle_SettleLapsedRevertIsTyped
    it('names a reverted single call by its method', async () => {
        const pc = pcOf(APPROVAL_ASSERT.tooEarlyToLapseSettle)
        fake.sendError = `logic eval error: assert failed pc=${pc}`
        const err = await chain
            .settleLapsed({ ticketIdRaw: TICKET, operatorId: 7n, nodeId: 1n, operatorOwnerAddr: OWNER, payer: PAYER })
            .catch((e: unknown) => e)
        expect(err).toMatchObject({ method: 'settleLapsed', assert: APPROVAL_ASSERT.tooEarlyToLapseSettle })
        expect(String(err)).toBe(`ApprovalError: escrow: submit settleLapsed pc=${pc}: escrow: too early to lapse settle`)
    })

    it('wraps a failure with no pc as a plain error', async () => {
        fake.sendError = 'overspend'
        const err = await chain.sendGroup(new Uint8Array([1]), 'settle').catch((e: unknown) => e)
        expect(err).not.toBeInstanceOf(ApprovalError)
        expect(String(err)).toBe('Error: escrow: submit settle: Network request error. Received status 400: overspend')
    })
})
