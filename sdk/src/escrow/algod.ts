/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The default EscrowChain: the escrow app over algod, as go/escrow's Client
// reaches it. Calls are composed with algosdk's composer, carry their box,
// account and asset references explicitly, pool their inner-txn fees on the
// outer call, and are submitted without waiting for confirmation. A revert
// comes back as an ApprovalError naming the assert.

import algosdk, { ABIMethod, Address, AtomicTransactionComposer, OnApplicationComplete, type SuggestedParams } from 'algosdk'
import {
    SECONDS_PER_DAY,
    type TicketRecord,
    decodeNodeRecord,
    decodeOperatorRecord,
    decodeTicketRecord,
    freeQuotaBoxKey,
    gapOpUpsForIters,
    nodeBoxKey,
    operatorBoxKey,
    ringGapIters,
    settleInnerCount,
    ticketBoxKey,
} from '@txnlab/zs-proto/escrow'

import type { SettleSubmission } from '../ack.js'
import type { PayerDeposit } from '../mbr.js'
import type { EscrowCall, SettleOutcome } from '../parts.js'
import { type Clock, type Logger, type Signer, SignerAddressError, discardLogger } from '../ports.js'
import { untilAborted } from '../sleep.js'
import type {
    EscrowChain,
    EscrowChainConfig,
    PayerSettleCall,
    ProtestCall,
    RefundInactiveCall,
    SettleLapsedCall,
} from '../wallet.js'
import { ESCROW_METHOD_SIGNATURES } from './generated/abi.js'
import { enrichSubmitError } from './revert.js'

export interface AlgodEscrowChainOptions {
    algod: algosdk.Algodv2
    appId: bigint
    /** The payer's signer; every call that acts as the payer signs with it. */
    signer: Signer
    /**
     * The most one algod request may take; absent, zero or negative is 30 s.
     * The pool calls take no signal and run under the wallet's deposit lock,
     * so this is what keeps a stalled algod from holding every open behind it.
     * It is also the only bound on the retries of those reads, and of the
     * account and free-quota reads, on a retrying algod (retryingAlgod).
     */
    requestTimeoutMs?: number
    logger?: Logger
    /** Wall clock, Unix ms: the day a settle's revenue-ring gap is counted to. */
    clock?: Clock
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000

/** The contract globals the chain composes with, read once (Go's RefreshConfig). */
interface Globals extends EscrowChainConfig {
    treasury: string
}

/** Thrown by freeQuotaMbrDue's read when the deployed app predates the free-ticket quota. */
class FreeQuotaUnsupportedError extends Error {}

/**
 * The ARC-4 signature of the admin call that ends a frozen ticket, Go's
 * escrow.ResolveFrozenSignature. No payer calls it, so it is absent from the
 * generated ABI; the payer only needs to know whether the deployed app has it.
 */
export const RESOLVE_FROZEN_SIGNATURE = 'resolveFrozen(byte[],uint64,byte[])void'

/**
 * programHasMethod reports whether an approval program carries the ARC-4
 * selector of signature, Go's escrow.ProgramHasMethod. A router matches each
 * call's first argument against its methods' selectors, so a method the
 * program routes has its 4-byte selector somewhere in the bytecode. A chance
 * match in other bytes is possible but unlikely at these program sizes.
 */
export function programHasMethod(program: Uint8Array | undefined, signature: string): boolean {
    if (program === undefined || program.length === 0) return false
    const sel = ABIMethod.fromSignature(signature).getSelector()
    outer: for (let i = 0; i + sel.length <= program.length; i++) {
        for (let j = 0; j < sel.length; j++) if (program[i + j] !== sel[j]) continue outer
        return true
    }
    return false
}

function globalStateOf(app: algosdk.modelsv2.Application): Map<string, algosdk.modelsv2.TealValue> {
    const out = new Map<string, algosdk.modelsv2.TealValue>()
    for (const kv of app.params?.globalState ?? []) out.set(new TextDecoder().decode(kv.key), kv.value)
    return out
}

// settleInnerCount's ceiling: a settle that refunds the payer, pays the
// operator and pays the treasury (Go's settleLapsedMaxInners).
const SETTLE_MAX_INNERS = 3n
const TICKET_ID_LEN = 16
const RECEIPT_DIGEST_LEN = 32
const RECEIPT_SIG_LEN = 64

const methods = new Map<string, ABIMethod>()
function method(name: string): ABIMethod {
    let m = methods.get(name)
    if (m === undefined) {
        const sig = ESCROW_METHOD_SIGNATURES[name]
        if (sig === undefined) throw new Error(`escrow: unknown method "${name}"`)
        m = ABIMethod.fromSignature(sig)
        methods.set(name, m)
    }
    return m
}

interface SingleCall {
    method: string
    args?: algosdk.ABIArgument[]
    boxes?: Uint8Array[]
    accounts?: string[]
    assets?: bigint[]
    /** Inner txns the outer call's fee pools for. */
    inners: bigint
    onComplete?: OnApplicationComplete
}

/** What algosdk passes on to fetch for one request. */
export type RequestOptions = { signal: AbortSignal }

/**
 * AlgodEscrowChain is the EscrowChain over an algod client. The escrow
 * config and the pool's ticket MBR and free-quota term are read once and
 * kept for the life of the instance, as Go's RefreshConfig keeps them; a
 * redeploy or treasury rotation needs a new instance. The protocol fee rate is
 * read live.
 *
 * Readonly calls simulate as the application account, which exists and
 * carries ALGO on any live deployment, so they answer for a payer that holds
 * none yet. Every algod request carries the call's signal, as Go's carry its
 * ctx, and the request timeout; a submit cut short after it went out leaves
 * its outcome unknown, as a cancelled ctx does in Go.
 */
export class AlgodEscrowChain implements EscrowChain {
    readonly #algod: algosdk.Algodv2
    readonly #appId: bigint
    readonly #appAddress: string
    readonly #signer: Signer
    readonly #timeoutMs: number
    readonly #log: Logger
    readonly #clock: Clock
    #globals: Promise<Globals> | undefined
    #ticketMbr: Promise<bigint> | undefined
    #freeQuotaMbr: Promise<bigint> | undefined

    constructor(o: AlgodEscrowChainOptions) {
        if (o.appId <= 0n) throw new Error('escrow: app id must be > 0')
        if (!algosdk.isValidAddress(o.signer.address)) throw new Error(`escrow: signer address ${o.signer.address} is not an address`)
        this.#algod = o.algod
        this.#appId = o.appId
        this.#appAddress = algosdk.getApplicationAddress(o.appId).toString()
        this.#signer = o.signer
        this.#timeoutMs = requestTimeoutOrDefault(o.requestTimeoutMs)
        this.#log = o.logger ?? discardLogger
        this.#clock = o.clock ?? Date.now
    }

    // ---- config ----

    async config(signal?: AbortSignal): Promise<EscrowChainConfig> {
        const g = await this.#readGlobalsOnce(signal)
        return {
            appId: g.appId,
            appAddress: g.appAddress,
            usdcAssetId: g.usdcAssetId,
            settlementGraceDefault: g.settlementGraceDefault,
            resolvesFrozen: g.resolvesFrozen === true,
        }
    }

    /**
     * Reads and keeps what the first open would otherwise read: the ticket
     * MBR, the globals and the free-quota term (Go's RefreshConfig). A
     * Client runs it at startup so a misconfigured app refuses there, not
     * after a node has signed a ticket. The reads it starts run under signal,
     * as Go's run under RefreshConfig's ctx: on a retrying algod a read left
     * running after Client.create gave up would retry until its own timeout.
     * A read already in flight when it is called keeps its own bound.
     */
    async refreshConfig(signal?: AbortSignal): Promise<void> {
        signal?.throwIfAborted()
        await untilAborted(this.#ticketMbrOnce(signal), signal)
        await untilAborted(this.#globalsOnce(signal), signal)
        await untilAborted(this.#readFreeQuotaMbrOnce(signal), signal)
    }

    async protocolFeeBps(signal?: AbortSignal): Promise<number> {
        signal?.throwIfAborted()
        const kv = await this.#globalState(signal)
        const v = kv.get('pfee')
        if (v === undefined) return 0
        if (v.type !== 2) throw new Error(`escrow: protocolFeeBps global has type ${v.type}, want 2 (uint)`)
        return Number(v.uint)
    }

    // One read serves every caller, so it runs under the timeout alone and
    // each caller stops waiting on its own signal. A failed read is not kept.
    #readGlobalsOnce(signal?: AbortSignal): Promise<Globals> {
        signal?.throwIfAborted()
        return untilAborted(this.#globalsOnce(), signal)
    }

    // start bounds the read only when this call starts it.
    #globalsOnce(start?: AbortSignal): Promise<Globals> {
        this.#globals ??= this.#readGlobals(start).catch((err: unknown) => {
            this.#globals = undefined
            throw err
        })
        return this.#globals
    }

    async #globalState(signal?: AbortSignal): Promise<Map<string, algosdk.modelsv2.TealValue>> {
        return globalStateOf(await this.#application(signal))
    }

    async #application(signal?: AbortSignal): Promise<algosdk.modelsv2.Application> {
        try {
            return await this.#algod.getApplicationByID(this.#appId).do(undefined, this.#opts(signal))
        } catch (err) {
            throw new Error(`escrow: get application ${this.#appId}: ${message(err)}`, { cause: err })
        }
    }

    // Go's readGlobals: usdc and treasury are required, a contract missing
    // either is misconfigured. The same fetch answers whether the program
    // routes resolveFrozen.
    async #readGlobals(signal?: AbortSignal): Promise<Globals> {
        const app = await this.#application(signal)
        const kv = globalStateOf(app)
        const usdc = kv.get('usdc')
        if (usdc === undefined) throw new Error(`escrow: usdcAssetId global not found on app ${this.#appId}`)
        if (usdc.type !== 2) throw new Error(`escrow: usdcAssetId global has type ${usdc.type}, want 2 (uint)`)
        if (usdc.uint === 0n) throw new Error('escrow: usdcAssetId global is 0 (contract misconfigured?)')
        const trea = kv.get('trea')
        if (trea === undefined) throw new Error(`escrow: treasury global not found on app ${this.#appId}`)
        if (trea.type !== 1) throw new Error(`escrow: treasury global has type ${trea.type}, want 1 (bytes)`)
        if (trea.bytes.length !== 32) throw new Error(`escrow: treasury raw bytes len = ${trea.bytes.length}, want 32`)
        const grace = kv.get('grace')
        if (grace !== undefined && grace.type !== 2) {
            throw new Error(`escrow: settlementGraceDefault global has type ${grace.type}, want 2 (uint)`)
        }
        return {
            appId: this.#appId,
            appAddress: this.#appAddress,
            usdcAssetId: BigInt(usdc.uint),
            settlementGraceDefault: grace === undefined ? 0n : BigInt(grace.uint),
            resolvesFrozen: programHasMethod(app.params?.approvalProgram, RESOLVE_FROZEN_SIGNATURE),
            treasury: new Address(trea.bytes).toString(),
        }
    }

    // ---- the prepaid pool ----

    ticketMbr(): Promise<bigint> {
        return this.#ticketMbrOnce()
    }

    // start bounds the read only when this call starts it.
    #ticketMbrOnce(start?: AbortSignal): Promise<bigint> {
        this.#ticketMbr ??= this.#readonly('mbrForTicket', [], [], start)
            .then((v) => {
                if (typeof v !== 'bigint') throw new Error(`escrow: mbrForTicket returned ${typeof v}, want uint64`)
                if (v === 0n) throw new Error('escrow: mbrForTicket returned 0 (contract misconfigured?)')
                return v
            })
            .catch((err: unknown) => {
                this.#ticketMbr = undefined
                throw err
            })
        return this.#ticketMbr
    }

    /**
     * The free-quota box MBR still owed (Go's FreeQuotaMbrDueFor). An app
     * that predates the quota owes nothing; any other failure to read the
     * term rejects, so a transient fault never reads as "no quota". An
     * unreadable box fails open to the full term.
     */
    async freeQuotaMbrDue(payer: string): Promise<bigint> {
        const mbr = await this.#readFreeQuotaMbrOnce()
        if (mbr === 0n) return 0n
        try {
            await this.#algod.getApplicationBoxByName(this.#appId, freeQuotaBoxKey(payer)).do(undefined, this.#opts())
            return 0n
        } catch (err) {
            if (!isNotFound(err)) this.#log.warn('escrow: free-quota box read failed; sizing as if absent', { err: message(err) })
            return mbr
        }
    }

    // start bounds the read only when this call starts it.
    #readFreeQuotaMbrOnce(start?: AbortSignal): Promise<bigint> {
        this.#freeQuotaMbr ??= this.#readonly('mbrForFreeQuota', [], [], start)
            .then((v) => {
                if (typeof v !== 'bigint') throw new Error(`escrow: mbrForFreeQuota returned ${typeof v}, want uint64`)
                return v
            })
            .catch((err: unknown) => {
                if (err instanceof FreeQuotaUnsupportedError) return 0n
                this.#freeQuotaMbr = undefined
                throw err
            })
        return this.#freeQuotaMbr
    }

    async readPayerDeposit(payer: string): Promise<PayerDeposit> {
        const v = await this.#readonly('payerDeposit', [payer], [payer])
        if (!Array.isArray(v) || v.length !== 2 || typeof v[0] !== 'bigint' || typeof v[1] !== 'bigint') {
            throw new Error('escrow: payerDeposit returned a value that is not a (uint64,uint64) tuple')
        }
        return { algoBalance: v[0], openTickets: v[1] }
    }

    async isPayerOptedIn(payer: string): Promise<boolean> {
        const acct = await this.#account(payer, 'opt-in check')
        return (acct.appsLocalState ?? []).some((ls) => BigInt(ls.id) === this.#appId)
    }

    async spendableMicroAlgos(payer: string): Promise<bigint> {
        const acct = await this.#account(payer, 'spendable balance')
        return spendableOf(BigInt(acct.amount), BigInt(acct.minBalance))
    }

    async minTxnFee(): Promise<bigint> {
        return BigInt((await this.#params()).minFee)
    }

    /** The two-txn deposit group: a fee-0 payment and the depositMbr call pooling both fees. */
    async depositMbr(payer: string, amount: bigint, optIn: boolean): Promise<string> {
        if (amount <= 0n) throw new Error('escrow: depositMbr amount must be > 0')
        this.#asPayer(payer)
        const sp = await this.#params()
        const pay = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender: payer,
            receiver: this.#appAddress,
            amount,
            suggestedParams: { ...sp, flatFee: true, fee: 0n },
        })
        const signer = this.#txnSigner()
        const atc = new AtomicTransactionComposer()
        atc.addMethodCall({
            appID: this.#appId,
            method: method('depositMbr'),
            methodArgs: [{ txn: pay, signer }],
            sender: payer,
            suggestedParams: { ...sp, flatFee: true, fee: BigInt(sp.minFee) * 2n },
            onComplete: optIn ? OnApplicationComplete.OptInOC : OnApplicationComplete.NoOpOC,
            signer,
        })
        const txids = await this.#submit('depositMbr', atc, 2)
        // The payment comes first; the call is the deposit.
        return txids[1]!
    }

    async withdrawMbr(payer: string, amount: bigint, signal?: AbortSignal): Promise<string> {
        if (amount <= 0n) throw new Error('escrow: withdrawMbr amount must be > 0')
        // 1 inner: the ALGO refund to the sender.
        return (await this.#single(payer, { method: 'withdrawMbr', args: [amount], inners: 1n }, signal)).txid
    }

    async closeDeposit(payer: string, signal?: AbortSignal): Promise<string> {
        // Up to 1 inner: the balance refund. The CloseOut returns the local-schema MBR.
        const call = { method: 'closeDeposit', inners: 1n, onComplete: OnApplicationComplete.CloseOutOC }
        return (await this.#single(payer, call, signal)).txid
    }

    // ---- groups and the payer's single calls ----

    async sendGroup(signed: Uint8Array, method: 'open' | 'settle', signal?: AbortSignal): Promise<void> {
        signal?.throwIfAborted()
        try {
            await this.#algod.sendRawTransaction(signed).do(undefined, this.#opts(signal))
        } catch (err) {
            throw enrichSubmitError(method, err)
        }
    }

    async settleOutcome(txId: string, signal?: AbortSignal): Promise<SettleOutcome> {
        signal?.throwIfAborted()
        const info = await this.#algod.pendingTransactionInformation(txId).do(undefined, this.#opts(signal))
        return settleOutcomeOf(info)
    }

    /**
     * The payer's standalone settle (Go's ComposeSettleStandalone). The fee
     * pools the disbursements this settle fires if it finalizes, finalize's
     * base op-up, and an op-up per revenue-ring catch-up a long-idle node or
     * operator box runs. A call the caller expects not to finalize
     * (outerFeeOnly: a freeze, or a first half on an open box) fires none of
     * them, so it pays for itself alone.
     */
    async settleStandalone(c: PayerSettleCall, signal?: AbortSignal): Promise<SettleSubmission> {
        checkLen('settle ticket id', c.ticketIdRaw, TICKET_ID_LEN)
        checkLen('settle receipt digest', c.args.receiptDigest, RECEIPT_DIGEST_LEN)
        checkAddr('settle payer addr', c.payer)
        checkAddr('settle operator owner addr', c.operatorOwnerAddr)
        const g = await this.#readGlobalsOnce(signal)
        const a = c.args
        const inners =
            c.outerFeeOnly === true
                ? 0n
                : settleInnerCount(a.amountCharged, c.maxPrice) + 1n + (await this.#gapSettleOpUps(c.operatorId, c.nodeId, signal))
        const r = await this.#single(
            c.payer,
            {
                method: 'settle',
                args: [
                    c.ticketIdRaw,
                    a.amountCharged,
                    a.receiptDigest,
                    a.ttftMs,
                    a.decodeMs,
                    a.inputTokens,
                    a.outputTokens,
                    BigInt(a.outputUsageType),
                    BigInt(a.auxOutputUsageType),
                    a.auxOutputCount,
                    false,
                ],
                boxes: [ticketBoxKey(c.ticketIdRaw), operatorBoxKey(c.operatorId), nodeBoxKey(c.operatorId, c.nodeId)],
                accounts: [c.payer, c.operatorOwnerAddr, g.treasury],
                assets: [g.usdcAssetId],
                inners,
            },
            signal,
        )
        return { txid: r.txid, payerFeeMicroalgos: r.fee }
    }

    /** protest() freezes the ticket: no inner transfers, three for its ed25519 check's budget (Go's ComposeProtest). */
    async protest(c: ProtestCall, signal?: AbortSignal): Promise<EscrowCall> {
        checkLen('protest ticket id', c.ticketIdRaw, TICKET_ID_LEN)
        checkLen('protest receipt digest', c.receiptDigest, RECEIPT_DIGEST_LEN)
        checkLen('protest receipt sig', c.receiptSig, RECEIPT_SIG_LEN)
        if (c.reason === 0) throw new Error('escrow: protest reason code must be non-zero')
        const r = await this.#single(
            c.payer,
            {
                method: 'protest',
                args: [c.ticketIdRaw, c.amountCharged, c.receiptDigest, c.receiptSig, c.disputeExcerpt, BigInt(c.reason)],
                boxes: [ticketBoxKey(c.ticketIdRaw), operatorBoxKey(c.operatorId), nodeBoxKey(c.operatorId, c.nodeId)],
                inners: 3n,
            },
            signal,
        )
        return { txId: r.txid, feeMicroalgos: Number(r.fee) }
    }

    /**
     * refundInactive() fires at most the USDC refund (Go's ComposeRefundInactive).
     * The treasury is referenced because the contract redirects the refund
     * there when the payer's USDC holding can't receive it.
     */
    async refundInactive(c: RefundInactiveCall, signal?: AbortSignal): Promise<string> {
        checkLen('refundInactive ticket id', c.ticketIdRaw, TICKET_ID_LEN)
        checkAddr('refundInactive payer addr', c.payer)
        const g = await this.#readGlobalsOnce(signal)
        const r = await this.#single(
            c.payer,
            {
                method: 'refundInactive',
                args: [c.ticketIdRaw],
                boxes: [ticketBoxKey(c.ticketIdRaw), operatorBoxKey(c.operatorId), nodeBoxKey(c.operatorId, c.nodeId)],
                accounts: [c.payer, g.treasury],
                assets: [g.usdcAssetId],
                inners: 1n,
            },
            signal,
        )
        return r.txid
    }

    /**
     * settleLapsed() (Go's ComposeSettleLapsed). The fee and the payout
     * account come from the ticket box, which is what the contract reads:
     * the operator's owner can rotate after open() while the box keeps the
     * one in force then, and a payout to an unreferenced account reverts.
     * An unreadable box takes the caller's owner and the most inners a
     * settle fires, since a short fee reverts every retry.
     */
    async settleLapsed(c: SettleLapsedCall, signal?: AbortSignal): Promise<string> {
        checkLen('settleLapsed ticket id', c.ticketIdRaw, TICKET_ID_LEN)
        checkAddr('settleLapsed operator owner addr', c.operatorOwnerAddr)
        checkAddr('settleLapsed payer addr', c.payer)
        const g = await this.#readGlobalsOnce(signal)
        let owner = c.operatorOwnerAddr
        let inners = SETTLE_MAX_INNERS
        try {
            const box = await this.#algod
                .getApplicationBoxByName(this.#appId, ticketBoxKey(c.ticketIdRaw))
                .do(undefined, this.#opts(signal))
            const rec = decodeTicketRecord(box.value)
            inners = settleInnerCount(rec.pendingAmount, rec.maxPrice)
            owner = rec.operatorOwnerAddr
        } catch {
            // Worst case, as above.
        }
        const gap = await this.#gapSettleOpUps(c.operatorId, c.nodeId, signal)
        const r = await this.#single(
            c.payer,
            {
                method: 'settleLapsed',
                args: [c.ticketIdRaw],
                boxes: [ticketBoxKey(c.ticketIdRaw), operatorBoxKey(c.operatorId), nodeBoxKey(c.operatorId, c.nodeId)],
                accounts: [owner, c.payer, g.treasury],
                assets: [g.usdcAssetId],
                inners: inners + 1n + gap,
            },
            signal,
        )
        return r.txid
    }

    /** The ticket's box, or null once it is gone (Go's ReadTicketBox). */
    async readTicketBox(ticketIdRaw: Uint8Array, signal?: AbortSignal): Promise<TicketRecord | null> {
        checkLen('ticket id', ticketIdRaw, TICKET_ID_LEN)
        let value: Uint8Array
        try {
            const box = await this.#algod
                .getApplicationBoxByName(this.#appId, ticketBoxKey(ticketIdRaw))
                .do(undefined, this.#opts(signal))
            value = box.value
        } catch (err) {
            if (isNotFound(err)) return null
            throw new Error(`escrow: fetch ticket box: ${message(err)}`, { cause: err })
        }
        return decodeTicketRecord(value)
    }

    // ---- plumbing ----

    /**
     * The extra finalize op-ups a single-call settle funds for the revenue
     * ring's catch-up on the node and operator boxes (Go's gapSettleOpUps).
     * Best effort: an unreadable or absent box adds none.
     */
    async #gapSettleOpUps(operatorId: bigint, nodeId: bigint, signal?: AbortSignal): Promise<bigint> {
        const today = BigInt(Math.floor(this.#clock() / 1000)) / SECONDS_PER_DAY
        let iters = 0n
        try {
            const box = await this.#algod.getApplicationBoxByName(this.#appId, nodeBoxKey(operatorId, nodeId)).do(undefined, this.#opts(signal))
            iters += ringGapIters(decodeNodeRecord(operatorId, nodeId, box.value).bucketsLastDay, today)
        } catch {
            // None.
        }
        try {
            const box = await this.#algod.getApplicationBoxByName(this.#appId, operatorBoxKey(operatorId)).do(undefined, this.#opts(signal))
            iters += ringGapIters(decodeOperatorRecord(operatorId, box.value).bucketsLastDay, today)
        } catch {
            // None.
        }
        return gapOpUpsForIters(iters)
    }

    /** One app call signed by the payer, its fee pooling c.inners (Go's submitSingleOC). */
    async #single(payer: string, c: SingleCall, signal?: AbortSignal): Promise<{ txid: string; fee: bigint }> {
        this.#asPayer(payer)
        signal?.throwIfAborted()
        const sp = await this.#params(signal)
        const fee = BigInt(sp.minFee) * (1n + c.inners)
        const atc = new AtomicTransactionComposer()
        atc.addMethodCall({
            appID: this.#appId,
            method: method(c.method),
            methodArgs: c.args ?? [],
            sender: payer,
            suggestedParams: { ...sp, flatFee: true, fee },
            onComplete: c.onComplete ?? OnApplicationComplete.NoOpOC,
            appAccounts: c.accounts ?? [],
            // Asset 0 is no asset, and the AVM refuses it as a reference.
            appForeignAssets: (c.assets ?? []).filter((a) => a !== 0n),
            boxes: (c.boxes ?? []).map((name) => ({ appIndex: 0, name })),
            signer: this.#txnSigner(),
        })
        const [txid] = await this.#submit(c.method, atc, 1, signal)
        return { txid: txid!, fee }
    }

    // Signing and sending are separate steps, as in Go: a signer's refusal
    // is not a submit failure, and only the send carries the signal.
    async #submit(name: string, atc: AtomicTransactionComposer, want: number, signal?: AbortSignal): Promise<string[]> {
        const txids = atc.buildGroup().map((t) => t.txn.txID())
        if (txids.length !== want) throw new Error(`escrow: ${name} built ${txids.length} txns, want ${want}`)
        let signed: Uint8Array[]
        try {
            signed = await atc.gatherSignatures()
        } catch (err) {
            throw new Error(`escrow: gather signatures for ${name}: ${message(err)}`, { cause: err })
        }
        signal?.throwIfAborted()
        try {
            await this.#algod.sendRawTransaction(signed).do(undefined, this.#opts(signal))
        } catch (err) {
            throw enrichSubmitError(name, err)
        }
        return txids
    }

    /** A readonly method simulated from the application account (see the class doc). */
    async #readonly(
        name: string,
        args: algosdk.ABIArgument[],
        accounts: string[] = [],
        signal?: AbortSignal,
    ): Promise<algosdk.ABIValue | undefined> {
        try {
            return await simulateReadonly(this.#algod, this.#appId, this.#timeoutMs, name, args, accounts, signal)
        } catch (err) {
            // An app without the method falls through its ABI router to a reject,
            // a logic eval failure. Only that means the quota is unsupported; a
            // transient fault read as unsupported would drop the term for good.
            if (name === 'mbrForFreeQuota' && err instanceof SimulateFailedError && err.failureMessage.includes('logic eval error')) {
                throw new FreeQuotaUnsupportedError(
                    `escrow: deployed app has no freeTicketAllowance method (app=${this.#appId}): ${err.failureMessage}`,
                )
            }
            throw err
        }
    }

    #params(signal?: AbortSignal): Promise<SuggestedParams> {
        return suggestedParams(this.#algod, this.#timeoutMs, signal)
    }

    async #account(addr: string, why: string): Promise<algosdk.modelsv2.Account> {
        try {
            return await this.#algod.accountInformation(addr).do(undefined, this.#opts())
        } catch (err) {
            throw new Error(`escrow: account info for ${why}: ${message(err)}`, { cause: err })
        }
    }

    #opts(signal?: AbortSignal): RequestOptions {
        return requestOptions(this.#timeoutMs, signal)
    }

    // The chain signs only as its own payer: a call naming another account
    // would be one the signer can't make.
    #asPayer(payer: string): void {
        if (payer !== this.#signer.address) throw new SignerAddressError(this.#signer.address, payer)
    }

    #txnSigner(): algosdk.TransactionSigner {
        return (txns, idx) => this.#signer.signTransactions(txns, idx)
    }
}

// ---- algod reads shared with the registry's chain read ----

/** The per-request timeout an option asks for; absent, zero or negative is 30 s. */
export function requestTimeoutOrDefault(ms: number | undefined): number {
    return ms !== undefined && Number.isFinite(ms) && ms > 0 ? ms : DEFAULT_REQUEST_TIMEOUT_MS
}

/** One algod request's options: its deadline, and the caller's signal when there is one. */
export function requestOptions(timeoutMs: number, signal?: AbortSignal): RequestOptions {
    const timeout = AbortSignal.timeout(timeoutMs)
    return { signal: signal ? AbortSignal.any([signal, timeout]) : timeout }
}

/**
 * settleOutcomeOf reads algod's pending-pool answer for a transaction, as Go's
 * settleOutcomeOf does: confirmed is landed, a pool error is dropped, and
 * anything else is still pending.
 */
export function settleOutcomeOf(info: { confirmedRound?: bigint; poolError: string }): SettleOutcome {
    if ((info.confirmedRound ?? 0n) > 0n) return 'landed'
    if (info.poolError !== '') return 'dropped'
    return 'pending'
}

/** Amount less min-balance, floored at zero: an account below its own minimum can send nothing. */
export function spendableOf(amount: bigint, minBalance: bigint): bigint {
    return amount > minBalance ? amount - minBalance : 0n
}

export async function suggestedParams(algod: algosdk.Algodv2, timeoutMs: number, signal?: AbortSignal): Promise<SuggestedParams> {
    try {
        return await algod.getTransactionParams().do(undefined, requestOptions(timeoutMs, signal))
    } catch (err) {
        throw new Error(`escrow: suggested params: ${message(err)}`, { cause: err })
    }
}

/** A simulated readonly call the app evaluated and rejected, as opposed to one algod never ran. */
export class SimulateFailedError extends Error {
    constructor(
        msg: string,
        readonly failureMessage: string,
    ) {
        super(msg)
        this.name = 'SimulateFailedError'
    }
}

/**
 * Simulates the escrow app's readonly method name and returns what it
 * returned. The sender is the application account, which exists and carries
 * ALGO on any live deployment, so the call answers for a payer that holds
 * none yet.
 */
export async function simulateReadonly(
    algod: algosdk.Algodv2,
    appId: bigint,
    timeoutMs: number,
    name: string,
    args: algosdk.ABIArgument[],
    accounts: string[] = [],
    signal?: AbortSignal,
): Promise<algosdk.ABIValue | undefined> {
    const sp = await suggestedParams(algod, timeoutMs, signal)
    const sender = algosdk.getApplicationAddress(appId).toString()
    const m = method(name)
    const atc = new AtomicTransactionComposer()
    atc.addMethodCall({
        appID: appId,
        method: m,
        methodArgs: args,
        sender,
        suggestedParams: sp,
        appAccounts: accounts,
        signer: algosdk.makeEmptyTransactionSigner(),
    })
    const [built] = atc.buildGroup()
    const txns = (await atc.gatherSignatures()).map((b) => algosdk.decodeSignedTransaction(b))
    const req = new algosdk.modelsv2.SimulateRequest({
        txnGroups: [new algosdk.modelsv2.SimulateRequestTransactionGroup({ txns })],
        allowEmptySignatures: true,
    })
    let res: algosdk.modelsv2.SimulateResponse
    try {
        res = await algod.simulateTransactions(req).do(undefined, requestOptions(timeoutMs, signal))
    } catch (err) {
        throw new Error(`escrow: simulate ${name}: ${message(err)}`, { cause: err })
    }
    // An eval failure is reported in the group, not as a transport error.
    const group = res.txnGroups[0]
    if (group?.failureMessage) {
        throw new SimulateFailedError(
            `escrow: simulate ${name} failed (app=${appId} sender=${sender}): ${group.failureMessage}`,
            group.failureMessage,
        )
    }
    const result = group?.txnResults[0]?.txnResult
    if (group?.txnResults.length !== 1 || result === undefined) {
        throw new Error(`escrow: simulate ${name} returned ${group?.txnResults.length ?? 0} results, want 1`)
    }
    const mr = AtomicTransactionComposer.parseMethodResponse(
        m,
        { txID: built!.txn.txID(), rawReturnValue: new Uint8Array(), method: m },
        result,
    )
    if (mr.decodeError) throw new Error(`escrow: decode ${name} return: ${mr.decodeError.message}`, { cause: mr.decodeError })
    return mr.returnValue
}

function checkLen(what: string, b: Uint8Array, want: number): void {
    if (b.length !== want) throw new Error(`escrow: ${what} must be ${want} bytes (got ${b.length})`)
}

function checkAddr(what: string, addr: string): void {
    if (!algosdk.isValidAddress(addr)) throw new Error(`escrow: ${what}: ${addr} is not an address`)
}

// Go's isNotFound: algod reports a missing box as a 404.
export function isNotFound(err: unknown): boolean {
    const status = (err as { response?: { status?: unknown } } | null)?.response?.status
    if (status === 404) return true
    const text = message(err)
    return text.includes('404') || text.toLowerCase().includes('box not found')
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
