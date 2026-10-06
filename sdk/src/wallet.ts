/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's escrow side, mirroring proto/go/zs Wallet and OpenHandle. The
// decisions live here: the open group's checks and the payer's signature on
// it, the prepaid pool's funding and the one retry a failed open earns, and
// the ack between the node's settle group and a standalone settle. What
// reaches the chain goes through EscrowChain, so a host can bring its own
// algod access without being able to skip a check.

import { base64 } from '@scure/base'
import algosdk from 'algosdk'
import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'
import { receiptSigDigest } from '@txnlab/zs-proto/ticket'

import { type AckSettleResult, type SettleSubmission, ackSettle, settleArgsOf, settleGroupSpecOf } from './ack.js'
import { type CompletedOpenGroup, completeOpenGroup, type OpenGroupSpec } from './escrow/open.js'
import { completeSettleGroup } from './escrow/settle.js'
import { type MbrDeposit, type MbrPoolChain, MbrDepositUnaffordableError, ensureMbrDeposit, mbrPoolState } from './mbr.js'
import type { Operator } from './operator.js'
import type { EscrowCall, OpenHandle, ProtestReasonCode, WalletOpener } from './parts.js'
import { type Logger, type Signer, discardLogger } from './ports.js'
import type { SettleArgs } from './reconcile.js'

/** The escrow deployment the payer's groups must name. */
export interface EscrowChainConfig {
    appId: bigint
    /** The application account, receiver of the open's USDC transfer. */
    appAddress: string
    usdcAssetId: bigint
}

/** The payer's half of settle(); the contract freezes the ticket if any value differs from the node's. */
export interface PayerSettleCall {
    /** The 16-byte ticket id. */
    ticketIdRaw: Uint8Array
    args: SettleArgs
    maxPrice: bigint
    payer: string
    operatorOwnerAddr: string
    operatorId: bigint
    nodeId: bigint
}

export interface ProtestCall {
    ticketIdRaw: Uint8Array
    amountCharged: bigint
    /** 32 bytes. */
    receiptDigest: Uint8Array
    /** 64 bytes. */
    receiptSig: Uint8Array
    /** The contract caps its length; the caller truncates. */
    disputeExcerpt: Uint8Array
    reason: ProtestReasonCode
    operatorId: bigint
    nodeId: bigint
    payer: string
}

export interface RefundInactiveCall {
    ticketIdRaw: Uint8Array
    operatorId: bigint
    nodeId: bigint
    payer: string
}

export interface SettleLapsedCall {
    ticketIdRaw: Uint8Array
    operatorId: bigint
    nodeId: bigint
    /** A fallback: the chain prefers the owner the box snapshotted at open(). */
    operatorOwnerAddr: string
    payer: string
}

/**
 * EscrowChain is the escrow app as the wallet reaches it, Go's escrow.Client.
 * Each call that acts as the payer signs as the payer named in it. signal is
 * the request's, as Go's ctx is. The pool calls take none, so an
 * implementation bounds those itself: a pool read that never settles holds
 * every later open behind it.
 */
export interface EscrowChain extends MbrPoolChain {
    config(signal?: AbortSignal): Promise<EscrowChainConfig>
    /** The contract's protocolFeeBps global. */
    protocolFeeBps(signal?: AbortSignal): Promise<number>
    /**
     * Submits a signed group, concatenated in group order. Rejects with
     * algod's refusal; a revert commits nothing, so the same group can be
     * sent again.
     */
    sendGroup(signed: Uint8Array, signal?: AbortSignal): Promise<void>
    settleStandalone(c: PayerSettleCall, signal?: AbortSignal): Promise<SettleSubmission>
    protest(c: ProtestCall, signal?: AbortSignal): Promise<EscrowCall>
    refundInactive(c: RefundInactiveCall, signal?: AbortSignal): Promise<string>
    settleLapsed(c: SettleLapsedCall, signal?: AbortSignal): Promise<string>
    /** Reclaims unreserved pool balance; the contract caps it at what no ticket reserves. */
    withdrawMbr(payer: string, amount: bigint, signal?: AbortSignal): Promise<string>
    /** Closes the pool and opts out; reverts while any ticket is live. */
    closeDeposit(payer: string, signal?: AbortSignal): Promise<string>
}

const TICKET_ID_LEN = 16
const RECEIPT_SIG_LEN = 64

/** decodeTicketId is the 16 raw bytes the contract keys a ticket by. */
export function decodeTicketId(b64: string): Uint8Array {
    if (!b64) throw new Error('ticket id is empty')
    let raw: Uint8Array
    try {
        raw = base64.decode(b64)
    } catch (err) {
        throw new Error(`decode ticket id base64: ${message(err)}`, { cause: err })
    }
    if (raw.length !== TICKET_ID_LEN) throw new Error(`ticket id decodes to ${raw.length} bytes, want ${TICKET_ID_LEN}`)
    return raw
}

/** decodeReceiptSig is the receipt's 64-byte signature, which protest() passes on. */
export function decodeReceiptSig(b64: string): Uint8Array {
    let raw: Uint8Array
    try {
        raw = base64.decode(b64)
    } catch (err) {
        throw new Error(`decode base64: ${message(err)}`, { cause: err })
    }
    if (raw.length !== RECEIPT_SIG_LEN) throw new Error(`receipt sig length ${raw.length}, want ${RECEIPT_SIG_LEN}`)
    return raw
}

export interface WalletOptions {
    chain: EscrowChain
    signer: Signer
    /** The pool's working set; 0 or absent is the default. */
    depositSlots?: number
    logger?: Logger
}

/**
 * Wallet is the default WalletOpener. One per payer and process: the pool's
 * funding is serialized per instance, so two Wallets for one payer can each
 * fund it.
 */
export class Wallet implements WalletOpener {
    readonly #chain: EscrowChain
    readonly #signer: Signer
    readonly #slots: bigint
    readonly #log: Logger
    /** The chain with the free-quota box's existence latched: the contract never deletes one. */
    readonly #pool: MbrPoolChain
    #quotaBoxKnown = false
    #depositReady = false
    #depositLock: Promise<unknown> = Promise.resolve()

    constructor(o: WalletOptions) {
        if (!o.signer.address) throw new Error('wallet: signer has no address')
        this.#chain = o.chain
        this.#signer = o.signer
        this.#slots = slotCount(o.depositSlots)
        this.#log = o.logger ?? discardLogger
        this.#pool = {
            ticketMbr: () => o.chain.ticketMbr(),
            freeQuotaMbrDue: async (payer) => {
                if (this.#quotaBoxKnown) return 0n
                const due = await o.chain.freeQuotaMbrDue(payer)
                if (due === 0n) this.#quotaBoxKnown = true
                return due
            },
            readPayerDeposit: (payer) => o.chain.readPayerDeposit(payer),
            isPayerOptedIn: (payer) => o.chain.isPayerOptedIn(payer),
            spendableMicroAlgos: (payer) => o.chain.spendableMicroAlgos(payer),
            minTxnFee: () => o.chain.minTxnFee(),
            depositMbr: (payer, amount, optIn) => o.chain.depositMbr(payer, amount, optIn),
        }
    }

    payerAddr(): string {
        return this.#signer.address
    }

    protocolFeeBps(signal?: AbortSignal): Promise<number> {
        return this.#chain.protocolFeeBps(signal)
    }

    /**
     * Opens escrow for ticket through the node's presigned group. The group is
     * checked against the ticket and the operator's chain-resolved signing key
     * before the payer signs anything.
     */
    async open(ticket: Ticket, op: Operator, presignedOpenGroup: string, signal?: AbortSignal): Promise<OpenHandle> {
        if (op.id === 0) throw new Error('wallet: open: operator id is unset')
        if (!op.ownerAddr || !op.signingAddr) throw new Error('wallet: open: operator addresses incomplete')
        if (!presignedOpenGroup) {
            throw new Error('wallet: open: presignedOpenGroup is empty (operator did not return a pre-signed open group on reserve)')
        }
        let ticketIdRaw: Uint8Array
        try {
            ticketIdRaw = decodeTicketId(ticket.ticket_id)
        } catch (err) {
            throw new Error(`wallet: decode ticket id: ${message(err)}`, { cause: err })
        }
        // Before any deposit, as Go decodes them: a bad registry entry is not
        // the node's group failing its checks.
        if (!algosdk.isValidAddress(op.signingAddr)) {
            throw new Error(`wallet: decode node signing addr: ${op.signingAddr} is not an address`)
        }
        if (!algosdk.isValidAddress(this.#signer.address)) {
            throw new Error(`wallet: decode payer addr: ${this.#signer.address} is not an address`)
        }
        signal?.throwIfAborted()
        const cfg = await wrap('escrow config', this.#chain.config(signal))
        // Every value from the signature-verified ticket and the chain, never
        // the group. A grace of 0 is what makes the refund deadline the payer
        // computes sound; a node that authored another is refused.
        const spec: OpenGroupSpec = {
            appId: cfg.appId,
            appAddress: cfg.appAddress,
            ticketIdRaw,
            operatorId: BigInt(ticket.operator_id),
            nodeId: BigInt(ticket.node_id),
            maxPrice: BigInt(ticket.max_price),
            usdcAssetId: cfg.usdcAssetId,
            nodeSigningAddr: op.signingAddr,
            payerAddr: this.#signer.address,
            expiresAt: BigInt(ticket.expires_at),
            settlementGraceSeconds: 0n,
        }

        // open() draws its box MBR from the prepaid pool and reverts without one.
        try {
            await this.#ensureDepositForServe(signal)
        } catch (err) {
            throw new Error(`wallet: ensure MBR deposit: ${message(err)}`, { cause: err })
        }
        signal?.throwIfAborted()
        // Go's SubmitPresignedOpenGroup: check, sign, send. Nothing is signed
        // unless the group passes, and any failure, a refused group included,
        // takes the pool re-check below as it does in Go.
        const submit = async (): Promise<CompletedOpenGroup> => {
            const g = await completeOpenGroup(presignedOpenGroup, spec, this.#signer)
            await this.#chain.sendGroup(g.signedGroup, signal)
            return g
        }
        let group: CompletedOpenGroup
        try {
            group = await submit()
        } catch (sendErr) {
            const r = await this.#retryOpen(submit, sendErr, signal)
            if (r.group === undefined) {
                throw new Error(`wallet: submit presigned open group: ${message(r.err)}`, { cause: r.err })
            }
            group = r.group
        }
        return this.#handle({
            appCallTxId: group.txids[1]!,
            groupId: group.groupId,
            ticketId: ticket.ticket_id,
            operator: op,
            maxPrice: ticket.max_price,
            openFeesMicroalgos: Number(group.payerFeeMicroalgos),
            signedGroup: group.signedGroup,
        })
    }

    /**
     * A failed open may be a prepaid-pool revert whose guard a top-up now
     * satisfies (a withdraw or a new deployment emptied a pool the latch
     * called ready), so re-check the pool whatever the revert was. If the
     * top-up deposited, send the same group once more: the revert committed
     * nothing. Resolves to the group, or to the error left standing.
     */
    async #retryOpen(
        submit: () => Promise<CompletedOpenGroup>,
        sendErr: unknown,
        signal: AbortSignal | undefined,
    ): Promise<{ group: CompletedOpenGroup; err?: never } | { group?: never; err: unknown }> {
        const { deposited, err: depositErr } = await this.#serialized(signal, async () => {
            this.#depositReady = false
            try {
                const d = await ensureMbrDeposit(this.#pool, this.#signer.address, this.#slots)
                if (!d.belowTarget) {
                    this.#depositReady = true
                    return { deposited: d.deposited, err: undefined }
                }
                // Below target: the guard may still be satisfied now, but the
                // next request re-attempts the rest.
                return { deposited: d.deposited, err: new BelowTargetError(d.deposited) }
            } catch (err) {
                // Nothing landed, so the guard is unchanged: no retry.
                return { deposited: 0n, err }
            }
        })
        let err: unknown = sendErr
        if (deposited > 0n) {
            try {
                // The pool calls take no signal, so the top-up can land after
                // the request was cancelled; Go's ctx would have failed it.
                signal?.throwIfAborted()
                return { group: await submit() }
            } catch (again) {
                err = again
            }
        }
        // The top-up's failure names the ALGO the pool needs, which is what
        // the payer can act on; with none, the pool covers the working set and
        // the revert is exhaustion that clears as tickets settle. Both stay
        // reachable (findError), as Go's two-%w wrap keeps both for errors.Is.
        if (depositErr !== undefined) return { err: new OpenTopUpError(err, depositErr) }
        return { err }
    }

    /**
     * Runs fn after every earlier deposit pass. A caller whose signal aborts
     * stops waiting, but the next caller still waits for the pass ahead of it:
     * the lock is released by the holder settling, never by a waiter leaving.
     */
    #serialized<T>(signal: AbortSignal | undefined, fn: () => Promise<T>): Promise<T> {
        const prior = this.#depositLock
        const run = (async () => {
            await untilAborted(prior, signal)
            signal?.throwIfAborted()
            return fn()
        })()
        this.#depositLock = Promise.allSettled([prior, run])
        return run
    }

    /**
     * Funds the pool the first time an open needs it, then skips the read
     * once it covers the working set. A top-up the payer can't afford, or one
     * that falls short, is fatal only when the pool has no free slot: one
     * open draws one slot, so refusing a request a free slot could serve
     * would be a false "underfunded". Neither latches, so the next request
     * tries again.
     */
    #ensureDepositForServe(signal: AbortSignal | undefined): Promise<void> {
        return this.#serialized(signal, async () => {
            if (this.#depositReady) return
            let short: unknown
            let deposited = 0n
            try {
                const d = await ensureMbrDeposit(this.#pool, this.#signer.address, this.#slots)
                if (!d.belowTarget) {
                    this.#depositReady = true
                    return
                }
                deposited = d.deposited
            } catch (err) {
                if (!(err instanceof MbrDepositUnaffordableError)) throw err
                short = err
            }
            let free = 0n
            try {
                free = await this.#freeSlots()
            } catch {
                // An unreadable pool proves no headroom.
            }
            if (free >= 1n) return
            throw short ?? new BelowTargetError(deposited)
        })
    }

    async #freeSlots(): Promise<bigint> {
        const ticketMbr = await this.#chain.ticketMbr()
        if (ticketMbr <= 0n) throw new Error('wallet: free-deposit-slots: ticket MBR not loaded')
        const dep = await this.#chain.readPayerDeposit(this.#signer.address)
        return mbrPoolState(ticketMbr, dep).availableMicroalgos / ticketMbr
    }

    /** Funds the pool toward slots tickets; 0 is the default working set, as Go's EnsureDeposit has it. */
    ensureDeposit(slots = 0, signal?: AbortSignal): Promise<MbrDeposit> {
        return this.#serialized(signal, () => ensureMbrDeposit(this.#pool, this.#signer.address, slotCount(slots)))
    }

    withdrawDeposit(amount: bigint, signal?: AbortSignal): Promise<string> {
        return wrap('withdraw-deposit', this.#chain.withdrawMbr(this.#signer.address, amount, signal))
    }

    closeDeposit(signal?: AbortSignal): Promise<string> {
        return wrap('close-deposit', this.#chain.closeDeposit(this.#signer.address, signal))
    }

    #handle(fields: Omit<OpenHandle, 'ackSettle' | 'protest' | 'refundInactive' | 'settleLapsed'>): OpenHandle {
        const chain = this.#chain
        const signer = this.#signer
        const payer = signer.address
        const log = this.#log
        const ids = () => ({
            ticketIdRaw: decodeTicketId(fields.ticketId),
            operatorId: BigInt(fields.operator.id),
            nodeId: BigInt(fields.operator.nodeId),
        })
        return {
            ...fields,
            ackSettle(receipt: UsageReceipt, settleGroup: string | null, signal?: AbortSignal): Promise<AckSettleResult> {
                const group = settleGroup ?? ''
                return ackSettle({
                    // An empty group is none, as Go's len(group) > 0 reads it.
                    atomic: group !== '',
                    log,
                    // A spec that can't be built is the payer's failure, not the
                    // node's: the ack goes standalone and the node is not barred.
                    spec: async () => {
                        const cfg = await chain.config(signal)
                        return settleGroupSpecOf(receipt, {
                            appId: cfg.appId,
                            ticketIdRaw: decodeTicketId(fields.ticketId),
                            payerAddr: payer,
                            operatorSigningAddr: fields.operator.signingAddr,
                        })
                    },
                    submitGroup: async (spec) => {
                        const g = await completeSettleGroup(group, spec, signer)
                        await chain.sendGroup(g.signedGroup, signal)
                        return { txid: g.txid, payerFeeMicroalgos: g.payerFeeMicroalgos }
                    },
                    standalone: () =>
                        chain.settleStandalone(
                            {
                                ticketIdRaw: decodeTicketId(fields.ticketId),
                                args: settleArgsOf(receipt),
                                maxPrice: BigInt(fields.maxPrice),
                                payer,
                                operatorOwnerAddr: fields.operator.ownerAddr,
                                operatorId: BigInt(fields.operator.id),
                                nodeId: BigInt(fields.operator.nodeId),
                            },
                            signal,
                        ),
                })
            },
            async protest(receipt, excerpt, reason, signal) {
                let call: ProtestCall
                try {
                    call = {
                        ...ids(),
                        amountCharged: BigInt(receipt.amount_charged),
                        receiptDigest: receiptSigDigest(receipt),
                        receiptSig: decodeReceiptSig(receipt.sig ?? ''),
                        disputeExcerpt: excerpt,
                        reason,
                        payer,
                    }
                } catch (err) {
                    throw new Error(`wallet: protest: ${message(err)}`, { cause: err })
                }
                return wrap('protest', chain.protest(call, signal))
            },
            async refundInactive(signal) {
                return wrap('refund-inactive', (async () => chain.refundInactive({ ...ids(), payer }, signal))())
            },
            async settleLapsed(signal) {
                return wrap(
                    'settle-lapsed',
                    (async () =>
                        chain.settleLapsed({ ...ids(), operatorOwnerAddr: fields.operator.ownerAddr, payer }, signal))(),
                )
            },
        }
    }
}

/**
 * BelowTargetError: a deposit landed but left the pool short of the working
 * set, Go's ErrDepositBelowTarget. Not a failed deposit: the funds are in the
 * pool.
 */
export class BelowTargetError extends Error {
    override readonly name = 'BelowTargetError'

    constructor(readonly deposited: bigint) {
        super(`wallet: prepaid MBR pool funded below the configured working set (deposited ${deposited} µALGO)`)
    }
}

/**
 * OpenTopUpError: an open that failed, and the pool top-up its retry needed
 * that failed too. Both are reachable through findError, as Go's two-%w wrap
 * keeps both for errors.Is: the top-up's is what tells an underfunded payer
 * from a pool that is only exhausted for now.
 */
export class OpenTopUpError extends AggregateError {
    override readonly name = 'OpenTopUpError'

    constructor(
        readonly open: unknown,
        readonly topUp: unknown,
    ) {
        super([open, topUp], `${message(open)}; topping up the ticket pool: ${message(topUp)}`, { cause: open })
    }
}

// A slot count from a number: anything but a positive finite count is 0, the
// default working set.
function slotCount(n: number | undefined): bigint {
    return n !== undefined && Number.isFinite(n) && n >= 1 ? BigInt(Math.floor(n)) : 0n
}

// Resolves once p settles, or rejects with signal's reason if it aborts first.
function untilAborted(p: Promise<unknown>, signal: AbortSignal | undefined): Promise<unknown> {
    if (!signal) return p
    signal.throwIfAborted()
    return new Promise((resolve, reject) => {
        const onAbort = () => reject(signal.reason)
        signal.addEventListener('abort', onAbort, { once: true })
        p.then(
            (v) => {
                signal.removeEventListener('abort', onAbort)
                resolve(v)
            },
            (e: unknown) => {
                signal.removeEventListener('abort', onAbort)
                reject(e)
            },
        )
    })
}

async function wrap<T>(what: string, p: Promise<T>): Promise<T> {
    try {
        return await p
    } catch (err) {
        throw new Error(`wallet: ${what}: ${message(err)}`, { cause: err })
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
