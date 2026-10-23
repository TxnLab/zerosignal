/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's wallet on the Solana rail, the twin of go/zs solana_wallet.go:
// it checks the node's open offer against the ticket and the node's
// registered signing key, funds the payer's rent pool, and signs the offer.
// It never submits the open. The node does, from the sealed request's
// payment_open, so the wallet needs a node that reads the rail-neutral names.

import { base64 } from '@scure/base'
import {
    type Instruction,
    type PublicKey,
    TOKEN_PROGRAM_ID,
    compileMessage,
    ed25519Verify,
    encodeTransaction,
    newTransaction,
    publicKeyBytes,
    setComputeUnitLimit,
    signTransactionWith,
} from '@txnlab/zs-proto/solana'
import {
    type Deployment,
    type Ending,
    ERR_PAST_DEADLINE,
    type OpenOfferSpec,
    TOKEN_INITIALIZED,
    type Ticket as TicketAccount,
    completeOpenOffer,
    decodeConfig,
    decodeOpenOffer,
    decodeTicket,
    decodeTokenAccount,
    encodeOpenPayment,
    parseOpenSeq,
    signReceiptAck,
} from '@txnlab/zs-proto/solana/zsescrow'
import { type Ticket, type UsageReceipt, receiptCanonicalBytes, receiptSigDigest } from '@txnlab/zs-proto/ticket'
import { RAIL_NEUTRAL_NAMES_MIN_VERSION, usesRailNeutralNames } from '@txnlab/zs-proto/wire'

import {
    type AckSettleResult,
    NoSettleAckRouteError,
    ProtestAfterDeadlineError,
    SentSettleError,
    type SettleSubmission,
    ackSettle,
    settleArgsOf,
} from '../ack.js'
import { findError } from '../errors.js'
import { MbrDepositUnaffordableError } from '../mbr.js'
import type { Operator } from '../operator.js'
import type { EscrowCall, OpenHandle, OverclaimFreeze, WalletOpener } from '../parts.js'
import { type Logger, type SolanaSigner, discardLogger } from '../ports.js'
import { type ClaimVerdict, type SettleArgs, judgeSolanaClaim } from '../reconcile.js'
import { untilAborted } from '../sleep.js'
import { decodeReceiptSig, decodeTicketId, followUpSignal, slotCount } from '../wallet.js'
import { solanaClaimFields } from './claim.js'
import { type ConfirmOptions, confirmSignature } from './confirm.js'
import { RentDepositBelowTargetError, SOLANA_SIGNATURE_FEE, SolanaRentPool } from './rent.js'
import { type SolanaRpc, SolanaRpcError, txCustomError, txErrorName } from './rpc.js'

// Confirmed, as the rent pool reads and sends.
const COMMITMENT = 'confirmed'

/**
 * How long past a ticket's expires_at the wallet remembers signing its open.
 * The program refuses an open past expires_at by the cluster's clock, which
 * may trail this machine's; the margin is generous because each ticket costs
 * the wallet one map entry. Go's signedOpenRetention.
 */
export const SIGNED_OPEN_RETENTION_MS = 10 * 60_000

export interface SolanaWalletOptions {
    rpc: SolanaRpc
    deployment: Deployment
    signer: SolanaSigner
    /** The rent pool's working set; 0 or absent is the default. */
    depositSlots?: number
    /** Tunes the wait for a rent deposit or an ack to land; absent polls. */
    confirm?: Omit<ConfirmOptions, 'signal'> | undefined
    /** Milliseconds since the epoch; Date.now by default. */
    clock?: () => number
    /** Receives the wallet's warnings; absent discards them. */
    log?: Logger
}

/**
 * SolanaWallet opens tickets on the Solana rail, as Wallet does on Algorand.
 * Go's zs.SolanaWallet.
 */
export class SolanaWallet implements WalletOpener {
    readonly #rpc: SolanaRpc
    readonly #confirm: Omit<ConfirmOptions, 'signal'> | undefined
    readonly #deployment: Deployment
    readonly #signer: SolanaSigner
    readonly #payerUsdc: PublicKey
    readonly #decimals: number
    /** The Config's genesis hash, which the ack digest binds. The program fixes it at initialize. */
    readonly #genesis: string
    readonly #pool: SolanaRentPool
    readonly #slots: bigint
    readonly #clock: () => number
    readonly #log: Logger
    #depositReady = false
    #depositLock: Promise<unknown> = Promise.resolve()
    /**
     * Each ticket this wallet signed an open for, by base64 id, with its
     * expires_at in seconds. The ack binds the node's open_seq, which is safe
     * only while the payer signs one open per ticket id at a node (SPEC.md
     * § 3a "The open and the ack on Solana"): a second offer for the same
     * ticket, on a fresh blockhash, could open it again once the first closed.
     */
    readonly #signed = new Map<string, number>()

    private constructor(o: SolanaWalletOptions, decimals: number, genesis: string) {
        this.#rpc = o.rpc
        this.#confirm = o.confirm
        this.#deployment = o.deployment
        this.#signer = o.signer
        this.#payerUsdc = o.deployment.tokenAccount(o.signer.address)
        this.#decimals = decimals
        this.#genesis = genesis
        this.#pool = new SolanaRentPool({ rpc: o.rpc, deployment: o.deployment, signer: o.signer, confirm: o.confirm })
        this.#slots = slotCount(o.depositSlots)
        this.#clock = o.clock ?? Date.now
        this.#log = o.log ?? discardLogger
    }

    /**
     * Reads the deployment's Config for the mint's decimals, which an offer's
     * transfer must carry. The Config must name the deployment's mint: the
     * wallet would otherwise check offers against one mint while the program
     * draws on another.
     */
    static async create(o: SolanaWalletOptions, signal?: AbortSignal): Promise<SolanaWallet> {
        try {
            publicKeyBytes(o.signer.address)
        } catch (err) {
            throw new Error(`solana wallet: payer address: ${message(err)}`, { cause: err })
        }
        let acct
        try {
            acct = await o.rpc.getAccountInfo(o.deployment.config(), { commitment: 'confirmed', signal })
        } catch (err) {
            throw new Error(`solana wallet: read config: ${message(err)}`, { cause: err })
        }
        if (acct === null || acct.owner !== o.deployment.program) {
            throw new Error(`solana wallet: program ${o.deployment.program} has no Config`)
        }
        let config
        try {
            config = decodeConfig(acct.data)
        } catch (err) {
            throw new Error(`solana wallet: ${message(err)}`, { cause: err })
        }
        if (config.usdcMint !== o.deployment.mint) {
            throw new Error(`solana wallet: the Config's mint is ${config.usdcMint}, not the deployment's ${o.deployment.mint}`)
        }
        return new SolanaWallet(o, config.usdcDecimals, config.genesisHash)
    }

    payerAddr(): string {
        return this.#signer.address
    }

    /** Refuses: the sealed run calls it only for a node that doesn't submit the open, and on Solana the node always does. */
    open(): Promise<OpenHandle> {
        return Promise.reject(new Error('wallet: open: on Solana the node submits the open (openForNode)'))
    }

    /**
     * Checks the node's offer (presigned_open_txn) against ticket and op, tops
     * up the rent pool, and signs the offer. The handle carries the signed
     * transaction as openGroup (payment_open) and its id as appCallTxId
     * (payment_ref). Nothing is broadcast: the open lands when the node
     * submits it, before the ticket's expires_at or not at all.
     */
    async openForNode(ticket: Ticket, op: Operator, presignedOpen: string, signal?: AbortSignal): Promise<OpenHandle> {
        if (!usesRailNeutralNames(op.protoVersion)) throw railNeutralNamesError(op)
        if (op.id === 0) throw new Error('wallet: open: operator id is unset')
        if (!op.ownerAddr || !op.signingAddr) throw new Error('wallet: open: operator addresses incomplete')
        if (!presignedOpen) {
            throw new Error('wallet: open: presigned open offer is empty (operator did not return one on reserve)')
        }
        let offer: Uint8Array
        try {
            offer = decodeOpenOffer(presignedOpen)
        } catch (err) {
            throw new Error(`wallet: open: decode presigned open offer: ${message(err)}`, { cause: err })
        }
        let ticketId: Uint8Array
        try {
            ticketId = decodeTicketId(ticket.ticket_id)
        } catch (err) {
            throw new Error(`wallet: decode ticket id: ${message(err)}`, { cause: err })
        }
        try {
            publicKeyBytes(op.signingAddr)
        } catch (err) {
            throw new Error(`wallet: decode node signing addr: ${message(err)}`, { cause: err })
        }
        // Every value from the signature-verified ticket, the operator's
        // chain-resolved signing key and the Config, never from the offer.
        const spec: OpenOfferSpec = {
            nodeSigning: op.signingAddr,
            operatorId: BigInt(ticket.operator_id),
            nodeId: BigInt(ticket.node_id),
            payer: this.#signer.address,
            payerUsdc: this.#payerUsdc,
            decimals: this.#decimals,
            ticketId,
            maxPrice: BigInt(ticket.max_price),
            expiresAt: BigInt(ticket.expires_at),
        }
        // Claimed before the deposit, so a ticket already signed for costs no
        // top-up, and released if nothing gets signed.
        const key = base64.encode(ticketId)
        this.#claimOpen(key, ticket.expires_at)
        let completed: Uint8Array
        try {
            // The open draws the ticket's rent from the pool and fails without
            // it. Nothing reached the chain, so a pool too short at submit
            // surfaces at the node, which refuses the request, and the sealed
            // run answers that with recheckDeposit.
            try {
                await this.#ensureDepositForServe(signal)
            } catch (err) {
                throw new Error(`wallet: ensure rent deposit: ${message(err)}`, { cause: err })
            }
            signal?.throwIfAborted()
            try {
                completed = await completeOpenOffer(this.#deployment, offer, spec, this.#signer)
            } catch (err) {
                throw new Error(`wallet: complete open offer: ${message(err)}`, { cause: err })
            }
        } catch (err) {
            this.#signed.delete(key)
            throw err
        }
        let payment: { paymentOpen: string; paymentRef: string }
        try {
            payment = encodeOpenPayment(completed)
        } catch (err) {
            throw new Error(`wallet: complete open offer: ${message(err)}`, { cause: err })
        }
        return this.handleFor({
            appCallTxId: payment.paymentRef,
            groupId: '',
            ticketId: ticket.ticket_id,
            operator: op,
            maxPrice: ticket.max_price,
            openFeesMicroalgos: 0,
            signedGroup: completed,
            openGroup: payment.paymentOpen,
        })
    }

    // Records that the wallet is about to sign an open for key, or throws when
    // it has signed one already or another call is signing one. It forgets
    // tickets whose opens can no longer land.
    #claimOpen(key: string, expiresAt: number): void {
        const horizon = Math.floor((this.#clock() - SIGNED_OPEN_RETENTION_MS) / 1000)
        for (const [k, exp] of this.#signed) if (exp < horizon) this.#signed.delete(k)
        if (this.#signed.has(key)) throw new Error(`wallet: open: already signed, or is signing, an open for ticket ${key}`)
        this.#signed.set(key, expiresAt)
    }

    /**
     * Wallet's #ensureDepositForServe for the rent pool: a top-up the payer
     * can't afford, or one that fell short, still serves while the pool can
     * fund this one ticket.
     */
    #ensureDepositForServe(signal: AbortSignal | undefined): Promise<void> {
        const prior = this.#depositLock
        const run = (async () => {
            await untilAborted(prior, signal)
            signal?.throwIfAborted()
            if (this.#depositReady) return
            let short: unknown
            let deposited = 0n
            try {
                const d = await this.#pool.ensureDeposit(this.#slots, signal)
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
                free = await this.#pool.freeSlots(signal)
            } catch {
                // An unreadable pool proves no headroom.
            }
            if (free >= 1n) return
            throw short ?? new RentDepositBelowTargetError(deposited)
        })()
        this.#depositLock = Promise.allSettled([prior, run])
        return run
    }

    /**
     * Reads the ticket account for ticketId at the node, null when there is
     * none: never opened, or ended and closed. An account the program doesn't
     * own is no ticket either, since only the program can write one at the
     * address. Go's readTicket.
     */
    async readTicket(operatorId: bigint, nodeId: bigint, ticketId: Uint8Array, signal?: AbortSignal): Promise<TicketAccount | null> {
        const d = this.#deployment
        let acct
        try {
            acct = await this.#rpc.getAccountInfo(d.ticket(d.node(operatorId, nodeId), ticketId), { commitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana wallet: read ticket: ${message(err)}`, { cause: err })
        }
        if (acct === null || acct.owner !== d.program) return null
        try {
            return decodeTicket(acct.data)
        } catch (err) {
            throw new Error(`solana wallet: read ticket: ${message(err)}`, { cause: err })
        }
    }

    /**
     * Sends the payer's half at a on t, the ticket account for ticketId at the
     * node, and waits for it to confirm: Algorand's standalone settle. On a
     * node's claim it settles the ticket when a matches and freezes it when
     * not; on an open ticket it is the first half, which the node answers or
     * refund_inactive refunds. What to send is the caller's decision; this
     * only refuses a ticket that isn't the payer's before asking the signer,
     * since the program refuses it. Once sent, a failure throws
     * SolanaAckSendError, carrying the signature to look for, and the fee and
     * program error of a transaction that landed and failed. Go's sendAck.
     */
    async sendAck(t: TicketAccount | null, operatorId: bigint, nodeId: bigint, ticketId: Uint8Array, a: SettleArgs, signal?: AbortSignal): Promise<SolanaAck> {
        const e = await this.#ending('ack', t, operatorId, nodeId, ticketId, signal)
        return this.#send('ack', [this.#deployment.ack(e, solanaClaimFields(a))], SOLANA_SIGNATURE_FEE, signal)
    }

    // The Ending of t, the ticket account for ticketId at the node, for the
    // payer to submit, with the treasury fallback a refund to the payer needs.
    // It refuses a ticket that isn't the payer's, since the program refuses
    // the payer's ack or protest there and a refund or lapse there is not this
    // wallet's to pay for. Go's ending.
    async #ending(what: string, t: TicketAccount | null, operatorId: bigint, nodeId: bigint, ticketId: Uint8Array, signal: AbortSignal | undefined): Promise<Ending> {
        const owned = this.#ownsTicket(what, t)
        const payer = this.#signer.address
        return { submitter: payer, operatorId, nodeId, ticketId, rentPayer: owned.rentPayer, payer, ...(await this.#refundFallback(what, signal)) }
    }

    #ownsTicket(what: string, t: TicketAccount | null): TicketAccount {
        if (t === null) throw new Error(`solana wallet: ${what}: no ticket account`)
        const payer = this.#signer.address
        if (t.payer !== payer) throw new Error(`solana wallet: ${what}: the ticket's payer is ${t.payer}, not this wallet's ${payer}`)
        return t
    }

    // Signs ixs as the payer's own transaction, sends it and waits for it to
    // confirm. fee is what the transaction costs: the payer sets no priority
    // fee, so it is the signature fee for each signature the runtime
    // verifies, its own and any precompile's. Once sent, a failure throws
    // SolanaAckSendError. Go's send.
    async #send(what: string, ixs: Instruction[], fee: bigint, signal: AbortSignal | undefined): Promise<SolanaAck> {
        const payer = this.#signer.address
        let bh
        try {
            bh = await this.#rpc.getLatestBlockhash({ commitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana wallet: ${what}: blockhash: ${message(err)}`, { cause: err })
        }
        let tx
        try {
            tx = newTransaction(compileMessage(payer, bh.blockhash, ixs, 'legacy'))
            await signTransactionWith(tx, payer, this.#signer)
        } catch (err) {
            throw new Error(`solana wallet: ${what}: ${message(err)}`, { cause: err })
        }
        let signature: string
        try {
            // Preflight at the commitment the ticket was read at, which the
            // RPC's finalized default may not have reached.
            signature = await this.#rpc.sendTransaction(encodeTransaction(tx), { preflightCommitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana wallet: send ${what}: ${message(err)}`, { cause: err })
        }
        let r
        try {
            r = await confirmSignature(this.#rpc, signature, bh.lastValidBlockHeight, COMMITMENT, { ...this.#confirm, signal })
        } catch (err) {
            throw new SolanaAckSendError(signature, 0n, null, `solana wallet: ${what} ${signature}: ${message(err)}`, err)
        }
        if (r.err !== null) {
            throw new SolanaAckSendError(signature, fee, r.err, `solana wallet: ${what} ${signature} failed: ${txErrorName(r.err)} ${JSON.stringify(r.err)}`)
        }
        return { signature, feeLamports: fee }
    }

    // The treasury's USDC account, writable, when the payer's own token
    // account can't take a refund the ending may pay, so the refund is
    // forfeited to it as Algorand's payOrForfeit forfeits it. Otherwise the
    // ending leaves it out: a write lock on the one protocol-wide account
    // would put every settle in one lane. The treasury comes from the Config,
    // which set_config can change. Go's refundFallback.
    async #refundFallback(what: string, signal: AbortSignal | undefined): Promise<Pick<Ending, 'treasury' | 'fallback'>> {
        const d = this.#deployment
        let acct
        try {
            acct = await this.#rpc.getAccountInfo(this.#payerUsdc, { commitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana wallet: ${what}: read the payer's token account: ${message(err)}`, { cause: err })
        }
        if (canReceiveRefund(acct, d.mint, this.#signer.address)) return {}
        let cfg
        try {
            cfg = await this.#rpc.getAccountInfo(d.config(), { commitment: COMMITMENT, signal })
        } catch (err) {
            throw new Error(`solana wallet: ${what}: read config: ${message(err)}`, { cause: err })
        }
        if (cfg === null || cfg.owner !== d.program) throw new Error(`solana wallet: ${what}: program ${d.program} has no Config`)
        let config
        try {
            config = decodeConfig(cfg.data)
        } catch (err) {
            throw new Error(`solana wallet: ${what}: ${message(err)}`, { cause: err })
        }
        return { treasury: config.treasury, fallback: 'writable' }
    }

    // The ending ix builds for h's ticket, read first for the rent payer the
    // ending returns its rent to. Go's solanaEnd.
    async #end(h: OpenHandle, what: string, ix: (e: Ending) => Instruction, signal: AbortSignal | undefined): Promise<string> {
        const { ticketId, opId, nodeId } = handleIds(what, h)
        const t = await this.readTicket(opId, nodeId, ticketId, signal)
        const e = await this.#ending(what, t, opId, nodeId, ticketId, signal)
        return (await this.#send(what, [ix(e)], SOLANA_SIGNATURE_FEE, signal)).signature
    }

    // The handle's protest: the receipt, with the node's signature over its
    // digest in an Ed25519 precompile instruction before the protest, by the
    // key the ticket took at open. The program has no dispute excerpt. One
    // the program refuses because the settle window has closed throws
    // ProtestAfterDeadlineError, as Algorand's revert names it. Go's
    // solanaProtest.
    async #protest(h: OpenHandle, receipt: UsageReceipt, reason: number, signal: AbortSignal | undefined): Promise<EscrowCall> {
        const { ticketId, opId, nodeId } = handleIds('protest', h)
        let sig
        try {
            sig = decodeReceiptSig(receipt.sig ?? '')
        } catch (err) {
            throw new Error(`solana wallet: protest: decode receipt sig: ${message(err)}`, { cause: err })
        }
        // Go's types allow a reason the program's u8 can't carry; so does a
        // host's number.
        if (!Number.isInteger(reason) || reason < 0 || reason > 0xff) throw new Error(`solana wallet: protest: reason ${reason} is past the program's 255`)
        const t = this.#ownsTicket('protest', await this.readTicket(opId, nodeId, ticketId, signal))
        const digest = receiptSigDigest(receipt)
        const d = this.#deployment
        try {
            const r = await this.#send(
                'protest',
                [
                    setComputeUnitLimit(PROTEST_COMPUTE_UNITS),
                    ed25519Verify(t.nodeSigning, sig, digest),
                    d.protest(this.#signer.address, opId, nodeId, ticketId, receiptCanonicalBytes(receipt), reason),
                ],
                2n * SOLANA_SIGNATURE_FEE, // the payer's signature and the precompile's
                signal,
            )
            return { txId: r.signature, feeMicroalgos: Number(r.feeLamports) }
        } catch (err) {
            if (refusedAs(err, ERR_PAST_DEADLINE)) throw new ProtestAfterDeadlineError(err)
            throw err
        }
    }

    // The handle's freezeOverclaim: when the node's claim on the ticket takes
    // more than the receipt charges, the payer's ack at the receipt, which
    // freezes it; nothing otherwise. The program always has resolve_frozen.
    // It never rejects. Go's solanaFreezeOverclaim.
    async #freezeOverclaim(h: OpenHandle, receipt: UsageReceipt, signal: AbortSignal | undefined): Promise<OverclaimFreeze> {
        let ids, a: SettleArgs, t: TicketAccount | null
        try {
            ids = handleIds('freeze', h)
            a = settleArgsOf(receipt)
            t = await this.readTicket(ids.opId, ids.nodeId, ids.ticketId, signal)
        } catch (err) {
            return { claim: 'unreadable', err }
        }
        const claim = judgeSolanaClaim(a, t)
        if (claim !== 'overclaims') return { claim }
        try {
            const r = await this.sendAck(t, ids.opId, ids.nodeId, ids.ticketId, a, signal)
            return { claim, call: { txid: r.signature, payerFeeMicroalgos: r.feeLamports } }
        } catch (err) {
            return { claim, err: new Error(`wallet: freeze: ${message(err)}`, { cause: err }) }
        }
    }

    /**
     * @internal A Solana open's handle, which openForNode returns and a test
     * builds for a ticket it holds. Each settle path is the payer's own
     * transaction, as Go's Solana handle sends it.
     */
    handleFor(fields: Omit<OpenHandle, 'ackSettle' | 'protest' | 'freezeOverclaim' | 'refundInactive' | 'settleLapsed'>): OpenHandle {
        const d = this.#deployment
        const h: OpenHandle = {
            ...fields,
            ackSettle: (receipt, settleGroup, signal) => this.#ackSettle(h, receipt, settleGroup ?? '', signal),
            protest: (receipt, _excerpt, reason, signal) => this.#protest(h, receipt, reason, signal),
            freezeOverclaim: (receipt, signal) => this.#freezeOverclaim(h, receipt, signal),
            // Anyone may send either, so each races the node's own, and
            // whichever lands second fails on the closed ticket.
            refundInactive: (signal) => this.#end(h, 'refund-inactive', (e) => d.refundInactive(e), signal),
            settleLapsed: (signal) => this.#end(h, 'settle-lapsed', (e) => d.settleLapsed(e), signal),
        }
        return h
    }

    /**
     * The handle's ackSettle, through Algorand's decision (ackSettle). slot is
     * the node's open_seq, or '' for none. The node's half is its
     * settle_cooperative, which only it can submit, so the payer hands it the
     * ack: its signature over the receipt's ack digest, as payment_settle.
     * With no slot, or no relay to carry the ack, the payer sends its own ack
     * transaction instead, as Algorand's standalone settle: over the node's
     * claim it settles the ticket or freezes it, and on an open ticket it is
     * the payer's first half. The ticket account read for the claim is the one
     * that ack names. Go's solanaAckSettle.
     */
    async #ackSettle(h: OpenHandle, receipt: UsageReceipt, slot: string, signal: AbortSignal | undefined): Promise<AckSettleResult> {
        // It never rejects, as the handle's ackSettle promises.
        let ticketId: Uint8Array, opId: bigint, nodeId: bigint, a: SettleArgs
        try {
            ticketId = decodeTicketId(h.ticketId)
            opId = BigInt(h.operator.id)
            nodeId = BigInt(h.operator.nodeId)
            a = settleArgsOf(receipt)
        } catch (err) {
            return { txid: '', feeMicroalgos: 0, groupRejected: false, err: new Error(`wallet: ack-settle: ${message(err)}`, { cause: err }) }
        }
        // As on Algorand: what follows a failed delivery runs on a budget of
        // its own.
        let follow = signal
        let t: TicketAccount | null = null
        let readOk = false
        const read = async (): Promise<ClaimVerdict> => {
            t = await this.readTicket(opId, nodeId, ticketId, follow)
            readOk = true
            return judgeSolanaClaim(a, t)
        }
        const ack = async (): Promise<SettleSubmission> => {
            // An unreadable claim is acked anyway, as on Algorand, which needs
            // the account it couldn't read.
            if (!readOk) await read()
            const r = await this.sendAck(t, opId, nodeId, ticketId, a, follow)
            return { txid: r.signature, payerFeeMicroalgos: r.feeLamports }
        }
        return ackSettle<bigint>({
            atomic: slot !== '',
            log: this.#log,
            // The caller checked that it parses (checkSettleSlot).
            spec: async () => parseOpenSeq(slot),
            submitGroup: async (openSeq) => {
                try {
                    const deliver = h.deliverAck
                    if (!deliver) throw new NoSettleAckRouteError()
                    const sig = await signReceiptAck(this.#signer, this.#signer.address, this.#deployment, this.#genesis, opId, nodeId, ticketId, openSeq, receipt)
                    // The node submits its settle with the ack and pays its fee.
                    await deliver({ ticket_id: h.ticketId, settle_group: sig }, signal)
                    return { txid: '', payerFeeMicroalgos: 0n }
                } catch (err) {
                    // With no route nothing was sent, so the standalone ack
                    // keeps the caller's budget, as with no slot.
                    if (!(err instanceof NoSettleAckRouteError)) follow = followUpSignal(signal)
                    throw err
                }
            },
            claim: read,
            standalone: ack,
            freeze: ack,
            half: ack,
            // The program always has resolve_frozen.
            resolvesFrozen: async () => true,
        })
    }

    /**
     * Clears the ready latch, so the next open reads the pool again: a node
     * refused an open the wallet signed, perhaps for a pool emptied outside
     * this wallet. Go's RecheckDeposit, except that Go waits for a funding
     * pass in flight and this doesn't: a pass that read the pool before it
     * emptied can still set the latch, and the next refusal clears it again.
     */
    recheckDeposit(): void {
        this.#depositReady = false
    }
}

/** The payer's own ack transaction once sent. Go's solanaAck. */
export interface SolanaAck {
    signature: string
    /** What the payer paid for it. */
    feeLamports: bigint
}

/**
 * An ack sent that didn't settle: it landed and failed, having paid
 * feeLamports, with txErr the TransactionError whose custom code tells a
 * deadline the ack lost to apart from a refund it couldn't route; or it never
 * confirmed (feeLamports 0, txErr null), and unless the cause is a
 * TransactionExpiredError it may still land, so the signature lets the caller
 * look before it sends another.
 */
export class SolanaAckSendError extends SentSettleError {
    override readonly name = 'SolanaAckSendError'

    constructor(
        readonly signature: string,
        readonly feeLamports: bigint,
        readonly txErr: unknown,
        msg: string,
        cause?: unknown,
    ) {
        super({ txid: signature, payerFeeMicroalgos: feeLamports }, msg, cause)
    }
}

/** The program's can_receive: a token account of mint, owned by owner and not frozen, which the token program owns. Go's canReceiveRefund. */
export function canReceiveRefund(acct: { owner: PublicKey; data: Uint8Array } | null, mint: PublicKey, owner: PublicKey): boolean {
    if (acct === null || acct.owner !== TOKEN_PROGRAM_ID) return false
    try {
        const t = decodeTokenAccount(acct.data)
        return t.mint === mint && t.owner === owner && t.state === TOKEN_INITIALIZED
    } catch {
        return false
    }
}

// Caps a protest's compute, the limit the program's own tests send it under.
// A protest uses about a quarter of it; with no priority fee the limit costs
// nothing. Go's protestComputeUnits.
const PROTEST_COMPUTE_UNITS = 60_000

function handleIds(what: string, h: OpenHandle): { ticketId: Uint8Array; opId: bigint; nodeId: bigint } {
    try {
        return { ticketId: decodeTicketId(h.ticketId), opId: BigInt(h.operator.id), nodeId: BigInt(h.operator.nodeId) }
    } catch (err) {
        throw new Error(`solana wallet: ${what}: decode ticket id: ${message(err)}`, { cause: err })
    }
}

// Whether a transaction failed on the program's error code: in its
// simulation, which sendTransaction's preflight runs, or once landed. Go's
// refusedAs.
function refusedAs(err: unknown, code: number): boolean {
    const landed = findError(err, SolanaAckSendError)
    const txErr = landed !== undefined ? landed.txErr : findError(err, SolanaRpcError)?.txErr
    return txCustomError(txErr) === code
}

function railNeutralNamesError(op: Pick<Operator, 'protoVersion'>): Error {
    return new Error(`wallet: open: node runs protocol ${JSON.stringify(op.protoVersion ?? '')}; a Solana open needs ${RAIL_NEUTRAL_NAMES_MIN_VERSION} or later`)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
