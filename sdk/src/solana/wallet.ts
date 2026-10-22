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
import { type PublicKey, publicKeyBytes } from '@txnlab/zs-proto/solana'
import { type Deployment, type OpenOfferSpec, completeOpenOffer, decodeConfig, decodeOpenOffer, encodeOpenPayment } from '@txnlab/zs-proto/solana/zsescrow'
import type { Ticket } from '@txnlab/zs-proto/ticket'
import { RAIL_NEUTRAL_NAMES_MIN_VERSION, usesRailNeutralNames } from '@txnlab/zs-proto/wire'

import { MbrDepositUnaffordableError } from '../mbr.js'
import type { Operator } from '../operator.js'
import type { OpenHandle, WalletOpener } from '../parts.js'
import type { SolanaSigner } from '../ports.js'
import { untilAborted } from '../sleep.js'
import { decodeTicketId, slotCount } from '../wallet.js'
import type { ConfirmOptions } from './confirm.js'
import { RentDepositBelowTargetError, SolanaRentPool } from './rent.js'
import type { SolanaRpc } from './rpc.js'

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
    /** Tunes the wait for a rent deposit to land; absent polls. */
    confirm?: Omit<ConfirmOptions, 'signal'> | undefined
    /** Milliseconds since the epoch; Date.now by default. */
    clock?: () => number
}

/**
 * SolanaWallet opens tickets on the Solana rail, as Wallet does on Algorand.
 * Go's zs.SolanaWallet.
 */
export class SolanaWallet implements WalletOpener {
    readonly #deployment: Deployment
    readonly #signer: SolanaSigner
    readonly #payerUsdc: PublicKey
    readonly #decimals: number
    readonly #pool: SolanaRentPool
    readonly #slots: bigint
    readonly #clock: () => number
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

    private constructor(o: SolanaWalletOptions, decimals: number) {
        this.#deployment = o.deployment
        this.#signer = o.signer
        this.#payerUsdc = o.deployment.tokenAccount(o.signer.address)
        this.#decimals = decimals
        this.#pool = new SolanaRentPool({ rpc: o.rpc, deployment: o.deployment, signer: o.signer, confirm: o.confirm })
        this.#slots = slotCount(o.depositSlots)
        this.#clock = o.clock ?? Date.now
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
        return new SolanaWallet(o, config.usdcDecimals)
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
        return solanaHandle({
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

function railNeutralNamesError(op: Pick<Operator, 'protoVersion'>): Error {
    return new Error(`wallet: open: node runs protocol ${JSON.stringify(op.protoVersion ?? '')}; a Solana open needs ${RAIL_NEUTRAL_NAMES_MIN_VERSION} or later`)
}

// A Solana open's handle, whose settle paths aren't built yet. Each fails as
// Go's does on a handle with no Algorand wallet.
function solanaHandle(fields: Omit<OpenHandle, 'ackSettle' | 'protest' | 'freezeOverclaim' | 'refundInactive' | 'settleLapsed'>): OpenHandle {
    const unsupported = (what: string) => new Error(`wallet: ${what} on Solana is not supported yet`)
    return {
        ...fields,
        ackSettle: () => Promise.resolve({ txid: '', feeMicroalgos: 0, groupRejected: false, err: unsupported('ack-settle') }),
        protest: () => Promise.reject(unsupported('protest')),
        freezeOverclaim: () => Promise.resolve({ claim: 'unreadable', err: unsupported('freeze') }),
        refundInactive: () => Promise.reject(unsupported('refund-inactive')),
        settleLapsed: () => Promise.reject(unsupported('settle-lapsed')),
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
