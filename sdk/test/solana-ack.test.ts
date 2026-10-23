/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// SolanaWallet's readTicket and sendAck, over the program's own ack
// transaction from the shared transaction vectors: the twin of go/zs
// solana_ack_test.go.

import { readFileSync } from 'node:fs'

import * as ed25519 from '@noble/ed25519'
import { base64 } from '@scure/base'
import {
    type Transaction,
    TOKEN_PROGRAM_ID,
    compileMessage,
    encodeBase58,
    encodeMessage,
    encodeTransaction,
    parseTransaction,
    publicKeyBytes,
    verifySignatures,
    verifyStrict,
} from '@txnlab/zs-proto/solana'
import {
    type ClaimFields,
    type Ending,
    Deployment,
    PROGRAM_ID,
    TICKET_OPEN,
    TICKET_PENDING_BY_OPERATOR,
    TOKEN_FROZEN,
    TOKEN_INITIALIZED,
    TOKEN_UNINITIALIZED,
    claimHash,
    decodeAckSignature,
    decodeConfig,
    decodeTicket,
    receiptAckDigest,
} from '@txnlab/zs-proto/solana/zsescrow'
import type { UsageReceipt } from '@txnlab/zs-proto/ticket'
import type { SettleAck } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { NoSettleAckRouteError, settleArgsOf } from '../src/ack.js'
import type { Operator } from '../src/operator.js'
import type { OpenHandle } from '../src/parts.js'
import type { SolanaSigner } from '../src/ports.js'
import type { ClaimVerdict } from '../src/reconcile.js'
import { solanaClaimFields } from '../src/solana/claim.js'
import { TransactionExpiredError } from '../src/solana/confirm.js'
import { SOLANA_SIGNATURE_FEE } from '../src/solana/rent.js'
import type { Account, SignatureStatus, SolanaRpc } from '../src/solana/rpc.js'
import { SolanaAckSendError, SolanaWallet } from '../src/solana/wallet.js'

type Json = Record<string, any>

const readJson = (name: string) => JSON.parse(readFileSync(new URL(`../../testdata/${name}`, import.meta.url), 'utf8')) as Json
const signVectors = readJson('solana_sign_vectors.json')
const txVectors = readJson('solana_tx_vectors.json')
const accountVectors = readJson('solana_account_vectors.json')

const MINT: string = signVectors.usdc_mint
const d = new Deployment(PROGRAM_ID, MINT)
const accountData = (name: string) => base64.decode(accountVectors.accounts.find((a: Json) => a.name === name).data_base64)
const CONFIG = accountData('config_initialized')
const TICKET_ADDR: string = accountVectors.accounts.find((a: Json) => a.name === 'ticket_pending').address
const TICKET_DATA = accountData('ticket_pending')

// The program's own ack: the payer answers the node's pending claim.
const ACK = txVectors.transactions.find((x: Json) => x.name === 'ack')
const ARGS = settleArgsOf(ACK.receipt_value as UsageReceipt)
const TICKET_ID = base64.decode(ACK.receipt_value.ticket_id)
const [OPERATOR_ID, NODE_ID] = (() => {
    for (let op = 1n; op < 8n; op++) for (let n = 1n; n < 8n; n++) if (d.ticket(d.node(op, n), TICKET_ID) === TICKET_ADDR) return [op, n]
    throw new Error("the ack fixture's ticket is not at any node 1..7 of operators 1..7")
})()

const seed = new Uint8Array(32).fill(txVectors.context.keys.payer.seed)
const publicKey = ed25519.getPublicKey(seed)
const PAYER = encodeBase58(publicKey)
const OTHER = '3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG'

/** The payer's signer, counting the transactions it signs. */
function countingSigner(): SolanaSigner & { asked: number } {
    const inner = solanaSigner({ seed, publicKey, address: PAYER })
    const s = {
        ...inner,
        asked: 0,
        signTransactionMessage: (address: string, message: Uint8Array) => {
            s.asked++
            return inner.signTransactionMessage(address, message)
        },
    }
    return s
}

/** An SPL token account of mint held by owner. */
function tokenAccount(mint: string, owner: string, state: number): Account {
    const data = new Uint8Array(165)
    data.set(publicKeyBytes(mint))
    data.set(publicKeyBytes(owner), 32)
    data[32 + 32 + 8 + 4 + 32] = state
    return { lamports: 1n, owner: TOKEN_PROGRAM_ID, data, executable: false }
}

/**
 * A cluster holding the Config, the ticket and the payer's token account. An
 * ack it is sent lands as land says (absent: confirmed; null: never), and
 * moves nothing.
 */
function cluster() {
    const state = {
        accounts: new Map<string, Account | null>([
            [d.config(), { lamports: 1n, owner: PROGRAM_ID, data: CONFIG, executable: false }],
            [TICKET_ADDR, { lamports: 1n, owner: PROGRAM_ID, data: TICKET_DATA, executable: false }],
            [d.tokenAccount(PAYER), tokenAccount(MINT, PAYER, TOKEN_INITIALIZED)],
        ]),
        reads: [] as string[],
        sent: [] as Transaction[],
        preflight: [] as (string | undefined)[],
        land: { slot: 5n, confirmations: 1n, err: null, confirmationStatus: 'confirmed' } as SignatureStatus | null,
        height: 0n,
    }
    const unused = () => {
        throw new Error('unused')
    }
    const rpc: SolanaRpc = {
        getMinimumBalanceForRentExemption: unused,
        getAccountInfo: async (k, o) => {
            expect(o?.commitment).toBe('confirmed')
            o?.signal?.throwIfAborted()
            state.reads.push(k)
            const a = state.accounts.get(k)
            if (a === undefined) throw new Error(`read of ${k}`)
            return a === null ? null : { ...a }
        },
        getBalance: unused,
        getLatestBlockhash: async (o) => {
            expect(o?.commitment).toBe('confirmed')
            return { blockhash: txVectors.context.recent_blockhash, lastValidBlockHeight: 150n }
        },
        sendTransaction: async (raw, o) => {
            const tx = parseTransaction(raw)
            verifySignatures(tx)
            state.sent.push(tx)
            state.preflight.push(o?.preflightCommitment)
            return encodeBase58(tx.signatures[0]!)
        },
        getSignatureStatuses: async () => [state.land],
        getBlockHeight: async () => (state.height += 100n),
        getProgramAccounts: unused,
        getGenesisHash: unused,
    }
    return { rpc, state }
}

async function fixture() {
    const c = cluster()
    const signer = countingSigner()
    const wallet = await SolanaWallet.create({ rpc: c.rpc, deployment: d, signer, confirm: { pollMs: 1, heightCheckMs: 1 } })
    const ticket = async () => {
        const t = await wallet.readTicket(OPERATOR_ID, NODE_ID, TICKET_ID)
        if (t === null) throw new Error('no ticket')
        return t
    }
    return { ...c, signer, wallet, ticket, ack: async (t: Awaited<ReturnType<typeof ticket>> | null) => wallet.sendAck(t, OPERATOR_ID, NODE_ID, TICKET_ID, ARGS) }
}

describe('SolanaWallet ack', () => {
    // The wallet's ack is the program's own, byte for byte: the payer signs
    // and pays alone, the ending comes from the ticket account, and a payer
    // whose token account can take the refund passes no treasury account.
    it("sends the program's ack", async () => {
        const f = await fixture()
        const res = await f.ack(await f.ticket())
        expect(f.state.sent).toHaveLength(1)
        expect(base64.encode(encodeTransaction(f.state.sent[0]!))).toBe(ACK.wire_base64)
        expect(res).toEqual({ signature: ACK.signatures[0], feeLamports: SOLANA_SIGNATURE_FEE })
        expect(f.state.preflight).toEqual(['confirmed'])
    })

    // A refund the payer's token account can't take is forfeited to the
    // treasury's, which the ack then passes writable: the program's
    // can_receive, case by case.
    const unable: [string, () => Account | null][] = [
        ['no account', () => null],
        ['frozen', () => tokenAccount(MINT, PAYER, TOKEN_FROZEN)],
        ['uninitialized', () => tokenAccount(MINT, PAYER, TOKEN_UNINITIALIZED)],
        ['another mint', () => tokenAccount(OTHER, PAYER, TOKEN_INITIALIZED)],
        ['another owner', () => tokenAccount(MINT, OTHER, TOKEN_INITIALIZED)],
        ["not the token program's", () => ({ ...tokenAccount(MINT, PAYER, TOKEN_INITIALIZED), owner: '11111111111111111111111111111111' })],
        ['short', () => ({ ...tokenAccount(MINT, PAYER, TOKEN_INITIALIZED), data: new Uint8Array(164) })],
    ]
    it.each(unable)('forfeits a refund the payer cannot take: %s', async (_name, acct) => {
        const f = await fixture()
        f.state.accounts.set(d.tokenAccount(PAYER), acct())
        const t = await f.ticket()
        await f.ack(t)
        const e: Ending = {
            submitter: PAYER,
            operatorId: OPERATOR_ID,
            nodeId: NODE_ID,
            ticketId: TICKET_ID,
            rentPayer: t.rentPayer,
            payer: PAYER,
            treasury: decodeConfig(CONFIG).treasury,
            fallback: 'writable',
        }
        const want = compileMessage(PAYER, txVectors.context.recent_blockhash, [d.ack(e, solanaClaimFields(ARGS))], 'legacy')
        expect(encodeMessage(f.state.sent[0]!.message)).toEqual(encodeMessage(want))
    })

    // readTicket decodes the program's ticket account, and reads none where
    // there is no account or one the program doesn't own.
    it('reads the ticket account', async () => {
        const f = await fixture()
        const t = await f.ticket()
        expect(t).toMatchObject({ status: 1, payer: PAYER })
        expect(f.state.reads.at(-1)).toBe(TICKET_ADDR)
        f.state.accounts.set(TICKET_ADDR, null)
        await expect(f.wallet.readTicket(OPERATOR_ID, NODE_ID, TICKET_ID)).resolves.toBeNull()
        f.state.accounts.set(TICKET_ADDR, { lamports: 1n, owner: '11111111111111111111111111111111', data: TICKET_DATA, executable: false })
        await expect(f.wallet.readTicket(OPERATOR_ID, NODE_ID, TICKET_ID)).resolves.toBeNull()
        f.state.accounts.set(TICKET_ADDR, { lamports: 1n, owner: PROGRAM_ID, data: TICKET_DATA.slice(0, 20), executable: false })
        await expect(f.wallet.readTicket(OPERATOR_ID, NODE_ID, TICKET_ID)).rejects.toThrow(/read ticket/)
    })

    // An ack for a ticket that isn't the payer's, or for none, asks the
    // signer nothing and sends nothing: the program refuses it.
    it("refuses a ticket that isn't the payer's", async () => {
        const f = await fixture()
        const t = await f.ticket()
        await expect(f.ack({ ...t, payer: OTHER })).rejects.toThrow(/not this wallet's/)
        await expect(f.ack(null)).rejects.toThrow(/no ticket/)
        expect(f.state.sent).toHaveLength(0)
        expect(f.signer.asked).toBe(0)
    })

    // An ack that landed and failed paid its fee, which the error carries
    // with the program's error and its code; one that never confirmed paid
    // nothing it knows of, and hands back its signature to look for and the
    // expiry that says it never can land.
    it('reports where it landed', async () => {
        const f = await fixture()
        const txErr = { InstructionError: [0, { Custom: 6012 }] }
        f.state.land = { slot: 5n, confirmations: 1n, err: txErr, confirmationStatus: 'confirmed' }
        const failed = await f.ack(await f.ticket()).catch((e: unknown) => e)
        expect(failed).toBeInstanceOf(SolanaAckSendError)
        expect(failed).toMatchObject({ signature: ACK.signatures[0], feeLamports: SOLANA_SIGNATURE_FEE, txErr })
        expect((failed as Error).message).toMatch(/failed.*6012/)

        const g = await fixture()
        g.state.land = null
        const expired = await g.ack(await g.ticket()).catch((e: unknown) => e)
        expect(expired).toBeInstanceOf(SolanaAckSendError)
        expect(expired).toMatchObject({ signature: ACK.signatures[0], feeLamports: 0n, txErr: null })
        expect((expired as Error).cause).toBeInstanceOf(TransactionExpiredError)
    })

    // A forfeit needs the Config's treasury; without a Config to read it
    // from the ack signs and sends nothing.
    const configs: [string, Account | null][] = [
        ['no account', null],
        ['another owner', { lamports: 1n, owner: '11111111111111111111111111111111', data: CONFIG, executable: false }],
        ['truncated', { lamports: 1n, owner: PROGRAM_ID, data: CONFIG.slice(0, 20), executable: false }],
    ]
    it.each(configs)('needs the Config to forfeit: %s', async (_name, config) => {
        const f = await fixture()
        f.state.accounts.set(d.tokenAccount(PAYER), null)
        const t = await f.ticket()
        f.state.accounts.set(d.config(), config)
        await expect(f.ack(t)).rejects.toThrow(/solana wallet: ack/)
        expect(f.state.sent).toHaveLength(0)
        expect(f.signer.asked).toBe(0)
    })
})

const RECEIPT = ACK.receipt_value as UsageReceipt

// The fixture ticket's handle, which hands its ack to deliver; absent hands it
// to no node.
function handleOf(f: Awaited<ReturnType<typeof fixture>>, deliver?: OpenHandle['deliverAck']): OpenHandle {
    const h = f.wallet.handleFor({
        appCallTxId: '',
        groupId: '',
        ticketId: base64.encode(TICKET_ID),
        operator: { id: Number(OPERATOR_ID), nodeId: Number(NODE_ID) } as Operator,
        maxPrice: 0,
        openFeesMicroalgos: 0,
        signedGroup: new Uint8Array(),
    })
    if (deliver) h.deliverAck = deliver
    return h
}

// The ticket account's offsets of the fields a claim is judged on, after the
// 8-byte discriminator, as Go's test has them.
const TICKET_STATUS_OFFSET = 9
const TICKET_PENDING_AMOUNT_OFFSET = 33
const TICKET_CLAIM_HASH_OFFSET = 185

// Rewrites the fixture's ticket account: status, and a claim of pending whose
// hash is the receipt's fields with the amount set to pending, as a node
// claiming pending would write it.
function setTicket(f: Awaited<ReturnType<typeof fixture>>, status: number, pending: bigint, edit?: (c: ClaimFields) => void) {
    const data = TICKET_DATA.slice()
    const fields = { ...solanaClaimFields(ARGS), amount: pending }
    fields.receiptDigest = fields.receiptDigest.slice()
    edit?.(fields)
    const h = claimHash(fields)
    data[TICKET_STATUS_OFFSET] = status
    new DataView(data.buffer).setBigUint64(TICKET_PENDING_AMOUNT_OFFSET, pending, true)
    data.set(h, TICKET_CLAIM_HASH_OFFSET)
    expect(decodeTicket(data)).toMatchObject({ status, pendingAmount: pending, claimHash: h })
    f.state.accounts.set(TICKET_ADDR, { lamports: 1n, owner: PROGRAM_ID, data, executable: false })
}

const ticketReads = (f: Awaited<ReturnType<typeof fixture>>) => f.state.reads.filter((k) => k === TICKET_ADDR).length

describe('Solana handle ackSettle', () => {
    // With the node's open_seq the payer hands the node its ack: its
    // signature over the receipt's ack digest at that open_seq, as
    // payment_settle. It reads nothing, sends nothing and pays nothing; the
    // node submits its settle.
    it('hands the node its ack', async () => {
        const f = await fixture()
        const got: SettleAck[] = []
        const h = handleOf(f, async (ack) => {
            got.push(ack)
        })
        // Ids that differ, so the digest binds each in its place; nothing
        // here reads the ticket account at them.
        h.operator = { id: 3, nodeId: 5 } as Operator
        const res = await h.ackSettle(RECEIPT, '7')
        expect(res).toEqual({ txid: '', feeMicroalgos: 0, groupRejected: false })
        expect(got).toHaveLength(1)
        expect(got[0]!.ticket_id).toBe(base64.encode(TICKET_ID))
        const genesis = decodeConfig(CONFIG).genesisHash
        const digest = receiptAckDigest(d, genesis, 3n, 5n, TICKET_ID, 7n, RECEIPT)
        expect(verifyStrict(PAYER, digest, decodeAckSignature(got[0]!.settle_group))).toBe(true)
        expect(ticketReads(f)).toBe(0)
        expect(f.state.sent).toHaveLength(0)
        expect(f.signer.asked).toBe(0)
    })

    // Without the node's open_seq, or with no relay to carry the ack, the
    // payer sends its own ack over the ticket it read, and pays for it: here
    // the node's claim matches the receipt, so the ack settles the ticket.
    const alone: [string, string, OpenHandle['deliverAck']][] = [
        ['no slot', '', () => Promise.reject(new Error('delivered'))],
        ['no relay', '7', () => Promise.reject(new NoSettleAckRouteError())],
        ['no ack route at all', '7', undefined],
    ]
    it.each(alone)('acks alone without the node: %s', async (_name, slot, deliver) => {
        const f = await fixture()
        const res = await handleOf(f, deliver).ackSettle(RECEIPT, slot)
        expect(res).toEqual({
            txid: ACK.signatures[0],
            feeMicroalgos: Number(SOLANA_SIGNATURE_FEE),
            groupRejected: false,
            claim: 'agrees',
            payerSettle: true,
            frozen: false,
        })
        expect(f.state.sent).toHaveLength(1)
        expect(base64.encode(encodeTransaction(f.state.sent[0]!))).toBe(ACK.wire_base64)
        // The ack names the account the claim was judged on.
        expect(ticketReads(f)).toBe(1)
    })

    // With no route nothing reached the node, so the payer's own ack runs on
    // the caller's budget, not a fresh one: a caller whose deadline has
    // passed gets nothing sent.
    it("acks alone on the caller's budget", async () => {
        const f = await fixture()
        const signal = AbortSignal.timeout(0)
        await new Promise((r) => setTimeout(r, 5))
        const res = await handleOf(f, () => Promise.reject(new NoSettleAckRouteError())).ackSettle(RECEIPT, '7', signal)
        expect(res.err).toBeDefined()
        expect(f.state.sent).toHaveLength(0)
    })

    // What the payer's own ack does turns on the claim it read, as on
    // Algorand: an over-claim is acked to freeze it, a claim that contradicts
    // the receipt without taking more is left to lapse, and an open ticket
    // gets the payer's first half.
    const amount = ARGS.amountCharged
    const otherDigest = (c: ClaimFields) => {
        c.receiptDigest[0]! ^= 0xff
    }
    const byClaim: [string, number, bigint, ((c: ClaimFields) => void) | undefined, ClaimVerdict, boolean, boolean][] = [
        ['an over-claim is frozen', TICKET_PENDING_BY_OPERATOR, amount + 1n, undefined, 'overclaims', true, true],
        ['a contradicting claim taking no more is not acked', TICKET_PENDING_BY_OPERATOR, amount - 1n, otherDigest, 'contradicts', false, false],
        ["an open ticket gets the payer's half", TICKET_OPEN, 0n, undefined, 'open', true, false],
    ]
    it.each(byClaim)('acks alone by the claim: %s', async (_name, status, pending, edit, claim, sent, frozen) => {
        const f = await fixture()
        setTicket(f, status, pending, edit)
        const res = await handleOf(f).ackSettle(RECEIPT, null)
        expect(res.err).toBeUndefined()
        expect(res.claim).toBe(claim)
        expect(res.payerSettle ?? false).toBe(sent)
        expect(res.frozen ?? false).toBe(frozen)
        expect(f.state.sent).toHaveLength(sent ? 1 : 0)
        if (sent) expect(res).toMatchObject({ txid: encodeBase58(f.state.sent[0]!.signatures[0]!), feeMicroalgos: Number(SOLANA_SIGNATURE_FEE) })
        expect(ticketReads(f)).toBe(1)
    })

    // After a delivery the node refused, or one that may have reached it, the
    // payer reads the ticket on a budget of its own and sends its ack only
    // where Algorand sends its settle: over an over-claim, to freeze it, and
    // over an open ticket, as its first half. A claim matching the receipt is
    // the node's to settle, and the delivery's error is returned.
    const failed: [string, number, bigint, ClaimVerdict, boolean, boolean][] = [
        ['over-claim', TICKET_PENDING_BY_OPERATOR, amount + 1n, 'overclaims', true, true],
        ['open ticket', TICKET_OPEN, 0n, 'open', true, false],
        ['matching claim', TICKET_PENDING_BY_OPERATOR, amount, 'agrees', false, false],
    ]
    it.each(failed)('follows a failed delivery: %s', async (_name, status, pending, claim, sent, frozen) => {
        const f = await fixture()
        setTicket(f, status, pending)
        const refused = new Error('node answered 409')
        // The delivery spends the whole of its signal, as a node holding the
        // request open until the timeout would.
        const signal = AbortSignal.timeout(20)
        const res = await handleOf(f, (_ack, s) => new Promise((_resolve, reject) => s?.addEventListener('abort', () => reject(refused)))).ackSettle(
            RECEIPT,
            '7',
            signal,
        )
        expect(res.claim).toBe(claim)
        expect(res.payerSettle ?? false).toBe(sent)
        expect(res.frozen ?? false).toBe(frozen)
        expect(f.state.sent).toHaveLength(sent ? 1 : 0)
        expect(res.err).toBe(sent ? undefined : refused)
    })

    // The payer's own ack that landed and failed reports its signature and
    // the fee it paid beside the error.
    it('reports what a failed ack paid', async () => {
        const f = await fixture()
        f.state.land = { slot: 5n, confirmations: 1n, err: { InstructionError: [0, { Custom: 6012 }] }, confirmationStatus: 'confirmed' }
        const res = await handleOf(f).ackSettle(RECEIPT, null)
        expect(res.err).toBeInstanceOf(SolanaAckSendError)
        expect(res).toMatchObject({ txid: ACK.signatures[0], feeMicroalgos: Number(SOLANA_SIGNATURE_FEE), payerSettle: true })
    })

    // With no ticket account to name there is no ack to send, and nothing is.
    it('sends no ack for a missing ticket', async () => {
        const f = await fixture()
        f.state.accounts.set(TICKET_ADDR, null)
        const res = await handleOf(f).ackSettle(RECEIPT, null)
        expect(res.err).toBeDefined()
        expect(res.claim).toBe('none')
        expect(f.state.sent).toHaveLength(0)
        expect(f.signer.asked).toBe(0)
    })
})
