/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// SolanaWallet's readTicket and sendAck, and its handle's settle paths, over
// the program's own ack and protest transactions from the shared transaction
// vectors: the twin of go/zs solana_ack_test.go and solana_endings_test.go.

import { readFileSync } from 'node:fs'

import * as ed25519 from '@noble/ed25519'
import { base64 } from '@scure/base'
import {
    type Instruction,
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
    TICKET_FROZEN,
    TICKET_OPEN,
    TICKET_PENDING_BY_OPERATOR,
    TICKET_PENDING_BY_PAYER,
    TOKEN_FROZEN,
    TOKEN_INITIALIZED,
    TOKEN_UNINITIALIZED,
    decodeAckSignature,
    decodeConfig,
    decodeTicket,
    receiptAckDigest,
    ticketDeadline,
} from '@txnlab/zs-proto/solana/zsescrow'
import type { UsageReceipt } from '@txnlab/zs-proto/ticket'
import type { SettleAck } from '@txnlab/zs-proto/wire'
import { describe, expect, it, vi } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { partsOf } from '../src/client-parts.js'
import { Client, type RegistryProvider, isMemoryJournal, memoryJournal, resolveNetwork } from '../src/index.js'
import { Reconciler } from '../src/reconciler.js'
import type { SettleArgs, TicketRecord } from '../src/reconcile.js'
import { solanaSweep } from '../src/solana/reconcile.js'
import { NoSettleAckRouteError, ProtestAfterDeadlineError, settleArgsOf } from '../src/ack.js'
import type { Operator } from '../src/operator.js'
import { type OpenHandle, ProtestReason, type ProtestReasonCode } from '../src/parts.js'
import type { SolanaSigner } from '../src/ports.js'
import type { ClaimVerdict } from '../src/reconcile.js'
import { Watchdog } from '../src/refund-watchdog.js'
import type { NodeRef } from '../src/types.js'
import { solanaClaimFields } from '../src/solana/claim.js'
import { TransactionExpiredError } from '../src/solana/confirm.js'
import { SOLANA_SIGNATURE_FEE } from '../src/solana/rent.js'
import { type Account, CODE_PREFLIGHT_FAILURE, type SignatureStatus, type SolanaRpc, SolanaRpcError } from '../src/solana/rpc.js'
import { SOLANA_ENDING_TIMEOUT_MS, SolanaAckSendError, SolanaWallet } from '../src/solana/wallet.js'

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
        // Fails the next transaction at sendTransaction, as a failed preflight
        // does, sending nothing.
        sendErr: undefined as unknown,
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
            if (state.sendErr !== undefined) {
                const err = state.sendErr
                state.sendErr = undefined
                throw err
            }
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
const TICKET_PENDING_OFFSET = 33

// Rewrites the fixture's ticket account: status, and a claim of the receipt's
// fields with the amount set to pending, as a node claiming pending would
// write it.
function setTicket(f: Awaited<ReturnType<typeof fixture>>, status: number, pending: bigint, edit?: (c: ClaimFields) => void) {
    const data = TICKET_DATA.slice()
    const fields = { ...solanaClaimFields(ARGS), amount: pending }
    fields.receiptDigest = fields.receiptDigest.slice()
    edit?.(fields)
    data[TICKET_STATUS_OFFSET] = status
    const at = TICKET_PENDING_OFFSET
    const v = new DataView(data.buffer)
    v.setBigUint64(at, fields.amount, true)
    data.set(fields.receiptDigest, at + 8)
    ;[fields.ttftMs, fields.decodeMs, fields.inputUnits, fields.outputUnits].forEach((x, i) => v.setBigUint64(at + 40 + 8 * i, x, true))
    data[at + 72] = fields.outputUsageType
    data[at + 73] = fields.auxUsageType
    v.setBigUint64(at + 74, fields.auxCount, true)
    expect(decodeTicket(data)).toMatchObject({ status, pending: fields })
    f.state.accounts.set(TICKET_ADDR, { lamports: 1n, owner: PROGRAM_ID, data, executable: false })
}

const ticketReads = (f: Awaited<ReturnType<typeof fixture>>) => f.state.reads.filter((k) => k === TICKET_ADDR).length

// A copy of the ticket account data with payer in its payer's place.
function withPayer(ticket: Uint8Array, payer: string): Uint8Array {
    const data = ticket.slice()
    const was = publicKeyBytes(decodeTicket(ticket).payer)
    const i = data.findIndex((_, j) => was.every((b, k) => data[j + k] === b))
    data.set(publicKeyBytes(payer), i)
    expect(decodeTicket(data).payer).toBe(payer)
    return data
}

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

// One of the program's own protest transactions, with the ack fixture's wallet
// and cluster. The ticket account is the fixture's pending ticket, moved to the
// protested ticket's address: the protest reads only its payer and the node key
// it took at open.
async function protestFixture(name: string) {
    const x = txVectors.transactions.find((t: Json) => t.name === name)
    if (x === undefined) throw new Error(`no ${name} transaction in solana_tx_vectors.json`)
    if (x.program !== 'ok') throw new Error(`the program refused ${name}: ${x.program}`)
    const receipt = { ...(x.receipt_value as UsageReceipt) }
    const f = await fixture()
    const at = d.ticket(d.node(OPERATOR_ID, NODE_ID), base64.decode(receipt.ticket_id))
    f.state.accounts.set(at, f.state.accounts.get(TICKET_ADDR)!)
    const h = f.wallet.handleFor({
        appCallTxId: '',
        groupId: '',
        ticketId: receipt.ticket_id,
        operator: { id: Number(OPERATOR_ID), nodeId: Number(NODE_ID) } as Operator,
        maxPrice: 0,
        openFeesMicroalgos: 0,
        signedGroup: new Uint8Array(),
    })
    const protest = (reason: ProtestReasonCode = ProtestReason.bodyHash) => h.protest(receipt, new TextEncoder().encode('no excerpt on Solana'), reason)
    return { ...f, x, receipt, at, protest }
}

describe('Solana handle protest', () => {
    // The handle's protest is the program's own, byte for byte, of an open
    // ticket and of a pending one: the compute limit, the node's signature over
    // the receipt's digest by the key the ticket took at open, and the protest.
    // It pays for two signatures, its own and the precompile's.
    it.each(['protest', 'protest_pending'])("sends the program's %s", async (name) => {
        const f = await protestFixture(name)
        const res = await f.protest()
        expect(f.state.sent).toHaveLength(1)
        expect(base64.encode(encodeTransaction(f.state.sent[0]!))).toBe(f.x.wire_base64)
        expect(res).toEqual({ txId: f.x.signatures[0], feeMicroalgos: Number(2n * SOLANA_SIGNATURE_FEE) })
    })

    // A protest the program refuses past the settle window throws
    // ProtestAfterDeadlineError, whether its preflight refused it or it landed
    // and failed, so the receipt check skips the freeze no settle could make
    // either. Any other refusal doesn't.
    const custom = (code: number) => ({ InstructionError: [2, { Custom: code }] })
    const preflight = (err: unknown) => new SolanaRpcError('sendTransaction', CODE_PREFLIGHT_FAILURE, 'm', { err, logs: [] })
    const landed = (err: unknown): SignatureStatus => ({ slot: 5n, confirmations: 1n, err, confirmationStatus: 'confirmed' })
    const refusals: [string, (f: Awaited<ReturnType<typeof protestFixture>>) => void, boolean, bigint | null][] = [
        ['preflight past the deadline', (f) => (f.state.sendErr = preflight(custom(6011))), true, null],
        ['landed past the deadline', (f) => (f.state.land = landed(custom(6011))), true, 2n * SOLANA_SIGNATURE_FEE],
        ['preflight on another code', (f) => (f.state.sendErr = preflight(custom(6052))), false, null],
        ['landed on another code', (f) => (f.state.land = landed(custom(6052))), false, 2n * SOLANA_SIGNATURE_FEE],
        ['another preflight failure', (f) => (f.state.sendErr = preflight('InsufficientFundsForFee')), false, null],
    ]
    it.each(refusals)('reads the refusal: %s', async (_name, set, deadline, fee) => {
        const f = await protestFixture('protest_pending')
        set(f)
        const err = await f.protest().catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect(err instanceof ProtestAfterDeadlineError).toBe(deadline)
        const sent = err instanceof ProtestAfterDeadlineError ? err.cause : err
        if (fee === null) expect(sent).not.toBeInstanceOf(SolanaAckSendError)
        else expect(sent).toMatchObject({ feeLamports: fee })
    })

    // A protest that can't land asks the signer nothing: no ticket, a ticket
    // that isn't the payer's, a receipt with no signature, a reason the
    // program can't carry.
    const before: [string, (f: Awaited<ReturnType<typeof protestFixture>>) => void, ProtestReasonCode, RegExp][] = [
        ['no ticket', (f) => f.state.accounts.set(f.at, null), ProtestReason.bodyHash, /no ticket account/],
        [
            "another payer's ticket",
            (f) => f.state.accounts.set(f.at, { lamports: 1n, owner: PROGRAM_ID, data: withPayer(TICKET_DATA, OTHER), executable: false }),
            ProtestReason.bodyHash,
            /not this wallet's/,
        ],
        ['no receipt signature', (f) => (f.receipt.sig = ''), ProtestReason.bodyHash, /receipt sig/],
        ['a reason past a byte', () => {}, 256 as ProtestReasonCode, /past the program's 255/],
    ]
    it.each(before)('refuses before signing: %s', async (_name, set, reason, want) => {
        const f = await protestFixture('protest_pending')
        set(f)
        await expect(f.protest(reason)).rejects.toThrow(want)
        expect(f.state.sent).toHaveLength(0)
        expect(f.signer.asked).toBe(0)
    })

    // 255 is the last reason the program's u8 carries, so it goes out.
    it('sends reason 255', async () => {
        const f = await protestFixture('protest_pending')
        await f.protest(0xff as ProtestReasonCode)
        expect(f.state.sent).toHaveLength(1)
    })
})

describe('Solana handle endings', () => {
    // refund_inactive and settle_lapsed go out as the payer's own transaction
    // over the ticket account: its rent payer, the payer's token account, and
    // the treasury's, writable, when the payer's can't take the refund.
    const endings: [string, (h: OpenHandle) => Promise<string>, (e: Ending) => Instruction][] = [
        ['refund_inactive', (h) => h.refundInactive(), (e) => d.refundInactive(e)],
        ['settle_lapsed', (h) => h.settleLapsed(), (e) => d.settleLapsed(e)],
    ]
    describe.each(endings)('%s', (_name, call, ix) => {
        it.each([false, true])('ends the ticket (forfeit %s)', async (forfeit) => {
            const f = await fixture()
            if (forfeit) f.state.accounts.set(d.tokenAccount(PAYER), null)
            const t = await f.ticket()
            const sig = await call(handleOf(f))
            expect(f.state.sent).toHaveLength(1)
            const e: Ending = { submitter: PAYER, operatorId: OPERATOR_ID, nodeId: NODE_ID, ticketId: TICKET_ID, rentPayer: t.rentPayer, payer: PAYER }
            if (forfeit) Object.assign(e, { treasury: decodeConfig(CONFIG).treasury, fallback: 'writable' })
            const want = compileMessage(PAYER, txVectors.context.recent_blockhash, [ix(e)], 'legacy')
            expect(encodeMessage(f.state.sent[0]!.message)).toEqual(encodeMessage(want))
            expect(sig).toBe(encodeBase58(f.state.sent[0]!.signatures[0]!))
        })

        // An ending of a ticket that isn't there, or isn't the payer's, asks
        // the signer nothing and sends nothing; one that landed and failed
        // hands back its signature.
        it('refuses or reports', async () => {
            const f = await fixture()
            f.state.accounts.set(TICKET_ADDR, null)
            await expect(call(handleOf(f))).rejects.toThrow(/no ticket account/)
            f.state.accounts.set(TICKET_ADDR, { lamports: 1n, owner: PROGRAM_ID, data: withPayer(TICKET_DATA, OTHER), executable: false })
            await expect(call(handleOf(f))).rejects.toThrow(/not this wallet's/)
            expect(f.state.sent).toHaveLength(0)
            expect(f.signer.asked).toBe(0)

            const g = await fixture()
            g.state.land = { slot: 5n, confirmations: 1n, err: { InstructionError: [0, { Custom: 6010 }] }, confirmationStatus: 'confirmed' }
            const err = await call(handleOf(g)).catch((x: unknown) => x)
            expect(err).toBeInstanceOf(SolanaAckSendError)
            expect((err as SolanaAckSendError).signature).toBe(encodeBase58(g.state.sent[0]!.signatures[0]!))
        })
    })
})

describe('Solana handle freezeOverclaim', () => {
    // It sends the payer's ack at the receipt over a node claim above it,
    // which freezes the ticket, and sends nothing over any other.
    it('freezes an over-claim', async () => {
        const f = await fixture()
        setTicket(f, TICKET_PENDING_BY_OPERATOR, ARGS.amountCharged + 1n)
        const res = await handleOf(f).freezeOverclaim!(RECEIPT)
        expect(res.err).toBeUndefined()
        expect(res.claim).toBe('overclaims')
        expect(f.state.sent).toHaveLength(1)
        expect(res.call).toEqual({ txid: encodeBase58(f.state.sent[0]!.signatures[0]!), payerFeeMicroalgos: SOLANA_SIGNATURE_FEE })
        const t = await f.ticket()
        const e: Ending = { submitter: PAYER, operatorId: OPERATOR_ID, nodeId: NODE_ID, ticketId: TICKET_ID, rentPayer: t.rentPayer, payer: PAYER }
        const want = compileMessage(PAYER, txVectors.context.recent_blockhash, [d.ack(e, solanaClaimFields(ARGS))], 'legacy')
        expect(encodeMessage(f.state.sent[0]!.message)).toEqual(encodeMessage(want))
    })

    const others: [string, number, bigint, ClaimVerdict][] = [
        ['a matching claim', TICKET_PENDING_BY_OPERATOR, ARGS.amountCharged, 'agrees'],
        ['a claim below', TICKET_PENDING_BY_OPERATOR, ARGS.amountCharged - 1n, 'contradicts'],
        ['an open ticket', TICKET_OPEN, 0n, 'open'],
    ]
    it.each(others)('sends nothing over %s', async (_name, status, pending, claim) => {
        const f = await fixture()
        setTicket(f, status, pending)
        const res = await handleOf(f).freezeOverclaim!(RECEIPT)
        expect(res).toEqual({ claim })
        expect(f.state.sent).toHaveLength(0)
    })

    it('reads no ticket, or an unreadable one, without sending', async () => {
        const f = await fixture()
        f.state.accounts.set(TICKET_ADDR, null)
        expect(await handleOf(f).freezeOverclaim!(RECEIPT)).toEqual({ claim: 'none' })
        f.state.accounts.set(TICKET_ADDR, { lamports: 1n, owner: PROGRAM_ID, data: TICKET_DATA.slice(0, 20), executable: false })
        const res = await handleOf(f).freezeOverclaim!(RECEIPT)
        expect(res.claim).toBe('unreadable')
        expect(res.err).toBeDefined()
        expect(f.state.sent).toHaveLength(0)
    })
})

// The ticket account's expires_at, after the discriminator, the header,
// open_seq, max_price, the pending claim and opened_at, as Go's test has it.
const TICKET_EXPIRES_AT_OFFSET = 123

// Moves the fixture's ticket account's deadline, its expires_at plus the
// grace it took at open, to deadline (unix seconds).
function setTicketDeadline(f: Awaited<ReturnType<typeof fixture>>, deadline: bigint) {
    const a = f.state.accounts.get(TICKET_ADDR)!
    const data = a.data.slice()
    new DataView(data.buffer).setBigInt64(TICKET_EXPIRES_AT_OFFSET, deadline - BigInt(decodeTicket(data).grace), true)
    expect(ticketDeadline(decodeTicket(data))).toBe(deadline)
    f.state.accounts.set(TICKET_ADDR, { ...a, data })
}

const nowSeconds = () => BigInt(Math.floor(Date.now() / 1000))

// A watchdog on short timings, with what it reported.
function solanaWatchdog() {
    const refunded: string[] = []
    const barred: NodeRef[] = []
    const rw = new Watchdog({ remedy: 'recover it by hand', refunded: (id) => refunded.push(id), overclaimed: (_id, n) => barred.push(n) })
    rw.marginMs = 2
    rw.retryDelayMs = 5
    // Long enough that the receipt is pinned before the lapse reads it.
    rw.lapseFallbackMs = 100
    return { rw, refunded, barred }
}

async function untilDone(rw: Watchdog, ticketId: string, ms = 2000) {
    const end = Date.now() + ms
    while (rw.watching(ticketId)) {
        if (Date.now() > end) throw new Error("timed out waiting for the ticket's driver to finish")
        await new Promise((r) => setTimeout(r, 2))
    }
}

describe('Solana refund watchdog', () => {
    // The watchdog drives a Solana handle as it drives an Algorand one,
    // reading the ticket account where Algorand reads the box: refund_inactive
    // on an open ticket past its deadline, nothing on a ticket gone or frozen,
    // settle_lapsed on a node's claim the node never lapsed, and nothing on a
    // claim above the receipt the node signed, whose node it bars.
    const cases: {
        name: string
        status?: number
        claim?: bigint
        receipt?: boolean
        send?: (e: Ending) => Instruction
        refunded?: boolean
        barred?: boolean
    }[] = [
        { name: 'open', status: TICKET_OPEN, send: (e) => d.refundInactive(e), refunded: true },
        { name: "the payer's own claim", status: TICKET_PENDING_BY_PAYER, claim: 100n, send: (e) => d.refundInactive(e), refunded: true },
        { name: 'gone' },
        { name: 'frozen', status: TICKET_FROZEN, claim: 100n },
        { name: "the node's claim", status: TICKET_PENDING_BY_OPERATOR, claim: 100n, send: (e) => d.settleLapsed(e) },
        { name: "the node's claim at the receipt", status: TICKET_PENDING_BY_OPERATOR, claim: 100n, receipt: true, send: (e) => d.settleLapsed(e) },
        { name: "the node's claim above the receipt", status: TICKET_PENDING_BY_OPERATOR, claim: 101n, receipt: true, barred: true },
    ]
    it.each(cases)('drives $name', async (c) => {
        const f = await fixture()
        let t = null
        if (c.status === undefined) {
            f.state.accounts.set(TICKET_ADDR, null)
        } else {
            setTicket(f, c.status, c.claim ?? 0n)
            setTicketDeadline(f, nowSeconds() - 60n)
            t = await f.ticket()
        }
        const { rw, refunded, barred } = solanaWatchdog()
        const h = handleOf(f)
        const before = ticketReads(f)
        rw.track(h, Number(nowSeconds()) - 60 - decodeConfig(CONFIG).defaultGrace)
        expect(rw.watching(h.ticketId)).toBe(true)
        if (c.receipt) rw.recordReceipt(h.ticketId, { op: Number(OPERATOR_ID), node: Number(NODE_ID) }, 100n)
        await untilDone(rw, h.ticketId)

        expect(ticketReads(f)).toBeGreaterThan(before)
        if (c.send === undefined) {
            expect(f.state.sent).toHaveLength(0)
        } else {
            expect(f.state.sent).toHaveLength(1)
            const e: Ending = { submitter: PAYER, operatorId: OPERATOR_ID, nodeId: NODE_ID, ticketId: TICKET_ID, rentPayer: t!.rentPayer, payer: PAYER }
            const want = compileMessage(PAYER, txVectors.context.recent_blockhash, [c.send(e)], 'legacy')
            expect(encodeMessage(f.state.sent[0]!.message)).toEqual(encodeMessage(want))
        }
        expect(refunded).toEqual(c.refunded ? [h.ticketId] : [])
        expect(barred).toEqual(c.barred ? [{ op: Number(OPERATOR_ID), node: Number(NODE_ID) }] : [])
    })

    // It first reads a Solana ticket at expires_at plus the Config's
    // default_grace, the grace a payer's open takes, and waits out the
    // ticket's own deadline when that is later.
    it("waits out the Config's grace", async () => {
        const f = await fixture()
        setTicket(f, TICKET_OPEN, 0n)
        setTicketDeadline(f, nowSeconds() - 60n)
        const { rw } = solanaWatchdog()
        const h = handleOf(f)
        const before = ticketReads(f)
        // Past expires_at by less than the grace.
        rw.track(h, Number(nowSeconds()) - decodeConfig(CONFIG).defaultGrace + 60)
        await new Promise((r) => setTimeout(r, 50))
        expect(ticketReads(f)).toBe(before)
        expect(rw.watching(h.ticketId)).toBe(true)
        rw.resolve(h.ticketId)
    })

    it("waits out the ticket's own deadline", async () => {
        const f = await fixture()
        setTicket(f, TICKET_OPEN, 0n)
        const ahead = nowSeconds() + 2n
        setTicketDeadline(f, ahead)
        const { rw, refunded } = solanaWatchdog()
        const h = handleOf(f)
        const before = ticketReads(f)
        rw.track(h, Number(nowSeconds()) - 60 - decodeConfig(CONFIG).defaultGrace)
        const end = Date.now() + 2000
        while (ticketReads(f) === before && Date.now() < end) await new Promise((r) => setTimeout(r, 2))
        expect(ticketReads(f)).toBeGreaterThan(before)
        expect(f.state.sent).toHaveLength(0)
        await untilDone(rw, h.ticketId, 5000)
        expect(f.state.sent).toHaveLength(1)
        expect(refunded).toEqual([h.ticketId])
        expect(Date.now()).toBeGreaterThanOrEqual(Number(ahead) * 1000)
    })

    // A Solana refund or lapse waits for its confirmation, which can outlast
    // the watchdog's callTimeoutMs. It is waited for rather than cut short
    // and sent again, so a refund that lands late is reported as one. The
    // budget is past a blockhash's life, a minute or so, with room for a slow
    // cluster.
    it.each([
        ['refund_inactive', TICKET_OPEN, 0n, true],
        ['settle_lapsed', TICKET_PENDING_BY_OPERATOR, 100n, false],
    ] as const)('waits for %s to confirm', async (_name, status, claim, refunds) => {
        expect(SOLANA_ENDING_TIMEOUT_MS).toBe(180_000)
        const f = await fixture()
        setTicket(f, status, claim)
        setTicketDeadline(f, nowSeconds() - 60n)
        const landAt = Date.now() + 150
        const land = f.state.land
        f.rpc.getSignatureStatuses = async () => [Date.now() < landAt ? null : land]
        // A height that never passes the blockhash.
        f.rpc.getBlockHeight = async () => 0n
        const { rw, refunded } = solanaWatchdog()
        rw.callTimeoutMs = 20
        const h = handleOf(f)
        rw.track(h, Number(nowSeconds()) - 60 - decodeConfig(CONFIG).defaultGrace)
        await untilDone(rw, h.ticketId)
        expect(f.state.sent).toHaveLength(1)
        expect(refunded).toEqual(refunds ? [h.ticketId] : [])
    })

    // A ticket read that fails is not a ticket gone: the watchdog goes on to
    // the refund, as on Algorand, and it lands once the read works again.
    it('takes a failed read for no ticket gone', async () => {
        const f = await fixture()
        setTicket(f, TICKET_OPEN, 0n)
        setTicketDeadline(f, nowSeconds() - 60n)
        const read = f.rpc.getAccountInfo
        let fail = 1
        f.rpc.getAccountInfo = async (k, o) => {
            if (k === TICKET_ADDR && fail-- > 0) throw new Error('rpc down')
            return read(k, o)
        }
        const { rw, refunded } = solanaWatchdog()
        const h = handleOf(f)
        rw.track(h, Number(nowSeconds()) - 60 - decodeConfig(CONFIG).defaultGrace)
        await untilDone(rw, h.ticketId)
        expect(f.state.sent).toHaveLength(1)
        expect(refunded).toEqual([h.ticketId])
    })

    // It reads the ticket at the handle's node, operator id then node id, as
    // the open put it there.
    it('reads the ticket at its node', async () => {
        const f = await fixture()
        setTicket(f, TICKET_OPEN, 0n)
        setTicketDeadline(f, nowSeconds() - 60n)
        const [opId, nodeId] = [7n, 9n]
        f.state.accounts.set(d.ticket(d.node(opId, nodeId), TICKET_ID), f.state.accounts.get(TICKET_ADDR)!)
        f.state.accounts.set(d.ticket(d.node(nodeId, opId), TICKET_ID), null)
        f.state.accounts.set(TICKET_ADDR, null)
        const { rw, refunded } = solanaWatchdog()
        const h = handleOf(f)
        h.operator = { id: Number(opId), nodeId: Number(nodeId) } as Operator
        rw.track(h, Number(nowSeconds()) - 60 - decodeConfig(CONFIG).defaultGrace)
        await untilDone(rw, h.ticketId)
        expect(f.state.sent).toHaveLength(1)
        expect(refunded).toEqual([h.ticketId])
    })
})

const sweepNetwork = { network: 'localnet', escrowAppId: 7n } as const
const sweepDeployment = resolveNetwork(sweepNetwork)

// The fixture ticket's journal row, its open long expired.
function rowOf(status: TicketRecord['status'], settle?: SettleArgs): TicketRecord {
    const hourAgo = Date.now() - 3_600_000
    return {
        ticketId: base64.encode(TICKET_ID),
        openTxId: '',
        escrowAppId: sweepDeployment.escrowAppId,
        deployment: sweepDeployment.key,
        target: { op: Number(OPERATOR_ID), node: Number(NODE_ID) },
        payer: PAYER,
        maxPrice: 1n,
        expiresAt: hourAgo,
        status,
        createdAt: hourAgo,
        updatedAt: hourAgo,
        ...(settle && { settle }),
    }
}

// A reconciler over the fixture's wallet and a journal holding rec, with
// what its spend guard heard.
async function solanaReconciler(f: Awaited<ReturnType<typeof fixture>>, rec: TicketRecord) {
    const journal = memoryJournal()
    await journal.put(rec)
    const spend: string[] = []
    const barred: NodeRef[] = []
    const r = new Reconciler({
        journal,
        chain: solanaSweep(f.wallet),
        payer: PAYER,
        deployment: sweepDeployment,
        watching: () => false,
        spend: {
            admit() {},
            reserve() {},
            settle: (id, charged) => void spend.push(`settle ${id} ${charged}`),
            release: (id) => void spend.push(`release ${id}`),
        },
        overclaimed: (rec) => void barred.push(rec.target),
    })
    const kept = async () => (await journal.list(PAYER, sweepDeployment)).length === 1
    return { r, spend, barred, kept }
}

describe('Solana reconciler', () => {
    // The reconciler finishes a journaled Solana ticket as it does an
    // Algorand one, reading the ticket account where Algorand reads the box:
    // it refunds an open ticket past its deadline, lapses a node's claim the
    // node left, re-fires the payer's ack against a claim at the receipt,
    // freezes one above it with the receipt's ack, and forgets a ticket
    // frozen or gone. It tells the spend guard how each refund and lapse
    // ended, and bars a node whose claim is above the receipt, inside the
    // window or past it.
    const over = (c: ClaimFields) => void (c.amount += 1n)
    const cases: {
        name: string
        status?: number
        edit?: (c: ClaimFields) => void
        deadlineIn?: bigint
        rec: TicketRecord['status']
        receipt?: boolean
        ending?: (e: Ending) => Instruction
        ack?: boolean
        kept?: boolean
        spend?: 'release' | 'settle'
        barred?: boolean
    }[] = [
        { name: 'open past its deadline', status: TICKET_OPEN, deadlineIn: -3600n, rec: 'open', ending: (e) => d.refundInactive(e), kept: true, spend: 'release' },
        { name: "a node's claim left to lapse", status: TICKET_PENDING_BY_OPERATOR, deadlineIn: -3600n, rec: 'open', ending: (e) => d.settleLapsed(e), kept: true, spend: 'settle' },
        {
            name: "a node's claim left to lapse, with a receipt",
            status: TICKET_PENDING_BY_OPERATOR,
            deadlineIn: -3600n,
            rec: 'settle_pending',
            receipt: true,
            ending: (e) => d.settleLapsed(e),
            kept: true,
            spend: 'release',
        },
        { name: "a node's claim at the receipt", status: TICKET_PENDING_BY_OPERATOR, deadlineIn: 3600n, rec: 'settle_pending', receipt: true, ack: true, kept: true },
        { name: 'an open ticket with a receipt', status: TICKET_OPEN, deadlineIn: 3600n, rec: 'settle_pending', receipt: true, ack: true, kept: true },
        {
            name: "a node's claim above the receipt",
            status: TICKET_PENDING_BY_OPERATOR,
            edit: over,
            deadlineIn: 3600n,
            rec: 'settle_pending',
            receipt: true,
            ack: true,
            kept: true,
            barred: true,
        },
        {
            name: "a node's claim above the receipt past the window",
            status: TICKET_PENDING_BY_OPERATOR,
            edit: over,
            deadlineIn: -3600n,
            rec: 'settle_pending',
            receipt: true,
            kept: true,
            barred: true,
        },
        { name: 'frozen', status: TICKET_FROZEN, deadlineIn: 3600n, rec: 'settle_pending', receipt: true },
        { name: 'gone', rec: 'settle_pending', receipt: true, spend: 'release' },
        { name: 'gone without a receipt', rec: 'open' },
    ]
    it.each(cases)('sweeps $name', async (c) => {
        const f = await fixture()
        let t = null
        if (c.status === undefined) {
            f.state.accounts.set(TICKET_ADDR, null)
        } else {
            setTicket(f, c.status, c.status === TICKET_OPEN ? 0n : ARGS.amountCharged, c.edit)
            setTicketDeadline(f, nowSeconds() + c.deadlineIn!)
            t = await f.ticket()
        }
        const rec = rowOf(c.rec, c.receipt ? ARGS : undefined)
        const { r, spend, barred, kept } = await solanaReconciler(f, rec)
        await r.sweep()

        if (c.ending !== undefined) {
            expect(f.state.sent).toHaveLength(1)
            const e: Ending = { submitter: PAYER, operatorId: OPERATOR_ID, nodeId: NODE_ID, ticketId: TICKET_ID, rentPayer: t!.rentPayer, payer: PAYER }
            const want = compileMessage(PAYER, txVectors.context.recent_blockhash, [c.ending(e)], 'legacy')
            expect(encodeMessage(f.state.sent[0]!.message)).toEqual(encodeMessage(want))
        } else if (c.ack) {
            expect(f.state.sent).toHaveLength(1)
            expect(base64.encode(encodeTransaction(f.state.sent[0]!))).toBe(ACK.wire_base64)
        } else {
            expect(f.state.sent).toHaveLength(0)
        }
        expect(await kept()).toBe(c.kept === true)
        const want = { release: [`release ${rec.ticketId}`], settle: [`settle ${rec.ticketId} ${ARGS.amountCharged}`] }
        expect(spend).toEqual(c.spend ? want[c.spend] : [])
        expect(barred).toEqual(c.barred ? [rec.target] : [])
    })

    // A Solana submit waits for its confirmation, which can outlast the
    // sweep's callTimeoutMs. It is waited for, so a refund that lands late
    // frees its reservation that sweep, rather than read as a ticket gone on
    // the next.
    it('waits for a submit to confirm', async () => {
        expect(solanaSweep(await (await fixture()).wallet).submitTimeoutMs).toBe(SOLANA_ENDING_TIMEOUT_MS)
        const f = await fixture()
        setTicket(f, TICKET_OPEN, 0n)
        setTicketDeadline(f, nowSeconds() - 3600n)
        const landAt = Date.now() + 150
        const land = f.state.land
        f.rpc.getSignatureStatuses = async () => [Date.now() < landAt ? null : land]
        f.rpc.getBlockHeight = async () => 0n
        const rec = rowOf('open')
        const { r, spend } = await solanaReconciler(f, rec)
        r.callTimeoutMs = 20
        await r.sweep()
        expect(f.state.sent).toHaveLength(1)
        expect(spend).toEqual([`release ${rec.ticketId}`])
    })

    // It reads the ticket at the row's node, operator id then node id, as
    // the open put it there.
    it.each([
        ['refunds', TICKET_OPEN, 0n, (e: Ending) => d.refundInactive(e)],
        ['lapses', TICKET_PENDING_BY_OPERATOR, ARGS.amountCharged, (e: Ending) => d.settleLapsed(e)],
    ] as const)('%s the ticket at its node', async (_name, status, claim, ix) => {
        const f = await fixture()
        setTicket(f, status, claim)
        setTicketDeadline(f, nowSeconds() - 3600n)
        const t = await f.ticket()
        const [opId, nodeId] = [7n, 9n]
        f.state.accounts.set(d.ticket(d.node(opId, nodeId), TICKET_ID), f.state.accounts.get(TICKET_ADDR)!)
        f.state.accounts.set(d.ticket(d.node(nodeId, opId), TICKET_ID), null)
        f.state.accounts.set(TICKET_ADDR, null)
        const rec = { ...rowOf('open'), target: { op: Number(opId), node: Number(nodeId) } }
        const { r } = await solanaReconciler(f, rec)
        await r.sweep()
        expect(f.state.sent).toHaveLength(1)
        const e: Ending = { submitter: PAYER, operatorId: opId, nodeId, ticketId: TICKET_ID, rentPayer: t.rentPayer, payer: PAYER }
        const want = compileMessage(PAYER, txVectors.context.recent_blockhash, [ix(e)], 'legacy')
        expect(encodeMessage(f.state.sent[0]!.message)).toEqual(encodeMessage(want))
    })

    // A ticket the sweep cannot read is no ticket gone: a failed read, or a
    // row whose ticket id does not decode, keeps the row past its expiry,
    // with nothing sent or released, for the next sweep to retry.
    it.each(['a failed read', 'an undecodable ticket id'])('keeps a row after %s', async (what) => {
        const f = await fixture()
        let rec = rowOf('settle_pending', ARGS)
        if (what === 'a failed read') {
            f.rpc.getAccountInfo = async () => {
                throw new Error('rpc down')
            }
        } else {
            rec = { ...rec, ticketId: 'not a ticket id' }
        }
        const { r, spend, kept } = await solanaReconciler(f, rec)
        await r.sweep()
        expect(await kept()).toBe(true)
        expect(f.state.sent).toHaveLength(0)
        expect(spend).toEqual([])
    })

    // A re-settle or freeze that fails says which, over the cause.
    it.each([
        ['re-settle', (s: ReturnType<typeof solanaSweep>, rec: TicketRecord) => s.resettle(rec, null, new AbortController().signal)],
        ['freeze', (s: ReturnType<typeof solanaSweep>, rec: TicketRecord) => s.freeze(rec, null, ARGS, new AbortController().signal)],
    ] as const)('wraps a failed %s', async (what, call) => {
        const f = await fixture()
        const err = await call(solanaSweep(f.wallet), rowOf('settle_pending', ARGS)).catch((x: unknown) => x)
        expect(err).toBeInstanceOf(Error)
        expect((err as Error).message).toMatch(new RegExp(`^wallet: ${what}: .*no ticket account`))
        expect(((err as Error).cause as Error).message).toMatch(/no ticket account/)
    })

    const registry: RegistryProvider = {
        operators: async () => [],
        resolve: async () => undefined,
        allOperators: async () => [],
        reprobeEphemeral: async () => null,
        recordModelDemand: () => {},
    }
    const signer = { address: PAYER, signBytes: async () => new Uint8Array(), signTransactions: async () => [] }

    // A Client over a SolanaWallet sweeps its journal from create, as one
    // over the SDK's Algorand Wallet does.
    it('runs from a Client over a SolanaWallet', async () => {
        const f = await fixture()
        setTicket(f, TICKET_OPEN, 0n)
        setTicketDeadline(f, nowSeconds() - 3600n)
        const journal = memoryJournal()
        await journal.put(rowOf('open'))
        const c = await Client.create({ signer, network: sweepNetwork, registry, wallet: f.wallet, stores: { journal } })
        try {
            await vi.waitFor(() => expect(f.state.sent).toHaveLength(1))
        } finally {
            await c.close()
        }
    })

    // With no journal it gets the in-memory default and a sweep over it, and
    // a second such Client on one journal is refused, as with the Algorand
    // Wallet.
    it('journals a SolanaWallet in memory and sweeps one journal once', async () => {
        const f = await fixture()
        const c = await Client.create({ signer, network: sweepNetwork, registry, wallet: f.wallet })
        try {
            expect(isMemoryJournal(c.config.stores.journal!)).toBe(true)
            expect(partsOf.get(c)!.reconciler).toBeDefined()
        } finally {
            await c.close()
        }
        const journal = memoryJournal()
        const a = await Client.create({ signer, network: sweepNetwork, registry, wallet: f.wallet, stores: { journal } })
        try {
            await expect(Client.create({ signer, network: sweepNetwork, registry, wallet: f.wallet, stores: { journal } })).rejects.toMatchObject({
                code: 'invalid_config',
                message: expect.stringContaining('already swept by another Client'),
            })
        } finally {
            await a.close()
        }
    })
})
