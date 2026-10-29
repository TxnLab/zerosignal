/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// SolanaWallet's open, over the program's own open offer from the shared sign
// vectors: the twin of go/zs solana_wallet_test.go.

import { readFileSync } from 'node:fs'

import * as ed25519 from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { encodeBase58, parseTransaction, publicKeyBytes, verifySignatures } from '@txnlab/zs-proto/solana'
import { Deployment, OfferRejectedError, PROGRAM_ID, decodeConfig, decodeOpenPayment } from '@txnlab/zs-proto/solana/zsescrow'
import type { Ticket } from '@txnlab/zs-proto/ticket'
import { RAIL_NEUTRAL_NAMES_MIN_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { findError } from '../src/errors.js'
import { MbrDepositUnaffordableError } from '../src/mbr.js'
import type { SolanaSigner } from '../src/ports.js'
import { SOLANA_SIGNER_RESERVE_LAMPORTS } from '../src/registry/solana.js'
import * as root from '../src/index.js'
import { RentDepositBelowTargetError, SOLANA_SIGNATURE_FEE, SolanaRentPool } from '../src/solana/rent.js'
import type { Account, SolanaRpc } from '../src/solana/rpc.js'
import { SIGNED_OPEN_RETENTION_MS, SolanaTicketGoneError, SolanaWallet, readSolanaConfig } from '../src/solana/wallet.js'
import { BelowTargetError } from '../src/wallet.js'
import { testOperator } from './fixtures.js'

type Json = Record<string, any>

const readJson = (name: string) => JSON.parse(readFileSync(new URL(`../../testdata/${name}`, import.meta.url), 'utf8')) as Json
const signVectors = readJson('solana_sign_vectors.json')
const txVectors = readJson('solana_tx_vectors.json')
const accountVectors = readJson('solana_account_vectors.json')

const OFFER = signVectors.offers[0]
const WIRE = base64.decode(OFFER.wire_base64)
const MINT: string = signVectors.usdc_mint
const d = new Deployment(PROGRAM_ID, MINT)
const CONFIG = base64.decode(accountVectors.accounts.find((a: Json) => a.name === 'config_initialized').data_base64)

const TICKET_RENT = (128n + 291n) * 6_960n
const POOL_RENT = (128n + 82n) * 6_960n

const seed = new Uint8Array(32).fill(txVectors.context.keys.payer.seed)
const publicKey = ed25519.getPublicKey(seed)
const PAYER = encodeBase58(publicKey)

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

function poolAccount(lamports: bigint): Account {
    const data = new Uint8Array(82)
    data.set(sha256(new TextEncoder().encode('account:RentPool')).slice(0, 8))
    data[8] = 1
    data[9] = 255
    data.set(publicKeyBytes(PAYER), 18)
    return { lamports, owner: PROGRAM_ID, data, executable: false }
}

/**
 * A cluster holding the Config, the payer and its pool funding poolSlots
 * tickets, or none when null. A deposit it is sent lands at once. It counts
 * the reads of the pool and the balance.
 */
function cluster(balance: bigint, poolSlots: bigint | null) {
    const state = {
        balance,
        pool: poolSlots === null ? null : poolAccount(POOL_RENT + poolSlots * TICKET_RENT),
        config: { lamports: 1n, owner: PROGRAM_ID, data: CONFIG, executable: false } as Account | null,
        sent: 0,
        height: 0n,
        poolReads: 0,
        balanceReads: 0,
    }
    const unused = () => {
        throw new Error('unused')
    }
    const rpc: SolanaRpc = {
        getMinimumBalanceForRentExemption: async (n) => (128n + BigInt(n)) * 6_960n,
        getAccountInfo: async (k, o) => {
            expect(o?.commitment).toBe('confirmed')
            if (k === d.config()) return state.config
            expect(k).toBe(d.rentPool(PAYER))
            state.poolReads++
            return state.pool === null ? null : { ...state.pool }
        },
        getBalance: async () => (state.balanceReads++, state.balance),
        getLatestBlockhash: async () => ({ blockhash: encodeBase58(new Uint8Array(32).fill(9)), lastValidBlockHeight: 150n }),
        sendTransaction: async (raw) => {
            const tx = parseTransaction(raw)
            verifySignatures(tx)
            state.sent++
            const data = tx.message.instructions[0]!.data
            const amount = new DataView(data.buffer, data.byteOffset).getBigUint64(data.length - 8, true)
            if (state.pool === null) {
                state.pool = poolAccount(POOL_RENT)
                state.balance -= POOL_RENT
            }
            state.pool.lamports += amount
            state.balance -= amount + SOLANA_SIGNATURE_FEE
            return encodeBase58(tx.signatures[0]!)
        },
        getSignatureStatuses: async () => [{ slot: 5n, confirmations: 1n, err: null, confirmationStatus: 'confirmed' }],
        getBlockHeight: async () => (state.height += 100n),
        getProgramAccounts: unused,
        getGenesisHash: unused,
    }
    return { rpc, state }
}

const ticket = {
    ticket_id: base64.encode(new Uint8Array(16).fill(1)),
    operator_id: 1,
    node_id: 1,
    max_price: 250_000,
    expires_at: 1_790_000_300,
} as Ticket
const op = testOperator({ id: 1, nodeId: 1, signingAddr: OFFER.spec.node_signing, protoVersion: RAIL_NEUTRAL_NAMES_MIN_VERSION })

/** The working set is 3. */
async function fixture(balance: bigint, poolSlots: bigint | null) {
    const c = cluster(balance, poolSlots)
    const signer = countingSigner()
    const now = { ms: 1_790_000_000_000 }
    const wallet = await SolanaWallet.create({
        rpc: c.rpc,
        deployment: d,
        signer,
        depositSlots: 3,
        confirm: { pollMs: 1, heightCheckMs: 1 },
        clock: () => now.ms,
    })
    return {
        ...c,
        signer,
        wallet,
        now,
        open: (t: Ticket = ticket) => wallet.openForNode(t, op, OFFER.offer_base64),
        /** Opens the ticket again, once the wallet has forgotten it, so the open reaches the pool again. */
        reopen: () => {
            now.ms = ticket.expires_at * 1000 + SIGNED_OPEN_RETENTION_MS + 1000
            return wallet.openForNode(ticket, op, OFFER.offer_base64)
        },
    }
}

describe('SolanaWallet', () => {
    it("signs the node's offer as the program's payer did, sending nothing", async () => {
        expect(OFFER.name).toBe('open')
        expect(PAYER).toBe(OFFER.spec.payer)
        expect(d.tokenAccount(PAYER)).toBe(OFFER.spec.payer_usdc)
        const f = await fixture(1_000_000_000n, 3n)
        const h = await f.open()
        expect(h.signedGroup).toEqual(WIRE)
        expect(h.openGroup).toBe(OFFER.wire_base64)
        const tx = decodeOpenPayment(h.openGroup!, h.appCallTxId)
        expect(h.appCallTxId).toBe(encodeBase58(tx.signatures[0]!))
        expect(h).toMatchObject({ ticketId: ticket.ticket_id, maxPrice: 250_000, groupId: '', openFeesMicroalgos: 0 })
        expect(h.operator.id).toBe(1)
        expect(f.state.sent).toBe(0)
    })

    // With no pool, the wallet funds one before it signs, and a pool the payer
    // can't fund refuses the open with nothing signed, leaving the ticket free
    // to open once the payer funds the wallet.
    it('funds the rent pool before signing', async () => {
        const f = await fixture(0n, null)
        const err = await f.open().catch((e: unknown) => e)
        expect(findError(err, MbrDepositUnaffordableError)).toBeDefined()
        expect(f.signer.asked).toBe(0)
        f.state.balance = 1_000_000_000n
        await f.open()
        expect(f.state.sent).toBe(1)
        expect(f.state.pool).not.toBeNull()
        expect(f.signer.asked).toBe(2)
    })

    // The ack binds the node's open_seq, which holds only while the payer
    // signs one open per ticket: a second offer for the same ticket is
    // refused before the signer is asked, unless the first was never signed.
    it('signs one open per ticket', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        const err = await f.open({ ...ticket, max_price: ticket.max_price + 1 }).catch((e: unknown) => e)
        expect(findError(err, OfferRejectedError)).toBeDefined()
        await f.open()
        await expect(f.open()).rejects.toThrow('already signed, or is signing, an open')
        expect(f.signer.asked).toBe(1)
    })

    // A pool short of the working set still serves while it can fund this one
    // ticket, and isn't latched ready, so the next open tries the top-up
    // again; a pool that can fund none refuses the open.
    it('serves on a short pool', async () => {
        const f = await fixture(0n, 1n)
        await f.open()
        expect(f.signer.asked).toBe(1)
        expect(f.state.sent).toBe(0)
        const reads = f.state.balanceReads
        await f.reopen()
        expect(f.state.balanceReads).toBe(reads + 1)

        const none = await fixture(0n, 0n)
        const err = await none.open().catch((e: unknown) => e)
        expect(findError(err, MbrDepositUnaffordableError)).toBeDefined()
        expect(none.signer.asked).toBe(0)
    })

    // A first deposit that lands short of the working set serves the open it
    // funded, and the next open tries the top-up again.
    it('serves on a deposit below target', async () => {
        // The pool's own rent, one ticket's and the fee, and no more.
        const f = await fixture(SOLANA_SIGNER_RESERVE_LAMPORTS + POOL_RENT + TICKET_RENT + SOLANA_SIGNATURE_FEE, null)
        await f.open()
        expect(f.state.sent).toBe(1)
        const reads = f.state.balanceReads
        await f.reopen()
        expect(f.state.balanceReads).toBe(reads + 1)
    })

    // A pool covering the working set is latched: later opens read nothing
    // until a node's refusal clears the latch.
    it('latches a covered pool until recheckDeposit', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        await f.open()
        expect(f.state.poolReads).toBe(1)
        await f.reopen()
        expect(f.state.poolReads).toBe(1)
        f.wallet.recheckDeposit()
        await f.reopen()
        expect(f.state.poolReads).toBe(2)
    })

    // A host reaches the wallet only through the package root, which is all
    // the package exports for it.
    it('is exported from the package root', () => {
        expect([root.SolanaWallet, root.SolanaRentPool, root.SolanaTicketGoneError, root.readSolanaConfig]).toEqual([
            SolanaWallet,
            SolanaRentPool,
            SolanaTicketGoneError,
            readSolanaConfig,
        ])
    })

    // Closing the pool clears the latch whether or not the close lands, so
    // the next open tops it up again rather than signing an offer the program
    // refuses for want of a pool.
    it('clears the latch on closeRentPool', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        expect(f.wallet.rentPool()).toBeInstanceOf(SolanaRentPool)
        await f.open()
        await f.reopen()
        const reads = f.state.poolReads
        await f.wallet.closeRentPool().catch(() => undefined)
        const afterClose = f.state.poolReads
        expect(afterClose).toBeGreaterThan(reads)
        await f.reopen()
        expect(f.state.poolReads).toBeGreaterThan(afterClose)
    })

    it('forgets a ticket past its open window, and not before', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        await f.open()
        f.now.ms = ticket.expires_at * 1000 + SIGNED_OPEN_RETENTION_MS
        await expect(f.open()).rejects.toThrow('already signed, or is signing, an open')
        f.now.ms += 1000
        await f.open()
    })

    // The node submits the open from payment_open, so a node that reads only
    // the Algorand names gets nothing signed, nor a node that doesn't submit
    // opens.
    it('needs a node that reads the rail-neutral names', async () => {
        const f = await fixture(1_000_000_000n, null)
        await expect(f.wallet.openForNode(ticket, { ...op, protoVersion: '9.12' }, OFFER.offer_base64)).rejects.toThrow('needs 9.13')
        await expect(f.wallet.open()).rejects.toThrow('the node submits the open')
        expect(f.signer.asked).toBe(0)
        expect(f.state.sent).toBe(0)
    })

    it('refuses a ticket id in another spelling', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        await expect(f.open({ ...ticket, ticket_id: 'AQEBAQEBAQEBAQEBAQEBAR==' })).rejects.toThrow('wallet: decode ticket id: decode ticket id base64')
        expect(f.signer.asked).toBe(0)
    })

    // The wallet checks offers against the Config's mint and decimals, so a
    // Config missing or naming another mint fails create.
    it.each([
        ['no account', null, MINT, 'has no Config'],
        ['another owner', { lamports: 1n, owner: MINT, data: CONFIG, executable: false }, MINT, 'has no Config'],
        ['another mint', undefined, PAYER, 'not the deployment'],
    ] as const)('refuses a Config with %s', async (_, config, mint, want) => {
        const c = cluster(0n, null)
        if (config !== undefined) c.state.config = config
        await expect(SolanaWallet.create({ rpc: c.rpc, deployment: new Deployment(PROGRAM_ID, mint), signer: countingSigner() })).rejects.toThrow(want)
    })

    // A receipt the handle can't read is the ack's or the freeze's error,
    // never a rejection, as each promises.
    it('hands back a handle whose ack and freeze never reject', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        const h = await f.open()
        const r = await h.ackSettle({} as never, null)
        expect(String(r.err)).toContain('wallet: ack-settle')
        const freeze = await h.freezeOverclaim!({} as never)
        expect(freeze.claim).toBe('unreadable')
        expect(freeze.err).toBeDefined()
    })

    // A ticket already signed for is refused before the pool is read, so a
    // second offer for it costs no top-up even once the latch is cleared.
    it('refuses a signed ticket before reading the pool', async () => {
        const f = await fixture(1_000_000_000n, 3n)
        await f.open()
        f.wallet.recheckDeposit()
        const reads = f.state.poolReads
        await expect(f.open()).rejects.toThrow('already signed, or is signing')
        expect(f.state.poolReads).toBe(reads)
    })

    // The offer's transfer must carry the Config's decimals, not an assumed
    // 6: against a Config of 9 decimals, the program's 6-decimal offer is
    // refused.
    it("checks the offer at the Config's decimals", async () => {
        const c = cluster(1_000_000_000n, 3n)
        const data = CONFIG.slice()
        data[12] = 9
        expect(decodeConfig(data).usdcDecimals).toBe(9)
        c.state.config = { lamports: 1n, owner: PROGRAM_ID, data, executable: false }
        const signer = countingSigner()
        const w = await SolanaWallet.create({ rpc: c.rpc, deployment: d, signer, depositSlots: 3 })
        const err = await w.openForNode(ticket, op, OFFER.offer_base64).catch((e: unknown) => e)
        expect(findError(err, OfferRejectedError)).toBeDefined()
        expect(signer.asked).toBe(0)
    })

    it('reports a pool below target in lamports, with what it deposited', () => {
        const err = new RentDepositBelowTargetError(2_512_560n)
        expect(err).toBeInstanceOf(BelowTargetError)
        expect(err.deposited).toBe(2_512_560n)
        expect(err.message).toBe('wallet: ticket rent pool funded below the configured working set (deposited 2512560 lamports)')
    })
})
