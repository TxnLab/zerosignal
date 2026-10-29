/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The TS Client through each ending against the real zs_escrow program on a
// cluster, served by the Go stub node (go/cmd/solanastub) and checked through
// its /stub/ routes. The twin of go/internal/solanastub e2e_test.go, and set
// up as it is: ZS_SOLANA_E2E_RPC names the cluster's endpoint, and the run is
// funded by ZS_SOLANA_E2E_MINT_AUTHORITY, a local validator's test USDC mint's
// authority and Config admin, or by ZS_SOLANA_E2E_FUNDER, a wallet holding SOL
// and test USDC; without the endpoint and one of them it skips.
// ZS_SOLANA_E2E_CLUSTER is the payers' network preset, localnet unless it says
// devnet, and ZS_SOLANA_E2E_STUB_IDENTITY an identity file the stub serves as
// rather than register a node.

import { type ChildProcess, execFile, spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import * as ed25519 from '@noble/ed25519'
import { base64 } from '@scure/base'
import {
    type Instruction,
    type PublicKey,
    SYSTEM_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    compileMessage,
    createAssociatedTokenAccountIdempotent,
    encodeBase58,
    encodeTransaction,
    newTransaction,
    signTransaction,
    transferChecked,
} from '@txnlab/zs-proto/solana'
import {
    Deployment,
    FREEZE_ORIGIN_PROTEST,
    FREEZE_ORIGIN_SETTLE_MISMATCH,
    decodeTokenAccount,
} from '@txnlab/zs-proto/solana/zsescrow'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { Client, ZsError, httpCreditIssuer, solanaDevnet, solanaLocalnet } from '../src/index.js'
import type { ReceiptVerified, SettleResult } from '../src/index.js'
import type { SolanaSigner } from '../src/ports.js'
import { confirmSignature } from '../src/solana/confirm.js'
import { SolanaRentPool, rentPoolAvailable, rentPoolFreeSlots } from '../src/solana/rent.js'
import { SolanaRpcClient } from '../src/solana/rpc.js'
import { fetchSolanaPayerTickets } from '../src/solana/tickets.js'
import { SolanaTicketGoneError, SolanaWallet, readSolanaConfig } from '../src/solana/wallet.js'

const RPC = process.env.ZS_SOLANA_E2E_RPC ?? ''
const AUTHORITY = process.env.ZS_SOLANA_E2E_MINT_AUTHORITY ?? ''
const FUNDER = process.env.ZS_SOLANA_E2E_FUNDER ?? ''
const CLUSTER = process.env.ZS_SOLANA_E2E_CLUSTER || 'localnet'
const IDENTITY = process.env.ZS_SOLANA_E2E_STUB_IDENTITY ?? ''

// Refused as the Go suite refuses them, rather than picking one.
function checkEnv(): void {
    if (AUTHORITY && FUNDER)
        throw new Error('set one of ZS_SOLANA_E2E_MINT_AUTHORITY and ZS_SOLANA_E2E_FUNDER, not both')
    if (CLUSTER !== 'localnet' && CLUSTER !== 'devnet')
        throw new Error(`ZS_SOLANA_E2E_CLUSTER=${JSON.stringify(CLUSTER)}: want localnet or devnet`)
}

// A wait on a transaction the node or payer sends.
const CONFIRM_MS = CLUSTER === 'devnet' ? 60_000 : 30_000
// vitest fixes a test's timeout when it is declared, before beforeAll reads
// the cluster's grace, so the caps are static: a turn, and a turn plus a
// deadline, room for a grace up to ten minutes and the watchdog's margins.
const TURN_MS = 240_000
const ENDING_MS = 900_000

// What go/cmd/solanastub prints once it is serving.
interface Stub {
    url: string
    operator_id: number
    node_id: number
    program: string
    fee_bps: number
    default_grace: number
    payer_usdc: number
    model: string
    free_model: string
    reply: string
    sol_usd: number
    credit_issuer: string
    issuer_payer_header: string
    treasury: string
    funds_source: string
    resolves: boolean
}

interface Behavior {
    issuer_down?: boolean
    no_receipt?: boolean
    claim_no_receipt?: boolean
    bad_body_hash?: boolean
    over_claim?: number
    ticket_lifetime_ms?: number
    hold_open?: boolean
}

interface TicketState {
    ticket_id: string
    max_price: number
    closed: boolean
    status?: string
    freeze_origin?: number
    deadline?: number
    pending_amount?: number
}

interface PayerState {
    usdc: number
    tickets: TicketState[]
    /** Priced tickets the stub issued whose open never landed; closed says no account exists. */
    unopened: TicketState[]
    receipt_amounts: number[]
    errors: string[]
    credits: number
    issuer_calls: number
}

let stub: Stub
let proc: ChildProcess | undefined
let binDir = ''

async function startStub(): Promise<Stub> {
    binDir = mkdtempSync(join(tmpdir(), 'solanastub-'))
    const bin = join(binDir, 'solanastub')
    // Built, not `go run`: killing go run can leave the server it started.
    await promisify(execFile)(process.env.GO ?? 'go', ['build', '-o', bin, './cmd/solanastub'], {
        cwd: fileURLToPath(new URL('../../go', import.meta.url)),
    })
    // stdin is a pipe only this process holds, so the stub exits with it even
    // when the runner is killed before afterAll.
    const args = ['-rpc', RPC, '-exit-on-stdin-eof', ...(AUTHORITY ? ['-mint-authority', AUTHORITY] : ['-funder', FUNDER])]
    if (IDENTITY) args.push('-identity', IDENTITY)
    const p = spawn(bin, args, {
        stdio: ['pipe', 'pipe', 'inherit'],
    })
    proc = p
    const line = await new Promise<string>((resolve, reject) => {
        p.once('error', reject)
        p.once('exit', (code) => reject(new Error(`solanastub exited with ${code} before it was ready`)))
        createInterface({ input: p.stdout! }).once('line', resolve)
    })
    return JSON.parse(line) as Stub
}

async function control<T>(path: string, init?: RequestInit): Promise<T> {
    const r = await fetch(stub.url + path, init)
    if (!r.ok) throw new Error(`stub ${path}: ${r.status} ${await r.text()}`)
    return (r.status === 204 ? undefined : await r.json()) as T
}

const payerState = (address: string) => control<PayerState>(`/stub/payers/${address}`)

const withFee = (amount: number | bigint) => BigInt(amount) + (BigInt(amount) * BigInt(stub.fee_bps)) / 10_000n

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** One funded payer and its own Client, so a node one scenario bars stays routable for the rest. */
class Payer {
    constructor(
        readonly key: Key,
        readonly client: Client,
    ) {}

    get address(): string {
        return this.key.address
    }

    get signer(): SolanaSigner {
        return this.key.signer
    }

    /** usdc absent is the stub's PayerUSDC. */
    static async create(behavior: Behavior, credits = false, usdc?: bigint): Promise<Payer> {
        const key = await newKey()
        const address = key.address
        await control('/stub/payers', {
            method: 'POST',
            body: JSON.stringify({ address, behavior, ...(usdc === undefined ? {} : { usdc: Number(usdc) }) }),
        })
        // The stub's issuer, naming the payer in the header it counts by, as
        // a host's gate header would.
        const freeCredits = credits
            ? {
                  issuers: {
                      [stub.credit_issuer]: httpCreditIssuer({
                          url: stub.url,
                          headers: (h) => h.set(stub.issuer_payer_header, address),
                      }),
                  },
              }
            : undefined
        const client = await Client.create({
            ...(freeCredits ? { freeCredits } : {}),
            solanaSigner: key.signer,
            network: { ...(CLUSTER === 'devnet' ? solanaDevnet() : solanaLocalnet()), rpcEndpoint: RPC, program: stub.program },
            // One node can't be its own relay.
            privacy: 'direct',
            allowPrivateHosts: true,
            disableTee: true,
            discovery: { operatorIds: [stub.operator_id] },
        })
        return new Payer(key, client)
    }

    /**
     * Runs one chat turn, on the stub's priced model unless model names another, and waits for its settle submit.
     * withinMs is the turn's budget, longer for a node a scenario has answer slowly.
     */
    async ask(
        stream: boolean,
        model = stub.model,
        withinMs = 120_000,
    ): Promise<{ text: string; err: unknown; settled: SettleResult; verified: ReceiptVerified | undefined }> {
        const body = JSON.stringify({
            model,
            messages: [{ role: 'user', content: 'say hello' }],
            max_tokens: 64,
            stream,
        })
        const s = this.client.stream({ endpoint: '/v1/chat/completions', body }, AbortSignal.timeout(withinMs))
        let text = ''
        let err: unknown
        let verified: ReceiptVerified | undefined
        try {
            for await (const ev of s.events()) {
                if (ev.type === 'delta.text') text += ev.delta
                if (ev.type === 'receipt.verified') verified = ev
            }
        } catch (e) {
            err = e
        }
        return { text, err, settled: await s.wait(AbortSignal.timeout(120_000)), verified }
    }

    async onlyTicket(): Promise<string> {
        const { tickets } = await payerState(this.address)
        expect(tickets, 'tickets the payer opened at the stub').toHaveLength(1)
        return tickets[0]!.ticket_id
    }

    /** Polls the ticket until done says it has reached the state a scenario waits for. */
    async waitTicket(
        id: string,
        withinMs: number,
        what: string,
        done: (t: TicketState) => boolean,
    ): Promise<TicketState> {
        const deadline = Date.now() + withinMs
        for (;;) {
            const t = (await payerState(this.address)).tickets.find((x) => x.ticket_id === id)!
            if (done(t)) return t
            if (Date.now() >= deadline)
                throw new Error(`ticket ${id}: not ${what} within ${withinMs} ms (now ${JSON.stringify(t)})`)
            await sleep(1000)
        }
    }

    async usdc(): Promise<bigint> {
        return BigInt((await payerState(this.address)).usdc)
    }

    async checkStub(): Promise<void> {
        expect((await payerState(this.address)).errors, 'stub node errors').toEqual([])
    }
}

const payers: Payer[] = []
async function newPayer(b: Behavior, credits = false, usdc?: bigint): Promise<Payer> {
    const p = await Payer.create(b, credits, usdc)
    payers.push(p)
    return p
}

/** Fails unless err is the SDK's error carrying the node's code, so a turn that failed some other way doesn't pass for the refusal a scenario drives. */
function expectCode(err: unknown, code: string): void {
    expect(err, 'the turn error').toBeInstanceOf(ZsError)
    expect((err as ZsError).code).toBe(code)
}

/** The program's deployment on the validator, its mint read from the Config. */
async function deployment(rpc: SolanaRpcClient): Promise<Deployment> {
    return new Deployment(stub.program, (await readSolanaConfig(rpc, new Deployment(stub.program, ''))).usdcMint)
}

/** A SolanaWallet for signer apart from any Client, as a host's wallet commands build one. */
async function walletFor(rpc: SolanaRpcClient, signer: SolanaSigner): Promise<SolanaWallet> {
    return SolanaWallet.create({ rpc, deployment: await deployment(rpc), signer })
}

/** Has the stub give an address lamports, from the run's funding. */
async function fundSol(to: string, lamports: bigint): Promise<void> {
    await control('/stub/fund', { method: 'POST', body: JSON.stringify({ address: to, lamports: Number(lamports) }) })
}

/** A throwaway key the run funds, which the sweep hands back. */
interface Key {
    seed: Uint8Array
    address: string
    signer: SolanaSigner
}

const keys: Key[] = []
async function newKey(): Promise<Key> {
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const publicKey = await ed25519.getPublicKeyAsync(seed)
    const address = encodeBase58(publicKey)
    const k = { seed, address, signer: solanaSigner({ seed, publicKey, address }) }
    keys.push(k)
    return k
}

// A one-signature transaction's fee on every cluster today.
const SIGNATURE_FEE = 5_000n

// The system program's Transfer and SPL Token's CloseAccount. Test tooling
// alone sends SOL between wallets or closes a token account, so these live
// here, as they do in go/internal/solanastub, rather than in ts/src/solana.
function systemTransfer(from: PublicKey, to: PublicKey, lamports: bigint): Instruction {
    const data = new Uint8Array(12)
    const v = new DataView(data.buffer)
    v.setUint32(0, 2, true)
    v.setBigUint64(4, lamports, true)
    return {
        programId: SYSTEM_PROGRAM_ID,
        accounts: [
            { publicKey: from, isSigner: true, isWritable: true },
            { publicKey: to, isSigner: false, isWritable: true },
        ],
        data,
    }
}

function closeTokenAccount(account: PublicKey, destination: PublicKey, owner: PublicKey): Instruction {
    return {
        programId: TOKEN_PROGRAM_ID,
        accounts: [
            { publicKey: account, isSigner: false, isWritable: true },
            { publicKey: destination, isSigner: false, isWritable: true },
            { publicKey: owner, isSigner: true, isWritable: false },
        ],
        data: Uint8Array.of(9),
    }
}

/**
 * Hands back what k holds when a funder paid for it: SOL and test USDC on a
 * shared cluster are topped up by hand, so a nightly run must not bleed them
 * into throwaway keys. The rent pool goes first, since once the SOL is
 * returned nothing is left to pay its close's fee; then the USDC, the token
 * account's rent and the SOL in one transaction, as solanastub's ReturnFunds
 * sends them. A scenario can end with its ticket still settling, and the
 * settle's refund then lands between the balance read and the return, whose
 * close fails on the balance it didn't send: so each step is tried again
 * after a pause. A pool with a frozen ticket won't close, and leaves its
 * lamports behind.
 */
async function sweep(rpc: SolanaRpcClient, d: Deployment, decimals: number, k: Key): Promise<void> {
    const pool = new SolanaRentPool({ rpc, deployment: d, signer: k.signer })
    try {
        await retrySweep(async () => {
            if ((await pool.status()).exists) await pool.close()
        })
    } catch (e) {
        console.warn(`sweep ${k.address}: the rent pool:`, e)
    }
    await retrySweep(() => returnFunds(rpc, d, decimals, k))
}

/** Runs step up to three times, five seconds apart, long enough for a settle in flight to land. */
async function retrySweep(step: () => Promise<void>): Promise<void> {
    for (let attempt = 1; ; attempt++) {
        try {
            return await step()
        } catch (e) {
            if (attempt === 3) throw e
            await sleep(5_000)
        }
    }
}

async function returnFunds(rpc: SolanaRpcClient, d: Deployment, decimals: number, k: Key): Promise<void> {
    const to = stub.funds_source
    let lamports = await rpc.getBalance(k.address, { commitment: 'confirmed' })
    const ixs: Instruction[] = []
    const ata = d.tokenAccount(k.address)
    const acct = await rpc.getAccountInfo(ata, { commitment: 'confirmed' })
    if (acct) {
        const { amount } = decodeTokenAccount(acct.data)
        if (amount > 0n) ixs.push(transferChecked(ata, d.mint, d.tokenAccount(to), k.address, amount, decimals))
        ixs.push(closeTokenAccount(ata, k.address, k.address))
        lamports += acct.lamports
    }
    if (lamports > SIGNATURE_FEE) ixs.push(systemTransfer(k.address, to, lamports - SIGNATURE_FEE))
    if (ixs.length > 0) await sendAs(rpc, k, ixs)
}

/** Sends ixs signed and paid for by k alone, and waits until they are confirmed. */
async function sendAs(rpc: SolanaRpcClient, k: Key, ixs: Instruction[]): Promise<void> {
    const bh = await rpc.getLatestBlockhash({ commitment: 'confirmed' })
    const t = newTransaction(compileMessage(k.address, bh.blockhash, ixs, 'legacy'))
    signTransaction(t, k.seed)
    const sig = await rpc.sendTransaction(encodeTransaction(t))
    const r = await confirmSignature(rpc, sig, bh.lastValidBlockHeight, 'confirmed')
    if (r.err) throw new Error(`landed and failed: ${JSON.stringify(r.err)}`)
}

/** Every key's sweep, in funder mode; a failure is logged, never a test's. */
async function sweepAll(): Promise<void> {
    if (!FUNDER || keys.length === 0) return
    const rpc = new SolanaRpcClient({ endpoint: RPC })
    const d = await deployment(rpc)
    const { usdcDecimals } = await readSolanaConfig(rpc, d)
    const results = await Promise.allSettled(keys.map((k) => sweep(rpc, d, usdcDecimals, k)))
    results.forEach((r, i) => {
        if (r.status === 'rejected') console.warn(`sweep ${keys[i]!.address}:`, r.reason)
    })
}

const closed = (t: TicketState) => t.closed
// Statuses as zsescrow.TicketStatus.String spells them.
const frozen = (t: TicketState) => !t.closed && t.status === 'Frozen'

describe.skipIf(RPC === '' || (AUTHORITY === '' && FUNDER === '')).concurrent('Solana end to end', () => {
    beforeAll(async () => {
        checkEnv()
        stub = await startStub()
    }, ENDING_MS)

    afterAll(async () => {
        try {
            await Promise.allSettled(payers.map((p) => p.client.close()))
            // After the Clients, so no watchdog is still spending.
            await sweepAll()
        } finally {
            proc?.kill()
            if (binDir) rmSync(binDir, { recursive: true, force: true })
        }
    }, ENDING_MS)

    // The payer opens, the node serves and settles on the payer's ack, and the
    // payer pays exactly the receipt's amount.
    for (const stream of [false, true]) {
        it(`settles a ${stream ? 'streamed' : 'buffered'} turn`, async () => {
            const p = await newPayer({})
            const { text, err, settled, verified } = await p.ask(stream)
            expect(err).toBeUndefined()
            expect(settled.err).toBeUndefined()
            expect(text).toBe(stub.reply)
            // The fees are priced at the node's SOL rate, not the ALGO one it also sends.
            expect(verified?.nativeUsd).toBe(stub.sol_usd)
            expect(verified?.feeUnit.currency).toBe('SOL')
            expect(settled.settlement.kind).toBe('atomic')
            expect(settled.settlement.frozen).toBeFalsy()
            await p.waitTicket(await p.onlyTicket(), CONFIRM_MS, 'settled', closed)
            const { receipt_amounts } = await payerState(p.address)
            expect(receipt_amounts).toHaveLength(1)
            expect(BigInt(stub.payer_usdc) - (await p.usdc())).toBe(withFee(receipt_amounts[0]!))
            await p.checkStub()
        }, TURN_MS)
    }

    // A free turn opens nothing: the payer signs and pays nothing, the node's
    // receipt charges zero, and nothing settles.
    for (const stream of [false, true]) {
        it(`opens nothing for a free ${stream ? 'streamed' : 'buffered'} turn`, async () => {
            const p = await newPayer({})
            const { text, err, settled } = await p.ask(stream, stub.free_model)
            expect(err).toBeUndefined()
            expect(settled.err).toBeUndefined()
            expect(text).toBe(stub.reply)
            expect(settled.settlement.kind).toBe('')
            const { tickets, receipt_amounts } = await payerState(p.address)
            expect(tickets, 'tickets the payer opened at the stub').toEqual([])
            expect(receipt_amounts).toEqual([0])
            expect(await p.usdc()).toBe(BigInt(stub.payer_usdc))
            await p.checkStub()
        }, TURN_MS)
    }

    // A free turn at a node that trusts the issuer carries a credit the node
    // verifies; the next turn spends the batch's next credit without asking
    // the issuer again. With the issuer down the turn still goes, with no
    // credit, and a paid turn asks the issuer nothing.
    it('carries a credit from the batch on each free turn', async () => {
        const p = await newPayer({}, true)
        for (const turn of [1, 2]) {
            const { text, err, settled } = await p.ask(turn === 2, stub.free_model)
            expect(err).toBeUndefined()
            expect(settled.err).toBeUndefined()
            expect(text).toBe(stub.reply)
            expect((await payerState(p.address)).credits, `credits verified after turn ${turn}`).toBe(turn)
        }
        // The day key and one batch.
        expect((await payerState(p.address)).issuer_calls).toBe(2)
        await p.checkStub()
    }, TURN_MS)

    it('serves a free turn without a credit while the issuer is down', async () => {
        const p = await newPayer({ issuer_down: true }, true)
        const { text, err, settled } = await p.ask(false, stub.free_model)
        expect(err).toBeUndefined()
        expect(settled.err).toBeUndefined()
        expect(text).toBe(stub.reply)
        const s = await payerState(p.address)
        expect(s.credits).toBe(0)
        expect(s.issuer_calls).toBe(1)
        await p.checkStub()
    }, TURN_MS)

    it('asks the issuer nothing for a paid turn', async () => {
        const p = await newPayer({}, true)
        const { err, settled } = await p.ask(false)
        expect(err).toBeUndefined()
        expect(settled.err).toBeUndefined()
        expect((await payerState(p.address)).issuer_calls).toBe(0)
        await p.checkStub()
    }, TURN_MS)

    // A ticket the node opened and never served is refunded in full by the
    // payer's watchdog once its deadline passes.
    it('refunds an unserved ticket', async () => {
        const p = await newPayer({ no_receipt: true, ticket_lifetime_ms: 10_000 })
        const { err } = await p.ask(false)
        expect(err, "the node's failure").toBeDefined()
        // Room for the watchdog's margin past the deadline and one retry of a
        // refund the validator's clock refused as early.
        await p.waitTicket(await p.onlyTicket(), 10_000 + stub.default_grace * 1000 + 120_000, 'refunded', closed)
        expect(await p.usdc()).toBe(BigInt(stub.payer_usdc))
        await p.checkStub()
    }, ENDING_MS)

    // What a host's wallet commands call, against the program: the fee rate and
    // the USDC account create for a payer with SOL alone, then the ticket
    // listing and recovery, and the rent pool's withdraw and close, around a
    // ticket the watchdog refunds.
    it("answers a host's wallet calls", async () => {
        const rpc = new SolanaRpcClient({ endpoint: RPC })
        const fresh = (await newKey()).signer
        await fundSol(fresh.address, 10_000_000n)
        const w = await walletFor(rpc, fresh)
        await expect(w.protocolFeeBps()).resolves.toBe(stub.fee_bps)
        expect(await w.ensureUsdcAccount()).not.toBe('')
        await expect(w.ensureUsdcAccount()).resolves.toBe('')
        expect((await rpc.getAccountInfo(w.usdcAccount(), { commitment: 'confirmed' }))?.owner).toBe(TOKEN_PROGRAM_ID)

        const p = await newPayer({ no_receipt: true, ticket_lifetime_ms: 10_000 })
        const { err } = await p.ask(false)
        expect(err, "the node's failure").toBeDefined()
        const id = await p.onlyTicket()
        const d = await deployment(rpc)
        const listed = await fetchSolanaPayerTickets(rpc, d, p.address)
        expect(listed.unreadable).toEqual([])
        expect(listed.tickets.map((t) => [base64.encode(t.ticket.ticketId), t.operatorId, t.nodeId])).toEqual([
            [id, BigInt(stub.operator_id), BigInt(stub.node_id)],
        ])
        // Inside its settle window the program allows no ending, so nothing goes.
        const pw = await walletFor(rpc, p.signer)
        const [opId, nodeId, ticketId] = [BigInt(stub.operator_id), BigInt(stub.node_id), base64.decode(id)]
        await expect(pw.recoverTicket(opId, nodeId, ticketId)).resolves.toEqual({ verdict: 'wait', signature: '' })
        await p.waitTicket(id, 10_000 + stub.default_grace * 1000 + 120_000, 'refunded', closed)
        await expect(pw.recoverTicket(opId, nodeId, ticketId)).rejects.toBeInstanceOf(SolanaTicketGoneError)
        expect((await fetchSolanaPayerTickets(rpc, d, p.address)).tickets).toEqual([])

        const pool = new SolanaRentPool({ rpc, deployment: d, signer: p.signer })
        const st = await pool.status()
        expect([st.exists, st.openTickets, rentPoolFreeSlots(st) > 0n]).toEqual([true, 0n, true])
        await pool.withdraw(st.ticketRent)
        const after = await pool.status()
        expect(rentPoolAvailable(after)).toBe(rentPoolAvailable(st) - st.ticketRent)
        expect((await pool.close()).returned).toBe(after.lamports)
        expect((await pool.status()).exists).toBe(false)
        await p.checkStub()
    }, ENDING_MS)

    // A receipt that doesn't hash the reply is protested at once, which freezes
    // the ticket.
    it('protests a bad receipt', async () => {
        const p = await newPayer({ bad_body_hash: true })
        const { settled } = await p.ask(false)
        expect(settled.err).toBeUndefined()
        expect(settled.settlement.kind).toBe('protest')
        expect(settled.settlement.frozen).toBe(true)
        const t = await p.waitTicket(await p.onlyTicket(), CONFIRM_MS, 'frozen by the protest', frozen)
        expect(t.freeze_origin).toBe(FREEZE_ORIGIN_PROTEST)
        await p.checkStub()
    }, TURN_MS)

    // A node claim above the receipt, with the node refusing the ack, gets the
    // payer's own half at the receipt's figures, which freezes the ticket.
    it('freezes an over-claim', async () => {
        // Small enough that the claim and its fee stay under max_price.
        const p = await newPayer({ over_claim: 10 })
        const { err, settled } = await p.ask(false)
        expect(err).toBeUndefined()
        expect(settled.err).toBeUndefined()
        expect(settled.settlement.frozen).toBe(true)
        const id = await p.onlyTicket()
        const t = await p.waitTicket(id, CONFIRM_MS, 'frozen by the mismatch', frozen)
        expect(t.freeze_origin).toBe(FREEZE_ORIGIN_SETTLE_MISMATCH)
        // The over-claim bars the node, so the next turn finds nowhere to go.
        expect((await p.ask(false)).err, 'a second turn at the barred node').toBeDefined()
        expect((await payerState(p.address)).tickets).toHaveLength(1)
        await p.checkStub()

        // Only the admin releases a frozen ticket. A run funded without it,
        // devnet's, stops at the freeze; that is the scenario's end there,
        // not a skip.
        if (!stub.resolves) {
            console.info("resolving the freeze needs the Config's admin, which this run doesn't hold")
            return
        }
        // Half the pre-fee ceiling to the node, its fee on top, the rest back
        // to the payer, as the program's resolve_split divides it.
        const share = 5_000n
        await control('/stub/resolve', {
            method: 'POST',
            body: JSON.stringify({ address: p.address, ticket_id: id, operator_share_bps: Number(share) }),
        })
        await p.waitTicket(id, CONFIRM_MS, 'resolved', closed)
        const award = ((BigInt(t.max_price) * 10_000n) / (10_000n + BigInt(stub.fee_bps)) * share) / 10_000n
        expect(BigInt(stub.payer_usdc) - (await p.usdc()), 'what the payer paid after the resolve').toBe(withFee(award))
    }, TURN_MS)

    // A node that sends the payer's open only after its blockhash expired can
    // never land it: the turn fails, no ticket account exists, and the payer
    // is charged nothing.
    it('charges nothing for an open whose blockhash expired', async () => {
        const p = await newPayer({ hold_open: true })
        // The node holds the turn for a blockhash's whole life, 150 blocks, a
        // minute or more on a busy cluster, before it answers.
        expectCode((await p.ask(false, stub.model, 300_000)).err, 'payment_verification_failed')
        const s = await payerState(p.address)
        expect(s.tickets, 'tickets the payer opened at the stub').toEqual([])
        expect(s.unopened.length, 'priced tickets the stub held the open of').toBeGreaterThan(0)
        expect(s.unopened.every((t) => t.closed), 'no ticket account for a held open').toBe(true)
        expect(BigInt(s.usdc)).toBe(BigInt(stub.payer_usdc))
        await p.checkStub()
    }, ENDING_MS)

    // Two turns at once whose max prices together exceed the payer's
    // balance: one open lands and is served, the cluster refuses the other's
    // transfer, and the payer pays once.
    it('spends once for two concurrent turns it can afford one of', async () => {
        // A turn's max price and charge, from a payer with plenty; the second
        // payer's turns are the same request, so the same figures.
        const warm = await newPayer({})
        const w = await warm.ask(false)
        expect(w.err).toBeUndefined()
        expect(w.settled.err).toBeUndefined()
        const ws = await payerState(warm.address)
        expect(ws.tickets).toHaveLength(1)
        expect(ws.receipt_amounts).toHaveLength(1)
        // One max price held, and short of a second even after the first
        // settles and refunds.
        const funded = BigInt(ws.tickets[0]!.max_price) + withFee(ws.receipt_amounts[0]!) - 1n
        const p = await newPayer({}, false, funded)

        const results = await Promise.all([p.ask(false), p.ask(false)])
        const served = results.filter((r) => r.err === undefined && r.settled.err === undefined && r.text === stub.reply)
        expect(served, 'turns served').toHaveLength(1)
        for (const r of results) if (!served.includes(r)) expectCode(r.err, 'payment_verification_failed')
        await p.waitTicket(await p.onlyTicket(), CONFIRM_MS, 'settled', closed)
        const s = await payerState(p.address)
        expect(s.receipt_amounts).toHaveLength(1)
        expect(funded - BigInt(s.usdc), 'what the payer paid').toBe(withFee(s.receipt_amounts[0]!))
        expect([...s.tickets, ...s.unopened].every((t) => t.closed), 'no ticket left open').toBe(true)
        await p.checkStub()
    }, TURN_MS)

    // A refund the payer can't take, its USDC account closed, goes to the
    // treasury: the ticket still closes, and the payer's account stays
    // closed.
    it('forfeits the refund of a payer whose USDC account is closed', async () => {
        const rpc = new SolanaRpcClient({ endpoint: RPC })
        const p = await newPayer({ no_receipt: true, ticket_lifetime_ms: 10_000 })
        const { err } = await p.ask(false)
        expect(err, "the node's failure").toBeDefined()
        const id = await p.onlyTicket()
        const maxPrice = BigInt((await payerState(p.address)).tickets[0]!.max_price)
        const treasuryUsdc = async () => BigInt((await payerState(stub.treasury)).usdc)
        const before = await treasuryUsdc()

        // The payer empties its USDC account and closes it, keeping its SOL
        // for the refund's fee.
        const d = await deployment(rpc)
        const { usdcDecimals } = await readSolanaConfig(rpc, d)
        const [ata, source] = [d.tokenAccount(p.address), stub.funds_source]
        await sendAs(rpc, p.key, [
            createAssociatedTokenAccountIdempotent(p.address, source, d.mint),
            transferChecked(ata, d.mint, d.tokenAccount(source), p.address, await p.usdc(), usdcDecimals),
            closeTokenAccount(ata, p.address, p.address),
        ])

        await p.waitTicket(id, 10_000 + stub.default_grace * 1000 + 120_000, 'refunded', closed)
        // At least the forfeit: on a shared cluster another run's forfeits
        // land on the treasury too.
        expect((await treasuryUsdc()) - before >= maxPrice, 'the treasury gained the forfeited max price').toBe(true)
        expect(await rpc.getAccountInfo(ata, { commitment: 'confirmed' }), "the payer's USDC account").toBeNull()
        await p.checkStub()
    }, ENDING_MS)

    // A claim the payer holds no receipt against is left to lapse: the payer
    // neither refunds nor freezes it, and it lapses to the node at the deadline.
    it('leaves an uncontested claim to lapse', async () => {
        const p = await newPayer({ claim_no_receipt: true, ticket_lifetime_ms: 10_000 })
        const { err } = await p.ask(false)
        expect(err, "the node's failure").toBeDefined()
        const id = await p.onlyTicket()
        const claimed = (t: TicketState) => !t.closed && t.status === 'PendingByOperator'
        const t = await p.waitTicket(id, CONFIRM_MS, 'claimed', claimed)
        // Past the watchdog's first look (the deadline plus its 15 s margin) and
        // a confirm: a payer that refunded or froze the claim would have by now.
        // Its own lapse waits ten minutes, so the claim is still the node's.
        await sleep(t.deadline! * 1000 + 30_000 - Date.now())
        const still = await p.waitTicket(id, 0, "still claimed past the payer's first look", claimed)
        // The validator's clock can trail the wall clock under load, which the
        // program reads as before the deadline.
        for (const start = Date.now(); ; await sleep(2000)) {
            try {
                await control('/stub/lapse', {
                    method: 'POST',
                    body: JSON.stringify({ address: p.address, ticket_id: id }),
                })
                break
            } catch (e) {
                if (Date.now() - start > 30_000) throw e
            }
        }
        await p.waitTicket(id, CONFIRM_MS, 'lapsed', closed)
        expect(BigInt(stub.payer_usdc) - (await p.usdc())).toBe(withFee(still.pending_amount!))
        await p.checkStub()
    }, ENDING_MS)
})
