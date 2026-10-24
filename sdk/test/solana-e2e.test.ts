/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The TS Client through each ending against the real zs_escrow program on a
// local validator, served by the Go stub node (go/cmd/solanastub) and checked
// through its /stub/ routes. The twin of go/internal/solanastub e2e_test.go.
// Like it, this skips unless ZS_SOLANA_E2E_RPC names the validator's endpoint
// and ZS_SOLANA_E2E_MINT_AUTHORITY the keypair file of its test USDC mint's
// authority, which is also the Config's admin.

import { type ChildProcess, execFile, spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import * as ed25519 from '@noble/ed25519'
import { encodeBase58 } from '@txnlab/zs-proto/solana'
import { FREEZE_ORIGIN_PROTEST, FREEZE_ORIGIN_SETTLE_MISMATCH } from '@txnlab/zs-proto/solana/zsescrow'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { solanaSigner } from '../src/accounts/solana.js'
import { Client, solanaLocalnet } from '../src/index.js'
import type { SettleResult } from '../src/index.js'

const RPC = process.env.ZS_SOLANA_E2E_RPC ?? ''
const AUTHORITY = process.env.ZS_SOLANA_E2E_MINT_AUTHORITY ?? ''

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
    reply: string
}

interface Behavior {
    no_receipt?: boolean
    claim_no_receipt?: boolean
    bad_body_hash?: boolean
    over_claim?: number
    ticket_lifetime_ms?: number
}

interface TicketState {
    ticket_id: string
    closed: boolean
    status?: string
    freeze_origin?: number
    deadline?: number
    pending_amount?: number
}

interface PayerState {
    usdc: number
    tickets: TicketState[]
    receipt_amounts: number[]
    errors: string[]
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
    const p = spawn(bin, ['-rpc', RPC, '-mint-authority', AUTHORITY, '-exit-on-stdin-eof'], { stdio: ['pipe', 'pipe', 'inherit'] })
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

const withFee = (amount: number) => BigInt(amount) + (BigInt(amount) * BigInt(stub.fee_bps)) / 10_000n

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** One funded payer and its own Client, so a node one scenario bars stays routable for the rest. */
class Payer {
    constructor(
        readonly address: string,
        readonly client: Client,
    ) {}

    static async create(behavior: Behavior): Promise<Payer> {
        const seed = crypto.getRandomValues(new Uint8Array(32))
        const publicKey = await ed25519.getPublicKeyAsync(seed)
        const address = encodeBase58(publicKey)
        await control('/stub/payers', { method: 'POST', body: JSON.stringify({ address, behavior }) })
        const client = await Client.create({
            solanaSigner: solanaSigner({ seed, publicKey, address }),
            network: { ...solanaLocalnet(), rpcEndpoint: RPC, program: stub.program },
            // One node can't be its own relay.
            privacy: 'direct',
            allowPrivateHosts: true,
            disableTee: true,
            discovery: { operatorIds: [stub.operator_id] },
        })
        return new Payer(address, client)
    }

    /** Runs one chat turn and waits for its settle submit. */
    async ask(stream: boolean): Promise<{ text: string; err: unknown; settled: SettleResult }> {
        const body = JSON.stringify({ model: stub.model, messages: [{ role: 'user', content: 'say hello' }], max_tokens: 64, stream })
        const s = this.client.stream({ endpoint: '/v1/chat/completions', body }, AbortSignal.timeout(120_000))
        let text = ''
        let err: unknown
        try {
            text = await s.text()
        } catch (e) {
            err = e
        }
        return { text, err, settled: await s.wait(AbortSignal.timeout(120_000)) }
    }

    async onlyTicket(): Promise<string> {
        const { tickets } = await payerState(this.address)
        expect(tickets, 'tickets the payer opened at the stub').toHaveLength(1)
        return tickets[0]!.ticket_id
    }

    /** Polls the ticket until done says it has reached the state a scenario waits for. */
    async waitTicket(id: string, withinMs: number, what: string, done: (t: TicketState) => boolean): Promise<TicketState> {
        const deadline = Date.now() + withinMs
        for (;;) {
            const t = (await payerState(this.address)).tickets.find((x) => x.ticket_id === id)!
            if (done(t)) return t
            if (Date.now() >= deadline) throw new Error(`ticket ${id}: not ${what} within ${withinMs} ms (now ${JSON.stringify(t)})`)
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
async function newPayer(b: Behavior): Promise<Payer> {
    const p = await Payer.create(b)
    payers.push(p)
    return p
}

const closed = (t: TicketState) => t.closed
// Statuses as zsescrow.TicketStatus.String spells them.
const frozen = (t: TicketState) => !t.closed && t.status === 'Frozen'

describe.skipIf(RPC === '' || AUTHORITY === '').concurrent('Solana end to end', () => {
    beforeAll(async () => {
        stub = await startStub()
    }, 300_000)

    afterAll(async () => {
        try {
            await Promise.allSettled(payers.map((p) => p.client.close()))
        } finally {
            proc?.kill()
            if (binDir) rmSync(binDir, { recursive: true, force: true })
        }
    }, 120_000)

    // The payer opens, the node serves and settles on the payer's ack, and the
    // payer pays exactly the receipt's amount.
    for (const stream of [false, true]) {
        it(`settles a ${stream ? 'streamed' : 'buffered'} turn`, async () => {
            const p = await newPayer({})
            const { text, err, settled } = await p.ask(stream)
            expect(err).toBeUndefined()
            expect(settled.err).toBeUndefined()
            expect(text).toBe(stub.reply)
            expect(settled.settlement.kind).toBe('atomic')
            expect(settled.settlement.frozen).toBeFalsy()
            await p.waitTicket(await p.onlyTicket(), 30_000, 'settled', closed)
            const { receipt_amounts } = await payerState(p.address)
            expect(receipt_amounts).toHaveLength(1)
            expect(BigInt(stub.payer_usdc) - (await p.usdc())).toBe(withFee(receipt_amounts[0]!))
            await p.checkStub()
        }, 180_000)
    }

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
    }, 300_000)

    // A receipt that doesn't hash the reply is protested at once, which freezes
    // the ticket.
    it('protests a bad receipt', async () => {
        const p = await newPayer({ bad_body_hash: true })
        const { settled } = await p.ask(false)
        expect(settled.err).toBeUndefined()
        expect(settled.settlement.kind).toBe('protest')
        expect(settled.settlement.frozen).toBe(true)
        const t = await p.waitTicket(await p.onlyTicket(), 30_000, 'frozen by the protest', frozen)
        expect(t.freeze_origin).toBe(FREEZE_ORIGIN_PROTEST)
        await p.checkStub()
    }, 180_000)

    // A node claim above the receipt, with the node refusing the ack, gets the
    // payer's own half at the receipt's figures, which freezes the ticket.
    it('freezes an over-claim', async () => {
        // Small enough that the claim and its fee stay under max_price.
        const p = await newPayer({ over_claim: 10 })
        const { err, settled } = await p.ask(false)
        expect(err).toBeUndefined()
        expect(settled.err).toBeUndefined()
        expect(settled.settlement.frozen).toBe(true)
        const t = await p.waitTicket(await p.onlyTicket(), 30_000, 'frozen by the mismatch', frozen)
        expect(t.freeze_origin).toBe(FREEZE_ORIGIN_SETTLE_MISMATCH)
        // The over-claim bars the node, so the next turn finds nowhere to go.
        expect((await p.ask(false)).err, 'a second turn at the barred node').toBeDefined()
        expect((await payerState(p.address)).tickets).toHaveLength(1)
        await p.checkStub()
    }, 180_000)

    // A claim the payer holds no receipt against is left to lapse: the payer
    // neither refunds nor freezes it, and it lapses to the node at the deadline.
    it('leaves an uncontested claim to lapse', async () => {
        const p = await newPayer({ claim_no_receipt: true, ticket_lifetime_ms: 10_000 })
        const { err } = await p.ask(false)
        expect(err, "the node's failure").toBeDefined()
        const id = await p.onlyTicket()
        const claimed = (t: TicketState) => !t.closed && t.status === 'PendingByOperator'
        const t = await p.waitTicket(id, 30_000, 'claimed', claimed)
        // Past the watchdog's first look (the deadline plus its 15 s margin) and
        // a confirm: a payer that refunded or froze the claim would have by now.
        // Its own lapse waits ten minutes, so the claim is still the node's.
        await sleep(t.deadline! * 1000 + 30_000 - Date.now())
        const still = await p.waitTicket(id, 0, "still claimed past the payer's first look", claimed)
        // The validator's clock can trail the wall clock under load, which the
        // program reads as before the deadline.
        for (const start = Date.now(); ; await sleep(2000)) {
            try {
                await control('/stub/lapse', { method: 'POST', body: JSON.stringify({ address: p.address, ticket_id: id }) })
                break
            } catch (e) {
                if (Date.now() - start > 30_000) throw e
            }
        }
        await p.waitTicket(id, 30_000, 'lapsed', closed)
        expect(BigInt(stub.payer_usdc) - (await p.usdc())).toBe(withFee(still.pending_amount!))
        await p.checkStub()
    }, 300_000)
})
