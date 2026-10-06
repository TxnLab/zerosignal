/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Wallet against a fake chain, porting go/zs wallet_pool_test.go and
// wallet_handle_test.go. The open and settle groups are the real vectors,
// so the checks that guard the payer's signature run for real.

import { readFileSync } from 'node:fs'

import algosdk from 'algosdk'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'
import { receiptSigDigest } from '@txnlab/zs-proto/ticket'

import type { CompletedSettleGroup, SettleGroupSpec } from '../src/escrow/settle.js'

// completeSettleGroup is the real one unless a test swaps it: a vector
// group can't match an arbitrary receipt's digest, so the atomic success
// path needs a stand-in.
let completeSettle: ((b64: string, spec: SettleGroupSpec) => Promise<CompletedSettleGroup>) | undefined
vi.mock('../src/escrow/settle.js', async (importOriginal) => {
    const real = await importOriginal<typeof import('../src/escrow/settle.js')>()
    return {
        ...real,
        completeSettleGroup: (b64: string, spec: SettleGroupSpec, signer: import('../src/ports.js').Signer) =>
            completeSettle ? completeSettle(b64, spec) : real.completeSettleGroup(b64, spec, signer),
    }
})

const {
    BelowTargetError,
    MbrDepositUnaffordableError,
    OpenGroupRejectedError,
    OpenTopUpError,
    findError,
    ProtestReason,
    SettleGroupRejectedError,
    Wallet,
    completeOpenGroup,
    decodeReceiptSig,
    decodeTicketId,
    settleArgsOf,
} = await import('../src/index.js')
type EscrowChain = import('../src/index.js').EscrowChain
type Signer = import('../src/index.js').Signer
const { testOperator } = await import('./fixtures.js')

interface GroupVectors {
    open: {
        spec: {
            app_id: number
            app_address: string
            ticket_id_b64: string
            operator_id: number
            node_id: number
            max_price: number
            usdc_asset_id: number
            node_signing_addr: string
            payer_addr: string
            expires_at: number
        }
        cases: { name: string; group_b64: string }[]
    }
    settle: { cases: { name: string; group_b64: string }[] }
}
const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/escrow_group_vectors.json', import.meta.url), 'utf8'),
) as GroupVectors
const s = vectors.open.spec
const openGroup = (name: string) => vectors.open.cases.find((c) => c.name === name)!.group_b64
const settleGroup = (name: string) => vectors.settle.cases.find((c) => c.name === name)!.group_b64

const OWNER = algosdk.generateAccount().addr.toString()

const ticket = {
    ticket_id: s.ticket_id_b64,
    operator_id: s.operator_id,
    node_id: s.node_id,
    max_price: s.max_price,
    expires_at: s.expires_at,
} as Ticket
const op = testOperator({ id: s.operator_id, nodeId: s.node_id, ownerAddr: OWNER, signingAddr: s.node_signing_addr })

function payerSigner(): Signer & { calls: number[][] } {
    const calls: number[][] = []
    return {
        address: s.payer_addr,
        calls,
        signBytes: () => Promise.reject(new Error('unused')),
        signTransactions: async (txns, idx) => {
            calls.push(idx)
            return idx.map((i) =>
                algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn: txns[i]!, sig: new Uint8Array(64).fill(7) })),
            )
        },
    }
}

const MBR = 100_000n
const FULL = 10n * MBR

/** A chain whose pool and submissions a test sets and reads. */
class FakeChain implements EscrowChain {
    deposit = { algoBalance: FULL, openTickets: 0n }
    optedIn = true
    spendable = 0n
    quotaDue = 0n
    configErr: Error | undefined
    /** Each sendGroup takes the next outcome; an empty queue succeeds. */
    sendOutcomes: (Error | undefined)[] = []
    sent: Uint8Array[] = []
    deposits: { amount: bigint; optIn: boolean }[] = []
    reads = 0
    quotaReads = 0
    calls: Record<string, unknown[]> = {}
    fail: Record<string, Error> = {}

    config = async (signal?: AbortSignal) => {
        this.signals.config = signal
        if (this.configErr) throw this.configErr
        return { appId: BigInt(s.app_id), appAddress: s.app_address, usdcAssetId: BigInt(s.usdc_asset_id) }
    }
    protocolFeeBps = async (signal?: AbortSignal) => {
        this.signals.protocolFeeBps = signal
        return 250
    }
    ticketMbr = async () => MBR
    freeQuotaMbrDue = async () => {
        this.quotaReads++
        return this.quotaDue
    }
    readPayerDeposit = async () => {
        this.reads++
        return { ...this.deposit }
    }
    isPayerOptedIn = async () => this.optedIn
    spendableMicroAlgos = async () => this.spendable
    minTxnFee = async () => 1000n
    depositMbr = async (_payer: string, amount: bigint, optIn: boolean) => {
        this.deposits.push({ amount, optIn })
        this.deposit.algoBalance += amount
        this.spendable -= amount
        return 'DEPOSIT'
    }
    sendGroup = async (signed: Uint8Array, signal?: AbortSignal) => {
        this.signals.sendGroup = signal
        this.sent.push(signed)
        const e = this.sendOutcomes.shift()
        if (e) throw e
    }
    signals: Record<string, AbortSignal | undefined> = {}
    #record = <T>(name: string, arg: unknown, out: T, signal?: AbortSignal): Promise<T> => {
        ;(this.calls[name] ??= []).push(arg)
        this.signals[name] = signal
        const e = this.fail[name]
        return e ? Promise.reject(e) : Promise.resolve(out)
    }
    settleStandalone = (c: unknown, signal?: AbortSignal) =>
        this.#record('settleStandalone', c, { txid: 'STANDALONE', payerFeeMicroalgos: 5000n }, signal)
    protest = (c: unknown, signal?: AbortSignal) => this.#record('protest', c, { txId: 'PROTEST', feeMicroalgos: 2000 }, signal)
    refundInactive = (c: unknown, signal?: AbortSignal) => this.#record('refundInactive', c, 'REFUND', signal)
    settleLapsed = (c: unknown, signal?: AbortSignal) => this.#record('settleLapsed', c, 'LAPSE', signal)
    withdrawMbr = (payer: string, amount: bigint, signal?: AbortSignal) =>
        this.#record('withdrawMbr', [payer, amount], 'WITHDRAW', signal)
    closeDeposit = (payer: string, signal?: AbortSignal) => this.#record('closeDeposit', payer, 'CLOSE', signal)
}

class SendRevert extends Error {}

function deferred<T = void>() {
    let resolve!: (v: T) => void
    const promise = new Promise<T>((r) => {
        resolve = r
    })
    return { promise, resolve }
}

let chain: FakeChain
let signer: ReturnType<typeof payerSigner>
let wallet: InstanceType<typeof Wallet>

beforeEach(() => {
    chain = new FakeChain()
    signer = payerSigner()
    wallet = new Wallet({ chain, signer })
    completeSettle = undefined
})

const causes = (err: unknown): unknown[] => {
    const out: unknown[] = []
    for (let e: unknown = err; e !== undefined; e = e instanceof Error ? e.cause : undefined) out.push(e)
    return out
}

describe('Wallet.open', () => {
    it('submits the payer-signed group and hands back its ids', async () => {
        const want = await completeOpenGroup(openGroup('valid'), {
            appId: BigInt(s.app_id),
            appAddress: s.app_address,
            ticketIdRaw: decodeTicketId(s.ticket_id_b64),
            operatorId: BigInt(s.operator_id),
            nodeId: BigInt(s.node_id),
            maxPrice: BigInt(s.max_price),
            usdcAssetId: BigInt(s.usdc_asset_id),
            nodeSigningAddr: s.node_signing_addr,
            payerAddr: s.payer_addr,
            expiresAt: BigInt(s.expires_at),
            settlementGraceSeconds: 0n,
        }, payerSigner())
        const h = await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.sent).toEqual([want.signedGroup])
        expect(signer.calls).toEqual([[0]])
        expect(h).toMatchObject({
            appCallTxId: want.txids[1],
            groupId: want.groupId,
            ticketId: s.ticket_id_b64,
            operator: op,
            maxPrice: s.max_price,
            openFeesMicroalgos: 0,
            signedGroup: want.signedGroup,
        })
        expect(chain.deposits).toEqual([])
    })

    // The group is checked against the operator's chain key, not its own
    // claims: a node signing as another key gets no payer signature.
    it("refuses a group the operator's signing key did not sign, before the payer signs", async () => {
        const other = { ...op, signingAddr: OWNER }
        const err = await wallet.open(ticket, other, openGroup('valid')).catch((e: unknown) => e)
        expect(findError(err, OpenGroupRejectedError)).toBeDefined()
        expect(String(err)).toMatch(/^Error: wallet: submit presigned open group: escrow: /)
        expect(signer.calls).toEqual([])
        expect(chain.sent).toEqual([])
    })

    // In Go the group is checked inside the submit, so a refused group takes
    // the pool re-check like any other failed submit, and is checked again on
    // the retry: a top-up never gets a refused group signed.
    it('re-checks the pool after a refused group, and re-checks the group on the retry', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        signer.calls.length = 0
        const err = await wallet.open(ticket, { ...op, signingAddr: OWNER }, openGroup('valid')).catch((e: unknown) => e)
        expect(chain.deposits).toEqual([{ amount: FULL, optIn: false }])
        expect(findError(err, OpenGroupRejectedError)).toBeDefined()
        expect(signer.calls).toEqual([])
        expect(chain.sent).toHaveLength(1)
    })

    it('refuses a malformed signing address before touching the pool', async () => {
        await expect(wallet.open(ticket, { ...op, signingAddr: 'NOTANADDRESS' }, openGroup('valid'))).rejects.toThrow(
            /wallet: decode node signing addr/,
        )
        expect(chain.reads).toBe(0)
    })

    it('refuses a malformed payer address before touching the pool', async () => {
        wallet = new Wallet({ chain, signer: { ...signer, address: 'NOTANADDRESS' } })
        await expect(wallet.open(ticket, op, openGroup('valid'))).rejects.toThrow(/wallet: decode payer addr/)
        expect(chain.reads).toBe(0)
    })

    it("names the escrow config's failure", async () => {
        chain.configErr = new Error('no globals')
        await expect(wallet.open(ticket, op, openGroup('valid'))).rejects.toThrow('wallet: escrow config: no globals')
        expect(chain.reads).toBe(0)
    })

    it('pins the grace to 0, refusing a node-chosen window', async () => {
        const group = vectors.open.cases.find((c) => c.name.includes('grace'))
        expect(group, 'a grace case in the open vectors').toBeDefined()
        await expect(wallet.open(ticket, op, group!.group_b64)).rejects.toThrow()
        expect(chain.sent).toEqual([])
    })

    it('refuses incomplete inputs before touching the chain', async () => {
        await expect(wallet.open(ticket, { ...op, id: 0 }, openGroup('valid'))).rejects.toThrow(/operator id is unset/)
        await expect(wallet.open(ticket, { ...op, ownerAddr: '' }, openGroup('valid'))).rejects.toThrow(/addresses incomplete/)
        await expect(wallet.open(ticket, { ...op, signingAddr: '' }, openGroup('valid'))).rejects.toThrow(/addresses incomplete/)
        await expect(wallet.open(ticket, op, '')).rejects.toThrow(/presignedOpenGroup is empty/)
        await expect(wallet.open({ ...ticket, ticket_id: 'AAAA' }, op, openGroup('valid'))).rejects.toThrow(/decode ticket id/)
        expect(chain.reads).toBe(0)
        expect(chain.sent).toEqual([])
    })

    it('stops on an aborted signal before submitting', async () => {
        const ac = new AbortController()
        ac.abort()
        await expect(wallet.open(ticket, op, openGroup('valid'), ac.signal)).rejects.toBe(ac.signal.reason)
        expect('config' in chain.signals).toBe(false)
        expect(chain.sent).toEqual([])
    })

    it('reads the pool once it covers the working set, then no more', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.reads).toBe(1)
    })

    it('funds an empty pool before the open', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.optedIn = false
        chain.spendable = 10n * FULL
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.deposits).toEqual([{ amount: FULL, optIn: true }])
        expect(chain.sent).toHaveLength(1)
    })

    it('funds the configured working set', async () => {
        wallet = new Wallet({ chain, signer, depositSlots: 3 })
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.deposits).toEqual([{ amount: 3n * MBR, optIn: false }])
    })

    // TestOpen_UnaffordableTopUp_ProceedsOnFreeSlot
    it('serves from a free slot when the top-up is unaffordable, without latching', async () => {
        chain.deposit = { algoBalance: 2n * MBR, openTickets: 1n }
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.sent).toHaveLength(1)
        await wallet.open(ticket, op, openGroup('valid'))
        // Not latched: the second open read the pool again.
        expect(chain.reads).toBeGreaterThan(2)
    })

    // TestOpen_UnaffordableTopUp_ZeroFreeSlots_Fatal
    it('refuses when the pool has no free slot and no top-up is affordable', async () => {
        chain.deposit = { algoBalance: MBR, openTickets: 1n }
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(causes(err).some((e) => e instanceof MbrDepositUnaffordableError)).toBe(true)
        expect(String(err)).toMatch(/ensure MBR deposit/)
        expect(chain.sent).toEqual([])
    })

    it('serves from a below-target deposit with a free slot, without latching', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = MBR + 2000n
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.deposits).toEqual([{ amount: MBR, optIn: false }])
        chain.spendable = 0n
        const reads = chain.reads
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.reads).toBeGreaterThan(reads)
    })

    it('refuses a below-target deposit that leaves no free slot', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 1n }
        chain.spendable = MBR + 2000n
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(causes(err).some((e) => e instanceof BelowTargetError)).toBe(true)
        expect(findError(err, BelowTargetError)!.deposited).toBe(MBR)
        expect(chain.sent).toEqual([])
    })

    // A pool that can't be read after an unaffordable top-up proves no free
    // slot, so the open is refused rather than sent against a full pool.
    it('refuses an unaffordable top-up when the free slots cannot be read', async () => {
        chain.deposit = { algoBalance: 2n * MBR, openTickets: 1n }
        const read = chain.readPayerDeposit
        chain.readPayerDeposit = async () => {
            if (chain.reads > 0) throw new Error('algod down')
            return read()
        }
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(findError(err, MbrDepositUnaffordableError)).toBeDefined()
        expect(chain.sent).toEqual([])
    })

    it('fails on a pool read error', async () => {
        chain.readPayerDeposit = async () => {
            throw new Error('algod down')
        }
        await expect(wallet.open(ticket, op, openGroup('valid'))).rejects.toThrow(/ensure MBR deposit: algod down/)
    })

    // Only a top-up the payer can't afford may be served from a free slot;
    // any other funding failure stays fatal, as in Go.
    it('refuses on a funding failure other than affordability, even with free slots', async () => {
        chain.deposit = { algoBalance: 3n * MBR, openTickets: 0n }
        chain.spendable = 10n * FULL
        chain.isPayerOptedIn = async () => {
            throw new Error('account read failed')
        }
        await expect(wallet.open(ticket, op, openGroup('valid'))).rejects.toThrow(/ensure MBR deposit: account read failed/)
        chain.isPayerOptedIn = async () => true
        chain.depositMbr = async () => {
            throw new Error('overspend')
        }
        await expect(wallet.open(ticket, op, openGroup('valid'))).rejects.toThrow(/ensure MBR deposit: overspend/)
        expect(chain.sent).toEqual([])
    })

    it('stops before submitting when the signal aborts during the deposit', async () => {
        const ac = new AbortController()
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        const deposit = chain.depositMbr
        chain.depositMbr = async (...args) => {
            ac.abort()
            return deposit(...args)
        }
        await expect(wallet.open(ticket, op, openGroup('valid'), ac.signal)).rejects.toThrow()
        expect(chain.deposits).toHaveLength(1)
        expect(chain.sent).toEqual([])
        expect(signer.calls).toEqual([])
    })

    // A hung pass holds the lock. A waiter whose request is cancelled gives
    // up at once, but the one behind it still waits for the pass ahead.
    it('lets a waiter abort without releasing the lock to the next', async () => {
        const gate = deferred()
        const read = chain.readPayerDeposit
        let reads = 0
        chain.readPayerDeposit = async () => {
            reads++
            await gate.promise
            return read()
        }
        const first = wallet.open(ticket, op, openGroup('valid'))
        const ac = new AbortController()
        const second = wallet.open(ticket, op, openGroup('valid'), ac.signal)
        const third = wallet.open(ticket, op, openGroup('valid'))
        // All three past the config read and queued on the lock, the first
        // holding it inside the pool read.
        await new Promise((r) => setTimeout(r, 0))
        expect(reads).toBe(1)
        ac.abort(new Error('cancelled'))
        await expect(second).rejects.toThrow(/cancelled/)
        await new Promise((r) => setTimeout(r, 10))
        expect(reads).toBe(1)
        gate.resolve()
        await first
        await third
        expect(chain.sent).toHaveLength(2)
    })

    // TestOpen_DepositRevert_RetryFiresWhenTopUpDeposits
    it('tops up and sends the same group once more when an open reverts on a drained pool', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        chain.sendOutcomes = [new Error('insufficient MBR deposit')]
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.deposits).toEqual([{ amount: FULL, optIn: false }])
        expect(chain.sent).toHaveLength(3)
        expect(chain.sent[2]).toEqual(chain.sent[1])
    })

    it('tops the retry up to the configured working set', async () => {
        wallet = new Wallet({ chain, signer, depositSlots: 3 })
        chain.deposit = { algoBalance: 3n * MBR, openTickets: 0n }
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit')]
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.deposits).toEqual([{ amount: 3n * MBR, optIn: false }])
    })

    // After a top-up, the retry's own failure is what the payer sees, not
    // the revert the top-up answered.
    it("reports the retry's failure after a full top-up", async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit'), new Error('second')]
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(String(err)).toBe('Error: wallet: submit presigned open group: second')
    })

    it('does not sign the retry when the request was cancelled during its top-up', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit')]
        const ac = new AbortController()
        const deposit = chain.depositMbr
        chain.depositMbr = async (...args) => {
            ac.abort()
            return deposit(...args)
        }
        signer.calls.length = 0
        await expect(wallet.open(ticket, op, openGroup('valid'), ac.signal)).rejects.toThrow()
        expect(chain.deposits).toHaveLength(1)
        expect(signer.calls).toEqual([[0]])
        expect(chain.sent).toHaveLength(2)
    })

    it('serializes the top-ups of concurrent reverted opens into one deposit', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        chain.sendOutcomes = [new SendRevert('a'), new SendRevert('b')]
        await Promise.allSettled([1, 2].map(() => wallet.open(ticket, op, openGroup('valid'))))
        expect(chain.deposits).toHaveLength(1)
    })

    // TestOpen_DepositRevert_NoTopUpSurfacesOriginal
    it('surfaces the revert alone when the pool already covers the working set', async () => {
        chain.sendOutcomes = [new Error('pool exhausted')]
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(String(err)).toBe('Error: wallet: submit presigned open group: pool exhausted')
        expect(chain.sent).toHaveLength(1)
    })

    // TestOpen_DepositRevert_TopUpFailureRidesAlong: both stay typed, since
    // the top-up's is what tells an underfunded payer from an exhausted pool.
    it("keeps the top-up's failure and the revert both reachable, without retrying", async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit')]
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(String(err)).toMatch(/submit presigned open group: insufficient MBR deposit; topping up the ticket pool: insufficient ALGO/)
        expect(findError(err, MbrDepositUnaffordableError)).toBeDefined()
        expect(findError(err, SendRevert)).toBeDefined()
        expect(findError(err, OpenTopUpError)!.cause).toBeInstanceOf(SendRevert)
        expect(chain.sent).toHaveLength(2)
    })

    // The re-ensure dropped the latch and couldn't restore it, so the next
    // open must try the pool again rather than trust the stale latch.
    it('leaves the latch down after a failed re-ensure', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 2n * MBR, openTickets: 1n }
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit')]
        await wallet.open(ticket, op, openGroup('valid')).catch(() => {})
        const reads = chain.reads
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.reads).toBeGreaterThan(reads)
    })

    it('retries after a below-target top-up and reports the shortfall if it fails again', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = MBR + 2000n
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit'), new SendRevert('still reverting')]
        const err = await wallet.open(ticket, op, openGroup('valid')).catch((e: unknown) => e)
        expect(chain.sent).toHaveLength(3)
        expect(String(err)).toMatch(/still reverting; topping up the ticket pool: .*below the configured working set/)
        expect(findError(err, BelowTargetError)!.deposited).toBe(MBR)
    })

    it('does not latch after a below-target top-up whose retry succeeds', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = MBR + 2000n
        chain.sendOutcomes = [new SendRevert('insufficient MBR deposit')]
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.sent).toHaveLength(3)
        const reads = chain.reads
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.reads).toBeGreaterThan(reads)
    })

    it('re-reads the pool after a revert, even with the latch set', async () => {
        await wallet.open(ticket, op, openGroup('valid'))
        chain.sendOutcomes = [new Error('revert')]
        await wallet.open(ticket, op, openGroup('valid')).catch(() => {})
        expect(chain.reads).toBe(2)
        // The re-check found the pool covered, so the latch holds again.
        await wallet.open(ticket, op, openGroup('valid'))
        expect(chain.reads).toBe(2)
    })

    // TestWallet_QuotaBoxExistenceIsLatched / AbsenceIsNotLatched
    it('latches the free-quota box once it exists, never its absence', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 0n
        chain.quotaDue = 50_000n
        await wallet.ensureDeposit().catch(() => {})
        await wallet.ensureDeposit().catch(() => {})
        expect(chain.quotaReads).toBe(2)
        chain.quotaDue = 0n
        await wallet.ensureDeposit().catch(() => {})
        await wallet.ensureDeposit().catch(() => {})
        expect(chain.quotaReads).toBe(3)
    })

    it('serializes concurrent first opens into one deposit', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        await Promise.all([1, 2, 3].map(() => wallet.open(ticket, op, openGroup('valid'))))
        expect(chain.deposits).toHaveLength(1)
    })

    it('serializes an explicit ensureDeposit with an open', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        await Promise.all([wallet.ensureDeposit(), wallet.open(ticket, op, openGroup('valid'))])
        expect(chain.deposits).toHaveLength(1)
    })
})

describe('Wallet deposit operations', () => {
    it('funds the default working set for 0, as Go does', async () => {
        wallet = new Wallet({ chain, signer, depositSlots: 3 })
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        await wallet.ensureDeposit()
        expect(chain.deposits).toEqual([{ amount: FULL, optIn: false }])
        await wallet.ensureDeposit(12)
        expect(chain.deposits[1]).toEqual({ amount: 2n * MBR, optIn: false })
    })

    it('funds a single slot when asked for one', async () => {
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        await wallet.ensureDeposit(1)
        expect(chain.deposits).toEqual([{ amount: MBR, optIn: false }])
    })

    it('reads a slot count that is not a positive number as the default', async () => {
        wallet = new Wallet({ chain, signer, depositSlots: Number.NaN })
        chain.deposit = { algoBalance: 0n, openTickets: 0n }
        chain.spendable = 10n * FULL
        await wallet.ensureDeposit(Number.POSITIVE_INFINITY)
        expect(chain.deposits).toEqual([{ amount: FULL, optIn: false }])
    })

    it('withdraws and closes as the payer', async () => {
        expect(await wallet.withdrawDeposit(5n)).toBe('WITHDRAW')
        expect(await wallet.closeDeposit()).toBe('CLOSE')
        expect(chain.calls.withdrawMbr).toEqual([[s.payer_addr, 5n]])
        expect(chain.calls.closeDeposit).toEqual([s.payer_addr])
        chain.fail.closeDeposit = new Error('tickets live')
        await expect(wallet.closeDeposit()).rejects.toThrow('wallet: close-deposit: tickets live')
    })

    it('names its payer and reads the fee rate', async () => {
        expect(wallet.payerAddr()).toBe(s.payer_addr)
        expect(await wallet.protocolFeeBps()).toBe(250)
    })
})

const receipt: UsageReceipt = {
    ticket_id: s.ticket_id_b64,
    actual_input_count: 250,
    actual_output_count: 750,
    amount_charged: 3030,
    ttft_ms: 1200,
    decode_ms: 300,
    body_hash: '0'.repeat(64),
    input_usage_type: 0,
    output_usage_type: 1,
    aux_output_usage_type: 2,
    aux_output_count: 1,
    cached_input_count: 0,
    sig: algosdk.bytesToBase64(new Uint8Array(64).fill(5)),
} as UsageReceipt

describe('OpenHandle', () => {
    const open = () => wallet.open(ticket, op, openGroup('valid'))
    const standaloneCall = {
        ticketIdRaw: decodeTicketId(s.ticket_id_b64),
        args: settleArgsOf(receipt),
        maxPrice: BigInt(s.max_price),
        payer: s.payer_addr,
        operatorOwnerAddr: OWNER,
        operatorId: BigInt(s.operator_id),
        nodeId: BigInt(s.node_id),
    }

    it('acks standalone when the node sent no group', async () => {
        const r = await (await open()).ackSettle(receipt, null)
        expect(r).toEqual({ txid: 'STANDALONE', feeMicroalgos: 5000, groupRejected: false })
        expect(chain.calls.settleStandalone).toEqual([standaloneCall])
    })

    it('reads an empty group as none', async () => {
        const r = await (await open()).ackSettle(receipt, '')
        expect(r).toEqual({ txid: 'STANDALONE', feeMicroalgos: 5000, groupRejected: false })
    })

    it("passes the request's signal to each chain call", async () => {
        const signal = new AbortController().signal
        await wallet.open(ticket, op, openGroup('valid'), signal)
        for (const name of ['config', 'sendGroup']) expect(chain.signals[name], `open ${name}`).toBe(signal)

        completeSettle = async () => ({ signedGroup: new Uint8Array([9]), txid: 'ATOMIC', groupId: 'G', feeMicroalgos: 0n, payerFeeMicroalgos: 0n })
        const atomic = await open()
        chain.signals = {}
        await atomic.ackSettle(receipt, 'GROUP', signal)
        for (const name of ['config', 'sendGroup']) expect(chain.signals[name], `atomic ack ${name}`).toBe(signal)

        const h = await open()
        await h.ackSettle(receipt, null, signal)
        await h.protest(receipt, new Uint8Array(), ProtestReason.bodyHash, signal)
        await h.refundInactive(signal)
        await h.settleLapsed(signal)
        await wallet.withdrawDeposit(1n, signal)
        await wallet.closeDeposit(signal)
        await wallet.protocolFeeBps(signal)
        for (const name of ['settleStandalone', 'protest', 'refundInactive', 'settleLapsed', 'withdrawMbr', 'closeDeposit', 'protocolFeeBps']) {
            expect(chain.signals[name], name).toBe(signal)
        }
    })

    it('settles through the node group when it passes', async () => {
        let seen: SettleGroupSpec | undefined
        completeSettle = async (_b64, spec) => {
            seen = spec
            return { signedGroup: new Uint8Array([9]), txid: 'ATOMIC', groupId: 'G', feeMicroalgos: 7000n, payerFeeMicroalgos: 0n }
        }
        const r = await (await open()).ackSettle(receipt, 'GROUP')
        expect(r).toEqual({ txid: 'ATOMIC', feeMicroalgos: 0, groupRejected: false })
        expect(chain.sent.at(-1)).toEqual(new Uint8Array([9]))
        expect(chain.calls.settleStandalone).toBeUndefined()
        expect(seen).toMatchObject({
            appId: BigInt(s.app_id),
            ticketIdRaw: decodeTicketId(s.ticket_id_b64),
            payerAddr: s.payer_addr,
            operatorSigningAddr: s.node_signing_addr,
            receiptDigest: receiptSigDigest(receipt),
            amountCharged: 3030n,
        })
    })

    // A vector group can't match this receipt's digest: the real verifier
    // refuses it, which is the node contradicting its own receipt.
    it('falls back to standalone and reports a group the checks refuse', async () => {
        const r = await (await open()).ackSettle(receipt, settleGroup('valid'))
        expect(r.groupRejected).toBe(true)
        expect(r.rejection).toBeInstanceOf(SettleGroupRejectedError)
        expect(r.txid).toBe('STANDALONE')
        expect(chain.calls.settleStandalone).toEqual([standaloneCall])
    })

    it('keeps groupRejected when the standalone fallback fails too', async () => {
        chain.fail.settleStandalone = new Error('algod down')
        const r = await (await open()).ackSettle(receipt, settleGroup('valid'))
        expect(r).toMatchObject({ groupRejected: true, txid: '' })
        expect(String(r.err)).toMatch(/algod down/)
    })

    it('surfaces a failed submit of a passing group without settling standalone at the payer\'s expense', async () => {
        completeSettle = async () => ({ signedGroup: new Uint8Array([9]), txid: 'ATOMIC', groupId: 'G', feeMicroalgos: 0n, payerFeeMicroalgos: 0n })
        const h = await open()
        chain.sendOutcomes = [new Error('pool eval')]
        const r = await h.ackSettle(receipt, 'GROUP')
        expect(r).toMatchObject({ groupRejected: false, txid: '' })
        expect(String(r.err)).toMatch(/pool eval/)
        expect(chain.calls.settleStandalone).toBeUndefined()
    })

    it("goes standalone without blaming the node when the payer's spec can't be built", async () => {
        const h = await open()
        chain.configErr = new Error('no config')
        const r = await h.ackSettle(receipt, settleGroup('valid'))
        expect(r).toMatchObject({ groupRejected: false, txid: 'STANDALONE' })
    })

    it('protests with the receipt digest and its decoded signature', async () => {
        const excerpt = new Uint8Array([1, 2, 3])
        const r = await (await open()).protest(receipt, excerpt, ProtestReason.bodyHash)
        expect(r).toEqual({ txId: 'PROTEST', feeMicroalgos: 2000 })
        expect(chain.calls.protest).toEqual([
            {
                ticketIdRaw: decodeTicketId(s.ticket_id_b64),
                amountCharged: 3030n,
                receiptDigest: receiptSigDigest(receipt),
                receiptSig: new Uint8Array(64).fill(5),
                disputeExcerpt: excerpt,
                reason: 1,
                operatorId: BigInt(s.operator_id),
                nodeId: BigInt(s.node_id),
                payer: s.payer_addr,
            },
        ])
    })

    it('refuses to protest on an undecodable receipt signature', async () => {
        const h = await open()
        await expect(h.protest({ ...receipt, sig: 'AAAA' }, new Uint8Array(), ProtestReason.bodyHash)).rejects.toThrow(
            /wallet: protest: receipt sig length 3/,
        )
        const { sig: _sig, ...unsigned } = receipt
        await expect(h.protest(unsigned, new Uint8Array(), ProtestReason.bodyHash)).rejects.toThrow(
            /wallet: protest/,
        )
        expect(chain.calls.protest).toBeUndefined()
    })

    it('refunds and lapses as the payer, for the dispatched node', async () => {
        const h = await open()
        expect(await h.refundInactive()).toBe('REFUND')
        expect(await h.settleLapsed()).toBe('LAPSE')
        const ids = { ticketIdRaw: decodeTicketId(s.ticket_id_b64), operatorId: BigInt(s.operator_id), nodeId: BigInt(s.node_id) }
        expect(chain.calls.refundInactive).toEqual([{ ...ids, payer: s.payer_addr }])
        expect(chain.calls.settleLapsed).toEqual([{ ...ids, operatorOwnerAddr: OWNER, payer: s.payer_addr }])
        chain.fail.refundInactive = new Error('not yet')
        await expect(h.refundInactive()).rejects.toThrow('wallet: refund-inactive: not yet')
    })
})

// TestDecodeTicketID_Boundaries / TestDecodeReceiptSig_Boundaries
describe('decoders', () => {
    const b64 = (n: number) => algosdk.bytesToBase64(new Uint8Array(n).fill(1))

    it('takes exactly 16 bytes of ticket id', () => {
        expect(decodeTicketId(b64(16))).toEqual(new Uint8Array(16).fill(1))
        expect(() => decodeTicketId('')).toThrow(/empty/)
        expect(() => decodeTicketId(b64(15))).toThrow(/15 bytes, want 16/)
        expect(() => decodeTicketId(b64(17))).toThrow(/17 bytes, want 16/)
        expect(() => decodeTicketId('not base64!')).toThrow(/base64/)
    })

    it('takes exactly 64 bytes of receipt signature', () => {
        expect(decodeReceiptSig(b64(64))).toEqual(new Uint8Array(64).fill(1))
        expect(() => decodeReceiptSig(b64(63))).toThrow(/63, want 64/)
        expect(() => decodeReceiptSig(b64(65))).toThrow(/65, want 64/)
        expect(() => decodeReceiptSig('%%')).toThrow(/base64/)
    })
})
