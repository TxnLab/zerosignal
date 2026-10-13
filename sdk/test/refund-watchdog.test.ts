/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The refund watchdog, porting go/zs refund_watchdog_test.go. Timings are
// shortened and the probe, refund and lapse calls faked, as Go's tests do.

import { PENDING_BY_OPERATOR, STATUS_OPEN, STATUS_PENDING_SETTLE, type TicketRecord, type Verdict } from '@txnlab/zs-proto/escrow'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { OpenHandle } from '../src/parts.js'
import { type TicketProbe, Watchdog, type WatchdogOptions, refundSources } from '../src/refund-watchdog.js'
import { recLogger } from './turn-fixtures.js'

type Probe = (signal: AbortSignal) => Promise<TicketProbe>
type Call = (signal: AbortSignal) => Promise<string>

/** Calls a test's closures made that the test forbids: Go's t.Error from inside them. */
let unexpected: string[]
beforeEach(() => {
    unexpected = []
})
afterEach(() => {
    expect(unexpected).toEqual([])
})

function testWatchdog(over: Partial<WatchdogOptions> = {}) {
    const log = recLogger()
    const rw = new Watchdog({ logger: log, remedy: 'recover it by hand', ...over })
    // Go's tests use 0, but a JS timer can wake within the deadline's own
    // millisecond, which classify still reads as wait.
    rw.marginMs = 2
    rw.retryDelayMs = 5
    rw.lapseFallbackMs = 5
    return { rw, log }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function waitFor(what: string, cond: () => boolean): Promise<void> {
    const deadline = Date.now() + 2000
    while (Date.now() < deadline) {
        if (cond()) return
        await sleep(2)
    }
    throw new Error(`timed out waiting for ${what}`)
}

// Fakes classify over a live box: "wait" until the box's own deadline
// passes and then afterwards. A static verdict could describe a state the
// contract can't hold, and the re-arm paths exist for that boundary.
function boxAt(deadlineMs: number, then: Verdict): Probe {
    return async () => ({ exists: true, verdict: Date.now() > deadlineMs ? then : 'wait', deadlineMs })
}

/** A live, unfrozen box already past its deadline: the "refund now" state. */
const liveBox = (): Probe => boxAt(Date.now() - 60_000, 'refundInactive')

/** The settleLapsed closure for a ticket that never reaches an operator claim: calling it is the failure. */
const noLapse: Call = async () => {
    unexpected.push('settleLapsed driven on a ticket with no operator-side claim')
    throw new Error('unexpected settleLapsed')
}

const noRefund: Call = async () => {
    unexpected.push('refundInactive on an operator-pending ticket')
    return ''
}

const counter = () => {
    let n = 0
    return {
        get n() {
            return n
        },
        call:
            (out: string | Error = 'TXID'): Call =>
            async () => {
                n++
                if (out instanceof Error) throw out
                return out
            },
    }
}

const untilAborted = (signal: AbortSignal) =>
    new Promise<void>((resolve) => {
        if (signal.aborted) resolve()
        signal.addEventListener('abort', () => resolve(), { once: true })
    })

function deferred() {
    let resolve!: () => void
    const promise = new Promise<void>((r) => {
        resolve = r
    })
    return { promise, resolve }
}

const within = <T>(p: Promise<T>, ms: number) =>
    Promise.race([p.then(() => true), sleep(ms).then(() => false)])

describe('RefundWatchdog', () => {
    // A hand-off mid-probe ends the probe and sends nothing: the next sweeper
    // owns the ticket the moment handOff returns.
    it('stops a probe in flight on handOff', async () => {
        const { rw } = testWatchdog()
        rw.callTimeoutMs = 3_600_000 // so only the hand-off can end the probe
        const probing = deferred()
        const refunds = counter()
        rw.arm(
            'tik',
            Date.now(),
            async (signal) => {
                probing.resolve()
                await untilAborted(signal)
                return liveBox()(signal) // a box that would be refunded, had it got this far
            },
            refunds.call(),
            noLapse,
        )
        await probing.promise
        expect(await within(rw.handOff(), 2000), 'handOff waited on a probe it should have ended').toBe(true)
        expect(refunds.n).toBe(0)
        rw.arm('late', Date.now(), liveBox(), refunds.call(), noLapse)
        await sleep(20)
        expect(refunds.n, 'a ticket armed after handOff was refunded').toBe(0)
    })

    // A refund already sent is waited for: released sooner, the next sweeper
    // would send the same refund alongside it.
    it('waits out a submit in flight on handOff', async () => {
        const { rw } = testWatchdog()
        const submitting = deferred()
        const finish = deferred()
        let submitSignal: AbortSignal | undefined
        rw.arm(
            'tik',
            Date.now(),
            liveBox(),
            async (signal) => {
                submitSignal = signal
                submitting.resolve()
                await finish.promise
                return 'TX'
            },
            noLapse,
        )
        await submitting.promise
        const handedOff = rw.handOff()
        expect(await within(handedOff, 20), 'handOff returned while a refund was still in flight').toBe(false)
        // The hand-off doesn't cut the submit short either.
        expect(submitSignal?.aborted).toBe(false)
        finish.resolve()
        expect(await within(handedOff, 2000), 'handOff never returned after the refund finished').toBe(true)
    })

    it('refunds a ticket whose box is still there past the deadline', async () => {
        const refunded: string[] = []
        const { rw, log } = testWatchdog({ refunded: (id) => refunded.push(id) })
        const refunds = counter()
        rw.arm('tik-1', Date.now() + 5, liveBox(), refunds.call('TXID'), noLapse)
        expect(rw.watching('tik-1')).toBe(true)
        await waitFor('refund attempt', () => refunds.n === 1)
        await waitFor('the run to end', () => !rw.watching('tik-1'))
        expect(refunded).toEqual(['tik-1'])
        expect(log.logged).toContainEqual({
            level: 'info',
            msg: 'refund watchdog: recovered escrowed USDC via refundInactive',
            attrs: { ticket_id: 'tik-1', txid: 'TXID' },
        })
    })

    // The refunded hook is the host's. One that throws is logged; left
    // unobserved, its rejection would end a Node process.
    it('logs a refunded hook that throws, and ends the run', async () => {
        const { rw, log } = testWatchdog({
            refunded: () => {
                throw new Error('guard bug')
            },
        })
        rw.arm('tik-1', Date.now(), liveBox(), counter().call('TXID'), noLapse)
        await waitFor('the run to end', () => !rw.watching('tik-1'))
        await rw.handOff()
        expect(log.logged).toContainEqual({
            level: 'error',
            msg: 'refund watchdog: ticket driver failed',
            attrs: { ticket_id: 'tik-1', err: 'guard bug' },
        })
    })

    // The operator settled standalone after the payer lost sight of it.
    it('does nothing when the box is already gone', async () => {
        const { rw } = testWatchdog()
        let probes = 0
        const refunds = counter()
        rw.arm(
            'tik-2',
            Date.now() + 5,
            async () => {
                probes++
                return { exists: false, verdict: 'unknown', deadlineMs: 0 }
            },
            refunds.call(),
            noLapse,
        )
        await waitFor('box probe', () => probes >= 1)
        await sleep(20)
        expect(refunds.n).toBe(0)
    })

    // refundInactive would revert on a frozen box: arbitration resolves it.
    it('leaves a frozen ticket to arbitration', async () => {
        const { rw } = testWatchdog()
        let probes = 0
        const refunds = counter()
        rw.arm(
            'tik-frozen',
            Date.now() + 5,
            async () => {
                probes++
                return { exists: true, verdict: 'arbitrate', deadlineMs: Date.now() - 60_000 }
            },
            refunds.call(),
            noLapse,
        )
        await waitFor('box probe', () => probes >= 1)
        await sleep(20)
        expect(refunds.n).toBe(0)
    })

    // A live box parked with an operator's claim, past its deadline.
    const operatorPendingBox =
        (probes: { n: number }): Probe =>
        async () => {
            probes.n++
            return { exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000 }
        }

    // The contract asserts 'ticket not refundable' on an operator's claim, so
    // a refund would burn the whole attempt budget on reverts.
    it('never refunds a ticket carrying an operator claim', async () => {
        const { rw } = testWatchdog()
        const probes = { n: 0 }
        const refunds = counter()
        rw.arm('tik-op-pending', Date.now() + 5, operatorPendingBox(probes), refunds.call(''), async () => 'TXID')
        await waitFor('box probe', () => probes.n >= 1)
        await sleep(20)
        expect(refunds.n).toBe(0)
    })

    // The node's driver finalized its claim during the fallback wait: the payer
    // must not spend a fee racing a node that did its job.
    it("defers an operator's claim to the node's own settleLapsed", async () => {
        const { rw } = testWatchdog()
        let probed = 0
        const lapses = counter()
        rw.arm(
            'tik-node-lapsed',
            Date.now() + 2,
            async () => {
                // Parked first; gone after the fallback.
                if (++probed === 1) return { exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000 }
                return { exists: false, verdict: 'unknown', deadlineMs: 0 }
            },
            noRefund,
            lapses.call(''),
        )
        await waitFor('post-fallback re-probe', () => probed >= 2)
        await sleep(20)
        expect(lapses.n).toBe(0)
    })

    // A node that never lapses (dead after its claim confirmed, ledger lost,
    // retries exhausted) would lock the payer's share for good.
    // refunded frees the SpendGuard reservation; a lapse pays the operator's
    // claim, so it must not.
    it('posts settleLapsed itself when the node stalls, without reporting a refund', async () => {
        const refunded: string[] = []
        const { rw, log } = testWatchdog({ refunded: (id) => refunded.push(id) })
        const probes = { n: 0 }
        const lapses = counter()
        rw.arm('tik-node-stalled', Date.now() + 2, operatorPendingBox(probes), noRefund, lapses.call('LAPSE'))
        await waitFor('payer-driven settleLapsed', () => lapses.n === 1)
        await waitFor('the run to end', () => !rw.watching('tik-node-stalled'))
        expect(lapses.n).toBe(1)
        expect(refunded).toEqual([])
        expect(log.logged).toContainEqual({
            level: 'info',
            msg: 'refund watchdog: finalized a stalled operator claim via settleLapsed',
            attrs: { ticket_id: 'tik-node-stalled', txid: 'LAPSE' },
        })
    })

    // The fallback wait comes before the re-read, so a node lapsing inside it
    // costs the payer nothing.
    it('waits out lapseFallbackMs before reading an operator claim again', async () => {
        const { rw } = testWatchdog()
        rw.lapseFallbackMs = 60
        const probes = { n: 0 }
        const lapses = counter()
        rw.arm('tik-fallback', Date.now(), operatorPendingBox(probes), noRefund, lapses.call())
        await waitFor('first probe', () => probes.n === 1)
        await sleep(25)
        expect([probes.n, lapses.n]).toEqual([1, 0])
        await waitFor('post-fallback settleLapsed', () => lapses.n === 1)
    })

    // An operator claim before its deadline classifies as wait, so the
    // refund loop's re-arm is what keeps settleLapsed from firing early, and
    // why the lapse loop has none of its own.
    it('re-arms an operator claim to its on-chain deadline', async () => {
        const { rw } = testWatchdog()
        const lapses = counter()
        rw.arm('tik-lapse-rearm', Date.now() + 2, boxAt(Date.now() + 60, 'settleLapsed'), noRefund, lapses.call())
        await sleep(20)
        expect(lapses.n, 'settleLapsed fired before the on-chain deadline').toBe(0)
        // Exactly one once it passes: the re-arm consumed no attempt.
        await waitFor('post-deadline settleLapsed', () => lapses.n === 1)
    })

    it('retries a failing settleLapsed to the attempt bound, then gives up', async () => {
        const { rw, log } = testWatchdog()
        const probes = { n: 0 }
        const lapses = counter()
        rw.arm('tik-lapse-fail', Date.now() + 2, operatorPendingBox(probes), noRefund, lapses.call(new Error('algod down')))
        await waitFor('all lapse retries', () => lapses.n === rw.attempts)
        await sleep(3 * rw.retryDelayMs)
        expect(lapses.n).toBe(rw.attempts)
        const giveUp = log.logged.find((l) => l.msg === 'refund watchdog: settleLapsed failed; giving up')
        expect(giveUp?.attrs).toMatchObject({
            ticket_id: 'tik-lapse-fail',
            remedy: 'recover it by hand',
            attempts: 3,
            err: 'algod down',
            probe: { verdict: 'settleLapsed' },
        })
    })

    // The box outlives the process, so the give-up line is the payer's only
    // lead. After a failed read it says so rather than print a verdict.
    it('logs the remedy and what the last read said when it gives up', async () => {
        const { rw, log } = testWatchdog()
        const refunds = counter()
        rw.arm('tik-give-up', Date.now() + 2, liveBox(), refunds.call(new Error('algod down')), noLapse)
        await waitFor('the give-up line', () => log.logged.some((l) => l.msg.includes('giving up')))
        const giveUp = log.logged.find((l) => l.msg === 'refund watchdog: refundInactive failed; giving up')
        expect(giveUp).toMatchObject({
            level: 'warn',
            attrs: { ticket_id: 'tik-give-up', remedy: 'recover it by hand', attempts: 3, err: 'algod down', probe: { verdict: 'refundInactive' } },
        })
        expect((giveUp!.attrs!.probe as { deadline: Date }).deadline).toBeInstanceOf(Date)

        const { rw: rw2, log: log2 } = testWatchdog()
        rw2.arm(
            'tik-blind',
            Date.now(),
            async () => {
                throw new Error('algod flake')
            },
            counter().call(new Error('algod down')),
            noLapse,
        )
        await waitFor('the give-up line', () => log2.logged.some((l) => l.msg.includes('giving up')))
        expect(log2.logged.find((l) => l.msg.includes('giving up'))!.attrs!.probe).toEqual({ err: 'algod flake' })
    })

    // Bindings that disagree with the deployed app: neither call is known to
    // be legal, so posting one spends fees on a probable revert.
    it('attempts nothing on a state these bindings cannot classify', async () => {
        const { rw, log } = testWatchdog()
        let probes = 0
        rw.arm(
            'tik-unknown',
            Date.now() + 2,
            async () => {
                probes++
                return { exists: true, verdict: 'unknown', deadlineMs: Date.now() - 60_000 }
            },
            async () => {
                unexpected.push('refundInactive on an unrecognized ticket state')
                return ''
            },
            noLapse,
        )
        await waitFor('box probe', () => probes >= 1)
        await sleep(3 * rw.retryDelayMs)
        expect(probes, 'an unrecognized state is terminal, not retried').toBe(1)
        expect(log.logged.at(-1)).toMatchObject({ level: 'warn', msg: expect.stringContaining('not attempting refundInactive') })
    })

    // The box can change while the lapse fallback runs: a freeze or a state
    // these bindings can't read stops the lapse as it stops the refund.
    for (const [verdict, msg] of [
        ['arbitrate', 'refund watchdog: ticket froze while awaiting settleLapsed; leaving to arbitration'],
        ['unknown', 'not attempting settleLapsed'],
    ] as const) {
        it(`posts no settleLapsed on a box that turns ${verdict} during the fallback`, async () => {
            const { rw, log } = testWatchdog()
            let probed = 0
            rw.arm(
                'tik-turned',
                Date.now(),
                async () => ({ exists: true, verdict: ++probed === 1 ? 'settleLapsed' : verdict, deadlineMs: Date.now() - 60_000 }),
                noRefund,
                noLapse,
            )
            await waitFor('the run to end', () => probed >= 2 && !rw.watching('tik-turned'))
            expect(probed).toBe(2)
            expect(log.logged.at(-1)?.msg).toEqual(expect.stringContaining(msg))
        })
    }

    // The payer's own standalone ack is a claim the operator never matched, so
    // refundInactive is exactly its deadline path.
    it("refunds a ticket carrying the payer's own claim", async () => {
        const { rw } = testWatchdog()
        const refunds = counter()
        rw.arm('tik-payer-pending', Date.now() + 2, async () => ({ exists: true, verdict: 'refundInactive', deadlineMs: Date.now() - 60_000 }), refunds.call(), noLapse)
        await waitFor('refund attempt', () => refunds.n === 1)
    })

    // track's deadline comes from the cached grace, which can have been
    // rotated: the box's own is authoritative.
    it("re-arms to the box's own deadline when track's ran early", async () => {
        const { rw } = testWatchdog()
        const refunds = counter()
        rw.arm('tik-rearm', Date.now() + 2, boxAt(Date.now() + 60, 'refundInactive'), refunds.call(), noLapse)
        await sleep(20)
        expect(refunds.n, 'refund fired before the on-chain deadline').toBe(0)
        // Exactly one once it passes: the re-arm consumed no attempt.
        await waitFor('post-deadline refund', () => refunds.n === 1)
    })

    it('pads the re-arm with the margin', async () => {
        const { rw } = testWatchdog()
        rw.marginMs = 60
        const refunds = counter()
        rw.arm('tik-margin', Date.now(), boxAt(Date.now() + 5, 'refundInactive'), refunds.call(), noLapse)
        await sleep(35)
        expect(refunds.n).toBe(0)
        await waitFor('post-margin refund', () => refunds.n === 1)
    })

    it('stops a ticket resolved before its deadline', async () => {
        const { rw } = testWatchdog()
        let touched = 0
        rw.arm(
            'tik-3',
            Date.now() + 30,
            async () => {
                touched++
                return { exists: true, verdict: 'refundInactive', deadlineMs: Date.now() - 60_000 }
            },
            async () => {
                touched++
                return ''
            },
            noLapse,
        )
        rw.resolve('tik-3')
        rw.resolve('tik-3')
        rw.resolve('never-armed')
        expect(rw.watching('tik-3')).toBe(false)
        await sleep(60)
        expect(touched).toBe(0)
    })

    // Resolve still cancels mid-retry, while the entry stays armed.
    it('stops a ticket resolved between retries', async () => {
        const { rw } = testWatchdog()
        rw.retryDelayMs = 30
        const refunds = counter()
        rw.arm('tik-mid', Date.now(), liveBox(), refunds.call(new Error('refund before deadline')), noLapse)
        await waitFor('first attempt', () => refunds.n === 1)
        expect(rw.watching('tik-mid')).toBe(true)
        rw.resolve('tik-mid')
        await sleep(60)
        expect(refunds.n).toBe(1)
    })

    it('retries a failing refund to the attempt bound, then gives up', async () => {
        const { rw } = testWatchdog()
        const refunds = counter()
        rw.arm('tik-4', Date.now() + 2, liveBox(), refunds.call(new Error('refund before deadline')), noLapse)
        await waitFor('all retries', () => refunds.n === rw.attempts)
        await sleep(3 * rw.retryDelayMs)
        expect(refunds.n).toBe(rw.attempts)
        expect(rw.watching('tik-4')).toBe(false)
    })

    // A failed read is not trusted as "box gone": a revert is cheap and the
    // error may be transient.
    it('refunds anyway when the probe fails', async () => {
        const { rw } = testWatchdog()
        const refunds = counter()
        rw.arm(
            'tik-5',
            Date.now() + 2,
            async () => {
                throw new Error('algod flake')
            },
            refunds.call(),
            noLapse,
        )
        await waitFor('refund despite probe error', () => refunds.n === 1)
    })

    // Each call gets its own budget: a slow read must not leave the submit a
    // spent deadline.
    it('bounds each probe and each submit by its own callTimeoutMs', async () => {
        const { rw } = testWatchdog()
        rw.callTimeoutMs = 30
        const elapsed: number[] = []
        const timed = (out: () => Promise<TicketProbe | string>) => async (signal: AbortSignal) => {
            const start = Date.now()
            if (signal.aborted) unexpected.push('a call started on a spent budget')
            await untilAborted(signal)
            elapsed.push(Date.now() - start)
            return out()
        }
        const refunds = counter()
        rw.arm(
            'tik-timeout',
            Date.now(),
            timed(() => Promise.reject(new Error('probe timed out'))) as Probe,
            timed(() => refunds.call('TXID')(new AbortController().signal)) as Call,
            noLapse,
        )
        await waitFor('the refund', () => refunds.n === 1)
        expect(elapsed).toHaveLength(2)
        for (const ms of elapsed) expect(ms).toBeGreaterThanOrEqual(25)
    })

    // Ticket ids are single-use, so a second arm is a no-op.
    // A re-arm costs no attempt, so the whole budget is still there for the
    // refund it was waiting for.
    it('keeps every attempt across a re-arm', async () => {
        const { rw, log } = testWatchdog()
        const refunds = counter()
        rw.arm('tik-rearm-fail', Date.now(), boxAt(Date.now() + 30, 'refundInactive'), refunds.call(new Error('algod down')), noLapse)
        await waitFor('the give-up line', () => log.logged.some((l) => l.msg.includes('giving up')))
        expect(refunds.n).toBe(rw.attempts)
        expect(log.logged.find((l) => l.msg.includes('giving up'))?.attrs).toMatchObject({ attempts: 3 })
    })

    // Back-to-back tries against an algod that just failed spend the budget
    // on one transient fault, and each settleLapsed a fee.
    for (const loop of ['refund', 'lapse'] as const) {
        it(`spaces ${loop} retries by retryDelayMs`, async () => {
            const { rw } = testWatchdog()
            rw.retryDelayMs = 40
            const at: number[] = []
            const failing: Call = async () => {
                at.push(Date.now())
                throw new Error('algod down')
            }
            if (loop === 'refund') rw.arm('tik-spaced', Date.now(), liveBox(), failing, noLapse)
            else rw.arm('tik-spaced', Date.now(), operatorPendingBox({ n: 0 }), noRefund, failing)
            await waitFor('every attempt', () => at.length === rw.attempts)
            for (let i = 1; i < at.length; i++) expect(at[i]! - at[i - 1]!).toBeGreaterThanOrEqual(35)
        })
    }

    // Go posts settleLapsed anyway when the read after the fallback fails, as
    // the refund loop refunds anyway: one algod hiccup must not abandon a
    // stalled claim.
    it('posts settleLapsed when the read after the fallback fails', async () => {
        const { rw } = testWatchdog()
        let probed = 0
        const lapses = counter()
        rw.arm(
            'tik-lapse-blind',
            Date.now(),
            async () => {
                if (++probed === 1) return { exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000 }
                throw new Error('algod flake')
            },
            noRefund,
            lapses.call(),
        )
        await waitFor('the lapse', () => lapses.n === 1)
        await waitFor('the run to end', () => !rw.watching('tik-lapse-blind'))
        expect(lapses.n).toBe(1)
    })

    // The lapse fallback runs inside the ticket's run: the sweep must read
    // the ticket as taken, and handOff must reach it.
    it("keeps watching an operator's claim through the lapse fallback", async () => {
        const { rw } = testWatchdog()
        rw.lapseFallbackMs = 60
        const probes = { n: 0 }
        const lapses = counter()
        rw.arm('tik-held', Date.now(), operatorPendingBox(probes), noRefund, lapses.call())
        await waitFor('first probe', () => probes.n === 1)
        expect(rw.watching('tik-held')).toBe(true)
        expect(await within(rw.handOff(), 30)).toBe(true)
        await sleep(100)
        expect(lapses.n).toBe(0)
    })

    // Each wait ends on cancel, so handOff never sits out a deadline, the
    // fallback or a retry delay.
    for (const [phase, setup] of [
        ['a re-arm', (rw: Watchdog, seen: () => void) => rw.arm('tik-wait', Date.now(), async () => (seen(), { exists: true, verdict: 'wait', deadlineMs: Date.now() + 60_000 }), counter().call(), noLapse)],
        ['the lapse fallback', (rw: Watchdog, seen: () => void) => {
            rw.lapseFallbackMs = 60_000
            rw.arm('tik-wait', Date.now(), async () => (seen(), { exists: true, verdict: 'settleLapsed', deadlineMs: Date.now() - 60_000 }), noRefund, counter().call())
        }],
        ['a lapse retry', (rw: Watchdog, seen: () => void) => {
            rw.retryDelayMs = 60_000
            rw.arm('tik-wait', Date.now(), operatorPendingBox({ n: 0 }), noRefund, async () => (seen(), Promise.reject(new Error('algod down'))))
        }],
    ] as const) {
        it(`ends ${phase} on handOff`, async () => {
            const { rw } = testWatchdog()
            let seen = false
            setup(rw, () => {
                seen = true
            })
            await waitFor('the wait to start', () => seen)
            await sleep(10)
            expect(await within(rw.handOff(), 200), `handOff sat out ${phase}`).toBe(true)
        })
    }

    it('runs on production timings by default', () => {
        expect(new Watchdog({ remedy: '' })).toMatchObject({
            marginMs: 15_000,
            retryDelayMs: 60_000,
            attempts: 3,
            callTimeoutMs: 30_000,
            lapseFallbackMs: 600_000,
        })
    })

    // A goroutine never holds Go's process open, and a one-shot script must
    // not sit out a ticket's deadline either.
    it('never holds the Node process open', () => {
        const spy = vi.spyOn(globalThis, 'setTimeout')
        const { rw } = testWatchdog()
        try {
            rw.arm('tik-unref', Date.now() + 60_000, liveBox(), counter().call(), noLapse)
            const handle = spy.mock.results.at(-1)?.value as NodeJS.Timeout
            expect(handle.hasRef()).toBe(false)
        } finally {
            spy.mockRestore()
            rw.resolve('tik-unref')
        }
    })

    it('arms a ticket once', async () => {
        const { rw } = testWatchdog()
        const refunds = counter()
        rw.arm('tik-dup', Date.now() + 5, liveBox(), refunds.call(), noLapse)
        rw.arm('tik-dup', Date.now(), liveBox(), refunds.call(), noLapse)
        await waitFor('refund', () => refunds.n === 1)
        await sleep(20)
        expect(refunds.n).toBe(1)
    })

    // setTimeout fires at once past ~24.8 days, which would loop box reads.
    it('waits out a deadline past the timer limit without reading the box', async () => {
        const { rw } = testWatchdog()
        let probes = 0
        rw.arm(
            'tik-far',
            Date.now() + 2 ** 32,
            async () => {
                probes++
                return { exists: true, verdict: 'wait', deadlineMs: Date.now() + 2 ** 32 }
            },
            counter().call(),
            noLapse,
        )
        await sleep(30)
        expect(probes).toBe(0)
        rw.resolve('tik-far')
    })

    // The cap is taken in steps, never as an early wake: a read before the
    // deadline that failed would send a refund the contract must revert.
    it('waits the whole of a deadline past the timer limit', async () => {
        vi.useFakeTimers()
        try {
            const { rw } = testWatchdog()
            let probes = 0
            rw.arm(
                'tik-far',
                Date.now() + 2 ** 31 + 1000,
                async () => {
                    probes++
                    throw new Error('algod down')
                },
                counter().call(),
                noLapse,
            )
            await vi.advanceTimersByTimeAsync(2 ** 31 - 1)
            expect(probes).toBe(0)
            await vi.advanceTimersByTimeAsync(1001)
            expect(probes).toBe(1)
        } finally {
            vi.useRealTimers()
        }
    })
})

describe('RefundWatchdog.track', () => {
    // Decades past the wall clock, so a deadline read off the wall instead
    // never comes.
    const T0 = 4_000_000_000_990

    /** A handle the SDK's Wallet opened, as far as track can tell: one with a refund source. */
    function walletHandle(box: () => TicketRecord | null, graceSeconds: bigint) {
        const reads: AbortSignal[] = []
        const refunds: AbortSignal[] = []
        const lapses: AbortSignal[] = []
        const h = {
            ticketId: 'TICKET',
            refundInactive: async (signal: AbortSignal) => {
                refunds.push(signal)
                return 'REFUND'
            },
            settleLapsed: async (signal: AbortSignal) => {
                lapses.push(signal)
                return 'LAPSE'
            },
        } as unknown as OpenHandle
        refundSources.set(h, {
            graceSeconds,
            readTicketBox: async (signal) => {
                reads.push(signal)
                return box()
            },
        })
        return { h, reads, refunds, lapses }
    }

    const box = (over: Partial<TicketRecord>) =>
        ({ status: STATUS_OPEN, pendingBy: 0, expiresAt: 3_999_999_998n, settlementGraceSeconds: 3n, ...over }) as TicketRecord

    // The clock runs from T0 at real speed, so the deadline arithmetic is
    // exact and the timers still fire.
    const fromT0 = () => {
        const start = Date.now()
        return () => T0 + (Date.now() - start)
    }

    // D = expires_at + grace + margin = T0 + 10 ms + 40 ms. Dropping the grace
    // fires at once, and dropping the margin at 10 ms.
    it('fires at expires_at plus the grace and the margin, then refunds through the handle', async () => {
        const refunded: string[] = []
        const { rw } = testWatchdog({ clock: fromT0(), refunded: (id) => refunded.push(id) })
        rw.marginMs = 40
        const w = walletHandle(() => box({}), 3n)
        rw.track(w.h, 3_999_999_998)
        expect(rw.watching('TICKET')).toBe(true)
        await sleep(30)
        expect(w.reads).toHaveLength(0)
        await waitFor('the refund', () => w.refunds.length === 1)
        expect(refunded).toEqual(['TICKET'])
    })

    // The grace was rotated up after the open: the box's own deadline, in
    // seconds, is the one the re-arm waits for.
    it("waits for the box's deadline when its grace outlasts the wallet's", async () => {
        const { rw } = testWatchdog({ clock: fromT0() })
        rw.marginMs = 50
        // track fires at T0 - 940 ms; the box's D + margin is T0 + 60 ms.
        const w = walletHandle(() => box({ expiresAt: 3_999_999_000n, settlementGraceSeconds: 1_001n }), 0n)
        rw.track(w.h, 3_999_999_000)
        await waitFor('the first read', () => w.reads.length === 1)
        await sleep(30)
        expect(w.refunds).toHaveLength(0)
        await waitFor('the refund', () => w.refunds.length === 1)
        // A timer can wake a millisecond before Date.now reaches its mark,
        // which costs one more re-arm.
        expect(w.reads.length).toBeGreaterThanOrEqual(2)
    })

    // The verdict reads the box against the Client's clock, not the wall.
    it("classifies the box on the watchdog's clock", async () => {
        const { rw } = testWatchdog({ clock: fromT0() })
        // Past due on the clock, and decades ahead of the wall's: read off the
        // wall, the box would wait and the stale clock would send a refund.
        const w = walletHandle(() => box({ status: STATUS_PENDING_SETTLE, pendingBy: PENDING_BY_OPERATOR, expiresAt: 3_999_999_000n }), 0n)
        rw.track(w.h, 3_999_999_000)
        await waitFor('the lapse', () => w.lapses.length === 1)
        expect(w.refunds).toHaveLength(0)
    })

    it('reads a box gone as settled', async () => {
        const { rw } = testWatchdog({ clock: fromT0() })
        const w = walletHandle(() => null, 0n)
        rw.track(w.h, 3_999_999_000)
        await waitFor('the read', () => w.reads.length === 1)
        await waitFor('the run to end', () => !rw.watching('TICKET'))
        expect([w.refunds.length, w.lapses.length]).toEqual([0, 0])
    })

    // Go's nil wallet: a caller's wallet hands back handles the watchdog
    // can't read a box for.
    it("tracks nothing for a handle the SDK's Wallet did not open", () => {
        const { rw } = testWatchdog()
        rw.track(null, 0)
        rw.track(undefined, 0)
        rw.track({ ticketId: 'x' } as OpenHandle, Math.floor(Date.now() / 1000))
        expect(rw.watching('x')).toBe(false)
    })
})
