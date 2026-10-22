/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Waiting for a sent transaction to land, the twin of go/solana/rpc
// confirm.go: a signatureSubscribe watch when there is a socket, a
// getSignatureStatuses poll when there isn't or it drops, and the block
// height deciding when the transaction can no longer land.

import type { SignatureResult, SignatureSubscription, SolanaPubSub } from './pubsub.js'
import type { Commitment, SignatureStatus, SolanaRpc } from './rpc.js'

/**
 * A transaction that can never land: the cluster has confirmed a block past
 * its blockhash's lastValidBlockHeight, and it has no status. Anything else, a
 * missing status included, may still land. Go's rpc.ErrExpired.
 */
export class TransactionExpiredError extends Error {
    override readonly name = 'TransactionExpiredError'

    constructor(readonly signature: string) {
        super(`solana rpc: transaction ${signature} expired without landing`)
    }
}

/**
 * The wait between status polls once no watch is armed. Each poll is a
 * request against the endpoint's rate limit, where a watch costs none, so it
 * is slow; the watch is the fast path.
 */
export const DEFAULT_CONFIRM_POLL_MS = 2_000
/**
 * The wait between block-height reads while a watch is armed: the watch says
 * when the transaction lands, the height when it can no longer.
 */
export const DEFAULT_CONFIRM_HEIGHT_CHECK_MS = 5_000

export interface ConfirmOptions {
    /** Watches the signature. Absent, or a watch that fails, isn't armed within heightCheckMs, or whose socket drops, polls instead. */
    pubsub?: SolanaPubSub | undefined
    pollMs?: number | undefined
    heightCheckMs?: number | undefined
    signal?: AbortSignal | undefined
}

/**
 * confirmSignature waits until signature reaches commitment and resolves to how
 * it landed: err set is a transaction that landed and failed. It throws
 * TransactionExpiredError once the transaction can no longer land
 * (lastValidBlockHeight is its blockhash's), and the signal's reason when it
 * aborts first. commitment absent waits for finalized, the RPC's default.
 */
export async function confirmSignature(
    rpc: SolanaRpc,
    signature: string,
    lastValidBlockHeight: bigint,
    commitment: Commitment | undefined,
    o: ConfirmOptions = {},
): Promise<SignatureResult> {
    const cm = commitment ?? 'finalized'
    const poll = o.pollMs !== undefined && o.pollMs > 0 ? o.pollMs : DEFAULT_CONFIRM_POLL_MS
    const heightCheck = o.heightCheckMs !== undefined && o.heightCheckMs > 0 ? o.heightCheckMs : DEFAULT_CONFIRM_HEIGHT_CHECK_MS
    const signal = o.signal
    let sub: SignatureSubscription | undefined
    if (o.pubsub !== undefined) {
        // Bounded, so a socket that stays open and never answers the subscribe
        // costs one height check before polling, not the caller's whole wait.
        const armBy = AbortSignal.timeout(heightCheck)
        try {
            sub = await o.pubsub.signatureSubscribe(signature, {
                commitment: cm,
                signal: signal === undefined ? armBy : AbortSignal.any([signal, armBy]),
            })
        } catch {
            if (signal?.aborted) throw signal.reason
        }
    }
    try {
        // One status read even with a watch armed: the transaction may have
        // reached the commitment before the watch did.
        let checkStatus = true
        for (;;) {
            const r = await confirmStep(rpc, signature, lastValidBlockHeight, cm, checkStatus, signal)
            if (r !== undefined) return r
            const woke = await wait(sub === undefined ? poll : heightCheck, sub, signal)
            if (woke.kind === 'watch') return woke.result
            if (woke.kind === 'dropped') {
                // The socket dropped: poll from here.
                sub = undefined
                checkStatus = true
            } else {
                checkStatus = sub === undefined
            }
        }
    } finally {
        sub?.unsubscribe()
    }
}

type Woke = { kind: 'timer' } | { kind: 'watch'; result: SignatureResult } | { kind: 'dropped' }

function wait(ms: number, sub: SignatureSubscription | undefined, signal: AbortSignal | undefined): Promise<Woke> {
    return new Promise<Woke>((resolve, reject) => {
        if (signal?.aborted) return reject(signal.reason)
        const done = (f: () => void) => {
            clearTimeout(timer)
            signal?.removeEventListener('abort', onAbort)
            f()
        }
        const onAbort = () => done(() => reject(signal!.reason))
        const timer = setTimeout(() => done(() => resolve({ kind: 'timer' })), ms)
        signal?.addEventListener('abort', onAbort, { once: true })
        sub?.result.then(
            (result) => done(() => resolve({ kind: 'watch', result })),
            () => done(() => resolve({ kind: 'dropped' })),
        )
    })
}

// Reads the status when checkStatus is set, and the block height whenever no
// status settles it. Resolves to a result, undefined to wait, or throws the
// expiry.
async function confirmStep(
    rpc: SolanaRpc,
    signature: string,
    lastValid: bigint,
    cm: Commitment,
    checkStatus: boolean,
    signal: AbortSignal | undefined,
): Promise<SignatureResult | undefined> {
    const status = async () => {
        const s = await rpc.getSignatureStatuses([signature], { signal })
        if (s.length !== 1) throw new Error(`solana rpc: ${s.length} statuses for one signature`)
        return s[0] ?? null
    }
    if (checkStatus) {
        const s = await status()
        if (s !== null) {
            if (reached(s, cm)) return { slot: s.slot, err: s.err }
            // Landed, not yet at the commitment: no height read while it
            // stands. A fork that drops it brings back no status, and the
            // height rule.
            return undefined
        }
    }
    const h = await rpc.getBlockHeight({ commitment: 'confirmed', signal })
    if (h <= lastValid) return undefined
    // Past the height: one last read decides, since it may have landed since
    // the status read, or no status was read.
    const s = await status()
    if (s === null) throw new TransactionExpiredError(signature)
    return reached(s, cm) ? { slot: s.slot, err: s.err } : undefined
}

const RANK: Record<Commitment, number> = { processed: 1, confirmed: 2, finalized: 3 }

/**
 * Whether a status is at c or beyond. A status without a confirmationStatus
 * is an older RPC's: finalized when its confirmations are null (the block is
 * rooted), else processed.
 */
export function reached(s: SignatureStatus, c: Commitment): boolean {
    const got = s.confirmationStatus ?? (s.confirmations === null ? 'finalized' : 'processed')
    return RANK[got] >= RANK[c]
}
