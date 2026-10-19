/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Finishes the tickets an earlier process left open. Every paid turn writes
// its ticket to the journal when escrow opens and removes it once settled;
// a crash in between leaves the row. A Client handed that journal sweeps it
// at once and every minute: it re-sends a settle that never landed, refunds
// a ticket the node never served once its deadline passes, and forgets one
// that is finished on chain.
//
//   ZS_MNEMONIC="word word …" pnpm start [--journal ./journal.json]
//
// It runs until the journal holds nothing for this payer, or Ctrl-C. A
// ticket whose submits keep failing is given up on for this process and
// stays in the journal, so the loop then runs until Ctrl-C.

import { open, readFile, rename, unlink } from 'node:fs/promises'
import { dirname } from 'node:path'
import { parseArgs } from 'node:util'

import { Client, type NetworkName, type TicketJournal, type TicketRecord, consoleLogger, ownsRecord } from '@txnlab/zerosignal'
import { mnemonicSigner } from '@txnlab/zerosignal/accounts/mnemonic'

const { values } = parseArgs({
    options: {
        network: { type: 'string', default: 'mainnet' },
        journal: { type: 'string', default: './journal.json' },
    },
})
const phrase = process.env.ZS_MNEMONIC
if (!phrase) {
    console.error('usage: ZS_MNEMONIC="…" pnpm start [--network mainnet|testnet] [--journal ./journal.json]')
    process.exit(2)
}

// A TicketJournal over one JSON file, held by one process at a time. Records
// hold bigints (amounts, the app id) and bytes (a receipt digest), which JSON
// has no form for, so both are tagged on the way out and restored on the way
// in. Pay from an account with the same file every time: that is what lets
// the next process finish what the last one started.
async function fileJournal(path: string): Promise<{ journal: TicketJournal; release(): Promise<void> }> {
    // Two holders would each rewrite the file over the other's rows, and both
    // sweeps would submit the same refund. Client.create refuses a second
    // Client on one journal object, which another process never shares.
    const lock = `${path}.lock`
    try {
        await (await open(lock, 'wx', 0o600)).close()
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
        throw new Error(`${path} is in use by another process (if none is running, delete ${lock})`)
    }
    const replacer = (_: string, v: unknown) =>
        typeof v === 'bigint' ? { $bigint: v.toString() } : v instanceof Uint8Array ? { $bytes: Buffer.from(v).toString('base64') } : v
    const reviver = (_: string, v: unknown) => {
        if (v !== null && typeof v === 'object') {
            if ('$bigint' in v) return BigInt((v as { $bigint: string }).$bigint)
            if ('$bytes' in v) return new Uint8Array(Buffer.from((v as { $bytes: string }).$bytes, 'base64'))
        }
        return v
    }
    const load = async (): Promise<Record<string, TicketRecord>> => {
        try {
            return JSON.parse(await readFile(path, 'utf8'), reviver) as Record<string, TicketRecord>
        } catch (err) {
            if ((err as NodeJS.ErrnoException).code === 'ENOENT') return {}
            // A journal that won't parse is not an empty one: refusing keeps
            // the next write from replacing it with nothing.
            throw err
        }
    }
    // One write at a time, each a whole new file synced to disk and swapped
    // in, so concurrent turns can't interleave and a crash or power loss
    // mid-write keeps the old journal. The rows name the payer's address, so
    // the file is the owner's alone.
    let queue: Promise<unknown> = Promise.resolve()
    const update = (fn: (all: Record<string, TicketRecord>) => void) => {
        const run = queue.then(async () => {
            const all = await load()
            fn(all)
            const tmp = `${path}.tmp`
            const f = await open(tmp, 'w', 0o600)
            try {
                await f.writeFile(JSON.stringify(all, replacer, 2))
                await f.sync()
            } finally {
                await f.close()
            }
            await rename(tmp, path)
            const dir = await open(dirname(path), 'r')
            try {
                await dir.sync()
            } finally {
                await dir.close()
            }
        })
        queue = run.catch(() => {})
        return run
    }
    const journal: TicketJournal = {
        put: (rec) => update((all) => void (all[rec.ticketId] = rec)),
        delete: (ticketId) => update((all) => void delete all[ticketId]),
        list: async (payer, d) => {
            await queue
            return Object.values(await load())
                .filter((r) => r.payer === payer && ownsRecord(d, r))
                .sort((a, b) => a.createdAt - b.createdAt)
        },
    }
    return {
        journal,
        release: async () => {
            await queue
            await unlink(lock)
        },
    }
}

const { journal, release } = await fileJournal(values.journal)
try {
    const zs = await Client.create({
        signer: mnemonicSigner(phrase),
        network: { network: values.network as NetworkName },
        stores: { journal },
        // The sweep reports what it does on each ticket here.
        logger: consoleLogger(),
    })
    const payer = zs.config.signer.address
    const deployment = zs.config.network

    const stop = new AbortController()
    process.once('SIGINT', () => stop.abort())

    const describe = (r: TicketRecord) =>
        `${r.ticketId} ${r.status} node ${r.target.op}/${r.target.node}, expires ${new Date(r.expiresAt).toISOString()}`
    let last = ''
    try {
        for (;;) {
            const rows = await journal.list(payer, deployment)
            const now = rows.map(describe).join('\n')
            if (now !== last) console.log(rows.length === 0 ? 'journal empty' : `${rows.length} open:\n${now}`)
            last = now
            if (rows.length === 0 || stop.signal.aborted) break
            await new Promise((resolve) => setTimeout(resolve, 5_000))
        }
    } finally {
        // Stops the sweep; whatever is left stays in the journal for the next run.
        await zs.close()
    }
} finally {
    await release()
}
