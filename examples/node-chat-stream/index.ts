/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Streams one chat completion through the SDK and prints the answer as it
// arrives, then the receipt and the settlement: the smallest complete payer.
//
//   ZS_MNEMONIC="word word …" pnpm start --model <model id> "Why is the sky blue?"
//
// The paying account must hold USDC and ALGO on the network (mainnet unless
// --network says otherwise). This pays real USDC on mainnet.

import { parseArgs } from 'node:util'

import { Client, type NetworkName, consoleLogger } from '@txnlab/zerosignal'
import { mnemonicSigner } from '@txnlab/zerosignal/accounts/mnemonic'

const { values, positionals } = parseArgs({
    options: {
        model: { type: 'string' },
        network: { type: 'string', default: 'mainnet' },
        verbose: { type: 'boolean', short: 'v', default: false },
    },
    allowPositionals: true,
})
const phrase = process.env.ZS_MNEMONIC
const prompt = positionals.join(' ')
if (!phrase || !values.model || !prompt) {
    console.error('usage: ZS_MNEMONIC="…" pnpm start --model <id> [--network mainnet|testnet] [-v] <prompt>')
    process.exit(2)
}

const zs = await Client.create({
    signer: mnemonicSigner(phrase),
    network: { network: values.network as NetworkName },
    ...(values.verbose && { logger: consoleLogger() }),
})

// Ctrl-C ends the turn. Before the node finishes generating it is told to
// stop; after that, the SDK still collects the receipt and settles.
const stop = new AbortController()
process.once('SIGINT', () => stop.abort())

try {
    const turn = zs.stream(
        {
            endpoint: '/v1/chat/completions',
            body: JSON.stringify({ model: values.model, messages: [{ role: 'user', content: prompt }], stream: true }),
        },
        stop.signal,
    )
    for await (const ev of turn.events()) {
        switch (ev.type) {
            case 'delta.text':
                process.stdout.write(ev.delta)
                break
            case 'receipt.verified': {
                const r = ev.receipt
                console.error(
                    `\n[receipt] ${r.actual_input_count} in / ${r.actual_output_count} out tokens, ` +
                        `${r.amount_charged} µUSDC to node ${ev.target.op}/${ev.target.node}`,
                )
                break
            }
            // The event set grows; anything else is ignored.
        }
    }
    process.stdout.write('\n')

    const { settlement, err } = await turn.wait(AbortSignal.timeout(30_000))
    if (err !== undefined) console.error('[settle] failed:', err)
    else if (settlement.txId) console.error(`[settle] ${settlement.kind} tx ${settlement.txId}`)
} finally {
    // A settle still being submitted would otherwise die with the process.
    await zs.waitSettles(AbortSignal.timeout(30_000)).catch((err: unknown) => console.error(err))
    await zs.close()
}
