/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Points the SDK at a local stack: AlgoKit localnet, an escrow app deployed
// there, and a zs-node on this machine. The network is the one setting that
// differs from a public network.
//
//   ZS_ESCROW_APP_ID=<app id> ZS_MNEMONIC="word word …" pnpm start --model <model id> "hello"

import { parseArgs } from 'node:util'

import { Client, consoleLogger } from '@txnlab/zerosignal'
import { mnemonicSigner } from '@txnlab/zerosignal/accounts/mnemonic'

const { values, positionals } = parseArgs({
    options: { model: { type: 'string' } },
    allowPositionals: true,
})
const phrase = process.env.ZS_MNEMONIC
const appId = process.env.ZS_ESCROW_APP_ID
const prompt = positionals.join(' ')
if (!phrase || !appId || !values.model || !prompt) {
    console.error('usage: ZS_ESCROW_APP_ID=<id> ZS_MNEMONIC="…" pnpm start --model <id> <prompt>')
    process.exit(2)
}

const zs = await Client.create({
    signer: mnemonicSigner(phrase),
    // The localnet preset is AlgoKit's algod (localhost:4001); it has no
    // escrow app of its own, so name the one you deployed. On it the SDK
    // sends direct and reaches a node on localhost by default.
    network: { network: 'localnet', escrowAppId: BigInt(appId) },
    logger: consoleLogger(),
})
try {
    for (const op of await zs.registry.allOperators()) {
        console.error(`[node] ${op.id}/${op.nodeId} ${op.baseUrl} reachable=${op.reachable} models=${op.models.join(',')}`)
    }
    const answer = await zs
        .stream({
            endpoint: '/v1/chat/completions',
            body: JSON.stringify({ model: values.model, messages: [{ role: 'user', content: prompt }] }),
        })
        .text()
    console.log(answer)
} finally {
    await zs.waitSettles(AbortSignal.timeout(30_000)).catch((err: unknown) => console.error(err))
    await zs.close()
}
