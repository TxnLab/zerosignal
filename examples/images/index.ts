/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Generates an image through /v1/images/generations and writes it to disk.
// The node prices an image request per image rather than per token, from the
// size and quality asked for, so the ticket's ceiling is known before it runs.
//
//   ZS_MNEMONIC="word word …" pnpm start --model <image model id> "a lighthouse at dusk"
//
// This pays real USDC on mainnet.

import { writeFile } from 'node:fs/promises'
import { parseArgs } from 'node:util'

import { Client, type NetworkName } from '@txnlab/zerosignal'
import { mnemonicSigner } from '@txnlab/zerosignal/accounts/mnemonic'

const { values, positionals } = parseArgs({
    options: {
        model: { type: 'string' },
        network: { type: 'string', default: 'mainnet' },
        size: { type: 'string', default: '1024x1024' },
        out: { type: 'string', default: 'image' },
    },
    allowPositionals: true,
})
const phrase = process.env.ZS_MNEMONIC
const prompt = positionals.join(' ')
if (!phrase || !values.model || !prompt) {
    console.error('usage: ZS_MNEMONIC="…" pnpm start --model <id> [--size 1024x1024] [--out image] <prompt>')
    process.exit(2)
}

const zs = await Client.create({ signer: mnemonicSigner(phrase), network: { network: values.network as NetworkName } })
try {
    const turn = zs.stream({
        endpoint: '/v1/images/generations',
        // No response_format: some image backends refuse it. Either form of
        // answer is handled below.
        body: JSON.stringify({ model: values.model, prompt, n: 1, size: values.size }),
    })
    // A whole (non-streamed) reply arrives as one frame: the OpenAI images
    // body, already opened.
    let body: Uint8Array | undefined
    for await (const ev of turn.events()) {
        if (ev.type === 'frame') body = ev.data
        if (ev.type === 'receipt.verified') console.error(`[receipt] ${ev.receipt.amount_charged} µUSDC`)
    }
    if (body === undefined) throw new Error('the node sent no image body')

    const images = (JSON.parse(new TextDecoder().decode(body)) as { data?: { b64_json?: string; url?: string }[] }).data ?? []
    for (const [i, img] of images.entries()) {
        if (img.b64_json) {
            // Named .png, though a node may answer in another format (WebP, JPEG).
            const file = `${values.out}-${i}.png`
            await writeFile(file, Buffer.from(img.b64_json, 'base64'))
            console.log(file)
        } else if (img.url) {
            console.log(img.url)
        }
    }
    await turn.wait(AbortSignal.timeout(30_000))
} finally {
    await zs.waitSettles(AbortSignal.timeout(30_000)).catch((err: unknown) => console.error(err))
    await zs.close()
}
