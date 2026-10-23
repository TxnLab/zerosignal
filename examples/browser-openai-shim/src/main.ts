/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The OpenAI SDK, unchanged, talking to ZeroSignal from a browser tab: the
// Client's fetch stands in for the network, so each request becomes a paid,
// sealed turn routed to a node. Nothing listens on a port.

import OpenAI from 'openai'

import { Client, type NetworkName, type StorageAdapter } from '@txnlab/zerosignal'
import { mnemonicSigner } from '@txnlab/zerosignal/accounts/mnemonic'

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const status = $<HTMLParagraphElement>('status')
const mnemonicInput = $<HTMLInputElement>('mnemonic')
const networkSelect = $<HTMLSelectElement>('network')
const connect = $<HTMLButtonElement>('connect')
const modelSelect = $<HTMLSelectElement>('model')
const promptBox = $<HTMLTextAreaElement>('prompt')
const send = $<HTMLButtonElement>('send')
const answer = $<HTMLPreElement>('answer')

// The catalog is saved here, so a reload lists models before the chain read
// and the first probes return. Storage can be unavailable (a private window,
// blocked site data); the SDK then just starts cold.
const pageStorage: StorageAdapter = {
    get: async (key) => {
        try {
            return localStorage.getItem(key) ?? undefined
        } catch {
            return undefined
        }
    },
    set: async (key, value) => {
        try {
            localStorage.setItem(key, value)
        } catch {
            // Starts cold next time.
        }
    },
    delete: async (key) => {
        try {
            localStorage.removeItem(key)
        } catch {
            // Nothing saved to remove.
        }
    },
}

// A pasted mnemonic is for trying this out: a real app derives the key from a
// passkey (xhdRootFromEntropy over a WebAuthn PRF output) or asks a wallet.
async function start(phrase: string, network: NetworkName) {
    const zs = await Client.create({ signer: mnemonicSigner(phrase), network: { network }, storage: pageStorage })
    addEventListener('pagehide', () => void zs.close())

    // No API key is read and none is sent: payment is the on-chain escrow.
    const openai = new OpenAI({ baseURL: zs.baseURL, fetch: zs.fetch, apiKey: 'unused', dangerouslyAllowBrowser: true })

    status.textContent = `Finding nodes on ${network}…`
    const models = await openai.models.list()
    for (const m of models.data) modelSelect.add(new Option(m.id, m.id))
    modelSelect.disabled = send.disabled = models.data.length === 0
    status.textContent = `${models.data.length} models. Paying from ${zs.config.payerSigner.address} on ${network}.`

    send.onclick = async () => {
        send.disabled = true
        answer.textContent = ''
        try {
            const stream = await openai.chat.completions.create({
                model: modelSelect.value,
                messages: [{ role: 'user', content: promptBox.value }],
                stream: true,
            })
            for await (const chunk of stream) answer.textContent += chunk.choices[0]?.delta.content ?? ''
        } catch (err) {
            // An SDK failure arrives as an OpenAI-shaped error, with the reason
            // (wallet_unfunded, operators_busy, …) as its code.
            answer.textContent += `\n\n${err instanceof Error ? err.message : String(err)}`
        } finally {
            send.disabled = false
        }
    }
}

connect.onclick = () => {
    const phrase = mnemonicInput.value.trim()
    if (!phrase) return
    mnemonicInput.value = ''
    mnemonicInput.disabled = networkSelect.disabled = connect.disabled = true
    status.textContent = 'Reading the chain…'
    start(phrase, networkSelect.value as NetworkName).catch((err: unknown) => {
        status.textContent = `Failed: ${err instanceof Error ? err.message : String(err)}`
        mnemonicInput.disabled = networkSelect.disabled = connect.disabled = false
    })
}
