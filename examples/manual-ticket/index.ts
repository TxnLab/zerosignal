/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// One paid turn, built from the SDK's parts instead of Client.stream: pick a
// node, reserve a ticket, check it, open escrow, seal the request, read the
// sealed answer, check the receipt and settle. Client.stream does all of it,
// plus failover across nodes, relays, retries, the journal and the refund
// watchdog. Use the parts only when a host has to own one of those steps.
//
//   ZS_MNEMONIC="word word …" pnpm start --model <model id> "Why is the sky blue?"
//
// This pays real USDC on mainnet. It talks to the node directly, so the node
// sees this machine's IP address; Client.stream relays by default.

import { parseArgs } from 'node:util'

import {
    AlgodEscrowChain,
    type NetworkName,
    type Operator,
    ProtestReason,
    ReceiptError,
    type StreamReceipt,
    Wallet,
    buildDiscovery,
    chainAlgod,
    decodeSettleGroup,
    httpReserveClient,
    openResponseKey,
    openSealedStream,
    operatorPricingOf,
    payerBytesSigner,
    reserveInputCount,
    resolveConfig,
    sealRecipientOf,
    sealRequest,
    verifyReceipt,
    verifyReservePrice,
} from '@txnlab/zerosignal'
import { mnemonicSigner } from '@txnlab/zerosignal/accounts/mnemonic'
import { algorandDeploymentId } from '@txnlab/zerosignal/proto/ticket'
import { ENCRYPTED_CONTENT_TYPE, RESPONSE_KEY_HEADER, ResponseOpener } from '@txnlab/zerosignal/proto/wire'

const MAX_OUTPUT_TOKENS = 512
// The contract's default cap on a protest's excerpt; a longer one reverts.
const DISPUTE_EXCERPT_BYTES = 1800

const { values, positionals } = parseArgs({
    options: {
        model: { type: 'string' },
        network: { type: 'string', default: 'mainnet' },
        // The most one ticket may lock, in µUSDC: $0.10.
        'max-price': { type: 'string', default: '100000' },
    },
    allowPositionals: true,
})
const phrase = process.env.ZS_MNEMONIC
const model = values.model
const prompt = positionals.join(' ')
if (!phrase || !model || !prompt) {
    console.error('usage: ZS_MNEMONIC="…" pnpm start --model <id> [--network mainnet|testnet] <prompt>')
    process.exit(2)
}
const signer = mnemonicSigner(phrase)
const cfg = resolveConfig({ signer, network: { network: values.network as NetworkName } })
const algod = chainAlgod(cfg)

// 1. Discovery, and a node to send to. Client.stream ranks the candidates
//    by price and responsiveness and fails over between them; this takes the
//    first that can be sealed to.
const { registry } = buildDiscovery(cfg, algod)
// sealRecipientOf throws for a node with no current sealing key.
const sealable = (o: Operator, now: number) => {
    try {
        sealRecipientOf(o, now)
        return true
    } catch {
        return false
    }
}
let op: Operator | undefined
try {
    await registry.ready
    const now = Date.now()
    op = (await registry.operators(model)).find((o) => !o.staging && registry.advertisable(o, now) && sealable(o, now))
} finally {
    await registry.stop()
}
if (op === undefined) throw new Error(`no reachable node serves ${model}`)
console.error(`[node] ${op.id}/${op.nodeId} ${op.baseUrl}`)

// 2. The escrow wallet: it reads the contract's config once, and keeps the
//    prepaid pool that pays for each ticket's box.
const chain = new AlgodEscrowChain({ algod, appId: cfg.network.escrowAppId, signer })
await chain.refreshConfig(AbortSignal.timeout(10_000))
const wallet = new Wallet({ chain, signer })

// 3. Reserve. The node signs a ticket naming its price ceiling and commits
//    to the key it will seal the answer under. httpReserveClient checks the
//    ticket's signature against the node's on-chain key, its terms against
//    the request, and that commitment.
const body = JSON.stringify({
    model,
    messages: [{ role: 'user', content: prompt }],
    max_tokens: MAX_OUTPUT_TOKENS,
    stream: true,
})
const input = reserveInputCount(op, model, body, MAX_OUTPUT_TOKENS)
// Every reserve names the payer's escrow deployment (the network's genesis
// hash and the escrow app), and the ticket must come back bound to it.
const params = await algod.getTransactionParams().do()
const deployment = algorandDeploymentId(params.genesisHash, cfg.network.escrowAppId)
const reserveClient = httpReserveClient({
    fetch: cfg.fetch,
    signer: payerBytesSigner(signer),
    timeoutMs: cfg.reserveTimeout,
    deployment,
})
const reserved = await reserveClient.reserve(
    op,
    {
        model,
        input_count: input.count,
        max_output_count: MAX_OUTPUT_TOKENS,
        stream: true,
        payer_addr: signer.address,
        input_bound_version: input.boundVersion,
    },
    null, // no relay
)
const ticket = reserved.ticket

// 4. The price is the payer's to check: the ceiling must not exceed what the
//    node advertised for this request, plus the protocol fee. The check
//    accepts when it can't run (the fee unread, the model unpriced), so a
//    hard cap backs it, as Config.spendGuard does for Client.stream.
const violation = await verifyReservePrice({
    ticket,
    pricing: operatorPricingOf(op, model),
    feeBps: () => wallet.protocolFeeBps(),
    reserveInputCount: input.count,
})
if (violation !== null) throw new Error(`ticket over the advertised price: ${violation.check} ${violation.field}`)
const maxPrice = Number(values['max-price'])
if (!(ticket.max_price <= maxPrice)) throw new Error(`ticket ceiling ${ticket.max_price} µUSDC is over --max-price ${maxPrice}`)
console.error(`[ticket] ${ticket.ticket_id}, at most ${ticket.max_price} µUSDC`)

// 5. Open escrow: the node's presigned group, completed and signed by the
//    payer, locks max_price in the contract. From here the payer has paid;
//    nothing below may be retried on another node. Client.stream journals the
//    ticket here and arms a refund watchdog, so a failure below is finished
//    later; this example only says what to do.
const handle = await wallet.open(ticket, op, reserved.presignedOpenTxn)
const txId = handle.appCallTxId
const stranded = (why: string) =>
    new Error(
        `${why}. Ticket ${ticket.ticket_id} is open in escrow app ${cfg.network.escrowAppId}: ` +
            `the node may still claim it; if it doesn't, the payer can call refundInactive once the ticket ` +
            `passes its deadline (expires ${new Date(ticket.expires_at * 1000).toISOString()}, plus the contract's grace).`,
    )

// 6. Seal the request to the key the reserve pinned, with the ticket bound
//    in, and send it.
const envelope = await sealRequest({
    body: new TextEncoder().encode(body),
    txId,
    ticketId: ticket.ticket_id,
    responseKey: reserved.responseKey,
    nodeRecipient: reserved.sealRecipient,
    ephemeral: reserved.identity,
})
const resp = await cfg.inferenceFetch(`${op.baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': ENCRYPTED_CONTENT_TYPE, Accept: 'text/event-stream' },
    body: envelope,
})
// A node that refuses, or answers a stream request with a whole body, is
// handled by Client.stream; here it ends the turn.
if (!resp.ok || resp.body === null || !(resp.headers.get('content-type') ?? '').startsWith('text/event-stream')) {
    throw stranded(`node answered ${resp.status} ${resp.headers.get('content-type') ?? ''}: ${await resp.text()}`)
}

// 7. Open the answer. openResponseKey checks the key against the ticket's
//    commit_k, which shows the node sealed under the key it committed to.
let receipt: StreamReceipt | undefined
const responseKey = await openResponseKey(resp.headers.get(RESPONSE_KEY_HEADER) ?? '', reserved.identity, ticket)
try {
    const chunks = openSealedStream({
        source: resp.body,
        opener: new ResponseOpener(responseKey, txId, ticket.ticket_id),
        api: 'chat',
        onReceipt: (r) => (receipt = r),
    })
    const reader = chunks.getReader()
    for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        // Each opened frame is one chat-completions chunk, as an OpenAI stream sends it.
        if (value.kind === 'content') {
            const chunk = JSON.parse(new TextDecoder().decode(value.bytes)) as { choices?: { delta?: { content?: string } }[] }
            process.stdout.write(chunk.choices?.[0]?.delta?.content ?? '')
        }
    }
    process.stdout.write('\n')
} catch (err) {
    throw stranded(`the answer broke off: ${err instanceof Error ? err.message : String(err)}`)
} finally {
    responseKey.fill(0)
}

// 8. Check the receipt, then settle on it. The receipt is signed by the node
//    and names the charge; its body_hash must match what was delivered.
if (receipt === undefined) throw stranded('the node sent no receipt')
try {
    verifyReceipt(receipt.receipt, ticket, op.ticketSigningKey, receipt.bodyHash)
} catch (err) {
    if (!(err instanceof ReceiptError)) throw err
    // The contract takes a protest only over the body hash: it checks the
    // receipt's signature and amount itself, so a protest over either
    // reverts. Such a receipt is not acked; the ticket refunds or lapses.
    if (err.violation !== 'body_hash') throw stranded(`the receipt failed its ${err.violation} check and was not acked`)
    // The evidence is what was delivered, the frames the hash covers in
    // order, cut to what the contract accepts. A protest freezes the ticket
    // for arbitration.
    const delivered = Buffer.concat(receipt.contentFrames)
    const excerpt = new Uint8Array(delivered.subarray(0, DISPUTE_EXCERPT_BYTES))
    const protest = await handle.protest(receipt.receipt, excerpt, ProtestReason.bodyHash)
    throw new Error(`the receipt's body hash doesn't match the answer; protested in ${protest.txId}`)
}
// A settle group that doesn't decode goes as none, so the payer settles on
// its own rather than not at all.
let settleGroup = receipt.settleGroup
try {
    if (settleGroup) decodeSettleGroup(settleGroup)
} catch {
    settleGroup = null
}
const settled = await handle.ackSettle(receipt.receipt, settleGroup)
if (settled.err !== undefined) throw settled.err
console.error(
    `[settle] ${receipt.receipt.amount_charged} µUSDC charged, tx ${settled.txid}` +
        (settled.groupRejected ? " (the node's settle group was refused; settled on the payer's own)" : ''),
)
