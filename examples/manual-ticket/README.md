# manual-ticket

One paid turn built from the SDK's parts instead of `Client.stream`, one protocol step at a time:

1. **Discovery.** Read the chain and probe the nodes, then pick one that serves the model and has a
   current ephemeral key to seal to.
2. **Wallet.** Read the escrow contract's config. The prepaid pool pays for each ticket's box.
3. **Reserve.** The node signs a ticket with a price ceiling and commits to the key it will seal the
   answer under. `httpReserveClient` checks the ticket's signature, its terms and that commitment.
4. **Price check.** `verifyReservePrice` checks the ceiling against the node's advertised rates plus
   the protocol fee. This check is the payer's job. It accepts when it can't run (the fee unread,
   the model unpriced), so a hard cap, `--max-price` (default $0.10), backs it.
5. **Open escrow.** `wallet.open` locks the ceiling in the contract. From here the payer has paid,
   and the turn belongs to this node. If anything after this fails, the example prints the ticket
   and how it is recovered: the node may still claim it, or the payer calls `refundInactive` once
   it passes its deadline. `Client.stream` journals the ticket here and runs a refund watchdog, so
   it finishes the ticket itself.
6. **Seal and send.** `sealRequest` binds the ticket into an envelope only the node can open.
7. **Open the answer.** The response key must match the ticket's `commit_k`. `openSealedStream`
   decrypts the frames in order and hands over the receipt.
8. **Settle.** `verifyReceipt` checks the node's signature, the charge and the body hash, then
   `ackSettle` settles, through the node's presigned settle group when it decodes. A receipt whose
   body hash doesn't match the answer is protested instead, which freezes the ticket for
   arbitration. One that fails the signature or amount check is not acked and not protested, since
   the contract checks both itself and refuses such a protest. That ticket refunds or lapses.

```bash
cd proto && pnpm install && make build-sdk
cd examples/manual-ticket
ZS_MNEMONIC="word word …" pnpm start --model <model id> "Why is the sky blue?"
```

**On mainnet this spends real USDC.** It sends to the node directly, so the node sees your IP
address. Any node you pay learns your Algorand address, since it is on the ticket.

`Client.stream` runs all of this, and adds the parts a production payer needs:

- ranking nodes by price and responsiveness, and failing over between them before payment;
- relaying, so no node learns the payer's IP address (`selectRelayHopWeighted`, `applyRelay`);
- retries for transient errors, and a spend cap (`Config.spendGuard`);
- the ticket journal and the refund watchdog, which finish a ticket that a failure leaves open.

Build a turn yourself only when the host has to own one of these steps. `proto/SPEC.md` lists the
rules each step has to follow.
