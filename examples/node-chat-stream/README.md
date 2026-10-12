# node-chat-stream

Streams one chat completion through `Client.stream` and prints the answer as it arrives, then the
node's verified receipt and the settlement the SDK submitted.

```bash
cd proto && pnpm install && make build-sdk
cd examples/node-chat-stream
ZS_MNEMONIC="word word …" pnpm start --model <model id> "Why is the sky blue?"
```

- `ZS_MNEMONIC` is a 25-word Algorand mnemonic for the paying account. It must hold USDC and ALGO
  on the network.
- `--network` is `mainnet` (the default) or `testnet`. **On mainnet this spends real USDC.**
- `-v` logs what the SDK does (never prompt or answer text) to stderr.
- Ctrl-C ends the turn. If the node has already finished generating, the SDK still collects the
  receipt and settles before the process exits.

`discovery` lists the model ids the network serves.

Open tickets are journaled in memory here, so a ticket that a crash leaves open is refunded only by
hand. `reconcile` shows a journal that survives a restart.
