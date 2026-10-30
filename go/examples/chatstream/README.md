# chatstream

Pays for one streamed chat completion and prints the answer as it arrives. The receipt
(tokens, µUSDC charged, the node that served it) and the settle transaction go to
stderr. It is the Go twin of the TypeScript `node-chat-stream` example. `cmd/zschat`
is the fuller CLI: it reads the zs-proxy wallet and keeps a ticket journal on disk.

```bash
cd proto/go
ZS_MNEMONIC="word word …" go run ./examples/chatstream -model <model id> "hello"
```

- `ZS_MNEMONIC`: the payer's 25-word Algorand mnemonic (a 24-word recovery phrase works
  too). The account must hold USDC and ALGO on the network.
- `-network`: `mainnet` (default), `testnet` or `localnet`. Localnet also needs
  `-app-id`; there the SDK sends direct and reaches a node on this machine by
  default.

**On mainnet this spends real USDC.** The open ticket is journaled in memory only, so a
ticket left open when the run exits is refunded only by hand; set
`zs.Stores.JournalPath` to keep the journal on disk.
