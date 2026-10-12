# browser-openai-shim

The OpenAI SDK, unchanged, running in a browser tab against ZeroSignal. `zs.fetch` stands in for
the network, so `openai.models.list()` lists what the network serves, and each
`chat.completions.create` becomes a paid, sealed turn routed to a node. No server and no API key
are involved.

```bash
cd proto && pnpm install && make build-sdk
cd examples/browser-openai-shim
pnpm dev                       # then open the URL it prints
```

- Paste the paying account's 25-word Algorand mnemonic into the page. The account must hold USDC
  and ALGO. The phrase stays in the tab's memory and is never stored or sent. Pasting a key is for
  trying this out: a real app derives the key from a passkey (`xhdRootFromEntropy` over a WebAuthn
  PRF output) or asks a wallet to sign.
- Pick `mainnet` or `testnet`. **On mainnet each answer costs real USDC.**
- The catalog is kept in `localStorage`, so the next visit lists models before discovery
  finishes.
- Open tickets are journaled in memory only. Closing or reloading the tab mid-answer leaves that
  ticket open, to be claimed by the node or refunded by hand after its deadline. A real app passes
  a durable `Stores.journal` (IndexedDB, say) so the next visit finishes it.

The same three lines work with any client that takes a `fetch`:

```ts
const zs = await Client.create({ signer, network: mainnet() })
const openai = new OpenAI({ baseURL: zs.baseURL, fetch: zs.fetch, apiKey: 'unused' })
```

`node-chat-stream` makes the same call through the SDK's own `Client.stream`, which also reports the
receipt and the settlement.
