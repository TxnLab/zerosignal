# openaishim

Serves the SDK's OpenAI-compatible API (`zs/handler`) on localhost. Any OpenAI client
pointed at it pays for each request it sends, with each request routed to a node
separately. It is the Go twin of the TypeScript `browser-openai-shim` example.

```bash
cd proto/go
ZS_MNEMONIC="word word …" go run ./examples/openaishim -addr 127.0.0.1:8080
# then, from any OpenAI client:
#   base URL http://127.0.0.1:8080/v1, any API key
```

With `-ask`, it sends one chat completion to itself over plain `net/http`, prints the
answer and the cost from the `X-Zs-*` response headers, and exits:

```bash
ZS_MNEMONIC="word word …" go run ./examples/openaishim -model <model id> -ask "hello"
```

- `ZS_MNEMONIC`: the payer's 25-word Algorand mnemonic (a 24-word recovery phrase works
  too). The account must hold USDC and ALGO on the network.
- `-network`: `mainnet` (default), `testnet` or `localnet`. Localnet also needs
  `-app-id`, and turns on direct sends, private hosts and staging nodes for the
  single local node.
- `-budget`: the most the process may spend, in µUSDC (default 1 000 000, $1). An
  open ticket counts at its ceiling until it settles. Past the budget, requests fail
  with a spend-cap error.

**On mainnet every request it serves spends real USDC.** The server asks no
credential, and it answers requests from any web origin, so a page open in this
machine's browser can send it requests too. Keep `-addr` on loopback, and keep the
budget small. The `zs-proxy` command, built on the same handler, has the same
exposure.
