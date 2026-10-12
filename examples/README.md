# Examples

Runnable programs for the ZeroSignal payer SDK. The TypeScript examples are here, one per
directory. The Go ones are in [`../go/examples`](../go/examples).

| Example | Shows | Pays |
|---|---|---|
| [`node-chat-stream`](./node-chat-stream) | One chat turn through `Client.stream`: the answer as it streams, the receipt and the settlement. Go: [`chatstream`](../go/examples/chatstream). | yes |
| [`browser-openai-shim`](./browser-openai-shim) | The OpenAI SDK in a browser tab, with `zs.fetch` in place of the network. Go: [`openaishim`](../go/examples/openaishim), which serves the same API on localhost. | yes |
| [`discovery`](./discovery) | The network's nodes and routable models, read from chain and probed, with no key. Go: [`discovery`](../go/examples/discovery). | no |
| [`manual-ticket`](./manual-ticket) | One turn built from the SDK's parts: reserve, price check, escrow, sealing, receipt and settle. | yes |
| [`reconcile`](./reconcile) | A ticket journal that survives a restart, and the sweep that finishes stranded tickets. | fees only |
| [`images`](./images) | Image generation through `/v1/images/generations`. | yes |
| [`localnet`](./localnet) | The settings for a stack on your own machine. | local USDC |

**The examples default to mainnet, and the paying ones spend real USDC.** Most take `--network
testnet`. Each paying example reads the payer's 25-word Algorand mnemonic from `ZS_MNEMONIC`, and
the account must hold USDC and ALGO on that network.

## Running one

The examples are part of this repository's pnpm workspace and build against the SDK source, so
build the SDK first:

```bash
cd proto
pnpm install
make build-sdk
cd examples/discovery && pnpm start
```

In your own project, install the published packages instead:

```bash
pnpm add @txnlab/zerosignal algosdk
```

`make test` typechecks every example and bundles the browser one, so they stay in step with the
SDK. They are not run there, since running them needs a funded account and the network.
