# @txnlab/zerosignal

The ZeroSignal payer SDK for TypeScript: discovery, routing, reserve, escrow, sealing, relay
hops, streaming and receipt checks for private LLM inference on Algorand. It is the twin of the
Go SDK, [`github.com/TxnLab/zerosignal/go/zs`](https://github.com/TxnLab/zerosignal/tree/main/go/zs):
event names, error kinds, config defaults and network presets are shared with it and pinned by
a golden fixture both test suites read.

> **Status: in development.** This release holds the API vocabulary and the ports. The client
> itself (`Client`, `stream`) is being ported from the ZeroSignal chat app and is not here yet.

## Install

```bash
pnpm add @txnlab/zerosignal
```

The protocol primitives (`@txnlab/zs-proto`) come with it, at exactly the version this release
was built with, under `@txnlab/zerosignal/proto` and `@txnlab/zerosignal/proto/<name>`
(`wire`, `ticket`, `selection`, `steering`, `relay`, `transient`, `inject`, `pricing`,
`tokenize`, `imageprice`, `escrow`, `attest`, `tools`).

## Ports

The SDK reads no environment and no global state. Everything it needs from its host arrives
through `Config`:

| Port | Default | Purpose |
|---|---|---|
| `signer` | required | The payer's key: raw Ed25519 `signBytes` and algosdk `signTransactions`, for one address. |
| `storage` | `memoryStorage()` | Durable key-value storage for state that should survive a reload. |
| `cache` | `memoryCache()` | Shared, single-flight fetch cache. Adapt TanStack Query or similar here. |
| `logger` | discards | slog-style `debug` / `info` / `warn` / `error`. Never receives prompt or response content. |
| `clock` | `Date.now` | Unix milliseconds. |
| `fetch` | `globalThis.fetch` | Node and chain traffic. |

### `signBytes` is raw Ed25519

The SDK signs a 32-byte sha256 digest of a domain-tagged canonical body, verbatim. This is
**not** go-algorand-sdk's `SignBytes` (which prepends `MX`) and not ARC-1 `signData`. A wallet
whose sign-bytes flow tags or prefixes the message cannot implement the port. The SDK also
refuses to sign for any address but `signer.address` (`payerBytesSigner`), so a multi-account
signer cannot sign a reserve with the wrong key.

## Configuration

```ts
import { resolveConfig, testnet } from '@txnlab/zerosignal'

const config = resolveConfig({ signer, network: testnet() })
```

`network` defaults to mainnet. Testnet and mainnet embed the escrow application id; localnet
and private deployments set `network.escrowAppId`. Durations are milliseconds. A config the SDK
cannot run with throws a `ZsError` with kind `invalid_request` and code `invalid_config`.

## Routing stores

`@txnlab/zerosignal/routing` holds the payer's own routing signals: `RelayReputationStore`,
`RelayLatencyStore`, `TargetBackoffStore` and `NodeExclusionStore`, each mirroring a store in
the Go SDK, and `RelayHealthStore`, the transient exclusions and direct-contact verdict a
browser needs because it can't reach every node a server can. Relay selection
(`selectRelayHopWeighted`, `applyRelay`) comes with them. They are per-instance and take an
injected clock. A wall clock that steps back costs at most one window, since each store
re-dates a record it finds in the future. A `Client` will own one of each; until it exists, a
host that routes for itself constructs them.

## Errors and events

The SDK's own failures are `ZsError`s. Branch on `kind`, the stable contract; `code` is
diagnostic and may gain values. The one exception is `SignerAddressError`, which
`payerBytesSigner` rejects with when asked to sign for another address. A turn's events are a discriminated union on `type`
(`payment.committed`, `delta.text`, `receipt.verified`, `done`, …). The set grows, so a
consumer must ignore types it does not handle.

## Development

This package and `@txnlab/zs-proto` (`../ts`) are one pnpm workspace rooted one directory up. This
package builds against `../ts/dist`, as a consumer of the published package would.

```bash
cd .. && pnpm install && make test   # Go, ts and sdk suites
make -C .. build-ts                  # this package resolves @txnlab/zs-proto to ../ts/dist
pnpm test                            # this package only
pnpm typecheck
```

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
