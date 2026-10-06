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
| `fetch` | Node: `nodeFetch()`; elsewhere `globalThis.fetch` | Traffic to nodes. Chain reads keep their own transport. |

### Private addresses

An operator registers its own URL on-chain, so an operator could point the payer at
`localhost` or its LAN. Routing skips a URL whose host is literally private
(`operatorUrlAllowed`), which is all a browser can check. In Node the default `fetch` also
checks every address it is about to dial, as Go's SDK does: a name that resolves into a
private, loopback, link-local, multicast or CGNAT range is refused at the dial, against the
same resolution the socket uses, so a DNS rebind can't slip between the check and the
connection. The refused fetch rejects with a `TypeError` whose `cause` is a
`PrivateTargetError`. `allowPrivateHosts: true` lifts both checks, for localnet.

The guard is `nodeFetch` from `@txnlab/zerosignal/node`, built on
[undici](https://github.com/nodejs/undici)'s fetch over its own connection pool, so its
`Response` is undici's class rather than the global one. Neither build reads `HTTP_PROXY`. A
`fetch` passed in `Config` replaces it, guard and all. `isPrivateAddress` is the range check
on its own, for a host that dials through something else.

The guard is Node's only. Bun and Deno get their own `fetch`, as a browser does, with only the
literal-host check: Bun's `undici` ignores the connection hook the guard rests on, and Deno
is untested. `nodeFetch` throws there rather than hand back a guard that checks nothing.

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

## Catalog

`@txnlab/zerosignal/catalog` holds the rules a model picker ranks its rows by:
`compareUniqueModelRows` and `pickColdStartDefault` (image tools when asked, then general
models before domain specialists, then price), `rowServesWireId` for a row that merges several
spellings of one model, `rankFamilyCandidates`, the affordability-aware ranking an automatic
pick takes its head of and a failed pick falls back through, and `deriveWeightsConsensus`, the
display-only weights summary. Their
types name only the fields the rules read, so an app's own row type passes. The Go SDK has no
picker, so these have no Go twin.

`buildUniqueModelRows` derives the picker's rows themselves from per-node catalog rows: one row
per model, its default node ranked by the same `selectTargets` call dispatch makes (a default
whose weights digest contradicts its peers is demoted), and, with `unifyEquivalent`, the
spellings of one model merged by `rowIdentityKey`. `uniqueModelRowVariants` adds the same rows
restricted to attested nodes. The app supplies its selection projection, its attestation
predicate, its candidate filter, and any per-node fields to carry.

It also holds what a payer does with its nodes' discovery probes, each matching the Go SDK's
registry under shared vectors: `selectProbeSet` bounds which nodes a cycle probes, steered by
the recently requested models in `ModelDemand`; `checkEphemeralAdvertisement` verifies a
node's signed ephemeral seal key and says why one is unusable (`EphemeralVerifyCache` reuses
the verdict for an app that rebuilds its rows often, and `recordEphemeralStaleness` charges a
relay that served a stale key).

`CatalogEngine` folds each node's probe results as the Go registry does. A node keeps its last
answer for `maxCarryAge` after it, through a failed probe, an unreachable relay, or a cycle that
skipped it. A probe that reached the node and failed reads `failing` but keeps the models. One
that learned nothing (every relay hop failed) changes nothing. Two readings are more cautious
than Go's, which starts each cycle with every node unprobed: a node's own failure stays `failing`,
and a privacy-mode probe with no relay reads `no-relay`, until the node is next probed. The app runs the probes and hands
each result over; `restoredProtoVersion` floors a version read back from storage to its major.

## Escrow app client

`@txnlab/zerosignal/escrow-client` is the typed `ZeroSignalEscrow` app client, generated by
algokit-client-generator (minimal mode) from the ARC-56 in this repository, with `APP_SPEC` and
the box record types. It needs `@algorandfoundation/algokit-utils` ^9.2.0, an optional peer
dependency that the rest of the SDK does not use. CI regenerates the client and fails if the
committed copy differs.

## Prepaid MBR pool

Each open ticket's box is paid for out of the payer's prepaid ALGO pool in escrow, so a request
carries no ALGO. `ensureMbrDeposit(chain, payer, slots)` funds the pool toward a working set of
`slots` concurrent tickets (`Config.concurrentSlots` by default), opting in on the first
deposit. The working set is an ideal rather than a requirement: a wallet that can't reach it
funds as many whole slots as it affords and reports `belowTarget`, and one that can't afford a
single slot throws `MbrDepositUnaffordableError` before anything is signed. `backedSlots` on
the error tells a pool that can still serve from one that can't, and `need` is what the next
deposit costs: the free-quota box term when that is what a serving pool lacks, else a slot. `planMbrDeposit` is the
sizing on its own, Go's `planDeposit`, and `readMbrPool` / `mbrPoolState` report what is
deposited, reserved by live tickets, and withdrawable.

The chain arrives as an `MbrPoolChain`: the escrow app's readonly calls, the payer's spendable
balance, and the deposit group. Calls aren't single-flight, so a host that can run two at once
for one payer serializes them, or both may deposit.

## Errors and events

The SDK's own failures are `ZsError`s. Branch on `kind`, the stable contract; `code` is
diagnostic and may gain values. Two exceptions carry fields a caller acts on:
`SignerAddressError`, which `payerBytesSigner` rejects with when asked to sign for another
address, and `MbrDepositUnaffordableError` from `ensureMbrDeposit`. A turn's events are a discriminated union on `type`
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
