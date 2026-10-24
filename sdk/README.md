# @txnlab/zerosignal

The ZeroSignal payer SDK for TypeScript: routing, reserve, escrow, sealing, relay hops,
streaming and receipt checks for private LLM inference on Algorand. It is the twin of the
Go SDK, [`github.com/TxnLab/zerosignal/go/zs`](https://github.com/TxnLab/zerosignal/tree/main/go/zs):
event names, error kinds, config defaults and network presets are shared with it and pinned by
a golden fixture both test suites read.

> **Status: in development.** `Client.stream` runs a paid turn end to end, over operator
> discovery the Client builds itself or one the host supplies.

Runnable examples are in [`../examples`](../examples): a streamed chat turn, the OpenAI SDK in a
browser, discovery, a turn built from the SDK's parts, a durable ticket journal, images and
localnet.

## Install

```bash
pnpm add @txnlab/zerosignal algosdk
```

The package is private for now: the install needs an npm token that can read the `@txnlab`
scope, in your user-level `~/.npmrc`.

`algosdk` (^3.6) is a peer dependency: the `Signer` port is algosdk's `TransactionSigner`, called
with algosdk `Transaction` objects, so the SDK and your wallet must share one copy.

The protocol primitives (`@txnlab/zs-proto`) come with it, at exactly the version this release
was built with, under `@txnlab/zerosignal/proto` and `@txnlab/zerosignal/proto/<name>`
(`wire`, `ticket`, `selection`, `steering`, `relay`, `transient`, `inject`, `pricing`,
`tokenize`, `imageprice`, `escrow`, `settle`, `attest`, `tools`).

## Ports

The SDK reads no environment and no global state. Everything it needs from its host arrives
through `Config`:

| Port | Default | Purpose |
|---|---|---|
| `signer` | required on Algorand | The payer's key: raw Ed25519 `signBytes` and algosdk `signTransactions`, for one address. |
| `solanaSigner` | required on Solana | The payer's Solana key: raw Ed25519 `signBytes` and `signTransactionMessage`, for one base58 address (`solanaSigner` in `@txnlab/zerosignal/accounts/solana` is the in-memory one). |
| `storage` | `memoryStorage()` | Durable key-value storage for state that should survive a reload: the operator catalog a built registry saves. |
| `cache` | `memoryCache()` | Shared, single-flight fetch cache. Adapt TanStack Query or similar here. |
| `logger` | discards | slog-style `debug` / `info` / `warn` / `error`. Never receives prompt or response content. |
| `clock` | `Date.now` | Unix milliseconds. |
| `fetch` | Node: `nodeFetch()`; elsewhere `globalThis.fetch` | Traffic to nodes: discovery probes, reserves and inference. Algod traffic goes through the global `fetch` (see [Algod](#algod)). |

### Private addresses

An operator registers its own URL on-chain, so an operator could point the payer at
`localhost` or its LAN. The default `fetch` refuses to send to one, as Go's SDK does, so such
a node stays in the chain read but every probe, reserve and request to it fails, and it never
reads as reachable. Outside Node it refuses a URL whose host is literally private
(`isBlockedOperatorUrl`), which is all a browser can check, rejecting with a
`PrivateTargetError`. In Node it checks every address it is about to dial: a name that
resolves into a private, loopback, link-local, multicast or CGNAT range is refused at the dial,
against the same resolution the socket uses, so a DNS rebind can't slip between the check and
the connection. The same goes for an IPv6 address that reaches such a range through NAT64, SIIT
or 6to4, and for the IPv6 ranges whose target can't be read off the address (`::/96`, local-use
NAT64 `64:ff9b:1::/48`, Teredo), which are refused whole. That fetch rejects with a `TypeError` whose `cause` is a `PrivateTargetError`.
`allowPrivateHosts: true` lifts the check, for localnet.

The guard is `nodeFetch` from `@txnlab/zerosignal/node`, built on
[undici](https://github.com/nodejs/undici)'s fetch over its own connection pool, so its
`Response` is undici's class rather than the global one. Neither build reads `HTTP_PROXY`. A
`fetch` passed in `Config` replaces it, guard and all. `isPrivateAddress` is the range check
on its own, and `operatorUrlAllowed` the URL check, for a host that dials through something
else.

The guard is Node's only. Bun and Deno get their own `fetch`, as a browser does, with only the
literal-host check: Bun's `undici` ignores the connection hook the guard rests on, and Deno
is untested. `nodeFetch` throws there rather than hand back a guard that checks nothing.

### Accounts

Four subpaths build a signer from a key held in memory, each the twin of Go's keystore and
pinned to it by `testdata/account_vectors.json`: three Algorand `Signer`s and one
`SolanaSigner`. Passkeys are not one of them: derive 32 secret
bytes from the passkey (a WebAuthn PRF output) and hand them to `xhdRootFromEntropy`.

- `@txnlab/zerosignal/accounts/algosdk`: `algosdkSigner(account)` over an algosdk `Account`.
- `@txnlab/zerosignal/accounts/mnemonic`: `mnemonicSigner(phrase)` for a 25-word Algorand
  mnemonic. Any whitespace separates words; case is significant, as in Go's keystore (the
  `zs-proxy wallet import` command lowercases a phrase before storing it; this does not). A
  24-word phrase is an xHD account and is refused here.
- `@txnlab/zerosignal/accounts/xhd`: a BIP-39 / ARC-52 xHD account, the form the ZeroSignal
  chat app derives and exports as a 24-word recovery phrase. `xhdRootFromPhrase(phrase)` loads
  the phrase; `xhdRootFromEntropy(bytes)` derives the account from 32 secret, uniformly random
  bytes, such as a WebAuthn PRF output and never a credential id or public key. Those bytes are
  the phrase's entropy, so `entropyToMnemonic(bytes)` is the recovery phrase. `xhdSigner(root)`
  signs as the account. Both derive the first address key, m/44'/283'/0'/0/0. It needs the
  optional peer dependencies `@algorandfoundation/xhd-wallet-api` and `@scure/bip39`; the first
  imports Node's `crypto` and `util` and reads the global `Buffer`, so a browser bundle must
  polyfill all three (e.g. vite-plugin-node-polyfills). The signer holds a copy of the root key,
  the whole tree's secret, for as long as it lives, and under Node the library leaves copies of
  key bytes in Buffer's shared pool after it signs.
- `@txnlab/zerosignal/accounts/solana`: the Solana account of a BIP-39 phrase, at
  m/44'/501'/0'/0' (SLIP-0010) with an empty passphrase, so the chat app's 24-word phrase
  imported into Phantom or Solflare shows the same address. `solanaKeyFromPhrase(phrase)` takes
  12 to 24 words, validated as `accounts/xhd` validates them; `solanaKeyFromEntropy(bytes)`
  derives from the same 32 bytes as `xhdRootFromEntropy`. `solanaSigner(key)` signs as the
  account and holds its own copy of the seed. It needs the optional peer dependency
  `@scure/bip39`.

Each signs only as its own address: `signBytes` (or a Solana signer's
`signTransactionMessage`) for any other rejects with `SignerAddressError`.

A `SolanaSigner` is a `PayerSigner` plus `signTransactionMessage(address, message)`: raw
Ed25519 over a Solana transaction's message bytes, the same primitive as `signBytes`, so a host
whose key lives in a worker implements both by forwarding to one sign operation there, and
nothing that signs through the port needs the key. It signs whatever it is handed. A node's open offer and a relayer's ack
reach it only through `completeOpenOffer` / `completeRelayedAck` in
`@txnlab/zs-proto/solana/zsescrow`, which check the whole message first and put the signature in
the payer's slot; `testdata/solana_sign_vectors.json` pins the signed bytes to Go's keystore.

### `signBytes` is raw Ed25519

The SDK signs a 32-byte sha256 digest of a domain-tagged canonical body, verbatim. This is
**not** go-algorand-sdk's `SignBytes` (which prepends `MX`) and not ARC-1 `signData`. A wallet
whose sign-bytes flow tags or prefixes the message cannot implement the port. The SDK also
refuses to sign for any address but the payer's (`payerBytesSigner`), so a multi-account
signer cannot sign a reserve with the wrong key.

## Configuration

```ts
import { resolveConfig, testnet } from '@txnlab/zerosignal'

const config = resolveConfig({ signer, network: testnet() })
```

`network` defaults to mainnet. Testnet and mainnet embed the escrow application id; localnet
and private deployments set `network.escrowAppId`. Durations are milliseconds. A config the SDK
cannot run with throws a `ZsError` with kind `invalid_request` and code `invalid_config`.

On Solana, pass the payer's Solana key as `solanaSigner` and a Solana network. `signer` is
for Algorand only, and each rail refuses the other's signer and network fields:

```ts
import { resolveConfig, solanaDevnet } from '@txnlab/zerosignal'
import { solanaSigner } from '@txnlab/zerosignal/accounts/solana'

const config = resolveConfig({ solanaSigner: solanaSigner(key), network: solanaDevnet() })
```

The `devnet` and `localnet` presets embed the `zs_escrow` program id and an RPC endpoint.
`rpcEndpoint` overrides the endpoint, verbatim. An endpoint with no preset must set `program`.
The USDC mint is read from the program's Config.

## Client

`Client.create(config)` builds the payer. One Client serves every concurrent turn. It builds
the operator registry, the reserve client and the wallet when `Config` leaves them out. Building
the wallet reads the escrow's config from chain, so `create` fails if algod, or on Solana the
RPC endpoint, can't be reached.

### Discovery

Without `Config.registry`, `Client.create` builds the SDK's discovery, as the Go SDK's `zs.New`
does: a `ChainOperatorSource` reading the escrow's operator and node boxes from the network's
algod, or on Solana the program's operator and node accounts through `SolanaChainReader`, and a
`DiscoveryRegistry` that refreshes it. Once started it reads the chain and probes a
bounded set of nodes every `refreshInterval`, and a read older than `maxCacheAge` refreshes
first. A node it did not reach keeps its last-known models for `maxCarryAge`. The catalog is
saved to `Config.storage` in the Go SDK's format, under `zs.catalog.<deployment key>` since
operator and node ids repeat across networks, so after a restart the nodes the first probe
does not reach keep their saved models. The deployment key is `resolveNetwork(network).key`,
`<rail>-<network>-<escrow>` such as `algorand-mainnet-3628061142`; a catalog saved under the
bare app id by an earlier SDK is read once and then deleted. The registry, its source and the stores it builds run on
`Config.clock`; the Go SDK's run on the wall clock. The registry probes each node through a relay unless
`privacy` is `direct`, dials with `Config.fetch`, verifies TEE evidence with `teeVerifier`, and
applies the same staging gate as routing (`allowStaging`). `close()` stops it.

`Config.discovery` tunes it, each setting in milliseconds or a count, a non-positive value
taking the default:

| Setting | Default | Purpose |
|---|---|---|
| `refreshInterval` | 300 000 | Time between refresh cycles. |
| `refreshTimeout` | 30 000 | One refresh cycle: the chain read and its probes. |
| `probeBudget` | 96 | Details probes per cycle; the rest of the fleet carries forward. Up to three quarters go to the recently requested models' fastest servers and then to nodes with nothing on record (no attempt in this process, no answer saved or carried); the rest sweeps the fleet in turn. |
| `targetTopK` | 8 | Targets probed in full per recently requested model. |
| `maxCacheAge` | 900 000 | A read of a snapshot older than this refreshes first. |
| `maxCarryAge` | 5 400 000 | How long a node not reached stays routable on its last answer. |
| `latencyStateMax` | 4096 | Entries per keying in the built latency store. |
| `detailsTimeout` | 2 000 | One details probe, and the attestation probe after it. |
| `detailsConcurrency` | 24 | Probes in flight at once. |
| `operatorIds` | all | Discover only these operators, each of which must exist. |

**Boot differs from Go's.** `create` waits for the saved catalog and one chain read
(`registry.ready`): up to 5 s to load the catalog, a minute for the chain read and 5 s to save
it again, and `create`'s signal bounds that wait. The first probe of every node then runs in the
background, and the first request, or any read of the registry, waits for it. `zs.New` waits for
the probe too. When the chain read fails, `create` still succeeds: the registry serves the saved
catalog, or nothing, and retries on its timer. A boot fleet holding a duplicate or zero node id
fails `create`, as in Go.

**The routing stores are shared.** With a built registry the Client builds each routing store
`Config.stores` leaves out (see [Routing stores](#routing-stores)) and hands every one, supplied
or built, to both the probes and the requests, so a relay the probes charge is demoted in the
requests' relay choice and a relay a request charges is passed over by the probes. The built
reputation store judges a relay's claim that its target is down by the probes' last answer from
that target; a supplied one judges it by its own `targetReachable`.

**One registry across Clients.** A `RegistryProvider` passed as `Config.registry` is used as is
and never stopped: the host owns it. That suits a browser that keeps one fleet view while it
builds a Client per account or per session. `buildDiscovery` builds the registry exactly as
`create` would from the same `Config` (every `discovery` setting, `privacy`, `fetch`,
`teeVerifier`, `allowStaging`, `storage` under `catalogStorageKey(network)` with the
`legacyStorageKey` it had before, the logger and the clock), with the routing stores its probes
record to. A host that builds its own `DiscoveryRegistry` instead passes both keys itself, or a
catalog saved under the bare app id is never read again. Pass those stores and the resolved
`teeVerifier` to each Client, since a Client with a supplied registry builds no routing store
and would otherwise build a second verifier:

```ts
import { Client, type Config, buildDiscovery, chainAlgod, resolveConfig, testnet } from '@txnlab/zerosignal'

const shared: Omit<Config, 'signer'> = { network: testnet(), storage, logger }
const cfg = resolveConfig({ ...shared, signer })
const { registry, stores } = buildDiscovery(cfg, chainAlgod(cfg))
await registry.ready
registry.start()

const zs = await Client.create({ ...shared, signer, registry, stores, teeVerifier: cfg.teeVerifier })
// ...
await zs.close()     // leaves the registry running
await registry.stop()
```

Build every Client sharing the registry from the same settings: one that sets another
`allowStaging` or `privacy` routes on a fleet view built for different ones.

A host can also implement `RegistryProvider` itself: it lists the operators for a model,
resolves one node by its ref, lists every operator for the relay pool, re-probes a node whose
ephemeral key went stale, and records which models were asked for. `subscribe` on a
`DiscoveryRegistry` hands each cycle's snapshot to an app that renders it, the saved fleet
first.

### Algod

The algod client the SDK builds, for its wallet and its discovery, retries as the Go SDK's does
(`algod.DefaultTransport`): a request that got no response, a 429 or any 5xx is retried up to
20 times after the first attempt, waiting one second more before each (1 s, 2 s, …) up to 30 s,
or a longer `Retry-After` (seconds or an HTTP date), also held to 30 s. Every method retries,
transaction submits included: algod does not apply a resent transaction twice, though one that
landed behind a lost 5xx answers the retry with an "already in ledger" failure. Each
request's timeout and signal bound the retries too. Algod is the endpoint `network` names, so its
requests go through the global `fetch`, not `Config.fetch` and its private-address guard.
`retryingAlgod` builds the same client for a host's own `ChainOperatorSource`. The escrow config
reads `create` makes run under its signal and its 10 s bound, so none outlives a `create` that
gave up. In a browser the `Retry-After` of a cross-origin algod is
readable only when it sends `Access-Control-Expose-Headers: Retry-After`; without it the linear
schedule applies.

### Turns

```ts
import { Client, testnet } from '@txnlab/zerosignal'

const zs = await Client.create({ signer, network: testnet() })

const turn = zs.stream({
  endpoint: '/v1/chat/completions',
  body: JSON.stringify({ model, messages: [{ role: 'user', content: 'hi' }], stream: true }),
})
for await (const ev of turn.events()) {
  if (ev.type === 'delta.text') process.stdout.write(ev.delta)
}
const { settlement } = await turn.wait()
```

`stream(request, signal)` returns a `Stream` and sends nothing until `events()` is read. The turn
routes, reserves, pays, seals the body to the node and yields its events in order, then throws
the turn's error if it has one (`err` holds it too). `text()` runs the turn and returns only the
answer text. Each `Stream` can be read once.

- **Leaving early.** A loop that stops reading, or a `signal` that aborts, is a caller who left.
  Before the node finishes generating, the node is told to stop. After that, the SDK keeps
  reading for up to 10 s to collect the receipt and submit the settle, and the loop's exit
  waits for that. A receipt that does not arrive in time is left to the refund watchdog.
- **Settlement.** `wait()` resolves once the turn's escrow submit has returned, with what it
  submitted; call it after `events()` has started, or it rejects. A failed submit does not
  reject: it comes back as `err` beside a `settlement` that was attempted, not one that took
  effect. `wait()` does not wait for the transaction to land: the refund watchdog and the
  journal cover one that never does. A whole (non-streamed) reply emits no `settle.submitted`,
  so `wait()` is where its settle shows.
- **Stalls.** A streamed answer that stops sending ends with a `StreamIdleTimeoutError` in the
  error's `cause` chain: by default after 300 s with no first byte, 60 s between bytes after
  that, or 300 s while a tool the node runs is working. `Config.streamIdle` sets each bound, and
  `false` turns it off. A whole reply's body is held to the between-bytes bound, and one over
  256 MiB is refused; either ends the turn `read_upstream`, with the cause in its chain. The Go
  SDK's is `Config.StreamIdle`.

A `Request` is the OpenAI-shaped `body` for one `endpoint` (`/v1/chat/completions`,
`/v1/responses`, `/v1/images/generations`, `/v1/images/edits`) plus the routing preferences that
don't travel in it:

| Field | Purpose |
|---|---|
| `contentType` | The body's media type. Only a multipart image edit needs it. |
| `requireTee` | Route only to attested nodes, on top of `Config.requireTeeModels`. |
| `relay` | `"auto"`, `"off"` or `"required"`; anything else defers to `Config.privacy`, and `"off"` applies only with `Config.allowPrivacyOverride`. A `provider.relay` in the body outranks it. |
| `framesOnly` | Yield the node's frames without decoding them, for a caller that re-emits the bytes. |
| `admitNode` | A check of each node before anything is sealed to it. See below. |

`admitNode(op, signal)` is for content that needs more of a node than `requireTee` checks. The
turn asks it about each candidate before that candidate's reserve, again on every repeat sweep,
and about a node whose ephemeral key was just refreshed, since the request would then be sealed
to the new key. `op` is a frozen copy, and the reserve seals to the key it shows. A refused node
is skipped, as is one whose check throws; the turn fails `no_tee_capacity` only when every
candidate was refused. The Go SDK has no counterpart.

### Lifecycle

Open tickets are recorded in `Stores.journal`. When the Client runs the SDK's `Wallet` (built or
passed in) and no journal is given, it keeps an in-memory one, so a ticket a crash leaves open
is refunded only by hand; `journalDurable` says which you have. Each such Client needs its own
journal: `create` throws for one another live Client already sweeps. A journal is scoped by
deployment: `list(payer, network)` returns the rows `ownsRecord(network, row)` accepts, which
are those naming `network.key`, and rows an earlier SDK wrote with only `escrowAppId`.

To shut down, stop starting turns, `await zs.waitSettles(signal)` for the escrow submits still
running, then `await zs.close()`. `feeRate()` is the protocol fee in basis points this payer
pays, read from chain in the background: null until the first read lands, or when the wallet
can't read it.

### `zs.fetch`

`zs.fetch` is an OpenAI-compatible endpoint as a fetch function. Build an OpenAI client on it
once, and each request it sends becomes a turn of this Client, routed to a node per request:

```ts
import OpenAI from 'openai'

const openai = new OpenAI({ baseURL: zs.baseURL, fetch: zs.fetch, apiKey: 'unused' })
```

`baseURL` (`FETCH_BASE_URL`) names no server, so a client that loses the fetch fails rather than
reaching a host. Nothing reads the API key, and the SDK forwards no `Authorization` header. It
serves `POST` on the four endpoints above and on `/v1/completions`, which it emulates over chat,
and `GET` / `HEAD` on `/v1/models` and `/v1/models/{id}` (and `/models`), so
`openai.models.list()` lists the models the registry would route to now. Each entry is
OpenRouter-shaped, priced at the lowest rates any node declared plus the protocol fee, and has no
`pricing` until the fee has been read. A `Config.registry` without `allModels` has no catalog,
and those routes answer 501. Every other request gets a 404.

The response is the node's, as an OpenAI API would send it. Request headers set the turn's
preferences: `X-Zs-Relay`, and `X-Zs-Require-TEE` and `X-Zs-Usage-Frame`, which any non-blank
value turns on (`X-Zs-Require-TEE: false` requires a TEE). A whole reply reports its
cost in `X-Zs-*` response headers. A stream's headers go out before its receipt, so with
`X-Zs-Usage-Frame` set the stream carries the cost in an `event: zs.usage` frame instead. That
frame is opt-in because its data is not an OpenAI chunk, and strict OpenAI clients fail on it.
Network fees are reported in the rail's own coin: `X-Zs-Fees-Amount` in base units, with
`X-Zs-Fees-Currency`, `X-Zs-Fees-Decimals` and `X-Zs-Fees-Usd-Rate`, and the frame's
`network_fees` object. `X-Zs-Fees-Microalgos`, `X-Zs-Algo-Usd-Rate` and the frame's `algo_*`
keys are still sent, but only when the fees are in ALGO. A
failure the SDK reports itself is an OpenAI-shaped error body with `X-Should-Retry`, and
`Retry-After` when there is a wait to report. An error the node sends keeps the node's status
and body; the SDK sets those two headers and strips the node's `X-Zs-*` ones.

`openAIFetch(zs, options)` builds the same fetch with options `zs.fetch` leaves out, such as
the `fundingUrl` a `wallet_unfunded` error points at. It reads the network and logger off the
Client unless the options set them, and the hint shows only on mainnet.

### Sizing

A turn sizes each candidate against that operator's declared capacity before reserving with it.
The functions are exported and mirror the Go SDK's sizing (`sizing.go`, plus `reserveInputCount`
in `dispatch.go`), pinned by `reserve_sizing_vectors.json`, so a host that
estimates a reserve or explains a no-fit gets the numbers dispatch uses. A `SizingRequest` holds
the model, the v1 and v2 input bounds, and either a flat `maxOutputTokens` or `deriveMaxOutput`
with its `maxOutputCeiling`.

- `capacityOf(op, model)` is the operator's `ModelCapacity` for the model, or `undefined` when
  it declares none.
- `effectiveMaxOutput(op, req)` is the max_output that operator's reserve escrows.
- `fits(op, req)` is whether the input bound plus that max_output fits the operator's context
  window and the max_output its cap. An operator at wire 9.11 or later lets its backend decide
  fit, so it also fits an input bound up to 3 × its input ceiling (`window − max_output`). An
  operator that declares no capacity for the model fits any request.
- `maxDeclaredOutput(ops, model)` is the largest `maxOutputTokens` any of `ops` declares, or 0
  when one of them declares none: one uncapped operator leaves no ceiling to clamp a request
  to. A turn reads it over the operators it could route to, before any reserve, and reports a
  clamp as `max_output.clamped`.
- `reserveInputCount(op, model, body, maxOutputTokens)` is the `input_count` the reserve
  commits to, with the `boundVersion` it measured by (v2 for an operator whose protocol
  version uses the tight bound). It is the body's bound, plus tool-loop headroom when the body
  carries server-side tools (`DEFAULT_TOOL_HEADROOM_PER_ITERATION` per iteration for an
  operator that declares none), floored at `RESERVE_MIN_INPUT_COUNT` and capped to the window.
  A body carrying `previous_response_id` can't be measured, so it reserves all of the window
  the output leaves.

### Reserve retries and busy nodes

A reserve that fails for infrastructure reasons is retried before anything is paid, in two
layers, each mirroring the Go SDK's:

- **One candidate.** `reserveWithTransientRetry` asks the same node up to `INNER_ATTEMPTS`
  (3) times, on `@txnlab/zs-proto/transient`'s inner delay schedule or a longer `Retry-After`,
  and through a different relay each time when the request is relayed. With no relay left to
  rotate to it stops rather than go direct. A stale ephemeral key is re-probed once per
  candidate. Each retry emits `reserve.retrying`, and a rotation `relay.hop`. A relay is
  charged with a failure only when the verdict names it, or when a later relay reaches the
  same node; no reserve credits a relay.
- **The whole list.** When every candidate failed transiently and none refused, the turn
  walks the list again, up to `SWEEPS` passes in all, within `Config.retryBudget` (60 s by
  default). `Config.sweepDelay` replaces the wait schedule.

A busy node is the one refusal that clears by itself. A `429` raises `BusyError`, whose
`retryable` comes from `retryableBusyCode`: only `no_capacity` is worth re-asking, and
re-asking after `payer_slot_cap` costs the payer a penalty strike. When a candidate was busy
with a retryable code and no candidate refused for a reason waiting can't fix (a hard
refusal, a size rejection, no eligible relay), the turn re-sweeps up to `BUSY_RETRIES` (2)
more times, starting only within `BUSY_RETRY_BUDGET_MS` (8 s) of dispatch. `busyRetryWait`
picks the wait: `BUSY_RETRY_DELAY_MS` (1 s), or a node's `Retry-After` clamped to
`BUSY_RETRY_MAX_DELAY_MS` (3 s) when that is longer; `Config.sweepDelay` replaces both. A
pool still full at the end fails `operators_busy` with the longest hint as its retry-after.

## Routing stores

`@txnlab/zerosignal/routing` holds the payer's own routing signals: `RelayReputationStore`,
`RelayLatencyStore`, `TargetBackoffStore` and `NodeExclusionStore`, each mirroring a store in
the Go SDK, and `RelayHealthStore`, the transient exclusions and direct-contact verdict a
browser needs because it can't reach every node a server can. Relay selection
(`selectRelayHopWeighted`, `applyRelay`) comes with them. They are per-instance and take an
injected clock. A wall clock that steps back costs at most one window, since each store
re-dates a record it finds in the future. A `Client` routes with the ones passed in
`Config.stores`. When it builds its registry it builds each one left out and shares them all with
the registry's probes (see [Discovery](#discovery)); with `Config.registry` it keeps no such
signal for one left out. `RelayHealthStore` is the host's.

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
the recently requested models in `ModelDemand` and then by the nodes nothing is known about yet
(no `lastRefreshAt`, no `reachableAsOf`); `checkEphemeralAdvertisement` verifies a
node's signed ephemeral seal key and says why one is unusable (`recordEphemeralStaleness`
charges a relay that served a stale key).

An app that renders a `DiscoveryRegistry` snapshot reads each node's row verdict with
`reachabilityOf(op, now, maxCarryAge)`, the rule the registry advertises on (`advertisable`,
which gates `allModels` and `/v1/models`) less the staging and signer-funding terms a picker
filters on itself: `incompatible` for an answer on another wire major or with no version, `ok`
while the node's answer stands (`answeredWithin`, the liveness half of `advertisable`),
`probing` until the registry first tries the node, and `failing` after. `carryLapsesAt` says
when the next carried answer leaves the window, so rows built from one snapshot can age while
the registry publishes nothing. Pass the `discovery.maxCarryAge` the registry was built with; 0
or less is the default, as the registry reads it. Dispatch does not consult the verdict: a node
probed down keeps its carried models and stays a candidate.

`restoredProtoVersion` floors a version read back from storage to its major, as the saved
catalog does.

## TEE evidence

`@txnlab/zerosignal/tee` verifies a node's attestation evidence, running the Go SDK's
`zs/tee` checks in Go's order. `testdata/tee_verdict_vectors.json` pins the two to the same
verdict for a given outcome of the Intel chain check; the chain check itself differs from Go's
in where it fetches collateral and how it reads a PCCS error (see `sdk/src/tee/pccs.ts`).
`defaultVerifier()` trusts the dstack OS images and zs-node releases compiled into this release,
so a node running a newer release counts as unattested until the SDK is updated: it still serves
requests that need no TEE, but none that do. A served list would let whoever serves it decide
what counts as attested.

The TDX quote is checked against Intel's PCK chain by `@phala/dcap-qvl`, loaded the first time
a TEE node is verified. The verifier fetches Intel's collateral from Phala's PCCS mirror by
default, because Intel's own service sends no CORS header, so a payer on the default trusts
Phala to serve current documents; `defaultVerifier({ pccsUrl })`, passed as
`Config.teeVerifier`, names another. Collateral is cached in the verifier: reused for an hour,
and served for up to seven days while the PCCS is unreachable, before the node's own carried set
is consulted. So build one verifier and keep it. `Config.teeVerifier` defaults to one per
Client, and `disableTee` turns verification off.

A `DiscoveryRegistry` runs the attestation probe, through `ChainOperatorSource.enrichSubset`,
after each successful details probe, with the source's `teeVerifier`. The registry a Client
builds hands its source `Config.teeVerifier`, so evidence checks and the collateral cache are
the Client's; with `disableTee` it checks none, and every node reads as unattested. A registry
the host supplies needs that same verifier passed to its source. A registry of the host's own,
after a node's details probe has applied its
verified ephemeral key, calls
`probeAttestation` with that row, the details' `tee` advertisement, `client.config.teeVerifier`,
a `fetch`, and the probe's relay hop and timeout, and sets the `TEEStatus` it returns on the
operator. That is `undefined` when the node advertises no TEE or verification is off; evidence
that could not be fetched gives `verified: false` with `failureTag: 'fetch_failed'`. For a node
with no verified ephemeral key the evidence is not fetched at all, and the status has
`failureTag: 'ephemeral_unavailable'`:
the verifier would refuse it before reading the evidence, and its `key_binding_mismatch` would
read as the node attesting the wrong key.

Routing reads `isTeeAttested`, which `requireTee` and `Config.requireTeeModels` filter on. A node
is attested only when `verified` is true **and** both `osImageChecked` and
`composeReleaseChecked` are: the guest image matched a trusted production image, and the compose
matched a published zs-node release. `probeAttestation` copies the two from the verdict's
`detail.measurementChecks`. A pass that carries no checks, such as a stub, is not attested. Go's
`TEEStatus.Attested` applies the same rule, pinned by `operator_vectors.json`. A host that builds
its own `TEEStatus` must set both fields, and leaving them `false` reads as unattested. The rest
of `detail` is for display. A caller's abort is rethrown rather than recorded.

## Escrow app client

`@txnlab/zerosignal/escrow-client` is the typed `ZeroSignalEscrow` app client, generated by
algokit-client-generator (minimal mode) from the ARC-56 in this repository, with `APP_SPEC` and
the box record types. It needs `@algorandfoundation/algokit-utils` ^9.2.0, an optional peer
dependency that the rest of the SDK does not use. CI regenerates the client and fails if the
committed copy differs.

## Prepaid MBR pool

Each open ticket's box is paid for out of the payer's prepaid ALGO pool in escrow, so a request
carries no ALGO. A node may refuse a reserve from a payer who isn't opted into the pool
(`payer_not_opted_in`), so the SDK's `Wallet` makes the first deposit before the payer's first
reserve; a wallet you supply does the same if it implements `WalletOpener.prepareDeposit`.
When a node refuses with that code anyway (the deposit was closed elsewhere, or the first
deposit hasn't confirmed), the SDK calls `WalletOpener.recheckDeposit`, so a wallet that skips
the opt-in read once it has seen the deposit should implement it and read the opt-in again on
its next `prepareDeposit`.
`ensureMbrDeposit(chain, payer, slots)` funds the pool toward a working set of
`slots` concurrent tickets (`Config.concurrentSlots` by default), opting in on the first
deposit. The working set is an ideal rather than a requirement: a wallet that can't reach it
funds as many slots as it affords, counting a part slot already in the pool, and reports
`belowTarget`, and one that can't afford a single slot throws `MbrDepositUnaffordableError`
before anything is signed. `backedSlots` on the error tells a pool that can still serve from
one that can't, and `need` is what the next deposit costs: the free-quota box term when that
is what a serving pool lacks, else what the pool's part slot lacks of a whole one. `planMbrDeposit` is the
sizing on its own, Go's `planDeposit`, and `readMbrPool` / `mbrPoolState` report what is
deposited, reserved by live tickets, and withdrawable.

The chain arrives as an `MbrPoolChain`: the escrow app's readonly calls, the payer's spendable
balance, and the deposit group. Calls aren't single-flight, so a host that can run two at once
for one payer serializes them, or both may deposit.

## Doctor

`npx @txnlab/zerosignal doctor --address <address> [--network testnet]` checks what an Algorand
payer address needs before a request can succeed, without signing anything (the command takes
Algorand networks only): algod, the escrow app (and that its admin hasn't paused it),
the account's ALGO, its USDC opt-in and balance, the prepaid MBR pool (and what the first
request will deposit), and one discovery cycle over the fleet. It exits 1 when a check fails,
2 on a usage error and 3 when the doctor itself fails. `--json` prints the report, `--direct`
probes nodes without relays, `--allow-staging` and `--allow-private-hosts` match a Client's
settings of those names, and `--algod-url`, `--algod-token` and `--escrow-app-id` point it at
another chain. `diagnose(config, address)`
is the same as a function, taking a `Config` without a signer, and `doctorChecks(readings)` is
the judgment alone. On a Solana network `diagnose` takes a base58 address and checks that rail
instead: the RPC, the program's Config (that its genesis hash is the cluster's the RPC
serves, and that the program isn't paused), the account's SOL, its USDC token account and
balance, the ticket rent pool, and the fleet against the lamports floor;
`solanaDoctorChecks(readings)` is that judgment. Go's
`zs.Diagnose`, `zs.DoctorChecks` and `zs.SolanaDoctorChecks` are the twins, and
`testdata/doctor_vectors.json` pins the checks' statuses and wording across the two.

## Errors and events

The SDK's own failures are `ZsError`s. Branch on `kind`, the stable contract; `code` is
diagnostic and may gain values. Two exceptions carry fields a caller acts on:
`SignerAddressError`, which `payerBytesSigner` rejects with when asked to sign for another
address, and `MbrDepositUnaffordableError` from `ensureMbrDeposit`. `findError(err, Class)`
looks for one through an error's `cause` chain: a streamed turn that stalls ends with a
`StreamIdleTimeoutError` there.

A turn's events are a discriminated union on `type`, with Go's event names and fields in lower
camel case:

- **Routing and reserve:** `max_output.clamped` (before any reserve), `route.candidates`,
  `relay.hop`, `reserve.started`, `reserve.retrying` and `reserve.succeeded`.
- **Payment:** `payment.committed`, once algod accepts the escrow open. Nothing is resent after
  it; a later failure ends in settle, protest or refund.
- **Response:** `response.started`, then `frame` (one per server-sent event as bytes; a whole
  reply is one frame) and the decoded content: `item.opened` / `item.closed`, `delta.text`,
  `delta.reasoning`, `delta.tool_call`, `annotation.added`, `tool.status`, `image.progress`,
  `image.partial` and `usage`.
- **Receipt and settlement:** `receipt.verified`, then on a stream `settle.submitted`. When
  the node's pre-signed settle group fails its check, the payer acks on its own instead
  (`atomic: false`), and with `Stores.nodeExclusions` set `node.excluded` comes first and bars
  the node (`reason: 'settle_group_rejected'`). Before that ack, and after a node's group fails
  to submit, the payer reads the node's own claim on the ticket. One above the receipt gets the
  payer's settle anyway, which freezes the ticket (`settle.submitted` with `frozen: true`), and
  bars the node (`reason: 'settle_claim_exceeds_receipt'`). One that differs without taking
  more is not acked, and no `settle.submitted` follows. After a failed group submit, a ticket
  with no claim on it gets the payer's own half (`settle.submitted` with `atomic: false`). On an
  escrow contract without `resolveFrozen`, the payer sends neither that half nor a freeze: the
  over-claim's node is still barred, and no `settle.submitted` follows. `receipt.violated` replaces
  `receipt.verified` when the receipt fails its check, and no settle follows; when a refused
  protest falls back to freezing an over-claim, `node.excluded` follows it. A receipt the node
  validly signed for another ticket is `receipt.violated` with `violation: 'sig'`, followed by
  `node.excluded` (`reason: 'receipt_names_other_ticket'`); a receipt whose signature fails bars
  no node.
- **End:** `done`, for a turn the node sealed as finished. A failed turn ends with the events
  loop throwing instead.

The set grows, so a consumer must ignore types it does not handle.

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
