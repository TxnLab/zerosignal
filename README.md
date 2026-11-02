# ZeroSignal

Privacy-first, OpenAI-compatible inference network. A **ZeroSignal client** [`age`](https://age-encryption.org)-encrypts each request and ships it to a remote **node**, which decrypts, forwards to an upstream LLM, and seals the response back. Per-request payment is escrowed in an Algorand smart contract and co-signed for settlement after the node delivers a signed usage receipt.

## Service map

```
   ┌──────────────────────────────────────────────────────────────────┐
   │                         ZeroSignal client                        │
   │                                                                  │
   │  Encrypts requests, opens escrow, ack-settles. Two common forms: │
   │                                                                  │
   │   • A ZeroSignal-aware app (web app, agent, daemon) built on a   │
   │     payer SDK: @txnlab/zerosignal (TS) or go/zs (Go).            │
   │   • The proxy daemon, built on go/zs, which exposes a vanilla    │
   │     OpenAI /v1 surface and bridges plaintext clients (tui,       │
   │     OpenAI SDKs, LM Studio, test harnesses) into the protocol.   │
   └────────────────────┬───────────────────────────┬─────────────────┘
                        │                           │
            Payment+open atomic group,              │  age-encrypted
            ack-settle / protest                    │  envelope
                        │                           │  (AAD-binds ticket
                        ▼                           ▼   + app-call txid)
            ┌──────────────────────┐         ┌──────────────────┐
            │        algod         │         │       node       │
            │                      │ ◀────── │  decrypts,       │
            │   running the        │ verify  │  forwards,       │
            │   ZeroSignalEscrow   │ open    │  seals,          │
            │   contract:          │         │  signs receipt,  │
            │   • operator registry│ ──────▶ │  posts op-side   │
            │   • per-ticket       │ op-side │  settle          │
            │     escrow boxes     │ settle  └────────┬─────────┘
            └──────────────────────┘                  │
                                                      │ plaintext OpenAI
                                                      ▼
                                                ┌──────────────┐
                                                │ upstream LLM │
                                                │ (OpenAI,     │
                                                │  vLLM, LM    │
                                                │  Studio, …)  │
                                                └──────────────┘
```

Key invariant: **all client→node traffic is encrypted**. There is no plaintext path between a client (or its proxy) and a node. Plaintext OpenAI exists only on the two end-segments — between a vanilla client and its local proxy, and between the node and the upstream LLM it forwards to.

Transport privacy: in the default privacy-on mode the sealed envelope is not sent straight to the serving node. A second node acts as a **relay** that blindly forwards it, so the target never sees the caller's network identity. Relay vs. target selection is covered in [`docs/operator-node-selection.md`](./docs/operator-node-selection.md) and [SPEC §3f](./SPEC.md).

Privacy posture: **upstream non-retention is the default; node-side and proxy-side non-retention are unconditional.** Two layers carry it: (1) the proxy and node both default `store: false` on every admitted request before it leaves for the upstream LLM, so a curl one-liner or unsophisticated SDK doesn't silently inherit OpenAI's retention default; clients that need server-side retention features (e.g. Responses API `previous_response_id` continuation) may opt in by sending `store: true` explicitly, accepting that the upstream provider will retain the request and response under the operator's account; (2) operators MUST NOT log, persist, mirror, or otherwise retain decrypted request or response content on the node — only metadata needed for settlement and observability (token counts, ticket IDs, addresses, latency, charges). See [SPEC.md "Prompt and response non-retention"](./SPEC.md).

User and operator documentation lives at [docs.zerosignal.ai](https://docs.zerosignal.ai).

## What's in this repo

The protocol specification, its two reference implementations, and the payer SDK built on each.
The implementations are kept byte-compatible by shared golden vectors.

The system around it: **`zs-proxy`** is a localhost, single-user (payer) daemon that exposes a
plain OpenAI `/v1` surface and speaks the protocol on the caller's behalf through the Go payer
SDK, `go/zs`. **`zs-node`** is the operator daemon: it decrypts envelopes, forwards them to an
upstream LLM, signs usage receipts, and settles on chain; it uses the protocol packages but not
`zs`. The **`ZeroSignalEscrow`** contract holds the operator and node registry and per-ticket
escrow. The **ZeroSignal web app** speaks the protocol directly from the browser and runs each
turn through the TypeScript payer SDK, `@txnlab/zerosignal`. Source paths such as `proxy/internal/...` or
`client/src/...` that appear in SPEC.md and `docs/` refer to those implementations.

### Specification

- [`SPEC.md`](./SPEC.md) — authoritative envelope format, AAD binding, two-phase admission, sealed-response shapes, error model. Section references like §5.3 in implementation code point here.
- [`ENCRYPTION_OVERVIEW.md`](./ENCRYPTION_OVERVIEW.md) — orientation map of the encryption layers (which keys exist, what each protects). Note the **mandatory forward secrecy** model: the node holds no long-lived encryption key — requests seal to a short-lived, in-memory **ephemeral age key** the node advertises and signs; trust roots in the on-chain Ed25519 signing key.
- [`TEE.md`](./TEE.md) — what a TEE-attested node proves and how a payer verifies it.
- [`docs/admission-tag.md`](./docs/admission-tag.md) — proof-of-possession HMAC that prevents mempool-race ticket hijack.
- [`docs/operator-node-selection.md`](./docs/operator-node-selection.md) — how `model X` resolves to a ranked target node and a privacy relay: the shared golden-vectored eligibility/price/diversity policy vs. the app-side RTT/TTFT/tok-s signals layered on top.
- [`docs/multi-turn-content.md`](./docs/multi-turn-content.md) — what each chat surface replays into the next turn (reasoning is **never** sent back), and what the proxy/node mutate or strip in transit.
- [`docs/*.puml`](./docs/) — PlantUML sequence diagrams for the reserve, request/response, ticket-lifecycle, and escrow-payment flows.
- [`CHANGELOG.md`](./CHANGELOG.md) — protocol version history.

### Go — [`go/`](./go/), module `github.com/TxnLab/zerosignal/go`

The canonical implementation; it generates every golden vector.

| Package | Surface |
|---|---|
| `wire` | Envelope types (`RequestEnvelope`, `ResponseEnvelope`), `WrapRequest` / `DecryptRequest` / `ResponseSealer`, AAD helpers (`BuildBodyAAD`, `BuildFrameAAD`), admission-tag HMAC, body-hash helpers, the sealed inner frame, ephemeral identity. |
| `ticket` | `Ticket` + `UsageReceipt` + reserve shapes; `BytesSigner` + Algorand address codec; `TicketSigDigest` / `ReceiptSigDigest` / `CommitResponseKey`. |
| `selection` | Shared operator- and relay-selection policy: eligibility, price, owner diversity, `DeriveMaxOutput`. |
| `pricing` | Token-pricing math; `VerifyTicketPrice` checks a signed ticket's price before a payer escrows it. |
| `imageprice` | Deterministic image-generation pricing from (size, quality) and an operator's image rate. |
| `tokenize` | Model-agnostic input-token bound used to size a reserve and enforce it at inference time. |
| `transient` | Classifies a failed request as retryable or terminal, with the shared retry schedule; the reserve `429` busy codes and `RetryableBusyCode`; `RetryableAfterPayment`. |
| `steering` | The arithmetic behind a payer's own routing signals: relay-reputation decay, target backoff windows, and the weights-digest consensus. The stores they feed belong to each SDK: `go/zs` and `@txnlab/zerosignal/routing`. |
| `relay` | Relay-indirection metadata and the closed allow-list of inner paths a relay forwards. |
| `attest` | TEE measurement checks: Intel TDX quote parsing, dstack event-log replay into RTMR3, compose-file policy, PCK chain and collateral, and the trusted dstack OS images and zs-node releases. |
| `inject` | Body mutators applied before sealing (`DefaultStoreFalse`, `DropEmptyTools`, `DropRoutingPreferences`, `InjectSafetyIdentifier`, `InjectStreamOptionsIncludeUsage`) plus `FitsContextWindow`; discovery shapes (`OperatorDetails` / `OperatorDetailsModel` / `ModelReasoning`, `TEEAdvertisement` / `TEEEvidenceBundle`). None touch message/reasoning/tool history. |
| `tools` | Built-in tool registry + tool-loop helpers (chat/responses rewriters, frame stitchers, marker/effect/status frame marshaling). |
| `settle` | The settlement rules every payment rail shares: the ticket view, `Classify` (what call a live ticket allows now), and the protocol fee math (`NetFee`, `ComputeFeeBreakdown`). |
| `escrow` | `ZeroSignalEscrow` ABI client (embedded ARC-56 JSON). `ComposeOpen` / `ComposeSettle` / `ComposeProtest`, `VerifyOpenAppCall` / `VerifyOpenGroup`, box decoders, operator-registry helpers. |
| `solana` | The Solana rail's wire layer: keys and base58, program derived addresses, the transaction message codec (legacy, and v0 without lookup tables), and the token and compute-budget instructions the rail needs, all checked against the transactions the `zs_escrow` program's own tests build, whose token and compute-budget instructions come from those programs' interface crates. Hand-rolled rather than `solana-go`, whose dependencies every consumer would build. `TransactionSigner` is the custody seam for a transaction signature, and `Transaction.SignWith` puts one in its signer's slot. `solana/idl` holds the program's IDL. |
| `solana/zsescrow` | The `zs_escrow` program: its addresses, a builder per instruction (each deriving the program addresses from operator and node ids), its account and event decoders, `VerifyOpenOffer` and `VerifyRelayedAck`, the payer's checks of a node's open offer and a relayer's ack before it co-signs, and `CompleteOpenOffer` / `CompleteRelayedAck`, which run those checks and only then sign. Also the cluster presets (`ClusterPreset`: RPC endpoint and program id per cluster), which the payer SDK and the node share. |
| `algod` | Thin `Client` interface over the algod SDK, plus per-network presets (escrow app id, endpoints). |
| `algo` | Adapts a keystore entry into a `TransactionSigner` for `AtomicTransactionComposer` groups. |
| `keystore` | Signing-mnemonic loader: `<NAME>_MNEMONIC` env vars + `ZS_MNEMONIC_URLS` cloud-secret URLs (AWS/GCP/Azure). See [`go/keystore/README.md`](./go/keystore/README.md). |
| `wallet` | A payer's local wallet: generate or import a recovery phrase, held in the OS keychain or a passphrase-encrypted file, shared by every zerosignal program on the machine. Feeds `keystore` through `Wallet.Provider`; `LoadPayer` loads it with the environment's keys and picks a `zs.Signer`, and `LoadSolanaPayer` a `zs.SolanaSigner`. `LoadKeys` / `LoadSolanaKeys` load the same keys unchosen, and `ChoosePayer` / `ChooseSolanaPayer` pick among them, for a host that signs as several addresses; `ReadEnvKeys` reads the environment once for a host that decides something from it before loading. |
| `httpx` | A tuned, shared `http.Transport` for node↔node and payer↔node calls, with a private-address dial guard. |
| `gcplog` | `slog` attribute names for Google Cloud Logging. |
| `zs` | The Go payer SDK: operator discovery, routing, reserve, escrow `open` / settle / refund, receipts, and `Diagnose`, the read-only doctor. Used by `zs-proxy`, the TUI's `-direct` mode, and `cmd/zschat`. |
| `zs/handler` | The OpenAI-compatible HTTP surface over a `zs.Client`: chat completions, responses, the emulated `/v1/completions`, image generation and edits, model discovery, `/v1/zs/details`. |
| `zs/tee` | Verifies a node's published attestation evidence: the bundle checks every platform shares, the dstack TDX verifier, and the process-wide Intel collateral cache. |
| `zs/tokenize` | The safe input-token upper bound a payer reserves against. |
| `cmd/releasenotes` | Release-notes generator used by the `zs-proxy` and `zs-node` release builds. |
| `cmd/zschat` | One chat-completions prompt through `zs`, streamed to stdout, with the `zs-proxy` wallet and a journal on disk. |
| `examples/` | Runnable programs: `chatstream`, `discovery`, `openaishim`, each with its own README. [`examples/README.md`](./examples/README.md) indexes them with the TypeScript ones. |

### TypeScript — [`ts/`](./ts/), npm package `@txnlab/zs-proto`

A port of the vectored Go packages so a browser can speak the protocol directly to a node.
Subpaths: `wire`, `ticket`, `selection`, `pricing`, `imageprice`, `tokenize`, `transient`,
`steering`, `relay`, `attest`, `inject`, `escrow`, `settle`, `solana`, `tools`, plus the fixtures under `testdata/*`. See
[`ts/README.md`](./ts/README.md).

Wire-shaped types use snake_case property names matching the JSON wire format, so `JSON.stringify(envelope)` produces the bytes the Go side emits — no field-rename layer. Function names are camelCase.

Not ported (intentionally): file-IO identity loaders, the Go `reflect+unsafe` ephemeral-key wipe (JS strings are immutable; see `ts/README.md` "Secret-key lifetime"), the `algo/`, `algod/`, `keystore/` subpackages, the node-side half of `tools/` (request rewriters, tool loop, markup recovery), and the chain-access half of `escrow/` (box reads, and checking and completing the node-built
open and settle groups), which the TypeScript SDK below carries instead (`sdk/src/escrow/`, and
`algod/`'s retrying transport in `sdk/src/algod-transport.ts`).

### TypeScript SDK — [`sdk/`](./sdk/), npm package `@txnlab/zerosignal`

The twin of `go/zs`, released in lockstep with it; the ZeroSignal web app runs on it. It holds the
payer client (routing, reserve, escrow `open` / settle, sealing, relay hops, streaming, receipt
checks), the shared API vocabulary (events, error kinds, config and its defaults, network
presets), and the ports a host app implements (signer, storage, cache, logger, clock, fetch).
Its `Client` builds operator discovery (`DiscoveryRegistry`) when `Config.registry` is absent, as
`zs.New` does, with one difference at boot: `zs.New` waits for the chain read and a probe of every
node, while `Client.create` waits only for the chain read, and the first request waits for the
probe. A host can still supply its own registry, or share one across Clients. It depends on
`@txnlab/zs-proto` at exactly its own version and re-exports it under
`@txnlab/zerosignal/proto`. The names it shares with Go are pinned by
`testdata/sdk_vocabulary_vectors.json`. See [`sdk/README.md`](./sdk/README.md).

### Examples — [`examples/`](./examples/)

Runnable programs for both SDKs: a streamed chat turn, the OpenAI SDK over `zs.fetch`, a fleet
listing that pays nothing, one turn built from the SDK's parts, a durable ticket journal, image
generation, and a localnet setup. The TypeScript ones are pnpm workspace members on
`@txnlab/zerosignal` `workspace:*`; the Go ones live in [`go/examples/`](./go/examples/) inside the
module. `make test` compiles all of them but runs none. See
[`examples/README.md`](./examples/README.md).

### Golden vectors — [`testdata/`](./testdata/)

Each vectored Go package writes its fixture (`vectors.json`, `selection_vectors.json`, …) from
a `Test*Vectors` test, and the matching `ts/test/*-vectors.test.ts` reads it unchanged, so
byte-format drift between the two implementations fails on either side. `make update-vectors`
regenerates them all; `make check-vector-generators` (part of `make test`) fails if a generator
is missing from that target.

Two fixtures pin the sealing framing instead, and are captured rather than derived (nonces and
age wrapping are random): `sealed_vectors.json` is sealed by Go and opened by TS, and
`ts_sealed_vectors.json` is sealed by TS and opened by Go. Regenerate them only when the framing
changes on purpose, with `make update-sealed-vectors` and `make update-ts-sealed-vectors`.

## Setup (shared across services)

**Algorand network.** Every service that touches chain reads `algod.network: localnet | testnet | mainnet` (with optional `algod.endpoint` / `algod.token` overrides). Resolves to nodely.dev for testnet/mainnet, `http://localhost:4001` for localnet.

**Node identity.** No age-key setup. Under mandatory forward secrecy the node holds **no** long-lived encryption key — request envelopes seal to an in-memory **ephemeral age key** the node generates, rotates on a fixed cadence, signs under its Ed25519 key, and advertises at `/v1/zs/details`; it is never persisted (there is no `node.key` / `identity_path`). See [`ENCRYPTION_OVERVIEW.md`](./ENCRYPTION_OVERVIEW.md). An operator's only persistent secret is its **signing mnemonic** (below).

**Signing mnemonics.** Both proxy (payer) and node (operator) load Algorand mnemonics via `proto/go/keystore`. Either set `<NAME>_MNEMONIC` env vars or point `ZS_MNEMONIC_URLS` at cloud-secret URLs. See [`go/keystore/README.md`](./go/keystore/README.md) for the full reference.

**Configuration.** Each Go service reads `./config.yaml` by default; override with `--config` or the `<SERVICE>_CONFIG` env var. Per-service `config.example.yaml` is the canonical reference. The proxy carries no upstream LLM credential — admission to the operator is via the on-chain seal, not a bearer token. The node's LLM provider key comes from env (`NODE_LLM_OPENAI_API_KEY`); never commit it.

## Build & test

```bash
pnpm install               # one workspace: ts/, sdk/ and examples/*
make test                  # guards (check-vector-generators, check-no-hayai, check-lockstep,
                           # check-escrow-client) + Go suite + ts suite + sdk typecheck/test/build/test:dist
                           # + examples typecheck and the browser example's bundle
make vet typecheck
make verify-vectors        # read-only: every fixture matches current Go output; Go opens the TS-sealed one
make update-vectors        # regenerate fixtures after an intentional format change
cd go && go test -race ./...   # before crypto/streaming changes
cd ts && pnpm build
```

The Solana rail also runs end to end on a local validator: each SDK against a stub node
(`go/internal/solanastub`) and the real `zs_escrow` program, through a settle on the payer's ack,
a protest, an over-claim freeze and the admin's resolve of it, a refund of an unserved ticket, a
refund forfeited to the treasury by a payer whose USDC account is closed, a lapse, an open sent
after its blockhash expired, two concurrent turns the payer can afford one of, and free turns with
and without a free credit from the stub's issuer. The Go scenarios
run the stub in-process; the TS ones build and spawn it (`go/cmd/solanastub`) and check the chain
through its `/stub/` routes. Start the validator with contracts-solana's `make localnet`, then:

```bash
ZS_SOLANA_E2E_RPC=http://127.0.0.1:8899 \
  ZS_SOLANA_E2E_MINT_AUTHORITY=$HOME/.config/zs-solana/deployer.json \
  make solana-e2e    # about 2 min a suite: two scenarios wait out a deadline
```

Without the endpoint and a key the scenarios skip, so `make test` and this repo's CI never need a
validator. The mint's authority is also the localnet Config's admin: the run shortens the default
grace to 60 s, and refuses an endpoint off this machine.

The same suites run on devnet with a funder in its place, a wallet holding SOL and test USDC that
it hands out by transfer and that holds no power over the program:

```bash
# Once: register the stub's node. The URL is the loopback address later runs serve on.
cd go && go run ./cmd/solanastub -rpc <devnet endpoint> -funder /abs/funder.json \
  -register-node http://127.0.0.1:18765 -identity-out /abs/stub-identity.json

# Each run. The paths are absolute: the suites run from go/ and sdk/.
ZS_SOLANA_E2E_RPC=<devnet endpoint> ZS_SOLANA_E2E_CLUSTER=devnet \
  ZS_SOLANA_E2E_FUNDER=/abs/funder.json ZS_SOLANA_E2E_STUB_IDENTITY=/abs/stub-identity.json \
  make solana-e2e
```

The grace is then the cluster's, so the deadline scenarios take longer. Each payer hands what it
has left back to the funder at the end, except what a frozen ticket holds, which only the admin
can release. The identity file holds the node's signing phrase and its owner's, which unregisters
it, so keep it as a secret. Off this machine a funder run serves only as a registered identity,
so nightly runs reuse one operator rather than stake a new one each time.

contracts-solana's `make integration` and its `integration` workflow run both suites on a
throwaway validator, with a real zs-node and zs-proxy; `-register-node` registers that node too,
since zs-node has no Solana register command.

## Releasing

Go, `@txnlab/zs-proto` and the `@txnlab/zerosignal` SDK release in lockstep: one version
number, all three tags on the same commit. Three commands do it:

```bash
make release-pr VERSION=X.Y.Z   # version commit on release/vX.Y.Z, pushed, PR opened
# squash-merge the PR
make release-tag                # tags the version commit, after a y/N confirmation
make release-status             # tags, release.yml runs, npm, Go module
```

What they do, step by step:

1. `release-pr` refuses a version not above both `main`'s and the latest `go/v*` tag. It
   branches `release/vX.Y.Z` off `main`, sets `version` to `X.Y.Z` in both `ts/package.json` and
   `sdk/package.json`, relabels each `###` CHANGELOG heading ending `(unreleased)` to `(X.Y.Z)`,
   runs `scripts/check-lockstep.sh`, commits `ts, sdk: X.Y.Z`, pushes the branch and opens the
   PR. It leaves your checkout on that branch.
2. `release-tag` reads the version from `main`'s package.json files, so the tags can only name
   what they say, and tags the commit that set it, not `main`'s tip: a PR merged after the
   release PR stays out of the release. It tags that commit `go/vX.Y.Z`, `ts/vX.Y.Z` and
   `sdk/vX.Y.Z` and pushes exactly those three, atomically. GitHub starts no workflow for a push
   of more than three tags, so never `git push --tags`. Re-running it is safe: it pushes only
   the tags missing from the remote and refuses, pushing nothing, when one already points at
   another commit. `scripts/release.test.sh` (in `make test`) pins these guards.
3. The Go module is live as soon as the tag is pushed (`go get github.com/TxnLab/zerosignal/go@vX.Y.Z`,
   with the private-repo setup below).
   Each of the `ts/v*` and `sdk/v*` tags runs [`release.yml`](./.github/workflows/release.yml),
   which runs the full test suite and **stages** that npm package. It does not publish it.
   The SDK is staged from its `pnpm pack` tarball, which pins `@txnlab/zs-proto` at `X.Y.Z`,
   and only when `ts/vX.Y.Z` is on the same commit.
4. A maintainer approves each staged package with 2FA, either in the package's *Staged
   Packages* tab on npmjs.com or with `npm stage approve <id>`. Only then is it installable.
   Approve `@txnlab/zs-proto` first: the SDK can't be installed until the version it pins is.
   If the zs-proto job failed, reject the staged SDK too.

A new package needs a one-time setup before its first tag: npmjs.com lets a trusted publisher be
added only to a package that exists, so publish its first version by hand with
`pnpm publish --access restricted` (pnpm, because `npm publish` would ship a `workspace:*`
dependency literally), then add a trusted publisher for `TxnLab/zerosignal`'s `release.yml` that
may only stage.

While this repo is private, so are new releases. Both npm packages publish with
`--access restricted` and no provenance (npm generates provenance only for a public package from a
public repo), and installing them needs a token that reads the `@txnlab` scope. The Go module
needs `GOPRIVATE=github.com/TxnLab/*` and git credentials for `TxnLab/zerosignal`. `go/v0.1.0`
and `go/v0.1.1` predate this and stay public on the Go module proxy. Going public means flipping
the repo, `publishConfig.access` in both `package.json` files, the `--access` and `--provenance`
flags in `release.yml`, and the access value its two metadata checks expect, together.

Under 0.x a minor bump is a breaking change and a patch bump is not. Never move or delete a
pushed `go/v*` tag: every consumer's `go.sum` has recorded its hash, so a moved tag fails their
builds with a checksum mismatch.

### When zs-node releases

Each verifier trusts only the zs-node releases compiled into it, so a node on a release a payer
doesn't list counts as unattested there: it still serves requests that need no TEE, but none that
do. Each node tag runs zs-node's `release-allowlist.yml`, which opens one pull request here. It
appends the release's image and its two compose skeletons (CPU, and GPU with sealed local models)
to `go/attest/releases.go`, and regenerates `ts/src/attest/trust-lists.ts` from it, which
`TestTrustListTwinVectors` requires. If a pull request arrives with only `releases.go` changed (a
node tag cut before the workflow gained that step), regenerate by hand with
`cd go && go test ./attest -run TestTrustListTwinVectors -update-trust-lists`.

Merging it reaches no payer. Once it merges, cut a release here (`make release-pr`), then bump
the pins in zs-proxy and the web app; each trusts the new node release from its own next release
or deploy. zs-node itself needs no pin bump for it: a node reads only the OS-image list, and its
own image can't be in the release it was built against.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
