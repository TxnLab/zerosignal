# ZeroSignal

Privacy-first, OpenAI-compatible inference network. A **ZeroSignal client** [`age`](https://age-encryption.org)-encrypts each request and ships it to a remote **node**, which decrypts, forwards to an upstream LLM, and seals the response back. Per-request payment is escrowed in an Algorand smart contract and co-signed for settlement after the node delivers a signed usage receipt.

## Service map

```
   ┌──────────────────────────────────────────────────────────────────┐
   │                         ZeroSignal client                        │
   │                                                                  │
   │  Encrypts requests, opens escrow, ack-settles. Two common forms: │
   │                                                                  │
   │   • A ZeroSignal-aware app (webapp, agent SDK, daemon) that      │
   │     speaks the protocol directly.                                │
   │   • The proxy daemon, which exposes a vanilla OpenAI /v1 surface │
   │     and bridges plaintext clients (tui, OpenAI SDKs, LM Studio,  │
   │     test harnesses) into the protocol on their behalf.           │
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

The protocol specification and its two reference implementations. They are kept
byte-compatible by shared golden vectors.

The system around it: **`zs-proxy`** is a localhost, single-user (payer) daemon that exposes a
plain OpenAI `/v1` surface and speaks the protocol on the caller's behalf. **`zs-node`** is the
operator daemon: it decrypts envelopes, forwards them to an upstream LLM, signs usage receipts,
and settles on chain. The **`ZeroSignalEscrow`** contract holds the operator and node registry
and per-ticket escrow. The **ZeroSignal web app** speaks the protocol directly from the browser
using the TypeScript package below. Source paths such as `proxy/internal/...` or
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
| `transient` | Classifies a failed request as retryable or terminal, with the shared retry schedule. |
| `relay` | Relay-indirection metadata and the closed allow-list of inner paths a relay forwards. |
| `attest` | TEE measurement checks: Intel TDX quote parsing, dstack event-log replay into RTMR3, compose-file policy, PCK chain and collateral. |
| `inject` | Body mutators applied before sealing (`DefaultStoreFalse`, `DropEmptyTools`, `DropRoutingPreferences`, `InjectSafetyIdentifier`, `InjectStreamOptionsIncludeUsage`) plus `FitsContextWindow`; discovery shapes (`OperatorDetails` / `OperatorDetailsModel` / `ModelReasoning`, `TEEAdvertisement` / `TEEEvidenceBundle`). None touch message/reasoning/tool history. |
| `tools` | Built-in tool registry + tool-loop helpers (chat/responses rewriters, frame stitchers, marker/effect/status frame marshaling). |
| `escrow` | `ZeroSignalEscrow` ABI client (embedded ARC-56 JSON). `ComposeOpen` / `ComposeSettle` / `ComposeProtest`, `VerifyOpenAppCall` / `VerifyOpenGroup`, box decoders, operator-registry helpers. |
| `algod` | Thin `Client` interface over the algod SDK, plus per-network presets (escrow app id, endpoints). |
| `algo` | Adapts a keystore entry into a `TransactionSigner` for `AtomicTransactionComposer` groups. |
| `keystore` | Signing-mnemonic loader: `<NAME>_MNEMONIC` env vars + `ZS_MNEMONIC_URLS` cloud-secret URLs (AWS/GCP/Azure). See [`go/keystore/README.md`](./go/keystore/README.md). |
| `httpx` | A tuned, shared `http.Transport` for node↔node and payer↔node calls, with a private-address dial guard. |
| `gcplog` | `slog` attribute names for Google Cloud Logging. |
| `cmd/releasenotes` | Release-notes generator used by the `zs-proxy` and `zs-node` release builds. |

### TypeScript — [`ts/`](./ts/), npm package `@txnlab/zs-proto`

A port of the vectored Go packages so a browser can speak the protocol directly to a node.
Subpaths: `wire`, `ticket`, `selection`, `pricing`, `imageprice`, `tokenize`, `transient`,
`relay`, `attest`, `inject`, plus the fixtures under `testdata/*`. See
[`ts/README.md`](./ts/README.md).

Wire-shaped types use snake_case property names matching the JSON wire format, so `JSON.stringify(envelope)` produces the bytes the Go side emits — no field-rename layer. Function names are camelCase.

Not ported (intentionally): file-IO identity loaders, the Go `reflect+unsafe` ephemeral-key wipe (JS strings are immutable; see `ts/README.md` "Secret-key lifetime"), and the `algo/`, `algod/`, `escrow/`, `tools/`, `keystore/` subpackages.

### Golden vectors — [`testdata/`](./testdata/)

Each vectored Go package writes its fixture (`vectors.json`, `selection_vectors.json`, …) from
a `Test*Vectors` test, and the matching `ts/test/*-vectors.test.ts` reads it unchanged, so
byte-format drift between the two implementations fails on either side. `make update-vectors`
regenerates them all; `make check-vector-generators` (part of `make test`) fails if a generator
is missing from that target.

## Setup (shared across services)

**Algorand network.** Every service that touches chain reads `algod.network: localnet | testnet | mainnet` (with optional `algod.endpoint` / `algod.token` overrides). Resolves to nodely.dev for testnet/mainnet, `http://localhost:4001` for localnet.

**Node identity.** No age-key setup. Under mandatory forward secrecy the node holds **no** long-lived encryption key — request envelopes seal to an in-memory **ephemeral age key** the node generates, rotates on a fixed cadence, signs under its Ed25519 key, and advertises at `/v1/zs/details`; it is never persisted (there is no `node.key` / `identity_path`). See [`ENCRYPTION_OVERVIEW.md`](./ENCRYPTION_OVERVIEW.md). An operator's only persistent secret is its **signing mnemonic** (below).

**Signing mnemonics.** Both proxy (payer) and node (operator) load Algorand mnemonics via `proto/go/keystore`. Either set `<NAME>_MNEMONIC` env vars or point `ZS_MNEMONIC_URLS` at cloud-secret URLs. See [`go/keystore/README.md`](./go/keystore/README.md) for the full reference.

**Configuration.** Each Go service reads `./config.yaml` by default; override with `--config` or the `<SERVICE>_CONFIG` env var. Per-service `config.example.yaml` is the canonical reference. The proxy carries no upstream LLM credential — admission to the operator is via the on-chain seal, not a bearer token. The node's LLM provider key comes from env (`NODE_LLM_OPENAI_API_KEY`); never commit it.

## Build & test

```bash
make test                  # vector-generator check + Go suite + TS suite
make vet typecheck
make verify-vectors        # read-only: every fixture matches current Go output
make update-vectors        # regenerate fixtures after an intentional format change
cd go && go test -race ./...   # before crypto/streaming changes
cd ts && pnpm build
```

## Releasing

Go and TypeScript release in lockstep: one version number, both tags on the same commit.

1. Set `ts/package.json` `version` to `X.Y.Z` and commit.
2. Tag that commit `go/vX.Y.Z` and `ts/vX.Y.Z`, then push both tags.
3. The Go module is live as soon as the tag is pushed (`go get github.com/TxnLab/zerosignal/go@vX.Y.Z`).
   The `ts/v*` tag runs [`release.yml`](./.github/workflows/release.yml), which tests both
   implementations and **stages** the npm package. It does not publish it.
4. A maintainer approves the staged package with 2FA, either in the package's *Staged Packages*
   tab on npmjs.com or with `npm stage approve <id>`. Only then is it installable.

Under 0.x a minor bump is a breaking change and a patch bump is not. Never move or delete a
pushed `go/v*` tag: the Go checksum database has already recorded it.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
