# @txnlab/zs-proto

TypeScript primitives for the [ZeroSignal](https://docs.zerosignal.ai) protocol: envelope
sealing, AAD and canonical bytes, ticket and receipt signatures, operator selection, pricing,
tokenize bounds, transient-error classification, and TEE attestation checks. Enough for a
browser or Node process to speak the protocol directly to a node, with no proxy daemon in front.

It is a port of the Go reference implementation and is kept byte-for-byte compatible with it on
every signed or AAD-bound payload. The authoritative wire spec is
[`SPEC.md`](https://github.com/TxnLab/zerosignal/blob/main/SPEC.md); the Go module is
[`go/`](https://github.com/TxnLab/zerosignal/tree/main/go).

This package ships primitives only. It does no chain access, discovery, or request orchestration.

## Install

```bash
pnpm add @txnlab/zs-proto
```

ESM only, Node ≥ 20.19 or any modern browser. Five runtime dependencies: `@noble/ciphers`,
`@noble/ed25519`, `@noble/hashes`, `@scure/base`, `age-encryption`.

## Entry points

| Import | Contents |
|---|---|
| `@txnlab/zs-proto` | Everything from `wire`, `ticket`, `selection`, `imageprice`, `tokenize`, `attest`, `inject` |
| `…/wire` | Envelope types, `wrapRequest` / `unwrapResponseKey` / `decryptBody` / `decryptSSEDataValue`, `decryptRequest` / `ResponseSealer` (node side, for round-trip tests), AAD builders, admission-tag HMAC, body hash, sealed inner frame, ephemeral identity, protocol version |
| `…/ticket` | `Ticket` / `UsageReceipt` / reserve types, `signTicket` / `verifyTicket` / `signReceipt` / `verifyReceipt`, signature digests, `commitResponseKey`, receipt header codec, Algorand address codec, `BytesSigner` |
| `…/selection` | Operator and relay selection policy, `deriveMaxOutput` |
| `…/pricing` | Token pricing and `verifyTicketPrice` |
| `…/imageprice` | Image-generation pricing |
| `…/tokenize` | Input-token bound used to size a reserve |
| `…/transient` | Retryable-vs-terminal error classification and the shared retry schedule |
| `…/relay` | Relay request metadata and the inner-path allow-list |
| `…/attest` | dstack / Intel TDX measurement checks and compose-file policy |
| `…/inject` | Tool classification (`classifyToolEntry`, `normalizeToolName`), server-side tool-growth detection, request-dialect helpers |
| `…/testdata/*` | The golden-vector fixtures this package is tested against |

`pricing`, `transient`, and `relay` are subpath-only: their names (`classify`, `wait`,
`buildRequest`, …) are package-qualified in Go and would be ambiguous at the root.

## Signing: raw Ed25519, not Algorand `signBytes`

A `BytesSigner` must return a **raw Ed25519 signature over the exact bytes it is given** — a
32-byte sha256 digest of a domain-tagged canonical body. This is **not** go-algorand-sdk's
`crypto.SignBytes` (which prepends `MX`) and not ARC-60 `signData`. A wallet whose sign-bytes
flow adds any prefix or tag cannot implement `BytesSigner`; the signer needs raw key access.
`inMemoryEd25519Signer` is the reference implementation.

## Wire shape and JSON property names

Wire-shaped types (`RequestEnvelope`, `ResponseEnvelope`, `Ticket`, `UsageReceipt`, `ReserveRequest`, `ReserveResponse`) use snake_case property names that match the JSON wire format. `JSON.stringify(ticket)` produces the exact bytes the Go side emits — no field-name remapping layer.

Function names use camelCase. Constants use UPPER_SNAKE.

## Numeric fields

Go's `uint64` / `int64` fields are typed as `number` here. Real values stay well within JS's safe-integer range (token counts, microUSDC totals up to ~10^12). Internally, the canonical-bytes encoder coerces via `BigInt` before writing the 8-byte big-endian form, so values up to 2^53−1 are encoded correctly.

## Secret-key lifetime

JS strings are immutable, so the AGE-SECRET-KEY-1… representation of an ephemeral identity cannot be reliably wiped from memory the way the Go side does (`ZeroEphemeralIdentity` reaches into age internals via reflect+unsafe). Callers should:

- Hold the `EphemeralIdentity` only as long as needed (until the response is fully decrypted).
- Drop the reference and let GC collect it; do not log or persist it.
- Treat in-memory secret lifetime as "best-effort" — the underlying bytes linger until GC runs and reclaims the string.

For higher-assurance setups, terminate envelopes in a worker / iframe whose JS heap can be discarded entirely on completion.

Not ported (intentionally): the Go file-IO identity loader, the Go `ZeroEphemeralIdentity` wipe,
and the Go `algo`, `algod`, `escrow`, `tools`, and `keystore` packages.

## Cross-implementation byte parity

Every vectored module is checked against a fixture the Go implementation generates: AAD layout,
admission tag, body hash, ticket / receipt canonical bytes, signature digests, address
encoding, selection order, pricing, tokenize bounds, transient verdicts, and attestation
checks. The Go suite fails when its output no longer matches the fixture, and this package's
suite fails when its output does, so drift on either side fails. In a checkout of the
repository:

```bash
make test              # Go suite, this package's suite, and the generator check
make update-vectors    # regenerate fixtures after an intentional format change
```

## Development

```bash
pnpm install
pnpm test          # vitest --run
pnpm typecheck
pnpm build
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
