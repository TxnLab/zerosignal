# Encryption Overview

A high-level map of the encryption layers in ZeroSignal: which keys exist, what each
one protects, and how a request/response round-trip is sealed end-to-end.

This is the **companion** to [`SPEC.md`](./SPEC.md), not a replacement. SPEC.md
is normative (exact byte layouts, AAD formulas, content-types, slashing
evidence); this file is the orientation you read first. Section refs like §3a
point into SPEC.md. The Go reference implementation lives in
[`go/wire/`](./go/wire/) (envelope crypto), [`go/ticket/`](./go/ticket/)
(tickets, receipts, ephemeral advertisement), and [`go/escrow/`](./go/escrow/)
(on-chain operator records); [`ts/`](./ts/) mirrors the canonical-bytes/signing
surface.

> **Forward secrecy is mandatory.** The only encryption key a node holds is the
> short-lived, in-memory **ephemeral**: there is no on-chain anchor recipient and no
> persistent `node.key`, so forward secrecy is unconditional with nothing to downgrade
> to. The ephemeral advertisement signs its `issued_at` under a hard lifetime cap, and
> trust roots in the on-chain **Ed25519 signing key** (see [`SPEC.md`](./SPEC.md) §8
> "Security properties", plus §3 key material and §3c ephemeral advertisement).

## What we're defending against

The proxy↔node hop (and, in transport-privacy mode, a relay operator on the
path) carries the user's prompt and the model's completion. The encryption
layers exist so that:

- **Confidentiality** — nobody on the path (relay, on-path MITM, a
  TLS-terminating intermediary) can read the prompt, the completion, or the
  payer's address.
- **Admission integrity** — an operator only accepts sealed requests from a
  caller who actually reserved and is paying (no spraying forged
  `algorand_tx_id`s at nodes).
- **Response integrity / anti-splice** — a response cannot be replayed,
  reordered, truncated-without-detection (within a frame), or spliced from a
  different request/ticket.
- **Forward secrecy (unconditional)** — every sealed request goes to a
  short-lived ephemeral recipient that is zeroed on rotation; the node keeps
  **no persistent encryption key**, so a later theft of its on-disk secrets (only
  the Ed25519 signing mnemonic) retroactively decrypts **nothing**. There is no
  anchor to downgrade to.

What is intentionally **not** hidden (these are operational metadata, safe to
log per the non-retention rules): token counts, operator/ticket IDs, Algorand
addresses, model names, latency, microUSDC charges. Prompt/response *content* is
never logged or retained on proxy or node (§ "Prompt and response
non-retention").

## The keys at a glance

| Key | Type | Lifetime | Held by | Job |
|---|---|---|---|---|
| **Operator signing key** | Ed25519 | long-lived, rotatable | node (hot) — pubkey on-chain as `signing_addr` | **Trust root.** Signs tickets, receipts, and the ephemeral advertisement. Everything else inherits trust from this. The node's *only* persistent secret. |
| **Ephemeral age key** | X25519 (`age`) | ~20 min + 10 min overlap (lifetime hard-capped) | node — **memory only, never persisted, zeroed on rotation** | **The only encryption recipient → unconditional forward secrecy.** Advertised + signed (with `issued_at`) at `/v1/zs/details`. |
| **Caller reply-to key** | X25519 (`age`) | per request, discarded after | proxy/client | Recipient that `K_response` is wrapped back to. |
| **Response key `K_response`** | 32-byte symmetric (ChaCha20-Poly1305) | per reservation | node mints it, caller receives it wrapped | Seals the response. Committed in the ticket as `commit_k = sha256(K_response)`. |

Note the split: the **ephemeral age key is encryption-only** — it never signs
anything. Identity and authenticity come exclusively from the **Ed25519 signing
key**, which is also what signs the ephemeral's advertisement. `age` here means
[filippo.io/age](https://age-encryption.org): X25519 key agreement →
ChaCha20-Poly1305 internally.

## The layers

### Layer 0 — Trust root (on-chain)

An operator's `OperatorRecord` box (keyed by `operator_id`) publishes its
`signing_addr` (Ed25519). The proxy/client read it from chain via
`escrow.FetchOperatorsByID`. The Ed25519 key recovered from `signing_addr` is the
sole on-chain trust root for **everything below** — including the ephemeral key,
which is only trusted because it is signed under this key. The record carries no
encryption key of any kind: it anchors *identity* only.

### Layer 1 — Recipient selection & forward secrecy

There is exactly one encryption recipient — the ephemeral — and selection is
**fail-closed**: a fresh, valid ephemeral or nothing (try another operator).

1. `GET /v1/zs/details` returns `ephemeral_age_pubkey`, `ephemeral_issued_at`,
   `ephemeral_expiry`, and `ephemeral_sig`.
2. The caller verifies `ephemeral_sig` (Ed25519, payload
   `"zs-ephemeral-v1\0" ‖ u64(operator_id) ‖ u64(node_id) ‖ lenStr(age_pubkey) ‖
   i64(expiry) ‖ i64(issued_at)`) under the **on-chain signing key**, binding the
   chain-resolved `(operator_id, node_id)` at verify time so a relay can't re-point
   the block at another operator — or at a sibling node of the same operator, which
   matters when an operator reuses one signing key across its nodes
   (`ticket.EphemeralAdvertisement.Verify`).
3. **Hard checks** gate whether to seal at all: valid signature; the signed
   window `expiry − issued_at` within `MaxEphemeralLifetime` (so a node can't
   advertise a long-lived "ephemeral" it secretly retains to defeat FS);
   `issued_at` not future-dated; and `now ≤ expiry + skew`. Pass → **seal to the
   ephemeral**. Fail → **refuse the operator** and fall through to another; there
   is **no anchor and no downgrade path**.
4. **Soft check** (relay attribution, not a gate): if `now − issued_at >
   FreshnessTarget` *and the path used a relay*, the relay is serving a staler
   block than the node should have → record a relay-staleness fault and prefer a
   fresher path (`RecordRelayStaleEphemeral`). The block is still *used* if it's
   the only hard-valid one (it's decryptable and forward-secret); the user is
   never failed for a relay's staleness.

The signature attests *only* "this operator controls this short-lived recipient
over `[issued_at, expiry]`" — no prices, capabilities, or scope ride in it.
Forward secrecy is unconditional; there is no knob to toggle it off.

### Layer 2 — Request confidentiality (`age` seal)

Two sealed request shapes, both age-encrypting the **plaintext body directly**
to the selected recipient (no intermediate symmetric wrap on this direction):

- **Reserve** — `wire.SealReserveRequest` →
  `application/vnd.zs-reserve+json`. Confidentiality-only seal of the
  `ReserveRequest` (which carries `payer_addr`), so a relay can't read who's
  paying. The node opens it with its identity set: current ephemeral →
  previous-ephemeral-in-overlap (`OpenReserveRequest`) — there is no anchor
  identity.
- **Inference** — `wire.WrapRequest` → `application/vnd.zs+json`. Seals the
  chat/responses body. The envelope also carries `reply_to_public_key` (the
  caller's per-request age recipient for the response), `ticket_id`,
  `algorand_tx_id`, and the admission tag (Layer 3). The node decrypts with the
  same identity set (`DecryptRequest`).

### Layer 3 — Admission binding

The inference envelope's **admission tag** proves the caller is the party that
reserved/paid:

```
admission_tag = HMAC-SHA256(K_response,
    "zs-admission-v1\0" ‖ ticket_id ‖ 0x00 ‖ tx_id ‖ 0x00 ‖ sha256(body))
```

Only a caller who unwrapped `K_response` (delivered at reserve, Layer 4) can
produce it, and it binds the request to its ticket, payment tx, and exact body —
defeating replay and forged-tx spam (`wire/admission.go`, §3a "Admission tag").

### Layer 4 — Response confidentiality & integrity

The response key is **committed at reserve, not chosen at response time**:

1. At reserve, the node mints `K_response` (32 bytes, `crypto/rand`), stores it
   server-side keyed by ticket, and puts `commit_k = sha256(K_response)` in the
   signed ticket. It returns `K_response` **age-wrapped to the caller's reply-to
   recipient** as `wrapped_response_key`, inside a reserve response that is
   itself age-sealed to the caller's `proxy_recipient`
   (`application/vnd.zs-reserve-response+json`; only error bodies stay
   plaintext). The caller needs the key both to build the admission tag and to
   read the response.
2. At response time the node seals frames with **ChaCha20-Poly1305 under that
   same committed `K_response`** (`NewResponseSealerWithKey` → `SealBody` /
   `SealStreamFrame`). Per-frame random nonce; AAD binds `tx_id` + `ticket_id`
   (+ a monotonic `frame_index` for streaming, preventing reorder/drop) via
   `BuildBodyAAD` / `BuildFrameAAD`. `K_response` is also echoed wrapped in the
   `X-Zs-Response-Key` header.
3. The caller decrypts with `K_response` (`DecryptBody` /
   `DecryptSSEDataValue`).

Sealing under a key whose `sha256` ≠ `commit_k`, or crossing AAD bindings, is
cryptographically provable fraud and **slashable** (§3b (a) key-substitution,
(d) cross-wiring). Slashing evidence keys entirely off the Ed25519 signing key,
tickets/receipts, and `commit_k` — never an encryption key, which is why no
encryption key has to exist on chain for the evidence to hold.

The `[DONE]` SSE sentinel is **always plaintext**, even on encrypted streams
(§5.3). Final-frame truncation is not AEAD-detectable — application-level
completion signals (`finish_reason`, `[DONE]`) catch it; the response is
deranking, not slashing.

### Layer 5 — Transport privacy (single-hop relay)

Optionally a request rides through another operator acting as a relay (§3f) so
the target node never sees the caller's network identity. The relay only ever
sees ciphertext on all four legs: the sealed reserve request hides `payer_addr`,
the sealed reserve response hides the ticket it carries, the sealed inference
request hides the body and its identifiers, and the inference response is sealed
under `K_response`. Relay
misbehavior (dropping forwards) is handled by soft reputation downranking, not
by exposing plaintext.

## End-to-end round trip

```
1. Discover   read OperatorRecord (chain) → signing_addr
              GET /v1/zs/details → ephemeral age key + issued_at + Ed25519 sig
              verify sig + lifetime cap under signing_addr → ephemeral (or try next)

2. Reserve    age-seal ReserveRequest → vnd.zs-reserve+json → (relay) → node
              node opens, mints K_response, commits sha256(K) in ticket,
              returns ticket + wrapped_response_key (age-wrapped to reply-to),
              the whole response sealed → vnd.zs-reserve-response+json

3. Inference  caller unwraps K_response; builds admission tag
              age-seal body → vnd.zs+json (+ reply_to, ticket_id, tx_id, tag)
              node opens, checks admission tag, runs the model

4. Response   node seals frames w/ ChaCha20-Poly1305 under committed K_response
              AAD binds tx_id + ticket_id (+ frame_index for streams)
              caller decrypts with K_response;  [DONE] stays plaintext
```

## Forward secrecy in one paragraph

The node holds **one** age private key, and it **lives only in memory** —
generated with `age.GenerateX25519Identity()`, rotated ~every 20 minutes with a
10-minute decrypt-overlap so in-flight requests still open, then wiped
byte-by-byte (`wire.ZeroEphemeralIdentity`). Its signed advertisement carries
`issued_at` and a hard `MaxEphemeralLifetime` cap, so the window any single key
can seal is bounded regardless of honest zeroing. Because the ephemeral is the
*only* recipient (no anchor, no knob, no fallback), **all** traffic is
sealed to a key whose secret half is gone within ~30 minutes. An attacker who
later steals the node's on-disk secrets gets only the Ed25519 signing mnemonic —
which decrypts **nothing** (it never was an encryption key). The signing key,
tickets, receipts, and on-chain settlement are untouched by rotation: ephemeral
rotation is a **decrypt-only** concern (§8).

## Normative references

- [`SPEC.md`](./SPEC.md): §2 (primitives), §3/§3a (key material, admission,
  receipts), §3b (slashing evidence), §3c (operator details + ephemeral
  advertisement, incl. signed `issued_at` + lifetime cap), §3f (transport
  privacy + relay staleness attribution), §5.3 (`[DONE]` / streaming), §6 (AAD),
  §8 (mandatory forward secrecy).
- Reference impl: `go/wire/{wrap,seal,reserve_seal,admission,envelope,identity}.go`,
  `go/ticket/ephemeral.go`, `go/escrow/operators.go`.
