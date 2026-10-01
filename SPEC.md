# ZeroSignal Protocol

This is the wire specification for the encrypted-envelope layer between a ZeroSignal caller and the node that decrypts its requests. It is authoritative for interoperability. The Go reference implementation is the `github.com/TxnLab/zerosignal/go` module beside this file; [`README.md`](./README.md) lists its packages. Section references in code (`§ 5.3`, `§ 6`) point here.

**Status.** The protocol is in active development and the wire shape is not frozen. This document describes the current state. § 13 covers design rationale and peer designs.

**Naming.** The protocol and product are **ZeroSignal**. Its short form `zs` is the only spelling on the wire: MIME types (`application/vnd.zs+json`), endpoint paths (`/v1/zs/*`), headers (`X-Zs-*`), SSE event names (`event: zs`), signing domains (`zs-ticket-v2\x00`) and built-in tool types (`zs_web_search`). The old project name, *hayai*, survives in implementation identifiers such as `proxy/internal/hayai/…`, `dispatchHayai` and `fetchHayaiDetails`, and in the text of one error message (`unknown hayai builtin tool type`, returned with code `unknown_builtin_tool`). None of these is an alternate protocol name; match on the code, never the message.

**Conventions.** The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** mark interoperability requirements. Wire names appear in `snake_case`; Go and TypeScript identifiers appear only in reference-implementation notes. Unless a paragraph says otherwise, “caller” means either a direct ZeroSignal client or the proxy acting for a plaintext OpenAI client. “Proxy” means only that local bridge, and “node” means a serving or relaying ZeroSignal node. Sections marked as design notes, rationale, operational guidance or deferred work are non-normative.

## 1. Overview

ZeroSignal has two caller forms:

- A direct ZeroSignal client does reservation, encryption, payment and settlement itself.
- The local ZeroSignal proxy does them for an OpenAI-compatible client. That client speaks ordinary OpenAI HTTP on `/v1/*` and need not know ZeroSignal is involved.

Either way, every prompt-carrying request body is encrypted to the target node's verified, short-lived recipient (§ 3c). Every admitted response is encrypted to a per-request recipient the caller chooses. Discovery and pre-envelope errors stay plaintext (§§ 3c, 5.1). In privacy mode, a second node relays the already-encrypted traffic without learning its contents (§ 3f).

```
OpenAI client ──(plain OpenAI)──► proxy ──(sealed)──► relay ──(sealed)──► target node
OpenAI client ◄──(plain OpenAI)── proxy ◄──(sealed)── relay ◄──(sealed)── target node

direct client ────────────────────────────(sealed, optionally relayed)──► target node
direct client ◄───────────────────────────(sealed, optionally relayed)── target node
```

Any OpenAI SDK that can POST to `http://localhost:9376/v1/chat/completions` works through the proxy with no protocol-specific support.

## 2. Cryptographic primitives

| Purpose | Algorithm | Library |
|---|---|---|
| Request body encryption | `age` v1 (X25519 → ChaCha20-Poly1305 internally) | `filippo.io/age` |
| Response symmetric-key wrap | `age` v1 | `filippo.io/age` |
| Response body/frame AEAD | ChaCha20-Poly1305 (RFC 8439) | `golang.org/x/crypto/chacha20poly1305` |
| Asymmetric keypair generation | X25519 via `age.GenerateX25519Identity()` | `filippo.io/age` |
| Randomness source | `crypto/rand` (OS CSPRNG) | Go standard library |
| Base64 encoding | Standard (RFC 4648) with padding | `encoding/base64` standard encoding |

There is no algorithm negotiation. Once the spec is frozen, replacing any primitive in this table requires a new content-type (§ 11).

## 3. Key material

| Key | Who holds it | Lifetime | Generation |
|---|---|---|---|
| **Node ephemeral identity** | Node, memory only | ~20 min, plus a 10 min decrypt overlap, then zeroed | `age.GenerateX25519Identity()` on each rotation. Never persisted. |
| **Node ephemeral recipient pubkey** | Node; advertised and signed at `/v1/zs/details` for sealing parties | Same as the identity | Derived from the identity. Signed with the node `signing` key as `ephemeral_sig` (§ 3c). There is no on-chain encryption recipient. |
| **Proxy ephemeral identity** | Proxy | One request; discarded after the response | `age.GenerateX25519Identity()` inside `wire.WrapRequest` |
| **Proxy ephemeral pubkey** | Proxy; embedded in the request envelope | One request | Derived from the identity |
| **Response symmetric key** | Node generates it at reserve (§ 3a); proxy receives it wrapped | One response | 32 bytes from `crypto/rand` on the node |
| **Operator id** | All parties | Operator lifetime | Sequential `uint64` from `ZeroSignalEscrow.createOperator` |
| **Node id** | All parties | Node lifetime | `uint64` from `ZeroSignalEscrow.createNode`, using a per-operator counter |
| **Operator owner address** | Operator (cold wallet, off the node) | Mutable via `updateOperator` | Algorand account |
| **Node signing address** | Node (hot) | Mutable via `updateNode` | Separate Algorand account |

**Operators and nodes.** The operator id is the on-chain key of the operator box `o:`. The operator is the economic entity: it holds the cold `owner` payout address and the rolled-up metrics, and its id survives rotation of every other row in this table. An operator owns many nodes. Each node is a running endpoint with its own hot `signing` key and base URL, stored in the node box `n:` + `be64(operator_id)` + `be64(node_id)`. Each node also advertises and signs an in-memory ephemeral recipient (§ 3c). Tickets name their destination as `(operator_id, node_id)`, and the proxy's registry, affinity and relay logic address nodes by that pair.

**Owner address.** The owner address receives the escrow's settle inner-payment and is stored in the operator box. Its private key stays off the node. Only the currently registered owner can call `updateOperator` for that id, so rotation means today's owner signs the transaction that names tomorrow's. Each ticket snapshots the owner address at `open()`, so a rotation never redirects an in-flight ticket's settlement.

**Signing address.** The node signing address is an Algorand account whose private key lives on the serving node. It signs:

- The node's pre-signed AppCalls: `escrow.open()` at reserve time and `escrow.settle(asOperator=true)` at receipt time. The contract authenticates both by consensus, checking `Txn.sender == node_signing`, where `node_signing` is resolved from the node box and snapshotted onto the ticket as `nodeSigning`.
- The off-chain receipt signature consumed by `escrow.protest()` and by audit: raw Ed25519 over `sha256(CanonicalBytes(receipt))` (§ 3a "Settlement receipt").
- The off-chain ticket signature, also produced for audit.

Its public key is recovered from the address with `DecodeAlgorandAddress`. It is stored in the node box and rotates independently of the owner address, subject to `updateNode` authorization.

The caller **MUST NOT** retain per-request ephemeral material past the end of the response handler. The node **MUST NOT** retain the response symmetric key past the end of the response, except between reserve and consume (§ 3a), while it waits for the paying request.

## 3a. Admission & reservation

Reservation solves two problems that payment alone does not: operators spammed with sealed envelopes that carry forged or stale `algorand_tx_id`s, and clients paying for work no operator agreed to serve. It adds a cheap, cryptographically binding pre-flight before the sealed request.

A reserve is bound to one specific operator at one specific price. Discovery (which operators serve which models, at what advertised rates and context windows) is in § 3c. Before reserving, a client MAY consult the per-model `?expand=coordinates,digest` **deep path** (§ 3c "Deep model details") to inspect a model's taxonomy and weights-integrity detail. That detail is **advisory and never part of reserve**. The routing and billing key is the exact `model` string below; coordinates and digest never change operator eligibility, price or admission. They only inform a human's choice of what to reserve.

### Endpoint

`POST /v1/zs/reserve`

- **Content-Type (request)**: `application/vnd.zs-reserve+json`, the JSON request body age-sealed to the target's recipient (`SealedReserveEnvelope`, § 3f). The seal provides confidentiality only: it stops a relay from reading the caller's `payer_addr`, which is a stable on-chain address. Unlike the inference envelope, it carries no ticket, tx id or admission tag, since none exist yet. The reply path is the `wrapped_response_key` in the inner plaintext. A node rejects a plaintext request with `415 bad_content_type`. The reserve describes only the *shape* of the work (model, token budget, stream flag) and never carries the prompt.
- **Content-Type (200 response)**: `application/vnd.zs-reserve-response+json`, the whole `ReserveResponse` age-sealed to the caller's `proxy_recipient` (also a `SealedReserveEnvelope`). It must be sealed because `presigned_open_txn` names the payer twice: as gtxn[0]'s sender and as `open()`'s `payerAddr` ABI arg. In plaintext, a forwarding relay could read the payer address directly and link it to the client IP it already sees. Opening costs the caller nothing, since it already holds the private key that unwraps `wrapped_response_key` and later `X-Zs-Response-Key`. Reference: `SealReserveResponse` / `OpenReserveResponse`.
- **Content-Type (error response)**: `application/json`, plaintext and OpenAI-shaped. Errors carry no ticket and no payer, and a caller that could not parse them could not report why its reserve failed.
- **Always active**: every node serves this endpoint, and payment is always required.

### Request

```json
{
  "model": "gpt-4o-mini",
  "input_count": 842,
  "max_output_count": 1024,
  "stream": true
}
```

| Field | Type | Semantics |
|---|---|---|
| `model` | string | Model id the client will request. The operator must currently serve it: it appears in the operator's published `model_pricing` map, or is surfaced through `default_pricing` plus discovery. |
| `input_count` | uint64 | Realistic **upper bound** on the request's input tokens; the input side of `max_price`. Computed as in "Input-token bound", with the version named in `input_bound_version`. The node clamps it ("Context-window cap/floor") and re-measures the decrypted body against it ("Inference-time input-budget enforcement"), so under-reserving cannot steal service. |
| `max_output_count` | uint64 | Ceiling on output length. `max_price` is sized for this worst case; unused output is reconciled against the operator's signed usage receipt at settlement. |
| `stream` | bool | Whether the paying request uses SSE. Recorded in the ticket; operators may plan capacity differently for streaming and buffered work. |
| `proxy_recipient` | string | The caller's age public key (`age1…`). The node wraps `K_response` to it and returns the result as `wrapped_response_key`, so the caller can compute the request's `admission_tag` ("Sealed request envelope") and decrypt the response. Required when the node enforces admission tagging, which it always does in escrow mode. |
| `payer_addr` | string | Algorand address that funds and signs the `open()` group's `usdcPayment` (gtxn[0]). It must also hold a prepaid ticket-MBR pool ("Settlement asset model"), from which `open()` draws box MBR. Required when the node enforces escrow admission. |
| `image_tool_budget` † | uint64 (optional) | Maximum images the in-loop `zs_image_generation` tool may produce. Used only to size `max_price`: the node adds `image_tool_budget × per-image cap` microUSDC. Omitted or 0 ⇒ the tool is unusable for this request. |
| `image_edit_tool_budget` † | uint64 (optional) | Same as `image_tool_budget`, for the in-loop `zs_image_edit` tool, sized with the edit per-image cap. Omitted or 0 ⇒ unusable. |
| `image_n` † | uint64 (optional) | Image count for the dedicated image route ("Dedicated image route"). When `> 0` and the model advertises `image_rate` / `image_edit_rate`, the node sizes `max_price = imageprice.CostMicroUSDC(rate, image_n, image_size, image_quality)`, and `max_output_count` is unused for sizing (`0` is allowed). |
| `image_size` † | string (optional) | Requested size (`"1024x1024"`, a `"W:H"` aspect ratio, `"auto"`, …). Scales the per-image price via `imageprice.Factor`. Empty or unparseable prices at the 1024²-standard reference. |
| `image_quality` † | string (optional) | Requested quality (`low` / `medium` / `standard` / `auto` / `high` / `hd`). Scales the per-image price. Empty ⇒ reference (×1.0). |
| `image_edit` † | bool (optional) | Sizes a dedicated image reserve at the edit rate (`image_edit_rate`) instead of the generation rate (`image_rate`). Ignored unless `image_n > 0`. |
| `payer_sig` † | string | `base64(Ed25519)` by the key behind `payer_addr` over the reserve-request canonical bytes ("Reserve-request signature"). Proves control of `payer_addr` instead of trusting it. An **escrow-mode node requires a valid one**. |
| `payer_issued_at` † | int64 (optional) | Unix-seconds start of the signature's validity window, `[issued_at, issued_at + 60s]` ("Reserve-request signature"). |
| `input_bound_version` † | uint8 (optional) | Which input-token bound version computed `input_count`, so the node re-measures with the same function. Omitted or 0 ⇒ version 1. A caller sets `2` only against a target that advertises support; a node rejects an unimplemented version at reserve time ("Input-token bound"). |

† Reserve request only: not part of the ticket or `Ticket.CanonicalBytes()`.

**`model` notes.** An explicit `model_pricing` entry is the operator's authoritative "I serve this" declaration. A priced model is reservable whenever the backend is reachable, whether or not the upstream's `/v1/models` lists it (many OpenAI-compatible upstreams list models incompletely). If the backend is entirely unreachable, the reserve is refused `503 provider_unavailable`, and the operator advertises zero models on `/v1/zs/details`.

**`payer_addr` notes.** The node binds `payer_addr` into its signed gtxn[1] AppCall as the `payerAddr` ABI arg. The contract then sets `t.payer = payerAddr` without trusting the txn `Sender`, which is the node's signing address ("Operator authentication").

**`image_n` notes.** Before sizing, the node resolves `image_size` / `image_quality` through the operator's per-model default and cap knobs, exactly as it does at serve time.

**`payer_sig` notes.** The signature also covers `proxy_recipient` and the target `(operator_id, node_id)`. The target ids are signed but never sent.

### Reserve-request signature

Sealing the reserve gives **confidentiality** (a relay cannot read `payer_addr`), not **authentication**. The seal is to the node's *published* ephemeral recipient (`/v1/zs/details`), so anyone can seal a reserve naming any `payer_addr`. Unauthenticated, the node's per-account rate limiter would key on a claim an attacker can rotate freely (quota evasion) or spoof with a victim's address (quota griefing). `payer_sig` is an Ed25519 signature by the key behind `payer_addr`. It proves control of the address before the node keys any stateful defense on it.

**Domain tag:** `zs-reserve-v1\x00`, with a trailing NUL like the `zs-ticket-v2` / `zs-receipt-v2` / `zs-ephemeral-v1` / `zs-admission-v1` tags. Its version is independent of theirs.

**Canonical bytes.** The signed digest is `sha256` of the following, encoded like `Ticket.CanonicalBytes` (length-prefixed strings, fixed-width big-endian numbers, one 0/1 byte for the boolean):

```
zs-reserve-v1\x00
‖ lenStr(payer_addr)      // the identity being authenticated
‖ u64(operator_id)        // TARGET binding — unsent signed context
‖ u64(node_id)            //   (see below); NOT a wire field
‖ lenStr(model)
‖ u64(input_count)
‖ u64(max_output_count)
‖ bool(stream)
‖ lenStr(proxy_recipient) // per-request fresh recipient → doubles as the replay nonce
‖ i64(payer_issued_at)    // tail; the [issued_at, issued_at+60s] window is tamper-evident
```

**Target binding — `(operator_id, node_id)` are signed but not on the wire.** Both ends already know them: the signer from the node it routes to, the verifier from its own identity. They enter the canonical bytes as parameters, never as JSON. Without them the signature would verify at *every* node. A malicious first-recipient node could then re-seal a captured reserve to a *sibling* node's published recipient and replay it inside the window, burning the payer's quota and slot cap and manufacturing abandon strikes at nodes the payer never contacted. With them, a signature presented to the wrong node fails to verify.

The image fields (and future video fields) are excluded from the canonical bytes, as in `Ticket.CanonicalBytes`. The age seal already protects the ciphertext's integrity; the signature's job is binding.

**Validity window and clock skew.** The verifier recovers the Ed25519 public key from `payer_addr` and checks the signature. It then requires that `payer_issued_at` is not in the future and that `now ≤ payer_issued_at + 60s`, each with a **30s** skew tolerance. Consumer devices stamp `payer_issued_at`, so skewed clocks are expected. On a window failure, the `401 invalid_payer_sig` body carries `node_time=<unix>`, the node's own clock. The caller re-stamps `payer_issued_at` to it, re-signs and retries the reserve **once**, as in AWS SigV4.

**A signing caller MUST implement this one-shot `node_time` resync.** Without it, every reserve from a device more than the skew tolerance off gets `401`. `proxy_recipient` is regenerated per reserve, so a fresh reserve after any hard failure has a new digest and nonce. Reference: the proxy (`proxy/internal/hayai/reserve.go`) and client (`client/src/stream/reserve.ts`) re-stamp to `node_time`, re-sign, re-seal and retry once; a persistent rejection then surfaces as `invalid_payer_sig` instead of looping.

**Replay set.** `proxy_recipient` is a fresh X25519 recipient per request, so it doubles as the anti-replay nonce. A node that enforces signatures keeps a bounded, TTL'd set of seen `proxy_recipient` values covering the `60s + 30s` window. It checks membership right after a successful verify, but **records a value only when a slot is successfully reserved**. A `401`, `415`, `429` or other refused request never consumes the nonce. A repeat within the window is refused `409 reserve_replayed`. Without this, a relay could replay a captured sealed body to fill a victim's slot cap and manufacture abandon strikes against an honest payer.

**Requirement.** An escrow-mode node **requires** a valid signature on every reserve. A missing, forged, wrong-target or out-of-window `payer_sig` is refused `401 invalid_payer_sig`; a replayed sealed body is refused `409 reserve_replayed`. `payer_sig` and `payer_issued_at` live inside the sealed body and no ticket or receipt signature covers them, so node, proxy and reference client ship signing as one coordinated release. A node has an internal off-switch for test isolation and non-standard unsigned callers; it is not an operator setting.

**Funds gate.** Keypairs are free, so a signature alone cannot stop a caller fielding an unbounded sybil fleet. A node MAY also require the payer to hold a prepaid-pool opt-in (the escrow-app opt-in, a scarce on-chain resource) before reserving a slot. Its refusals are `403 payer_not_opted_in` and, when the node's cold-miss budget for opt-in lookups is exhausted, `503 payer_optin_unavailable`.

### Input-token bound

`input_count` is a realistic upper bound, not a tokenizer output. A shared implementation computes it, in **two versions**. The caller sends the version it used as `input_bound_version`, and the node re-measures with the same version ("Inference-time input-budget enforcement"). Reference: `proto/go/tokenize`, mirrored in `proto/ts`, pinned by `proto/testdata/tokenize_vectors.json`.

Both versions compute `ceil(textBytes / 2) + image_tile_tokens + flat_margin(32)`. Two bytes per token is a safe floor across modern BPE and SentencePiece vocabularies, and `textBytes` excludes image-URL strings. Images use OpenAI's tile formula: 85 tokens at `detail: low`, and `85 + 170 × ceil(w/512) × ceil(h/512)` at `detail: high`.

**Version 1** (`InputTokenBound`) knows an image's dimensions only from explicit `width`/`height` on the content part. No client sets those: they are not standard OpenAI fields, and strict upstreams reject unknown keys. So in practice v1 charges **every** image the 2048×2048 high-detail fallback of 2805 tokens. Measured against `proto/testdata/tokenize_corpus/`, that is 3.7×–11× the true cost of an ordinary 512×512 or 1024×768 paste, and too low for larger images (a 4096×4096 image really costs ~11k tokens). v1 is frozen, because changing it would invalidate reserves that were correct when made.

**Version 2** (`InputTokenBoundV2`) changes only the image term. It reads each image's **true pixel dimensions** from the image **header** inside the body's `data:image/...;base64,...` URL, so client, proxy and node derive the same number from the same body with no wire change. Because the node runs this on payer-controlled input:

- **Header only, never decode.** Nothing inflates, allocates per pixel or walks image data. A decoder would be a decompression-bomb vector.
- **Bounded read.** At most 64 KB of the base64 payload is examined, so a 50 MB data URL costs the same as a 50 KB one.
- **Fail high.** A remote URL, a truncated or malformed header, an unknown format, or a SOF marker past the scan window falls back to 2048×2048 high detail.
- **GIF is not read.** The header's only size field, the Logical Screen Descriptor, is not what decoders use (PIL and the transformers/vLLM path read the per-frame Image Descriptor), and the two may legally differ. Trusting those four payer-controlled bytes let a patched 4096×4096 GIF reserve 302 tokens instead of 11,012, so GIF takes the fallback.
- **Dimensions are clamped** to 16384 px before tile arithmetic. A declared value below 1 counts as *absent*, so a nested `"width": 0` cannot erase an outer value.

v2's **text term is byte-identical to v1's**, so v1's known text under-counts (base64, hex, emoji, embedded JSON; recorded in `proto/testdata/tokenize_corpus.json`) apply to v2 too. Tightening the text term needs a much broader corpus with a train/holdout split.

The image term moves both ways (smaller for a common paste, larger above 2048×2048), so v2 is not uniformly smaller than v1. That is why the version is negotiated explicitly instead of inferred.

**Tool-loop headroom.** For a request that carries tools, the caller adds `max_tool_iterations × tool_headroom_per_iteration` (both advertised on `/v1/zs/details`) to the body bound. Each iteration appends its result to the context, and billing covers the aggregate input across iterations, so the reserve must cover that growth. A request with no tools adds no headroom (`ReserveInputCount(bound, carriesTools=false, …)`), so a plain question reserves a few hundred input tokens, not the whole window.

**Server-side response chains** (`previous_response_id`) hide their history from the node, so a chain request reserves the worst case, `context_window − max_output_count`. The client chat app is stateless (it replays full history and never sends `previous_response_id`), so only the proxy's chain path needs this.

The estimator overcounts on purpose. An overestimate only widens the refund at settlement; an underestimate would truncate a tool loop or let a caller under-reserve. Because the bound is model-agnostic, unknown open models (Qwen, Gemma, Llama, …) can be reserved with no config change on either side.

**Context-window cap/floor.** When the operator declares a `context_window` for the model (advertised on `/v1/zs/details`), the **node** clamps the caller's `input_count` on the issued ticket to `[min_input_count, context_window − max_output_count]`. The cap stops a caller reserving above the window; the floor raises a tiny claim. The node does **not** raise a realistic value to the ceiling. Under-reservation is caught at inference time instead (below). A model with no declared `context_window` skips the cap, so the caller's value passes through and the operator accepts the subsidy risk. The residual `max_price − amount_charged` is refunded to the payer at settlement through the contract's normal disbursement.

### Inference-time input-budget enforcement

Because the reserve is realistic rather than worst case, the node checks actual usage against it at inference time. This is what makes a small reserve safe against a caller that under-declares `input_count`. After decrypting, the node recomputes the input-token bound over the **pre-mutation** body (the exact bytes the caller sized from, before node-side injection) and compares it to `input_count × (1 + input_budget_tolerance)`.

The node measures with **the version the caller declared** in `input_bound_version`, not its own newest bound. The versions differ in the image term, which moves both ways: a v1 caller reserves 2805 tokens for a 4096×4096 image that v2 measures at ~11k. Measuring with v2 would therefore reject a correctly sized v1 request just because the node upgraded. An omitted or zero field means version 1. A node rejects an unimplemented `input_bound_version` at **reserve** time (`invalid_reserve`), not mid-flight after payment. A caller sizes with v2 only against a target that advertises support (`wire.UsesTightInputBound`): sizing v2 against a node that measures v1 fails closed with `input_budget_exceeded`, while sizing v1 against a v2 node merely over-reserves. When support cannot be established, the caller uses v1.

- **Plain request over budget** → rejected before any upstream call with a sealed **zero-cost** error. Settlement refunds the reserve in full, so the caller pays only network fees and the operator only gas. An honest caller cannot hit this, since it sized the reserve from the same body. The code gives the cause: `input_budget_exceeded` when the measured bound is below the model's ceiling (a genuine under-declaration), or `context_length_exceeded` when it also exceeds `context_window − max_output_count` (the prompt cannot fit the model, whatever the reserve).
- **Tool loop over budget** → the loop stops at the budget boundary. The node forces a final synthesis (`tool_choice: "none"`) instead of another tool round, so the user still gets an answer from the tool results so far. Tool-loop billing is the aggregate across iterations, so this is checked before every iteration after the first.
- **Chain rule** → a `previous_response_id` request whose reserved `input_count` is below `context_window − max_output_count` is rejected `chain_reserve_insufficient`. The caller must reserve the worst case for history the node cannot see.

Enforcement is controlled by `zs.reserve.enforce_input_budget`, default **on**. It protects the operator from under-declared `input_count`, and it never false-rejects a plain turn, because the node measures with the caller's own bound. Turning it **off** suits a trusted single-user node, or "monitor mode": over-budget requests are served, logged and counted on `zs_reserve_input_budget_over_total`. The node logs a startup WARN when it is off. Models with no declared `context_window` remain an operator subsidy either way.

`max_output_count` is not estimated. It is read from the body's `max_tokens`, `max_completion_tokens` or `max_output_tokens`. If the body has none, the caller (proxy or client) uses a configured per-model override, or else **derives a ceiling per operator** from that operator's declared capacity:

1. the operator's declared `max_output_tokens`, verbatim; else
2. `clamp(context_window / 4, 256, ceiling)`; else
3. the global fallback ceiling.

The ceiling is `32768` for **every** caller: the proxy's `fallback_max_output_tokens` default and the client's `DEFAULT_MAX_OUTPUT_TOKENS` both equal it. The sizing filter runs `Fits` against the derived number, so different ceilings would make proxy and client disagree on which operators are eligible, and the proxy is meant to route identically to the client. The value leaves a thinking model room for its reasoning and its answer, so reasoning models need no special case. Reference: `selection.DeriveMaxOutput` and `selection.DefaultMaxOutputCeiling`, shared Go↔TS and pinned by `proto/testdata/selection_vectors.json`.

**Escrow cost.** The derived ceiling sets `max_output_count` and so `max_price`, which is USDC locked in escrow until settlement. At a `$6`/1M output rate, a derived `32768` locks about `$0.20` per turn; unused output is refunded at settlement. On the client the same number sets `modelFloorMicroUsdc`, which decides whether a model reads as affordable and feeds the low-balance blocker. This applies only to models whose operator declares no `max_output_tokens`, since a declared cap is used verbatim. `zs-node init`'s Sizing step and `zs-node doctor`'s missing-ceiling check push operators to declare one.

This is **caller-side sizing**, not a wire change. The derived number rides `max_output_count`, and the node applies the same `context_window` fit check (§ 3a "Context-window cap/floor"). Deriving per operator lets a request reserve a right-sized ceiling on a small-window operator instead of routing away from it. The sizing filter and the escrow always agree because both call `DeriveMaxOutput` on the same inputs. The request is rejected before reserve with `400 max_output_required` (§ 10) only when the body omits the field, no per-model override exists and the global fallback is disabled (set to 0), because the node needs a concrete ceiling to compute `max_price`.

### Response (success)

HTTP 200, `Content-Type: application/json`:

```json
{
  "ticket": {
    "ticket_id": "<base64 16 bytes>",
    "operator_id": 42,
    "node_id": 7,
    "input_count":      842,
    "max_output_count": 1024,
    "input_rate":        150000,
    "output_rate":       600000,
    "cache_read_rate":    37500,    // microUSDC/1M for cached-read input; ≤ input_rate; 0 = free; unset in config ⇒ input_rate
    "max_price":         baseMax + ceil(baseMax * feeBps / 10000),   // baseMax = max(ceil(842*150000/1e6) + ceil(1024*600000/1e6), min_price); see "Rate derivation" + "Protocol fee"
    "min_price":         ceil(1000 * 600000 / 1_000_000),   // token component only (min_charge.output_tokens=1000, algo_txns=0)
    "expires_at":        1734567890,
    "model":             "gpt-4o-mini",
    "stream":            true,
    "commit_k":          "<base64 sha256(K_response) — 32 bytes>",
    "input_usage_type":  1,
    "output_usage_type": 1,
    "sig":               "<base64 Ed25519(ticket_signing_key, sha256(CanonicalBytes)) — 64 bytes; off-chain audit only>"
  },
  "wrapped_response_key": "<base64(age_encrypt(K_response, proxy_recipient)) — present whenever proxy_recipient was supplied>",
  "presigned_open_txn":   "<base64(msgpack(SignedTxn)) for the node's gtxn[1] AppCall — present whenever payer_addr was supplied and escrow admission is enabled>"
}
```

`wrapped_response_key` uses the same age primitive as the response-time `X-Zs-Response-Key` header (§ 5.2). Delivering it early gives the caller `K_response` in time to compute the sealed request's `admission_tag`.

`presigned_open_txn` is the node's signed `escrow.open()` AppCall: gtxn[1] of the open group. Its group hash already commits to the caller's funding transaction, gtxn[0], a `usdcPayment` from `payer_addr` with fee 0. gtxn[1] carries `fee = 2 × minTxnFee`, which pays for the whole group. The caller builds and signs gtxn[0] and submits the two-transaction group atomically. Algorand consensus then authenticates the node signing key's intent on gtxn[1], and the contract reads its ABI args directly.

So the operator, not the payer, pays the open-time ALGO fee ("Settlement asset model"). The per-ticket box MBR comes from the payer's prepaid pool, not from a per-turn payment. `escrow.open()` takes no `ticketSigDigest` / `ticketSig` args: admission is authenticated by consensus on gtxn[1], so `ticket.sig` is carried only for off-chain audit and dispute tooling.

**Validity window.** The pre-signed open txn is valid from `firstValid = currentRound` to `lastValid = currentRound + 1000` (the Algorand maximum), fixed at reserve time. If the paying request lands after `lastValid`, the proxy treats it like any failed reserve and tries another operator.

**Ticket signature.** `ticket.sig` is raw Ed25519 over `sha256(CanonicalBytes())`, used for audit and SDK verification; no on-chain method consumes it. The off-chain verifier resolves the signing key from the destination's `(operator_id, node_id)` node box.

`CanonicalBytes()` places `node_id` (`u64`) right after `operator_id`, then appends `input_usage_type` and `output_usage_type` (one byte each, "Usage types"), then `cache_read_rate` (`u64`) at the tail. `UsageReceipt` canonical bytes end with the matching `cached_input_count` `u64`. The ticket and receipt signing tags carry a literal `v2`: `zs-ticket-v2\x00` and `zs-receipt-v2\x00`.

The authoritative on-chain commitment to `(operatorId, nodeId, maxPrice, expiresAt, payerAddr, settlementGraceSeconds)` is the node's signed gtxn[1] `open()` AppCall. Algorand consensus verifies it at pool admission, and the node's hot signing key signs it.

**Rate derivation.** `input_rate`, `output_rate` and `cache_read_rate` are microUSDC per 1,000,000 tokens. The node stores operator rates as USD per 1,000,000 tokens and converts them at reserve:

```
microUSDC_per_1m = ceil(usd_per_1m × 1_000_000)
```

For example, `$0.15/1M` becomes `150000`. Either rate MAY be `0`, and both token rates MAY be `0`. A free model skips the minimum charge, produces `max_price == min_price == 0`, and uses a valid zero-amount `usdcPayment`. Its prepaid box-MBR slot stays locked until settlement, but the operator fee-pools the happy-path transaction fees ("Settlement asset model"), so the payer's happy-path ALGO cost is zero.

The ALGO/USD oracle plays no part in token pricing: `max_price` and `amount_charged` are USDC amounts. The reserve response still includes `algo_usd_price` when available, because it feeds the optional µALGO component of the minimum charge.

`cache_read_rate` prices the **cached-read** part of the input: prompt tokens the upstream served from a prefix or prompt cache, reported as `cached_input_count` on the receipt. It lets an operator pass an upstream cache discount on to the payer. The operator configures it in USD/1M like the other rates, and the node resolves it to a concrete microUSDC value at reserve. **An unset `cache_read_rate` resolves to the resolved `input_rate`**, so a config that never mentions caching bills cached reads at the input rate. The wire value is therefore always literal: `0` means **free cached reads**, just as `input_rate == 0` means a free model, and never means "inherit". Real pricing always has `cache_read_rate ≤ input_rate`, and the charge formula and `max_price` below rely on it: a cache read is a strict discount.

`max_price` is the rate-based ceiling. Each term uses ceiling division by `1_000_000`, so every figure is whole microUSDC:

1. **Base ceiling:** `baseMax = ceil(input_count × input_rate / 1_000_000) + ceil(max_output_count × output_rate / 1_000_000)`. There is no output round-up.
2. **Minimum:** `baseMax` is raised to `max(baseMax, min_price)`, so the escrow always covers the minimum charge.
3. **Fee gross-up:** `max_price = baseMax + ceil(baseMax × feeBps / 10000)`, so the escrow covers the base plus the worst-case protocol fee (§ 3a "Protocol fee").

The ticket's `max_output_count` matches the request verbatim. Settlement clamps `amount_charged` (the operator's base take) to `baseMax`, and reserve enforces `min_price ≤ baseMax ≤ max_price`, so `amount_charged ≤ max_price` holds for any usage within the ticket's caps.

`baseMax` prices the **whole** input at `input_rate` and does **not** subtract the cache discount. A cache-read rate is always `≤ input_rate`, so the discounted charge never exceeds this ceiling. A future cache-*write* rate above `input_rate` would need a `max(input_rate, cache_write_rate)` ceiling, because one request would then mix rates on both sides of `input_rate`; that is deferred. The long-context tier below is not such a case: it replaces the whole rate set rather than mixing two.

**Long-context (surcharge) tier.** Some upstreams (xAI / Grok) have a **context-size cliff**: once a prompt's token count reaches a threshold, the **entire request** bills at higher rates, for input, cached and output tokens alike. An operator advertises this as a second rate set: `long_context_threshold_tokens` plus high `input` / `output` / `cache_read` rates (§ 3c).

The node picks the tier at **reserve**, from the signed `input_count` **alone**: `tier = (input_count ≥ threshold)`, an inclusive boundary (`pricing.IsLongContext`). It pins that tier's rates into the ticket's usual `input_rate` / `output_rate` / `cache_read_rate` fields. No new ceiling is needed, for two reasons:

- **One tier per request.** Output bills at the tier's output rate but never decides the tier, so no request mixes a base rate with a high rate.
- **Same tier on both sides.** The node and the payer-side verifier derive the tier from the same signed `input_count`, so `max_price` stays an exact recompute from the ticket's own rates.

High rates must be `≥` their base counterparts (a surcharge, not a discount), and the high `cache_read_rate` must be `≤` the high `input_rate`, as in the base tier. The high tier can be entered **only at reserve**. `reserve.enforce_input_budget` (default on) holds the actual prompt to roughly the reserved `input_count`, so a sub-threshold reserve followed by a longer prompt is rejected or cut off at inference, never silently re-tiered upward.

**Stepping back down at settle.** The reserve and the upstream tier on different quantities, and the difference runs only one way:

- `input_count` is an **upper bound**. It includes tool-loop headroom (`max_tool_iterations × tool_headroom_per_iteration`), and a `previous_response_id` chain reserves the model's whole worst case because the node cannot see the history. An operator that sets `context_window` to the model's true maximum will therefore reserve above the threshold for *every* chained request.
- The upstream tiers each API call on **that call's own prompt**. A tool loop is N calls: the receipt bills their aggregate, but the upstream never tiered them together.

Either way, a request can be signed into the high tier although its real prompt never crossed the cliff. So at settle the node **re-checks the tier against the measured prompt**, meaning the largest single upstream call, which is exactly what the upstream tiered on. If that never reached the threshold, the node bills the **base** rates. This is safe to do unilaterally because it only ever **lowers** the charge, and the payer's receipt check is `amount_charged ≤ max_price`, not an exact recompute. The reverse is not allowed: a measured prompt above a base-signed ticket's threshold is not escalated, because the tier is a reserve-time commitment the operator cannot raise later. `min_price` is sized from the **base** rates because it is a fixed-cost floor, not a per-token price, so a stepped-down request is not left at a tier-inflated minimum.

**Near the threshold.** `input_count` is our tokenizer's estimate, while the upstream counts its own prompt tokens, so a request right at the threshold could tier differently on the two sides. An operator can set `threshold_tokens` slightly conservatively for margin. The `long_context_tier` check ("Payer-side price verification") stops a node from spending `input_count_bound`'s ±10% tolerance to push a sub-threshold request across the cliff.

**Minimum charge.** `min_price` is the microUSDC floor that `amount_charged` must respect on non-zero usage. It is the larger of two components, both configured under `zs.min_charge` on the node:

```
tokenFloor    = ceil(min_charge.output_tokens × output_rate / 1_000_000)   # 0 if either operand is 0
algoTxnFloor  = ceil(min_charge.algo_txns × 1000 × algo_usd_price)         # 0 unless paid model + enabled + fresh oracle
min_price     = max(tokenFloor, algoTxnFloor)
```

- **Token component** (`min_charge.output_tokens`, default `1000`, `0` disables). A successful response bills as if it produced at least this many output tokens at the ticket's output rate, so a tiny completion never settles for ~0 microUSDC. A model whose `output_rate` is `0` contributes `0`.
- **µALGO component** (`min_charge.algo_txns`, default `0` = disabled). Recovers the Algorand network fees the operator pays on the `open()` + atomic `settle()` flow, since the operator fee-pools the whole flow. The node converts this µALGO budget to microUSDC at reserve, using its cached ALGO/USD reading. It applies only when the ticket is paid (below) and the oracle has a fresh reading at reserve. A free model, a disabled component, or a stale or never-populated oracle contributes `0` for that cycle.

**Recommended `algo_txns`: `7`.** `open()` costs 2 × minTxnFee (the `usdcPayment` + `open` AppCall group). A paid steady-state `settle()` costs 5 × minTxnFee: the 2 co-signed outer transactions plus 3 USDC disbursement inners (refund, payout, treasury fee), with no op-up ("Settlement asset model"). The settle fee is **sized to the inners that actually fire**. It is lower when fewer disburse (2 for a free model, 3 for a zero-charge failed request). It is higher only on a node's first settle after a multi-day idle, which funds revenue-ring catch-up op-ups that amortize across later requests.

**"Paid"** is read from whichever basis prices the ticket, since a ticket can bill real microUSDC with no token rates at all:

- A token-priced ticket is paid if its token rates are not both `0`.
- A dedicated-image-route ticket, whose token rates are always `0`, is paid if its route's rate is `> 0`: `image_rate` for generation, `image_edit_rate` for edits.
- A chat ticket with a reserved in-loop image-tool budget `> 0` is paid, because it bills `image_rate` for each produced image on top of its tokens. So a **free** chat model offering paid image tools is still a paid ticket.

Reading "paid" off the token rates alone would call the last two free and forfeit the operator's recovery.

With the defaults (`output_tokens: 1000`, `algo_txns: 0`), only the token floor applies. `min_price ≤ max_price` always holds: when the rate-based `max_price` would be below the floor (tiny paid requests), the node raises `max_price` to `min_price` before signing the ticket and before composing the pre-signed `open()` group, so the escrow covers the floor. The inference-failure short-circuit, `actual_input_count == 0 && actual_output_count == 0`, still settles at `amount_charged = 0` regardless of `min_price`, refunding the payer in full although the operator paid the gas. Charging the floor on failed inferences would mean retiring that (0,0) short-circuit, which is out of scope.

**Usage types.** `Ticket` and `UsageReceipt` carry a one-byte `UsageType` for each metered direction in `CanonicalBytes()`, placed before the ticket's `cache_read_rate` and the receipt's `cached_input_count` at the tail:

| Value | Name | Count unit | Rate unit |
|---|---|---|---|
| `0` | `None` | direction / aux slot unused | — |
| `1` | `Tokens` | tokens | microUSDC per 1,000,000 tokens |
| `2` | `Images` | produced image units | microUSDC for one 1024²-standard image × `imageprice.Factor(size, quality)` |
| `3` | `Characters` | characters | microUSDC per 1,000,000 characters |
| `4` | `Seconds` | whole seconds | microUSDC per second |

`UsageType` changes only how a *count* is read; `max_price` and `amount_charged` stay a single microUSDC amount whatever the unit. Chat is `Tokens`/`Tokens`. Just before its trailing `cached_input_count`, the receipt also carries an `aux_output_usage_type` (one byte) + `aux_output_count` (`u64`) pair for the one inline secondary modality a response may mix in, such as tool-produced images alongside chat tokens; `0` / `None` means none. Reference: `proto/go/ticket/usagetype.go` (TS mirror `proto/ts/src/ticket/usagetype.ts`).

**Dedicated image route (`/v1/images/{generations,edits}`).** An operator prices each route with a per-image rate, `image_rate` / `image_edit_rate`, advertised on `/v1/zs/details` as `image_rate_micro_usdc` / `image_edit_rate_micro_usdc`: microUSDC for one 1024²-standard image. Eligibility comes from the `serves_image_gen` / `serves_image_edit` booleans on `/v1/zs/details`, not from the rate. A free route advertises a `0` rate, which `omitempty` drops, so the rate alone cannot tell it from a non-image model. A peer keys eligibility off these flags. Pricing:

```
Factor(size, quality) = (w·h)/(1024·1024) × qualityMult   # reduced rational
qualityMult: low 0.25 / medium·standard·auto·"" 1.0 / high·hd 4.0
per_image = ceil(image_rate × Factor(size, quality))
amount    = n × per_image                                  # imageprice.CostMicroUSDC
```

An aspect-ratio size (`"16:9"`), `"auto"`, or an empty or unparseable size prices at the 1024²-standard reference (`Factor = 1`). The reserve request carries `image_n` / `image_size` / `image_quality` / `image_edit`, which are not in `Ticket.CanonicalBytes()`. From them the node sizes `max_price = CostMicroUSDC(rate, image_n, image_size, image_quality)` and tags the ticket `output_usage_type = Images`. At serve time it bills the images actually produced (below), clamped to `baseMax`. The receipt carries `output_usage_type = Images` and the **delivered** image count in `actual_output_count`. Reference: `proto/go/imageprice` (TS mirror `proto/ts/src/imageprice`), pinned by `proto/testdata/image_vectors.json`.

**Billing basis: delivered pixels.** `max_price` is sized from the *requested* size, after operator resolution. The charge, though, uses the dimensions of the images the backend actually **returned**, measured from the image bytes and each clamped to the operator's `max_size`: `Σ ceil(rate × Factor(delivered_size_i, quality))`. This is node-local behavior with no wire surface, but it defines what `amount_charged` means. A peer may assume the charge matches the pixels it received, and that `actual_output_count` is the count delivered, not requested.

Backends do not always honor the requested size, and the gap is otherwise invisible. For a period, xAI's `/v1/images/edits` ignored size and rendered its 1k tier while nodes billed a configured 2k, a 4× overcharge. Resolution tiers are also not area-preserving across aspect ratios, so no fixed request→pixels table stays correct. Two clamps keep `amount_charged ≤ max_price` when a backend over-delivers:

- Each measurement is shrunk to `max_size`'s area, keeping its aspect ratio, so a widescreen result is not priced as the square cap.
- The dedicated route also caps the total at the figure the reserve was sized with. That is stricter than `baseMax`, because this route reserves exactly what it resolves.

**Measurement covers size only.** `quality` leaves no observable trace in the returned image, so `max_quality` remains its only bound.

**Operator size/quality resolution.** An operator may set per-model default and cap knobs for this route (node-local config). A request resolves through them in this order:

1. `default_size` / `default_quality` fill an omitted value.
2. An aspect-ratio size becomes concrete pixels covering `default_size`'s area.
3. `default_size` is a **floor**: a smaller request is raised to it by area, keeping its aspect ratio.
4. `max_size` / `max_quality` clamp **down**.

The floor stops a caller from selecting a cheaper tier than the operator serves. On a tiered backend the smaller image cannot be rendered, so billing for it while delivering the operator's tier would misprice. The node resolves identically at reserve and at serve time, so `max_price` covers the charge either way: a request omitting `size` on a model with `default_size: 2048x2048` reserves at 4× the base, and one above `max_size` reserves at the clamped tier. Pricing the reserve from the raw request while billing the resolved value would under-lock every default-sized request, which the serve-time ceiling check then rejects as `image_budget_exceeded`.

The knobs are **not on the wire**. A caller sees their effect only through the ticket's `max_price` and the receipt, so a peer must treat the node's `max_price` as authoritative rather than recompute `CostMicroUSDC` from its own request parameters.

`image_rate_micro_usdc` / `image_edit_rate_micro_usdc` stay the per-1024²-standard **base**. Reserve sizing and cross-operator price ordering use them, and they must not be rescaled. For **display**, two more `omitempty` values carry the knobs' effect, like the in-loop tool's base/cap pair:

- `image_default_micro_usdc` / `image_edit_default_micro_usdc`: the **representative** price, what a caller sending no size or quality pays (the base resolved through `default_size` / `default_quality` and clamped to `max_size` / `max_quality`). Omitted when no knobs are configured, since the base is then the representative price.
- `image_cap_micro_usdc` / `image_edit_cap_micro_usdc`: the worst case, `base × Factor(max_size, max_quality)`. Omitted when the operator sets **no** cap. Unlike the in-loop tool, whose ceiling defaults to 1024²/medium, an uncapped dedicated route has no ceiling: the caller picks the size and the charge scales with it, so there is no honest cap to quote.

A peer shows `default → cap` as a range, collapsing to one price when the two are equal (`default_size == max_size`) or the cap is absent. A node that predates these fields omits both; a peer then falls back to the raw rate as the single price. These fields are for discovery and display only and change no sizing.

A dedicated image model needs **no token pricing**. The node pins `input_rate = output_rate = 0` on its tickets (unused, since `max_price` comes from `CostMicroUSDC`), so the operator declares only `image_rate` / `image_edit_rate` and omits the per-model `pricing` block. An image model **never inherits** the fleet-wide `default_pricing`. That setting exists for token-billed chat models, and inheriting it would advertise a per-token price the image route can never bill. A peer's candidate **price ordering** on these endpoints MUST therefore key off `image_rate_micro_usdc` / `image_edit_rate_micro_usdc`, not the token rates, and a caller's per-1M-**token** price ceiling does not apply to them. `Factor(size, quality)` is the same for every candidate, so ordering by base rate equals ordering by `CostMicroUSDC`. Unlike a token rate, a `0` image rate among operators that advertise `serves_image_gen` means **free**, not undeclared, so it ranks cheapest.

**In-loop image tools (`zs_image_generation` / `zs_image_edit` on `/v1/responses`).** A chat model offering these is priced from the same per-1024²-standard `image_rate` base. It advertises **two** microUSDC values per tool on `/v1/zs/details`, both `omitempty` and non-zero only on a chat model with an `image_tools` block:

- `image_tool_rate_micro_usdc` / `image_edit_tool_rate_micro_usdc`: the worst-case **cap**, `ceil(base × Factor(max_size, max_quality))`, from the operator's per-tool ceilings. These default to `1024x1024` / `medium`, so `Factor = 1` and cap == base. This is the reserve-sizing figure: a peer reserves `image_tool_budget × cap` of image headroom, via the `image_tool_budget` / `image_edit_tool_budget` reserve fields. The node bills `Σ base × Factor(delivered_size_i, quality) ≤ cap` over the images produced; quality is per call, and only size varies per image. This is the dedicated route's delivered-pixels basis, with each measurement clamped to `max_size` so no image exceeds the cap the reserve was sized with. The model picks each image's size and quality, and the operator's default/floor/cap resolution applies to that request, but the charge follows what came back.
- `image_tool_base_micro_usdc` / `image_edit_tool_base_micro_usdc`: the **representative** price, what an image costs when the model does not set a size (the base scaled to `default_size` / `default_quality`, clamped to the per-tool `max_size` / `max_quality` ceiling). With no defaults configured it equals the raw base. Display only: it lets a peer show a representative per-image price and, when the ceiling is above the default, a price **range** up to the cap. An operator that pins a tool to one tier (`default_size == max_size`) reports base == cap, a single price. A node that predates this field omits it; a peer then uses the cap as the single price.

The cap is the **true ceiling**. When the operator caps *below* 1024²-standard (`max_quality: low`, or `max_size < 1024²`, so `Factor < 1` and cap < base), the 1024²-standard image cannot be produced. A peer must then **clamp the displayed base to the cap** and never show a higher price. `default_size` / `default_quality` / `max_size` / `max_quality` are **not** on the wire; only the two pre-multiplied values are.

A tool is eligible when its cap (or base) is positive. `amount_charged ≤ max_price` holds because the reserve uses the cap and billing never exceeds it. These fields are **separate** from the dedicated route's `image_rate_micro_usdc` / `serves_image_gen`: a chat model that set the dedicated field would attract bare image-route reserves.

**Per-call tool pricing (vendor server-side tools + node `zs_` tools).** A request can also incur a **per-call fee** for tool calls. The operator prices these in `zs.tool_pricing`, and they are advertised per model on `/v1/zs/details`. There are two kinds.

**Vendor server-side tools** are hosted tools the *upstream* LLM runs inside one completion and bills the operator for per call (xAI `web_search` / `x_search` / `code_interpreter`, OpenAI `web_search` / `file_search`, Kimi `$web_search`). The node sorts each `tools[]` entry into one of three classes:

| Class | Members | Handling |
|---|---|---|
| Client tools | `type:"function"`, a bare `{"function":{…}}`, or a `zs_*` built-in | Passed through untouched. |
| Not-billed tools | Hosted or caller-executed types that no upstream charges per call for: `mcp`, `custom`, `local_shell`, `apply_patch`, `computer_use`, `shell` with `environment.type:"local"`, Anthropic's `bash` / `text_editor`. They cost tokens, not calls. | Passed through untouched and never metered. `vendor_tool_catchall_micro_usdc` does not apply to them. |
| Vendor server-side tools | Every other `type`, so an unrecognized hosted tool stays default-denied. | **Unpriced: stripped from the request**, so the operator is never charged for a tool it didn't price. Priced: forwarded, with the per-request `vendor_tool_call_cap` injected as the upstream's own cap (`max_tool_calls` / `max_turns`) so calls cannot exceed the reserved count. |

Only the vendor-*hosted* members of the not-billed class can be made billable, by an explicit named rate. A caller-executed member can never be metered, since the caller ran it, so pricing one is a config error. A surviving hosted tool still counts toward `vendor_tool_call_cap` at any rate, including zero, because the cap also bounds context growth.

Under strict chat, where no cap knob exists, a vendor tool priced at exactly `0` survives. The chat-only `search_parameters` / `web_search_options` fields follow the `web_search` rate and survive on the same rule. The strict-chat rule exists to stop *uncapped per-call overage*, and at a rate of zero there is none.

The node reads executed-call counts from the completed response, summed across every upstream call in its tool loop. It uses a structured `usage` field where present (xAI `usage.server_side_tool_usage_details.*_calls`, Anthropic `usage.server_tool_use.*`), and otherwise counts `*_call` items in the Responses `output[]`. The count excludes the caller-executed not-billed types: `function_call`, `tool_call`, `custom_tool_call`, `local_shell_call`, `apply_patch_call` and `computer_call` never count, while a hosted-but-free `mcp_call` does. A passed-through `mcp` connector is fetched by the *upstream*, never by the node, so it is outside the node's URL-provenance gate.

**Node `zs_` tools** are the built-ins the node runs itself (`zs_web_search`, `zs_web_read`, `zs_image_search`); it counts their executions directly. `zs_image_generation` / `zs_image_edit` bill per produced image instead (above).

**Advertised fields** (all `omitempty`, per model):

- `tool_call_rates_micro_usdc`: canonical tool name → per-call microUSDC, for both kinds.
- `vendor_tool_catchall_micro_usdc`: blanket per-call price for any *unnamed* vendor tool. Never applied to `zs_` tools.
- `vendor_tool_call_cap`: the per-request cap on vendor tool calls.
- `vendor_tool_tokens_per_call`: estimated input-token growth per vendor call, since search results are fed back into context.

A peer folds `max_tool_iterations × max_zs_rate` + `vendor_tool_call_cap × max_vendor_rate` + the input-token cost of `vendor_tool_call_cap × vendor_tool_tokens_per_call` into `max_price`. The node bills the actual `Σ count × rate` on the receipt's **`extra_micro_usdc`** line (the additive slot in-loop image tools also use), clamped to `base_max`, so `amount_charged ≤ max_price` holds. Rates are **advisory and not signed into the ticket**. Only the reserve (`max_price`) and the receipt clamp bind, so tool pricing needs no ticket canonical-bytes field and no `ProtoVersion` bump.

**Signature domain.** The node signs a fixed-size digest:

```
digest = sha256(CanonicalBytes())
sig    = Ed25519(node_signing_priv, digest)         # raw — no further prefix
```

`CanonicalBytes()` is a length-prefixed binary serialization of every ticket field except `sig`, domain-tagged with `"zs-ticket-v2\x00"`. Its tail is the `input_usage_type` / `output_usage_type` bytes followed by the `cache_read_rate` `u64`. The tag separates ticket signatures from receipt signatures (tagged `"zs-receipt-v2\x00"`) and from any future Ed25519 use. `escrow.protest()` verifies the receipt digest, built the same way with its own tag, on chain with `op.ed25519verifyBare(digest, sig, node_signing_pub)`. The ticket digest is verified off-chain only ("Ticket signature").

**Not Algorand sign-bytes.** `algosdk crypto.SignBytes`, Pera's `signData`, Defly's `signMessage` and any other API that prefixes its input with Algorand's `"MX"` cannot produce ZeroSignal ticket or receipt signatures. Those APIs sign `Ed25519(priv, "MX" || msg)` over the raw message; ZeroSignal signs a 32-byte sha256 digest of the domain-tagged canonical body. The signer must expose a raw Ed25519 sign operation, or accept the precomputed digest with no further framing. Reference: `ticket.BytesSigner`; raw signing in `proto/go/keystore/keystore.go::SignBytes`.

The signing key is the private key of the serving node's **signing Algorand address**, not the owner address. Proxies verify with the public key decoded from that address (`DecodeAlgorandAddress`). The same key signs the node's pre-signed `open()` AppCall at reserve time and `settle(asOperator=true)` at receipt time; consensus authenticates those over the transaction bytes, not the receipt digest. Reference: `ticket.Ticket.Sign` / `Ticket.Verify` / `TicketSigDigest` in `ticket/ticket.go`; `ticket.UsageReceipt.Sign` / `ReceiptSigDigest` in `ticket/receipt.go`.

### Payer-side price verification

The escrowed amount, `ticket.max_price`, is written by the **node**. The payer signs only the USDC leg of the `open()` group, pinned to `assetAmount == max_price` ("Settlement asset model"), and the contract asserts `amountCharged + netFee ≤ max_price`. So a node can never extract *more* than the ticket says. But neither bounds `max_price` itself, and the advertised rate card is non-binding (§ 3c "Authority of advertised vs. ticket-pinned values"). A well-formed, correctly signed ticket can therefore still be over-priced by:

- inflated rates;
- an arbitrary `max_price` at honest rates;
- `min_price` raised to the ceiling, so every request settles at the maximum;
- an `input_count` above what the caller actually sized;
- a `cache_read_rate` that turns the advertised cache discount into a surcharge.

So before opening escrow, a payer-side peer (proxy or direct client) **recomputes** the price from the ticket's own signed numbers and bounds it against the operator's advertised card. No new wire fields are needed: every input is already on the signed ticket, on `/v1/zs/details`, or in the on-chain `pfee` global. Each check is named by the violation it reports:

| Check | Bound | Reference |
|---|---|---|
| `max_price` | `max_price == ExpectedMaxPrice(input_count, max_output_count, input_rate, output_rate, min_price, extraBase, feeBps)` — **exact** | none (the ticket's own fields + on-chain `feeBps`) |
| `cache_read_discount` | `cache_read_rate ≤ input_rate` — a cache read is always a discount | none (internal invariant) |
| `rate_bound` | `input_rate` / `output_rate` ≤ **tier-appropriate** advertised × `RateMaxMultiple` (base below the threshold, high at/above it — see the tier note below) | `input_rate_usd_per_1m` / `output_rate_usd_per_1m` (+ `long_context_{input,output}_rate_usd_per_1m` when a tier is advertised) |
| `cache_read_bound` | `cache_read_rate` ≤ **tier-appropriate** advertised × `RateMaxMultiple` | `cache_read_rate_usd_per_1m` (+ `long_context_cache_read_rate_usd_per_1m`) |
| `long_context_ordering` | when a tier is advertised: high `input` / `output` ≥ their base counterparts — a surcharge, not a discount | `long_context_{threshold_tokens,input_rate,output_rate}_usd_per_1m` |
| `long_context_tier` | when a tier is advertised: a signed `input_count` at/above the threshold requires the peer's **own** bound to be at/above it too — the tier is not purchasable with `input_count_bound`'s tolerance | `long_context_threshold_tokens` + the peer's own tokenize bound |
| `min_charge_bound` | `min_price ≤ MinChargeFloor(advertised) × RateMaxMultiple` | `min_charge_output_tokens` / `min_charge_microusdc` |
| `input_count_bound` | `input_count ≤ ReserveInputCount(…) × (1 + InputCountTolerance)` | the peer's own tokenize bound ("Input-token bound") |

`extraBase` is any additive per-request budget the caller folded into the reserve: the in-loop image-tool headroom and the per-call tool-fee reserve (`ToolFeeReserveMicroUSDC`, the sizing formula in "Per-call tool pricing"). Including it lets the `max_price` recompute match the node's figure exactly. An advertised rate of `0` (free) requires a signed rate of `0`. `RateMaxMultiple` is an *abuse* bound, not a precision bound: it absorbs a legitimate reprice between the details probe and the reserve, which § 3c says is expected and not misbehavior.

**Long-context tier.** When the operator advertises a long-context tier (§ 3c, § 3a "Rate derivation" → "Long-context (surcharge) tier"), `rate_bound` and `cache_read_bound` compare against the **high** advertised rates when the ticket's signed `input_count` reaches `long_context_threshold_tokens` (`IsLongContext`), and against the **base** rates below it. That is the same signed count the node priced with, so `max_price` stays an exact recompute. `long_context_ordering` also rejects an advertised tier whose high rates undercut the base. A ticket that signs the high rate onto a **sub-threshold** `input_count` is bounded against the **base** rate and rejected unless it also fits within base × `RateMaxMultiple`. An exactly-2× surcharge happens to fit that bound during a fleet rollover; any tier above 2× needs tier-aware verifiers deployed first.

`long_context_tier` is what makes it safe to choose the comparand from the **signed** count. `input_count_bound` alone allows a signed count up to `reserveInputCount × (1 + 0.10)`. Near the cliff, a ≤10% count inflation would buy a **2× multiplier on the whole request**, and `rate_bound` would accept it, since an exactly-2× surcharge sits right on the base × `RateMaxMultiple` boundary. The tolerance exists to absorb tokenizer drift, not to buy a tier. So this check compares **tiers, not counts**: a signed `input_count` at or above the threshold is refused whenever the peer's own bound is below it. It cannot false-reject an honest node, because a node only ever clamps `input_count` **down**. (Its own `ReserveInputCount` call adds no headroom, and the only upward move is the `min_input_count` floor, far below any real threshold.) Like `input_count_bound`, it is skipped when the peer has no bound of its own (`reserveInputCount == 0`).

**Fail-open.** A missing reference MUST NOT block an honest send:

- No advertised rate or min-charge for the model ⇒ skip the checks that need it. The two reference-free checks (`max_price`, `cache_read_discount`) still run.
- No advertised `cache_read_rate_usd_per_1m` (no discount offered) ⇒ skip `cache_read_bound`.
- No advertised long-context tier (no `long_context_threshold_tokens`) ⇒ the rate bounds use the **base** rates for every `input_count`, and neither `long_context_ordering` nor `long_context_tier` runs.
- No cached on-chain `feeBps` ⇒ skip the recompute entirely.
- `output_usage_type` of `Images` / `Characters` / `Seconds` ⇒ the token-price verifier skips the ticket, because a different primitive (`imageprice`, `videoprice`) prices it.

**The one check that fails closed.** Fail-open covers a *missing* reference. `long_context_ordering` judges a reference that is **present and self-contradictory** (high rates below base), so it rejects **every** ticket from that operator, including sub-threshold ones, instead of skipping. An inverted advertisement says nothing trustworthy about either tier, so there is no rate left to bound against, and the payer cannot route around it by choosing a different `input_count`. An honest node never reaches this state, because `validateLongContextPricing` refuses such a config at startup.

The cross-operator aggregate a proxy republishes on its own `/v1/zs/details` cannot create the condition either. Each high rate there is a min over the tier-advertising operators and each base rate a min over all of them, so `min(high) ≥ min(base)` holds whenever every contributor is consistent. Per-operator verification never reads that aggregate anyway.

**Settlement sibling.** At receipt time the same approach covers the one cached-token field the ticket does not bound. A receipt with `cached_input_count > actual_input_count` is self-inconsistent and is rejected as an amount violation ("Settlement receipt").

**This is refusal, not enforcement.** A node can still *sign* an over-priced ticket; verifiers just decline to escrow against it. An inflated but internally consistent `max_price` is not slashable, since § 3b (b) covers only charging **above** `max_price`. Enforcement would need per-model pricing on chain in `NodeRecord`, so that advertised-versus-signed becomes attributable. That is out of scope.

**Reference implementation.** Pricer and verifier are one shared, golden-vectored primitive, which keeps the verifier from drifting from the pricer:

- `proto/go/pricing` (`ExpectedMaxPrice`, `ExpectedBaseMax`, `RateBasedMaxPrice`, `ReserveMinPrice`, `MinChargeFloor`, `AlgoTxnFloorMicroUSDC`, `GrossUpForFee`, `CeilInputCost`, `ChargeFor`, `ToolFeeReserveMicroUSDC`, `IsLongContext`, `VerifyTicketPrice`, `DefaultPolicy`), with TS mirror `proto/ts/src/pricing`, pinned by `proto/testdata/pricing_vectors.json`.
- The **node prices with the same code the payer verifies with**: `node/internal/server/reserve.go` and `receipt.go::chargeFor` delegate to it.
- `DefaultPolicy` is `RateMaxMultiple: 2.0`, `InputCountTolerance: 0.10` (the node's `input_budget_tolerance`), `FailOpen: true`.
- Proxy: `proxy/internal/server/hayai_dispatch.go::verifyReservePrice`. A violation skips that operator like a capacity rejection; if every operator is rejected on price, the proxy returns `502 ticket_price_rejected`.
- Client: `client/src/stream/ticket-price-gate.ts`, called from `envelope-fetch.ts`, raises the `ticket_price_exceeded` blocker.

### Response (refusal)

| Condition | Status | Body / Headers |
|---|---|---|
| Operator at capacity (`active tickets >= max_active_tickets`) | `429 Too Many Requests` | code `no_capacity`, OpenAI-shaped, with `Retry-After: <seconds>`. The value is small and fixed (~2s): a full pool is almost always active inference, and slots free as requests complete, so the wait is seconds, not the ticket TTL. |
| Unknown or unpriced model, or a priced model the operator's upstream LLM backend isn't currently serving | `400` | code `unsupported_model` |
| Operator's upstream LLM backend unreachable: it failed the node's periodic health probe (in this state the operator advertises zero models on `/v1/zs/details`) | `503 Service Unavailable` | code `provider_unavailable`. Transient: the proxy should try another operator and re-check `/v1/zs/details` before routing back. |
| Plaintext request body (not `application/vnd.zs-reserve+json`) | `415 Unsupported Media Type` | code `bad_content_type`; the reserve is sealed-only (see "Endpoint" above) |
| Request body exceeds the node's reserve-body size cap | `413 Payload Too Large` | code `reserve_body_too_large` |
| Malformed request body (missing model, zero token fields, missing or unparseable `proxy_recipient`) | `400` | code `invalid_reserve` or `invalid_proxy_recipient` |
| Missing or undecodable `payer_addr` (required for escrow admission) | `400` | code `missing_payer_addr` / `invalid_payer_addr` |
| `payer_sig` missing (when `zs.require_payer_sig`), forged, bound to another node's `(operator_id, node_id)`, or outside the signature window | `401 Unauthorized` | code `invalid_payer_sig`. The body carries `node_time=<unix>` so a skewed-clock client can resync and re-sign once ("Reserve-request signature"). |
| Replayed sealed reserve: a `proxy_recipient` already seen within the signature window | `409 Conflict` | code `reserve_replayed`. A `proxy_recipient` is recorded only by a prior *successful* reservation. The client should re-reserve with a fresh `proxy_recipient`. |
| Payer holds no prepaid-pool opt-in (when `zs.require_payer_optin`) | `403 Forbidden` | code `payer_not_opted_in`. Opt-in is not funding: a drained but opted-in pool still passes. The client should prompt a deposit. See "Funds gate" under "Reserve-request signature". |
| Opt-in check unavailable: the cold-miss budget is exhausted, or the opt-in probe failed (transient algod) | `503 Service Unavailable` | code `payer_optin_unavailable`, with `Retry-After`. Fails closed, because admitting an unverified payer would reopen slot exhaustion. See "`payer_optin_unavailable` as an alert" below. |
| Payer has used its daily free-ticket allowance (free models only, where the reserve prices at `max_price = 0`) | `403 Forbidden` | code `free_quota_exhausted`. The message names the reset time, and `Retry-After` gives it in seconds. See "Why `free_quota_exhausted` is `403`" below. |
| Free-ticket allowance check unavailable: the cold-miss budget is exhausted, or the allowance read failed (transient algod) | `503 Service Unavailable` | code `free_quota_unavailable`, with `Retry-After`. Fails closed, like `payer_optin_unavailable`: admitting the reserve would only move the refusal to an on-chain revert that kills the turn and strands a reserve slot. Metric `zs_reserve_free_quota_total`. |
| Arithmetic overflow in `max_price` computation | `400` | code `price_overflow` |
| No fresh ephemeral sealing key (mid-rotation / just restarted) | `503` | code `node_ephemeral_unavailable` (§ 8, § 10) |

**`payer_optin_unavailable` as an alert.** A sustained rate tells the operator the funds gate is under a key-rotating flood (metric `zs_reserve_funds_gate_total{outcome="cold_miss_budget"}`).

**Why `free_quota_exhausted` is `403`, not `429`.** The cap is per payer and enforced on chain, so backing off or failing over to another operator, which a `429` invites, cannot help. It is the same class as `payer_not_opted_in`. See "Free-ticket quota" below.

**Oracle outage** at reserve time is **non-fatal**. The node still issues the ticket, pins `algo_usd_price = 0` in the reserve response, and drops the **µALGO component** of the minimum charge to `0` for that cycle. The **token component** (`min_charge.output_tokens × output_rate`) does not use the oracle, so a paid model with default settings keeps a non-zero `min_price` through an outage. `min_price` falls to `0` only when the token component is also zero (a free model, or `output_tokens` set to 0). A dedicated-image-route ticket has **no** token component, since it produces no tokens, so its `min_price` does fall to `0` during an outage. In-flight tickets settle normally because their rates were pinned at reserve.

### Free-ticket quota

A ticket whose `max_price` is `0` (both declared rates zero and no minimum charge) escrows nothing and pays the operator nothing. It still holds one prepaid-MBR slot until settlement, so without a limit free models would be an unrationed faucet.

The escrow contract caps them **per payer, per 24-hour window**: at most `FREE_TICKETS_PER_DAY` free `open()` calls, 20 in the current deployment. The window starts at **the payer's first free open**, not at a calendar boundary. That open stamps the window start and sets the count to 1. Later opens increment the count up to the cap. After that the payer is refused until `now >= window_start + 86400`, when the next free open starts a new window. The window is fixed, not sliding, so a payer can use the whole cap at the end of one window and again at the start of the next.

A quota slot is used at `open()` and **never given back**. A free ticket that is refunded (`refundInactive`), lapses (`settleLapsed`), settles at zero or is frozen does not return it; otherwise opening and refunding would get around the cap. This counter is independent of the prepaid-MBR slot, which *is* returned when the ticket box is deleted.

#### Why the counter is a box, and what it costs

The counter lives in a per-payer **box** (`q:` + the payer's 32-byte public key), not in payer local state. This is required, because the payer can clear its own local state at will. `CloseOut` wipes it, and a bare `ClearState` transaction wipes it whatever the clear-state program returns (Algorand's guarantee that an app cannot hold an account hostage). A local-state quota could be reset by opting out and back in for a few thousand microALGO, which is no cap at all. A box belongs to the app: only the contract can delete it, and nothing in the contract does.

The box is created on the payer's **first** free open. Its MBR is charged **once and permanently** to the payer's prepaid ALGO pool (`mbrForFreeQuota()`, ~0.0225 ALGO at the current record size). It is never refunded, because a refundable box could be deleted and recreated to reset the counter. Two consequences:

- **Deposit sizing must include it exactly.** A pool funded for only `slots × mbrForTicket()` fails the payer's *first* free open with `insufficient MBR deposit for free-quota box`.
  - Funding code adds `mbrForFreeQuota()` to its target **only while the payer has no box**. Read the box directly (`q:` + pubkey; a 404 means absent) rather than simulating.
  - Cache only a positive answer: once created the box stays, but absence changes the moment the first free ticket opens.
  - Adding the term unconditionally also works, but leaves every payer holding an idle, withdrawable copy forever.
  - The term is smaller than one slot. Funding logic must be able to deposit a partial slot, or a pool at exactly N whole slots can never get its box.
  - Against an app that predates the quota, the method is absent and the term is `0`.
- **It gives the free tier a real cost per identity.** Farming fresh payer addresses burns this amount *irrecoverably* per address. An attacker can still mint addresses, but each one now costs something.

Enforcement is on chain (`open()` reverts with `daily free ticket limit reached`), so it holds across every node. That revert only comes after the node has signed the open group and handed it to the caller, killing the turn at submit time and stranding a reserve slot until the open watchdog reaps it. So the node also **pre-checks** the payer's allowance at reserve with the contract's read-only `freeTicketAllowance(payer)`, and refuses up front with `403 free_quota_exhausted`. (A reverted group fails in evaluation and is never committed, so no network fee is burned.) The pre-check is advisory: the contract stays the authority, and a node with a stale reading just lets through an open that then reverts. Paid reserves never consult it.

`freeTicketAllowance` returns `[remaining, windowEndsAt, capPerDay]` with window expiry already applied, so callers need no clock arithmetic. `windowEndsAt` is **always a real future timestamp**. With no window running, it reports the end of the window that would start now, never `0`, because a `0` would read as the epoch and look like "retry immediately". Callers must pass the payer's quota box as a box reference. A free `open()` (`max_price == 0`) must reference it too, or it fails on chain. A paid `open()` must not: the contract never touches the box there, and the reference would put the payer-derived box name (`q:` + payer public key, a stable payer pseudonym) on chain for nothing. The node composes `open()`, so it applies this split when it builds `presigned_open_txn`.

Reference: `proto/go/escrow.OpenBoxReferences`.

**Nodes must not assume the deployed app has the quota.** Methods resolve against the ARC-56 the node was built with, so a node upgraded ahead of the contract would fail every allowance read. Probe support once at startup (for example, simulate `mbrForFreeQuota()`) and run *without* the gate if it is absent. An app that cannot enforce the cap cannot revert an `open()` for it either, so failing closed would take every free model offline against a correctly behaving contract.

Clients should treat `free_quota_exhausted` as final for the current window: show the reset time and offer a paid model. Do **not** retry it on a timer or fail over to another operator. The same payer is refused everywhere, so failover only multiplies reserve traffic.

### Ticket lifecycle

1. **Generate**: the node creates a 128-bit `ticket_id` and a fresh 32-byte `K_response`, computes `commit_k = sha256(K_response)`, and stores `ticket_id → {K_response, max_price, model, expires_at, consumed=false}` in a bounded TTL cache. If the cache is still at its `max_active_tickets` cap after sweeping expired entries, reserve fails with `429`.
2. **Sign**: the node signs the ticket with its Ed25519 private key. The ticket is non-repudiable: anyone with the node's public key can verify that the operator promised this price, at this time, for this shape of work.
3. **Return**: the ticket goes back to the proxy.
4. **Consume**, later, when the paying sealed request arrives: the node looks up `ticket_id` and rejects it if missing, expired or already consumed. Otherwise it atomically sets `consumed` and seals the response with the stored `K_response`, not a fresh key. The same slot stays held during inference and is released (`Release()`) when the response completes.

### Why the response key is committed, not chosen

`commit_k` ties the sealed response to a symmetric key the operator named before payment. When the proxy recovers `K_response` from the `X-Zs-Response-Key` header (§ 5.2 non-stream; § 5.3 stream setup), it checks `sha256(K_response)` against `ticket.commit_k` on **both** response paths, before accepting any body or frame. A mismatch is cryptographic proof that the operator did not seal with the committed key, and the ticket plus the mismatch is slashing evidence (§ 3b has the full evidence list). The commitment is anchored by the node-signed ticket, whose signed canonical bytes include `commit_k` (§ 3a "Ticket signature"), making it non-repudiable off-chain evidence. There is **no on-chain copy**: `open()`'s ABI args carry no `commit_k`, and no transaction in the open group carries a commitment note.

### Sealed request envelope

A ticket-gated request carries the ticket id inside the sealed inner-request frame (§ 4) and binds it into the AEAD AAD with `algorand_tx_id` (§ 6). The node age-decrypts first, as it must, since the admission tag commits to `sha256(plaintext_body)`. It then runs these admission checks, in order, before any inference work:

1. **Ticket lookup.** For encrypted envelopes, the decrypted `ticket_id` MUST be present and match an unconsumed entry in the node's ticket store. The lookup is non-destructive. Missing `ticket_id` → `402 ticket_required`; unknown or already consumed → `402 ticket_invalid`. The lookup does **not** check expiry. Expiry is enforced by `Consume` (against the open-call admission window) and by the background sweep, so an expired but unswept ticket still yields `K_response` to steps 2–3 and is refused at step 4 with `402 ticket_invalid`. That is harmless: whoever holds that `K_response` is by definition the party that reserved it.
2. **Admission tag.** The inner header's `admission_tag` MUST verify against `HMAC-SHA256(K_response, …)` (formula below). Missing or mismatched → `402 admission_tag_invalid`. This runs **before** `Consume`, so a forged tag does not burn the ticket.
3. **Reply-to binding.** The inner header's `reply_to_public_key` MUST equal the `proxy_recipient` declared on the reserve that issued this ticket. Mismatch → `402 reply_to_mismatch`. Like step 2, this runs **before** `Consume`. The admission tag does not cover `reply_to_public_key`, so without this check anyone holding a plaintext inner frame could re-frame the same body and tag to their own recipient and recover `K_response` from the wrapped-key header. This is defense in depth on top of the tag, not a substitute for it.
4. **Consume.** The ticket is atomically marked consumed. A later request reusing the same `ticket_id` fails at step 1.
5. **Payment verification.** The node verifies the pending app call named by `algorand_tx_id`. When the ticket's payer was proven by a reserve signature (`require_payer_sig`), the app call's `payerAddr` arg MUST also equal that payer; mismatch → `402 payment_verification_failed`. An unsigned reserve's `payer_addr` is spoofable, so it is not compared.
6. **Model match.** The body's `model` MUST equal the ticket's reserved model; otherwise `400 model_mismatch`, sealed, with a zero-cost receipt. Rates, the input ceiling and the tool and modality gates all come from the *ticket's* model, while the body reaches the upstream verbatim, so an unchecked mismatch would let a caller reserve a cheap model and be served an expensive one. Unlike steps 2–3, this runs after `Consume`. The caller holds `K_response`, so this is a misdeclaring payer rather than an attacker, and their escrow is already open. The zero-cost receipt settles it at zero instead of stranding it until `refundInactive`.
7. **Body mutations** run after admission, so the tag binds the unmutated body the proxy actually sent: safety-identifier injection (gated, off by default), `store: false` defaulting, requesting streamed usage via `stream_options.include_usage` (streaming chat), and the § 3d built-in tool rewrite.

Reference: step 1 is `ticketStore.Peek`; step 5 runs `proto/go/escrow.VerifyOpenAppCall`; step 7's mutators are `InjectSafetyIdentifier`, `DefaultStoreFalse` and `InjectStreamOptionsIncludeUsage`.

**Payment-verification failure burns the ticket.** Step 5 runs *after* `Consume`. On failure (`402 payment_verification_failed`) the node frees the slot by deleting the store entry: the ticket is gone, not reset to unconsumed. This keeps the store single-transition, so a `ticket_id` is never resurrected and a replayed envelope can never race a retry. The cost is that a *transient* algod failure during the node's mempool poll also consumes the ticket. The client-side contract: on `payment_verification_failed`, **re-reserve**, and never retry the same `ticket_id`.

If the `open()` group did confirm on chain, the escrowed `max_price` sits in the ticket box with no operator claim coming, because the node keeps no settlement-ledger row for a request it refused. The payer recovers it with `refundInactive` after `D = expires_at + grace` ("Settlement windows" below).

Reference: the proxy automates this with a **refund watchdog** (`proxy/internal/hayai/refund_watchdog.go`). It arms on every submitted `open()`, resolves when an atomic settle finalizes or a protest freezes the ticket, and otherwise fires `refundInactive` at `D + margin`. Before firing, it reads the ticket box. A box already gone (settled standalone) or frozen (arbitration owns it) is a no-op. A box whose own `expires_at + settlement_grace_seconds` is later than the locally computed fire time re-arms to the on-chain deadline instead of burning retries.

#### Admission tag

The admission tag proves possession of `K_response` and is attached to every encrypted request. Without it, an attacker who scrapes `ticket_id` from a public `escrow.open()` could race the legitimate proxy and burn the ticket. Checking the tag before `Consume` rejects the attacker's envelope with no state change. `proto/docs/admission-tag.md` walks through the attack.

```
K = K_response                                (32 bytes; proxy obtained by unwrapping
                                               ReserveResponse.wrapped_response_key)
domain = "zs-admission-v1\x00"
bodyHash = SHA-256(plaintext_body)            (32 bytes)
admission_tag =
    HMAC-SHA256(K,
        domain
     || ticket_id          (string bytes of the inner header's base64 value)
     || 0x00
     || algorand_tx_id     (string bytes of the inner header's base32 value)
     || 0x00
     || bodyHash)
```

Both sides hash the inner header's wire-form strings, with no decoding. The NUL separators prevent collisions between `ticket_id` and `algorand_tx_id`, and including `bodyHash` means a captured tag cannot be replayed against a different body. Reference: `wire.ComputeAdmissionTag` in `wire/admission.go`.

### Reference implementation

- `ticket.Ticket` (`ticket/ticket.go`): canonical struct, `CanonicalBytes()`, `Sign`, `Verify`, plus `CommitResponseKey(K)` helper.
- `ticket.ReserveRequest` / `ticket.ReserveResponse` (`ticket/reserve.go`) — including `PayerAddr` and `PreSignedOpenTxn`.
- `wire.NewResponseSealerWithKey` (`wire/seal.go`): sealer variant that takes a caller-supplied K — used by the node to honor the pre-commitment.
- `escrow.ComposeOpenGroup` / `escrow.SubmitPresignedOpenGroup` / `escrow.EncodeOpenGroup` / `escrow.DecodeOpenGroup` (`proto/go/escrow/client.go`): operator-side composition of gtxn[1] (signs AppCall with `fee = 2 × minTxnFee`); proxy-side completion of gtxn[0] (usdcPayment) and atomic submission. Plus `escrow.ComposeDepositMbr` / `ComposeWithdrawMbr` / `ComposeCloseDeposit` / `ReadPayerDeposit` for the per-payer prepaid-pool lifecycle.
- Node-side: `node/internal/server/reserve.go` (handler) composes + signs gtxn[1] post-Reserve, encodes it into `PreSignedOpenTxn`.

### Settlement receipt

The receipt is the post-response counterpart of the ticket. For each completed ticket-admitted request, the node builds one `UsageReceipt` and signs it with the same node signing key that signed the ticket. It returns the receipt in the `X-Zs-Receipt` header on non-stream responses (§ 5.2), or as an `event: zs-receipt` SSE frame just before `[DONE]` on streams (§ 5.3). The proxy independently verifies:

1. The Ed25519 signature, under the node's signing public key.
2. `amount_charged ≤ ticket.max_price`. `amount_charged` is the operator's base (net) take, which the node clamps to the base ceiling `baseMax`, itself `≤ max_price`. At settle the contract separately asserts `amount_charged + grossFee ≤ max_price`, so base plus fee fits the escrow.
3. `body_hash` equals the sha256 of the reconstructed plaintext. For non-stream responses that is the full body. For streams it is the decrypted **content** frames concatenated in `frame_index` order, including any sealed § 5.3.1 tool-round status frames. The `zs-receipt` frame takes the next `frame_index` but is not part of the hash it carries.

Verified receipts feed `escrow.protest()`, ledger reconciliation against on-chain settle and lapse events, and the dispute-retention obligation in § 3b.

**Schema.** On the wire the receipt is **always JSON**. The canonical binary form exists only as signature input. The non-stream header is `base64(JSON)` (`EncodeReceiptHeader`). The streaming `zs-receipt` frame carries the same JSON **sealed** under `K_response`, like a content frame (§ 5.3 "Out-of-band settlement event types" has the sealing and counter rules):

```json
{
  "ticket_id":            "<base64 16 bytes — same form as Ticket.ticket_id>",
  "actual_input_count":  842,
  "actual_output_count": 487,
  "amount_charged":       418200,
  "ttft_ms":              120,
  "decode_ms":            3400,
  "body_hash":            "<lowercase hex sha256(plaintext) — exactly 64 chars>",
  "input_usage_type":     1,
  "output_usage_type":    1,
  "aux_output_usage_type": 0,
  "aux_output_count":     0,
  "cached_input_count":   700,
  "sig":                  "<base64 Ed25519(node_signing_priv, sha256(CanonicalBytes())) — 64 bytes>"
}
```

| Field | Meaning |
|---|---|
| `ticket_id` | The issuing ticket's value. |
| `actual_input_count` / `actual_output_count` | The node's authoritative usage counts, usually read from the upstream's terminal `usage` chunk. `actual_output_count` includes reasoning tokens ("Reasoning tokens" below). |
| `cached_input_count` | The part of `actual_input_count` the upstream served from a prefix or prompt cache. Always `≤ actual_input_count`: enforced when the receipt is built, and re-checked by both payer-side verifiers (§ 3a "Payer-side price verification"). Billed at `cache_read_rate`, with the rest at `input_rate` ("Charge formula"). `0` when the upstream reports no cached count, and on the dedicated image route. |
| `amount_charged` | microUSDC: the operator's base (net) take, computed below and clamped to `baseMax` (the rate-derived ceiling before the fee gross-up), which is `≤ ticket.max_price`. The protocol fee rides on top, within the escrow's gross-up headroom. |
| `ttft_ms` / `decode_ms` | Operator-measured timing: time to first token, and the decode window from the upstream's first frame (of any kind) to completion. On a non-stream request, or one with no first token, `ttft_ms` is total service time and `decode_ms` is 0. Both are co-signed verbatim on `settle()` (§ 3c). `ttft_ms` feeds the per-operator TTFT-latency metric; `decode_ms` with `actual_output_count` feeds the throughput metric. |
| `body_hash` | Lowercase hex, always 64 characters, so it is small, case-stable and easy to copy into logs and dispute material. |
| `input_usage_type` / `output_usage_type` / `aux_output_usage_type` / `aux_output_count` | See "Usage types". |
| `sig` | The node's Ed25519 over the digest in "Signature domain" below. |

**Reasoning tokens.** **`actual_output_count` counts every token the model generated, reasoning included.** This defines the count; it is not always the upstream's `completion_tokens` verbatim. OpenAI-compatible providers disagree. Most fold reasoning into `completion_tokens` (`total == prompt + completion`). Others report it separately (`total == prompt + completion + reasoning`), so their `completion_tokens` is visible output only, and billing it as-is would charge for a fraction of the work. A node reconciles the two from the provider's own arithmetic: it adds `reasoning_tokens` only when the reported `total_tokens` confirms that `completion_tokens` excludes it. An absent or inconsistent total leaves the count unchanged, so an unfamiliar upstream under-bills rather than over-bills. A payer-side verifier may assume the count is generated tokens, not rendered ones; a reasoning-heavy turn legitimately reports far more output than the visible answer. Reference: `proto/go/tools.GeneratedOutputTokens`.

**Charge formula.** Settlement bills the cached part of the input at `cache_read_rate` and the rest at `input_rate`, bills output per token, then clamps the total up to `min_price` (on non-zero usage) and down to `baseMax`, the base ceiling before the fee gross-up (§ 3a "Protocol fee"):

```
if actual_input_count == 0 && actual_output_count == 0:
    amount_charged = 0                                       # inference-failure short-circuit
                                                              # — full refund, min_price bypassed
else:
    cached      = min(cached_input_count, actual_input_count)
    non_cached  = actual_input_count - cached
    # input leg is a SINGLE ceil over the combined numerator (not one ceil per
    # sub-leg) — see below
    input_cost  = ceil((non_cached * input_rate + cached * cache_read_rate) / 1_000_000)
    output_cost = ceil(actual_output_count * output_rate / 1_000_000)
    amount_charged = min(max(input_cost + output_cost, min_price), baseMax)
```

The input leg takes **one ceiling over the combined numerator**, not `ceil(non_cached·input_rate) + ceil(cached·cache_read_rate)`. Two things depend on this:

- When `cache_read_rate == input_rate` (the default for an unset rate), the numerator is exactly `actual_input_count · input_rate`, so a non-zero `cached` count charges exactly what flat billing would.
- Since `cache_read_rate ≤ input_rate`, one ceiling keeps the discounted charge `≤` the flat charge. Two ceilings could round up twice and, for tiny cached counts, exceed it.

The output leg has its own ceiling.

There is **no output round-up**. The minimum-output semantics live entirely in `min_price`'s token component ("Minimum charge"), so a short-output, large-input request whose input alone clears `min_price` bills at the rate-based amount. Per-leg ceiling division keeps every charge a whole number of microUSDC. The outer `min(..., baseMax)` never binds for in-bounds usage: rates are pinned at reserve, so in-bounds usage stays `≤ baseMax`, and reserve enforces `min_price ≤ baseMax` (bumping `baseMax` if needed), so the clamp up cannot break it. It remains as a backstop for arithmetic-overflow paths, which charge `baseMax` as a fail-closed max-out. Because `baseMax ≤ max_price` and the fee rides on top within the gross-up headroom, `amount_charged + fee ≤ max_price` still holds.

**Zero-charge cases.** `amount_charged` is `0` whenever:

- both actual token counts are zero: the inference-failure short-circuit (§ 10), where `min_price` is **not** applied, so a failed request is never billed; or
- the ticket was issued for a **free model** (`input_rate == output_rate == 0`), where `min_price` is `0` for any usage and `max_price` is already `0`.

The receipt is still emitted in both cases, with `body_hash` over whatever bytes were sealed, so the proxy can drive `escrow.settle(amount_charged=0)` and refund the full `max_price` in USDC. For a free model that is `0`, leaving only the standard ALGO box-MBR refund the contract pays on every settle.

**Canonical bytes.** Same encoding rules as the ticket's `CanonicalBytes()` (length-prefixed strings, fixed-width big-endian numbers), domain-tagged with `"zs-receipt-v2\x00"`. `sig` is excluded, since it is the output. `cached_input_count` affects only this **off-chain** digest, which the node (signer) and proxy (verifier) both compute. The contract takes the digest as an opaque ABI arg and never recomputes the preimage, so adding `cached_input_count` needed no contract change, and no cached-token aggregate is tracked on chain. The layout:

```
"zs-receipt-v2\x00"
|| u32_be(len(ticket_id))    || ticket_id_utf8
|| u64_be(actual_input_count)
|| u64_be(actual_output_count)
|| u64_be(amount_charged)
|| u64_be(ttft_ms)
|| u64_be(decode_ms)
|| u32_be(len(body_hash))    || body_hash_utf8
|| u8(input_usage_type)                  # usage-type tail
|| u8(output_usage_type)
|| u8(aux_output_usage_type)
|| u64_be(aux_output_count)
|| u64_be(cached_input_count)            # cached-token tail
```

`ticket_id` and `body_hash` are encoded as their wire-form strings (base64 and hex), not decoded first. The layout does not depend on any JSON encoder, so another implementation can reproduce the exact bytes.

**Signature domain.** Same construction as the ticket signature:

```
digest = sha256(CanonicalBytes())
sig    = Ed25519(node_signing_priv, digest)         # raw — no further prefix
```

The `"zs-receipt-v2\x00"` tag is inside `CanonicalBytes()`. `escrow.protest()` verifies the same digest on chain with `op.ed25519verifyBare(digest, sig, node_signing_pub)`, so off-chain `Verify` and on-chain `ed25519verify_bare` agree byte for byte. Signing the digest rather than the raw message keeps on-chain cost constant as the receipt grows.

The ticket's wallet warning applies here too ("Not Algorand sign-bytes" under "Response (success)"). APIs that add Algorand's `"MX"` prefix (`algosdk crypto.SignBytes`, Pera's `signData`, Defly's `signMessage`) cannot produce receipt signatures. The signer must expose a raw Ed25519 sign operation, or accept the precomputed digest with no further framing. Reference: `ticket.BytesSigner`, `proto/go/keystore/keystore.go::SignBytes`.

**Reference implementation.**

- `ticket.UsageReceipt` (`proto/go/ticket/receipt.go`): canonical struct, `CanonicalBytes()`, `Sign`, `Verify`, `ReceiptSigDigest`, `EncodeReceiptHeader` / `DecodeReceiptHeader`, `SetBodyHashBytes` / `BodyHashBytes`.
- `wire.BodyHashOfBody` / `wire.BodyHashFromFrames` (`proto/go/wire/`): the body-hash construction the node uses for non-stream and streaming cases respectively. Frames are concatenated in `frame_index` order (the same order the AAD counter walks).
- Node-side charge math: `node/internal/server/receipt.go::chargeFor`, delegating to the shared, golden-vectored `proto/go/pricing.ChargeFor` (exact per-token billing, clamp UP to `min_price` then DOWN to `baseMax`); `node/internal/server/reserve.go::computeMinPrice` / `computeAlgoTxnFloorMicroUSDC` (the two `min_price` components) and `computeMaxPrice`; the rate denominator constant `rateDenominatorTokens = 1_000_000` and the `MinChargeConfig` struct in `node/internal/config/config.go`.
- TS parity: `proto/ts/src/ticket/receipt.ts` (`UsageReceipt`, `receiptCanonicalBytes`, `receiptSigDigest`, `signReceipt` / `verifyReceipt`, `encodeReceiptHeader` / `decodeReceiptHeader`).
- Cross-impl golden vectors at `proto/testdata/vectors.json`, regenerated via `cd proto/go && go test ./ticket -run TestVectors -update` and consumed by `proto/ts/test/vectors.test.ts` — any change to the canonical-bytes or digest construction here MUST be matched in both implementations and the vectors regenerated.

### OpenAI compatible safety_identifier

This is a body-level concern, not a wire-format one; the ticket and envelope do not touch it. It is documented here because the behavior is visible downstream of the node, and the identifier is derived from the Algorand address that pays.

**Injection happens on the node**, not the proxy, because only the node can verify the payer: it checks `algorand_tx_id` against algod and reads the payer from the `open()` call's `payerAddr` arg. OpenAI's safety signal is then grounded in the verified on-chain payer, not in a proxy's claim.

After verifying payment, the node *may* inject `safety_identifier = "zs:" + base64(HMAC-SHA256(operator_key, payer_addr))` into the plaintext request body before handing it to the upstream, *unless* the client already supplied a `safety_identifier`. Injection is **opt-in and off by default**, gated by the node's `zs.inject_safety_identifier` (env `NODE_ZS_INJECT_SAFETY_IDENTIFIER`); when off, the body passes through unchanged.

The value is self-describing (the `zs:` prefix) and deterministic per `(operator_key, address)` pair. `operator_key` is a secret each node derives once from its long-lived signing key, so the **same payer gets a different identifier at each operator**. A shared upstream therefore cannot join one payer's traffic across the fleet by comparing identifiers, and, since the key is secret, cannot recompute the identifier even if it learns the address.

Reference: `inject.SafetyIdentifierFor` (takes the key), `server.DeriveSafetyIDKey` in `node` (derives it), `inject.InjectSafetyIdentifier`, and the injection step in `node/internal/server/handlers.go`, where `rc.payerAddr` comes from the verified payment transaction.

### Prompt and response non-retention

By default, no hop on the request path retains prompt or response content: not the upstream provider, not the operator's node, not the proxy. Encryption covers the wire between proxy and node; this section covers the two hosts where plaintext exists. Upstream retention is the one place the default is *caller-controlled* (below). Node-side and proxy-side non-retention are unconditional operator obligations.

#### Upstream retention: caller-controlled, default off

OpenAI's Chat Completions and Responses APIs accept a top-level boolean `store`, which asks the upstream provider to keep the request for the operator's dashboards, evals and fine-tuning data. Some Responses features, notably `previous_response_id` continuation, need that retention: a strict provider honoring `store: false` rejects a `previous_response_id` that points at an unretained response.

**Default off.** The proxy and the node both set `store` to `false` when the client omits it. This protects simple callers (a curl one-liner, a quick Python script) from silently inheriting the provider's retention default; OpenAI's default is to retain.

**Caller may opt in.** An explicit client value, true or false, is kept. A client that needs `previous_response_id` continuation, dashboards or another server-side retention feature sends `store: true`, accepting that the provider will retain the request and response under the operator's account. The choice is visible end to end: the AAD and admission tag commit to the post-mutation body, so a misbehaving operator cannot tamper with it.

**Operator override.** An operator that requires unconditional non-retention can add middleware that forces `store: false` whatever the caller sent; that is a few lines on top of `inject.DefaultStoreFalse`. The protocol does not require it, and doing it removes `previous_response_id` continuation for that operator's clients.

Reference: `inject.DefaultStoreFalse`; the injection step in `proxy/internal/server/hayai_dispatch.go` (`dispatchHayai`); the injection step in `node/internal/server/handlers.go` (`handleStreamable`, right after `safety_identifier` injection); and `tui/main.go`, which sends `Store: openai.Bool(false)` by default and `true` with `--retain-upstream`.

**`store: false` is not zero data retention, and where the upstream can express ZDR the node MUST take it.** `store` asks a provider not to keep the request *for the operator's own use*. It says nothing about the provider's separate audit or abuse retention, which on some upstreams is an unrelated setting. So a conformant node does not leave zero data retention to `store` or to the caller. Wherever the upstream offers a ZDR mechanism, the node applies it **by default, and what it advertises reflects what it applied**: a payer is never told a constraint is in force when it is not. The two mechanisms work in opposite directions, because the upstreams do, and `models[].retention` reports which one applies:

- **The upstream confirms; the node verifies.** xAI sends `x-zero-data-retention: true` on every API response when the org has ZDR enabled. The reference node refuses any otherwise-successful response without that header set to `true`. It returns a client-facing 403 `zero_data_retention_required` with a **zero-cost** receipt: the upstream call succeeded, so there is no error body to forward, and the caller must not pay for a result it does not receive. The startup usage probe is a real inference, so a non-ZDR xAI backend fails to boot. There is **no operator opt-out**: the node only inspects a header the upstream already sends, so the check costs the operator nothing. Advertised as `upstream_confirmed`.
- **The request decides; the node pins.** OpenRouter routes per request, and its privacy settings are documented as tighten-only: request-level `provider.zdr` is OR'ed with the account and guardrail settings, so it can only enable, and guardrails can only get stricter. The reference node therefore sets `provider.zdr: true` and `provider.data_collection: "deny"` on every prompt-carrying body. It overrides any caller value for those two keys and leaves the caller's routing keys alone. A model with no zero-retention endpoint becomes unroutable rather than unprotected. The node checks this at startup against OpenRouter's public, unauthenticated ZDR endpoint list, and refuses to boot on a definite absence. A body that cannot carry the constraints is refused before egress, again with a zero-cost receipt (403 `upstream_privacy_required`). Advertised as `upstream_enforced`.

  **What `upstream_enforced` claims.** The constraint is *asserted, never observed*: unlike xAI's header, nothing comes back confirming it was honored, so an upstream that ignored it looks the same as one that obeyed. It also covers only **the endpoint that serves the request**. When the named upstream is a broker or aggregator, whatever sits between the node and that endpoint also reads the prompt, under settings these keys do not control. The tighten-only argument covers the upstream's *routing filter*, not the broker's own storage. So `upstream_enforced` means "no retaining endpoint served it, as far as the node can tell", not "nothing in the path kept a copy". That is why it ranks below `upstream_confirmed` even though it prevents the leak *earlier*, and why a posture that must name the single party that read the prompt (§ 3e `plaintext_terminates: named_upstream`) cannot rest on it. A node MUST NOT advertise `upstream_enforced` as evidence of anything beyond that scope.

  **The one opt-out.** The pin can cost an operator a model outright, so unlike the xAI check it has **one operator opt-out** (`llm.allow_upstream_retention` in the reference node, per route). A node that takes it MUST advertise **no** `upstream_enforced` tier for that route. The tier is a claim about what the node sends, so dropping the constraint while keeping the claim is a conformance violation, not a configuration choice. `retention` also feeds `config_hash`, so the operator's signed policy fingerprint changes with it. Nothing else about the opt-out is normative, and a node MAY have no such knob at all; but a node that has one MUST keep the advertisement and the outbound body in agreement.

Reference: `inject.EnforceUpstreamPrivacy`, `llm.VerifyOpenRouterZDRCoverage`, and the per-response guard in `node/internal/llm/openai.go`.

#### Node-side non-retention: no logging of plaintext request or response content

Operators MUST NOT log, persist, or otherwise retain decrypted request bodies, response bodies, prompts, completions, tool-call arguments, or tool-call outputs. This is a normative requirement of running a ZeroSignal node, not a default that can be turned off.

Concretely, conformant nodes:

- MUST NOT include prompt or response content (or fragments of either, including any `messages[]` / `input[]` / `output[]` / `delta` fields) in log records, traces, metrics labels, error reports, crash dumps, or any other persistent or queryable channel.
- MUST NOT proxy, mirror, tee, or otherwise duplicate the decrypted request or response stream to any sink other than the configured upstream LLM and the requesting client.
- MUST NOT be operated behind a reverse proxy, sidecar, service mesh, or capture tool whose configuration retains request or response bodies (e.g. nginx `$request_body` capture, Envoy access-log body fields, mitmproxy, any debug shim that dumps payloads).

The reference node implementation logs only metadata required for settlement and observability — token counts, ticket IDs, operator and payer Algorand addresses, model names, error reasons, latency, and microUSDC charges. None of these reveal prompt or response content. Operators forking the node MUST preserve that property.

Pre-envelope errors (malformed envelope, ticket failures, decryption failures) may be logged with their error reasons, since by definition no payer-supplied plaintext is available at that point.

Settlement requires committing to the response bytes through the receipt's `body_hash` (§ 5). The receipt digest, which goes on chain in `settle()`, covers it. The hash is not content and is not subject to this section. The plaintext it was computed from is, and MUST be discarded once the hash is recorded and the response has been sealed for the client.

### Settlement asset model

Tickets escrow USDC, not ALGO. The proxy locks `max_price` microUSDC into the contract at `open()`, in the open group's `usdcPayment`. Every settlement disbursement is also USDC: operator owner, treasury and any payer refund are all transfers of the `usdcAssetId` global the contract was created with.

**Prepaid box-MBR pool (no per-turn ALGO leg).** Each ticket box's minimum-balance reserve comes from a per-payer **prepaid pool**, so **no ALGO moves in the open group**:

- The payer opts into the app with `depositMbr` and deposits ALGO **once**. The contract account holds it, tracked in the payer's **local state** (`algoBalance`, `openTickets`).
- `open()` draws one box-MBR slot: it asserts `(openTickets + 1) × mbrForTicket() ≤ algoBalance`, then increments `openTickets`.
- Each terminal box-deletion path (`settle`, `settleLapsed`, `refundInactive`) **releases** the slot (`openTickets--`) instead of refunding ALGO through an inner transaction.
- The invariant `algoBalance ≥ openTickets × mbrForTicket()` holds across deposit, open, settle, refund and withdraw. The payer may `withdrawMbr` up to `available = algoBalance − openTickets × mbrForTicket()`.
- `closeDeposit` (CloseOut) refunds the balance and opts the payer out, returning the local-schema MBR natively. It reverts while any ticket, including a frozen one, is still live.
- A payer who force-clears its local state (`ClearState`) forfeits its `algoBalance`, which stays in the app. The box-deletion decrements are gated on `app_opted_in`, so a cleared payer's tickets still settle.

Settlement inner transactions are not pre-funded: disbursement fees are pooled from the settle caller's outer fee at finalization.

The open group is therefore two transactions, `[usdcPayment, open()]`. `usdcPayment.assetAmount` MUST equal `max_price`; for a free model that is a valid zero-amount asset transfer. `mbrForTicket()` is the contract's read-only box-MBR figure. It covers the open-time `feeBps` / `discountBps` snapshot, with bounded fields stored as narrow ARC-4 ints (§ 3c "Reserved slots"). It is the unit the pool reserves per ticket, and the figure clients use to size `depositMbr` / `withdrawMbr`; no per-turn transaction leg is asserted against it.

Fees are the operator's responsibility, since the operator is the economic entity, but the transactions are signed by the serving **node**'s hot key and funded through Algorand fee pooling on node-signed AppCalls:

- **Open.** The node's gtxn[1] (the `escrow.open()` AppCall) carries `fee = 2 × minTxnFee`, covering both outer transactions. The payer's gtxn[0] (`usdcPayment`) carries `fee = 0`.
- **Atomic settle.** The node's gtxn[0] carries `fee = (2 + inners + gapOpUps) × minTxnFee`, covering both outer transactions, the disbursement inners `finalizeSettlement` will actually submit, and any gap-scaled finalize op-ups. The payer's gtxn[1] ack carries `fee = 0`.
- **Standalone** (the node's watchdog settle, `settleLapsed`). `fee = (1 + inners + 1 + gapOpUps) × minTxnFee`, pooling over its own disbursements plus the base op-up.

The exceptions are `refundInactive` and `protest`, which the payer fires and pays standard payer-side outer fees for: `refundInactive` carries `2 × minTxnFee` (one outer plus one USDC refund inner), and `protest` carries `4 × minTxnFee` because of its on-chain Ed25519 op-ups.

**The payer's net ALGO cost on the happy path is 0 µALGO.** The one-time `depositMbr` is a separate, payer-funded, fully recoverable deposit, not a per-turn cost.

| Path | Outer txns | Disbursement inners | Operator outer-fee budget | Payer outer-fee budget |
|---|---|---|---|---|
| `depositMbr()` (one-time / top-up) | 2 (payer payment + payer AppCall) | 0 | n/a | `2 × minTxnFee` |
| `open()` (atomic) | 2 (payer usdcPayment + operator AppCall) | 0 | `2 × minTxnFee` (gtxn[1]) | 0 (gtxn[0]) |
| `settle()` happy-path atomic group | 2 (operator first-half + payer ack) | 0–3 (refunds + payouts) + 0–N finalize op-ups (gap-scaled) | `(2 + inners + gapOpUps) × minTxnFee` (gtxn[0]); `5 ×` paid steady-state, `2 ×` free model | 0 (gtxn[1]) |
| `settle()` standalone (watchdog or contested ack) | 1 | 0–3 (refunds + payouts) + 1 base + 0–N finalize op-ups (gap-scaled) | `(2 + inners + gapOpUps) × minTxnFee`; `5 ×` paid steady-state | n/a |
| `settleLapsed()` | 1 | 0–3 | `(2 + inners + gapOpUps) × minTxnFee` (anyone can fire; operator typical) | n/a |
| `refundInactive()` | 1 | 1 (USDC refund) | n/a | `2 × minTxnFee` |
| `protest()` | 1 | 0 (3 OpUp inners auto-budgeted) | n/a | `4 × minTxnFee` |
| `withdrawMbr()` / `closeDeposit()` | 1 | 1 (ALGO refund) | n/a | `2 × minTxnFee` |

In the typical happy path the operator absorbs about **7,000 µALGO per paid request** (2,000 at open plus 5,000 at a steady-state settle), recovered through its advertised USDC rates. A free model costs 4,000 (2,000 + 2,000) and a zero-charge failed request 5,000, because the settle fee is sized to the disbursement inners that fire. The per-ticket box MBR is a one-time per-payer pool deposit (`depositMbr`), fully recoverable with `withdrawMbr` / `closeDeposit`.

### Protocol fee

A protocol fee in basis points (`protocolFeeBps`, default `1000` = 10%, hard-capped at 2000 admin-side) is added **on top of the operator's charge** at settlement and paid by the *payer*. This is the **additive** model. The operator's advertised rate is **net**: the operator receives it in full (`opPayout == amountCharged`), and the payer pays `amountCharged + netFee`. There is no fee discount, so `netFee == grossFee` for every ticket:

```
grossFee   = amountCharged * feeBps / 10000          # amountCharged is the operator's base (net) take
netFee     = grossFee                                # no discount mechanism — discountBps is always 0
opPayout   = amountCharged                           # operator receives the full base
usdcRefund = maxPrice - amountCharged - netFee       # payer net cost = amountCharged + netFee
```

Because the fee rides on top, the node **grosses up** `maxPrice` (the escrowed USDC) at reserve time to cover base plus fee: `maxPrice = baseMax + ceil(baseMax * feeBps / 10000)`. `baseMax` is the rate-derived, min-charge-floored base ceiling, and `feeBps` is read from the contract's `pfee` global. At settle the contract asserts `amountCharged + grossFee <= maxPrice`, and the node clamps the receipt's `amountCharged` to `baseMax`, so `usdcRefund` never underflows. A full-`baseMax` charge refunds at most 1 µUSDC, because the reserve gross-up rounds the fee up and settle rounds it down.

- The treasury inner-payment is skipped when `netFee == 0`. That covers `protocolFeeBps == 0` and zero-charge tickets, including every ticket for a free model, where `amountCharged` and the fee are both `0`.
- Operator-advertised rates and the ticket's `minPrice` are **net of fee**. The protocol adds the fee on top and escrows it, so an operator's published price is what it keeps, not a fee-inclusive figure.
- The fee math lives entirely in the contract. The node's only fee-aware step is the reserve-time `maxPrice` gross-up; the proxy escrows whatever `maxPrice` the ticket carries.

#### Open-time fee snapshot

A ticket's fee rate is **snapshotted at `open()` and fixed for the ticket's life**, not read live at settle. `open()` writes two fields to the `TicketRecord` box:

- `feeBps`: the gross rate, copied from the `protocolFeeBps` global at open.
- `discountBps`: the fee-discount snapshot. No discount mechanism exists, so `open()` always writes **0**. The field is fixed-width (`arc4.Uint16`) and part of the ticket-box layout the Go/TS positional parsers expect; a future discount mechanism could write a non-zero value.

`finalizeSettlement` uses these fields instead of re-reading `protocolFeeBps`:

```
netFee = floor(amountCharged × feeBps / 10000)       # discountBps is always 0, so netFee == grossFee
```

The fee therefore depends only on the co-signed `amountCharged` and the fixed open-time rate. The payer's exact debit (`amountCharged + netFee`), refund (`maxPrice − amountCharged − netFee`) and total are **known as soon as `amountCharged` is set**, without waiting for the settle's treasury transfer to confirm. Getting the *rate* off-chain is a separate, cheap step ("Off-chain rate queries" below). A `setProtocolFeeBps` change **after open does not affect** an already-open ticket; the open-time rate is authoritative. The snapshot carries through every pending and frozen re-constructor, and the early-reject pre-check uses `t.feeBps`.

**No fee discount.** `open()` reads no payer token holding, so the **`open()` AppCall carries no HAY, oracle or staking resource references and no discount inner-transaction fee**; `gtxn[1].fee = 2 × minTxnFee` covers just the two outer transactions. The payer account is always on the AppCall's `ForeignAccounts`, because `open()` reads and writes the payer's prepaid-pool local state. The in-contract HAY-holding helpers and the `hayOracleAppId` / `hayAssetId` / `stakingAppId` config globals remain but are dormant.

**Off-chain rate queries.** The box snapshot is the **settlement authority**: the rate the contract actually charges. Off-chain cost meters (proxy, client) read the rate straight from the live `protocolFeeBps` global with one `GetApplicationByID`. The rate is the same for every payer and `discountBps` is always 0, so the global read is exact and no simulation is needed. (The read-only `feeAndDiscountFor(account)` method is dormant: it returns `[protocolFeeBps, 0]`, the meters do not use it, and it is deprecated rather than removed.) A consumer that needs a *specific* ticket's exact rate reads `feeBps` / `discountBps` from that ticket's box; both are fixed until the box is deleted at finalize.

A mid-flight admin **increase** of `protocolFeeBps` is the one case where the node's reserve-time gross-up can lag. The node uses the value it read at reserve, while `open()` snapshots the live value at open, a much shorter window than reserve to settle. The settle assertion (`amountCharged + grossFee ≤ maxPrice`, using the fixed `t.feeBps`) catches the under-grossed escrow, and the ticket settles at a lower base or lapses. `protocolFeeBps` is admin-gated and capped at 2000, so this is rare.

### Settlement windows

The escrow app enforces a co-signed settlement protocol. Finalization requires explicit on-chain consent from both the operator and the payer; there is no unilateral settle. Implementations MUST respect the window bounds below; an out-of-window call reverts on chain.

#### Atomic settle group (typical happy path)

The node delivers an operator-pre-signed atomic settle group in the response envelope: the `X-Zs-Settle-Group` header on non-streaming responses, or an `event: zs-settle-group` SSE frame on streams (§ 5). Group shape:

| gtxn | sender | fee | role |
|---|---|---|---|
| 0 | `node_signing` | `(2 + inners + gapOpUps) × minTxnFee` (operator pre-signed) | `escrow.settle(ticketId, amountCharged, receiptDigest, ttftMs, decodeMs, inputCount, outputCount, outputUsageType, auxOutputUsageType, auxOutputCount, asOperator=true)` first-half |
| 1 | payer | 0 (proxy signs at submit time) | `escrow.settle(…, asOperator=false)` ack — identical args |

The gtxn[0] fee pays for the whole group: the 2 settle outers, the disbursement inners `finalizeSettlement` will actually submit, and `gapOpUps` finalize op-ups. Disbursements top out at 3, because the pool slot is released by `openTickets--` rather than by an ALGO refund inner.

**`inners`** is derived from the ticket, not assumed. `finalizeSettlement` gates each disbursement separately (operator payout on `amount_charged > 0`, treasury fee on `net_fee > 0`, payer refund on `max_price - amount_charged - net_fee > 0`), so:

```
inners = (amount_charged > 0 ? 2 : 0) + (max_price > amount_charged ? 1 : 0)
```

This is an upper bound for any protocol fee rate, and exact whenever `amount_charged == 0`:

- A **free model** (`max_price == amount_charged == 0`) disburses nothing and settles at `2 × minTxnFee`.
- A **zero-charge settle** (the `(0,0)` inference-failure short-circuit of § 3a, refunded in full) fires only the refund and settles at `3 ×`.
- A **paid** settle with unspent headroom fires all three and settles at `5 ×`.

Composers MUST NOT feed a non-authoritative fee rate into this; the ticket's open-time `feeBps` snapshot is the only correct one. A stale value under-funds in either direction: too high zeroes the computed refund while the real refund inner fires, and too low zeroes the computed fee while the real treasury inner fires.

**`gapOpUps`** funds `finalizeSettlement`'s `ensureBudget`, whose target grows with the gap: `SETTLE_BASE_BUDGET + ringGapIters × RING_GAP_OPCODES_PER_ITER`. The only unbounded cost is the revenue-ring catch-up loop, which zeroes one bucket per skipped day on both the node and operator boxes. A node settling after a multi-day idle runs that loop, the target scales op-ups to match, and the caller must fund the extra inner-transaction fees. `SETTLE_BASE_BUDGET` is below the grouped path's entry opcode budget, so a steady-state grouped settle needs **zero** op-ups (`gapOpUps == 0`). The single-app-call paths start with a thinner budget and always add one base op-up.

- The **single-app-call** composers read the node and operator `bucketsLastDay` directly and mirror `ringGapIters` exactly. `settleLapsed` takes only a ticket id and the contract reads the amounts from the box, so its composer also reads `pendingAmount` / `maxPrice` from the box rather than trusting a caller's copy. If that read fails, it assumes all three inners.
- The **grouped** composer runs on the response hot path and must not read boxes, so the caller supplies `gapOpUps`. A node derives it from the day of its own last settle (every settle bumps both boxes, so one settle pins both): `GapOpUpsForIters(2 × BoundedRingGapIters(lastSettleDay, today))`. Three rules keep that a safe **lower** bound on `bucketsLastDay`, and each makes the fee over-fund rather than under-fund:
  - The day comes from the settling ticket's **served-at** time, never from when the settle was observed. A settle landing at 23:59 and confirmed at 00:01 wrote the earlier day.
  - Only a settle finalize bumps `bucketsLastDay`. `refundInactive` deletes a ticket box and bumps nothing, so seeing "the box is gone" advances the day only when the box vanished **before the ticket's expiry**. The contract's `latestTimestamp > expiresAt + settlementGraceSeconds` guard proves that case was a finalize.
  - `BoundedRingGapIters` clamps a full-wrap gap instead of taking `ringGapIters`' O(1) reset branch. Otherwise a *fresher* operator box (a sibling node settled recently) could run more iterations than a fully wrapped node box's exact count allows.

  A node with no observed settle yet funds one op-up of headroom.

Reference: the single-app-call composers are `ComposeSettleLapsed` / `ComposeSettleStandalone`; the grouped one is `ComposeSettleGroup`.

Under-funding the group is bounded, not lossy. The group fails admission unconfirmed, costing the operator nothing, and the operator's settlement watchdog re-settles through the gap-aware single-app-call path. It does **not** silently overflow the opcode budget: the caller-supplied `gapOpUps` scales with the gap, so a ~14–29-day gap cannot exceed a fixed single op-up, and the happy path pays for no op-up at all.

Payers MUST NOT assert an exact gtxn[0] fee when verifying a pre-signed settle group. The operator funds it. A fee too low fails admission, which is the operator's loss and leaves the payer's `refundInactive` backstop untouched; a fee too high spends the operator's own ALGO. Neither harms the payer, and pinning the fee would break with every legitimate change to the operator's fee arithmetic. The payer's gtxn[1] fee MUST be verified to be exactly 0.

The node composes gtxn[1] and the payer only signs it, so before signing the payer MUST also verify that neither member sets `rekey_to` and that both are NoOp calls. A rekey on the payer's ack hands the node the payer's account. A ClearState ack skips the approval program and wipes the payer's prepaid-pool accounting. `settle()`'s TEAL rejects a rekey on either side as a backstop, but only when gtxn[1] really is a `settle()` call on an app whose installed approval program carries that assert; a node can put the rekey on any other txn type, which is why the payer must pin gtxn[1]'s type, app id and selector. Nothing on chain can reject a ClearState ack, so that check is the payer's alone.

The proxy signs gtxn[1] without modifying any group-hash-participating field and broadcasts the group atomically. On admission:

1. gtxn[0] runs first → status flips OPEN → PENDING_SETTLE with operator-side claim.
2. gtxn[1] runs → matching args + opposite side → finalize and delete the box.

A mismatched gtxn[1] is structurally unreachable when both txns originated from the same receipt; a status that is not OPEN at gtxn[0] time falls into the cases described in "Race ordering" below.

#### `asOperator` ABI arg

The `settle()` ABI signature is `settle(byte[] ticketId, uint64 amountCharged, byte[] receiptDigest, uint64 ttftMs, uint64 decodeMs, uint64 inputCount, uint64 outputCount, uint64 outputUsageType, uint64 auxOutputUsageType, uint64 auxOutputCount, bool asOperator)`. The `asOperator` arg states the caller's role explicitly, for two reasons:

- The same Algorand account can act as both operator and payer (for example, an operator testing on its own deployment). Dispatching on address equality could not handle that without a confusing "same side" revert.
- It fixes the contract's authorization branch at the call site instead of inferring it: `asOperator=true` requires `Txn.sender == t.nodeSigning`, and `asOperator=false` requires `Txn.sender == t.payer`. Either failed assertion aborts the transaction before any state change.

#### `inputCount` / `outputCount` / usage-type ABI args

`inputCount` and `outputCount` carry the receipt's `actual_input_count` and `actual_output_count` as two separate full `uint64`s, with no cap, so on-chain logic reads them directly. They count units of a `UsageType`, not necessarily tokens; `outputUsageType` (the receipt's `output_usage_type`: `1`=Tokens, `2`=Images, …) says which. Input is token-denominated; there is no input-side modality vector yet.

Three more `uint64` args carry the modality routing the contract co-signs and applies at finalization:

- **`outputUsageType`** selects the `outputUnits` slot the primary `outputCount` credits, and **gates the speed EWMAs**. `latencyEwmaMs` / `latencyTotalMs` (from `ttftMs`) and `tokensPerSecEwma` (from `decodeMs` + `outputCount`) update **only when `outputUsageType == Tokens`**. A dedicated image route (`outputUsageType == Images`) credits `outputUnits[Images]` and leaves the speed metrics alone, because image latency must not pollute the token-throughput signal that selection uses. It must be `< 8` (the `outputUnits` width); the contract asserts it.
- **`auxOutputUsageType`** / **`auxOutputCount`** carry the one inline secondary modality a response may mix in, such as tool-produced images alongside chat tokens on `/v1/responses`. When `auxOutputUsageType != None (0)`, `auxOutputCount` *also* credits `outputUnits[auxOutputUsageType]`, so one co-signed `amountCharged` records both the chat tokens (primary slot) and the produced images (aux slot). `auxOutputUsageType` must also be `< 8`.

**On-chain metric — `outputUnits` vector.** Each `OperatorRecord` / `NodeRecord` carries `outputUnits[8]`: one `uint64` per `UsageType`, indexed by the discriminator (`1`=Tokens, `2`=Images, …). A new modality uses an existing slot, with no redeploy. `totalInputTokens` is a scalar. The protocol-wide `protoTotalOutputTokens` is a **token-only** scalar, gated on `outputUsageType == Tokens`; a protocol-wide modality vector is deferred.

The receipt digest already commits to all of these through the receipt canonical bytes ("Settlement receipt"). They are also passed as explicit ABI args because a `sha256` is opaque on chain; the credits above need plain `uint64`s the AVM can read.

These args follow the same co-signing model as the timing args. The first-half claim records the counts and usage types on the pending `TicketRecord` (`pendingInputCount`, `pendingOutputCount`, `pendingOutputUsageType`, `pendingAuxOutputUsageType`, `pendingAuxOutputCount`), and the second-half ack must pass identical values or the ticket freezes. `settleLapsed` uses the pending values when crediting the operator after payer silence.

#### Same-side idempotency

The contract's "same side cannot re-claim with different args" rule has one exception. A same-side re-claim with byte-for-byte matching `(amountCharged, receiptDigest, ttftMs, decodeMs, inputCount, outputCount, outputUsageType, auxOutputUsageType, auxOutputCount)` is a **no-op**; mismatched args still revert. This resolves the race where the operator's settlement driver fires a standalone first half before the payer's atomic group lands: the atomic group's gtxn[0] becomes a no-op, and gtxn[1] then finalizes normally.

#### Operator settlement driver as watchdog

The operator's settlement driver is a fallback for absent payers. It SHOULD wait `zs.settlement_watchdog_seconds` (default **30s**, configurable) after the request ends before considering a standalone broadcast:

- **Box gone** (the proxy finalized atomically): the driver records the external finalize and stops.
- **Box exists, status OPEN**: the driver fires a standalone `settle(asOperator=true)` at `fee = (1 + inners + 1 + gapOpUps) × minTxnFee`. That covers its one outer, the disbursement inners that will fire, one base finalize op-up, and `gapOpUps` extra op-ups sized to the node's revenue-ring gap, so a long-idle node's first settle finalizes instead of reverting for lack of fee. With no gap (`gapOpUps == 0`), a paid ticket costs `5 × minTxnFee`.
- **Status PENDING_SETTLE, pendingBy=OPERATOR**: the driver does nothing; another operator instance fired first.

Firing early does not break correctness, since same-side idempotency lets the payer's later atomic group succeed. But it wastes a standalone settle's outer fee each time (~5,000 µALGO on a paid ticket), because the operator's pre-signed gtxn[0] in the atomic group already covers everything. The watchdog delay should be tuned to favor the proxy's atomic path on healthy traffic. Reference: `ComposeSettleStandalone` / `ComposeSettleLapsed` read the node and operator `bucketsLastDay` and mirror the contract's gap-aware `ensureBudget`.

#### Pre-flight box check

Before broadcasting a standalone settle, the driver MUST check whether the ticket box exists. A missing box on a non-PENDING ticket means one of two things:

- (a) The proxy already finalized atomically. Record the externally finalized state so ledger metadata is preserved.
- (b) `open()` never confirmed. Mark the ledger entry terminally failed, without spending retry budget.

A standalone settle in either case wastes operator funds and reverts with ticket-not-found. Reference: `BoxChecker.TicketBoxExists`; case (a) records through `MarkSettling` + `MarkSettled`; the revert surfaces as `ErrTicketNotFound`.

#### Race ordering — atomic group outcomes

| Pre-state of ticket box | gtxn[0] outcome | gtxn[1] outcome | Net result |
|---|---|---|---|
| `OPEN` | first-half claim → PENDING_SETTLE pendingBy=OPERATOR | matching ack → finalize, box deleted | typical happy path; payer ALGO net = 0 |
| `PENDING_SETTLE` pendingBy=OPERATOR, args match (operator watchdog fired first) | **idempotent no-op** | matching ack → finalize, box deleted | payer ALGO net = 0; operator wasted ~5,000 µALGO |
| `PENDING_SETTLE` pendingBy=OPERATOR, args mismatch | revert (`same side cannot re-claim with different args`) | never runs | atomic group fails; no state change |
| `PENDING_SETTLE` pendingBy=PAYER | ack → finalize, box deleted | revert (`ticket not found`) | atomic group fails; no state change. Unreachable for an atomic group in normal flow. |
| `FROZEN` / non-existent | revert | never runs | atomic group fails; no state change |

Let `G = ticket.settlement_grace_seconds` (per-ticket, defaults to `settlement_grace_default`) and `D = ticket.expires_at + G` (the refund deadline, unix seconds). All timing — `ticket.expires_at`, `G`, and the on-chain comparison against `Global.latestTimestamp` — is measured in unix seconds. The ticket's `opened_at` is recorded for off-chain bookkeeping and gates no on-chain call.

Ticket status progression:

```
STATUS_OPEN (1)  -- first settle() call -->  STATUS_PENDING_SETTLE (5)
                 |                                     |
                 |                                     | matching 2nd call   -> box deleted
                 |                                     | mismatched 2nd call -> STATUS_FROZEN
                 |                                     | protest()           -> STATUS_FROZEN
                 |                                     | latestTimestamp > D + settleLapsed (op claim)
                 |                                     |   -> box deleted (operator paid)
                 |                                     | latestTimestamp > D + refundInactive (payer claim)
                 |                                     |   -> box deleted (payer refunded)
                 | protest()            -> STATUS_FROZEN
                 | latestTimestamp > D + refundInactive -> box deleted (payer refunded)
```

| Window            | Range                  | Legal calls                         |
|-------------------|------------------------|-------------------------------------|
| Happy path        | `[T0, D]`              | `settle` (either party) and `protest` (payer). First `settle` records a pending claim; matching second call finalizes, mismatched or `protest` freezes. |
| Post-deadline     | `(D, ∞)`               | `settleLapsed` (anyone) if a pending operator claim exists — finalizes to the operator. `refundInactive` (anyone) if no operator claim is pending — refunds the payer. `settle` reverts with `settle after refund deadline`; `protest` remains legal while status is OPEN or PENDING_SETTLE. |

Invariants:

- `settle` is callable by either `node_signing` (with `asOperator=true`) or the ticket's `payer` (with `asOperator=false`). The contract dispatches on the `asOperator` arg and then asserts `Txn.sender` matches the corresponding role; `operator_owner` is not a settle caller (settlement uses the hot signing key, not the cold owner key).
- The first call records `(amount_charged, receipt_digest, ttft_ms, decode_ms, input_count, output_count, output_usage_type, aux_output_usage_type, aux_output_count, pending_by)` on the ticket; the second call must come from the opposite side. A same-side re-claim with byte-for-byte matching args is a no-op ("Same-side idempotency"); with mismatched args it reverts.
- If the second call's nine settle args (`amount_charged` through `aux_output_count` above) match the pending claim, the disbursement inner transactions fire, funded by the calling outer's fee pool, and the ticket box is deleted. If any differ, the ticket flips to `STATUS_FROZEN` and the first side's claim is preserved for off-chain arbitration.
- Post-deadline finalization is disjoint by pending side. `settleLapsed` requires `pendingBy == OPERATOR`; `refundInactive` requires `status == OPEN` or (`status == PENDING_SETTLE` and `pendingBy == PAYER`). For any given timestamp, at most one of the two is reachable.
- `protest` is legal whenever status is OPEN or PENDING_SETTLE, with no timestamp gating. It is the structured-evidence path; silent disagreement via a mismatched second `settle` also freezes, but without attaching a `dispute_excerpt`.
- `settlement_grace_seconds` is a payer-silence window: how many seconds after `expires_at` the operator waits before `settleLapsed` force-finalizes their pending claim. It is *not* a race window — silence is not implicit consent, so there is no protest-wins-race.

Operator SDKs MAY treat a `settle after refund deadline` revert as a programming error: the node's settlement driver missed the deadline. The payer is protected by `refundInactive` or `settleLapsed`, depending on who posted first, but the operator forfeits a prompt payout.

### Operator authentication

The contract's three privileged methods authenticate operator commitments with two mechanisms. Both commit to the same Ed25519 keypair, the serving **node**'s signing-account key. They differ in *where* verification happens (consensus or contract), which decides whether the payer or the operator pays for it.

- `open()` and `settle(asOperator=true)`: **consensus-verified sender**. The transaction carries the serving **node**'s Algorand Ed25519 signature, which consensus verifies at pool admission. The contract asserts `Txn.sender == node_signing` and reads the ABI args directly, with no in-contract `ed25519verify_bare`. `node_signing` is the node's hot key, resolved from the `(operator_id, node_id)` node box and snapshotted on the ticket as `nodeSigning`.
- `protest()`: **in-contract receipt-signature check**, `op.ed25519verify_bare` over `sha256("zs-receipt-v2\x00" || canonical_receipt_bytes)`. The payer receives the receipt signature off-chain in the response envelope (§ 5).

#### `open()` — node-signed AppCall

`gtxn[1]` of the open group is an `escrow.open()` AppCall sent by the serving **node**'s signing address. Consensus verifies its Ed25519 signature at pool admission, which binds the node to the exact ABI args (`operatorId, nodeId, maxPrice, expiresAt, payerAddr, ...`). The contract resolves the node from the `(operatorId, nodeId)` node box and asserts `Txn.sender == nodeRec.signing`; there is no in-contract `ed25519verify_bare`.

Consensus-verified sender authentication is sufficient because of:

1. **Term-binding.** The node's signature on gtxn[1] commits to the exact ABI args, which the contract reads straight from the transaction. A malicious payer cannot substitute different terms without invalidating the node's signature.
2. **Squat-DoS protection.** `ticket_id` becomes visible once the `open()` group reaches the mempool, but gtxn[1]'s group hash binds it to the proxy's own funding transaction (the `usdcPayment`). An attacker scraping the wire cannot rewrite the funding transaction or reuse the node's signed gtxn[1] without forging Ed25519.
3. **Domain disjointness.** The methods have different ABI selectors (the first app arg), so an `open()` AppCall cannot be mistaken for a `settle()` AppCall.

#### `settle()` — operator-attested via consensus

`settle()` is callable by the serving node (`node_signing`) or the payer; its ABI signature is under "`asOperator` ABI arg". `ttftMs` and `decodeMs` are operator-measured timing, as two separate `uint64`s: `ttftMs` is time-to-first-token and `decodeMs` is the decode window, which opens at the upstream's first frame of any kind rather than at the first token (§ 3c "Where the decode window starts"). A non-stream or no-first-token settle passes `ttftMs` = total service time and `decodeMs = 0`.

`ttftMs`, `decodeMs`, `inputCount`, `outputCount`, `outputUsageType`, `auxOutputUsageType` and `auxOutputCount` are all committed inside the receipt digest and co-signed verbatim across both halves of the settle; a mismatch on any of them freezes the ticket. At finalization `ttftMs` feeds the per-operator TTFT-latency metric and `decodeMs` + `outputCount` feed the throughput metric, **both gated on `outputUsageType == Tokens`** ("`inputCount` / `outputCount` / usage-type ABI args" above).

The two sides are dispatched as follows:

- **Operator-side calls** (`asOperator = true`) are authenticated by consensus on the transaction body, as for `open()`. The contract asserts `Txn.sender == t.nodeSigning` and writes the operator's first-half claim (or treats a matching same-side re-claim as a no-op).
- **Payer-side calls** (`asOperator = false`), in the atomic 2-transaction group `[op_first_half, payer_ack]`, take their args from the node-signed gtxn[0]. The contract asserts `Txn.sender == t.payer`, and the payer's gtxn[1] ack must carry the same nine settle args as the pending claim: every arg except `ticketId` and `asOperator` ("Race ordering — atomic group outcomes"). The match check freezes the ticket on any disagreement, so the payer has no way to inject fabricated args.

The explicit `asOperator` arg keeps the two roles apart even when `t.nodeSigning == t.payer`. That is legal: operators can use the protocol as payers, for example to test their own deployment. See "`asOperator` ABI arg".

`settle()` carries no `receiptSig` arg and runs no `op.ed25519verifyBare` on the payer-first branch. Evidence on a frozen ticket is still non-repudiable: whichever side posted first, the node's claim is a node-signed AppCall transaction that an indexer query can later recover.

#### `settle()` idempotency

The contract's `'same side cannot re-claim with different args'` assertion treats a same-side re-claim with matching args as a no-op; mismatched args revert. See "Same-side idempotency" for the watchdog race this resolves.

#### `protest()` — receipt signature

`protest()` runs an in-contract `op.ed25519verifyBare` over `sha256("zs-receipt-v2\x00" || canonical_receipt_bytes)`. It is the payer's *one-call* freeze: no operator co-signature, and no timestamp gating beyond status. The receipt-signature check is therefore the only authentication for the freeze. Without it, the payer could DoS any OPEN or PENDING_SETTLE ticket with a fabricated receipt.

That is why the node puts the receipt's off-chain Ed25519 signature on the wire at request end. The ticket's off-chain Ed25519 signature also rides the wire, but only for off-chain audit; no contract method consumes it. Reference: `ticket.UsageReceipt.Sig`, `ticket.Ticket.Sig`.

#### Cost of authentication

| Method | Authentication | Cost |
|---|---|---|
| `open()` | Algorand consensus on gtxn[1].sender | 1 × minTxnFee (the AppCall's own outer fee, paid by operator) |
| `settle()` | Algorand consensus on gtxn[0].sender (atomic) or Txn.sender (standalone) | 1 × minTxnFee |
| `protest()` | `ed25519verify_bare` over receipt digest | 4 × minTxnFee (1 outer + 3 OpUp inners), paid by payer |

The protest authentication cost is the only non-trivial ALGO fee the payer pays.

#### Protest reason codes

`protest()` takes a payer-asserted `reason_code: uint64` as its last ABI arg.

- It is **not** part of the receipt digest, because operators can't predict which reason a payer will pick.
- It is **not** stored on the ticket box, the same as `dispute_excerpt` and `receipt_sig`.
- It rides as an indexable transaction arg, so off-chain arbiters and analytics can categorize freezes without redoing the receipt-vs-plaintext comparison.
- The contract rejects `0`, so callers must pick a reason. It accepts any other value, so off-chain consumers can extend the numbering without a contract upgrade.

The canonical registry is the `ProtestReason*` constants in `proto/go/escrow/client.go`. A new code goes there and into the table below in the same change, so the wire, SDK and spec stay in step.

| Code | Constant                          | Meaning                                                 |
|-----:|-----------------------------------|---------------------------------------------------------|
| 0    | `PROTEST_REASON_UNSPECIFIED`      | Reserved sentinel. Contract reverts with `'reason required'`. |
| 1    | `PROTEST_REASON_BODY_HASH`        | `receipt.body_hash` ≠ proxy-reconstructed plaintext hash. Currently the only reason the proxy emits. |
| 2    | `PROTEST_REASON_RECEIPT_SIG`      | Reserved. Receipt-signature violations are currently only logged, since the contract's own `ed25519verify_bare` would reject the protest. |
| 3    | `PROTEST_REASON_AMOUNT`           | Reserved. Amount-charged > max-price violations are currently only logged, since the contract's `amountCharged <= maxPrice` assert would reject the protest. |
| 4    | `PROTEST_REASON_SEALING`          | Reserved: the operator returned an unsealed or malformed envelope where one was required. |
| 5    | `PROTEST_REASON_RECEIPT_MISSING`  | Reserved: the operator returned 2xx without a receipt. |

## 3b. Operator accountability & slashing

This spec defines the wire format; the on-chain registry contract is the arbiter that decides which evidence triggers which response. This section connects the two. It lists the operator misbehavior the protocol is designed to attribute, names the wire artifacts that serve as evidence, and specifies the retention the proxy MUST uphold to keep a dispute possible.

### Design principle

Every slashable offense must be **cryptographically attributable**: the arbiter verifies fault from signed artifacts the operator cannot repudiate, not from the proxy's account of events. Uptime, latency and answer quality are reputational concerns, handled by deranking (audits and ratings); they do not slash stake.

The ticket (§ 3a) is the single root of attributability. Its Ed25519 signature over `sha256(CanonicalBytes())` binds the operator to `max_price`, `expires_at`, `model`, `stream` and `commit_k` before any inference runs. Every slashing case below reduces to: produce the ticket plus one more artifact, and run a deterministic check.

### Slashing options

Four categories. (a) and (d) rest on signed artifacts alone. (b) also needs the ticket's open-time `feeBps`, which only the on-chain ticket box records, and (c) depends on on-chain settlement state.

#### (a) Key-substitution fraud

- **What the operator did:** sealed the response under a symmetric key `K'` where `sha256(K') ≠ ticket.commit_k`.
- **Evidence:** (1) the signed ticket; (2) the `X-Zs-Response-Key` header value from the response; (3) the unwrapped `K_response`, which the proxy submits directly, or its retained ephemeral X25519 private key so the arbiter can re-derive it.
- **Arbiter verification:** recompute `sha256(K_response)` and compare it to `ticket.commit_k`.
- **Severity:** the strongest case, since the operator demonstrably broke its pre-commitment. Full payment refund plus stake forfeiture.

#### (b) Overcharge

- **What the operator did:** signed a receipt charging more than the escrow covers: `amount_charged` plus the protocol fee exceeds `ticket.max_price`.
- **Prevented on chain.** `settle()` reverts when `amountCharged + grossFee > maxPrice` (fee at the ticket's open-time `feeBps`), so an overcharge is never recorded, never confirms and never moves funds. A reverted settle leaves nothing on chain, but the node-signed receipt, held off-chain, is still evidence of the attempt.
- **Evidence:** (1) the signed ticket; (2) the node-signed receipt (§ 3a "Settlement receipt"); (3) the ticket box's open-time `feeBps` snapshot (§ 3a "Open-time fee snapshot"). Neither signed artifact carries a fee field.
- **Arbiter verification:** verify both signatures off-chain, read `feeBps` from the ticket box, then check `amount_charged + floor(amount_charged × feeBps / 10000) > max_price`.
- **Severity:** a fixed penalty; no overage is ever taken, so there is none to return. For persistent offenders, escalate toward full forfeiture.

#### (c) Capacity reneging

- **What the operator did:** consumed the ticket (inflight slot held, `open()` confirmed) but delivered no complete response, and still claimed a non-zero charge at settlement. "No complete response" means the connection dropped before the final sealed frame and `[DONE]` on a stream, or there was no response body at all on a non-stream request. A non-zero claim on a truncated stream is not proof by itself: the node may bill an estimate for a stream cut off before `usage` arrives, most often because the caller disconnected (§ 3c "Latency + throughput: co-signed `ttft_ms` + `decode_ms`"), and nothing on chain records who cut it.
- **Evidence:** (1) the signed ticket; (2) the confirmed `open()` group; (3) the node-signed `settle()` claim with `amountCharged > 0`.
- **Arbiter verification:** confirm the node's claim and its amount. The proxy cannot prove non-delivery cryptographically, so this case relies on the escrow:
  - A node claim moves funds only when the payer acks it with matching args, or through `settleLapsed` once the deadline passes with the claim still pending.
  - Before the deadline, a payer that disputes the claim can send a mismatched `settle()` ack, which freezes the ticket. A payer holding a node-signed receipt can instead `protest()`. A frozen ticket's funds stay locked for off-chain arbitration; no contract method releases them.
  - If the node never claims, anyone can call `refundInactive` after the deadline and the payer is refunded in full, so the case does not arise.
- **Severity:** refund the inference fee plus a small penalty on first offense; derank on repeat. Persistent reneging crosses the threshold into full slash.

#### (d) Cross-wiring / ticket replay

- **What the operator did:** returned a response whose `algorand_tx_id` / `ticket_id` AAD binding does not match the sealed request. That is, it attempted to splice a cached or stolen response onto a different request, or to reuse a consumed ticket's `K_response` on a new request.
- **Evidence:** (1) the signed ticket; (2) the request envelope; (3) the response envelope (or the sealed SSE frames).
- **Arbiter verification:** rebuild the body or frame AAD (§ 6) from the sent request's values and try to AEAD-open the response. An AEAD failure under the ticket-committed `K_response` proves the operator deliberately crossed bindings.
- **Severity:** equivalent to (a). Deliberate splicing defeats the purpose of the AAD binding, so it is a full slash.

### What is not slashable (reputation or passthrough only)

- **Channel-level tampering** (a TLS-terminating intermediary, the ISP, or an on-path attacker stripping `X-Zs-Response-Key`). The proxy sees an AEAD failure or `502 proxy_error`, but the operator owes nothing for network attacks on a path the proxy chose. TLS between proxy and node is the first defense; there is no bearer auth, because admission is on-chain (§ 3a).
- **Upstream LLM provider outages, rate limits or refusals.** The operator ran the protocol correctly and the inference failed. Chronic unavailability is deranked.
- **Answer quality as the client perceives it.** Handled by the audit-prompt and rating system, not the wire protocol.
- **Final-frame drop with no AEAD failure.** Truncation is not AEAD-detectable (§ 8). Application-level completion signals (`finish_reason`, `[DONE]`) catch it, and deranking is the response.
- **Malformed request from the proxy.** A `400` from the node is not operator fault, even if the proxy had a valid ticket.
- **An over-priced but internally consistent ticket.** Case (b) covers charging *above* `max_price`. `max_price` itself is node-authored and prices are not on chain, so an inflated but honestly settled ticket can't be attributed. The defense is payer-side refusal before escrow (§ 3a "Payer-side price verification"), plus deranking.

### Evidence retention

**What the reference proxy does.** Slashing arbitration (the arbiter for cases (a)–(d)) lives outside this spec, and the reference proxy keeps **no** local dispute buffer. It handles evidence only at detection time:

- Receipt verification (signature, `amount_charged ≤ max_price`, `body_hash`) and the `commit_k` check run inline on every response (§ 3a "Settlement receipt", § 5.2 / § 5.3).
- A `body_hash` mismatch fires `escrow.protest()` **immediately**, attaching a head-truncated excerpt of the reconstructed plaintext (no larger than the contract's dispute-excerpt cap) as on-chain dispute material, and freezes the ticket. The durable evidence is that protest transaction, which carries the receipt's `amountCharged`, `receiptDigest` and node signature `receiptSig` (verified on chain; the full receipt, including `body_hash`, is not recoverable from chain), together with any node-signed pending claim the frozen ticket already held.
- Signature and amount violations are only logged, not protested, because the contract's own checks would reject such a protest on chain. AEAD failures and `commit_k` mismatches fail the request closed and are logged with ticket and operator ids.
- The ephemeral X25519 key is wiped unconditionally when the handler returns. Nothing decryptable outlives the request. Reference: `wire.ZeroEphemeralIdentity`.

**What a dispute-filing proxy would need to retain.** A proxy that files the § 3b cases with an arbiter after the fact, instead of protesting inline, must copy this material **before** its handler returns and hold it until `ticket.expires_at + settlement_grace_seconds`. Disputes are inadmissible after that.

1. **Signed ticket** (§ 3a). Small; always retainable.
2. **`X-Zs-Response-Key` header value** (§ 5.2 / 5.3).
3. **At least one sealed payload**: the full non-stream response envelope, or the first sealed SSE frame plus its computed `frame_index`. Needed for case (d).
4. **Ephemeral X25519 private key OR the unwrapped `K_response`.** The arbiter accepts either: the ephemeral private key plus the wrapped header is equivalent to `K_response`.
5. **The node-signed receipt** (§ 3a "Settlement receipt"). Needed for case (b), and the required input to `protest()`.

Retaining (4) is a privacy tradeoff: holding the ephemeral key lengthens the window in which a later compromise could decrypt this one response. A retaining proxy SHOULD hold it only as long as it needs to assert the dispute, and purge it immediately afterward. The reference proxy's wipe-on-completion policy is the privacy-maximal end of that tradeoff. It gives up after-the-fact filing of cases (a) and (d) in exchange for retaining no key material, and relies on the inline protest for the disputes it can raise.

### Reference implementation

Slashing arbitration lives outside this module. The wire-level primitives this section relies on:

- `ticket.Ticket.Verify` / `CanonicalBytes` (`ticket/ticket.go`) — non-repudiation.
- `ticket.CommitResponseKey` (`ticket/ticket.go`) — case (a) check.
- `wire.BuildBodyAAD` / `BuildFrameAAD` (`wire/envelope.go`) — case (d) check.
- `wire.UnwrapResponseKey` (`wire/wrap.go`) — used by both proxy and arbiter to derive `K_response` from the retained ephemeral.

## 3c. Operator details

Reserve (§ 3a) is where a proxy *commits* to an operator's prices and capacity by exchanging a signed ticket. Details is the discovery surface that lets a client decide which operator is worth reserving against. Without committing to anything, it answers: which models does this node serve, what context window does it admit per model, what does it charge in USD, and which ZeroSignal built-in tools does it run?

### Endpoint

`GET /v1/zs/details`

- **Content-Type** (response): `application/json`, plaintext: no envelope, no auth.
- **Always active** on every node. The reference proxy probes it once per operator at registry refresh; direct clients (TUIs, dashboards, custom routers) are also expected consumers.
- **Request**: an empty `GET`, with no body and no required headers beyond `Accept: application/json`.

### Response

```json
{
  "operator_id": 42,
  "node_id": 7,
  "owner_addr": "<owner address>",
  "signing_addr": "<signing address>",
  "ephemeral_age_pubkey": "age1...",
  "ephemeral_issued_at": 1699998500,
  "ephemeral_expiry": 1700000000,
  "ephemeral_sig": "<base64 Ed25519>",
  "models": [
    {
      "id": "gpt-4o-mini",
      "input_rate_usd_per_1m": 0.15,
      "output_rate_usd_per_1m": 0.60,
      "cache_read_rate_usd_per_1m": 0.0375,
      "context_window": 128000,
      "max_output_tokens": 16384,
      "input_modalities": ["text", "image"],
      "output_modalities": ["text"],
      "reasoning": { "supported": true, "allowed_efforts": ["off", "low", "medium", "high"], "default_effort": "medium" },
      "tool_use": true
    },
    {
      "id": "local-llama-free",
      "input_rate_usd_per_1m": 0,
      "output_rate_usd_per_1m": 0,
      "context_window": 32768,
      "input_modalities": ["text"],
      "output_modalities": ["text"],
      "tool_use": false,
      "tags": ["nsfw", "uncensored"]
    }
  ],
  "oracle_source": "coingecko",
  "oracle_healthy": true,
  "algo_usd_price": 0.18,
  "algo_usd_at": "2026-04-25T17:30:00Z",
  "min_charge_output_tokens": 1000,
  "min_charge_algo_txns": 7,
  "min_charge_microusdc": 1260,
  "builtin_tools": [
    {"type": "zs_web_search"}
  ],
  "max_tool_iterations": 4,
  "tool_headroom_per_iteration": 4000,
  "version": "0.21.0+abc1234 [2026-05-03T12:00:00Z]",
  "proto_version": "9.10",
  "config_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

| Field | Type | Semantics |
|---|---|---|
| `operator_id` | uint64 | Stable on-chain operator id (§ 3 "Operator id"). Omitted when no id is assigned yet (development, unregistered). |
| `node_id` | uint64 | This node's id within `operator_id` (§ 3 "Node id"). `signing_addr` and the advertised ephemeral recipient belong to this node. One node process advertises exactly one `(operator_id, node_id)`. Omitted when unassigned. |
| `owner_addr` | string | Owner Algorand address (§ 3 "Operator owner address"). Receives funds at settlement. |
| `signing_addr` | string | Node signing Algorand address (§ 3 "Node signing address"). Its private key signs tickets; clients verify ticket signatures against the public key decoded from it. |
| `ephemeral_age_pubkey` | string | The short-lived `age` recipient (`age1...`) for sealing request envelopes (§ 4). It is the **only** encryption recipient. See "Ephemeral recipient" below. |
| `ephemeral_issued_at` | int64 | Unix-seconds **start** of the ephemeral's validity window (its mint or rotation time). See "Ephemeral recipient" below. |
| `ephemeral_expiry` | int64 | Unix-seconds **end** of the validity window. See "Ephemeral recipient" below. |
| `ephemeral_sig` | string | base64 Ed25519 signature binding the ephemeral to this node and window. See "Ephemeral recipient" below. |
| `models[].id` | string | Model identifier: the same value as the OpenAI request body's `model` field and `ReserveRequest.model`. See "Which models are listed" below. |
| `models[].input_rate_usd_per_1m` | float | **Advertised** input rate, USD per 1,000,000 tokens ("Authority of advertised vs. ticket-pinned values" below). Always emitted, including `0`, which means the operator offers this side for free. A free model has both rates `0` and issues `max_price == 0` tickets (§ 3a "Rate derivation"). Nodes that predate this may omit a zero rate; decode an absent value as `0`. |
| `models[].output_rate_usd_per_1m` | float | **Advertised** output rate, USD per 1,000,000 tokens. Same conventions as the input rate. |
| `models[].cache_read_rate_usd_per_1m` | float | **Advertised** discounted rate for cached-read input tokens, USD per 1,000,000 (§ 3a "Rate derivation" / "Charge formula"). An **absent** field means *no discount*; a **present** `0` means *free cached reads*. See "Cached-read rates" below. |
| `models[].long_context_threshold_tokens` | uint64 | **Advertised** long-context (surcharge) threshold in input (prompt) tokens: xAI/Grok's context-size cliff. A prompt whose `input_count` reaches it bills the whole request at the high rates below (§ 3a "Rate derivation" → "Long-context (surcharge) tier"). `0`/omitted means no tier, and the three high rates are omitted too. Advisory: the authoritative per-request rates are the tier-resolved microUSDC rates pinned into the ticket at reserve. |
| `models[].long_context_input_rate_usd_per_1m` | float | **Advertised** high-tier input rate, USD per 1,000,000, applied when `input_count ≥ long_context_threshold_tokens`. Present (even at `0`) **only** when a threshold is advertised. It is `≥` the base `input_rate_usd_per_1m`: a surcharge, since the node rejects a tier that undercuts its base. |
| `models[].long_context_output_rate_usd_per_1m` | float | **Advertised** high-tier output rate, USD per 1,000,000. Same conventions; `≥` the base `output_rate_usd_per_1m`. |
| `models[].long_context_cache_read_rate_usd_per_1m` | float | **Advertised** high-tier cached-read rate, USD per 1,000,000, with the same absent-vs-`0` rule as `cache_read_rate_usd_per_1m`. Present **only** when the high tier discounts cached reads (strictly below the high `input_rate`). See "Cached-read rates" below. |
| `models[].context_window` | uint64 | Per-model capacity ceiling. The node rejects a reserve with `input_count + max_output_count > context_window` as `400 context_length_exceeded`. Zero or omitted means no declared cap. See "`context_window` with a long-context tier" below. |
| `models[].max_output_tokens` | uint64 | Optional per-model output ceiling, tighter than `context_window`. Zero or omitted means no separate output cap. |
| `models[].input_modalities` | []string | Content kinds the model accepts (`"text"`, `"image"`, `"audio"`, `"video"`). Nil means undeclared: clients should treat it as text-only for filtering, but the node's reserve handler is the authoritative gate. |
| `models[].output_modalities` | []string | Content kinds the model produces. Same conventions. |
| `models[].reasoning` | object | Reasoning capability `{supported, allowed_efforts?, default_effort?}`. Nil = unknown. Auto-discovered where the runner exposes it (LM Studio), otherwise declared in operator config. The cross-operator aggregate drops `default_effort`. |
| `models[].tool_use` | bool | Tool/function-calling support. Nil = unknown; an explicit `false` is not unknown. Discovered and overridden like `reasoning`. |
| `models[].tags` | []string | Free-form labels (`nsfw` is the canonical value). The union of the model author's Hugging Face `cardData.tags`, discovered from the model's `source` repo so operators need not maintain them, and any operator-config tags. The proxy OR-unions tags across operators. |
| `models[].coordinates` | object | Optional model taxonomy `{family?, parameters?, active_parameters?, quantization?, variant?}`. The bare response carries only the cheap in-memory config/runner signal; `expand=coordinates` may enrich it from Hugging Face ("Deep model details" below). Advisory only. |
| `models[].source` | string | **Canonical source pointer**: an operator-declared, scheme-tagged link to the public artifact this model *is* (`hf:org/model[@revision]`; other schemes such as `oci:` reserved). The cross-operator **identity key**. **Advisory and operator-attested.** See "`source` and `canonical_id`" below. |
| `models[].canonical_id` | string | Cross-operator identity key for a **closed-weights frontier** model (grok / gpt / claude / gemini), which has no public HF repo and so no `hf:` `source`. Filled from the curated frontier whitelist, e.g. `"xai/grok-4.5"`. Present **only when `source` is empty**. See "`source` and `canonical_id`" below. |
| `models[].retention` | string | **Upstream data-retention tier**: whether the prompt is retained *anywhere* once it leaves the payer, and on what evidence. One of five values. **Absent means unknown, never "retains".** See "Retention tiers" below. |
| `oracle_source` | string | Oracle implementation name (e.g. `"coingecko"`). Informational. |
| `oracle_healthy` | bool | `true` only when the oracle has a fresh quote within `max_staleness`. `false` neither invalidates the rest of the advertisement nor blocks reserves. See "Oracle health" below. |
| `algo_usd_price` | float | Last-known ALGO/USD quote. Populated once the oracle cache has ever been warmed, even if stale, so dashboards can show the last quote. |
| `algo_usd_at` | RFC 3339 timestamp | Time of `algo_usd_price`. Zero time when the cache has never been populated. |
| `min_charge_output_tokens` | uint64 | Output-token count for the **token component** of the per-request minimum charge: a tiny successful response bills as if it produced at least this many output tokens at the ticket's output rate. Default `1000`; `0` (omitted) disables it. See "Minimum charge fields" below. |
| `min_charge_algo_txns` | uint64 | The operator's **µALGO component** of the minimum charge, as a count of Algorand `minTxnFee` units (1,000 µALGO each). `0` (default, omitted) disables it; the recommended enabled value is `7`. See "Minimum charge fields" below. |
| `min_charge_microusdc` | uint64 | The *current* USD value of the µALGO component, `ceil(min_charge_algo_txns × 1000 × algo_usd_price)`, in microUSDC at the operator's latest oracle reading. `0` (omitted) when the component is disabled or the oracle is stale or never populated. See "Minimum charge fields" below. |
| `builtin_tools` | []object | ZeroSignal built-in tools this node serves, as **type-only** `{type}` entries. The `type` value is the client opt-in surface (§ 3d). Omitted or empty when the node has no tool registry. See "Built-in tools" below. |
| `max_tool_iterations` | int | Cap on chat→tool→chat loops per tool-bearing request. A caller sizes a tool-carrying reserve's `input_count` as `body_bound + max_tool_iterations × tool_headroom_per_iteration` (§ 3a "Input-token bound"), so the escrow covers the input a tool loop accumulates. Omitted when no registry is loaded. |
| `tool_headroom_per_iteration` | uint64 | Input-token headroom per tool-loop iteration that the operator recommends, sized from its tools' typical result size (e.g. `web_read`'s byte cap). Advisory: a mismatch changes only the reserve size, never correctness, since the node's inference-time input-budget check reconciles actual usage. Omitted/`0` on older nodes; callers then use a built-in default (4000). |
| `version` | string | Node build identification, `<release>+<commit>[-dirty] [<commit-time>]`. Informational only: clients MUST NOT parse it, nor compare it semantically, to drive routing or settlement, which stay driven by ticket-pinned values. See "Build version" below. |
| `proto_version` | string | Wire-protocol generation, `<major>.<minor>` (currently `"9.10"`). **Parsed by clients**, unlike `version`. Compatibility is **major equality**: a peer (proxy or direct client) drops an operator whose major differs from its own build's. Minor differences MUST NOT cause filtering. 9.9 and 9.10 are the two minor bumps that are not backwards-compatible: 9.8 and 9.9 verifiers refuse each other's `dstack-tdx` evidence, as do 9.9 and 9.10 (§ 3e verifier step 6). That refusal comes from the evidence check, not from comparing versions. An absent value reads as `"1.0"`, so a node that omits the field falls out of a current peer's candidate set by major inequality. See "Protocol version negotiation" below. |
| `config_hash` | string | `"sha256:<hex>"` fingerprint of the operator's **policy** config: what the node serves and at what price. Nodes with the same policy advertise the same hash, and it changes when any policy field does. Advisory: clients MUST NOT drive routing or settlement from it. See "Policy fingerprint" below. |

**Ephemeral recipient.**

- The ephemeral lives only in the node's memory: never persisted, regenerated on a fixed cadence (~20 min), and dropped on restart. There is no on-chain encryption anchor.
- A sealing party MUST verify `ephemeral_sig` under the on-chain `signing_addr` and pass the hard checks before use. On failure it refuses the operator and tries another; it **never** downgrades.
- `ephemeral_issued_at` is signed, so the `[issued_at, expiry]` window is tamper-evident. It drives a **hard** lifetime cap: `expiry − issued_at` MUST be ≤ `MaxEphemeralLifetime`, so a node cannot advertise a long-lived "ephemeral" it secretly keeps to defeat forward secrecy. It also drives a **soft** relay-staleness signal: on a relayed path, `now − issued_at > FreshnessTarget` downranks the relay (§ 3f). `issued_at` MUST NOT be future-dated (beyond skew).
- After `ephemeral_expiry`, plus a small verifier skew tolerance, the ephemeral has expired. A sealing party then refuses the operator and refetches or tries another; there is no on-chain key to fall back to.
- `ephemeral_sig` is over `"zs-ephemeral-v1\0" || be64(operator_id) || be64(node_id) || lenStr(ephemeral_age_pubkey) || i64(ephemeral_expiry) || i64(ephemeral_issued_at)`. `i64` is the 8-byte big-endian two's-complement encoding, as for `expires_at` in the ticket canonical bytes; it equals `be64` for the positive timestamps the protocol produces. The domain tag is **`zs-ephemeral-v1`**. The signature verifies under the public key decoded from the on-chain `signing_addr`, the same key that signs tickets and receipts.
- The signed `operator_id` and `node_id` are the **chain-resolved** ids, never the JSON's top-level fields, so a substituted `/details` body cannot forge either. `node_id` is bound so that a sibling node's advertisement never validates as this node's, even when an operator reuses one signing key across nodes. Nothing enforces per-node key distinctness, and without the binding, traffic would seal to a key the receiving node cannot decrypt.
- `ephemeral_age_pubkey` is omitted only when the node advertises no ephemeral, and the other three `ephemeral_*` fields are omitted then too. That makes it unreachable for sealing, so the node 503s `/details` and `/reserve` rather than serve a dead block.

**Which models are listed.** `models[]` is what the operator's upstream LLM backend is *currently* serving (the node probes it on a short interval), intersected with the operator's configured pricing and capacity. A priced model the backend isn't loading is omitted. An unreachable backend yields an **empty `models[]`** even with pricing configured, and `/v1/zs/reserve` then returns `503 provider_unavailable` (§ 3a "Response (refusal)"). A node restarting its backend may briefly advertise zero models.

**Cached-read rates.**

- `cache_read_rate_usd_per_1m` is the discount an operator passes through for prompt tokens an upstream serves from a prefix or prompt cache; the receipt reports the billed subset as `cached_input_count`. It is emitted **only when the resolved cache-read rate is strictly below `input_rate`**. An unset `cache_read_rate` resolves to `input_rate`, so there is nothing to advertise. Unlike the input and output rates, `0` is **not** an "omitted" sentinel here.
- It is advisory; the authoritative per-request rate is the `cache_read_rate` pinned into the signed ticket at reserve. The proxy's cross-operator aggregate shows the lowest advertised discount ("from $X").
- On the wire, the base discount does **not** carry into the high tier: an absent `long_context_cache_read_rate_usd_per_1m` means high-tier cached reads bill at the high `input_rate`. In an operator's **config** it does carry. A node whose base tier discounts cached reads resolves an unset high `cache_read_rate` to the base one scaled by the input rate's step-up (xAI's 2× tier reproduces its published figure exactly), and refuses a config that explicitly declares no high-tier discount while the base has one.
- Both config rules keep the high-tier field present whenever `cache_read_rate_usd_per_1m` is. Otherwise a verifier would bound the high-tier ticket's cache-read rate against the **base** discount × `RateMaxMultiple` and refuse every long-context ticket from that node. The proxy's aggregate takes the lowest advertised value of each tier field ("from $X"), for display only; per-operator values drive verification.

**`context_window` with a long-context tier.** With a tier configured, an operator raises `context_window` to the model's **true max**, instead of capping it at the threshold to prevent under-billing. A request above the threshold is then admitted and billed at the high tier instead of rejected. This is safe for traffic below the threshold too. A `previous_response_id` chain reserves `context_window − max_output_tokens` of `input_count`, which above the threshold would tier every continuation, but the settle-time step-down (§ 3a) bills those at base rates from the measured prompt.

**`source` and `canonical_id`.**

- Two operators advertising the same `source` repo resolve to one model in the picker, however each spelled `models[].id`. Comparison is case-insensitive and ignores the optional `@revision`, which pins an artifact version but is not model identity. `source` also keys the `?expand=coordinates` Hugging Face lookup. It rides the **bare** list, since it is a free, tiny, operator-declared string.
- `source` does not prove the served bytes match the artifact; the `digest` signal covers integrity and is cross-checked against `source` ("Deep model details" below). The wire `model` string stays the routing, billing and signing key.
- `source` is omitted for a closed-weights model resolved through the frontier whitelist (which advertises `canonical_id` instead), a default-priced upstream id, or a pre-feature node.
- The reference node MAY refuse to advertise a model that declares neither a `source` nor a whitelisted id (`zs.provenance.require`, default on). **Image-route models** (`serves_image_gen` / `serves_image_edit`) are **exempt** from that gate, since a generation workflow maps to no single HF repo and isn't a frontier text LLM. An operator MAY still declare a `source` for one, to enable cross-operator grouping and HF coordinates.
- `canonical_id` covers what `source` cannot. Two operators may spell a frontier model's id differently (`grok-4.5` vs `x-ai/grok-4.5`); the node fills `canonical_id` from the identity gate's canonical, so both resolve to one picker row. It rides the **bare** list. For a sourced model the canonical identity *is* the `source` repo, so consumers key on `source` first and fall back to `canonical_id`, never both, and it is not duplicated.
- `canonical_id` is omitted for image-route models and for any sourceless id that is neither frontier-whitelisted nor advertised. It is advisory and attested only as far as `source` is: the whitelist says "this wire id is the well-known model X", not that the operator serves X. It never gates routing, billing or settlement.

**Retention tiers.** `retention` rides the **bare** list. Its values, strongest evidence first:

| Value | Meaning |
|---|---|
| `tee_attested` | Local weights inside a TEE: nothing leaves the node to answer the request, and the node's own non-retention is hardware-attested. |
| `upstream_confirmed` | The upstream affirms zero retention on every response, and the node refuses any 2xx that does not (xAI's `x-zero-data-retention: true`). |
| `upstream_enforced` | The node pins a constraint the upstream's own semantics make tighten-only, so a retaining endpoint is unroutable rather than merely unused (OpenRouter's `provider.zdr` + `data_collection: "deny"`). |
| `no_upstream` | Local weights or a loopback runtime, no TEE: the prompt never leaves the box to be answered, but the node's own non-retention is policy rather than evidence. |
| `operator_declared` | The operator asserts an arrangement the node cannot check. |

- **Absent means UNKNOWN, never "retains".** That covers a pre-field node, or an upstream offering no guarantee the node can pin or check, which is the honest state of most hosted passthroughs. A consumer that renders absence as a warning makes a claim the wire did not. An **unrecognized** value is also unknown and MUST NOT be displayed verbatim, or a node could mint its own reassuring label.
- **Every tier describes the INFERENCE route** — where the node sends the prompt in order to answer. "Nothing leaves the node" on `tee_attested` and `no_upstream` is a claim about that route, not a promise that a caller cannot cause an egress of its own: built-in tools are caller-initiated and a node MAY serve them at any tier (§ 3d, and § 3e's note under `posture`). A caller that lists **no caller-initiated egress tool** gets the tier unqualified. That condition is wider than the `zs_` built-ins: a remote `mcp` entry and a provider-native `web_search` are both egress the caller put in `tools[]`, and neither is a `zs_` type (§ 3d). A client presenting these as a user-facing switch should note that the reference client's own switch defaults **on**, so "the caller chose it" is a statement about the request, not necessarily about a decision the user made.
- **Trust ceiling.** The order is by evidence, and every tier below `tee_attested` describes only the *destination*. `upstream_confirmed` says the upstream will not retain the prompt, and nothing about whether the node logged it on the way past. That is why `no_upstream`, where the prompt never leaves the box, sorts *below* two tiers that send it to a third party. Node-side non-retention is an unconditional operator obligation (§ 3a "Prompt and response non-retention") that only a TEE turns into evidence, so read this field together with `tee`, never alone.
- **The ceiling is two-sided.** "Destination" means the endpoint that served the request. `upstream_enforced`, a constraint the node sends and never sees confirmed, also says nothing about an intermediary in front of that endpoint, which is the case whenever the upstream is a broker. This field covers neither end of the path.
- **Gates nothing, and MUST NOT.** It is node-authored with no peer corroboration, unlike `weights_digest`. Raising placement on it would reward the boldest claim, and demoting on its absence would penalize every honest passthrough. A payer who wants it enforced asks explicitly, as `X-Zs-Require-TEE` does.

**Oracle health.** While the oracle is unhealthy, new reservations still succeed, but they pin `algo_usd_price = 0` in the reserve response and drop the µALGO component of the minimum charge to `0` for that cycle. The oracle-independent token component still applies (§ 3a "Minimum charge"). In-flight tickets settle correctly, because rates are pinned at issuance.

**Minimum charge fields** (§ 3a "Minimum charge").

- The per-model floor combines both components: `min_price_model = max(ceil(min_charge_output_tokens × ceil(output_rate_usd_per_1m × 1e6) / 1e6), min_charge_microusdc)`.
- The recommended `min_charge_algo_txns` of `7` covers 2 minTxnFee at `open()` (the 2-transaction group, with no discount inner) plus 5 at a paid steady-state atomic `settle()` (2 co-signed outers + 3 disbursement inners, no op-up). The settle fee is sized to the inners that actually fire, so it runs lower on free or zero-charge settles and higher only on a first settle after a multi-day idle.
- `min_charge_microusdc` is **one component** of the floor, not the whole floor; the token component is per-model. The authoritative per-request value is the signed ticket's `min_price` from `/v1/zs/reserve`.

**Built-in tools.** `name`, `description` and `parameters` are **not** advertised. They are node-internal (the node's tool registry is authoritative; § 3d "Authority") and identical on every node with the same `proto_version`, so a human-readable surface resolves them locally by `type` from its bundled proto package instead of downloading them on every poll. The response-side status events for streaming tool rounds are described in § 5.3.1.

**Build version.**

- `<commit>` is an abbreviated git SHA. `<release>` is the published version, or `dev` when the build could not determine one. For example: `0.21.0+abc1234 [2026-05-03T12:00:00Z]` from a release binary, `dev+abc1234 [2026-05-03T12:00:00Z]` from one compiled at the same commit, and `dev+abc1234-dirty [...]` with uncommitted changes on top.
- **Two matching CLEAN tails were built from the same source**, however each was built; that is what the shape is for. A `-dirty` tail is **not**: it names the commit its build departed from and carries nothing about the departure, so two of them can match over different source.
- Reading two tails side by side is the intended use, as a legibility aid for operators and dashboards. Nothing may be **gated** on the result. The value is an unsigned, uncorroborated claim a node makes about itself, so it is never evidence.
- Nodes that predate the field omit it. Builds that predate this *format* emit the older `<commit>:<branch> [<date>]` shape, so the same source reports two different strings across that boundary.
- The reference proxy unions versions across operators and re-exposes them as a deduplicated, byte-sorted (not version-ordered) `node_versions` list on its own aggregate `/v1/zs/details`.

**Policy fingerprint.** `config_hash` covers the deployment-independent policy subset: the per-model rate card and capacity/capability envelope, the built-in tool roster, public rate limits, the per-request minimum charge, the oracle source and the relay mode. It excludes identity, infrastructure, secrets and operational tuning, so two nodes running the same policy advertise the same hash regardless of listen address, file paths or per-node identity. It is a convenience for diffing operators or detecting drift. The hashing scheme is `zs-config-policy-v1`: a domain tag prefixed to the canonical JSON of the policy view. Nodes that predate the field omit it.

**Fields defined elsewhere.** These `/v1/zs/details` fields are specified with the feature they belong to:

| Field | Defined in |
|---|---|
| `models[].serves_image_gen`, `serves_image_edit`, `image_rate_micro_usdc`, `image_edit_rate_micro_usdc`, `image_default_micro_usdc`, `image_edit_default_micro_usdc`, `image_cap_micro_usdc`, `image_edit_cap_micro_usdc` | § 3a "Dedicated image route" and "Operator size/quality resolution" |
| `models[].image_tool_rate_micro_usdc`, `image_edit_tool_rate_micro_usdc`, `image_tool_base_micro_usdc`, `image_edit_tool_base_micro_usdc` | § 3a "In-loop image tools" |
| `models[].tool_call_rates_micro_usdc`, `vendor_tool_catchall_micro_usdc`, `vendor_tool_call_cap`, `vendor_tool_tokens_per_call` | § 3a "Per-call tool pricing" |
| `models[].weights_digest`, `weights_unverifiable` | "Deep model details" below |
| `tee` | § 3e "Discovery: `tee` field on `/v1/zs/details`" |

Reference: the `context_window` check is `inject.FitsContextWindow`; `builtin_tools` entries are `tools.BuiltinToolAdvert` and the registry is `tools.BuiltinToolDef`; a peer's own major is `wire.ProtoVersion`; `version` comes from `node/internal/build.DetailsVersion`; `config_hash` from `node/internal/config.Config.PolicyHash`.

### Model capabilities & tags: sources & precedence

- **Discovery.** `reasoning` and `tool_use` are auto-discovered where the runner exposes them (LM Studio's `capabilities`). vLLM, llama.cpp, `openai_passthrough` and Ollama-via-passthrough expose nothing, so the operator declares them under `zs.models[].context`. Precedence is **config wins, discovery fills gaps**, as in the modality merge.
- **Tags** are the **UNION** of the model author's Hugging Face `cardData.tags` and any operator-config tags (additive, for labels HF doesn't carry). HF tags are discovered from the model's `source` repo, keyed and cached exactly like the `?expand=coordinates` lookup, gated by the same `coordinates.discover_huggingface` opt-out, and warmed for the served set at startup so they ride the bare list. Only operator-config tags feed `config_hash`, which keeps the hash deterministic.
- **Vision and image output** are NOT separate flags. Clients derive them from the modality lists: `vision = "image" ∈ input_modalities`, and image output = `"image" ∈ output_modalities`.
- **Across operators** the proxy **OR-unions** capabilities and tags: one is advertised if ANY reachable operator advertises it, which for a content label like `nsfw` is the conservative default. It also unions `allowed_efforts`, and **drops** `default_effort` from the aggregate, since a single default has no clean cross-operator meaning.

`reasoning`, `tool_use` and `tags` are additive optional fields, so they need no `proto_version` bump and cause no operator filtering. They are advisory like the rest of this section: they never bind the operator for a specific request and never drive proxy routing or selection.

### `GET /v1/models` — the same catalog in the OpenAI-compatible shape

`/v1/zs/details` is the protocol's own discovery surface. `/v1/models` is the catalog an OpenAI-compatible client already knows how to read. Both the node and the proxy synthesize it from the **same** advertised model set, never by proxying an upstream's list.

OpenAI's official Model object is only `{id, object, created, owned_by}`, with no context window, price or capability. Each entry therefore adds the **OpenRouter-shaped** fields a client reading past `id` actually parses: `context_length`, `architecture.{input,output}_modalities`, `pricing.{prompt,completion,input_cache_read}`, `top_provider.{context_length,max_completion_tokens}`, `hugging_face_id` and `canonical_slug`. It also carries `reasoning` and `tool_use`, spelled as in this section, so one client struct decodes both surfaces. `data` is always an array, `[]` when nothing is advertised.

Four properties are normative:

- **`pricing` is USD per TOKEN, as a decimal string** (OpenRouter's units and type), whereas this section's `*_usd_per_1m` fields are USD per 1,000,000. The string lets a consumer read the advertised rate back without float-formatting noise.
- **`prompt` and `completion` are always present when `pricing` is, `"0"` included; `input_cache_read` follows the OPPOSITE rule.** It appears only when cached reads are actually discounted, and a present `"0"` means free cached reads, the same absent-vs-zero split as `cache_read_rate_usd_per_1m`. Reading an absent `input_cache_read` as zero gets it backwards.
- **`pricing` describes the TOKEN terms and nothing else, and MUST be omitted entirely rather than contradict the rest.** OpenRouter's pricing object has no shape for the long-context surcharge tier, per-image billing or per-tool-call rates. A tiered model therefore advertises only its base rate here, and `long_context_*` stays on `/v1/zs/details`. Two kinds of model MUST publish no `pricing` at all, because token rates would misdescribe what they cost:
  - one serving a **dedicated image route** (`serves_image_gen` / `serves_image_edit`), which bills per image, so any token rates it declares are inert;
  - one whose token rates are **both zero while it charges per in-loop image or per tool call**. An explicit zero is a real "this is free" claim, and that model is not free.
- **`GET /v1/models/{id}` returns the identical entry** to that id's element in the list. A client must not be able to learn different terms from the two.

Every field is additive and optional: a consumer MUST treat any of them as absent, and a new field needs no `proto_version` bump and drives no operator filtering, the same rule as the `/v1/zs/details` model fields. Two shapes follow from that, and both are intended, not defects:

- `architecture` may carry only one of the two modality lists. A declaration on one side is not a declaration on the other, and fabricating the missing one would be worse.
- `canonical_slug` appears **only when `hugging_face_id` is absent**, because for a sourced model the repo IS the canonical identity. OpenRouter, by contrast, always includes it.

Everything here is advisory like the rest of § 3c; the authoritative per-request price is the microUSDC the serving node signs into the reserve ticket. The node and the proxy publish different rates:

- A **node** publishes its own operator rate, matching its `/v1/zs/details`.
- The **proxy** publishes the **payer-net** rate: the operator rate grossed up by the protocol fee. The OpenRouter pricing object has no `fee_bps` field to carry the correction, so a client reading a pre-fee number in that shape would understate its cost with no way to fix it.
- With no field to qualify a number, the proxy publishes no `pricing` while the protocol fee is **unknown**; a cold cache would otherwise emit the raw rate, indistinguishable from a warm zero-fee protocol. It also publishes none when **either** rate is zero: its aggregate keeps the lowest *declared, non-zero* rate and folds the two sides independently, so a zero there means "unknown", never "free".

### Deep model details: the `expand` query parameter

The bare `GET /v1/zs/details` response is the **lean** discovery surface. It may contain cheap signals already held in memory: config/runner coordinates, compact weight digests, tags, and identity fields. Data that requires outbound lookup or verbose per-node evidence is opt-in:

`GET /v1/zs/details?expand=coordinates[,digest]&model=<id>`

- **`model`** scopes the deep computation to one advertised id. The value MUST match a `models[].id` the node currently serves; an unserved id yields an empty `models[]`. A caller SHOULD always pair `expand` with `model`. `expand` without `model` MAY be served lean or refused, because computing the expanded set for *every* model on *every* poll is what this parameter exists to avoid.
- **`expand`** is a comma-separated set of field groups. Tokens compose, so `expand=coordinates,digest` returns both groups. Unknown tokens are ignored for forward compatibility.
  - **`coordinates`** enriches `models[].coordinates` with Hugging Face metadata. Operator config always wins. Hugging Face may refine runner-reported `family`, `parameters`, `active_parameters` and `variant`, but runner-observed `quantization` wins over Hugging Face because it describes the weights actually loaded. The lookup uses the model's `hf:` `source`, or its raw id when that is a valid repository id. It is lazy, cached and fail-open, and the operator MAY disable it.
  - **`digest`** adds verbose weights-integrity detail, described next.

    **Unverifiable models** get `weights_unverifiable_reason`: `no_local_weights`, `runtime_unverified`, `split_weights`, `image_model` or `hash_failed`. `split_weights` means a multi-part set whose parts could not be combined (see below). A set the runtime declines to vouch for is `runtime_unverified`, which names the verification failure rather than the shape.

    **Verifiable models** get `weights_digest_trust`, one of these tiers, strongest first:

    | Tier | Meaning |
    |---|---|
    | `node_supervised` | The node hashed the path it launched. |
    | `runtime_attested` | The serving runtime reported a digest it states it verified against the local file. |
    | `operator_declared` | The node hashed an operator-supplied path, without proving that path is serving requests. |
    | `operator_pinned` | The node accepted an operator-supplied digest without hashing anything locally. |

    The tiers are meant to be ranked, not merely told apart. A consumer SHOULD prefer `node_supervised` and `runtime_attested` (in both, a process hashed local bytes and reported what it found) over `operator_declared`, and both over `operator_pinned`, where no verification of any kind occurred. A consumer that treats `operator_pinned` as equal to a runtime attestation gains nothing from this block, because the cheapest way to claim a model one does not serve is to publish its genuine digest, copied from its registry page.

    **Multi-artifact weight sets.** A model may be several files: safetensors shards, or the multi-part GGUF that every model above a registry's per-file size cap (50 GB on Hugging Face) is published as. A node learns the artifacts either by hashing a declared file list or from a serving runtime that reports a content digest per part. **Both MUST produce the same value for the same bytes**, since they are the same weights and the mismatch rule below reads two distinct digests for one model as a disagreement. So there is exactly one definition:

      > **`zs-weights-digest-v2`.** SHA-256 over the domain tag `zs-weights-digest-v2\0` followed by the artifacts' `sha256:<hex>` **content digests**, lowercased, de-duplicated, lexically sorted, and joined with `\n`. Rendered `sha256:<hex>`.

      **Contents and nothing else**: no filename, path or size. A runtime legitimately renames an artifact on download, so any of those would make two operators serving identical bytes disagree. v2 replaces a v1 that folded a JSON manifest of `{path, size, sha256}` per file. A node advertising a v1 digest for a multi-file model disagrees with a v2 node serving the same weights. That is a one-time upgrade cost, not evidence about either node's weights.

      A single artifact is NOT folded: its digest is that file's own SHA-256, so it stays comparable with `sha256sum` and with a registry's published LFS OID.

      A node MUST advertise no digest, with `weights_unverifiable_reason: split_weights`, unless every artifact in the set is verified and carries a well-formed content digest, and the set has at least two distinct artifacts. A fold over the usable subset would describe weights nobody serves.

      A folded digest is not any artifact's content digest. A consumer MUST NOT expect to find it in a registry, and MUST NOT compare it against a single-artifact digest as though a difference implied different weights. One residual case for the mismatch rule ("Routing consequence" below): a node that hashes just the FIRST part of a split set as a lone file (for a runtime that auto-discovers the remaining parts from it) publishes that part's own SHA-256, which differs from a node publishing the fold. That difference is a provisioning artifact, not different weights.

    **Registry match.** A verifiable model MAY also carry `weights_registry_match`, which is independent of the trust tier:

    - `matched`: the digest is among the artifacts the model's `source` repository publishes.
    - `mismatch`: a complete listing was read, and either an artifact is absent or a shard's group is not held in full.
    - `unchecked`: no conclusive lookup happened, for example because the listing was truncated or a group was unevaluable before either could be established.

    The comparison is content-addressed against the repository's published artifact digests. It MUST NOT be keyed on filename, because a runtime legitimately stores an artifact under a different name than the repository publishes.

    For a **multi-artifact** set the lookup runs per artifact, not on the folded digest, which no repository publishes. It answers whether the set is *one model the repository publishes*:

    - Every artifact MUST be published.
    - For every artifact the repository names as a shard of a multi-part group (`<stem>-NNNNN-of-MMMMM.gguf` / `.safetensors`, grouped by directory, stem and count), the set MUST hold that group's published set in full. Membership alone is not identity: a repository often publishes several quantizations side by side, so parts drawn from two of them, or a subset of one, are each "published" and none is a model.
    - A set MAY hold more than one whole group (a pipeline whose components are each sharded).
    - An artifact the repository does not name as a shard is exempt, since the repository has said nothing about its grouping and membership is the whole answer. A node MUST NOT report `mismatch` on grouping it inferred from names the repository did not give.
    - A group whose published size disagrees with the count its own names declare is unevaluable. A set that fails only against such a group is `unchecked`.

    A `matched` verdict SHOULD be accompanied by `weights_registry_path`, the repo-relative path of the artifact that matched. On a multi-artifact set it MUST be omitted: no page prints a folded digest, and naming one arbitrary artifact would hand the reader a receipt for a different value than the one advertised. It is a display pointer, present only on `matched`, so a consumer can link to that artifact's registry page, which prints the same digest being claimed. Everything else in this block is the operator's node reporting on itself; this is the one field that lets a reader go check. Consumers MUST NOT match on it: it names the file in the repository, never the file on the operator's disk, and the two legitimately differ.

    **Declaration conflict.** A model MAY also carry `weights_declaration_conflict: true`: the operator declared a digest (a pin, or a declared file set) and the serving runtime independently reported loading a different artifact. A node that detects this MUST advertise the runtime's digest rather than the operator's, and report `runtime_attested`, because a declaration is an assertion while the runtime's report is evidence about the artifact loaded. The flag is not proof of dishonesty; pinning an original repository's digest while serving a quantization of it conflicts honestly. But it is the one signal a copied digest cannot suppress, because the contradiction comes from the operator's own runtime.

The compact `models[].weights_digest` and `models[].weights_unverifiable` fields stay on the bare response. They are computed once and are needed across operators for mismatch detection; `expand=digest` does not replace them.

**Trust ceiling.** Every digest and trust tier is self-reported by the operator's node, including `node_supervised`. A dishonest operator can copy a genuine digest while serving different weights. Digest agreement therefore means only that operators report the same digest; disagreement means that reported weights differ and may be legitimate for a quantization or repack. Neither result proves fraud, and neither may affect reserve admission, pricing, or settlement.

**Routing consequence.** Disagreement MAY carry a payer-side routing consequence, and in the reference proxy and client it does. Where at least two distinct operator **owners** advertise the same digest for a model, a candidate advertising a *different* digest for it is demoted to the tail of that request's candidate list. A consumer implementing this MUST follow four rules:

- **Demote, never exclude.** The candidate stays routable as a last resort. A model served by one node must remain reachable, and a legitimate requantization disagrees honestly.
- **Owners, not nodes.** One owner's several nodes are one opinion. Counting nodes would let a single operator manufacture a majority against an honest peer for the price of node registrations instead of operator registrations.
- **A tie is undecided.** Two camps of equal standing identify no outlier, so neither is demoted.
- **Never promote on a self-reported field.** Advertising no digest MUST NOT be penalized, since it is the honest state of every hosted-passthrough model. `weights_digest_trust` / `weights_registry_match` MUST NOT raise a candidate's placement: both are node-authored, and rewarding them would favour the boldest claim rather than the truest one.

Two places where the demotion silently fails to apply:

- **A routing *preference* is not an exemption.** A consumer holding a genuine session continuation (the upstream session lives in one operator's account, so any other operator 404s) MAY exempt that pin, since trading it away breaks correctness. Nothing weaker qualifies. A KV-cache-affinity or last-used-operator pin is a preference. Exempting it disables the demotion for a payer already bound to the contradicted operator for a whole multi-turn conversation: the payer the rule exists for, and the case where a substituted model is worth most to the operator. Both reference consumers exempt nothing.
- **Wherever a fallback path represents a model by a single pre-chosen operator, the ordering has to be applied when that operator is CHOSEN.** A demotion pass over the candidate list cannot reach a model with one candidate, since there is nothing to reorder against. A cross-model fallback that queues one operator per model therefore bypasses the policy entirely, unless the choice itself skips a contradicting operator (falling back to the unfiltered pick when every eligible operator contradicts, per "demote, never exclude").

This policy is local and vantage-specific: the verdict depends on which operators a given consumer has successfully probed. So it lives in each consumer's own routing layer, on purpose outside the shared selection policy and its golden vectors.

`weights_registry_match` narrows the trust ceiling without removing it. A `matched` verdict adds an independent party, since the registry publishes that exact content digest. But it inherits the trust tier's weakness: an operator who can report a digest it does not serve can report one the registry happens to publish. Read the two fields together, and treat `mismatch` as a signal for human review, not evidence of fraud. A locally requantized copy, or a repository that re-uploaded an artifact after the operator pulled it, mismatches honestly.

**Deferred work.** Per-file manifests and hardware-attested measurement bindings are not part of the current response. A future binding may remove the operator from the trust path.

- **Content-Type / auth**: identical to the bare call: plaintext `application/json`, no envelope, no auth. It is still a discovery GET. In transport-privacy mode it rides a relay like any other discovery GET. The relay's inner-path allow-list (the SSRF boundary, § 3f) gates the **path** and forwards the `?model=&expand=` query to the target verbatim; the query can change neither the host nor the route.
- **Advisory.** Coordinates never drive reserve admission, proxy selection, pricing or settlement. A shared `family` describes lineage, not interchangeability; a finetune can share its base family while differing in `variant` and digest. The one exception anywhere in § 3c is the digest-disagreement demotion under "Routing consequence", which reads `weights_digest` and nothing else.
- **Versioning**: `expand`, `model` and every expanded block (`coordinates`, `digest`, future tokens) are **additive**. An unrecognized `expand` token, an absent expanded block, or a node that ignores the parameter entirely are all valid, so a consumer that never sends `expand` sees the byte-identical lean payload. This is a minor, backwards-compatible discovery addition: no `proto_version` **major** bump, no signed structure change, no golden-vector impact.

The reference proxy forwards expanded fields from a specific node without aggregation. Its lean aggregate combines only bare signals:

- config/runner coordinates use a per-field majority, omitting fields with no unique mode;
- `weights_digest` is emitted when all verifiable operators agree, while `weights_mismatch` marks two or more distinct reported digests;
- `source` uses normalized, case- and revision-independent consensus, while `canonical_id` uses exact consensus and appears only when `source` is empty.

Operators without a digest do not vote on digest consensus. `/v1/zs/operators` exposes each node's bare evidence verbatim. A node never sets `weights_mismatch`; that field exists only on the proxy aggregate. These aggregate fields are display signals and gate nothing. The only routing consequence of disagreement is the demotion under "Routing consequence" above, computed per request from per-operator evidence rather than from this aggregate.

### Authority of advertised vs. ticket-pinned values

Details is **non-binding**. A field on this endpoint expresses the operator's current configuration; nothing here is signed and nothing here commits the operator to a specific request.

- **Pricing**: the authoritative per-request rates are the microUSDC/1M values the operator signs into the ticket at reserve (§ 3a "Rate derivation"). The advertised USD rates are a rate card for dashboards and operator-selection heuristics. A client that needs a guaranteed price MUST call `/v1/zs/reserve` and use the returned `ticket.input_rate` / `ticket.output_rate`.
  - Advertised rates are **net of the protocol fee** (§ 3a "Protocol fee"): the operator receives them in full. The fee is added on top and paid by the payer, so at reserve the node grosses up the escrowed `max_price` to `baseMax + ceil(baseMax × feeBps / 10000)`, reading `protocolFeeBps` from chain, to cover base plus worst-case fee. The operator's net price needs no fee adjustment, and nothing else on the reserve, details or hot path changes when `protocolFeeBps` moves; a ticket bills at the rate snapshotted onto its box at `open()` (§ 3a "Open-time fee snapshot").
  - Non-binding does **not** mean unbounded. Before escrowing, a payer-side peer bounds the signed ticket against this rate card and the ticket's own internal consistency (§ 3a "Payer-side price verification"). The bound is a generous abuse multiple because an advertised value is a snapshot that may have aged: a legitimate reprice passes, an inflated ticket does not.
  - A `0` advertised rate (a free model) is also just a snapshot of what the operator offers now; the binding price is still the ticket. A client expecting a free reserve that gets non-zero `input_rate` / `output_rate` back (the operator changed config between probe and reserve) is seeing an aged advertisement like any other divergence below, not misbehavior.
- **Capacity**: the advertised `context_window` and `max_output_tokens` are the values the node consults when accepting a reserve, but the node may change config between the discovery probe and the reserve call. The reserve endpoint is the binding gate: a request that fits at probe time may be rejected if the operator tightens its limits, and vice versa.
- **Identity**: the reference proxy checks `operator_id`, `owner_addr` and `signing_addr` against the on-chain `ZeroSignalEscrow` registry before trusting them to verify tickets or the ephemeral advertisement. (The on-chain record carries no encryption key; envelope encryption targets the signed ephemeral recipient, § 4.) A mismatch between this advertisement and the on-chain record is a misconfiguration the proxy treats as "operator unavailable", not a slashable offense.

A divergence between an advertised value and the eventual ticket is therefore not evidence of misbehavior under § 3b; it is a snapshot that aged. Clients that pre-check capacity through this endpoint should expect occasional reserve rejections and fall through to the next candidate operator.

### Protocol version negotiation

`proto_version` advertises the wire-protocol generation a node speaks. Unlike the rest of the details payload, which is *advisory*, `proto_version` **drives routing**: a proxy or direct client filters out operators whose advertised major differs from its own build's constant, before any reserve round-trip.

**Shape.** `<major>.<minor>` strings, currently `"9.10"`. Both segments are non-negative integers. A major alone (`"9"`) decodes as major-only. A patch suffix (`"9.8.1"`) is tolerated; compatibility still consults only the major segment.

**Compatibility rule.** Major equality. A proxy or client with `wire.ProtoVersion = "9.10"` accepts operators advertising `"9.0"`, `"9.5"`, or `"9.999.x"`. It rejects a different or unparseable major. Minor-version capability checks are separate and fail closed when a feature requires them.

**Missing field.** An absent `proto_version` decodes to `"1.0"`, so the major-equality filter drops the node from a current peer's candidate set, along with every other incompatible generation, without any per-operator config: the node is skipped at discovery.

**Relationship to the crypto domain tags.** `proto_version` is independent of the version tags in the cryptographic layer (`zs-admission-v1\x00`, `zs-ticket-v2\x00`, `zs-receipt-v2\x00`, `zs-ephemeral-v1\x00`) and of the `application/vnd.zs+json` MIME. The rules:

- A **minor** bump is reserved for additive, backwards-compatible changes, such as a new optional field on a discovery response or a new SSE event the client can ignore. It MUST NOT touch the domain tags. 9.9 and 9.10 are the minor bumps so far that were not backwards-compatible; see § 3e verifier step 6.
- A **major** bump is required for any wire-incompatible change. It MAY come with new domain tags or a new MIME, but need not.
- Bumping a domain tag (`-v1` → `-v2`), or rotating the request MIME, is always wire-incompatible and MUST come with a major bump of `proto_version`.

The asymmetry lets a coordinated `proto_version` bump announce "this generation introduces new envelope crypto" *without* forcing the constant to track every internal tag change. Filtering is a discovery-time signal; the domain tags remain the in-the-clear cryptographic separator. Reference: the tags are `AdmissionTagDomain`, `ticketSigningTag`, `receiptSigningTag` and `ephemeralSigningTag`.

**Why this is on details, not in the ticket.** The version field decides whether a client reaches reserve at all. Carrying it on `/v1/zs/details` lets a proxy or client skip an incompatible peer before computing any sealed round-trip, escrow group or admission tag. The failure then surfaces as a discovery-layer 503 (`no_compatible_operator` from the reference proxy), not as a cryptographic decode failure mid-flight.

### Reference implementation

- `inject.OperatorDetails` / `inject.OperatorDetailsModel` (`inject/details.go`) — canonical response shape; both proxy and node import it.
- `node/internal/server/handlers.go::handleDetails` — node-side handler that builds the response from the operator's advertised catalog (`Server.advertisedModels`: ids in `model_pricing`, plus upstream-discovered ids when `default_pricing` is set), with metadata hydrated from upstream discovery and overridden by `model_context_windows`, plus oracle and tool-registry state.
- `proxy/internal/hayai/details.go::DetailsClient.Fetch` — proxy-side probe used by the operator-registry refresh loop.
- `wire/version.go` and `ts/src/wire/version.ts` — version constants, parsing, compatibility, and minor capability gates. The proxy's major-version filter is `pickCandidates` in `proxy/internal/server/hayai_dispatch.go`.

### On-chain reliability metrics

Beyond identity and capacity, the on-chain boxes carry a tamper-resistant lifetime track record that any reader can pull off chain. The contract maintains these fields with no off-chain trust dependency: every counter and aggregate is incremented from the serving node's own settlement and refund paths. `updateOperator` / `updateNode` rotation preserves them verbatim, so re-registering with a fresh signing key does not zero the score.

**Two tiers.** The same metric field block (the table below) lives on BOTH `ZeroSignalEscrow.NodeRecord` (per node, keyed by the compound `(operator_id, node_id)` box) and `ZeroSignalEscrow.OperatorRecord` (the operator-level **rollup** across every node the operator owns). Each finalized settlement, refund or protest bumps the serving node's box AND the operator rollup in the same call. EWMAs and the daily-revenue ring are maintained incrementally on each tier independently, so both are exact. Discovery surfaces per-node metrics (the proxy lists nodes); the operator rollup is the one-shot "how is this operator doing across all its nodes" read. Protocol-wide globals (`proto*`) are the top tier.

| Field | Type | Semantics |
|---|---|---|
| `last_activity_at` | uint64 | Unix-seconds timestamp of the operator's most recent ticket-touching state change (`open()` / `finalizeSettlement` / `refundInactive()` / `protest()` / settle-disagreement freeze). Sentinel 0 = no activity since registration. `updateOperator` does **not** stamp it — config rotation is not service activity. Use this for sub-day liveness in discovery; `buckets_last_day` only moves on successful settlement and is too coarse. |
| `tickets_opened` | uint64 | Total tickets opened against this operator over its lifetime. Incremented inside `open()`. |
| `tickets_settled` | uint64 | Tickets finalized via co-signed match (`settle()` happy path). The success counter. |
| `tickets_lapsed_settled` | uint64 | Tickets force-finalized via `settleLapsed()` — operator's pending claim, payer never acked. Operator was paid via the timeout path. |
| `tickets_refunded_inactive` | uint64 | Tickets refunded via `refundInactive()` — operator never claimed (or never acked a payer-only claim). Operator-side fault. |
| `total_refunded_inactive_usdc` | uint64 | Cumulative `Σ ticket.max_price` (microUSDC) at the time of each `refundInactive()` — total USDC value the operator failed to capture. Pairs with `tickets_refunded_inactive` so a ranker can weight one $500 unpaid ticket above ten $0.10 ones. |
| `tickets_protested` | uint64 | Tickets frozen via `protest()`. Tracked neutrally — outcome resolved off-chain. |
| `total_protested_usdc` | uint64 | Cumulative `Σ amount_charged` from each `protest()` call (the payer-asserted contested figure) — total USDC under payer protest. |
| `tickets_frozen_dispute` | uint64 | Tickets frozen via `settle()` disagreement (mismatched amount / digest / processing-time on second-half ack). Tracked neutrally. |
| `total_frozen_dispute_usdc` | uint64 | Cumulative `Σ ticket.pending_amount` (the first-half claimed amount) on each settle-disagreement freeze — total USDC under co-signing dispute. |
| `latency_total_ms` | uint64 | Cumulative `Σ ttft_ms` (the co-signed `ttftMs` settle arg; total service time on non-stream / no-first-token settles) over **token-output settlements only** (`outputUsageType == Tokens`) — image / other-modality settles are excluded, since TTFT describes the token stream. **Its denominator is `latency_samples`, never `tickets_settled + tickets_lapsed_settled`** — those count every modality, so dividing by them understates the mean for any operator also serving the dedicated image / video routes. |
| `latency_ewma_ms` | uint64 | Exponentially weighted moving average of co-signed **TTFT** (`ttft_ms`) with window N=10, folded **only on token-output settlements** (`outputUsageType == Tokens`). First (token) sample seeds directly (sentinel `latency_ewma_ms == 0`); subsequent samples fold in as `ewma = (ewma * 9 + sample) / 10`. |
| `total_revenue_gross` | uint64 | Cumulative `Σ amountCharged` (microUSDC) over every finalized settlement (clean + lapsed). Under the additive fee model this is the operator's full take — the fee is paid by the payer on top, not netted out. |
| `buckets_last_day` | uint64 | Day index (`floor(latestTimestamp / 86_400)`) of the most recent revenue-bucket update. Sentinel 0 = no settlements ever recorded. |
| `revenue_buckets[30]` | uint64[30] | Daily gross-revenue ring, ring-indexed by `dayIndex % 30`. The contract zeros stale slots on rotation, so every non-zero slot is guaranteed to fall inside the rolling 30-day window. |
| `total_input_tokens` | uint64 | Cumulative `Σ actual_input_count` across every finalized settlement (clean + lapsed). Credited from the co-signed `inputCount` settle arg on finalization. The receipt digest also commits to this value. Input stays token-denominated (no input-side modality vector). |
| `output_units[8]` | uint64[8] | Per-`UsageType` output volume: `output_units[t]` is `Σ output count` credited under `UsageType t` across every finalized settlement (clean + lapsed). Slot `1`=Tokens, `2`=Images, `3`=Characters, `4`=Seconds (+ 3 reserved; slot `0`=None unused). The PRIMARY `outputCount` credits `output_units[outputUsageType]`; an `auxOutputUsageType != None` *additionally* credits `output_units[auxOutputUsageType]` by `auxOutputCount` (chat tokens + tool-produced images on one settle). New modalities reuse a slot — no future deploy. |
| `tokens_per_sec_ewma` | uint64 | EWMA of generation throughput (output tokens / sec), window N=10, folded per finalized settlement as `outputCount * 1000 / decode_ms` (the co-signed `decodeMs` settle arg). Folded **only on token-output settles** (`outputUsageType == Tokens`) with `decode_ms > 0 && outputCount > 0` — image / other-modality settles never sample it, and non-stream / no-first-token settles are excluded so they don't drag it toward zero. First qualifying sample seeds directly. `0` = no qualifying sample yet. |
| `usdc_escrowed` | uint64 | Not a metric — the USDC stake (micro-USDC) this operator/node escrowed at registration (exactly `operatorStakeUsd6` / `nodeStakeUsd6`, since USDC is 6-decimal — no oracle conversion), slashable **to the treasury** by the admin-only `evictOperator(operatorId, slashBps)`. Sits here in box order, between `tokens_per_sec_ewma` and the reserved residual. |
| `latency_samples` | uint64 | Count of settlements folded into `latency_total_ms`, bumped inside the *same* `outputUsageType == Tokens` guard as the numerator, so it is the exact denominator for the mean TTFT. **Sits at the very tail of the box, AFTER the reserved residual** ("Reserved slots" below). See the note below. |

**`latency_samples` seeding.** `0` means no token settle has landed since the field was added. The contract seeds it once, on the first such settle, from the all-modality count (`tickets_settled + tickets_lapsed_settled` at that moment), so existing `latency_total_ms` history isn't divided by a counter starting at zero. The seed carries any earlier skew forward, since the information to unwind it was never recorded; every fold after it is exact.

Field order in the box matches this table, except `latency_samples`, which is the last field, after the reserved residual. The `proto/go/escrow/operators.go` positional parser mirrors it.

#### Protocol-wide aggregates (app global state)

The contract also maintains a set of cumulative protocol-wide totals in app **global state** (not box state — no MBR cost), so a dashboard can pull a one-shot "how is the protocol doing?" read without enumerating every operator box. All are `uint64`; read via the standard algod application-global-state query.

| Global key | Semantics |
|---|---|
| `pto` | `proto_tickets_opened` — Σ over all operators' `open()` calls. |
| `pts` | `proto_tickets_settled` — Σ clean co-signed settlements. |
| `ptl` | `proto_tickets_lapsed_settled` — Σ `settleLapsed()` finalizations. |
| `ptr` | `proto_tickets_refunded_inactive` — Σ `refundInactive()` refunds. |
| `ptp` | `proto_tickets_protested` — Σ `protest()` freezes. |
| `ptf` | `proto_tickets_frozen_dispute` — Σ settle-disagreement freezes. |
| `prg` | `proto_revenue_gross` — Σ `amountCharged` over every finalized settlement. |
| `pfn` | `proto_fees_net_collected` — Σ `netFee` transferred to treasury over every finalized settlement. Under the additive model the fee is paid by the payer on top of the operator's base charge (payer net cost = `amountCharged + netFee`); the operator's payout is the full `amountCharged`. With no discount mechanism, `netFee == grossFee` and this equals Σ `grossFee`. |
| `pat` | `proto_active_tickets` — count of ticket boxes currently alive on chain (OPEN+PENDING+FROZEN). Incremented at `open()`, decremented only on box deletion (`finalizeSettlement` / `refundInactive`); freeze paths do **not** decrement because frozen funds remain in custody. |
| `peu` | `proto_escrowed_usdc` — Σ `maxPrice` locked in alive ticket boxes; mirrors `pat`'s increment/decrement sites. The TVL of escrowed USDC in the app. |
| `pdg` | `proto_discount_granted_usdc` — Σ `(grossFee − netFee)` over every finalized settlement; total USDC value the protocol forgave via fee discounts. **DEPRECATED**: with no discount mechanism (`discountBps` is always 0), `netFee == grossFee` and this accumulates 0. Retained for state-layout stability. |
| `ptin` | `proto_total_input_tokens` — Σ actual input tokens across every finalized settlement. Mirrors the per-operator `total_input_tokens` aggregate so dashboards can pull a one-shot protocol read. |
| `pton` | `proto_total_output_tokens` — Σ output **tokens** across every finalized settlement. Kept token-only (gated on `outputUsageType == Tokens`); image / other-modality output is not folded here (a protocol-wide modality vector is deferred — the per-operator/node `output_units[8]` carries the breakdown). |

#### Latency + throughput: co-signed `ttft_ms` + `decode_ms`

`ttft_ms` and `decode_ms` on the receipt are operator-measured timing, carried as two separate `uint64`s:

- `ttft_ms` is time-to-first-token: prefill plus queue, up to the **first response from the LLM of any kind** (reasoning, content or a tool call).
- `decode_ms` is decode time, from the **first frame the upstream sent** to completion — deliberately not from the first *output* frame. See "Where the decode window starts" below.

The two windows therefore **overlap**: decode opens at or before TTFT closes, and `ttft_ms + decode_ms` is not total service time. The gap between them is whatever the upstream sent before its first token, which for a provider that opens the stream and then thinks silently is the entire thinking phase. They coincide (adjacent, as they were before) whenever the first frame *is* the first output frame, which is the common case.

Both are in the receipt's canonical bytes, so the receipt digest commits to them, and both are passed verbatim as the `ttftMs` / `decodeMs` ABI args on `settle()`. The contract requires each to match across both halves of the co-signed settle (operator first half + payer ack); a mismatch on either freezes the ticket (`STATUS_FROZEN`), just as an `amount_charged` or `receipt_digest` mismatch does. Neither side can inflate or deflate either metric on its own: the primitive that secures the amount secures the timing.

On finalization the contract folds:

- **TTFT → latency** (`latency_total_ms` / `latency_ewma_ms`, N=10). `ttft_ms` is the latency sample. Total wall-clock mixes prefill latency, generation throughput and response length; TTFT isolates the operator-quality signal a caller feels before the first token. The first token of any kind stops the clock: a reasoning model's leading thought and a tool-first turn's tool-call delta count, not just visible text.
- **decode + output tokens → throughput** (`tokens_per_sec_ewma`, N=10): `output_tokens * 1000 / decode_ms`, sampled only when `decode_ms > 0 && output_tokens > 0`.

Both aggregates are also **routing inputs**: `latency_ewma_ms` (TTFT) and `tokens_per_sec_ewma` (decode throughput) feed the app-side target **responsiveness banding** (the combined expected-response-time score in § 3f "Path selection"). They are per-node aggregates across served models, a hardware-speed proxy rather than a per-model figure, which is why the decode term is weighted lightly there.

**Where the decode window starts.** `output_tokens` is the provider's completion count with **reasoning tokens folded in**, so the window `decode_ms` measures must cover the thinking those tokens paid for. A provider that streams its reasoning poses no problem; several do not, and for them the whole thinking phase sits before the first output frame. Splitting there would divide the full token count by the visible answer alone and report a decode rate the hardware never reached — inflated by the ratio of total to visible tokens, which reaches 10–40× on a heavy reasoning model, and folded straight into a `tokens_per_sec_ewma` that routers rank targets by. Two rules keep the window honest:

- The window opens at the first frame that means the model has **begun generating**, not merely that the request was accepted. On the Chat shape that includes the role-only prelude (`{"delta":{"role":"assistant"}}`), which a provider sends once it is producing. On the Responses shape the envelope acks — `response.created`, `response.in_progress`, `response.queued` — are **excluded**: they are emitted when the upstream accepts the request, before prefill and before a queued request has started, so anchoring there would charge every Responses request's prefill to its decode window. The window opens at the first item / content / delta event instead. `ttft_ms` is unaffected either way and still ends at the first real output frame: a frame the caller cannot see must not shorten the reported wait, while a provider that opens the stream and then thinks silently has that thinking counted as the decode it is. Call such a window **anchored** — a frame arrived strictly before the first token, so something marks where generation began.
- When a receipt bills reasoning tokens, **no reasoning frame was ever streamed**, and the window is **not anchored** — the upstream said nothing at all before the answer — then nothing marks where generation began. The operator then measures `decode_ms` over the whole service window (`request_start` → completion, less tool-execution time). That folds prefill into decode and so **under**-states throughput — deliberately: the error is bounded and in the safe direction, and unlike setting `decode_ms = 0` it still produces a sample, so a node serving only hidden-reasoning models converges instead of holding whatever value it already had.

  All three conditions are load-bearing, and the anchoring one is the least obvious. A provider that opens with a prelude and *then* thinks silently also reports reasoning it never streamed, so the first two conditions alone would fire on it — and replace a window that already covers the thinking and excludes prefill with a wider one that folds prefill back in. Anchoring is what keeps the two rules disjoint rather than the second shadowing the first.

  The rule is scoped to **streams that produced a first token**, which is not the same as "streams reporting a non-zero `decode_ms`". A provider that thinks for ten seconds and then returns its whole answer in one frame has a measured window that rounds to zero, and that is the receipt most in need of the fallback — so scoping on a non-zero `decode_ms` would exclude precisely the worst cases while admitting the mild ones. It still cannot reach a non-stream or no-first-token settle (see the next convention), and it never overrides the estimated-usage rule below, whose `decode_ms = 0` is a MUST.

**Built-in tool loops:** a request that invokes ZeroSignal built-in tools runs as several upstream generation rounds with tool execution in between. The operator measures `decode_ms` as wall-clock from the window start above to completion **minus the time spent executing tools** between rounds. The throughput metric then reflects the node's own generation rate (all rounds, including post-tool generation, count toward `output_tokens`), not the latency of the external tools (web search, image generation) it called for the caller. Inter-round prefill stays in `decode_ms`, since it is genuine node work.

**Non-stream / no-first-token convention:** when no first-token timestamp exists (a non-streamed request, or a stream that produced no output), the operator sets `ttft_ms` = total service time and `decode_ms = 0`. Such a settle still contributes to latency through `ttft_ms`, but the `decode_ms > 0` guard **excludes** it from the throughput EWMA, so a non-streamed request never reads as "0 tokens/sec".

**Estimated-usage convention:** `decode_ms = 0` has a second producer, which does **not** carry the `ttft_ms` meaning above.

- When a stream is truncated before an authoritative `usage` payload arrives (most often because the caller disconnected mid-generation), the operator may bill an estimate from the number of streamed output frames instead of refunding in full. `output_tokens` is then a frame count, not a token count, so any throughput derived from it is meaningless. The operator MUST therefore set `decode_ms = 0` on such a receipt, while still reporting the measured first-token latency as `ttft_ms` when a first token was observed.
- The two conventions can coincide. The frame counter behind an estimate is cheaper than the first-token detector by design (it need not parse each frame), so a stream of frames carrying no model output can yield an estimate with no first-token timestamp. The non-stream convention then applies and `ttft_ms` *is* total service time.
- So `decode_ms == 0` alone says nothing about which `ttft_ms` meaning is in force. The two differ only in whether a first token was observed, which the receipt does not encode, so a consumer must not infer either from the zero.

**Payer side:** an absent sample leaves `tokens_per_sec_ewma` at 0. The app-side responsiveness banding must treat an unknown decode term as *unknown*, substituting the median known term across the candidate set, not as zero decode time. A consumer that instead dropped the term from its additive lower-is-faster score would rank a node reporting nothing as infinitely fast, making the omission profitable. See § 3f "Path selection".

`settleLapsed()` (operator-claimed, payer silent) credits both metrics from the operator's pending values, as it credits revenue from the pending `amount_charged`. Refund, protest and freeze paths credit neither, since no co-signed value exists.

Block timestamps are not used. `Global.latestTimestamp` is per block (~2.8s on Algorand mainnet), too coarse for sub-block inference timing; the operator-measured value is the trusted source.

#### Revenue: lifetime + 30-day ring

`total_revenue_gross` is an unbounded lifetime counter, incremented on every clean and lapsed finalization. There is no per-record net counter: under the additive fee model the operator's take *is* the gross `amountCharged`, and the fee side lives in the protocol-wide `pfn` global. `revenue_buckets[]` is a 30-slot daily ring keyed by `dayIndex % 30`. The on-chain write path zeros any slot whose day is more than 29 days old before writing, so off-chain readers can sum slots blindly without stale entries.

Off-chain windowed reads (`Revenue24h`, `Revenue7d`, `Revenue30d` in `proto/go/escrow/operators.go`) sum the appropriate slice for the requested window length:

- 24h → the slot at `currentDay % 30` only.
- 7d  → the 7 slots at `(currentDay − 6 .. currentDay) % 30`.
- 30d → all 30 slots.

A reader passing a `currentDay` that is more than 29 days ahead of `buckets_last_day` will see all-zero windows — the on-chain write path has already zeroed every slot in that case.

Per-bucket counts are intentionally not stored; daily-average revenue is `windowed_revenue / window_days`, and per-ticket-within-window averages are recoverable off chain from settle-txn history via the indexer.

#### Tokens: lifetime totals (co-signed)

`total_input_tokens` accumulates the operator's actual prompt token count, and `output_units[UsageType]` accumulates output counts per modality, across every finalized settlement (clean + lapsed). The inputs are the `inputCount` / `outputCount` settle args (two separate `uint64`s) plus `outputUsageType` / `auxOutputUsageType` / `auxOutputCount` for routing:

- `inputCount` adds straight into `total_input_tokens`;
- `outputCount` credits `output_units[outputUsageType]`;
- `auxOutputCount` credits `output_units[auxOutputUsageType]` when the aux type is not `None`.

The receipt digest already commits to all of these through the receipt canonical bytes, so the credit is authenticated end to end. They follow the same co-signing model as the timing args: a mismatch on the second-half ack freezes the ticket, and `settleLapsed` credits the operator's pending values. Reference: `SettleArgs.InputCount` / `OutputCount` / `OutputUsageType` / `AuxOutputUsageType` / `AuxOutputCount`; `ticket.UsageReceipt.CanonicalBytes`.

There is **no** per-day ring buffer for tokens. The lifetime totals are the only on-chain token/output aggregate. Off-chain consumers that want windowed volume can derive it from settle-transaction history through the indexer, since each settle transaction carries the `inputCount` / `outputCount` / `outputUsageType` / `auxOutputUsageType` / `auxOutputCount` args.

#### Wire-format note

The metric block lives on both boxes, and the positional parsers in `proto/go/escrow/operators.go` (rollup) and `proto/go/escrow/nodes.go` (per node) mirror the table's field order:

- **`OperatorRecord`** = **529 bytes**: `owner`(32) + `status`(1, `arc4.Uint8`) + `nfd_app_id`(8) + `next_node_id`(8) + `live_node_count`(8) + 96 reliability + 8 total_revenue_gross + 8 buckets_last_day + 240 revenue_buckets + 8 total_input_tokens + 64 `output_units[8]` + 8 throughput_ewma + 8 `usdc_escrowed` + 24 reserved_slots + 8 `latency_samples`. Box key `o:` + `be64(operator_id)`. This record is the operator-level rollup; node identity (signing address, base URL) and per-node metrics live on `NodeRecord`.
- **`NodeRecord`** = **755 bytes**: `status`(1) + `signing`(32) + `base_url_len`(1) + `base_url`(248) + the same 96 + 8 + 8 + 240 + 8 total_input_tokens + 64 `output_units[8]` + 8 throughput_ewma metric tail + 8 `usdc_escrowed` + `staging`(1, `arc4.Uint8`: 0=production, 1=staging) + 24 reserved_slots + 8 `latency_samples`. There is no on-chain encryption key; envelope encryption targets the signed ephemeral recipient (§ 4 / § 8). Box key `n:` + `be64(operator_id)` + `be64(node_id)`; the operator-id-first key lets off-chain consumers prefix-scan one operator's nodes. The `staging` byte is toggled by the operator's owner OR the node's signing key via `setNodeStaging`. A staging node still advertises on-chain but is meant to be held out of normal routing and selection.

Adding, removing or reordering metric fields, or any protocol-wide global key, is a wire-format change under the same coordination rules as any other contract-side change in this spec: update this section and the Go parsers in the same change.

##### Reserved slots (the 32-byte reserve on OperatorRecord / NodeRecord / TicketRecord)

Each of the three records was deployed with a raw 32-byte `arc4.StaticBytes<32>` blob (`reservedSlots` / `ReservedSlots`), zero-initialized at `createOperator` / `createNode` / `open()`. The blob is **slack** for adding small fields (uint8 enums, small counters, a single 32-byte digest) without a fresh deploy. A new field is carved *out of* the reserve, leaving a shorter residual at the same total length, so MBR and the per-box size never move. ARC-4 tuples are byte-packed with no alignment, so any width carves cleanly. Every carve must land in `proto/go/escrow`'s positional parser (`operators.go` / `nodes.go` / `tickets.go`) and its round-trip test in the same commit; those decode by byte offset, so a mismatch silently mis-decodes the box instead of failing loudly.

**`reservedSlots` is not the last field on `OperatorRecord` and `NodeRecord`.** `latency_samples` (uint64) was carved from the **tail end** of their reserve, so each reads `… reservedSlots: arc4.StaticBytes<24>, latencySamples: uint64`, with the 24-byte residual *ahead* of the carved field. (A tail carve cannot collide with a concurrent head carve on the same blob.) The obvious mental model, "the reserve is the tail", is therefore wrong for these two records:

- On `OperatorRecord` / `NodeRecord`, **carve further fields from the HEAD of the 24-byte residual and shrink it, never past its end.** A field appended after `latencySamples` grows the box, a real MBR delta that `updateApplication` cannot perform.
- On `TicketRecord` the reserve is still a true 32-byte tail, so the plain recipe applies: replace the blob with the typed field(s) plus a shorter residual after.

Check the remaining slack before planning a carve: `OperatorRecord` and `NodeRecord` are down to 24 bytes each, and unmerged work may already claim some of it. Once a record's reserve is exhausted, the next field on it is a real wire-format break, and a fresh deploy is the expected path.

**`TicketRecord`.** When promoting a field out of its `reservedSlots` tail, keep the total length stable so there is no per-ticket MBR delta, and update `proto/go/escrow/tickets.go`'s positional parser and `tickets_test.go`'s round-trip in lockstep. The ticket box value is **264 bytes** (`mbrForTicket()` = 115,300 µALGO). That includes:

- the unpacked pending timing and count fields (`pendingTtftMs` / `pendingDecodeMs` / `pendingInputCount` / `pendingOutputCount`);
- the co-signed modality routing (`pendingOutputUsageType` / `pendingAuxOutputUsageType`, 1 byte each, plus `pendingAuxOutputCount` u64);
- the open-time `feeBps` + `discountBps` fee snapshot, stored as two typed fields rather than carved from `reservedSlots`, so the rate is self-documenting in the ARC-56 struct and the generated clients. `reservedSlots` stays a full 32 bytes.

Adding a real field beyond the reserved blob is a per-ticket MBR delta, so a fresh deploy absorbs the in-flight overlap.

**Right-sized bounded fields.** Fields with a small, contract-bounded domain are stored as narrow ARC-4 ints rather than `uint64` to cut box MBR:

- `TicketRecord`: `status` / `pendingBy` as `arc4.Uint8`, `feeBps` / `discountBps` as `arc4.Uint16`;
- `OperatorRecord`: `status` as `arc4.Uint8`;
- `NodeRecord`: `status` and `baseUrlLen` as `arc4.Uint8`.

ARC-4 tuples are byte-packed with no alignment, so each narrowing saves its full width delta. The Go positional parsers (`tickets.go` / `operators.go` / `nodes.go`) read the narrow widths and widen back to `uint64`, so Go consumers are unaffected. The generated **TS** client decodes these fields as `number` rather than `bigint`; consumers that compare against `bigint` literals or need a `bigint` must adjust (e.g. `Number(record.baseUrlLen)`). Narrowing or widening any of these is a wire-format break under the usual coordination: update the contract struct, the Go parsers and round-trip tests, and this section in lockstep.

## 3d. ZeroSignal built-in tools (client opt-in)

ZeroSignal built-in tools (`zs_web_search`, `zs_web_read`, …) are server-executed function tools the **node** runs for the client during a request, transparently to the upstream LLM provider. The client opts in per request by listing them in the OpenAI-shaped request body's `tools[]` array. The node intercepts those entries, rewrites them into standard function-tool definitions before forwarding upstream, and dispatches the resulting `function_call` outputs against its local tool registry instead of returning them to the client.

This section fixes the contract, so a client (TUI, SDK, third-party router) can opt in without coupling to a specific node's tool catalog.

**The per-request opt-in is the only control, and it is load-bearing beyond convenience.** `zs_web_search`, `zs_web_read` and `zs_image_search` send prompt-derived content to a third party; the node runs one only because the caller named it in `tools[]`, so which requests egress is the caller's decision and not the operator's. A node advertising a confidential posture (§ 3e) MAY therefore serve these tools, and `builtin_tools[]` on `/v1/zs/details` is the disclosure — read § 3e's note under the `posture` object for what that disclosure does and does not carry, and for why it does not weaken `plaintext_terminates`. An operator may still decline to offer a tool at all: the caller cannot request one the node does not advertise.

The same is true of the other caller-supplied egress in this array — a remote `mcp` entry, or a provider-native `web_search` — neither of which is a `zs_` type and neither of which the node intercepts. A relying party reasoning about egress must read the whole `tools[]` array, not the `zs_` prefix.

### Wire shape — what the client sends

A ZeroSignal built-in-tool opt-in is a single-field JSON object inside the existing OpenAI `tools[]` array:

```json
{ "type": "zs_web_search" }
```

The `type` value is the built-in tool type, always `zs_`-prefixed. The client MAY include other `zs_` entries alongside its own function tools and the provider-native `web_search` / built-ins; the node acts only on entries whose `type` starts with `zs_`.

Clients **MUST NOT** populate `name`, `description` or `parameters` on a ZeroSignal built-in-tool entry. The node-side rewrite silently strips anything beyond `type`, and extra fields would only desync the client's view from the node's authoritative definition. The reference TUI enforces this, with a test.

### Discovery — how the client learns the available types

Available `type` values come from `GET /v1/zs/details` (§ 3c). Each `builtin_tools[]` entry advertises **only** the bare `{type}`, the opt-in surface. `name`, `description` and `parameters` are **not** carried on the wire; they are node-internal and authoritative there ("Authority" below). A client that needs human-readable text (dashboards, CLI listings, autocompletion) resolves it locally by `type` from its bundled proto package. The descriptors are identical across nodes of the same `proto_version`, and `/v1/zs/details` is polled, so re-sending them on every probe would be waste. The advertisement is non-binding (§ 3c "Authority of advertised vs. ticket-pinned values"): a client that pre-checked a tool may still see a request rejected if the node's catalog narrows between probe and dispatch.

### Authority — who owns the function-tool definition

The **node's local registry** is the single source of truth for `name`, `description` and `parameters`. Those fields never leave the node: they are not advertised (only `type` is) and never accepted from the client. The proxy mirrors the node's type-only advertisement on its own aggregated `/v1/zs/details`. The reasons:

- the node executes the tool locally, so the parameter shape and description it documents are the ones it actually accepts;
- a client shipping its own copy of the descriptor would freeze whatever it last saw at discovery, and silently disagree with the node when the catalog evolves;
- a node can fix a description bug without coordinating a client release.

### Node behavior — request-side rewrite

After admission and decryption, before forwarding the body upstream, the node walks `body.tools[]` and replaces every `{"type":"zs_*"}` entry with the endpoint's standard function-tool form:

- **Responses API** (`POST /v1/responses`): hoisted shape — `{"type":"function","name":"<def.Name>","description":"<def.Description>","parameters":{<def.Parameters>}}`.
- **Chat Completions** (`POST /v1/chat/completions`): nested shape — `{"type":"function","function":{"name":"<def.Name>","description":"<def.Description>","parameters":{<def.Parameters>}}}`.

`def.Name` MUST equal `string(def.Type)`. The rewriter sets the function name to the `zs_` type string so the response interceptor can match `tool_calls[i].function.name` against the `zs_` type set without extra bookkeeping.

Non-`zs_` entries (provider-native tools, client-defined function tools) pass through byte-for-byte. When `tools[]` contains no `zs_` entries, the rewrite is a byte-for-byte no-op on the entire body.

A `zs_*` type missing from the node's registry is rejected as `400 invalid_request_error` with code `unknown_builtin_tool`. When the node's built-in tool subsystem is disabled, the rewrite is skipped: bare `zs_` entries reach the upstream LLM unrewritten and the LLM does not call them. That is the safe failure mode, since the LLM treats an unknown tool type as a no-op rather than a malformed request.

### Dispatch — what happens during inference

When the model emits a `function_call` (Responses) or a `tool_calls[]` entry (Chat) whose function name matches a rewritten `zs_` type, the node:

1. suppresses the call frames from the client wire, since they are not part of the OpenAI vocabulary the client expects;
2. executes the tool locally against its registry runtime;
3. (Responses API only) emits sealed status frames per § 5.3.1, so the client can show progress;
4. appends a synthetic `function_call_output` / `tool` message carrying the tool's JSON result, and re-enters inference for another iteration.

The loop ends when:

- the model emits no more `zs_` calls;
- `max_tool_iterations` (advertised on `/v1/zs/details`, § 3c) is reached; or
- the node's stall guard finds the model stuck, repeating the same built-in tool call (identical tool name and arguments) for several consecutive rounds without progress. The stall guard is a node-internal safety heuristic, not wire-advertised.

On the cap or a stall, the node returns a sealed error response and a zero-cost receipt, so the proxy settles the ticket at 0.

**Tool-call markup in content.** "No more `zs_` calls" means no more *structured* calls. A serving runtime with no tool-call parser for the model's chat template (vLLM/SGLang without a matching `--tool-call-parser`) returns the model's native tool-call tokens verbatim in the visible content instead. That would read as a finished answer and ship raw protocol markup to the caller.

- The node therefore also scans a round's visible content for such markup. When the markup names a tool this request offered and is the round's *entire* output, the node recovers the call and runs it as if it had been structured.
- Like the stall guard, this is node-internal and not wire-advertised. Recovered calls are subject to the same iteration cap, stall guard and per-tool provenance rules, and count toward the same billing.
- The one case it cannot recover is a round that the reserve input-budget guard (§ 3a) had already forced to be final, since another tool round there would bill past the escrow. That round is re-asked once; if it still produces only markup, it ends with a sealed error and a zero-cost receipt.

Client-defined function tools and provider-native built-ins (e.g. OpenAI's `web_search`) are NOT intercepted; those calls flow through to the client or provider as normal.

**MCP.** The Model Context Protocol is not a wire concept here. It can reach a node in two ways, handled differently:

- **Caller-run MCP.** A caller that runs its own MCP client (every coding agent does: Claude Code, Codex, opencode, Cursor) expands each MCP server's tools into ordinary `{"type":"function"}` entries *before* sealing. The node sees function tools and the rule above applies unchanged: the caller executes each call and re-issues, one reserve → pay → settle per round. This works against any tool-calling backend.
- **Remote MCP.** A caller may instead send a remote-MCP entry (`{"type":"mcp","server_url":…}`, a Responses-API construct where the *upstream* performs the call). The node classifies it as a vendor-hosted tool with no per-call fee, forwards it unchanged, and does not meter it. It counts toward the operator's vendor call cap where one applies. An operator that has priced nothing has no cap, so remote MCP is forwarded unbounded by default, on purpose: each hosted call's results are re-prefilled into the context and billed as ordinary input tokens against the ticket's `max_price`. Whether it works at all depends on the operator's upstream. It is not part of this protocol and is not advertised on `/v1/zs/details`, so a caller cannot discover which operators honour it.

Reserve sizing follows the same split. Tool-loop headroom (§ 3a) is added only for tools that grow the *serving* side's context: `zs_` built-ins (the node loops in-process) and vendor-hosted tools (the upstream re-prefills results). Caller-executed tools add none, because each of the caller's rounds is a separate request, measured and paid for on its own. Those are plain function tools and the hosted-shaped types the harness actually runs (`local_shell`, `apply_patch`, `computer_use`, `shell` with `environment.type:"local"`, Anthropic's `bash` / `text_editor`).

### Read provenance — `zs_web_read` is limited to known URLs

`zs_web_read` fetches an arbitrary URL and feeds the page into the model's context. A malicious page can therefore carry an indirect prompt injection that steers a *later* tool call into encoding conversation data into an attacker-controlled URL, a data-exfiltration channel out of the sealed session. To close it, the node limits what `zs_web_read` may fetch within a request to a **provenance allow-set**. A URL is permitted only if it:

- (a) appeared in the caller's own prompt/input text, or
- (b) was returned as a result of a prior `zs_web_search` / `zs_image_search` **in the same request**.

A URL the model synthesized from fetched-page content, including a link found *inside* a fetched page, is refused. The node returns the read as a tool-error observation and never performs the fetch; the model recovers and can search for the page first. URLs carrying embedded credentials, or targeting loopback / private / link-local / metadata hosts, are also refused even when in the allow-set (SSRF hardening).

Membership is exact on a normalized URL with the query string preserved verbatim, so appending a `?…=<data>` payload to an allowed URL does not match.

The node performs the fetch itself, converting the page to markdown in-process rather than delegating to a URL→markdown service, so no third party learns what a caller asked to read. That makes the SSRF surface the node's own network, so the guard has two layers. The provenance gate screens the URL's *hostname* without resolving it, and the fetch refuses to dial any *resolved* address in private / loopback / link-local / carrier-NAT space. A public hostname pointing into private space, or rebinding between check and connect, is therefore refused at connect time.

This mirrors the mitigation major hosted agents apply ("limit navigation to search results and user-provided URLs"). Both layers are **node-enforced and not wire-advertised**. Clients need not opt in or change their request shape, and a well-behaved model doing `search → read a result` is unaffected. The only client-visible effect is that a read of an unknown URL returns a tool error instead of page content.

### Reference implementation

- `proto/go/tools/tools.go::BuiltinToolDef` — node-internal canonical descriptor (registry + request-side rewrite). `proto/go/tools/tools.go::BuiltinToolAdvert` (`BuiltinToolDef.Advert()`) is the type-only shape `/v1/zs/details` advertises.
- `proto/go/tools/tools.go::IsBuiltinToolType` — the `zs_` prefix check that gates the rewrite.
- `proto/go/tools/tools_responses.go::RewriteBuiltinToolsResponses`, `proto/go/tools/tools_chat.go::RewriteBuiltinToolsChat` — endpoint-specific request-side rewriters.
- `node/internal/server/handlers.go` (search "Built-in tools rewrite") — node-side dispatch into the rewriter, including the gate-closed log line useful for diagnosing "the LLM doesn't see my tool" reports.
- `node/internal/server/web_read_gate.go` — the `zs_web_read` read-provenance allow-set (seed from user text, accrue from search results, exact-normalized membership + SSRF/credential screen); enforced in `executeBuiltinCalls`.
- `node/internal/tools/webread/webread.go` — the in-process fetch + readability + HTML→markdown conversion. Its HTTP client refuses to dial a resolved private/loopback/link-local/CGNAT address (`proto/go/httpx`), which is the network-layer half of the SSRF defense above; the gate is the provenance half.
- `tui/main.go::fetchHayaiDetails` — TUI's bare-type opt-in; the canonical client reference for this contract. The `SPEC §3d` test assertion in `tui/main_test.go` enforces the no-extra-fields rule under "Wire shape".

## 3e. Optional: node hardware attestation (TEE)

A node MAY opt into **confidential mode**, running the entire node binary inside an attested CVM, and advertise that posture so the proxy can verify it before sealing TEE-required traffic. This section fixes the wire surface and the verifier's responsibilities. The threat model, encryption walk and key-binding rationale are in [`TEE.md`](./TEE.md); operator setup is in the [confidential compute guide](https://docs.zerosignal.ai/concepts/confidential-compute).

Confidential mode is **layered on top** of the existing protocol: no envelope (§ 4) or AAD (§ 6) shape changes. The proxy makes a routing decision at request time from a verdict cached at refresh time ("Why attestation is not bound into per-request AAD" below).

**A quote is not a posture.** The measurement answers "which software ran", not "where does plaintext come to rest". Two nodes can present equally valid quotes that mean different things:

- **Plaintext terminates in the enclave**: the node runs the weights itself, inside the measured CVM, and the prompt reaches no other host to be answered. ("To be answered" is the scope, and is load-bearing — see the `posture` object below.)
- **Plaintext terminates at a named upstream**: the node decrypts inside the measured CVM and forwards to exactly one named third-party inference API under that API's zero-retention terms. The operator is not that party and, because the measured image fixes the forwarding behaviour, cannot become it.

The second is a real but weaker guarantee, and a payer must be able to tell the two apart *before* routing. The bundle therefore carries a `posture` block. **Since 9.10 it is bound into `report_data`** (`H_posture`, verifier step 6). The value a verifier reads is the one the measured binary derived from its **effective** configuration, signed by the hardware alongside the key binding. The measurement says which code ran, and the binding says what that code reported. Before 9.10 the block was a claim signed by nobody, and nothing tied the upstream a payer was shown to the upstream the node dialed. The literal `NODE_CONFIG_YAML` text in `app_compose` cannot stand in for it: env overrides and dstack's `${VAR}` substitution both apply after the compose is hashed, so the text is not what the node runs.

### Discovery: `tee` field on `/v1/zs/details`

The `OperatorDetails` response (§ 3c) has an optional `tee` object. Absent or null means "this operator does not advertise TEE"; clients with no TEE awareness are unaffected.

```json
{
  "...existing fields...": "...",
  "tee": {
    "mode": "nvidia-cc-tdx",
    "attested_at": "2026-04-29T12:34:56Z",
    "evidence_url": "/v1/zs/attestation"
  }
}
```

| Field | Type | Semantics |
|---|---|---|
| `mode` | string | One of `"stub"` (dev only), `"nvidia-cc-tdx"`, `"nvidia-cc-snp"`, `"dstack-tdx"`. Empty equals `"none"`, the same as the field being absent. Production proxies MUST reject `"stub"` unless explicitly opted in via an `allow_stub` config knob. **Advisory only at the verifier**: it is cross-checked against the bundle's `mode` for `advertisement_mismatch`, but the vendor chain is derived from the report bytes ("Verifier responsibilities" step 5), never selected by this string. |
| `attested_at` | RFC 3339 | `GeneratedAt` of the most recent successfully minted evidence bundle. Zero until the cold-start refresh lands; the proxy treats that as "advertised but not yet attested", so TEE-required traffic still filters this operator out. |
| `evidence_url` | string | Absolute or path-relative URL of the full evidence bundle. Always `/v1/zs/attestation` in v1; it is explicit so a future protocol version can move the endpoint without breaking discovery. |

### Evidence: `GET /v1/zs/attestation`

The endpoint is **plaintext JSON, no envelope**. Like `/v1/zs/details`, it carries no prompt and is gated only by HTTP. (`/v1/zs/reserve` is also gated only by HTTP and carries no prompt, but its request body is age-sealed; § 3a.) Refresh cadence is operator-configured (default 1h); evidence served past `2 × refresh_interval` returns `503 stale_attestation` (§ 10).

```json
{
  "mode":            "nvidia-cc-tdx",
  "cpu_report":      "<base64 TDX or SEV-SNP report>",
  "gpu_eat":         "<NVIDIA EAT JWT>",
  "node_pubkey":     "age1... (the node's current signed ephemeral_age_pubkey, § 3c)",
  "operator_id":     42,
  "report_data":     "<base64 SHA-256(node_pubkey || be64(operator_id))>",
  "generated_at":    "2026-04-29T12:34:56Z",
  "refresh_seconds": 3600,
  "stub":            false
}
```

A `dstack-tdx` bundle carries no `gpu_eat` and adds the runtime measurement log, the compose preimage, and a posture block:

```json
{
  "mode":            "dstack-tdx",
  "cpu_report":      "<base64 TDX quote>",
  "event_log":       "[{\"imr\":3,\"event_type\":134217729,\"event\":\"compose-hash\",\"event_payload\":\"6e6f38...\"}, ...]",
  "app_compose":     "{\"manifest_version\":2,\"runner\":\"docker-compose\",\"docker_compose_file\":\"services:\\n  zs-node:\\n ...\"}",
  "node_pubkey":     "age1... (§ 3c)",
  "operator_id":     42,
  "report_data":     "<base64 SHA-256(node_pubkey || be64(operator_id))>",
  "posture": {
    "plaintext_terminates": "named_upstream",
    "upstream_base_url":    "https://api.x.ai/v1",
    "zero_retention":       true
  },
  "generated_at":    "2026-04-29T12:34:56Z",
  "refresh_seconds": 3600
}
```

| Field | Type | Semantics |
|---|---|---|
| `mode` | string | Must equal `OperatorDetails.tee.mode`. A mismatch is an `advertisement_mismatch` failure at the verifier. |
| `cpu_report` | base64 string | TDX quote or SEV-SNP report. Empty in stub mode. The verifier derives the platform from **these bytes** (TDX v4 `tee_type == 0x81`), not from `mode`. |
| `gpu_eat` | string | NVIDIA Entity Attestation Token (EAT JWT). Empty in stub mode and on CPU-only modes (`dstack-tdx`). |
| `event_log` | string | The platform's runtime measurement log, as raw JSON. Present only on modes that have one (`dstack-tdx`). **Untrusted input whose only power is to be checkable**: the verifier replays it to recompute RTMR3 and compares the result with the RTMR3 the hardware signed inside `cpu_report`. A log that does not replay to the quote's value is worthless, which is what makes it safe to accept from the node. |
| `app_compose` | string | The dstack `app-compose.json` document verbatim, on `dstack-tdx` (since 9.6). The **preimage** of the `compose-hash` the replay recovers, never a second path to its value: `SHA-256(app_compose)` MUST equal that measurement exactly. Carried **byte-for-byte**. See "`app_compose`" below. |
| `posture` | object | Optional. Where plaintext terminates (field table below). Bound into `report_data` since 9.10 (`H_posture`); absent is committed as absent. Judged at verifier step 7. |
| `node_pubkey` | string | **The node's current signed `ephemeral_age_pubkey`** (§ 3c): the age recipient a sealing party actually seals request envelopes to, NOT the on-chain `signing_addr`. The verifier cross-checks it against the ephemeral it independently verified for this operator (`advertisement_mismatch` on disagreement), so the attested key is provably fresh and lifetime-capped. See "Why the ephemeral is bound" below. |
| `operator_id` | uint64 | The operator's on-chain id. Must equal the registry-resolved `op.ID`. |
| `report_data` | base64 string | The binding nonce in the CPU report's `report_data` / `REPORT_DATA` field: `SHA-256(utf8(node_pubkey) \|\| big_endian_uint64(operator_id))`, over the **ephemeral recipient**. The verifier recomputes it from the ephemeral it **independently verified** this cycle and the **chain-resolved** operator id, never from the bundle's self-report of either; a mismatch is `key_binding_mismatch`. This field is the lower half only. The upper half, the aux binding, is read from the quote. See "Why `report_data` omits `node_id`" below. |
| `generated_at` | RFC 3339 | When the bundle was minted. **Node-authored and covered by no signature**, so a verifier MUST treat it as a self-report: the window around it is absolute (a future date is as stale as an old one), an absent or unparseable value is stale rather than skipped, and the verifier imposes its own ceiling on top of the node's `2 × refresh_seconds` rule (`stale_evidence` failure tag). See "Evidence age" below. |
| `refresh_seconds` | uint | The node's configured `tee.attestation.refresh_interval` in whole seconds (default `1h` → `3600`), so the verifier can size its own re-verification loop. **Node-authored, so a verifier MUST NOT let it be the only bound on evidence age.** See "Evidence age" below. |
| `collateral` | object | Optional, `dstack-tdx` (since 9.7). The Intel-signed collateral set for this quote's platform: PCK CRL, root CA CRL, TCB info for the quote's FMSPC, and QE identity, each with its issuer chain. A **resilience fallback, not a preferred source** (rules below). |
| `upstream_attestation` | object | Optional, `attested_passthrough` only (since 9.8). Pointers and digests describing the enclave this node forwards plaintext **to**: `protocol`, `base_url`, `report_url`, `keyset_digest`, `verified_at`, `lease_expires_at`, `carve_outs`. It says **nothing about the node itself** (rules below). |
| `app_models` | array | Optional, since 9.9. The entries `H_app` is computed over: one per model the node advertises on `/v1/zs/details`, each `{model_id, source, weights_digest, weights_state}`. The bundle carries the entries rather than `H_app` so the verifier can recompute it and compare with `report_data[32:64]`. **Every key is present in every entry**, even when its value is empty; an entry with a missing key, a `null`, or a value of the wrong type is refused. Order is irrelevant: `H_app` sorts by `model_id` UTF-8 bytes. An absent or empty list claims the node serves no models. See "Model measurement" below. |
| `nonce` | string | Optional, since 9.9. The caller's `?nonce=` challenge, echoed as hex. Absent on the cached bundle. A verifier that sent a challenge MUST refuse the bundle if this field is absent or decodes to a different value (verifier step 6). |
| `stub` | bool | True only for the dev `stub` mode. Production proxies MUST reject `stub == true` unless explicitly opted in. |

**`app_compose`.** A verifier that reads a single field before checking the hash has misread the field. Substituting a friendlier document moves the digest and is caught, so nothing in it is trusted. Any re-encoding, including a re-marshal that only reorders keys, moves the digest and makes the bundle unverifiable.

**Why the ephemeral is bound.** Binding the identity key instead would prove only that the attested hardware controls the operator *identity*, leaving the hop to the *decryption* key operator-attested. Because the ephemeral rotates (~20 min), the node **re-mints evidence on rotation**. A node that has rotated but not yet re-minted fails closed, and returns to the verified set on the next probe.

**Challenging for freshness — `GET /v1/zs/attestation?nonce=<64 hex>`.** Optional, since 9.9. Rotation already limits a replayed bundle to one rotation period. A caller that wants proof the enclave is running now sends a nonce; the node mints a bundle whose aux binding hashes that nonce, and echoes it in `nonce`.

- The nonce MUST be exactly 64 hex characters (32 bytes); a node MUST refuse any other length with `400 invalid_nonce` and MUST NOT truncate or pad it. The aux binding hashes exactly 32 bytes, so no other length has a defined meaning.
- An all-zero nonce hashes the same as no nonce. A node MUST refuse one, and a verifier MUST NOT send one: a cached bundle with a `nonce` field of 64 zeros would otherwise pass as its answer. `VerifyAux` refuses an all-zero challenge (`ErrZeroChallenge` / `zero_challenge`).
- On any failure (malformed nonce, rate limit, a provider that cannot mint on demand) a node MUST return an error, never the cached bundle. Reference codes: `400 invalid_nonce`, `429 attestation_rate_limited`, `501 nonce_unsupported`, `503 attestation_unavailable`.
- A challenged mint MUST NOT replace the node's cached bundle. The cached bundle is what unchallenged callers receive; it must not carry a value a third party chose, and a challenge must not reset its age.
- Challenging is optional. A node MAY rate-limit challenges and MUST keep the unchallenged path available when it does. After a refused challenge, the caller decides whether to fall back to the unchallenged bundle, which is fresh only to within one rotation.

The reference proxy and client do not send challenges yet.

**Why `report_data` omits `node_id`.** Anything keyed to a serving endpoint normally keys by `(operator_id, node_id)`, so this looks like an oversight. It is not needed:

- Node identity is bound one layer up, in the `ephemeral_sig` canonical bytes (§ 3c), which the verifier checks against the **chain-resolved `node_id`** *before* computing this hash. "This key belongs to this node" is already established by the ground-truth value the recompute consumes; repeating it here would only re-assert it.
- `operator_id` is in the hash for what the advertisement cannot cover: a **cross-operator** lift, where a different owner replays this bundle and the recompute under *their* chain-resolved id no longer matches.
- **Residual in the lower half:** within one operator, a node can present a sibling's bundle (the operator can sign an advertisement naming the sibling's ephemeral as its own), so the verdict can land on the wrong node of that operator's fleet. That is not a confidentiality break. The payer seals to the sibling's recipient, whose private half exists only inside the sibling's CVM, so the presenting node cannot read the prompt; it can only fail, or forward to the node that holds the key.

  **Since 9.9 the upper half closes this.** The aux binding hashes `be64(node_id)` and the verifier supplies the chain-resolved id, so a sibling's bundle recomputes to a different value and is refused. The lower half still omits `node_id`, for the two reasons above.

**Evidence age.**

- `generated_at` is a self-report because it is not inside the quote, which carries no timestamp of its own.
- The self-report is tolerable because it is not the main freshness check. The key binding is: a bundle must attest a live ephemeral, so it cannot outlive one however it is dated.
- `refresh_seconds` is **not the re-mint cadence**. A node re-mints on every ephemeral rotation (~20 min), far more often, so this is an upper bound on how long evidence may go unrefreshed.
- A rule stated purely as "2 × `refresh_seconds`" is one the attested party sets for itself, with two one-field escapes: omitting the field (no cadence, so no check) and advertising a day (a two-day window). A verifier therefore applies its own absolute ceiling as a **minimum against** the advertised window. That ceiling can reject nothing honest: an accepted bundle must attest a live ephemeral, whose signed window is capped at `MaxEphemeralLifetime` + skew, so honest evidence is always far inside it.

Reference: `EvidenceMaxAgeCeiling` (`proxy/internal/hayai/attestation.go`) / `EVIDENCE_MAX_AGE_CEILING_MS` (`client/src/operators/tee-verify.ts`), both `2 × MaxEphemeralLifetime`.

**`collateral`: carried so a verifier can judge the quote while a PCCS is unreachable, and MUST NOT be preferred over one it can reach.** The field names and encodings mirror Intel's QVL collateral structure verbatim (`pck_crl_issuer_chain`, `root_ca_crl`, `pck_crl`, `tcb_info_issuer_chain`, `tcb_info`, `tcb_info_signature`, `qe_identity_issuer_chain`, `qe_identity`, `qe_identity_signature`). Binary members are hex, and `tcb_info` / `qe_identity` are the signed inner documents **byte-for-byte**: a re-marshal that only reorders keys invalidates Intel's signature, as for `app_compose`. Five rules:

1. **A verifier MUST fetch from a PCCS first and use this only when that fetch was UNREACHABLE**, never when a fetch succeeded and verification refused, which is an answer. Nothing here can be forged: every document is Intel-signed and MUST be re-validated against the verifier's own embedded Intel root CA. But a node chooses which validly signed *vintage* to send, and the only freshness bound a verifier can apply is each document's own validity window, up to ~30 days for TCB info. That is enough to hide a platform TCB downgraded to `OutOfDate` by a newer publication, or a PCK certificate revoked since the CRL it sent. Preferring node-served collateral would let the party under attestation supply the criteria it is judged by.
2. **The precedence is three-deep: the PCCS, then the verifier's OWN cache of it, then this.** A verifier that caches PCCS responses SHOULD serve a cached document past its refresh window when the PCCS is unreachable, and MUST try that before this field, bounded by its own staleness ceiling. The order follows from rule 1 and is not a preference: a cached document's vintage was *ours* to choose, so it is the better fallback. Two consequences are normative, because the natural implementation gets both wrong:
   - Reaching this field means the verifier's cache had no ANSWER: no entry, or one past its staleness ceiling. **A cached document that was consulted and REFUSED the quote MUST NOT fall through to this field.** That is a signed Intel "no", of a vintage the operator did not choose. Replacing it with one the operator did choose is the rollback rule 1 exists to prevent, and is strictly worse than the no-cache case, where the verifier holds no statement at all.
   - Such a refusal is still reported as `collateral_unreachable`, not as invalid evidence. Its two causes (the node's evidence really is bad, or our own document has been superseded since we fetched it) are indistinguishable from the verifier's position. Both tags fail closed, and guessing wrong in the other direction accuses the whole confidential fleet during one PCCS outage. A verifier's *diagnostic* surfaces MAY distinguish the two; its routing decision need not.
3. **A verifier that accepts it SHOULD apply a freshness floor tighter than Intel's `nextUpdate`**, to bound that rollback.
4. **A partial set MUST be treated as an absent set.** A missing member is a check that would not run, which is exactly what a node with something to hide would engineer. Fall back to fetching, or refuse; never verify with a hole in the set.
5. **Absent is routine and is not a failure.** A node that cannot reach a PCCS publishes its quote and event log without collateral rather than going dark, and a verifier treats that as the pre-9.7 state: fetch your own.

**`upstream_attestation`: the node's claim about the party it forwards TO, carried as pointers rather than as evidence.** Since 9.8, and only on `attested_passthrough`. Four rules:

1. **A verifier MUST NOT read it as saying anything about this node.** The node's own half is the quote, the replay and the compose gate above; this field adds a second, independent enclave to appraise and does not strengthen the first.
2. **`report_url` is the point of the field, not decoration.** The payer re-fetches it **with their own nonce**, which is a freshness guarantee no relayed recording can provide. `keyset_digest` is what that report's `report_data` commits to, so a payer's independent fetch is checkable against what the node claims it appraised. The node's own verdict is deliberately absent, for the same reason a measurement field would be: a verdict is the one thing a payer must not take from a party in the chain under appraisal.
3. **`carve_outs` is normative and MUST NOT be omitted when non-empty.** It names each policy rule the node's upstream appraisal *downgraded* rather than enforced, as `<rule>:<detail>` — today only `root_backdoor_env:<ENV_NAME>`. A verifier MUST read a non-empty list as **capping what a clean upstream appraisal means**: a declared dstack root-shell channel is measured by *name* and not by *value*, so nobody can tell whether it was used, and RTMR3 records boot rather than runtime, so a shell changes what runs while every other check keeps passing. An **absent** list means the node enforced every rule its policy carries; it does **not** mean the policy was strict.
4. **An unrecognized `protocol` makes the block unverifiable, not ignorable.** A verifier that does not implement it MUST treat the upstream half as unestablished rather than skip it and accept the rest — the node is advertising a verification the verifier cannot reproduce.

What this block does **not** let a payer confirm is the per-request half. The upstream's protocol may bind each request's receipt to the credential that made it (ACI/1 § 7.6 does), in which case the receipts naming where each individual prompt went are retrievable by the node alone. The appraisal is independently reproducible; the per-request check is asserted.

**No `compose_hash` or `os_image_hash` field exists, by design.** Both are recoverable by replaying `event_log`. Carrying them separately would invite a verifier to read the self-report instead of replaying: the cheap wrong verifier, indistinguishable from the correct one on every honest node.

**`app_compose` is not an exception to that rule.** A measurement *field* would be a value a verifier could substitute for the replay. The preimage is bytes a verifier can use only by hashing them and comparing with the replay's own answer. A verifier that skips the hash check is not reading a self-reported measurement; it is reading an operator-authored document with no measurement attached, which nothing in the bundle would let it mistake for evidence. Carrying it makes an allowlist possible at fleet scale. `compose-hash` covers the operator's own configuration, so it differs per operator and per redeploy and no relying party can enumerate it, whereas the document's *content* narrows to a per-release list.

The `posture` object:

| Field | Type | Semantics |
|---|---|---|
| `plaintext_terminates` | string | `"in_enclave"` or `"named_upstream"`. An unrecognized value is treated as unknown, **never as the stronger of the two**. |
| `upstream_base_url` | string | The single API plaintext is forwarded to, when `plaintext_terminates == "named_upstream"`; absent otherwise. Naming it is the point of the weaker posture: "readable by exactly one party" is a claim about a party the payer can identify, so a posture that declines to name one is not making the claim. |
| `zero_retention` | bool | The measured image refuses to serve a response the named upstream did not confirm zero-retention on. A statement about what the software enforces, not about the upstream's terms of service. |
| `upstream_attested` | bool | Since 9.10. The node is configured to appraise the named upstream's own enclave (`tee.upstream_attestation`), and publishes that appraisal as the bundle's `upstream_attestation` block while it holds. Bound, unlike the block; see "Posture measurement". |

**`plaintext_terminates` describes the INFERENCE path** — where the node sends the prompt in order to produce an answer. It is not a claim that no byte derived from the prompt can leave under any circumstance, because one class of egress is not the node's to decide: **built-in tools (§ 3d) are caller-initiated**. A `zs_web_search`, `zs_web_read` or `zs_image_search` call exists for a request only because the caller listed that type in the request body's `tools[]`. So a node MAY advertise `in_enclave` (or `named_upstream`) and also advertise the egress built-ins in `builtin_tools[]` on `/v1/zs/details`. A verifier MUST NOT treat the two as contradictory, and MUST NOT demote on the pair.

What makes that sound is the pairing of two things, and **neither is sufficient alone**. The caller's own request fixes what was *asked for*: omit those types and the omission is committed to by the admission tag over `sha256(body)` (§ 4), so no relay can add one. The **measurement** fixes what the node *does with that*: an allowlisted image is one known to dispatch a built-in only on a caller-listed type. Read the sealed bytes alone and you have a statement about the caller, not about the node — the same gap that left a pre-9.10 `posture` "a claim signed by nobody", and the reason a payer routing on this must be routing on an allowlisted measurement in the first place. Given both, a caller that omits the types has the posture's claim unqualified; a caller that includes one is choosing that egress for that request. `builtin_tools[]` is the disclosure surface and `tools[]` is the control.

Two limits on reading that as consent. The advertisement is **type-only**, so a payer learns *that* a tool egresses, never to where; and on an aggregating relying party such as the reference proxy, `builtin_tools[]` is a **deduplicated union across operators**, so it does not say which operator serves which tool. A client that presents the tools as a user-facing choice is therefore making a claim this field does not carry on its own.

This does **not** extend to routes the node picks. An image backend is one the operator points somewhere: a caller asking for an image cannot see or choose where it goes, and a dedicated image model reaches it with no tool involved. So the image route is held to the posture itself — in-enclave under `in_enclave`, or, under `named_upstream`, an upstream whose zero-retention the node confirms per response — and the reference node refuses to start otherwise.

### Verifier responsibilities

A relying party (the proxy) verifies in this order. Each check has a canonical failure tag, stamped on the operator's status for telemetry. Reference: `proxy/internal/hayai/attestation.go::BundleVerifier.Verify`.

**Decoding the bundle.** Two verifiers given the same body MUST read the same values from it:

- A verifier MUST refuse a body that is not valid UTF-8 rather than decode it. Decoders replace invalid bytes with U+FFFD and disagree on how many, so a model id with bad bytes would hash differently in each. The refusal fails closed; the reference proxy tags it `fetch_failed`.
- A verifier MUST match keys exactly, at the top level and inside `posture`, `collateral` and `upstream_attestation`, and ignore any other key. Go's default decoder matches keys case-insensitively with Unicode folding, and JavaScript does not.
- When a key repeats, the last occurrence wins, as in both reference decoders.
- An escaped unpaired surrogate (`"\ud800"`) is valid JSON and is not refused. It hashes as U+FFFD (`EF BF BD`).
- A `nonce` that is neither a string nor `null`, or an `app_models` that is neither an array nor `null`, is refused in step 6 with that step's tag, not as an undecodable body.

0. **Defensive `key_binding_mismatch`.** If there is no verified ephemeral recipient for this operator this cycle (never advertised, expired, or a bad `ephemeral_sig`), fail closed before consulting any bundle field, rather than falling through to a binding hash over an empty key. Such an operator is unsealable anyway.
1. **`advertisement_mismatch`**: `bundle.mode == advertised.mode`, `bundle.operator_id == op.ID`, and `bundle.node_pubkey ==` the **independently verified `ephemeral_age_pubkey`** (§ 3c: signature-checked under the chain-resolved `signing_addr`, bound to `(operator_id, node_id)`, lifetime-capped). The verifier's own ephemeral verification is the ground truth; the bundle's self-report is cross-checked, never trusted on its own. A node that has rotated but not yet re-minted lands here and recovers on the next probe.
2. **`stale_evidence`**: `|now − bundle.generated_at| ≤ min(2 × bundle.refresh_seconds, ceiling)`, where `ceiling` is the verifier's own absolute bound (reference: `2 × MaxEphemeralLifetime`). The node's own staleness gate already returns 503 before the verifier sees a stale bundle, but a hostile node can lie, so this is cheap belt-and-braces. Three properties:
   - **The window is ABSOLUTE, not one-sided.** `time.Since(...) > maxAge` is negative for a future instant and never exceeds the bound, so a node that mints once and stamps 2126 would stay fresh forever while advertising a compliant cadence. A well-formed future date is a strictly better bypass than an old one, because it survives any later timestamp-validity hardening.
   - **The advertised window alone is not a bound**, since omitting `refresh_seconds` would otherwise skip the check.
   - **The ceiling is a minimum against the advertised window, never merely a default for its absence** ("Evidence age" above). The obvious fix gets this wrong: capping only the absent case leaves "advertise 86400" wide open.

   **An absent, unusable or non-positive `generated_at` MUST fail closed, but the tag is implementation-dependent and not a conformance point.** A verifier that decodes the bundle into a typed timestamp rejects a malformed RFC 3339 value at parse time (the reference proxy answers `fetch_failed` and never reaches this step), while one that parses leniently reaches it and answers `stale_evidence`. Both refuse; do not assert the tag for that case.
3. **`key_binding_mismatch`**: `bundle.report_data == base64(SHA-256(ephemeral_age_pubkey || be64(op.ID)))`, computed from the *independently verified* ephemeral recipient, NOT from `bundle.node_pubkey` (only a self-report), so a hostile operator cannot pair a real attestation report with a substituted key.
   This step compares the bundle's self-reported lower half. The quote's own `report_data`, both halves, is checked in step 6.
4. **`stub_not_allowed`**: when `bundle.stub == true`, the proxy's `allow_stub` knob must be set. CPU/GPU evidence is empty by construction in stub mode, so chain verification is impossible.
5. **Real evidence.** **This step carries the key-binding guarantee.** The hardware signs `report_data` *blindly*: the quote says "software with measurement M asked me to sign these bytes", never "these bytes are a key I generated". Only checking M against a known-good reference shows that the software presenting the ephemeral mints it in-CVM and never exports it. Without step 5, steps 0–3 prove only that the sealed-to key is one that *some* software in *some* TEE presented, not that its private half never left the enclave.

   The platform is derived from the **report bytes** (TDX v4 `tee_type == 0x81`), never from `mode`. Selecting the vendor chain by a node-authored string would let the operator choose which chain its evidence is judged against.

   - `nvidia-cc-tdx` / `nvidia-cc-snp`: verify the TDX/SEV-SNP report against Intel's PCK / AMD's VCEK chain, verify the NVIDIA EAT against NRAS (or `nvtrust` for offline deployments), and confirm the report measurements match a published ZeroSignal node CVM image. Failure tags: `vendor_chain_invalid`, `nras_unreachable`. *(Reference implementations still ship a placeholder returning `verifier_not_implemented`.)*
   - `dstack-tdx`: verify the quote against Intel's PCK chain (`vendor_chain_invalid`), then run the replay in "Measurement replay" below. No NRAS call is made and none is configured.

   **A verifier that could not reach the vendor's collateral service MUST NOT report the operator's evidence as invalid.** `collateral_unreachable` (the `nras_unreachable` twin) is a separate tag because the two are opposite claims: one is the relying party's own outage, the other says this node's evidence is forged. Both fail closed, but folding them together stamps "invalid evidence" on every operator in the fleet during one upstream outage, which is indistinguishable from an attack to whoever reads it.

   **Since 9.7**, an unreachable collateral service is not always the end of the check: the verifier walks its own cache and then the node's carried `collateral` set, under that field's precedence rules above. This tag is what remains when every rung comes up empty. A fetch that *ran and refused* is an answer and never reaches here. A refusal reached on the verifier's own **cached** collateral does land here, on purpose, because a verdict taken partly on our aging document cannot be attributed to the operator (rule 2).

6. **`report_data`, both halves**, read from the quote. The field is 64 bytes and the quote signature covers all of it, so an unchecked half would let a node get 32 bytes of its choice signed by real hardware.

   Check in this order:

   1. `[0:32]` MUST equal the recomputed `SHA-256(ephemeral || be64(operator_id))`. Failure tag: `key_binding_mismatch`. A quote too short to hold `report_data` also fails here.
   2. `[32:64]` MUST NOT be all zero. Failure tag: `aux_binding_absent`, meaning the node predates 9.9 and needs upgrading. There is no version switch that accepts a zero upper half.
   3. **The nonce.** If the verifier sent a challenge, it MUST NOT be all zero, the bundle's `nonce` MUST decode to it (otherwise `aux_binding_mismatch`), and the challenge is the nonce. If it sent none, the nonce is the bundle's `nonce` decoded, or 32 zero bytes when the field is absent; a present value that is not 64 hex characters is `aux_binding_mismatch`. A bundle minted for another caller's challenge therefore verifies for a verifier that sent none. Such a bundle gives that verifier no freshness guarantee; a verifier that needs one sends its own challenge.
   4. `H_app` over the bundle's `app_models` ("Model measurement" below). If `H_app` refuses the entries, the failure tag is `happ_preimage_invalid`.
   5. `H_posture` over the bundle's `posture` ("Posture measurement" below). If `H_posture` refuses it, the failure tag is `posture_preimage_invalid`.
   6. `[32:64]` MUST equal `SHA-256("zs-aux-v2\0" || be64(node_id) || H_app || H_posture || nonce)`, where `node_id` is **chain-resolved, never read from the bundle**. On a mismatch, the failure tag is `happ_preimage_missing` if `app_models` is absent or empty, else `aux_binding_mismatch`. The digest cannot say which input differs, so `aux_binding_mismatch` covers a changed catalog, posture, node id or nonce, and `happ_preimage_missing` covers a withheld catalog as well as a node-id, posture or nonce mismatch on an empty one.

   Steps 3–6 are one shared function per language (`attest.ReportDataHalves.VerifyAux` / `verifyAux`, tags via `AuxFailureTag` / `auxFailureTag`), pinned against each other by the `aux_verify` vectors. Verifiers call it rather than reimplementing it.

   **Why this is a minor bump.** Before 9.9, `[32:64]` had to be zero; now zero is refused. `ProtoVersionCompatible` compares majors, so 9.8 and 9.9 remain compatible for everything else, and a major bump would drop every non-TEE node from routing over a rule only dstack-tdx nodes use. The cost is on dstack-tdx only: a 9.9 verifier refuses a 9.8 node with `aux_binding_absent`, and a 9.8 verifier refuses a 9.9 node with `key_binding_mismatch`, because its rule requires a zero upper half. The second tag is fixed in deployed 9.8 code and cannot be improved. 9.10 repeats that choice for the same reason. The aux tag moved to `zs-aux-v2`, so 9.9 and 9.10 refuse each other's dstack-tdx nodes with `aux_binding_mismatch`, and nothing else is affected.
7. **Posture.** Judge the `posture` value step 6 hashed, never a copy read from elsewhere. Refuse (`advertisement_mismatch`) an incoherent block: an `in_enclave` posture that names an upstream, a `named_upstream` posture that names none, or an unrecognized `plaintext_terminates`, which is never read as the stronger value. A `named_upstream` posture MUST also pass `NamedUpstreamAdmissible` (Go `inject`, TypeScript `namedUpstreamAdmissible`, pinned by `testdata/dialect_vectors.json`), or the failure tag is `posture_upstream_unverifiable`. It requires all of:
   - `upstream_base_url` is `https`, carries no userinfo, and names a plain LDH host. The URL carries no ASCII control byte and no `%` that is not followed by two hex digits, anywhere. Go's `url.Parse` and WHATWG `URL` disagree outside that subset, so both refuse everything outside it.
   - Either the host is xAI (`x.ai` or a subdomain of it, matched on a label boundary, never by substring, ASCII only) and `zero_retention` is set, or the posture's bound `upstream_attested` is set **and** the bundle carries an `upstream_attestation` object whose `protocol` is `aci/1` (`UpstreamAttested` / `upstreamAttested`, pinned by the same vectors). A block with any other protocol, or a value that is not an object, does not count.

   The two inputs on the second branch do different jobs. The bound bit says the measured binary was configured to appraise its upstream, so a relay that adds a block to any other node gains nothing. The unsigned block says the appraisal currently holds: the node omits it while its lease on the upstream is lapsed or revoked, when it also refuses requests. This check does not verify the block's contents; a payer who wants that fetches its `report_url` with a nonce of their own.

   Every input the decision rests on is bound, so this check repeats the node's own boot validation, and a bug in either one alone does not admit a lookalike upstream: an operator's own server, named so that a substring match would read it as `api.x.ai`, and answering with the zero-retention header itself.

   Coherence also refuses (`advertisement_mismatch`) an `in_enclave` posture with `upstream_attested` set.

   **`builtin_tools[]` is not an input to this step, and MUST NOT be cross-checked against `posture`.** A node advertising `in_enclave` alongside the egress built-ins is well-formed (the `posture` note above). A verifier that infers "in_enclave ⟹ this node serves no egress tool" is reading a property of one release's *validation rules* as if it were a property of the posture, and will de-route honest nodes.

A failed verdict does not mark the operator unreachable: non-TEE traffic still routes to it, and only `Require-TEE` requests filter it out. The verdict is cached on the operator's struct for the next refresh cycle.

**`Require-TEE` constrains routing, not the caller's own `tools[]`.** It picks which nodes may serve the request; it does not strip, reject, or warn about an egress tool the same request carries. A caller that wants the posture's claim unqualified omits those tools itself — the two controls are independent and a client that wires only the first has not delivered the second.

### Measurement replay (`dstack-tdx`)

dstack extends RTMR3 with a runtime event log instead of publishing the measurements directly, so recovering them is a computation, not a read:

```
acc = 0x00 * 48
for each event in event_log where event_type == 0x08000001:
    payload = hex_decode(event.event_payload)
    digest  = SHA-384( le32(event_type) || ":" || event.event || ":" || payload )
    acc     = SHA-384( acc || digest )
```

`acc` MUST equal RTMR3 from the verified quote, else `measurement_mismatch`. Then `compose-hash` and `os-image-hash` are read off the **replayed** events. Both MUST be checked against a known-good reference, but **the two references have different shapes, and a single allowlist for both does not scale**:

- **`os-image-hash` names Phala's guest image**, so its value is the same for every operator on a given dstack release, and the reference is a short enumerable list shipped preset in both the proxy and the browser client. It is required in production, not optional hardening: without it a node can present a valid quote taken on a **development** OS image, whose hardening guarantees do not hold, while every other check passes identically. **An empty list verifies nothing**: no `os-image-hash` is a member of it, so every bundle fails. It never means "accept anything". Read as a skip, it would remove the one check that catches a quote taken on a `dstack-dev-*` image, which `phala deploy` selects on its own when `--image` is omitted.
- **`compose-hash` covers the operator's own configuration**, so it differs per operator *and per redeploy*, and no relying party can enumerate it. It is checked by **validating its preimage**: hash `app_compose`, require the digest to equal this measurement, and only then read the document's content against per-release rules. What stays enumerable is a per-**release** list. A verifier MAY also accept a `compose-hash` listed in a hand-configured allowlist, as an escape hatch for a deployment blessed out of band.

  **The `docker_compose_file` rule is a whole-file TEMPLATE MATCH, not a deny-list, and that difference is the design.** A verifier lifts out the three spans an operator may legitimately vary, replaces each with a fixed placeholder, and hashes the remaining text (comments included) against a list of published release *skeletons*. The three spans are:

  - the **first** `image:` reference, checked separately against a list of published release images, because images and skeletons move on different cadences;
  - the `NODE_CONFIG_YAML:` block scalar body;
  - the `content:` block scalar of a top-level `configs:` entry named exactly `zs-engine-config`.

  The third span carries the inference engine's own configuration on the `sealed_local` shape, so an operator can size the runtime for its hardware without a published release per hardware profile. Three properties bound it:

  - It is armed only by the **exact two-line shape**: the sentinel line, then a `content:` block scalar indented deeper. `content` is the compose spec's fixed key and far too generic to lift on sight, so any other `content:` is hashed as ordinary text.
  - The **wiring** around it (the entry name, the mount target, the environment variable pointing at it) stays inside the skeleton, so the engine cannot be redirected at a file the measurement does not cover.
  - Its body is subject to a **content rule**: a span declaring `adapters` (LoRA) or `template` (the chat template) is an `engine_config_key` violation. Both change what the model produces while the weights digest keeps reporting a byte-perfect match against the source repository, and the weights chain reports loaded artifacts, which an adapter is not.

  The content rule reads **the spans the skeleton lifted**, never a second walk of the document. It is evaluated **whether or not release matching is enforced**, since it is a statement about the document's own content and must bind a node pinned by whole-document hash too. A document the walk refuses is a violation, not an absence, whenever it mentions the sentinel at all. The key test is a case-insensitive substring match over the span, not a YAML key-position analysis: enumerating the positions a mapping key may occupy means enumerating YAML, and `adapters : [x]`, `- adapters: [x]`, `[adapters: [x]]` and `"\x61dapters":` are all valid spellings such an analysis misses. Nothing enumerates what is forbidden. A host bind mount, `privileged: true`, an added port and a `command:` override are all text the published compose does not contain, so they are refused by construction.

  **A SECOND service is admitted, only under two conditions that together make it a pin rather than an exception.** The `sealed_local` rung runs its inference engine as a sidecar in the same measured document, so such a compose carries two `image:` lines. A verifier MUST lift only the first, and MUST refuse any later `image:` not pinned as `<repository>@sha256:<64 lowercase hex>`. Both conditions matter:

  - Leaving the engine reference literal, instead of lifting it into a second checked span, puts the release's own engine digest inside the structure an operator may not vary. It also avoids checking two references against one flat image list, where a released *engine* would pass as a released *node*.
  - Requiring a digest pin stops that literal from being `${VAR}`. `docker_compose_file` is hashed **before** environment substitution, so an unpinned sidecar would publish one skeleton digest covering every engine the operator later supplies, to the process that sees plaintext prompts. A verifier MUST refuse `${` anywhere in the reference, the repository half included. That half is refused for conformance to the shape above, not for the substitution argument, since `${REPO}@sha256:<hex>` still content-addresses the bytes.

  Which service is "first" needs no parser and no service-name convention: reordering changes the skeleton *and* hands the release-image check the engine's reference, so a reordered document matches nothing. That is a property of the DOCUMENT, not a guarantee about release authoring. It holds as long as every published multi-image skeleton lists the node first, which nothing here can enforce. A release that listed an engine first would have to put that engine's reference on the node-image list, and from then on a released engine could fill some other release's node-image hole. Publishers MUST therefore keep the node's `image:` first.

  **Why not a deny-list** (no bind mounts, no `privileged`, ports ⊆ `{9090}`)? Enumerating hazards over a YAML document needs a YAML parser in each implementation language, and two parsers disagreeing about anchors, merge keys or duplicate keys is not a crash: it is two verifiers silently reaching opposite verdicts on identical evidence. The template match is a line-oriented walk with no parser and one golden-vectored answer. Its cost is real rigidity: the compose becomes a published artifact with the operator's configuration written into it, not a file the operator composes, and reformatting it is indistinguishable from tampering.

An absent or empty `app_compose` **MUST NOT be reported as a compose check that passed**. An empty document still hashes to a well-formed digest, and "the node did not send the preimage" is exactly the state a node with something to hide would engineer. It is not automatically a rejection: a verifier MAY still accept such a node through the hand-configured allowlist above, but never as content-validated. A node that CANNOT send one (its guest agent does not publish the document, or its event log carries no `compose-hash` to anchor it to) is expected to publish its quote and event log without it rather than go dark.

**Implementation status.** Shipping `app_compose` does not by itself get a node verified. The table separates two things that are easy to conflate: whether a rule is IMPLEMENTED, and whether the reference data it needs is populated so that it RUNS:

| | implemented | in force by default |
|---|---|---|
| Node mints the preimage and self-verifies it against its own replay | **yes** | yes |
| `VerifyComposeHash` — the digest gate that makes the document safe to read | **yes**, one per language | yes, on every verifier that reads a preimage |
| `VerifyAppCompose` — manifest version, runner, `allowed_envs`, root-backdoor names, pre-launch digest, platform toggles, `features`, `storage_fs` | **yes** | **yes** — both the proxy and the browser client call it |
| Preset production OS-image list, proxy and browser client | **yes** | yes |
| `docker_compose_file` template match — release skeleton + published image | **yes** | **yes.** Both consumers ship `EnforceComposeSkeleton` on with the published `zs-node` release lists populated — the proxy in its config defaults, the browser client as a bundled constant |

With the skeleton rule in force, a passing verdict means what the field is named for, and the browser client reports `measurementChecks.compose` accordingly. Without it, a compose could measure nothing at all (`image: ${SOME_VAR}` yields a stable `compose_hash` over arbitrary code), and a clean `VerifyAppCompose` would mean only "nothing structurally disqualifying, workload unchecked". Implementations MUST honor two consequences:

- **`trusted_compose_hashes` (or its equivalent) narrows; it MUST NOT substitute.** A verifier offering a whole-document pin applies it *in addition to* the release match. Treating a pinned digest as sufficient would make "ask the operator to bless my hash" a documented route around the release identity.
- **An absent preimage MUST be refused, not skipped, wherever the release match is enforced.** Skipping was only ever safe when a whole-document pin was the gate. With the release match as the gate there is nothing behind it, so a node that declines to publish would evade every content rule, which is strictly easier than the document substitution `VerifyComposeHash` exists to catch. A verifier that does *not* enforce the release match MAY still skip, so a guest agent predating the preimage is not read as compromised.

**An empty skeleton or image list with enforcement ON refuses everything**, the fail-closed direction, matching the OS-image list. Enforcement is an explicit flag, not derived from list length, because "empty means no constraint" makes a check vanish while looking like the feature working. The converse is also a defect: a verifier carrying populated lists with the flag off performs no check while appearing configured, so implementations MUST surface that as a violation against the *verifier*, not treat it as a lenient policy.

Three properties matter, and each can look covered while being vacuous:

- **The per-event digest is COMPUTED, never read.** dstack leaves the log's own `digest` field empty on every runtime event. An implementation that reads it extends with nothing, produces a well-formed 48-byte value, and reports a mismatch that will be believed.
- **Filter on `event_type`, not on `imr`.** They do not select the same set.
- **A replay that extended zero events, an all-zero RTMR3 in the quote, and any undecodable payload each FAIL rather than compare.** Otherwise each compares two values that agree for the wrong reason.

The arithmetic above and the `report_data` binding hash are **one implementation per language, in the protocol module**: `proto/go/attest` and `proto/ts/src/attest`, pinned against each other by `proto/testdata/attest_vectors.json` over a real CVM capture. Three parties run it for different reasons. The node replays its own log at mint time so that it never publishes evidence no verifier could accept; the proxy replays it to decide whether to route; and a browser client replays it to decide the same without trusting the proxy. A divergent copy never fails loudly, since every wrong implementation still produces a well-formed 48 or 32 bytes. The failure mode is a node that passes its own check and is silently dropped by every relying party, with `measurement_mismatch` or `key_binding_mismatch` reported against perfectly valid evidence.

### Model measurement — `H_app` (since 9.9)

`H_app` commits to the model catalog the node advertises on `/v1/zs/details`, with each entry's weights digest and what that digest is based on. It enters the upper half of `report_data`, so the CPU signs it alongside the key binding. A node MUST compute `H_app` and `app_models` from the same snapshot of its catalog.

```
H_app = SHA-256( "zs-happ-v1\0" || be32(n) || entry[0] || … || entry[n-1] )
entry = lenStr(model_id) || lenStr(source) || lenStr(weights_digest) || u8(weights_state)
aux   = SHA-256( "zs-aux-v2\0" || be64(node_id) || H_app || H_posture || nonce )
```

`H_posture` is defined under "Posture measurement" below; the `v2` tag dates from its addition in 9.10.

`lenStr` is a big-endian `uint32` **byte** length followed by the UTF-8 bytes; every field is length-prefixed and an empty one still occupies its four length bytes. Entries sort by `model_id`'s **UTF-8 bytes** (not UTF-16 code units, which order differently above the BMP) before hashing, inside the implementation rather than as a caller duty. `nonce` is 32 bytes, all zero when absent. Both domain tags end in a NUL so no tag can be a prefix of another.

`weights_state` is a JSON number: `1` measured (code in the node hashed the files, or a runtime reported them), `2` declared (the operator pinned the digest in config), `3` unverifiable (no digest; normal for hosted passthrough). Measured and declared digests are the same kind of string, so without this field a verifier could not tell them apart. `0` is not a state, so a missing or defaulted value never reads as measured.

Refusals, all fail-closed. Check 1 runs over the whole list first; checks 2–4 then run per entry in sorted order:

1. **Malformed entry.** Each entry MUST be a JSON object with all four keys, the three strings as strings and `weights_state` as an integer. A missing key, a `null`, or a wrong type is refused. Implementations MUST NOT default a missing field: Go's decoder and `JSON.parse` default differently, and the two would hash different preimages for one bundle.
2. **Empty `model_id`:** nothing can match it to a request.
3. **Duplicate `model_id`**, compared as UTF-8 bytes: a minter and a verifier that kept different entries would compute different digests. (Go's JSON decoder turns an unpaired UTF-16 surrogate into U+FFFD; a TypeScript verifier compares encoded bytes so it sees the same duplicates.)
4. **State and digest disagree:** `measured` or `declared` with no digest, or `unverifiable` with one. An unknown state, including `0`, is also refused.

A string that is not valid UTF-8 is also malformed. A verifier never decodes one: it refuses raw invalid bytes, and an escaped unpaired surrogate decodes to U+FFFD. The rule binds a node building entries in memory. The sort MUST be stable so two entries with one id are checked in their input order. The `h_app` and `h_app_json` vectors pin the error code each refusal produces.

The digest format (`sha256:<hex>`) is not validated: an attacker would send a well-formed digest of the wrong bytes, so checking the shape catches nothing, and it would make a new digest scheme a breaking change.

An **empty entry list is valid**. A node publishes it until its catalog is available to the minter, and a node that serves nothing publishes it indefinitely. Its `H_app` is not 32 zero bytes, so the aux binding over it is not zero, and a booting node is not mistaken for a pre-9.9 one.

**The list is the catalog at mint time.** A node re-mints when its advertised catalog changes, but between the change and the mint `/v1/zs/details` and `app_models` differ. The reference verifiers therefore report the attested list but do not route on it.

### Posture measurement — `H_posture` (since 9.10)

```
H_posture = SHA-256( "zs-posture-v1\0" || u8(0) )                                  posture absent
H_posture = SHA-256( "zs-posture-v1\0" || u8(1) || lenStr(plaintext_terminates)
                     || lenStr(upstream_base_url) || u8(zero_retention)
                     || u8(upstream_attested) )                                     posture present
```

`upstream_attested` is true when the node is configured to appraise its upstream's enclave (`tee.upstream_attestation`). It is derived from configuration, not from the appraisal's current verdict, so a node does not re-mint when its lease on the upstream changes; the bundle's unsigned `upstream_attestation` block carries that state instead. The bit exists because the block is unsigned: step 7 requires both, so a relay that adds a block to a node which never signed the bit gains nothing.

The node hashes the `TEEPosture` it publishes, built from its effective configuration. The verifier hashes the bundle's `posture` as decoded. A JSON `null` posture is absent, and inside the object a `null` or missing field is its zero value (`""` or `false`), which is how Go's decoder leaves it. Unknown keys are ignored and do not enter the preimage. Present-but-empty (`{}`) is not absent, because the presence byte differs.

Every `posture` field is in the preimage. Adding one requires a new `zs-posture` tag. The Go suite fails if a field is added to `TEEPosture` without that change. Refusals: a posture that is not an object or null, or a field that is neither null nor of its type, in both languages (Go's bundle decoder marks such a posture rather than failing the bundle, so the verdict names it); and in Go, a string that is not valid UTF-8, so the node refuses to mint rather than publish a digest no verifier reproduces. Every refusal is `posture_preimage_invalid`. Keys other than the four are ignored, and keys match exactly. The `h_posture` vectors pin the digest, and the `aux_verify` vectors pin the verdict when a posture is rewritten, stripped, or added.

### Routing: opt-in by request

Two surfaces, both small:

- **Header `X-Zs-Require-TEE: nvidia-cc`** at proxy entry: a transport-time signal that does not traverse the sealed envelope. Any non-empty value triggers the filter.
- **Proxy config `zs.tee.require_for_models: [list]`** for blanket policies on sensitive models.

When either fires, candidate selection (§ 3f "Path selection") drops every operator without a current passing verdict. If none survives, the proxy returns `503 no_tee_capacity` (§ 10). That is distinct from `no_operator` and `operators_busy`, so a client can retry on a different cadence: TEE recovery usually means a node refreshing its evidence, not new capacity being provisioned. Reference: `pickCandidates`, `op.IsTEEAttested()`.

Silent fallback to a non-attested operator is **forbidden by the spec**: the feature exists to refuse to seal plaintext to hardware that hasn't been verified.

### Why attestation is not bound into per-request AAD

The simplest design would bind a digest of the verified evidence into the envelope's AAD (§ 6), so each request individually authenticates the routing decision. This v1 spec does *not* do that, by choice, for three reasons:

1. **Evidence is large and slow to mint.** A TDX quote + EAT JWT is several KB, and minting it costs a guest-agent round trip plus a collateral fetch, orders of magnitude more than a request may spend. Per-request binding would force either per-request fetches, which breaks the latency budget, or a proxy-side evidence cache relying on cache-time ordering anyway, at which point the binding adds no real-time check.
2. **The wire format is already committed.** Adding fields to AAD is a wire-breaking change between proxy and node. v1 keeps the envelope frozen and treats attestation as a routing-time decision, which matches how relying parties use it: filter once at refresh, route many.
3. **The same-origin guarantee comes directly from the key-binding check.** The evidence binds the node's **current ephemeral recipient**, the exact key the sealing party encrypts to, so "attested hardware" and "sealing key" are one hop, not a chain.
   - Because that key rotates (~20 min, § 3c), the node re-mints evidence on rotation, **which is not what `refresh_seconds` reports**. That field carries the configured refresh interval (default 1h), so the re-mint cadence is the faster of the two and the advertised number is only an upper bound. **The key binding, not `refresh_seconds`, bounds evidence age**, because evidence cannot outlive the key it attests.
   - A verifier reads `/v1/zs/details` and `/v1/zs/attestation` in the same refresh pass, so it compares the bundle against the ephemeral it just verified. The brief window in which a node has rotated but not yet re-minted fails closed (the operator drops out of `Require-TEE` routing) and clears on the next probe.
   - Binding the on-chain `signing_addr` instead would leave the signing-key → ephemeral hop operator-attested. An operator holding the signing key outside the CVM could sign an advertisement for a recipient whose private half lived on the plain host, and every check would still pass.

The cost is that a request issued *before* the verifier's next refresh runs against the verdict from the *previous* refresh. **The RELYING PARTY's own polling interval bounds that window, not the node's evidence cadence.** The reference proxy re-probes every operator on `hayai.refresh_interval` (5 min by default) and recomputes the verdict from scratch each pass. A deployment that needs tighter freshness lowers that interval. Lowering `tee.attestation.refresh_interval` on the node changes how often evidence is re-minted, a different knob that, given re-mint-on-rotation, is usually already the faster of the two.

### Reference implementation

- `proto/go/inject/tee.go::TEEAdvertisement` / `TEEEvidenceBundle` / `TEEPosture` — canonical wire shapes; both proxy and node import them.
- `node/internal/tee/` — node-side Provider interface, StubProvider, and Refresher; mints + caches + persists the evidence bundle.
- `node/internal/tee/dstack.go::DstackProvider` — the `dstack-tdx` provider: guest-agent `POST /GetQuote` over the unix socket, plus the runtime event log the verifier replays.
- `node/internal/server/attestation.go::handleAttestation` — node-side `GET /v1/zs/attestation` handler.
- `proto/go/attest` + `proto/ts/src/attest` — the shared measurement arithmetic: TDX quote field access, the RTMR3 replay above, and `ReportData`. Golden-vectored against each other; see the note under "Measurement replay".
- `proxy/internal/hayai/attestation.go` — proxy-side `AttestationClient`, `TEEVerifier` interface, and `BundleVerifier`, which checks what no platform is trusted to check for itself (advertisement cross-check, ephemeral key binding, freshness, stub gating) and then dispatches on `mode`. Failure tags (`FailureKeyBindingMismatch`, `FailureStubNotAllowed`, …) match the `code` values § 10 uses.
- `proxy/internal/hayai/fetcher.go::probeAttestation` — per-operator attestation probe + verify pass run after the existing details probe.
- `proxy/internal/server/hayai_dispatch.go::pickCandidates` — TEE-required filter; `pickResult.TEEBlocked` propagates to `dispatchHayai`'s `503 no_tee_capacity`.
- See [`TEE.md`](./TEE.md) for the threat model, encryption layers, and trust shift.

## 3f. Transport privacy (single-hop operator-as-relay)

> Transport privacy defaults **on** at the proxy and the client: the forwarding
> route and the selection primitive are part of every node, so honest clients
> route through a relay by default.

The wire envelope (§ 4–6) gives end-to-end confidentiality and integrity, but
not network-level unlinkability: a node sees the client's IP on every request,
reserve and discovery probe. Single-hop relaying closes that gap. A client
sends its unchanged, target-sealed request to **another operator**, which
forwards the opaque bytes to the target and streams the response back. The
target sees the relay's IP, never the client's.

**Every node is a relay.** Forwarding is part of the node binary, not an opt-in
capability: there is no `relays` flag and no on-chain relay record. A node
advertises its generation via `proto_version` (§ 3c), and the major-equality
filter drops any incompatible-generation node from a relay-using client's
candidate set.

### The relay route

`POST /v1/zs/relay`, exposed by every node. The relay is a **byte-transparent
forwarder**: it does not decrypt, does not verify admission, and never touches
its keystore.

Request headers (defined in `proto/go/wire`, mirrored in `proto/ts`):

| Header | Value |
|---|---|
| `X-Zs-Relay-Target` | on-chain operator id of the destination |
| `X-Zs-Relay-Target-Node` | on-chain node id (within the operator) of the destination; the relay resolves the base URL from the `(operator, node)` pair |
| `X-Zs-Relay-Path` | inner request path (e.g. `/v1/chat/completions`) |
| `X-Zs-Relay-Method` | inner request method (`GET` / `POST`) |

The request body and `Content-Type` are the inner request's, verbatim: a sealed
inference envelope `application/vnd.zs+json`, a sealed reserve envelope
`application/vnd.zs-reserve+json`, or empty for discovery GETs. The relay
forwards the opaque bytes either way and can read neither the inference body
nor the reserve's `payer_addr`.

The same holds on the **return** path. A relay forwards a request's reserve leg
*and* its inference leg (both paths are on the allow-list below), so a leak in
any one of the four bodies would re-expose the payer. All four are sealed:

| Leg | Direction | Sealed to |
|---|---|---|
| reserve | request | target's ephemeral |
| reserve | response | caller's `proxy_recipient` |
| inference | request | target's ephemeral (body and identifiers alike) |
| inference | response | `K_response` (body, frames, receipt, settle group, metadata) |

The response headers a relay copies through are `X-Zs-Response-Key` (age-wrapped
to the caller's ephemeral, so opaque without its private half) and the sealed
`X-Zs-Receipt` and `X-Zs-Settle-Group`. Nothing else identifying rides the wire.

One response header is authored by the **relay itself** rather than copied:

| Header | Set by | Value |
|---|---|---|
| `X-Zs-Relay-Hop` | the relay, on every response it produces on `/v1/zs/relay` | `1` |

- A relay MUST set it as the first action of its handler (before the drain
  shed, header validation and the forward), so its presence means exactly "the
  zs relay handler ran", on the success path and every error path alike.
- A relay MUST also **skip this key when copying the target's response
  headers** (step 4 below), so a target can neither forge nor erase it. The
  marker is the relay's statement about itself, and nothing upstream may edit
  it.
- It separates two failures that otherwise look byte-identical to the caller:
  the relay's own CDN / ingress / LB answering a code-less `504` (the handler
  never ran; the request died at the relay's front door), versus the relay
  forwarding the **target's** code-less `504` verbatim. § 10 gives the decision
  rule for its absence.
- It leaks nothing: the caller already knows which relay it chose, the header
  never travels to the target, and a proxy strips every `X-Zs-*` before
  answering its own client.
- A node MUST list it in `Access-Control-Expose-Headers`. Otherwise browser JS
  cannot read it and every relayed response reads as "marker absent", which
  does not degrade gracefully but inverts the signal.

On receipt the relay:

1. Validates `X-Zs-Relay-Path` against a **closed allow-list**:
   `/v1/chat/completions`, `/v1/responses`, `/v1/images/generations`,
   `/v1/images/edits`, `/v1/models`, `/v1/models/{id}`, `/v1/zs/reserve`,
   `/v1/zs/details`, `/v1/zs/attestation`.
   - `/v1/zs/relay` itself is **not** allowed: relaying is single-hop, never
     chained.
   - A **query string** is split off before matching and forwarded to the
     target verbatim (the per-model deep details probe rides
     `/v1/zs/details?model=…&expand=…`, § 3c). The query can change neither the
     host nor the route, so the boundary gates the path only.
   - Traversal (`..`) and any non-`/v1/` path (checked on the path portion) are
     rejected.
2. Resolves the target id to a base URL through its **own on-chain operator
   directory**, never a client-supplied URL (SSRF boundary). An unknown id is
   rejected.

   2a. **Refuses a private dial target (SSRF guard).** The relay's forwarding
   HTTP client rejects any *resolved* IP in a loopback / RFC1918 / link-local /
   CGNAT / ULA range (v4 and v6). A malicious operator that registers a private
   `base_url`, or a hostname resolving into private space, therefore cannot turn
   a relay into a prober against its own LAN: the dial fails before any bytes
   are sent, surfacing as `relay_upstream_unreachable`. Because the check
   inspects the address actually dialed, it is DNS-rebinding-proof. The proxy
   applies the same guard to its operator-facing clients, and the `client/`
   browser applies a literal-host equivalent at catalog ingestion (it cannot
   resolve DNS). A localnet dev opt-out (`zs.allow_private_relay_targets` on the
   node, `zs.allow_private_operators` on the proxy, `VITE_ZS_ALLOW_LOCALHOST` on
   the client) disables the guard where operators legitimately run on
   `127.0.0.1` / `10.x`.
3. Reconstructs `target_base_url + inner_path` and forwards the body verbatim.
4. Copies the response status, `Content-Type` and `X-Zs-*` headers back,
   streaming the body with incremental flushing. **`X-Zs-Relay-Hop` is skipped
   from the target's header set** so the relay's own marker survives; the copy
   assigns rather than appends, so without the skip a target could overwrite
   it. **No re-framing**: sealed SSE frames (`event: zs`) and the plaintext
   `[DONE]` sentinel (§ 5.3) pass through byte-for-byte, preserving the
   frame-index AAD binding (§ 6).

Reference: `relay.IsAllowedInnerPath` (step 1); the step 2a hook is a
`net.Dialer.Control` installed by `httpx.Options.BlockPrivateTargets`, using
`httpx.IsPrivateIP`.

The relay route is disabled when the node runs with no escrow app configured
(the test-isolation `escrow_app_id == 0` mode), since it then has no directory
to resolve targets against and is unreachable in production anyway.

### What goes through the relay

With privacy mode on (the default; `privacy: false` / `PROXY_ZS_PRIVACY=false`
opts out), **all** of a client's operator-bound HTTP traffic is relayed: the
inference POST, `/v1/zs/reserve`, and the discovery GETs (`/v1/models`,
`/v1/models/{id}`, `/v1/zs/details`, `/v1/zs/attestation`). Direct discovery
probes would re-expose the client's IP on a background cadence, so they ride a
relay too. On-chain operator *enumeration* (algod box reads) is not an operator
HTTP call and is not relayed.

The envelope, ticket, receipt, admission tag and AAD layout are **unchanged**:
the request is sealed to the target's age key and admission-tag-bound to the
target-issued ticket exactly as in the direct case. The relay cannot read the
payload, forge admission or tamper (AEAD fails closed at the target).

A relay **is not a forward-secrecy downgrade vector.** The `/v1/zs/details` it
forwards carries the target's **signed** ephemeral advertisement
(`ephemeral_age_pubkey` + `ephemeral_issued_at` + `ephemeral_expiry` +
`ephemeral_sig`, § 3c), signed under the node's Ed25519 signing key, which the
relay does not hold. A relay can therefore neither forge a different ephemeral
nor strip the fields to coerce a weaker recipient. With no anchor key (§ 8)
there is nothing weaker to seal *to*, and a caller that finds no hard-valid
ephemeral fails closed to another operator (§ 4) rather than downgrading. The
one move left to a relay is to **replay a stale-but-unexpired** `/details` (an
older, still validly signed advertisement). The signed `ephemeral_issued_at`
makes that detectable and attributable ("stale-ephemeral replay" below).

### Path selection

The target and the relay are chosen by a shared, golden-vectored policy in
`proto/go/selection` (mirrored in `proto/ts`), so the proxy and the `client/`
app pick identically.

- **Target** — `SelectTargets` applies the model-eligibility, sizing, version,
  TEE, staging, signer-funding, built-in-tool and affinity policy. The shared policy is
  **price-ordered**.

  On top of it each caller applies an app-side **responsiveness banding**. It
  reads per-process and on-chain signals, so, like the relay weighting below, it
  is not golden-vectored and stays out of `proto/selection`.
  - Candidates are bucketed into ~500 ms bands by **expected response time =
    network RTT + TTFT + decode**:
    - network RTT is observed by the client;
    - TTFT is the node's on-chain co-signed first-token latency
      (`latency_ewma_ms`);
    - decode is `NORM_TOKENS / tok_s` from the node's on-chain throughput
      (`tokens_per_sec_ewma`), normalized to a fixed token count. It is weighted
      lightly because it is the noisiest term: a per-node aggregate, and decode
      rate is dominated by model size.
  - **Price is preserved within each band.** The affinity pin stays first, a
    node with no signal lands in the median band, and an all-cold field stays
    price-ordered.
  - Unlike the relay weighting, this is a pure *performance* refinement with
    **no** anti-profiling property: a target sees prompts, not the
    who-talked-to-whom metadata a relay sees ("Anonymity & trust model").
  - The two on-chain inputs come from the same `ttft_ms` / `decode_ms` receipt
    fields the metrics in § 3c aggregate.
- **Staging gate** — `SelectTargets` drops nodes whose on-chain
  `NodeRecord.staging` flag is set, unless the request opts in via
  `Constraints.allow_staging` (default off).
  - A node an operator brought up for testing and flagged staging (via
    `setNodeStaging`, callable by the operator owner or the node's signing key)
    is held out of production target selection. It still advertises on **its
    own** `/v1/zs/details` and can serve a caller who opts in, but the standard
    path never targets it.
  - **An aggregator's discovery surface tracks its routing.** Advertising a
    staging node's models to a caller who hasn't opted in promises capacity
    selection then refuses, and — because cross-operator aggregates fold sizing
    to the minimum and price to the lowest — lets a held-out node set the
    published context window and "from $X" rate for a model nobody can buy. So
    the proxy omits staging nodes from `/v1/models`, from its **aggregate**
    `/v1/zs/details`, and from `/v1/zs/operators` unless `allow_staging` is set,
    as the client's model picker already does. Both still use them as relays
    (see below), so the relay pool is built from an unfiltered view.
  - The proxy opts in via `zs.allow_staging` (config / `--allow-staging` /
    `PROXY_ZS_ALLOW_STAGING`); the client via its Model Routing "allow staging"
    toggle.
  - When the only nodes serving a model are staging and the caller didn't opt
    in, the policy returns `staging_blocked` (distinct from "nobody serves this
    model"), which the proxy surfaces as `503 no_production_operator`.
  - It gates TARGET selection only. Staging nodes remain usable as relays, since
    a relay forwards bytes and runs no inference.
  - It is golden-vectored like the rest of the shared policy (`staging_*` cases
    in `selection_vectors.json`).
- **Signer-funding gate** — `SelectTargets` drops a node whose signing account
  (`NodeRecord.signing`) holds less than `MinSignerSpendableMicroAlgos` (5 ALGO)
  **spendable**, i.e. algod's `amount − min-balance`. That account pays the
  pooled fees of every payer's `open()` group and atomic settle ("Settlement
  asset model"), so a node that can't cover them can't serve a request whatever
  else it advertises. There is no opt-in.
  - The balance rides the shared descriptor as
    `selection.Operator.signer_spendable_microalgos`, read by each app from
    algod (`/v2/accounts/{addr}?exclude=all`) on its catalog-refresh cadence.
  - **Unknown is eligible.** A never-read balance is absent and passes, so an
    algod outage cannot empty the catalog. A failed read keeps the last known
    value: a node read as broke stays excluded until a read shows it refunded.
  - **Every signer is read, uniformly.** Never only the chosen target's, and
    never at request time. The submitted `open()` group already names the node
    to the algod provider, but a targeted read would add a signal ahead of it —
    including for requests that never reach `open()` — so the read stays
    demand-independent and adds no channel.
  - The floor doubles as the staleness budget. At ~7,000 µALGO of pooled fees
    per paid request, 5 ALGO covers ~700 requests between reads.
  - Both continuation pins re-check it, because a pinned node can drain
    mid-conversation. The tool-affinity pin: under `prefer` it yields, under
    `strict` the result is `signer_underfunded_blocked` — after the caller's
    `only`/`ignore`/`order` conflict and the fit check, whose permanent refusals
    outrank this retryable one. The proxy's `previous_response_id` pin applies
    the same order.
  - When every otherwise-eligible node is below the floor, or a pin resolves to
    one, the policy returns `signer_underfunded_blocked`, which the proxy
    surfaces as `503 no_funded_operator`. An aggregator omits nodes below the
    floor from `/v1/models` and the aggregate `/v1/zs/details`; unlike staging
    nodes they stay listed in `/v1/zs/operators`, with the balance and a
    `signer_underfunded` flag, so a payer can see why a model left.
  - It gates TARGET selection only: a relay pays no fee, so a broke node is
    still a valid relay hop.
  - Golden-vectored (`signer_underfunded_*` and `relay_underfunded_*` cases in
    `selection_vectors.json`).
- **Caller routing preferences** (OpenRouter-style) — a caller may guide
  `SelectTargets` with an optional top-level **`provider`** object on the
  request body. It is a **proxy/client-only hint**: the proxy or client parses
  it, feeds it into the shared policy, then **strips it pre-seal**, so it never
  reaches the node or the upstream LLM. It is **not** on the wire. All fields
  are advisory; an absent or malformed value is ignored, never fatal.

  | Field | Meaning |
  |---|---|
  | `only` / `ignore` | Allowlist / denylist of operator refs. Deny wins. |
  | `order` | Explicit preference order. Matched candidates float to the front, after any continuation-affinity pin. |
  | `allow_fallbacks` (default `true`) | When `false`, `order` is a hard pin to exactly the named set and the rest are dropped. Governs `order` only; never loosens `only` / `ignore`. |
  | `max_price: {input, output}` | USD/1M ceilings. An operator over a set ceiling is dropped; an undeclared `0` rate counts as too expensive. |
  | `require_tools` | Promotes the built-in-tool partition to a hard filter. |
  | `sort` (`price`\|`throughput`\|`latency`) | **App-side.** Selects which terms of the responsiveness score apply (below). |
  | `relay` (`auto`\|`off`\|`required`) | **App-side.** The per-request transport-privacy override (§ 3f "Privacy is the default"). `off` forfeits single-hop unlinkability for that request and is gated by `zs.allow_privacy_override`. |

  The app-side fields are consumed by the per-process responsiveness and relay
  passes, not the golden-vectored policy, and are mirrored proxy↔client. `sort`
  re-weights the responsiveness banding above:
  - `latency`: first-token only (network RTT + TTFT; the decode term is
    dropped).
  - `throughput`: the decode term only. Lower decode time means higher tok/s,
    so this orders by sustained throughput.
  - `price`: skip the reband and keep the shared policy's pure price order.
  - absent (the default): the full combined score.

  Every variant stays "lower = faster" so the banding is uniform, and price
  still breaks ties within a band.

  An **operator ref** is `"<operatorId>"` (any node of the operator) or
  `"<operatorId>:<nodeId>"` (one exact node): base-slug vs full-slug, keyed by
  the same
  `(operatorId, nodeId)` pair as everything else in a routing path.

  Unsatisfiable preferences surface as distinct errors:

  | Condition | Error | Notes |
  |---|---|---|
  | `only` miss, or `order` with no fallbacks misses | `503 no_pinned_operator` | A pool-availability condition like `no_operator` / `no_tee_capacity`. The pin is well-formed (a malformed ref is skipped at parse time), so a retry can succeed once the pinned operator/node reappears. |
  | a `previous_response_id` continuation whose target the preferences exclude | `400 pin_conflicts_with_continuation` | A genuine client contradiction; retrying the same body never resolves it. |
  | `max_price` excludes everyone | `400 price_ceiling_exceeded` | |
  | `require_tools` with no capable operator | `503 no_tool_capacity` | § 10 |

  Reference: parsed by `selection.ExtractRoutingPreferences`; stripped by
  `inject.DropRoutingPreferences`, alongside `DefaultStoreFalse` /
  `DropEmptyTools`. The shared, golden-vectored fields are `proto/go/selection`
  `Constraints.{Only,Ignore,Order,AllowFallbacks,MaxInputUSDPer1M,MaxOutputUSDPer1M,RequireTools}`.
- **Relay** — `SelectRelay` picks any operator `!= target` that satisfies:
  - `owner_addr != target.owner_addr` (hard diversity rule);
  - version-compatible, so it exposes the relay route.

  `/16` subnet diversity is applied best-effort (skipped for DNS-name and
  non-public hosts). Reachability is a soft *preference*, not a requirement: a
  known-reachable relay is chosen over a not-known-reachable one, but when none
  are known-reachable the pick falls back to the full eligible set rather than
  failing. A down operator therefore isn't chosen as a relay in steady state,
  yet cold start still bootstraps.

  The pick *within* the eligible pool is a per-request seeded draw. This
  rotation stops an entry relay from learning a stable client↔target pair
  across a session.
  - **Latency weighting.** A caller that measures relay latency (the proxy and
    the client both do; each is a single-payer process reaching the mesh from
    its own vantage) draws with weight `∝ 1/(rtt + bias)`, favoring low-RTT
    relays. Relays with no fresh sample get the median weight, so they keep
    being sampled.
  - **Floor.** The weighted distribution is **mixed with uniform by a floor**
    (`latencyFloorFraction`, ~0.15), so weighting can never starve a relay.
    Every eligible relay keeps at least `floor/n` of the draw, and no single
    relay exceeds ~`(1−floor)+floor/n`.
  - **Capture bound.** That ceiling is also the **most a single relay can
    capture even if it games its measured RTT** to attract traffic, so `floor`
    is the tunable knob for this §3f capture bound. To cap any relay at a
    fraction `C` of a target's requests, set `floor ≈ (1−C)·n/(n−1)` (requires
    `C ≥ 1/n`; you can't cap below uniform). For example,
    `n=100, C=25% → floor ≈ 0.76`. The `~0.15` default is latency-first (ceiling ≈85–93%), fine when
    relays are trusted not to game RTT.
  - The ceiling is a worst case (one relay far faster than all others). A tight
    ceiling at large `n` forces `floor ≈ 1−C`, which largely cancels the latency
    bias. This one knob can't give both a tight cap and strong latency
    preference; a hard per-relay probability cap would, but is not specified
    here.
  - A caller with no latency data (cold start, or one that doesn't measure)
    falls back to plain uniform `seed % len`.
  - Weighting trades **some** of uniform rotation's diffusion for lower latency.
    The floor bounds that trade, so the anti-profiling property below still
    holds, bounded rather than perfectly uniform.
  - Latency is a stateful, per-process, vantage-specific signal, so it is
    **not** in the golden-vectored `selection` policy. Each caller layers it
    over the shared eligibility ordering.

  When no operator qualifies, selection returns `ErrNoRelay` and the client
  MUST **hard-fail** the request. It MUST NOT fall back to a direct route,
  which would silently void the privacy guarantee.
- **Failure attribution feeds reachability correctly.** A relayed probe or
  request can fail at *either* hop, and the two MUST NOT be conflated.
  - A transport error reaching the relay, or a relay-generated error code
    (`relay_busy`, `relay_unknown_target`, `relay_bad_*`,
    `relay_build_request`), means the **relay** failed. The caller marks the
    relay down (deprioritizing it for the preference above) and retries through
    a different relay. It MUST NOT mark the *target* unreachable: the target was
    never reached, so its status is unknown this cycle.
  - `relay_upstream_unreachable` is the exception: the relay reached out but the
    target was down, so it is a **target**-side signal.
  - Any other status is the target's own response, forwarded verbatim.

  This lets a flaky relay drop out of the candidate set without a healthy target
  being mistaken for down. `relay.IsHopErrorCode` is the shared classifier;
  mirror it in the TS implementation.

Reference: the target policy was lifted from the proxy's `pickCandidates`; the
staging flag is carried into the shared policy as `selection.Operator.staging`.

### Anonymity & trust model

- **Property delivered:** the target operator does not learn the client's IP.
  This is the OHTTP-single-relay property, without OHTTP's streaming gap.
  Hiding the *target's* IP from the client (symmetric privacy) is out of scope
  for single-hop.
- **What each hop sees, per request:**
  - The **relay** sees the client IP, the target IP, ciphertext, timing and
    byte counts: **who talked to whom, never what** (the body is sealed to the
    target's age key).
  - The **target** sees the **relay's** IP and the decrypted prompt: **what was
    asked, but never the client's IP**, which it never receives.
  - The target *does* read the payer's Algorand address from the reserve, and
    `open()` publishes it on chain. That address is a stable *payment*
    pseudonym, so "never who" holds for the client's network identity, not for
    the payer (payment linkability: § 13.6).
- **The relay does not read the payer's Algorand address off the wire**, but
  linkage is *reduced*, not *eliminated*.
  - Sealing every leg (the table in "The relay route") removes the payer,
    `ticket_id` and `algorand_tx_id` from everything a relay handles.
  - What remains: **`open()` is a public Algorand transaction**. "Account Y
    opened a ticket to operator T at time τ" is on chain forever. A relay that
    records `(client IP, target T, timing)` for a request it forwards can scan
    the chain for an `open()` to T near τ. If the correlation is tight (T
    lightly loaded, request and open closely spaced), it recovers the payer
    **by timing** despite a perfect seal.
  - Sealing every leg reduces the attack from an *exact, immediate read off the
    wire* to a *statistical timing correlation against public chain data*. That
    is the timing/volume class this spec declares out of scope for single-hop
    below (mixnet territory). It is a real improvement and the accepted
    stopping point for this item, not a proof of unlinkability.
  - Closing the residual means decoupling `open()` submission timing from
    request timing (pre-funded ticket pools, jittered or batched opens, a larger
    per-target anonymity set) or diluting it structurally with multi-hop. Both
    are out of scope here.
- **The split is per-request, and it's what makes single-hop hold.** Every node
  is both a relay and an inference target, so over time one operator sees many
  client IPs (as relay) and many prompts (as target). But `relay ≠ target`
  (enforced with owner-key diversity) guarantees they are **two different
  operators for any one request**. So **no single operator (owner key) ever
  holds both the IP and the prompt of the same request**, and none can bind a
  prompt to a client without a second owner's cooperation (see collusion /
  Sybil below).
- **Across many requests** this stays true.
  - A relay accumulates client→target metadata for the traffic that rotates
    through it. The per-request draw diffuses this. Latency weighting biases it
    toward faster relays, but the uniform-mixing floor caps any one relay's
    share at ~`(1−floor)+floor/n`, so no single relay profiles a client's whole
    session. Diffusion is *bounded*, not perfectly uniform; raise
    `latencyFloorFraction` to favor diffusion over latency.
  - A target accumulates prompts but *zero* client IPs. It can assemble "every
    prompt I served" but attach no *network* identity to them. It can still
    attach the payer's address (above), so what is unlinkable here is the
    client's IP, not the payer (§ 13.6).
- **Where it breaks — collusion / Sybil.** Joining "client C ↔ target T" (the
  relay's view) with prompt P (the target's view) for the *same* request
  requires the relay and target to collude, or one entity to control both.
  - `relay ≠ target` + owner-key diversity stops a single owner from being both
    for one request, so the residual threat is a **Sybil**: one party registering
    many operators under distinct owner keys and being the relay *and* the
    target of the same request. This is the documented single-hop limit ("a
    compromised or coerced relay collapses the property for traffic that
    transits it").
  - A global passive observer doing timing/volume correlation across both flows
    is likewise out of scope (mixnet territory).
  - Multi-hop relaying mitigates both: with ≥2 relays no single hop sees both
    ends, so every hop on the circuit would have to collude.
- **Mandatory, not incentivized:** relaying is built into the node binary, not
  a paid role, because it is a commons. Every privacy-mode request reaches its
  target *through* a relay, so a fleet where operators could decline to relay
  would have no privacy path at all. Operators are compensated indirectly,
  through the inference revenue they already earn.
  - **Non-compliant forks.** A fork that advertises a compatible generation but
    strips the forwarding path is handled by a soft, per-relay reputation
    signal. Each forward outcome is credited to the relay, so a fork that
    black-holes forwards accrues a failure streak and is deprioritized to the
    fallback tier. A fork that answers its own discovery probe still stays
    `Reachable`, so the streak, not the probe, is what demotes it.
  - **Stale-ephemeral replay** (§ 8) is covered by a sibling signal. When a
    relay-fetched `/v1/zs/details` carries an ephemeral whose signed
    `ephemeral_issued_at` is older than `FreshnessTarget` (§ 3c), the caller
    records a relay-staleness fault and prefers a fresher path. The block is
    still *used* if it is the only hard-valid one (it remains decryptable and
    forward-secret), so the user is never failed for a relay's staleness; only
    the relay's reputation pays. A fresh block over the same relay resets the
    streak.
  - The heavier on-chain `evictOperator` lever is **admin-only** and
    independent of this app-side signal. It tombstones a misbehaving operator
    and slashes a percentage of its escrowed USDC stake to the treasury. It is a
    moderation action, not an automatic consequence of a reputation streak.

  Reference: `proxy/internal/hayai/relay_reputation.go`, `RecordRelayOutcome`
  (forward outcomes) and `RecordRelayStaleEphemeral` (staleness faults).

### Privacy is the default

Privacy mode is **on** by default; opt out with `privacy: false` in YAML or
`PROXY_ZS_PRIVACY=false`. Every privacy-mode request reaches its target
*through* a relay, so relaying is the steady state, not an opt-in. The
`proto_version` **major** is itself the gate (§ 3c "Protocol version
negotiation"): a peer only talks to peers of the same major, which drops any
relay-incapable node from a relay-using client's candidate set with no separate
mechanism. This is also why the node's reserve handler is sealed-only (§ 3a).

**Per-request override (caller opt-out).** A caller can override the default
for a single request through the routing-preference surface (§ 3f "Path
selection"): `provider.relay` on the body, or the `X-Zs-Relay` header. The body
wins.

| Value | Effect |
|---|---|
| `"off"` | Skips the relay and sends **direct** to the target, byte-identical to the `privacy: false` path. Trades the anti-profiling property above for lower latency. That request's target **does** see the caller's IP, so single-hop unlinkability is forfeited *for that request only*; the fleet default and everyone else's traffic are unchanged. |
| `"required"` | Forces a relay even when the config default is off. Hard-fails `no_relay_available` if none is eligible. |
| `"auto"` / absent | Keeps the config default. |

- The override lets a caller weaken *its own* privacy, so the proxy gates the
  `"off"` direction behind `zs.allow_privacy_override` (default true). Set it
  false to refuse `"off"`, e.g. when the localhost proxy is exposed to other
  local apps. `"required"` is never gated.
- The decision governs the single relay hop that carries **both** the sealed
  reserve and the inference forward, so `"off"` is consistent end-to-end.
  Background discovery probes (not per-request) are unaffected.

Reference: the default is `Privacy: true` in `proxy/internal/config/config.go`.

### Caller-supplied correlators in the request body

An OpenAI-compatible client may put a value in an ordinary request field that is
constant across a conversation. Such a value is an exact-match join key for any
party that sees two turns carrying it.

**Scope this honestly.** It is not a channel the rest of the protocol closes:
- Target selection is deterministic (§ 3f "Path selection": price sort, id
  tiebreak), and affinity *pins* one operator by design across tool rounds and
  `previous_response_id` continuations. The per-request random draw is relay
  selection, not target selection.
- An operator that serves a turn decrypts the full conversation history and
  reads `payer_addr` off the verified payment, so two operators who each served
  a turn can already join on prefix or payer.

What a constant token adds is a join that is short, opaque, cheap to index, and
survives context truncation, prompt edits and compaction (exactly where prefix
matching stops working), for a field nothing downstream needs. Removing it is
cheap defense in depth, not a guarantee.

The reference proxy strips what it can **pre-seal**, before the AAD and admission
tag commit to the body:

- **`prompt_cache_key`** — OpenAI's upstream cache-shard hint. Clients derive it
  from what does *not* change across a conversation (Hermes Agent: a digest of
  session id, system prompt and tool schemas).
  - Stripping it costs the shard hint, not prompt caching: upstreams that cache
    do so on the prompt prefix regardless.
  - The node's responses-to-chat translator already drops the field, so on an
    emulating node it never reached the upstream. The pre-seal strip keeps it
    from reaching the node, and covers natively-Responses backends the
    translator never sees.
  - Recovering the hint without the join would mean rewriting the value per
    operator under a secret the operator cannot recompute (the keying
    `inject.SafetyIdentifierFor` applies to its own identifier), rather than
    dropping it. This is not currently done.

  Reference: `inject.DropPromptCacheKey`, alongside `DefaultStoreFalse` /
  `DropEmptyTools` / `DropRoutingPreferences`; the translator is
  `node/internal/llm/responsestochat`.

**Not closed, by design.** A caller-supplied `safety_identifier` has the same
shape and is preserved. Per § 3a "OpenAI compatible `safety_identifier`", the
node fills in a per-node keyed default (`inject.SafetyIdentifierFor`) only when
injection is enabled (`zs.inject_safety_identifier`, **opt-in and off by
default**) and the caller sent none. It never overrides a finer-grained value
the caller chose. A legacy `user` field is untouched too. Both remain the
caller's own choice, and a caller that sets either forfeits this property for
itself.

**Implementation scope.** Only the Go proxy currently performs these strips. `client/`
composes its own request bodies and has no OpenAI-compatible ingress, so it has
nothing to strip. If it ever accepts third-party bodies it needs the same pass,
and `proto/ts` has no `inject` twin to mirror into.

### Reference implementation

- `proto/go/inject/promptcachekey.go` — `DropPromptCacheKey`, applied pre-seal at the proxy's dispatch site (`proxy/internal/server/hayai_dispatch.go`).
- `proto/go/wire/envelope.go` — `RelayPath`, `RelayTargetHeader`, `RelayPathHeader`, `RelayMethodHeader` (mirrored in `proto/ts/src/wire/constants.ts`).
- `proto/go/relay` — `BuildRequest` (relay indirection builder), `IsAllowedInnerPath` (the allow-list / SSRF boundary), mirrored in `proto/ts/src/relay`.
- `proto/go/selection` — `SelectTargets`, `SelectRelay`, the affinity-key derivation helpers, mirrored in `proto/ts/src/selection`; pinned across implementations by `proto/testdata/selection_vectors.json`.
- `node/internal/server` — the `/v1/zs/relay` handler + the node-local cached operator directory.
- `proxy/internal/server` / `proxy/internal/hayai` — the `zs.privacy` knob and relay indirection at the inference, reserve, and discovery call sites.

## 4. Request format

**HTTP method and URL**: unchanged from OpenAI. A `POST /v1/chat/completions` from the client becomes a `POST /v1/chat/completions` to the node, and likewise for `/v1/responses`.

**Request headers**:
- `Content-Type: application/vnd.zs+json` identifies the envelope.
- No `Authorization` header. Admission is via the sealed envelope and the on-chain `Payment + escrow.open` group. The proxy injects no bearer auth, and the node ignores any `Authorization` it receives.
- `Accept: application/json` (non-streaming) or `Accept: text/event-stream` (streaming). The proxy decides streaming from the `"stream": true` field of the **plaintext** request body (the client's body, before encryption).

**Request body** (`application/vnd.zs+json`):

```json
{
  "ciphertext": "<base64 of age output>"
}
```

The envelope carries **nothing but ciphertext**. Everything the node needs rides inside the seal as an *inner-request frame*, the plaintext that `ciphertext` encrypts:

```
"zsrq" || uint8(version=1) || uint32_be(headerLen) || headerJSON || body
```

`headerJSON` is a compact JSON object with the fields below. `body` is the original OpenAI request body, appended **verbatim**.
- The framing exists so `body` survives byte-for-byte. The admission tag and the receipt's `body_hash` both commit to `sha256(body)`, and re-serializing arbitrary caller JSON does not round-trip its bytes.
- Length-prefixing the header keeps `body` a raw suffix: no escaping, and no base64 inflation on multi-megabyte image-edit bodies.
- A peer that seals a bare body fails the magic check and is rejected with a framing error, rather than a JSON parse error deep in the provider path.

| Field | Where | Type | Semantics |
|---|---|---|---|
| `ciphertext` | envelope | base64 string | Age output (binary, not armored) of the inner-request frame, encrypted to the node's advertised **ephemeral** X25519 recipient as the sole recipient ("Sealing recipient" below). |
| `reply_to_public_key` | inner header | string | The proxy's ephemeral X25519 public key in age's `age1...` bech32 format. The node uses it as the age recipient when wrapping the response symmetric key. The node checks it against the ticket's `proxy_recipient` (note below). |
| `algorand_tx_id` | inner header | string | Txid of the request's escrow.open **app call** (gtxn[1] of the group; note below). The node **MUST** bind it into the AEAD AAD of every sealed response payload per § 6. It is **not** echoed in the response envelope. |
| `ticket_id` | inner header | string | References a `Ticket` previously obtained from the node's reserve endpoint (§ 3a). AAD-bound alongside `algorand_tx_id` on every sealed response payload per § 6. Admission is always ticket-gated (the node rejects unadmitted POSTs), so every request carries one. |
| `admission_tag` | inner header | string (optional) | base64 of `HMAC-SHA256(K_response, "zs-admission-v1\0" \|\| ticket_id \|\| \0 \|\| algorand_tx_id \|\| \0 \|\| sha256(body))`. Proves the sender holds `K_response`, delivered to the proxy at reserve time via `wrapped_response_key`. Required when `ticket_id` is present and the node enforces admission tagging; missing or mismatched → `402 admission_tag_invalid` (note below). |

**`reply_to_public_key`.** The proxy reuses the identity it declared at reserve time as `proxy_recipient`, so one private key unwraps both `wrapped_response_key` (reserve) and `X-Zs-Response-Key` (response). **The node enforces this**: a value other than the ticket's `proxy_recipient` is rejected with `402 reply_to_mismatch`, before `Consume`.

**`algorand_tx_id`.** The group is two transactions: the payer's usdcPayment (gtxn[0]) and the node-signed AppCall (gtxn[1]). The node pre-signs gtxn[1] and delivers it at reserve time as `presigned_open_txn` (§ 3a); the proxy signs gtxn[0] against it and submits the group atomically. The proxy puts gtxn[1]'s app-call txid in this field, and the node looks it up directly via algod's `PendingTransactionInformation`. The group id is NOT a valid lookup key, so the app-call txid is used; the proxy keeps the group id for audit only.

**`admission_tag`.** The node verifies it before `Consume`, so a forged tag does not burn the ticket (§ 3a "Sealed request envelope").

**Why sealing the identifiers costs nothing.** The obvious objection is DoS ordering: "then the node must decrypt before it can reject an unadmitted request." It must anyway. The admission tag commits to `sha256(body)` of the *plaintext* body, so the tag check cannot run until after the age-decrypt. The decrypt is the node's forced-work floor on the inference path either way (as the age-unseal is on the reserve path), and there is no pre-decrypt admission gate to lose. The node reads the identifiers from the already-decrypted plaintext instead of the outer JSON: the same decrypt, with the fields moved.

Reference: `reply_to_public_key` comes from `age.X25519Identity.Recipient().String()`; the tag check is `verifyAdmissionTag`.

### Sealing recipient: the signed ephemeral (mandatory, fail-closed)

The `ciphertext` recipient is the node's signed **ephemeral** recipient; there is no on-chain anchor (§ 8). A sealing party (proxy or direct client) reads `ephemeral_age_pubkey` / `ephemeral_issued_at` / `ephemeral_expiry` / `ephemeral_sig` from `/v1/zs/details` (§ 3c) and applies these **hard checks** before sealing:

1. `ephemeral_sig` verifies under the public key decoded from the on-chain `signing_addr`, with `operator_id` bound from the chain-resolved id.
2. The signed window satisfies `ephemeral_expiry − ephemeral_issued_at ≤ MaxEphemeralLifetime`.
3. `ephemeral_issued_at` is not future-dated.
4. `now ≤ ephemeral_expiry`.

(each with a small skew tolerance)

**All pass → seal to the ephemeral. Any fail (absent, expired, over-lifetime, future-dated, or bad signature) → refuse the operator and fall through to another candidate.** There is **no fallback recipient and no silent downgrade**; forward secrecy is unconditional (§ 8).

Separately, and without gating: on a relayed path, an `ephemeral_issued_at` older than `FreshnessTarget` downranks the *relay* without failing the user (§ 3f).

**Refetch-and-retry on stale-seal decrypt failure.** The ephemeral key is in-memory-only, dies on restart, and rotates out of the decrypt-overlap window (§ 3c, § 8). A sealing party's cached ephemeral can therefore briefly outlive the key the node holds.
- The node decrypts only with its current and previous-in-overlap identities (there is no anchor identity). When a request was sealed to a recipient it no longer holds, it returns a distinguishable envelope-decrypt error: `400 bad_reserve_envelope` on reserve, and on inference a plaintext error per § 10.
- When the sealing party gets that error **after sealing to an ephemeral recipient**, it refetches `/v1/zs/details` for the operator's current ephemeral and reseals once against the **same** operator. If no fresh ephemeral qualifies, it falls through to another candidate.
- A failure sealed to the already-current ephemeral is a genuine error and is not retried.

This bounds the post-rotation stale-seal window to a single refetch-and-retry rather than a full discovery-refresh interval, and never falls back to a non-forward-secret recipient, because none exists.

## 5. Response format

Every prompt-carrying response is a sealed envelope. The proxy detects the streaming or non-streaming variant from `Content-Type` (§ 5.2 vs § 5.3). Responses to admitted requests MUST be sealed; there is no plaintext passthrough.

### 5.1 Plaintext rejection (sealed-only)

- **Trigger**: `X-Zs-Response-Key` header is absent on a 2xx response.
- **Proxy behavior**: treated as a protocol violation; the proxy returns 502 `proxy_error / operator_unsealed_response` to the client. Streaming variants are refused before any frames are pumped.
- **Pre-envelope errors only**: a node MAY return plaintext `application/json` with status >= 400 for transport-level failures it hits before sealing is set up (malformed envelope, ticket failures, missing identity). The proxy passes those through so the client sees the cause. Successful (2xx) responses without sealing are forbidden.

### 5.2 Non-streaming encrypted response

- **Trigger**: `X-Zs-Response-Key` header present AND `Content-Type: application/vnd.zs+json`.

**Response headers**:
- `Content-Type: application/vnd.zs+json`
- `X-Zs-Response-Key: <base64 of age ciphertext wrapping 32 bytes>`
- `X-Zs-Receipt: <base64(nonce || AEAD(base64(json_receipt)))>`
  - Present whenever the request was admitted via a ticket. Carries the node-signed usage receipt the proxy uses for `protest()`, ledger consistency, and § 3b dispute retention.
  - **Sealed under `K_response`** with `HeaderAAD(algorand_tx_id, ticket_id, "receipt")` (§ 6), because the receipt carries `ticket_id`, which resolves to `TicketRecord.payer` on chain.
  - Inside the seal the value is `base64(json)`. The canonical binary encoding exists only as signature input, never on the wire.
- `X-Zs-Settle-Group: <base64(nonce || AEAD(base64(msgpack([op_first_half(SignedTxn), payer_ack(SignedTxn-with-empty-sig)]))))>`
  - Present whenever the response carries a receipt and the node has algod connectivity. The proxy signs gtxn[1] in place and broadcasts atomically.
  - **Sealed under `K_response`** with `HeaderAAD(algorand_tx_id, ticket_id, "settle-group")`, because the encoded group names the payer address outright: gtxn[1]'s sender, and both txns' `ForeignAccounts`. That these transactions later go on chain is no defense: a relay forwarding the response also holds the client's IP, and the chain does not.
  - Soft failure: if composition fails (e.g. algod unreachable, no operator signer), the header is omitted and the proxy falls through to its standalone-ack path. The receipt header is still delivered.

The value of `X-Zs-Response-Key` is the 32-byte symmetric key that AEAD-seals the body, age-encrypted to the request's `reply_to_public_key`. It is the only response header a relay may read, and it is opaque to anyone without the caller's ephemeral private key.

Reference: the receipt header is encoded by `EncodeReceiptHeader` / `DecodeReceiptHeader`.

**Response body** (`application/vnd.zs+json`):

```json
{
  "nonce": "<base64 12 bytes>",
  "ciphertext": "<base64 of ChaCha20-Poly1305 sealed bytes (incl. 16-byte tag)>"
}
```

The node MUST AEAD-seal the body with AAD = `BodyAAD(algorand_tx_id, ticket_id)` as defined in § 6. `algorand_tx_id` is **not** echoed on the response. Both endpoints reconstruct the AAD from state they already hold, so an echo would add only a redundant equality check while handing a relay the identifier that resolves to the payer on chain. Splice resistance rests entirely on the AAD, which is strictly stronger; a rewritten echo never defeated it anyway.

Proxy behavior:
1. Extract `X-Zs-Response-Key` and age-decrypt it with the per-request ephemeral identity → `response_key`. Verify `sha256(response_key) == ticket.commit_k`; a mismatch refuses the response.
2. Parse the envelope.
3. `chacha20poly1305.New(response_key).Open(nil, nonce, ciphertext, BodyAAD(tx_id, ticket_id))` → plaintext OpenAI response body. A response sealed under a different request's `tx_id` fails here (§ 10).
4. Emit to the client with `Content-Type: application/json`, and without `X-Zs-Response-Key`, `X-Zs-Receipt` or `X-Zs-Settle-Group`.
5. Open `X-Zs-Receipt` and `X-Zs-Settle-Group` (when present) under their `HeaderAAD` names, then decode. Validate that the receipt matches the inference body, then either broadcast the atomic settle group or fall through to a standalone ack-settle (§ 3a "Settlement windows"). A value that fails to open is treated as absent: the proxy degrades exactly as it does for a node that sent nothing.

### 5.3 Streaming encrypted response

- **Trigger**: `X-Zs-Response-Key` header present AND `Content-Type: text/event-stream`.

**Response headers**: same `X-Zs-Response-Key` as § 5.2; `Content-Type: text/event-stream`.

**Frame format** (per SSE):

Encrypted frame:
```
event: zs
data: <base64(12-byte nonce || ChaCha20-Poly1305 sealed plaintext_frame_data (incl. 16-byte tag))>

```

- `plaintext_frame_data` is the bytes that would appear after `data: ` in a normal (unencrypted) OpenAI SSE frame — typically a JSON chunk such as `{"id":"chatcmpl-...","choices":[...]}`.
- On the wire each frame is a complete SSE frame terminated by a blank line.
- The 12-byte nonce is prepended to the ciphertext before base64 encoding, so the whole `data:` value is `base64(nonce || ct_with_tag)`.
- Each encrypted frame is sealed with AAD = `FrameAAD(algorand_tx_id, ticket_id, frame_index)`, where `frame_index` is the 0-based position of this encrypted frame within the stream (§ 6). The node MUST emit encrypted frames in index order.

Plaintext frame (within an otherwise-encrypted stream):
```
data: [DONE]

```
- Any frame **without** `event: zs` is passed through unchanged. This covers the `[DONE]` sentinel, mixed streams, and any SSE metadata lines the node wants visible. **Plaintext frames do not advance the AAD frame counter**; only `event: zs` frames do. Both sides follow the same convention.

#### Out-of-band settlement event types

Two more named SSE events carry the out-of-band settlement metadata. Both are sealed under `K_response`, but with different AAD constructions:

- **`zs-settle-group` is sealed under `HeaderAAD(algorand_tx_id, ticket_id, "settle-group")`** (§ 6). It stands in for the § 5.2 response header of the same name, which is not yet computable at stream start.
  - It does **not** advance the encrypted-frame AAD counter. It precedes the `zs-receipt` frame, which must land on the index the content frames left off at, and header metadata is emitted at most once per name.
  - It is sealed for *confidentiality*, not integrity. Consensus already authenticates the operator's Algorand signatures at broadcast, but the payer-ack template names the payer address (gtxn[1]'s sender, both txns' `ForeignAccounts`). In plaintext, a relay forwarding the stream would read the payer with no chain lookup at all (§ 3f).
- **`zs-receipt` is sealed under the standard frame construction.** It consumes the **next `frame_index`** after the final content frame, AAD-bound like any `event: zs` frame.
  - The plaintext inside is the **JSON-encoded UsageReceipt**, the same encoding as the § 5.2 header, never canonical binary.
  - Sealing binds the receipt into the same tx/ticket/position AAD chain as the content it prices, so a relay cannot splice a receipt across streams. A receipt frame that fails AEAD-open (e.g. after a dropped tail content frame desyncs the counter) is discarded, not trusted.
  - The receipt frame is **excluded from `body_hash`**. The hash covers the content frames it commits to (indices `0..N-1`); the receipt rides at index `N`.

```
event: zs-settle-group
data: <base64(nonce || ChaCha20-Poly1305(base64(msgpack([op_first_half(SignedTxn), payer_ack(SignedTxn-with-empty-sig)]))))>   [AAD = HeaderAAD(tx_id, ticket_id, "settle-group")]

event: zs-receipt
data: <base64(nonce || ChaCha20-Poly1305(JSON UsageReceipt))>   [AAD = FrameAAD(tx_id, ticket_id, N)]

```

| Event | Sealing / counter | When emitted | Required ordering | Consumer |
|---|---|---|---|---|
| `zs-settle-group` | Sealed under `K_response` with `HeaderAAD(tx_id, ticket_id, "settle-group")`; no `frame_index` consumed. | Once, after the final encrypted content frame and immediately before `zs-receipt`. Soft failure: the node MAY omit it on algod outage. | Before `zs-receipt`, before `[DONE]`. | Proxy AEAD-opens it under the header AAD and caches the decoded group; when the receipt arrives it signs gtxn[1] and broadcasts atomically. |
| `zs-receipt` | Sealed under `K_response`; consumes the next `frame_index`. | Once, after `zs-settle-group` (when emitted) and immediately before `[DONE]`. Always present on a successful streamed inference admitted via a ticket. | After `zs-settle-group` (when emitted), before `[DONE]`. | Proxy AEAD-opens at the current counter, parses the JSON receipt, and runs the § 3a verification + settle/protest. The raw receipt is never forwarded to the client. |

The node MUST NOT emit either event before all encrypted content frames are flushed. Proxies parse the stream sequentially and treat these events as the signal that the inference body is complete. The proxy treats either event arriving mid-content as a protocol violation.

Proxy behavior:
1. On the upstream response headers: extract `X-Zs-Response-Key` and age-decrypt it with the ephemeral identity → `response_key`. Verify `sha256(response_key) == ticket.commit_k` (the same check as § 5.2); a mismatch refuses the stream at setup, before any frame is pumped. Initialize `frame_index = 0`.
2. For each frame read by the SSE pump:
   - `frame.Event == "zs"`: base64-decode `data`, split into `(nonce, ct)`, AEAD-open with `response_key` and AAD = `FrameAAD(tx_id, ticket_id, frame_index)`, increment `frame_index`, accumulate the plaintext for `body_hash`, and emit a new SSE frame to the client with `data: <plaintext_frame_data>` and `event:` cleared.
   - `frame.Event == "zs-settle-group"`: open under `HeaderAAD(tx_id, ticket_id, "settle-group")`, decode, and cache the group, with no counter change. The client never sees it.
   - `frame.Event == "zs-receipt"`: AEAD-open at the current `frame_index` (then increment it), parse the JSON receipt, and run receipt verification + settle/protest. The client never sees it; the reference proxy optionally substitutes its own unsigned `zs.usage` frame when the client opted in via `X-Zs-Usage-Frame`.
   - Anything else: emit to the client verbatim; `frame_index` unchanged.
3. On any AEAD-open failure mid-stream, the proxy emits an OpenAI-shaped error frame followed by `data: [DONE]` and closes the stream (§ 10). Because the counter diverges, a reorder, drop or duplication of any encrypted frame shows up as an AEAD-open failure on the *next* encrypted frame, not necessarily the tampered one. That includes the receipt frame, which is then discarded rather than trusted.

The client sees a normal OpenAI stream, with no `event: zs` and no `X-Zs-Response-Key`.

##### Consuming the settlement tail

The `zs-settle-group` / `zs-receipt` / `[DONE]` frames are the **settlement tail**. They arrive *after* the frame that tells the caller its answer is finished. A consumer whose own caller has gone away (client disconnect, browser tab closed, SDK closing on `finish_reason: "stop"`, an SDK throwing on an error event) therefore has to choose at every frame: stop reading, or keep reading for the tail.

**Requirement.**
- Once a frame is *terminal*, a consumer MUST continue reading until `[DONE]` or stream end, even if the party it is proxying for is gone.
- It SHOULD bound that drain with its own timeout (the reference proxy uses 10s) and MUST NOT let a dead downstream socket abort it.
- Before any terminal frame, a consumer SHOULD cancel promptly on disconnect, so an abandoned request doesn't keep a node generating.

A frame is terminal when it is either:

| Terminal kind | Chat completions | `/v1/responses` |
|---|---|---|
| Generation complete | a choice's `finish_reason` is `stop` or `length` (**not** `tool_calls` — the node runs the tool and keeps generating) | `response.completed`, `response.incomplete`, `response.failed` |
| Error envelope | `{"error": {…}}` with no `"choices"` | `{"type": "error", …}` — the event union's error member, which carries no top-level `"error"` key |

**The verdict is read off the frame's own discriminator, never off its content.** For `/v1/responses` that means the top-level `type` member, not the presence of a terminal event name somewhere in the bytes.
- A consumer that substring-matches will classify `{"type":"response.output_text.delta","delta":"response.completed"}` as terminal. A tool-round status frame also embeds the model's own search query (§ 5.3.1 `action`), so a caller who asks about the Responses API can flip the verdict from inside their own prompt. Content must not steer a payer-safety signal.
- A cheap substring prefilter *ahead* of the confirming parse is fine and expected, since it keeps ordinary deltas off the parse path. It decides nothing on its own.
- Where a consumer cannot complete the check (a truncated frame that mentions a terminal type), it MUST fail toward terminal. A missed terminal drops the settlement tail; a spurious one only arms the drain early.

**Why both kinds, and why this is normative rather than a rendering nicety.**
- Dropping the tail after a *completed generation* costs the operator: no receipt and no co-signed settle, so the node's unilateral claim only finalizes at the deadline via `settleLapsed`.
- Dropping it after an *error frame* costs the **payer**, and is worse. Every node error path writes the error frame, then a zero-cost receipt, then `[DONE]`, so the tail is where the payer learns what it is being charged (zero, on that path) and gets the signed artifact to verify it. Without the receipt the payer cannot check `amount_charged`, cannot `protest()`, and cannot co-sign. The ticket sits in `PENDING_SETTLE` until `settleLapsed`, **which treats payer silence as acceptance of whatever the operator claimed**.

A consumer that treats an error frame as "stop reading" therefore turns every post-admission failure into an unverifiable, uncontestable charge.

**Reference implementation.** `proto/go/wire/stream_terminal.go` (`ClassifyStreamFrame`, `StreamErrorMessage`) and `proto/ts/src/wire/streamTerminal.ts` (`classifyStreamFrame`, `streamErrorMessage`), pinned against each other by `proto/testdata/stream_vectors.json` (regenerate: `cd proto/go && go test ./wire -run TestStreamTerminalVectors -update`). The classification is shared rather than re-derived per consumer because it is a payer-safety property, and two implementations answering it differently is exactly the failure above. Consumers: `proxy/internal/server/sse.go::forwardRawStream` (drain-vs-cancel on client disconnect, armed by `buildHayaiFrameFactory`) and the reference client's stream pipeline.

#### 5.3.1 Node-originated status events (ZeroSignal tool rounds)

During a server-side ZeroSignal built-in tool round (Responses API only), the node MAY emit sealed status frames so streaming clients can render an in-progress indicator while the tool executes. These frames use the same `event: zs` channel and sealing rules as any other encrypted frame: they increment `frame_index`, bind AAD identically, and are included in the receipt `body_hash`. The plaintext inside the envelope is an OpenAI-Responses-shaped event with a ZeroSignal-specific `type`:

```json
{"type":"response.zs_tool_call.in_progress","item_id":"zstc_<hex>","output_index":0,"tool":"zs_web_search","call_id":"call_abc123","action":{"type":"search","query":"algorand consensus"}}
{"type":"response.zs_tool_call.completed", "item_id":"zstc_<hex>","output_index":0,"tool":"zs_web_search","call_id":"call_abc123","action":{"type":"search","query":"algorand consensus","sources":[{"type":"url","url":"https://algorand.co/…"}],"icons":{"algorand.co":{"mime":"image/png","data_b64":"iVBOR…"}}}}
```

Fields:
- `type` — one of `response.zs_tool_call.in_progress`, `response.zs_tool_call.completed`.
- `item_id` — opaque `zstc_<hex>` identifier generated per tool call; the in_progress / completed pair for one call share the same `item_id`.
- `output_index` — index of this call within the iteration's built-in tool calls, 0-based.
- `tool` — the built-in tool type name (e.g. `zs_web_search`) so clients can label the round.
- `call_id` — the function call's `id` as it appeared in the model's `function_call` item, for downstream correlation.
- `action` — **optional**, since `proto_version` 9.4. What the round is doing, so a client can render "Searching for X" and list sources instead of a bare "Searching the web". See below.

##### The `action` object

`action` mirrors OpenAI's `web_search_call.action`, so a consumer that already renders OpenAI's native web search renders ZeroSignal's with the same code path. Two variants are emitted:

| `action.type` | Emitted for | Fields |
|---|---|---|
| `search` | `zs_web_search`, `zs_image_search` | `query` (string); `sources` (array, completed frame only) |
| `open_page` | `zs_web_read` | `url` (string) |

`sources[]` entries are `{"type":"url","url":"…"}` and carry **no title**. That is OpenAI's source shape, and the URL/title pairs already reach the client as `url_citation` annotations (§ 3d), so a renderer joins them by URL rather than putting scraped third-party text on a frame. Tools with nothing meaningful to show (`zs_get_time`, the image tools) emit no `action` at all, and neither does any call whose arguments don't yield a value. The field is omitted, never null.

A node MUST bound both `query` and `sources` (the reference implementation uses 512 bytes and 20 entries). The query is model-chosen, the sources come from a third-party backend, and the action rides two sealed frames per call plus the receipt `body_hash`.

URLs follow a different rule from the query: **bound, but never truncate.** A query is display text, so clipping it is cosmetic. A URL is actionable (consumers render it as a link), so a clipped one points at a different resource than the node fetched. A node MUST drop an over-long URL rather than shorten it (the round then advertises no action, or omits that source), and SHOULD emit only `http`/`https` URLs with a host.

**Consumers MUST NOT rely on that.** A caller receives these from an operator it does not control, so before turning any `url` or `sources[].url` into a link it MUST itself refuse schemes outside `http`/`https`. Otherwise a hostile node can place a `javascript:` or `data:` URL behind what renders as an ordinary source chip. The node-side rule above is hygiene; this one is the security boundary.

##### `action.icons` — inlined favicons

`icons` is **optional** and is a ZeroSignal extension with no OpenAI counterpart: the favicon of each source's site, inlined as bytes so the consumer renders a real site mark. It appears only on the `completed` frame.

```jsonc
"icons": { "algorand.co": { "mime": "image/png", "data_b64": "iVBOR…" } }
```

**The bytes, not a URL, are the point.** A consumer that rendered `<img src="https://thatsite.com/favicon.ico">` would disclose its IP address and a render timestamp to every host in a search result. Those hosts are selected by a third-party search backend, steered by a model-chosen query: an attacker-influenceable set, so this is a beacon channel rather than a decoration. Carrying the bytes on the sealed frame means a relay learns nothing and the consumer contacts nobody. A node MUST NOT substitute a URL for the bytes, and a consumer MUST NOT fetch a favicon itself from a `sources[].url` host.

`icons` accompanies a `search` round's `sources`. An `open_page` round MUST NOT carry it: there is no source chip to decorate, so the bytes would be spent on something no consumer displays.

The map key is the source URL's **WHATWG [`URL.hostname`](https://url.spec.whatwg.org/#dom-url-hostname)**: lowercased, port dropped, IDN in punycode, an IPv6 literal bracketed and canonically compressed. `www.` is **not** stripped.
- One external standard is named because URL parsers genuinely disagree. A key that differs by platform means the node fetches an icon and spends the frame bytes, and the consumer never finds it.
- Go's `net/url` applies no IDNA and strips IPv6 brackets, so a Go implementation must do that work itself to match.
- A consumer's display layer is free to trim `www.` for readability, but MUST NOT trim it from the lookup key.

`mime` MUST be one of `image/x-icon`, `image/png`, `image/gif`, `image/jpeg`, `image/webp`. A node MUST derive it by inspecting the bytes rather than trusting the serving site's `Content-Type`, which is set by a host the node does not control. **`image/svg+xml` MUST NOT be emitted.** SVG is an active document format, and these are third-party bytes that a consumer will inline into its own page.

**Consumers MUST NOT rely on that either.** Before constructing a `data:` URI a consumer MUST validate `mime` against its own allowlist and drop anything outside it, exactly as it must validate URL schemes above. The node-side sniff is hygiene; this is the security boundary.

A node MUST bound one icon's decoded size (**16 KiB**), the total base64 across one action (**96 KiB**), and the number of distinct hosts (**12**). These are fixed numbers, not implementation choices, so a consumer can re-apply them: it receives the frame from an operator it does not control, and cannot re-derive a bound it was never told.

Over-budget icons are **dropped, never truncated**, since half an icon is a broken image, not a smaller one. The two caps drop differently, on purpose:
- The host-count cap is a **prefix**: the first 12 entries in source order.
- The byte budget is **first-fit**: an icon too large for the remaining room is skipped, and later smaller ones still fit. A prefix here would let one large icon near the head blank every chip behind it.

Both favour the head of the source list, which is what a reader looks at first.

A node **MAY** omit an icon for a host it has already sent on the same stream, so a consumer **SHOULD** cache icons by host for the life of the stream. Neither failure is unsafe: an absent icon just means the consumer renders its generic fallback, which is also what any node below 9.4 and any host without a reachable favicon produce.

**`zs_web_read` MUST NOT carry an `action` on its `in_progress` frame.** This is normative, and it is the one asymmetry in the shape.
- A node emits in_progress frames for every call in an iteration *before* any of them execute. The `zs_web_read` provenance gate (§ 3d) runs per call at execution time.
- The gate cannot be hoisted: its allow-set accrues from search citations *within* the same iteration, so a read-after-search is not yet decidable when the frames go out.
- Advertising the URL up front would therefore render "Reading `<attacker URL>`" in the caller's UI for a read the node then refuses. That gives attacker-chosen text a trusted-looking surface, which is the indirect prompt injection the gate exists to stop.

A read's URL appears only on the `completed` frame, and only when the fetch actually happened.

The `action` is prompt-derived content. It is sealed to the caller like any other frame, so a relay cannot read it, and it falls under the same non-retention rule as every other content field: it MUST NOT be written to logs, traces, or metrics on the node or the proxy.

Client handling:
- Clients implementing the Responses API event switch SHOULD render these events (e.g. as "web search running…" / "web search complete") and MUST treat unknown `type` values as skippable, since they're not part of the OpenAI Responses event vocabulary.
- A client MUST tolerate an absent `action` (any node below 9.4, and any round with nothing to show) by falling back to a generic label.

The node emits in_progress frames immediately before executing the tool(s) for the iteration, and completed frames immediately after all executions return. Chat completions streaming has no in-progress event shape: the node emits nothing, and clients see a silent pause during tool execution.

#### 5.3.2 Node-originated image-tool progress events

A built-in image tool (`zs_image_generation` / `zs_image_edit`) can run for tens of seconds, so the node MAY emit additional sealed frames between a call's `in_progress` and `completed` status pair. They share that pair's `item_id`, so a client correlates them with the right placeholder. Like every frame in § 5.3.1 they ride `event: zs`, increment `frame_index`, and are folded into the receipt `body_hash`. A node MUST NOT emit any of them in plaintext, which would desync the consumer's frame index.

```json
{"type":"response.zs_image.progress","item_id":"zstc_<hex>","value":12,"max":20,"node":"KSampler"}
{"type":"response.zs_image.partial","item_id":"zstc_<hex>","partial_image_b64":"<base64>","mime":"image/jpeg"}
{"type":"response.zs_image.completed","item_id":"zstc_<hex>","response":{"created":1234567890,"data":[{"b64_json":"<base64>"}]}}
```

- `response.zs_image.progress` — sampling-step counters (`value` of `max`) for a determinate progress bar. `node` is the backend's stage label, advisory and omitted when empty. Carries no prompt or image content. Emitted zero or more times, operator-throttled.
- `response.zs_image.partial` — an intermediate low-resolution preview render, so the image can be shown resolving. Carries image **content**, so sealing is mandatory (a relay must not read a partial render). Emitted zero or more times, operator-throttled.
- `response.zs_image.completed` — terminal frame of a *streamed* `/v1/images/*` response (the dedicated image routes under `stream: true`, not the in-loop tool path). `response` is the same `{created, data:[…]}` body the buffered route returns, nested so a client parses it identically. Emitted once, immediately before the `zs-receipt` frame and `[DONE]`.

The in-loop tool path delivers its finished image via the `zs_image_generation_call` / `zs_image_edit_call` marker item (§ 3d), not via `response.zs_image.completed`. As in § 5.3.1, a client that doesn't know these types MUST skip them.

## 6. AEAD construction

- **Algorithm**: ChaCha20-Poly1305 (RFC 8439).
- **Key size**: 32 bytes (`wire.ResponseKeySize`).
- **Nonce size**: 12 bytes (`wire.NonceSize`, matches `chacha20poly1305.NonceSize`).
- **Tag size**: 16 bytes (`chacha20poly1305.Overhead`), appended to the ciphertext by `Seal`.
- **Nonce source**: node-generated, and unique per `response_key`. Both reference implementations draw a fresh random 12-byte nonce from a CSPRNG for every sealed payload (body, frame, and header). Even a very long stream seals far fewer than 2^32 payloads under one key, the usual limit for random 96-bit nonces. A per-response monotonic 96-bit counter is an equally valid alternative.
- **Base64**: standard alphabet with padding (`base64.StdEncoding`), no URL-safe variant, no line wrapping.

### AAD (Additional Authenticated Data)

Every sealed payload (non-streaming bodies, § 5.2, and each encrypted SSE frame, § 5.3) MUST be sealed with AAD constructed as follows. This binds each ciphertext to its request and, for streams, to its position in the stream. A MITM cannot splice a response from request A onto request B, or reorder, drop or duplicate frames within a stream, without breaking authentication.

All AAD values use a common protocol tag `"zs"`, followed by a domain tag that makes body AAD and frame AAD disjoint.

**Body AAD** (non-streaming responses):

```
BodyAAD(tx_id, ticket_id) = "zs" || 0x00 || "body" || 0x00 || utf8(tx_id) || 0x00 || utf8(ticket_id)
```

**Frame AAD** (encrypted SSE frames):

```
FrameAAD(tx_id, ticket_id, frame_index) = "zs" || 0x00 || "frame" || 0x00 || utf8(tx_id) || 0x00 || utf8(ticket_id) || 0x00 || uint64_be(frame_index)
```

**Header AAD** (sealed post-response metadata: the `X-Zs-Receipt` / `X-Zs-Settle-Group` header values, and the `zs-settle-group` SSE frame):

```
HeaderAAD(tx_id, ticket_id, name) = "zs" || 0x00 || "hdr" || 0x00 || utf8(tx_id) || 0x00 || utf8(ticket_id) || 0x00 || utf8(name)
```

where:
- `0x00` is a single NUL byte separator;
- `utf8(tx_id)` is the UTF-8 encoding of the `algorand_tx_id` string (Algorand base32 txids are pure ASCII, so this is trivially stable);
- `utf8(ticket_id)` is the inner-request header's `ticket_id` field, or the empty string when absent. The separator is always present, so empty and non-empty produce distinguishable AAD. (A prompt-carrying node never seals with an empty one; a missing `ticket_id` is refused at admission, § 3a.)
- `uint64_be(n)` is `n` encoded as an 8-byte big-endian unsigned integer;
- `name` is one of the two metadata names `"receipt"` / `"settle-group"`.

Neither `tx_id` nor `ticket_id` appears in cleartext anywhere on the wire. Both endpoints reconstruct the AAD from state they already hold: the caller generated the tx id and reserved the ticket, and the node decrypts both out of the inner-request frame. AAD is *reconstructed*, never carried.

The three domain tags (`body` / `frame` / `hdr`) keep the constructions disjoint, so a body ciphertext cannot be replayed as a frame or as a header value. Within `hdr`, `name` keeps the two metadata values disjoint, so a receipt ciphertext cannot be presented as a settle group.

**Frame index semantics:**
- `frame_index` starts at `0` for the first `event: zs` frame emitted in the response and increments by 1 for each subsequent **frame-AAD-sealed** frame: every `event: zs` content frame **plus the sealed `event: zs-receipt` frame** (§ 5.3), which consumes the next index after the final content frame.
- Frames that are not frame-AAD-sealed do **not** consume a `frame_index`: the plaintext `[DONE]` sentinel, SSE comments and keepalives, and the `zs-settle-group` event (sealed, but under `HeaderAAD`; it carries no index and is emitted at most once).
- Both proxy and node MUST apply this rule consistently; otherwise the counters diverge and AEAD-open fails.
- 64 bits of counter space is never exhausted by any real stream.

**Reference implementation:** `wire.BuildBodyAAD`, `wire.BuildFrameAAD`, and `wire.BuildHeaderAAD` in `envelope.go` of the `github.com/TxnLab/zerosignal/go` module are the normative Go implementations. All three are golden-vectored in `proto/testdata/vectors.json` against the TypeScript mirror.

### Wire layout

The concatenation order on SSE frames is **nonce || ciphertext**. The reference `wire.DecryptSSEDataValue` helper splits on `wire.NonceSize`, so an implementation using a different order fails authentication cleanly.

## 7. Algorithm: full request lifecycle

Numbered walkthrough from client submission to client response. Code names for each step are collected in the Reference list at the end.

**Non-streaming request:**

1. The client sends `POST /v1/chat/completions` with a normal OpenAI JSON body and `Content-Type: application/json`.
2. The proxy reads the plaintext body. `"stream"` is `false` (or absent), so it takes the non-streaming path.
3. The proxy already holds the reserved ticket from a prior `/v1/zs/reserve` round-trip (§ 3a), including the node-signed `presigned_open_txn` (gtxn[1]) and the unwrapped `K_response`. To produce `tx_id` it completes the open group: it signs gtxn[0] (usdcPayment, fee=0, sender=payer_addr) against the group hash already pinned into gtxn[1], submits the 2-tx group atomically, and uses gtxn[1]'s app-call txid as `tx_id`.
4. The proxy resolves the node's age recipient.
5. The proxy seals the request:
   - It generates an ephemeral X25519 identity, or reuses the one already held from reserve.
   - It frames the inner request: `"zsrq" || 1 || uint32_be(len(headerJSON)) || headerJSON || body`, where `headerJSON` carries `reply_to_public_key`, `algorand_tx_id`, `ticket_id`, `admission_tag` (§ 4).
   - It age-encrypts the inner frame to the recipient → binary ciphertext bytes.
   - It builds the envelope `{ciphertext: base64(ct)}`, with nothing else.
   - It returns the envelope JSON and the ephemeral identity. The ephemeral identity lives only in the handler's stack/heap.
6. The proxy forwards the envelope JSON with `Content-Type: application/vnd.zs+json`.
7. The proxy sends `POST /v1/chat/completions` to the operator's base URL from the on-chain registry. There is no `Authorization` header: admission is via the sealed envelope, not a bearer token, and the proxy actively drops any `Authorization` that survives in the request headers.
8. The node receives the request:
   - It decrypts `ciphertext` with its in-memory ephemeral identity set: the current key, falling back to the previous key inside the decrypt-overlap window (§ 3c, § 8). There is no long-lived identity.
   - It decodes the inner-request frame → `body` plus the header's `reply_to_public_key`, `algorand_tx_id`, `ticket_id`, `admission_tag`. A frame without the `zsrq` magic is rejected here.
   - It parses `reply_to_public_key` as an age X25519 recipient.
   - It verifies admission: ticket lookup, admission-tag verify, `Consume`, and the open app-call check (§ 9).
   - It processes the OpenAI request against the real model.
   - It builds a node-signed `UsageReceipt` (§ 3a).
   - It composes the atomic settle group: it pre-signs gtxn[0] (`asOperator=true`, fee=6×minTxnFee) against the unsigned gtxn[1] payer-ack template (sender = `t.payer`, fee=0, identical args). It computes `group[0].txid` and stamps it on the settlement-ledger row at `MarkServed`. Soft failure on algod outage: the settle group is omitted from the response, and the operator's settlement driver becomes the sole finalize path.
   - It reuses the `K_response` committed at reserve (the pre-committed K, not a fresh key).
   - It age-encrypts the raw 32 bytes to the `reply_to_public_key` recipient → wrapped_key bytes.
   - It seals the plaintext response body with ChaCha20-Poly1305 under `response_key`, with a random 12-byte nonce and AAD = `BodyAAD(tx_id, ticket_id)` (§ 6) → `ct_with_tag`.
   - It seals the receipt and (when composed) the settle group under `response_key` with `HeaderAAD(tx_id, ticket_id, name)` (§ 6).
   - It returns HTTP 200 with `Content-Type: application/vnd.zs+json`, `X-Zs-Response-Key: base64(wrapped_key)`, `X-Zs-Receipt: <sealed>`, optionally `X-Zs-Settle-Group: <sealed>`, and body `{nonce: base64(nonce), ciphertext: base64(ct_with_tag)}`.
9. The proxy's non-stream responder runs:
   - It unwraps `X-Zs-Response-Key` with the ephemeral identity → `response_key`.
   - It rebuilds `BodyAAD(tx_id, ticket_id)` and AEAD-opens the body → plaintext OpenAI response. A response sealed under a different request's `tx_id` fails the open.
   - It opens `X-Zs-Receipt` and `X-Zs-Settle-Group` (when present) under their `HeaderAAD` names, decodes them, verifies the receipt's commit-K and body-hash, and records the spend.
   - It sets `Content-Type: application/json`, strips all `X-Zs-*` headers, copies the other upstream headers, and writes the plaintext to the client.
   - Only then, in the background, it submits the settle: if the receipt checked out, it signs gtxn[1] of the settle group and broadcasts the atomic group. Without a settle group it falls through to the operator's settlement driver (no proxy-side settle action). The client never waits on this algod round-trip.
10. The client receives what looks like a normal OpenAI response.
11. The handler returns. The ephemeral identity and `response_key` go out of scope.

**Streaming request:** the same up to step 5; step 6 then takes the streaming path.
- The response detection of step 9 runs in the frame factory instead. The response key is unwrapped once, when the upstream headers arrive, and the proxy initializes `frame_index = 0`.
- Each subsequent SSE frame either passes through (no `event: zs`; `frame_index` unchanged) or is AEAD-opened with `response_key` and AAD = `FrameAAD(tx_id, ticket_id, frame_index)`, after which `frame_index` is incremented.
- After the final encrypted content frame the node emits `event: zs-settle-group` (when present; sealed under `HeaderAAD`, no counter change), then the **sealed** `event: zs-receipt` frame at the next `frame_index` (§ 5.3 "Out-of-band settlement event types").
- The proxy caches the group, AEAD-opens and verifies the receipt, and submits the atomic settle group inline when the receipt frame arrives, then forwards the trailing `[DONE]` to the client.

**Reference** (Go names, by step):
- 2: `streamableRequest`. 4: `s.recipientProvider.Recipient(ctx)` → `age.Recipient`.
- 5: `wire.WrapRequest(body, tx_id, ticket_id, admission_tag, recipient)`, or `WrapRequestWithIdentity(...)` when reusing the reserve-time identity; `age.GenerateX25519Identity()`; `age.Encrypt(w, recipient)`; `RequestEnvelope`.
- 6–7: `forwardRawNonStream`; the base URL is `op.BaseURL`; `buildOperatorRequest` drops `Authorization`.
- 8: `age.ParseX25519Recipient`; `VerifyOpenAppCall`; `ticket.UsageReceipt`; the settle txid via `crypto.GetTxID`; the committed key is `rc.admitted.Key`.
- 9: `wire.UnwrapResponseKey(hdr, ephemeral)`; `wire.DecryptBody(respBody, response_key, tx_id, ticket_id)`; `wire.OpenSealedHeader`; `Wallet.AckSettle` signs and broadcasts, run after the write by `submitAfterResponse`.

## 8. Security properties

What the scheme guarantees:
- **Confidentiality of request body** against every party between the proxy and node, including TLS-terminating CDNs, HTTP caches, corporate proxies, and on-path observers.
- **Confidentiality of response body / frames** symmetrically.
- **Forward secrecy per request**: the proxy's ephemeral X25519 keypair is generated fresh per request and discarded after the response. Compromise of the node's long-term identity does not retroactively decrypt prior responses, which were sealed under `response_key`s only ever wrapped to ephemerals that no longer exist.
- **Forward secrecy of the request body (mandatory, key-erasure)**: every request is sealed to the node's signed ephemeral recipient (§ 3c, § 4), the only encryption recipient there is.
  - The ephemeral private key is in-memory-only and is cryptographically erased on rotation and on restart. Once it is erased, captured request ciphertext sealed to it can no longer be decrypted, even by an attacker who later obtains the node's on-disk secrets (only the Ed25519 signing mnemonic, which never was an encryption key). The concrete attacker is a single-hop relay that logs envelopes and later compromises the target. This is the non-TEE analog of a per-boot key.
  - There is **no on-chain anchor and no fallback**, so the protection is **unconditional**: there is nothing to downgrade to. A sealing party that finds no verified, unexpired, lifetime-capped ephemeral refuses the operator and tries another (the reference proxy surfaces `503 no_ephemeral_capacity` once every candidate is exhausted). The node itself 503s rather than serve a dead block: `no_fresh_ephemeral` on `/v1/zs/details`, `node_ephemeral_unavailable` on `/v1/zs/reserve`.
  - The signed `issued_at` and the hard `MaxEphemeralLifetime` cap bound how long any one key can seal, so the blast radius of a key-retaining node is capped regardless of honest zeroing.
  - The one residual: traffic captured *before* the rotation that erased its sealing key stays exposed only until that key is dropped (bounded by the rotation period).
- **Integrity of each response frame individually**: each encrypted SSE frame carries its own ChaCha20-Poly1305 tag, so tampering with one byte of any frame makes that frame's decryption fail.
- **Request-response binding**: every sealed payload's AAD contains the request's `algorand_tx_id`, so a ciphertext sealed for request A cannot be spliced onto request B; AEAD authentication fails at the proxy. Attackers cannot cross-wire responses between concurrent requests even if they control the channel.
- **Frame-order integrity within a stream**: each encrypted SSE frame's AAD contains its 0-based index within the stream, so a MITM cannot reorder, drop or duplicate encrypted frames without the next frame's decryption failing. Dropping the *final* frame is still undetectable at the AEAD layer, since there is nothing after it to fail on; application-level completion signals (e.g. `finish_reason` in the last chunk) are still required to detect truncation.
- **Key-confidentiality**: the response symmetric key is only ever transmitted in wrapped form (`X-Zs-Response-Key`), which requires the proxy's ephemeral private key to open.

What the scheme does **not** guarantee:
- **Proxy authentication to node**: the proxy has no long-term key material. The node accepts any caller who can open a valid `Payment + escrow.open` group on-chain and produce a sealed envelope binding the resulting txid. It does not distinguish a legitimate proxy operator from anyone else who satisfies that admission. Defense in depth: run TLS between proxy and node so traffic isn't observable on the wire.
- **Request metadata privacy**: URL path (`/v1/chat/completions` vs `/v1/responses`), HTTP method, timing, ciphertext size, and client-supplied headers the proxy may forward are all visible on the wire between proxy and node.
- **Hiding the existence of encryption from a passive observer**: the content-type and vendor header reveal that ZeroSignal is in use.
- **Replay protection at the envelope-crypto layer**: none, and it isn't needed there.
  - Prompt-carrying requests are ticket-gated (§ 3a) and tickets are single-use (`Consume`), so a recorded envelope re-submitted after the original was served fails at admission step 1 with `402 ticket_invalid`.
  - The `ticket_id` rides *inside* the seal, so that rejection lands after the age-decrypt rather than before it. This costs nothing: the admission tag commits to `sha256(plaintext_body)`, so the decrypt is the node's forced-work floor either way, and there is no cheaper pre-decrypt gate to lose.
  - Nothing in the AEAD/envelope construction itself rejects a replay, so the protection is only as strong as the admission gate. That gate is mandatory on every prompt endpoint; there is no unadmitted path.
  - A node MAY additionally reject duplicate `algorand_tx_id` values, but the burned ticket already covers the replay case.
- **Anti-downgrade against an active MITM between proxy and node**: an attacker who controls the channel can strip `X-Zs-Response-Key` to attempt a downgrade to plaintext. The proxy refuses unsealed 2xx responses (§ 5.1), so a downgrade produces a 502 to the client rather than a silent leak. TLS between proxy and node is still the primary defense. For transport-level error responses (status >= 400, plaintext OpenAI-shaped JSON) the proxy passes through, since pre-envelope errors are unauthenticatable by construction.
- **Truncation detection at the protocol layer**: dropping the trailing frames of a stream produces a valid-looking but incomplete response. OpenAI's chunk schema already carries this signal (`finish_reason`, `[DONE]` sentinel) at the application layer.
- **Ephemeral-key survival across restart**: the signed ephemeral sealing key (§ 3c, § 4) is in-memory-only and dies on restart **by design**. That erasure *is* the forward secrecy, so it MUST NOT be persisted.
  - There is no durable anchor to fall back to. A request sealed to a pre-restart (or already-rotated) ephemeral fails to decrypt; the sender refetches `/v1/zs/details` for the current ephemeral and retries, against this or another operator. A node with no fresh ephemeral 503s rather than serve a dead block.
  - Ephemeral rotation is a **decrypt-only** concern. It plays no role in ticket signing, receipt signing, response sealing or settlement, so issued tickets, signed receipts and on-chain settlement are unaffected by a rotation or restart.

## 9. Algorand transaction ID semantics

The 2-tx atomic open group is **co-composed**:
- The serving node's signing key signs gtxn[1] (the `escrow.open()` AppCall) at reserve time and delivers it to the proxy as `presigned_open_txn`.
- The proxy signs gtxn[0] (`usdcPayment` AssetTransfer, sender = `payer_addr`) at request time and broadcasts the assembled group.
- There is no feePayment leg; the box MBR is drawn from the payer's prepaid pool at `open()`.

The proxy places gtxn[1]'s app-call txid in the envelope's `algorand_tx_id` field, and the node resolves it with a targeted per-txid lookup (`algod.PendingTransactionInformation(txid)`). Group id is **not** used as the lookup key because algod has no "find pending txn by group id" primitive; the proxy keeps it for audit/dispute logging only.

On admission success the node verifies the pending app call, checking that:

- `Txn.sender == node_signing` (the serving node's hot key, consensus-verified; § 3a "Operator authentication");
- the ABI args `(ticketId, operatorId, nodeId, payerAddr, maxPrice)` match the ticket the proxy is admitting against. `expiresAt` and `settlementGraceSeconds` are **not** re-checked: the node composed and signed this very txn at reserve time, so those args are node-authored and consensus covers them on-chain. There is no `commitK` ABI arg at all; the commitment lives only in the signed ticket (§ 3a "Why the response key is committed, not chosen");
- `payerAddr` (decoded from the gtxn[1] ABI arg, NOT from gtxn[1]'s `Sender`) matches the payer bound to the ticket at reserve time, when the reserve carried a verified payer signature.

The node does not itself compare `payerAddr` with `gtxn[0].Sender` (the usdcPayment). That consistency is checked payer-side by the group-shape check in `VerifyOpenGroup` (below), and asserted on chain by `open()` (`usdcPayment.sender == payerAddr`).

The payer address comes from the ABI arg rather than `Txn.Sender` because, under the consensus-verified-operator model, the AppCall's sender is the serving node's signing address, not the payer. This payer address is what unlocks safety-identifier injection downstream.

**The payer runs the mirror-image check before signing.** The delivered `presigned_open_txn` is entirely counterparty-composed, including the `usdcPayment` the payer is about to sign. A payer that signed blind would be trusting the node with an arbitrary asset transfer (any amount, any receiver) grouped with an arbitrary app call. The reference implementation therefore verifies the whole group **before** producing the payer's signature:
- group shape, and a group id that both members carry **and** that equals the group id recomputed over the two members as presented. Agreement alone is not enough: the payer's signature covers the group id, so a gid committing to a different gtxn[1] than the one shown would bind that signature to a sibling the payer never checked;
- gtxn[0] is a USDC transfer of exactly `max_price` from the payer to the app account, with `fee == 0` and no `rekey_to`, `asset_close_to`, `asset_sender`, `note` or `lease` (the Go reference also refuses a payment-only `close_remainder_to`). The first four would make the payer's signature do more than fund the escrow: rekey hands over the account, close-to sweeps the payer's remaining USDC, asset-sender turns the transfer into a clawback, and a fee spends payer ALGO that gtxn[1] is meant to pool. `open()`'s TEAL also rejects those four, and since the payer's signature covers the group id, a rejected group voids it. That backstop runs only when gtxn[1] really is `open()` on our app, and only on an app whose installed approval program carries those asserts, so this payer-side check stays mandatory. Note and lease move no funds but are node-chosen bytes published under the payer's signature; the TEAL does not check them;
- gtxn[1] is a NoOp call (a ClearState call skips `open()`'s approval program entirely, so the payer's USDC would land in the app with no ticket box to refund against) to `open()` on the expected app, with every ABI arg pinned to the **signature-verified ticket**, including the two window args the node-side check skips: `expiresAt` must equal `ticket.expires_at`, and `settlementGraceSeconds` is pinned to `0` (the contract's `grace` default).

Refund recovery depends on the window pin: it is what makes the payer's computed `refundInactive` deadline `D = expires_at + default grace` match the on-chain one; a node-authored non-zero grace would silently push `D` out past the payer's refund logic.

The payment sibling is **not** re-verified on the node. Algod only admits an `open()` to the mempool after evaluating the contract's TEAL, which already gates gtxn[0] (AssetTransfer, asset_receiver == app address, xfer_asset == `usdcAssetId`, asset_amount == `max_price`, fee == 0, no rekey_to / asset_close_to / asset_sender) and the prepaid-pool draw (`open()` asserts the payer is opted in with sufficient `algoBalance`, then `openTickets++`). The per-ticket box MBR is not a payment leg; it is reserved against the payer's pool.

**Settle-side txids.** At compose time the node also computes the on-chain txid of gtxn[0] of the atomic settle group (the operator's first half). The txid is the hash of the canonical, sig-stripped txn body, so the signature does not affect it and the txn lands under this txid whoever broadcasts it. The node stamps it on the settlement ledger row at `MarkServed`, so the row carries the on-chain reference even when the proxy, not the operator's settlement driver, submitted finalize. Computing the txid correctly requires the algod genesis ID and genesis hash on the txn; both are static per network and cached on the node's escrow client.

**Init precondition.** The escrow app account MUST have been opted into the configured `usdcAssetId` via the contract's `init()` method before any `open()` group is admitted. This is one-shot per deploy and handled by the bootstrap CLI; node and proxy callers do not need to retry against it. The payer wallet MUST also be opted into the same USDC asset before issuing requests, since algod rejects asset-transfer txns from non-opted-in senders at admission time.

The field is cryptographically bound into AEAD AAD per § 6. It is not echoed on the response: a response sealed under a different request's `algorand_tx_id` fails to AEAD-open at the proxy, which is the same rejection an echo check gave, with one fewer identifier on the wire.

Reference: the node's app-call check is `proto/go/escrow.VerifyOpenAppCall`; the payer's pre-sign check is `proto/go/escrow.VerifyOpenGroup` (`SubmitPresignedOpenGroup` takes the spec and refuses first); settle txids use `crypto.GetTxID(SignedTxn)`.

**Invariant:** the value is a 52-character base32 string (no padding). Implementations MUST treat it as opaque at the wire level.

## 10. Error handling

**Infrastructure failures vs. protocol refusals.** No component of this protocol
ever emits `504`. A relaying node answers a failed forward with `502
relay_upstream_unreachable`, and every other relay code is `400`/`404`/`502`/`503`
(§ 3f). A target node's own refusals always carry an OpenAI-shaped `error.code`.

So a transient-shaped status carrying **no** `error.code` did not come from the
protocol. It came from an operator's CDN, ingress or load balancer, most often
while the node behind it restarts. The transient-shaped cases are the statuses
`408`, `425`, `429`, `500`, `502`, `503`, `504` and Cloudflare `520`–`527`, plus
a transport failure that produced no response at all (the exact set is
`retryableStatuses`, Reference below). A `4xx` outside
`{408,425,429}` with no code is a genuine refusal, not weather.

The two classes deserve opposite treatment. A refusal is an answer, and
re-asking cannot change it; an infrastructure fault clears on its own within
seconds. Callers classify with the shared primitive and retry only
infrastructure faults, on one schedule that both the reference proxy and the
reference client follow:

- **Per candidate**, up to 3 attempts (immediate, +500 ms, +1500 ms), **rotating
  the relay hop each time**. Rotation is what actually clears a bad front door,
  and it is the only thing that helps when the candidate list has one entry (a
  `previous_response_id` continuation or a strict affinity pin, § 3a).
- **Across the pool**, up to 4 sweeps (immediate, +4 s, +12 s, +30 s), entered
  only when *every* candidate failed transiently and none refused the request.
- **60 s overall ceiling**. A server-supplied `Retry-After` overrides the table
  whenever it is longer.

Two invariants bound this:
- Retrying stops the moment any candidate gives a considered refusal (sizing,
  price, payer-scoped, busy). That is the real error, and the caller gets it
  immediately.
- A sweep can only run **pre-payment**. Once `escrow.open` has committed, the
  only retryable failure is a relay-generated hop error. That proves the target
  never received the envelope and so never consumed the ticket, so the
  byte-identical sealed request may be re-sent through a different relay. An
  ambiguous post-payment failure (a target-side `504`, a transport error) is
  **not** retried: the node may be mid-generation, and a second submission would
  collide with a ticket already consumed.

Reference: the status set is `proto/go/transient`'s `retryableStatuses`. The
classifier is `proto/go/transient`, mirrored in `proto/ts/src/transient` and
golden-vectored in `proto/testdata/transient_vectors.json`.

Attribution follows the same verdict. A relay-generated code faults the relay,
and a `relay_upstream_unreachable` claim is treated differentially (§ 3f).

An infrastructure failure with **no** code is unattributable *from the response
body alone*, and guessing does active harm in both directions: crediting keeps a broken
relay in rotation, and blaming benches a healthy target. On a **relayed**
request, though, the caller holds route evidence the body does not carry, and
refines the verdict with it (`transient.NarrowRelayed`):

| Evidence | Charged to | Why |
|---|---|---|
| The **caller's own** cancel or deadline fired | **neither** | Says nothing about either hop. Checked first, because it is otherwise indistinguishable from a dial failure and would charge a relay for a socket the caller tore down. |
| No response at all (transport failure) | **relay** | The socket the caller opened was the relay's; there is no marker to be missing. |
| `X-Zs-Relay-Hop` absent and the status is *front-door shaped* (`425`, `429`, `500`, `502`, `503`, `520`, `521`, `522`, `523`, `525`–`527`) | **relay** | A relay marks every response its handler produces. This one is unmarked, and the status says the request never reached that handler: the shape a relay's own edge produces when it is down, refusing, or failing ahead of the handler. |
| `X-Zs-Relay-Hop` absent, but the status means *took too long* (`408`, `504`, `524`) | **neither** | "Relay wedged" and "relay waiting on a slow target" are indistinguishable (note below). |
| `X-Zs-Relay-Hop` present | **target**, differentially | The relay ran and copied a status back. This is the same shape of claim as `relay_upstream_unreachable` ("I forwarded, and this is what I got"), so it takes the same differential treatment (§ 3f), never face value. |

**Why timeouts charge neither.** A relay is byte-transparent: it writes nothing
until the target's headers arrive, so it cannot flush its marker without
committing to a status it does not yet know. For the whole forward window it
looks idle to its own gateway, which is what makes the two cases
indistinguishable. `522` is different: it is a *connect* timeout, and
does prove the relay unreachable.

**The front-door set** is enumerated exhaustively above. It is **not** derived as
"every retryable status except the timeouts", because a derived set would
silently absorb any future addition to the retryable list into "charge the
relay". `429` is in it on purpose, even though "come back later" is a capacity
signal rather than a fault: otherwise a relay's throttle answering an unmarked
`429` would read as a **target-side** failure and bench a node the request never
reached. The penalty is self-limiting (soft downrank, three consecutive
strikes, any successful forward resets it).

Two properties are load-bearing:
- The marker only ever moves an *unattributed* verdict. An attributed one passes
  through untouched, so a coded response still names its own hop. The narrowing
  answers **who**, never **whether**: it may not flip retryability.
- A caller MUST NOT charge a hop for its own cancellation or client-side
  deadline.

**Discovery-probe exception.** One deliberate exception to "the marker never
outranks a coded body" is the **discovery probe** (the proxy's and the client's). It reads
marker absence status-first, ignoring `error.code` entirely.
- It may, because it only chooses an error *type* (rotate to another relay,
  versus record the target as unreachable) and never flips retryability.
- It matters because a front door routinely emits its own coded JSON (an Envoy
  `upstream_connect_error`, or a node's per-IP throttle answering a coded `429`
  ahead of the relay handler), and attributing those to the target evicts a
  healthy node from discovery.
- The two probes MUST agree on this; the dispatch path MUST NOT adopt it.

A verdict still unattributed after this narrowing is the genuinely undecidable
residue: a gateway timeout from any relay. It is resolved by **rotation**, which
is therefore a permanent part of the design. Reaching the same target through a
different relay proves the first one was at fault; every relay failing proves
the target was, and charges nobody.

An operator behind a CDN or ingress MUST ensure `X-Zs-Relay-Hop` survives to the
caller. An edge that strips unknown response headers turns every code-less
connect failure that relay forwards into a penalty against itself.

The marker grants a dishonest relay no new power. One that wants a healthy
target benched can already emit `relay_upstream_unreachable` and reach the
target attribution directly; routing the marked case to the same attribution
puts it in the same differential path rather than a new one.

| Failure | HTTP status | Client-facing behavior |
|---|---|---|
| Plaintext POST to `/v1/chat/completions` or `/v1/responses` (Content-Type ≠ `application/vnd.zs+json`) | 400 | Node returns an OpenAI-shaped `bad_envelope` error; proxy passes through. There is no plaintext path on prompt-carrying endpoints. |
| Sealed envelope whose plaintext is not an inner-request frame (missing the `zsrq` magic, or an unknown frame version) | 400 | Node returns `bad_envelope`. Cross-major peers are normally dropped at discovery (§ 3c), so this is a backstop. |
| 200 reserve response the caller cannot age-open with its `proxy_recipient` identity | Proxy-authored `invalid_reserve` | Should not happen against a compliant node; the caller sealed the request declaring that recipient. Treat as an operator fault and try another candidate. |
| Malformed request envelope (JSON parse, bad base64, missing field) | 400 | Node returns an OpenAI-shaped error; proxy passes through (pre-envelope transport error). |
| Age decryption of `ciphertext` fails on node side | 400 | Same as above — node-authored error. |
| Missing `X-Zs-Response-Key` on a 2xx upstream response | 502 `proxy_error`, `operator_unsealed_response` | Proxy refuses; the operator violated §5.1 by returning a successful response unsealed. |
| `X-Zs-Response-Key` set but `Content-Type` ≠ `application/vnd.zs+json` | 502 `proxy_error`, `operator_inconsistent_response` | Proxy refuses; the operator set a key but did not seal the body. |
| Missing/invalid `X-Zs-Response-Key` on an otherwise-encrypted-looking response (e.g. malformed key value) | 502 `proxy_error`, `response_handler` | Proxy emits an OpenAI error envelope. |
| Age decryption of `X-Zs-Response-Key` fails | 502 `proxy_error`, `response_handler` | Same — proxy error. |
| ChaCha20-Poly1305 AEAD-open fails (tag mismatch) on a non-streaming body — including a response spliced from a different request, which fails on the `algorand_tx_id` / `ticket_id` AAD mismatch | 502 `proxy_error`, `response_handler` | Proxy error. |
| ChaCha20-Poly1305 AEAD-open fails on an SSE frame mid-stream (including reorder/drop/duplication detected via AAD frame-index mismatch) | Stream already started (status already sent; likely 200) | Proxy emits `data: {"error": {...}}\n\n` then `data: [DONE]\n\n` and closes the stream, the same as any other mid-stream failure in the proxy's SSE pump. |
| Upstream TCP error / timeout | 502 `proxy_error`, `upstream_unreachable` | Proxy error. |
| Upstream LLM provider returned a transient overload (`429`/`502`/`503`/`504`) that the node's bounded in-place retry could not ride out | Streaming: sealed error frame then `[DONE]`; non-streaming: node-authored sealed body carrying the upstream's HTTP status | `code=provider_overloaded`, node-authored. Transient; client should retry shortly. See "`provider_overloaded`" below. |
| Pre-envelope transport error from the node (status >= 400, plaintext `application/json`, no `X-Zs-Response-Key`) | Whatever the node returned | Passed through unchanged so the client sees the cause (`ticket_required`, `bad_envelope`, etc.). |
| Reserve refused for capacity (`active tickets >= max_active_tickets`) | 429 `invalid_request_error`, `no_capacity` | Plaintext OpenAI-shaped error on the reserve endpoint; `Retry-After` header set. Proxy should try another operator or wait. |
| Reserve refused for unknown model — or a priced model the operator's backend isn't currently serving | 400 `invalid_request_error`, `unsupported_model` | Proxy should skip this operator for this model. |
| Reserve refused because the operator's upstream LLM backend is unreachable (failed the node's periodic health probe) | `503 server_error`, `provider_unavailable` | Node-authored; transient. The operator also advertises zero models on `/v1/zs/details` while in this state. Proxy should try another operator and re-poll the operator's `/v1/zs/details` before routing to it again. |
| Reserve validation (missing model, zero tokens) | 400 `invalid_request_error`, `invalid_reserve` | Proxy-side bug if this fires in production. |
| Request body has no `max_tokens` / `max_completion_tokens` / `max_output_tokens`, no per-model default, and the proxy's global fallback is disabled (`fallback_max_output_tokens: 0`) | 400 `invalid_request_error`, `max_output_required` | Emitted by the proxy before reserve — the node needs a concrete output ceiling to compute `max_price`. Does not fire in the default config, where the global fallback supplies a ceiling for omitting clients. |
| Reserve price computation overflow | 400 `invalid_request_error`, `price_overflow` | Token counts too large for the configured rates; proxy should reduce `max_output_tokens`. |
| Sealed request with no `ticket_id` | 402 `invalid_request_error`, `ticket_required` | Proxy must call `/v1/zs/reserve` first and include the returned ticket id. |
| Sealed request with unknown/expired/consumed `ticket_id` | 402 `invalid_request_error`, `ticket_invalid` | Ticket expired before payment arrived, or replay detected — obtain a fresh ticket. |
| Sealed request whose inner-header `reply_to_public_key` is not the ticket's reserve-time `proxy_recipient` | 402 `invalid_request_error`, `reply_to_mismatch` | Caller must reuse the reserve-time ephemeral identity as the envelope's reply-to (§ 4). Checked before `Consume`, so the ticket survives — re-send with the correct identity. |
| Sealed request whose body `model` differs from the ticket's reserved model | 400 `invalid_request_error`, `model_mismatch` | Sealed, with a zero-cost receipt, so the escrow settles at zero. Reserve for the model you intend to call — the ticket's model, not the body's, determines the rates and limits. |
| Sealed request whose on-chain payment verification failed at admission (algod lookup error, txn not found in the pool within the node's poll window, or ABI args ≠ ticket) | 402 `invalid_request_error`, `payment_verification_failed` | The ticket was consumed before verification ran and is **burned** (§ 3a "Payment-verification failure burns the ticket"). **Re-reserve**; never resubmit the same `ticket_id`, which now fails as `ticket_invalid`. If the `open()` group did confirm on-chain, the payer recovers the escrowed `max_price` via `refundInactive` after `expires_at + grace`; the reference proxy's refund watchdog automates this. |
| Second `escrow.settle` call from the same side as the pending claim, with args that differ from it | On-chain revert `same side cannot re-claim with different args` | Caller-logic bug: only the counterparty of the pending claim can answer it with different args. A same-side re-claim with byte-for-byte matching args is a no-op (§ 3a "Settlement windows"). See "Settle outcomes" below. |
| Second `escrow.settle` call from the counterparty, with args that differ from the pending claim | No revert; the ticket transitions to `STATUS_FROZEN` | The counterparty disagreed with the first side's claim. It proceeds to off-chain arbitration, and the first claim stays on-chain as the disputed reference. |
| `escrow.settle` broadcast after `ticket.expires_at + ticket.settlement_grace_seconds` (both unix seconds) | On-chain revert `settle after refund deadline` | Neither party acked in time. The operator force-finalizes a pending operator claim via `escrow.settleLapsed`; the payer recovers funds via `escrow.refundInactive` when no operator claim is pending. |
| `escrow.settleLapsed` broadcast while `pendingBy != OPERATOR` | On-chain revert `only operator claims can lapse into settle` | `settleLapsed` finalizes operator-initiated pending claims only. If the payer posted the pending claim and the operator never responded, the payer uses `refundInactive` instead. |
| `Require-TEE` request when no operator survives the TEE filter (every otherwise-fitting candidate has `op.IsTEEAttested() == false`) | `503 service_unavailable`, `no_tee_capacity` | Proxy refuses; client should retry on a TEE-recovery cadence (typically the operator's `attestation.refresh_interval`). Distinct from `no_operator` and `operators_busy` — see § 3e. |
| No operator serves the requested model (none registered, or all filtered by sizing) | `503 service_unavailable`, `no_operator` | Proxy-authored; pick a different model or retry later. |
| Every otherwise-eligible node serving the model is flagged `staging` and the caller didn't opt in (§ 3f "Staging gate") | `503 service_unavailable`, `no_production_operator` | Proxy-authored; enable `allow_staging` to reach them, or pick a different model. |
| Every otherwise-eligible node serving the model has a signing account below the 5 ALGO spendable floor, or a strict tool-affinity pin or a `previous_response_id` pin resolves to one (§ 3f "Signer-funding gate") | `503 service_unavailable`, `no_funded_operator` | Proxy-authored; clears when an operator tops up its signing account. Retry later; for an unpinned request, a different model; for a pinned one, a new conversation. |
| A model is served but every candidate's reserve was refused for capacity (all 429'd) | `503 service_unavailable`, `operators_busy` | Proxy-authored after exhausting candidates; transient, retry shortly. |
| Every candidate was unreachable through *infrastructure* (a transient-shaped status carrying **no** protocol `error.code`, per the status set above, or a transport failure) and none ever refused the request, after the full retry budget above | `503 service_unavailable`, `operators_unreachable` | Proxy-authored. Distinct from `operators_busy` on purpose: the pool is not at capacity but unreachable, and reporting congestion invites an immediate retry storm during a fleet-wide restart. `Retry-After` lands past a typical node restart. |
| Node is shutting down (graceful drain) | `/v1/zs/reserve`: `503 server_error`, `node_draining`; new relay circuits: `503 server_error`, `relay_busy` | Node-authored. Tickets already issued are still honored for a short grace window; a *new* reservation is refused so the payer's escrow isn't opened against a node about to exit. A draining node also advertises zero models, so peers route away on their next probe. |
| No candidate speaks a compatible `proto_version` major (all wire-incompatible, § 3c) | `503 service_unavailable`, `no_compatible_operator` | Proxy-authored; the fleet hasn't upgraded to this build's generation. |
| Every candidate lacked a verified, unexpired ephemeral recipient (mandatory FS, § 8) | `503 service_unavailable`, `no_ephemeral_capacity` | Proxy-authored after exhausting candidates; transient (nodes mid-rotation). |
| Privacy mode on but no eligible relay for the target (§ 3f) | `503 service_unavailable`, `no_relay_available` | Proxy refuses rather than route direct (which would leak the client IP). |
| Node has no fresh ephemeral to advertise / seal against | `/v1/zs/details`: `503 service_unavailable`, `no_fresh_ephemeral`; `/v1/zs/reserve`: `503 server_error`, `node_ephemeral_unavailable` | Node-authored; transient (mid-rotation or just-restarted). Proxy treats as operator-unavailable and tries another. |
| `GET /v1/zs/attestation` on a node whose attestation refresh has not yet succeeded | `503 service_unavailable`, `attestation_unavailable` | Cold start; node-authored. The proxy treats this the same as a non-attested operator for routing. |
| `GET /v1/zs/attestation` on a node whose evidence is older than `2 × refresh_interval` | `503 service_unavailable`, `stale_attestation` | Refresh wedged on the node side; same routing consequence as `attestation_unavailable`. |
| `GET /v1/zs/attestation` on a node that does not run in TEE mode | `404 invalid_request_error`, `attestation_disabled` | Defensive — should not happen if the proxy reads `tee.mode` from `/v1/zs/details` first. |
| Payer's `open()` app-call was seen in the mempool (admission proceeded speculatively) but never confirmed on-chain (see "`open_unconfirmed`" below) | Streaming: node cancels inference and emits a sealed OpenAI error frame with `code=payment_verification_failed`, message prefixed `open_unconfirmed:`. Settle-side (non-streaming, or any case the watchdog didn't catch): the operator's settlement driver marks the ledger entry terminally `failed` immediately (no retry budget burned); no client-visible signal, since the response was already returned. | Streaming clients see `payment_verification_failed` with the `open_unconfirmed` reason and know they will not be billed: no settle was made, and the `open()` never moved any funds, so no refund is needed either. On the non-streaming path the proxy never gets a receipt; since the `open()` never confirmed, the payer's funds were never escrowed and no `refundInactive` is needed. |

**Settle outcomes are not client errors.** The four settle rows above are
on-chain outcomes of settlement, which runs after admission. None is surfaced to
the HTTP client as an error code; the `402 payment_verification_failed` refusal
is admission-time only. A reverted settle is logged by its sender, and the ticket
then resolves via `settleLapsed` or `refundInactive`. A frozen ticket has no
on-chain resolution: its funds stay locked pending off-chain arbitration. The only client-visible
effect is on the reported ALGO fee total, which does not include the payer's
settle fee when that settle is submitted after the response or fails to submit.

**`provider_overloaded`.** The node-authored code replaces the upstream's
vendor-specific one, which the client can't map. On the non-streaming path the
node **synthesizes** a clean `provider_overloaded` body rather than forwarding
the upstream's verbatim error, so the receipt's `body_hash` covers the
synthesized bytes. Other structured upstream errors (e.g.
`context_length_exceeded`) keep their own code and, non-streaming, are forwarded
byte-identical.

**`open_unconfirmed`.** Typically a balance shift between mempool admission and
block production drops the group. It is detected in one of two ways:
- Mid-inference, for streaming requests, by the node's open-confirmation
  watchdog. Algod returns "transaction not found" for a txid this same algod
  node previously had in its pool. Algod keeps recently committed txns in cache
  for tens of rounds, so a 404 is unambiguous evidence that the txn dropped
  without confirming.
- Operator-side at settle time, when `escrow.settle` reverts with
  `ticket not found` because the ticket box was never created.

## 11. Versioning

Version negotiation occurs at discovery, as defined in § 3c “Protocol version negotiation”; the current `proto_version` is `"9.10"`. The envelope has no inline version field. Peers with the same major remain compatible, while capabilities introduced by a minor version are used only when their specific version gate passes. An absent or unparseable version never implies capability support.

Minor versions are additive and need not introduce a gate. For example, 9.3 added long-context pricing fields, 9.4 added built-in-tool `action` fields (§ 5.3.1), 9.5 added the `dstack-tdx` attestation mode with its `event_log` / `posture` evidence fields (§ 3e), 9.6 added the `app_compose` preimage beside them, 9.7 added the optional `collateral` set beside that, and 9.8 added the optional `upstream_attestation` block, all of which older peers can ignore. 9.9 and 9.10 are the exceptions: 9.8 and 9.9 verifiers refuse each other's dstack-tdx nodes, as do 9.9 and 9.10 (§ 3e, verifier step 6). Within a compatible major, implementations are otherwise expected to track the same revision of this spec.

**Before stability.** The wire shape is not frozen. Incompatible changes may be made in place while the protocol remains in active development.

**After stability.** A breaking envelope change—including a field reshape or a change to AEAD, nonce semantics, AAD, or key wrapping—will bump both the `proto_version` major and the MIME type. A caller MUST reject an unknown MIME variant with a clear error.

**Forward compatibility:** Implementations MUST treat unknown-but-syntactically-valid values in existing fields (e.g. `algorand_tx_id`) as opaque.

## 12. Example wire captures

All examples use a fixed test keypair for reproducibility. **Do not** use these in production.

Test node identity: `AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQHZ3S0K` *(illustrative; real file format)*
Test node pubkey: `age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p`

### Example A: non-streaming request + encrypted response

**Proxy → Node**

```http
POST /v1/chat/completions HTTP/1.1
Host: node.example
Content-Type: application/vnd.zs+json
Accept: application/json

{
  "ciphertext": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBCVVQzL0dFQnVUM2xx..."
}
```

The ciphertext's plaintext is the inner-request frame (§ 4):

```
"zsrq" 0x01 0x00000090
{"reply_to_public_key":"age1mgmp5vu6r9lm7mf8lw0gfvgwxjgxtzmucetf5x5rq9ww6vvj39xsvkkedh","algorand_tx_id":"ZFCNYOCELJQF3IITBIXONVJTFW5XADXK2U26YFTW6B2WFBOE37UQ","ticket_id":"iltxGgiVSMuzzC6C4Vr8Fg==","admission_tag":"PZ2q..."}
{"model":"gpt-4.1-mini","messages":[…]}
```

There is no `Authorization` header. Admission is the sealed envelope plus the
on-chain `Payment + escrow.open` group (§ 4), and the `ticket_id` +
`admission_tag` gate the request after decryption (the tag commits to
`sha256(body)`, so it cannot be checked earlier).

**Node → Proxy**

The node seals the OpenAI response body with AAD = `BodyAAD("ZFCN…37UQ", "iltxGgiVSMuzzC6C4Vr8Fg==")` (both the tx id and the ticket id, § 6):

```http
HTTP/1.1 200 OK
Content-Type: application/vnd.zs+json
X-Zs-Response-Key: YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB...  (wraps the ticket-committed 32-byte AEAD key)
X-Zs-Receipt: RExcvrU1kYrvjgQLPZ2q...  (nonce || AEAD of the base64 JSON-encoded signed UsageReceipt, under HeaderAAD(tx_id, ticket_id, "receipt"))
X-Zs-Settle-Group: kYrvjgQLRExcvrU1gaN0eG6D...  (nonce || AEAD of the base64 msgpack 2-tx atomic settle group, under HeaderAAD(tx_id, ticket_id, "settle-group") — omitted on algod outage)

{
  "nonce": "RExcvrU1kYrvjgQL",
  "ciphertext": "A3l5mZ2qD... (AEAD-sealed OpenAI chat-completion response + 16-byte tag)"
}
```

**Proxy → Client**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":"chatcmpl-abc","object":"chat.completion","choices":[...]}
```

### Example B: streaming request + encrypted SSE response

**Proxy → Node**

Same envelope structure as Example A. The proxy knows from peeking the plaintext body that this is a stream request, so it sets `Accept: text/event-stream` on the outbound request.

**Node → Proxy** (headers then SSE body)

Frame 0 is sealed with AAD = `FrameAAD(tx_id, ticket_id, 0)`, frame 1 with AAD = `FrameAAD(tx_id, ticket_id, 1)`. After the content frames the node emits the `zs-settle-group` event (sealed under `HeaderAAD`, no counter advance), then the frame-sealed `zs-receipt` frame at the next index (frame 2 here). The `[DONE]` sentinel is not an `event: zs` frame and does not consume an index.

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
X-Zs-Response-Key: YWdlLWVuY3J5cHRpb24u... (wraps the ticket-committed 32-byte AEAD key)

event: zs
data: RExcvrU1kYrvjgQLA3l5mZ2qDxBvKQXzmC9...  (base64(nonce_0 || ct_0 || tag_0))  [AAD = FrameAAD(tx_id, ticket_id, 0)]

event: zs
data: Qk5EefvmXuzuh9pqLpY8bC0xTm6VnRTgsw...  (base64(nonce_1 || ct_1 || tag_1))  [AAD = FrameAAD(tx_id, ticket_id, 1)]

event: zs-settle-group
data: kYrvjgQLgaN0eG6D...  (base64(nonce || AEAD(base64 msgpack of the 2-tx atomic settle group)))  [AAD = HeaderAAD(tx_id, ticket_id, "settle-group")] — no frame index

event: zs-receipt
data: T2hy8p...  (base64(nonce_2 || ct_2 || tag_2)) — sealed JSON UsageReceipt at [AAD = FrameAAD(tx_id, ticket_id, 2)]

data: [DONE]

```

The `zs-receipt` frame carries `event: zs-receipt` (not `event: zs`) but is sealed exactly like a content frame. The proxy AEAD-opens it, verifies the receipt, and never forwards it to the client.

**Proxy → Client**

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no

data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant"}}]}

data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","choices":[{"delta":{"content":"Hello"}}]}

data: [DONE]

```

## 13. Design notes and comparison to peer designs

This appendix is for reviewers who want to understand *why* ZeroSignal makes the choices it does. It is **not normative**: it defines no wire behavior.

Proton's Lumo (https://proton.me/blog/lumo-security-model) gets the deepest treatment because it is the closest publicly documented peer *at the envelope layer*. § 13.1 places it among the other systems in the same space.

Descriptions of other systems come from their own public documentation (checked July 2026), not from independent audit or source review. Where a vendor's documentation is silent, this appendix says so rather than filling the gap by inference.

### 13.1 The peer landscape

| System | Who runs inference | Encryption from user to inference host | What hides the user's IP from the inference host | Conversation history at rest | What backs non-retention |
|---|---|---|---|---|---|
| **Proton Lumo** | Proton, on its own hardware | End-to-end: per-request AES key, PGP-wrapped to the LLM server | Proton's own front end (same vendor) | Stored on Proton's servers under zero-access encryption (per-conversation keys → per-user master key → user's PGP key, unlocked by the account password), plus a browser cache | Vendor policy; blog states the LLM server "forgets the request as soon as the response is generated" |
| **Brave Leo** | Brave, plus third-party model APIs | TLS to Brave's proxy | Brave's anonymizing reverse proxy (same vendor) | Local to the device, encrypted | Vendor policy ("we don't store or retain prompts, responses, context, or personal data") |
| **DuckDuckGo Duck.ai** | Third-party providers (OpenAI, Anthropic, …) | TLS to DuckDuckGo, TLS onward | DuckDuckGo's proxy substitutes its own IP | Local to the device | Vendor policy plus bilateral contracts with the providers (delete within 30 days, no training) |
| **Venice** | A pool of decentralized GPU providers, reached via Venice's proxy | TLS | Venice's proxy | Browser local storage, encrypted (key derivation not publicly documented) | Vendor policy; Venice's own architecture note says the design has not been third-party audited |
| **Apple PCC** | Apple, on Apple silicon in Apple data centers | End-to-end to an attested node whose measurement the *user's device* validates against a public transparency log | A third-party-operated OHTTP relay | No chat-history product; computation is stateless per request | Hardware and verifiable measurement (Secure Enclave, no persistence across reboot), enforced device-side |
| **ZeroSignal** | Independent operators — a marketplace, no vendor | End-to-end: `age`/X25519 envelope sealed to the node's signed, rotating ephemeral recipient (§ 4); plaintext is refused (§ 5.1) | Another **operator's** node acting as relay, drawn per request under owner-key diversity (§ 3f) | Nothing server-side; the `client/` app keeps history locally, sealed (§ 13.7) | Normative protocol obligation (§ 3a), optional hardware TEE (§ 3e), and on-chain escrow + signed receipts + `protest()` (§ 3b) |

Two structural differences follow from that table.

**There is no vendor to trust.** Every other row has a company that both operates the privacy-preserving intermediary and stands behind the retention promise. The separation between "who sees your IP" and "who sees your prompt" is organizational, and the same entity can undo it. ZeroSignal has no such party: the relay and the target are *different operators* for every request, enforced by owner-key diversity (§ 3f), and neither one is us. Apple PCC is the peer that also makes the split structural (a third party runs its OHTTP relay), but within a single-vendor trust root rather than across mutually distrusting parties.

**Non-retention is not only a promise.** For Lumo, Leo, Duck.ai and Venice, the guarantee's floor is a published policy (plus, for Duck.ai, a contract with the providers): good-faith commitments with no cryptographic or economic enforcement behind them. ZeroSignal's floor is a protocol obligation (§ 3a) backed by attributable, signed artifacts and a slashable stake (§ 3b), and by hardware in confidential mode (§ 3e). That is a different *kind* of assurance, not automatically a stronger one in practice. A large vendor with a reputation to lose and a decentralized operator with a bond at risk are different bets, and § 13.6 lists where the peers are ahead.

**Where the chain of custody ends.** A ZeroSignal node may serve a model from self-hosted weights *or* by passing the request to a hosted third-party API. In the second configuration, plaintext leaves the node for that provider. That puts the hop in the same class as Duck.ai, minus a bilateral contract, plus a `store: false` default that the caller can override (§ 3a "Upstream retention: caller-controlled, default off"). Self-hosted weights, or a confidential-mode node (§ 3e), is the configuration where the custody chain actually ends at the operator.

### 13.2 Where ZeroSignal and Lumo agree

Both are hybrid KEM-DEM schemes transporting OpenAI-shaped traffic between a client-side sealing party and an inference-serving node over TLS. Both accept that full end-to-end privacy (encrypting *from* inference) would require homomorphic encryption and is not practical today. Both publish an asymmetric recipient for the node, generate a fresh per-request key, and use an AEAD for bulk data. Both accept that the node necessarily sees plaintext at inference time and that TLS-level protections (channel auth, metadata opacity) are still required.

### 13.3 Primitive choices

| Layer | Lumo | ZeroSignal |
|---|---|---|
| Node asymmetric recipient | PGP, static, published out of band | X25519 via `age`, **rotating**, signed under the node's on-chain Ed25519 identity and served from `/v1/zs/details` (§ 3c) |
| Per-request caller key material | Fresh AES symmetric key | Fresh X25519 ephemeral keypair (used to wrap the node's fresh symmetric key on the return trip) |
| AEAD | AES-GCM (inferred — blog says AES + AEAD) | ChaCha20-Poly1305 |
| Key transport | AES key encrypted with node's PGP public key; the same key is reused for the response | Request body age-encrypted to the node's signed ephemeral recipient (age internally KEM-DEMs to ChaCha20); response symmetric key age-wrapped to the caller's per-request ephemeral pubkey |
| Forward secrecy | Neither leg — compromise of the server's PGP private key opens every recorded request *and* response | Both legs (§ 13.4) |

**`age` vs PGP.** `age` has a single-purpose wire format, a small audited reference implementation, and a narrow primitive set (X25519, ChaCha20-Poly1305, scrypt for passphrase mode). PGP's 30-year format history, large packet taxonomy, and repeated parsing-related CVEs (EFAIL, SigSpoof, key-smuggling) make it a worse foundation for a new protocol. We picked `age` for that reason.

**Why AES + PGP in Lumo is not "extra"; it's standard hybrid encryption.** Lumo's blog describes generating a per-request AES key, encrypting the message under it, and encrypting the AES key under the server's PGP public key. This is KEM-DEM. Asymmetric crypto is too size-limited and too slow to handle a multi-kilobyte chat body directly, so it only transports a symmetric key, and the symmetric key does the bulk work. `age` performs this construction internally (X25519 → HKDF → ChaCha20-Poly1305), so ZeroSignal's `age.Encrypt(body, ephemeralRecipient)` is structurally the same operation Lumo describes; `age` just assembles the construction and makes the primitive choices.

### 13.4 Where ZeroSignal is stronger

**Forward secrecy on both legs.** This is the most important divergence from Lumo. Lumo reuses the request's AES key for the response, and that key is wrapped under the server's long-term PGP public key, so compromise of that private key retroactively decrypts **every recorded request and response**. ZeroSignal holds no long-term encryption key at all:

- *Response leg*: the node generates a fresh response symmetric key per request and `age`-wraps it to the caller's per-request ephemeral X25519 public key. Once the handler returns, the ephemeral private scalar is wiped (`wire.ZeroEphemeralIdentity`) and the wrapping cannot be undone afterwards.
- *Request leg*: the body is sealed to the node's **signed ephemeral** recipient (§ 4), which is in-memory-only, rotates, and is erased on rotation and on restart. The signed `issued_at`/`expiry` pair carries a hard `MaxEphemeralLifetime` cap, so a node cannot advertise a long-lived key while calling it ephemeral. There is no on-chain anchor and no fallback recipient: a sealing party that finds no valid, unexpired, lifetime-capped ephemeral refuses that operator rather than downgrading (§ 8).

The protection is therefore unconditional rather than best-effort: there is no long-term recipient to fall back to and nothing to downgrade toward.

**Streaming is first-class.** Lumo's blog does not detail streaming. ZeroSignal specifies an SSE frame format, an `event: zs` tag that lets plaintext metadata frames pass through unchanged, and per-frame AAD with a monotonic counter (§ 6). Reorder, drop or duplication of any encrypted frame mid-stream shows up as an AEAD failure on the next frame, which triggers the error-frame-plus-`[DONE]` termination in § 10.

**Transport privacy is inside the protocol, and the split is across parties.** Every privacy-mode request reaches its target through a relay run by a different operator, chosen per request with owner-key diversity, so no single party holds both the client's IP and the prompt (§ 3f). Peer systems that interpose a proxy run it themselves, so the property rests on the vendor not correlating its own two views.

**Accountability is on-chain.** Admission is a paid, single-use ticket. The node signs a usage receipt that the caller verifies against the body it actually received. Disputes have a defined evidence set and a `protest()` freeze path, and operators post a slashable stake (§ 3a, § 3b). No peer design has a counterpart; with a vendor, the remedy for misbehavior is the terms of service.

**Modern software-friendly AEAD.** ChaCha20-Poly1305 is constant-time in pure software and performs well on platforms without AES-NI. AES-GCM is slightly faster with hardware AES support, but for a mixed proxy/node deployment the difference is noise, so the robustness advantage wins.

### 13.5 Request-response binding: AEAD AAD

Both designs bind a request identifier into the AEAD as Additional Authenticated Data: Lumo a Request-ID, ZeroSignal the `algorand_tx_id`. Without such a binding, an attacker on the channel between caller and node could splice a response sealed for request A onto request B. The AEAD tag would still validate (same key, same algorithm), and neither side would detect the switch.

ZeroSignal binds `algorand_tx_id` into the AAD of every sealed payload, non-streaming bodies and streaming frames alike, through the `BodyAAD` / `FrameAAD` constructions in § 6. Streaming frames also bind a 0-based frame index, so reorder, drop and duplication attempts within a stream show up as AEAD failures rather than successful tampering. That per-frame binding is stronger than the Lumo equivalent, whose blog does not address streaming.

### 13.6 Where a peer design is stronger

**Payment unlinkability — Brave Leo.** Leo Premium issues unlinkable tokens, so Brave cannot join a subscription purchase to the requests it authorizes. ZeroSignal deliberately goes the other way: admission is a *public* on-chain `open()` naming the payer's address, and the target node reads `payer_addr` out of the reserve. The relay hides the caller's IP, but the payer address is a stable pseudonym that a target can accumulate prompts against, and the `(payer, operator, time)` tuple is on chain for everyone. That is the price of escrow-backed accountability and refundability. Blind-signature or Privacy-Pass-style admission drawn against a prefunded pool would recover the property; it is not in this spec.

**Synced history with account recovery — Proton Lumo.** A server-side zero-access store means any device with the account password gets the full history back. ZeroSignal keeps no server-side copy at all, so history lives on the device that made it. Moving it takes an explicit encrypted export/import, and recovery runs through the passkey (or its 24-word phrase), with no password reset. That is strictly less convenient; in exchange, no server holds the ciphertext to begin with.

**Verifiable code identity — Apple PCC.** PCC binds each request to an attested image whose measurement the user's *device* checks against a public transparency log, so "which code ran" is a claim the user can verify rather than trust. ZeroSignal's analog is confidential mode (§ 3e), and the gap is narrower and more specific than "the control plane is specified".

- For `dstack-tdx`, both reference verifiers (the Go proxy and the browser client) replay the event log, bind the sealing key, and match the workload against a published release, with enforcement on by default. A payer who opts in refuses to route to anything else.
- What is still missing is the half PCC's device-side check actually rests on: **a public transparency log and a reproducible derivation of the measurement from source**. Today a payer verifies that a node runs a build ZeroSignal published, which is a weaker claim than verifying that the published build is the source everyone can read.

See § 3e, `proto/TEE.md`, and `plans/future/spec/measurement-transparency.md`.

### 13.7 Conversation history at rest

**On the node there is nothing to encrypt.** Non-retention is a normative operator obligation, not a storage-layer choice: decrypted request and response bodies, prompts, completions, tool-call arguments, and tool-call outputs MUST NOT be logged or persisted (§ 3a "Prompt and response non-retention"). The node keeps no conversation store, no per-user account, and no session state that carries content between requests; the caller resends multi-turn context every turn. The state the node *does* hold is metadata: reserved tickets inside the reserve-to-consume window (§ 3a), the receipt it signs, and settlement/billing rows (ticket ids, token counts, addresses, amounts, never content).

**Lumo's at-rest layer protects something else.** Proton's zero-access design covers a hosted *history sync service*: conversations stored on Proton's servers so they follow the user across devices, under a key hierarchy that keeps Proton from reading what it stores. Its own blog says the inference server does not retain requests either. So the two systems are not making opposite choices about the same surface: Lumo encrypts a server-side store that ZeroSignal does not have.

**The comparable surface is the client.** The `client/` app keeps history in a per-passkey IndexedDB database, with conversation and message content sealed under an `age` DEK derived from the passkey.

- **Key derivation:** WebAuthn PRF output → ARC-52 XHD root key → HKDF-SHA-256 under a purpose label (`dek.content`) → X25519 identity.
- **Root key isolation:** the root key stays inside a SharedWorker and never crosses the port. A tab receives a derived, purpose-bound identity, never the root.
- **Record binding:** every record binds its own associated data (`conv:<id>`, `msg:<conversationId>:<id>`) through a custom `age` header stanza covered by age's header MAC, so records cannot be swapped for one another.
- **Backup/export** moves ciphertext without decrypting it.
- **No escrow:** there is no server-side copy and no wrapped key escrowed anywhere, so there is nothing to phish and no reset path.
- **In the clear at rest:** only structural metadata, namely record ids, timestamps, message role, and the per-turn `(operator, model)` attribution. The attribution is left clear deliberately, since both ids are already public on chain and in the upstream API call.

None of this is normative: the wire spec does not prescribe client storage, and a conforming client may store nothing at all. It is described because it is where conversation history lives in the deployed system: on the user's device, or nowhere.

### 13.8 What none of these designs solve

- **True E2EE against the inference host**: the model host must see plaintext to run inference, and every design here accepts this. Confidential mode (§ 3e) narrows the trusted party from the operator to the CPU/GPU vendor; it does not remove the exposure. Apple PCC leans hardest on the same idea.
- **Replay protection inside the encryption layer**: no design here rejects replays at the AEAD layer. ZeroSignal closes the gap one layer up: admission is single-use-ticket-gated (§ 3a), so a replayed envelope dies at `ticket_invalid` before the body is touched. Lumo's blog does not describe an equivalent.
- **Caller authentication without an identifier**: Lumo authenticates the account over TLS, Duck.ai and Venice authenticate at their own proxy, and Brave uses unlinkable tokens. ZeroSignal carries no bearer auth at all. Admission is the on-chain `Payment + escrow.open` group plus the ticket/admission-tag gate (§ 3a), which authenticates *payment* rather than identity but is not unlinkable (§ 13.6).
- **Traffic analysis**: per hop, the request path (`/v1/chat/completions` vs `/v1/responses`), timing and ciphertext size stay visible, and the content-type plus the `X-Zs-Response-Key` header mark traffic as ZeroSignal. The relay removes the target's view of the caller's IP but not a global observer's view of both flows. Because `open()` is a public transaction, a relay can also attempt a timing correlation against the chain to recover the payer (§ 3f "Anonymity & trust model"). Mixnet-grade defenses (cover traffic, batching, multi-hop) are out of scope for single-hop.
