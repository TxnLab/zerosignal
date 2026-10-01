# Admission tag — proof-of-possession on the sealed request

## Summary

**The admission tag is a 32-byte HMAC-SHA256 that proves whoever sealed a request is the same party
that reserved it and is paying for it.** The node verifies it *before* consuming the ticket, so a
request it cannot attribute costs the legitimate payer nothing.

Age encryption gives the sealed request confidentiality and tamper-resistance, but **not
authorship** — the node's ephemeral recipient is published at `/v1/zs/details`, so anyone can
construct a well-formed envelope to it. The tag supplies the missing property, keyed on
`K_response`: the per-ticket secret the node mints at reserve and hands back only to the reserving
caller, wrapped to the recipient that caller declared.

This document is the threat-model companion to [`../SPEC.md`](../SPEC.md) § 3a, which is normative
for the formula, the field layout, the admission order and every error code. Here we cover what an
adversary can actually attempt and which control refuses it — the tag plus the bindings layered
around it:

| Attempt | Control | Refusal |
|---|---|---|
| Scrape `ticket_id` off the public `open()` and race a forged envelope | admission tag, verified pre-`Consume` | 402 `admission_tag_invalid` |
| Replay a captured tag against a different body | `sha256(body)` inside the MAC | 402 `admission_tag_invalid` |
| Splice a tag across tickets or app-call txids | both ids, NUL-separated, inside the MAC | 402 `admission_tag_invalid` |
| Re-frame a plaintext inner frame to the attacker's own reply-to | reply-to bound to the reserve-time `proxy_recipient` | 402 `reply_to_mismatch` |
| Pin a ticket to a payer the caller doesn't control | `payer_addr` proven by the reserve signature | 402 `payment_verification_failed` |
| Reserve a cheap model, run an expensive one | body `model` compared to the ticket's | 400 `model_mismatch` (sealed, zero-cost receipt) |
| Replay a reserve to mint duplicate tickets | `proxy_recipient` is signed context and doubles as the replay nonce | 409 `reserve_replayed` |

## Adversary model

Three vantages, with materially different reach. Only the first is what the tag exists for.

**1. Public-chain observer.** Reads the `open()` group from any algod, for free, the moment it hits
the mempool: `ticket_id`, the app-call txid, the payer address, `max_price`, `expires_at`, the
operator and node ids, and the node's ticket signature. Sees neither `K_response` (never in a public
artifact) nor the prompt (age-encrypted to the node). **This is the live vantage** — sealing the
wire did nothing to it, because `open()` is public by construction.

**2. On-path observer or relay.** Sees `{ciphertext}` and transport headers, nothing else. The
identifiers ride the age-sealed inner frame (`"zsrq" || version || headerLen || headerJSON ||
body`), so a relay cannot even *name* a ticket to attack it. This vantage was materially narrowed
when the identifiers moved inside the seal; it is not the vantage the tag defends.

**3. Misdeclaring payer.** Holds a real ticket and a real `K_response`, and can therefore compute
valid tags all day. Not a tag adversary at all. The model and input-budget bindings exist for this
one, and unlike everything else here they protect the **operator**, not the payer.

### Secrets in play

| Secret | Held by | Transported over |
|---|---|---|
| Node's ephemeral age private key | Node — memory only, rotated, never persisted | Never transmitted |
| `K_response` (per ticket) | Node (ticket store) → caller, via `wrapped_response_key` at reserve | Age-sealed to the caller's `proxy_recipient` |
| Ticket signing key | Node (`signing_addr`) | Never transmitted |
| `ticket_id` (16 random bytes) | Node → caller, then **public** once `open()` reaches the mempool | Sealed reserve response; Algorand mempool from `open()` on |

The operator publishes its age recipient, owner address, signing address and escrow `app_id`. All of
that is meant to be public; none of it authenticates a request.

## Attack: mempool-race ticket hijack

The attack the tag was built for, and the reason verification is ordered ahead of `Consume`.

The window opens when the `Payment + escrow.open()` group is admitted to the mempool and closes when
the legitimate caller's sealed POST reaches the node — in practice single-digit to tens of
milliseconds. An adversary colocated with the same algod sees the `open()` at the earliest possible
moment and so gets the largest usable share of it.

Inside that window an attacker holds everything needed to *address* a request: the legitimate
`ticket_id` and app-call txid from the mempool, and the node's published age recipient. They seal an
inner frame carrying those two identifiers, their own prompt, and their own `reply_to_public_key`,
and POST it. What they do **not** hold is `K_response`, so they cannot produce a tag over it.

**What this would achieve if nothing checked authorship.** Age decryption succeeds — it is
independent of `K_response`. `Consume` is atomic and winner-takes-all, so the attacker takes the
ticket. Payment verification then *passes*, because the on-chain values genuinely are the legitimate
ones. From there:

- **Attacker** — receives the completion in cleartext, and recovers `K_response` itself from the
  wrapped-key header, at zero on-chain cost.
- **Legitimate payer** — gets `402 ticket_invalid` on their own request, and their escrow is
  debited for work they never requested.
- **Operator** — pays real upstream API cost and signs a receipt for a request indistinguishable
  from a legitimate one.
- **Upstream provider** — sees the attacker's prompt tagged with the legitimate payer's
  `safety_identifier` (where the operator has opted into `zs.inject_safety_identifier`), so any
  policy violation is attributed to the wrong identity.

**What actually happens.** The tag is missing or wrong, `verifyAdmissionTag` fails, and the node
refuses with `402 admission_tag_invalid` from `refuseEnvelope` — before `Consume`. No state changes:
the ticket stays live and the legitimate request, arriving milliseconds later, succeeds normally.
The attacker learns nothing beyond what the chain already told them.

### Why the narrower bindings are not substitutes

Two adjacent checks look like they might cover this. Neither does, which is why the tag is the
primary control and they are layered on top:

- **Payer binding alone.** The on-chain payer *is* the legitimate caller — the attack rides their
  `open()`. The ticket's recorded `payer_addr` and the app call's `payerAddr` arg agree, so the
  check passes and the attack proceeds untouched.
- **Reply-to binding alone.** Forcing the response seal to the legitimate recipient stops the
  cleartext exfiltration, but the ticket is still burned, the attacker's prompt is still inferred,
  the operator still pays, and the escrow still settles against the legitimate payer. That is a
  downgrade, not a closure.

## Attack: reply-to re-framing

`reply_to_public_key` is the one inner-header field the tag does **not** cover — the MAC commits to
`ticket_id`, the app-call txid and `sha256(body)`, and nothing else. A party holding a *plaintext*
inner frame could therefore re-frame the identical body and tag to their own recipient, receive the
sealed response, and recover `K_response` from the wrapped-key header.

Reaching that state requires the plaintext frame itself, so a wire observer or a relay cannot get
there. The binding is genuine defense in depth rather than the load-bearing control: `verifyReplyTo`
compares the inner header against the `proxy_recipient` recorded on the reserve that issued the
ticket, and refuses a mismatch with `402 reply_to_mismatch` — also before `Consume`.

A ticket carrying **no** stored recipient is refused, not waved through. `handleReserve` always
populates the field, so this cannot happen today; but `ReserveParams.ProxyRecipient` is an ordinary
optional string, and a future `ticketStore.Reserve` caller that forgot it would otherwise disable
the binding silently with every test still green. Failing closed turns that into a visible refusal.

## Attack: body substitution and cross-ticket splice

`sha256(plaintext_body)` sits inside the MAC, so a captured tag cannot be lifted onto a different
body — the attacker would need `K_response` to recompute it.

Two consequences worth stating, because they constrain code elsewhere:

- **The hash is over the un-mutated body**, exactly as the caller sent it. That is *why* every
  node-side mutator — `InjectSafetyIdentifier`, `DefaultStoreFalse`,
  `InjectStreamOptionsIncludeUsage`, the built-in-tool rewrite — runs after admission rather than
  before. Reordering any of them breaks verification.
- **Both identifiers are in the MAC, NUL-separated**, so a tag cannot be spliced across tickets or
  across app-call txids, and the separators prevent a concatenation collision between the two
  variable-length strings.

## Attack: payer misattribution

The tag authenticates the **consumer** of a ticket, not its **funder**. Payer attribution is a
separate control: `payer_addr` is carried on the reserve and proven by the reserve signature, and at
admission the node compares it against the `payerAddr` ABI arg of the on-chain `open()`.

This one is explicitly defense in depth rather than a primary control. The node pre-signs the
`open()` app call at reserve with that payer already baked in, and the contract requires `gtxn[1]`'s
sender to be the node's own signing key — so an attacker cannot author an `open()` naming a
different payer for someone's ticket in the first place. The comparison catches drift between those
two paths.

The comparison is gated on the reserve having been signed. An unsigned reserve's `payer_addr` is
spoofable, so comparing against it would let anyone pin a ticket to a payer they do not control —
turning a defensive check into the very attack it looks like it prevents.

## Attack: model substitution

This one points the other way: it protects the **operator** against a misdeclaring payer.

Rates, the input ceiling, and the tool and modality gates all resolve from the *ticket's* model,
while the body reaches the upstream verbatim. An unchecked divergence would let a caller reserve a
cheap model and be served an expensive one. `verifyRequestModel` compares the two and refuses with
`400 model_mismatch`.

Unlike the tag and reply-to checks this runs **after** `Consume`, deliberately. The caller
demonstrably holds `K_response`, so this is a misdeclaring payer rather than an attacker, and their
escrow is already open. Refusing with a sealed, zero-cost receipt settles that escrow at zero;
refusing before `Consume` would strand it until `refundInactive`.

## Why the ordering is the control

The tag's security value is entirely in *when* it is checked. The admission path is:

```
unwrapRequest                        400 bad_envelope
  ticket_id present?                 402 ticket_required
  refuseIfDrained                    503 node_draining
  ticketStore.Peek                   402 ticket_invalid       ← non-destructive
  refuseEnvelope
      verifyAdmissionTag             402 admission_tag_invalid ┐ pre-Consume: a bad
      verifyReplyTo                  402 reply_to_mismatch     ┘ envelope must not
  ticketStore.Consume                402 ticket_invalid          burn the ticket
  verifyPaymentGroup                 402 payment_verification_failed
  verifyRequestModel                 400 model_mismatch          sealed + zero-cost receipt
  checkInitialInputBudget            4xx                         sealed + zero-cost receipt
  body mutations, then inference
```

**Peek-then-Consume is the whole invariant.** `Peek` returns `K_response` and the reserve-time
recipient in a single lock acquisition without flipping the `consumed` flag, so the two
envelope-binding checks can run against a ticket that is still live. Splitting them across two store
calls would let a concurrent sweep or `Consume` land in between. Both checks live in
`refuseEnvelope`, shared by all three admission sites, so their order and error shapes cannot drift
apart.

`Peek` surfaces the same not-found and already-consumed errors as `Consume`, so the admission error
shape stays uniform — but it does **not** check expiry. That is enforced only in `Consume` (against
`admittedUntil`, the open-call admission window) and in the background sweep, so an
expired-but-unswept ticket still yields `K_response` to the two binding checks and is refused one
step later. Harmless, because the caller holding that `K_response` is by definition the one who
reserved it.

**Payment-verification failure is the deliberate asymmetry.** It runs *after* `Consume`, and failing
it deletes the store entry — the ticket is gone, not reset to unconsumed. That keeps the store
single-transition, so a `ticket_id` is never resurrected and a replayed envelope can never race a
retry. The cost is that a transient algod failure during the node's mempool poll also burns the
ticket. The client contract is therefore: on `payment_verification_failed`, **re-reserve** — never
retry the same `ticket_id`. See [`../SPEC.md`](../SPEC.md) § 3a for the refund path that recovers
the escrow.

## Delivering `K_response` without a round trip

The tag is only possible because the caller holds `K_response` *before* it constructs the sealed
request. That is what `wrapped_response_key` on the reserve response is for: the node age-encrypts
`K_response` to the `proxy_recipient` the caller declared, so the caller unwraps it locally.

The caller reuses that same reserve-time ephemeral identity as the request's `reply_to_public_key`,
so one private key unwraps both `wrapped_response_key` and the response's `X-Zs-Response-Key`. The
tag itself is computed after the `open()` group is submitted (it commits to the app-call txid) and
before the envelope is wrapped, over the plaintext body.

Because the recipient is signed context in the reserve's canonical bytes, it doubles as the reserve
replay nonce, and the unsent `(operatorId, nodeId)` in those same bytes defeats re-sealing a
captured reserve at a different node.

## What this does not defend

- **Compromised caller host.** Anyone who extracts `K_response` from a live proxy or client can
  compute valid tags. That already implies control of the paying process; nothing at this layer
  helps.
- **Compromised node host.** The node holds every live `K_response` in its ticket store, and can
  forge receipts and approve arbitrary requests regardless.
- **No `K_response` rotation.** One key per ticket, fixed at reserve. The tag binds to that value
  for the ticket's life.
- **Funder identity.** The tag proves possession of a ticket secret, not who paid — that is the
  separate payer binding above, and it is only as strong as the reserve signature backing it.
- **Traffic analysis.** Request timing, size and cadence are outside this layer entirely; see
  [`../SPEC.md`](../SPEC.md) § 3f for the relay-rotation privacy properties.

## Code references

The identifiers this document discusses are **not** plaintext envelope fields. `ticket_id`,
`algorand_tx_id`, `reply_to_public_key` and `admission_tag` all ride the age-sealed inner-request
frame; the outer `RequestEnvelope` is a single `ciphertext` field.

| Concern | Path |
|---|---|
| Formula, domain constant, tag size | `proto/go/wire/admission.go` — `ComputeAdmissionTag`, `AdmissionTagDomain`, `AdmissionTagSize` |
| Inner frame (carries the tag) | `proto/go/wire/inner.go` — `innerRequestHeader` |
| Outer envelope (`ciphertext` only) | `proto/go/wire/envelope.go` — `RequestEnvelope` |
| Envelope decode (node) | `proto/go/wire/seal.go` — `DecryptRequest` → `DecryptedRequest.AdmissionTag` |
| Envelope encode (caller) | `proto/go/wire/wrap.go` — `WrapRequestWithIdentity`; `WrapRequest` is a tests-only generate-identity variant that cannot satisfy the reply-to check |
| Reserve delivery (proto types) | `proto/go/ticket/reserve.go` — `ReserveRequest.ProxyRecipient`, `ReserveResponse.WrappedResponseKey`, `CanonicalBytes` |
| Reserve delivery (node) | `node/internal/server/reserve.go` — `wrapResponseKeyForProxy` |
| Reserve delivery (proxy) | `proxy/internal/hayai/reserve.go` — `HTTPReserveClient.Reserve` |
| Node verification | `node/internal/server/admission.go` — `verifyAdmissionTag`, `verifyReplyTo`, `verifyRequestModel`, and the payer comparison in `verifyPaymentGroup` |
| Peek-verify-consume ordering | `node/internal/server/admission.go` — `Server.refuseEnvelope` (true == refused), called from the three admission sites in `handlers.go` |
| Ticket store | `node/internal/server/tickets.go` — `ticketStore.Peek` returns `PeekedTicket` (key + reserve-time recipient) in one lock acquisition |
| Proxy tag computation | `proxy/internal/server/hayai_dispatch.go` — `runHayaiSealed`, before `WrapRequestWithIdentity` |
| TS parity | `proto/ts/src/wire/admission.ts` — `computeAdmissionTag`; client call site `client/src/stream/envelope-fetch.ts` |

Go↔TS parity is pinned by the `admission_tag` golden vector in `proto/testdata/vectors.json`.

## Related

- [`../SPEC.md`](../SPEC.md) § 3a "Sealed request envelope" — normative admission order, error
  codes and the HMAC formula; § 4 for the inner-frame layout.
- [`../ENCRYPTION_OVERVIEW.md`](../ENCRYPTION_OVERVIEW.md) — the layer map one level up; admission
  binding is its Layer 3.
- [`../TEE.md`](../TEE.md) — the confidential-compute threat model, which assumes this admission
  path unchanged.
- [`./operator-node-selection.md`](./operator-node-selection.md) — how a caller picks the node it
  reserves against.
- `flow-ticket-reserve.puml` — reserve flow: the caller's ephemeral identity, `proxy_recipient`,
  `wrapped_response_key`, and the admission pre-flight.
- `flow-request-response.puml` — request/response pipeline: tag computation on the caller side,
  and the peek → verify → consume path on the node side.
