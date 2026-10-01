# Operator / node selection — model X → ranked node → relay

## Summary

The starting point is exactly what you'd expect: **"I want model X"** and several operators/nodes advertise it. Selection turns that into two concrete, *separate* decisions:

1. **Target** — which node actually serves the inference.
2. **Relay** — which *other* node forwards the sealed request, so the target never sees the caller's network identity (transport privacy, [SPEC §3f](../SPEC.md)).

Both decisions are split across **two layers**, and this split is the thing to understand before anything else:

| Layer | Lives in | Decides | Golden-vectored (Go↔TS byte-identical)? |
|---|---|---|---|
| **Shared selection policy** | `proto/go/selection/` ↔ `proto/ts/src/selection/` | Eligibility + **price** + diversity | **Yes** — pinned by [`proto/testdata/selection_vectors.json`](../testdata/selection_vectors.json) |
| **App-side signals** | `proxy/internal/hayai/` ↔ `client/src/operators/` | Reachability, relay reputation, **latency (RTT / TTFT / tok-s)** | **No** — stateful, per-process, vantage-specific |

RTT, TTFT and tokens/sec are **never** in the shared policy. They're measured-and-stateful and depend on *where you're standing*, so they can't be a pure function of the static inputs the golden vectors pin — and they'd introduce float arithmetic that threatens Go↔TS parity. The shared policy is comparison-only on advertised price; everything quantitative-and-observed is bolted on top, app-side. See [Why the split](#why-the-split).

> **Naming note.** In the *routing* tier, an "Operator" **is a single node**, addressed by the `(operatorId, nodeId)` pair. Every cache / dedup / sort / tie-break in a selection path keys on that pair, **never operator-id alone**. (Operator-id-alone is correct only for owner-level concerns: payout, the operator's escrowed stake, relay *owner*-diversity.) The repo-root `AGENTS.md` describes this two-tier naming in full.

---

## Target selection — which node serves the request

Two phases run in order: the shared policy filters and price-sorts, then the app-side layer nudges the order by responsiveness.

### Phase 1 — shared policy: `SelectTargets` (filter → price-sort)

`selection.SelectTargets(ops, constraints, preferred)` (`proto/go/selection/select.go`, mirrored in `select.ts`). Fixed order:

> model eligibility → sizing → image-factor → wire-version → TEE → **price sort** → built-in-tool partition → in-loop image-tool partition → affinity

1. **Model eligibility** — keep only `op.ServesModel(X)`: the node's published `Models` list must contain X. An **empty list serves nothing** — a node advertising zero models is not a candidate for *any* model, matching its own `/v1/zs/details` contract (that list is the exact set of reservable models, so an empty one means every reserve would be refused). There is deliberately no `Reachable` wildcard: a reachable node with an empty catalog would otherwise be tried and rejected for every model, burning reserve round-trips and masking a real `no_operator` behind `operators_busy`. Sets `RegistryCount`; `0` means literally nobody advertises X.
2. **Sizing** — keep only nodes where `inputTokens + maxOutputTokens` fits the node's advertised `ContextWindow` / `MaxOutputTokens` for X. Delegates to `inject.FitsContextWindow` so node and proxy agree byte-for-byte. Misses recorded in `SizingMisses`.
3. **Image-factor** (image endpoints only) — hard filter on the per-model image token factor (`ImageTokenFactor` / `ImageEditTokenFactor`); unlike text sizing this is a filter, not a record.
4. **Wire-version** — keep only `wire.ProtoVersionCompatible` nodes (major-version equality).
5. **TEE** — when the request sets `RequireTEE`, keep only `TEEAttested` nodes.
6. **Price sort** ← *the base ordering.* Stable sort by `lessByPrice`: lowest `InputUSDPer1M`, then lowest `OutputUSDPer1M`, then `ID`, then `NodeID`. An undeclared rate (`0`) sorts **last** (`priceRank: 0 → +Inf`). Pure comparisons, no arithmetic — this is what keeps it vector-safe.
7. **Tool partitions** — stable partitions that *prefer* (never filter) nodes supporting the requested built-in tools, then the in-loop image tools, preserving price order within each bucket.
8. **Affinity** — `prefer` puts a caller-supplied sticky node first (deduping it from the tail by `(ID, NodeID)` so its sibling nodes stay in the fallback pool); `strict` pins it alone; `none` is a no-op. The cache *lookup* that resolves `preferred` is the caller's job — it needs live runtime state, so it can't live in the pure policy.

Out of Phase 1 you get **a price-ordered list of nodes that can actually serve model X**. No RTT / TTFT / tok-s yet.

### Phase 2 — app-side: responsiveness banding

Now the metrics enter. The proxy (`pickCandidates` → `bandByResponsiveness`, `proxy/internal/server/hayai_dispatch.go`) and client (`resolveDispatchCandidates`, `client/src/operators/dispatch-candidates.ts`) compute a **combined expected response time** per candidate — additive, all in milliseconds:

```
score = network_RTT      # client-observed target-aggregate EWMA, counted only when samples >= 2
      + TTFT             # on-chain NodeRecord.latencyEwmaMs (co-signed time-to-first-token)
      + decode_term      # 128 / tokensPerSecEwma * 1000  (on-chain co-signed tokens/sec)
```

(`responsivenessScore`, `hayai_dispatch.go` ≈ L1023, mirrored at `dispatch-candidates.ts` ≈ L105.) Each term is added only when known; a node with no signal at all gets `signal=false`.

- **RTT** — *your own* observed round-trip to that target, EWMA(α=0.3), gated on ≥2 samples so one noisy measurement can't reorder.
- **TTFT** — on-chain `NodeRecord.latencyEwmaMs`, weight 1, added straight in ms. Makes a fast GPU node outrank a marginally-cheaper CPU one.
- **decode term** — converts on-chain `tokensPerSecEwma` into the ms cost of a "typical" 128-token reply (`decodeNormTokens = 128`). Weighted **lightly** on purpose: tok/s is the noisiest term (a per-node aggregate across *all* served models, dominated by model size).

Then **banding** (`bandByResponsiveness`): each node's band = `round(score / 500)` (`targetResponsivenessBandMS = 500`). Sort ascending by band, but **price order is preserved within a band** (stable sort). Net effect: *a node only jumps ahead of a cheaper peer when it's roughly a full 500 ms band faster.* Price stays the default; responsiveness only breaks ties at coarse granularity.

Edge cases:
- A node with **no metrics** ("cold") lands in the **median band** — neither promoted nor buried.
- Fewer than 2 candidates, or all-cold → list returned untouched (pure price order).
- The affinity-preferred node is pinned to band `-1` (always first), keyed by exact `(operatorId, nodeId)`.

**Net precedence:** affinity > responsiveness band (~500 ms granularity) > price > id.

---

## Relay selection — the privacy hop

A wholly separate decision. Relays only forward bytes — they don't run inference — so relay selection weights **network RTT only**; TTFT and tok/s are irrelevant here.

### Phase 1 — shared policy: `EligibleRelays` (diversity filter)

`selection.EligibleRelays(ops, target)` (`select.go` ≈ L398). A relay candidate is excluded when it:

- belongs to the **target's own operator** (`op.ID == target.ID`) — so sibling nodes of the target are never used, or
- shares the **target's owner address** (`op.OwnerAddr == target.OwnerAddr`) — the **hard owner-diversity rule**, or
- isn't `wire.ProtoVersionCompatible`, or
- shares the target's **/16 subnet** (`diverseSubnet`, best-effort, public-IPv4-only; DNS names and loopback/private addrs count as diverse).

`Reachable` is then a *soft* two-tier preference: if any eligible relay is reachable, return only reachables; otherwise the full eligible set (cold-start fallback). Empty pool → `ErrNoRelay`, and the caller **hard-fails rather than routing direct** — that's the privacy guarantee. `SelectRelay = EligibleRelays(...)[seed % len]`; `EligibleRelays` is factored out precisely so the app-side layer can re-rank the diverse pool by latency without duplicating the diversity rules.

### Phase 2 — app-side: latency-weighted seeded draw

On top of that diverse pool, `SelectRelayHopWeighted` (`proxy/internal/hayai/relayrouter.go`, mirrored by `selectRelayHopWeighted` in `client/src/operators/relay-router.ts`) does a weighted random pick:

```
weight = 1 / (RTT + 50ms)                 # faster relay -> higher weight; bias prevents runaway
weight = 0.15 * uniform + 0.85 * weight    # floor-mix so no relay is starved
pick   = seeded draw over weights          # fresh crypto-random seed per request
```

- **50 ms bias** (`latencyWeightBiasMS`) stops a near-zero-RTT relay from getting a runaway weight.
- **15 % uniform floor** (`latencyFloorFraction`) guarantees diffusion: the fastest relay can never exceed ~`(1-0.15) + 0.15/n` of traffic. This is both the [SPEC §3f](../SPEC.md) anti-profiling bound *and* the cap on how much an adversary wins by gaming its RTT.
- **Cold start** (no latency known) → degrades to exactly `pool[seed % len]`, i.e. plain seed rotation, until latency warms.
- RTT is keyed by the `(relay, target)` *pair* when known, falling back to a per-relay-endpoint aggregate.

**Relay reputation** layers on as a *soft downrank* (not the `Reachable` bool): a relay with a forward-failure / stale-ephemeral-key streak ≥3 is demoted into `EligibleRelays`' fallback tier, never hard-excluded (`relay_reputation.go` ↔ `relay-reputation.ts`). On the client, a sticky direct-contact reachability verdict also overrides the catalog hint, because in a browser "target-reachable" ≠ "relay-reachable" (`relay-health.ts`, orchestrated by `resolveRelayDecision` in `relay-decision.ts`).

---

## Where the metrics come from

| Metric | Source | Trust / scope | Read into routing at |
|---|---|---|---|
| **RTT** | Measured by *you* on clean, pre-inference round-trips: the `/v1/zs/details` discovery probe and the reserve POST. EWMA(α=0.3), stale after 5 min, min 2 samples. In-memory only, never persisted or shared. | Vantage-specific, live | `relay_latency.go` (proxy) / `latency-store.ts` (client) |
| **TTFT** (`latencyEwmaMs`) | On-chain, co-signed, EWMA(N=10) of time-to-first-token over settled tickets. Per-node aggregate **across served models** (a hardware-speed proxy). | Trustworthy but coarse | `fetcher.go` ≈ L826 (proxy) / `adaptNodeFields` in `operators.ts` ≈ L163 (client) |
| **tok/s** (`tokensPerSecEwma`) | On-chain, co-signed, EWMA(N=10) of decode throughput, sampled only on streamed settles with a decode window. Per-node aggregate across served models (decode rate is model-size-dominated → noisiest term). | Trustworthy but coarsest | same as TTFT |

Both on-chain metrics live on the **`NodeRecord`** box (per node), not the `OperatorRecord` — the operator rollup is the sum across its nodes. They're hardware-speed proxies, not per-model figures.

---

## The full flow

```
model X
  |
  +-- SelectTargets (shared, golden):  serves-X -> fits -> price-sort
  |     |
  |     +-- responsiveness banding (app-side):  + RTT + TTFT + decode, 500ms bands, price kept within band
  |           |
  |           +-- pick top target node (operatorId, nodeId)
  |
  +-- EligibleRelays (shared, golden):  exclude same-operator / same-owner / same-/16, version-compatible, reachable tier
        |
        +-- latency-weighted seeded draw (app-side):  1/(RTT+50ms), 15% floor, soft reputation downrank
              |
              +-- send sealed request:   you  ->  relay  ->  target
```

---

## Why the split

The shared `selection` policy is **golden-vectored**: `proto/go/selection` and `proto/ts/src/selection` must produce byte-identical results, pinned by `proto/testdata/selection_vectors.json`. That demands inputs that are a *pure function* of static, serializable data and comparisons that don't drift across languages — hence eligibility + price (comparison-only) + diversity, and nothing else.

RTT / TTFT / tok-s break both requirements: they're **stateful** (EWMAs that accumulate over a process's lifetime), **per-process / vantage-specific** (the proxy and a browser client measure different RTTs to the same node), and **float-arithmetic** (a weighted score, not a comparison). So they live entirely in the app-side mirrors and are layered *on top of* the shared policy's output.

This is symmetric by design: the proxy is a **localhost single-user (payer) process**, the CLI/daemon twin of the client — not a multi-tenant server. Its RTT vantage *is* the payer's, so it can route identically to the client. When routing behavior changes on one side, mirror it on the other (and update [SPEC §3f](../SPEC.md) if it touches the relay-rotation privacy property).

---

## Code references

| Concern | Shared (proto) | Proxy (Go) | Client (TS) |
|---|---|---|---|
| Target select (filter+price) | `proto/go/selection/select.go::SelectTargets` / `operator.go::ServesModel,Fits,lessByPrice` | mirrored in `internal/hayai/operator.go`, `internal/hayai/sizing.go`, `internal/server/hayai_dispatch.go::pickCandidates` | `@txnlab/zs-proto/selection` `selectTargets`, used by `operators/dispatch-candidates.ts` |
| Responsiveness banding | — (app-side only) | `internal/server/hayai_dispatch.go::responsivenessScore,bandByResponsiveness` (`decodeNormTokens=128`, `targetResponsivenessBandMS=500`) | `operators/dispatch-candidates.ts::responsivenessScore,bandByResponsiveness` (`DECODE_NORM_TOKENS=128`, `TARGET_RESPONSIVENESS_BAND_MS=500`) |
| Relay eligibility (diversity) | `proto/go/selection/select.go::EligibleRelays,SelectRelay,diverseSubnet` | (consumes the shared fn) | (consumes the shared fn) |
| Relay weighted pick | — (app-side only) | `internal/hayai/relayrouter.go::SelectRelayHopWeighted,weightedRelayPick` (`latencyWeightBiasMS=50`, `latencyFloorFraction=0.15`) | `operators/relay-router.ts::selectRelayHopWeighted,weightedPick`; orchestrated by `operators/relay-decision.ts::resolveRelayDecision` |
| Latency EWMA store | — | `internal/hayai/relay_latency.go` (α=0.3, stale 5m, min 2) | `operators/latency-store.ts` (same constants) |
| Relay reputation | — | `internal/hayai/relay_reputation.go` (streak threshold 3) | `operators/relay-reputation.ts` |
| Reachability | — | `internal/hayai/fetcher.go::recallReachable,recordReachable` | `operators/relay-health.ts` (sticky verdict + TTL exclusions) |
| On-chain metrics read | `NodeRecord.LatencyEwmaMs` / `.TokensPerSecEwma` | `internal/hayai/fetcher.go` (into `Operator.Metrics`) | `algorand/operators.ts::adaptNodeFields` (onto `RoutableNode`) |

> `selectTargets` / `selectRelay` are **not** in `client/src/algorand/operators.ts` — that file only defines the `RoutableNode` type and the on-chain box reads. The shared functions come from `@txnlab/zs-proto/selection`; the app-side wrappers live in `client/src/operators/{dispatch-candidates,relay-router,relay-decision}.ts`.

## Related

- [`SPEC.md`](../SPEC.md) §3f — relay-rotation privacy property (the diffusion bound the `latencyFloorFraction` floor enforces).
- [`docs/flow-transport-relay.puml`](./flow-transport-relay.puml) — the relay forwarding flow.
- [`docs/flow-ticket-reserve.puml`](./flow-ticket-reserve.puml) — the reserve round-trip (one of the two clean RTT samples).
- [`docs/admission-tag.md`](./admission-tag.md) — what rides inside the sealed envelope once a target is chosen.
