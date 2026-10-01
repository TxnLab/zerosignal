# Multi-turn conversation content — what each surface replays, and what transit touches

## Summary

**Does the client send reasoning back to the LLM on the next turn? No.** Neither chat surface (`client/`, the `tui/`) replays prior-turn reasoning. Both capture reasoning **for display only** and **strip it** from the history they re-send. The proxy and node do **not** strip reasoning on the main request or response path — the only reasoning drop anywhere in transit is a node-internal, server-side-tool-loop-only replay step that never touches the client's request or the client-facing stream.

Both surfaces are **stateless / full-history-replay by default**: each turn re-sends the entire conversation as a fresh `input[]`, with `store:false` (the privacy default). The one exception is an **opt-in** TUI continuation mode (`previous_response_id` + `store:true`).

> **Why reasoning is dropped on replay.** Reasoning is ephemeral by design. Re-feeding a model its own prior chain-of-thought (or a `<think>` scratchpad that leaked into the text channel) is at best wasted context and at worst destabilizing. Surfaces keep it client-side for the disclosure UI, but the model sees a reasoning-free transcript every turn.

---

## Table 1 — what each surface replays into the next turn's outgoing request

Legend: ✅ sent back · ❌ stored-but-stripped (or never stored) · ⚠️ partial / conditional.

| Prior-turn content | `client/` | `tui/` |
|---|---|---|
| **Assistant visible text** | ✅ as `output_text` part | ✅ verbatim raw `message` item |
| **Reasoning / thinking** | ❌ stored for UI, stripped on replay | ❌ explicitly ephemeral, never captured |
| Inline `<think>`/`<thought>` tags leaked into text | ❌ stripped from replayed text | — |
| **Tool calls** (`function_call`) | ❌ display-only, dropped | ✅ **rebuilt** as `OfFunctionCall` |
| **Tool results** (`function_call_output` / `tool` role) | ❌ no tool role in wire union | ✅ `OfFunctionCallOutput` |
| **Generated images** | ⚠️ most-recent image turn inlines bytes; older → `[generated an image]` marker | — |
| **User attachments** (images/files) | ✅ `input_image` / `input_file` | — |
| **Citations / annotations** | text annotations only | — |
| **System / date seed** | ✅ re-dated `system` msg at index 0 (fresh per turn) | ✅ re-dated date seed at `input[0]` |

**Notable divergences:**
- **Tool calls/results:** the **TUI replays them**; `client/` **drops them** (consequence: in `client/` the model can't see its own earlier tool-call arguments — e.g. the original image-gen prompt — on a later turn). The reason is *where the tool runs*: the TUI has **client-side function tools** (its `executeTool` stub) so it must replay the `function_call`/`function_call_output` pair to satisfy the standard protocol obligation (a result is an orphan without its matching call), whereas every tool `client/` offers is a node-executed `zs_*` built-in whose entire call→execute→result loop runs **server-side inside the node within the same turn** (`node/internal/server/tool_loop.go`) — the surface only ever receives the final assistant text plus display-only status, so it never holds a half-finished exchange to replay.
- **Reasoning is dropped on both**, but via different mechanisms: `client/` *stores-then-filters* (kept for the disclosure UI), the TUI *never captures it* in the first place.

---

## Table 2 — request/transport shape per surface

| Aspect | `client/` | `tui/` |
|---|---|---|
| **API** | Responses (`/v1/responses`) | Responses default; Chat via `--api-mode chat` |
| **History strategy** | full replay every turn | full replay every turn (default) |
| **`store`** | omitted → `store:false` applied downstream | explicit `store:false` (default) |
| **`previous_response_id` continuation** | ❌ never (stateless invariant) | ⚠️ **opt-in** via `--retain-upstream` / `/retain on` → `store:true` + `previous_response_id`, sends only the new delta |
| **Encrypted reasoning** | not requested | not requested (`Include` never set) |

> Even in the TUI's opt-in continuation mode, local `r.history` stays intact (minus reasoning); the delta is just a wire optimization, and `lastResponseID` is captured only on `response.completed` so a partial stream never poisons continuation.

---

## Table 3 — what the proxy and node do to the body in transit

The pipeline is `client | tui → (proxy, for the tui only — client talks directly to the node) → relay → node → upstream LLM`. Body mutators live in `proto/go/inject/` and are applied by both. **None of them parse or remove `messages[]` / `input[]` / reasoning / tool history** — the body is otherwise passed through verbatim (parsed as `map[string]json.RawMessage`, so unknown fields including reasoning history survive untouched).

| Mutator | Applied at | What it changes | Touches reasoning / tool calls / messages? |
|---|---|---|---|
| `DropRoutingPreferences` | proxy (pre-seal) | deletes top-level `provider` routing hint | no |
| `DefaultStoreFalse` | proxy + node | sets `store:false` **only when omitted/null**; preserves explicit `true`/`false` | no |
| `DropEmptyTools` | proxy (pre-seal) | deletes `tools` when it's `[]` (+ dangling `tool_choice`) | only the top-level `tools` array when empty; never `tool_calls` in messages |
| `InjectSafetyIdentifier` | node | adds `safety_identifier` (hash of payer addr) if absent; preserves client value | no |
| `StripBuiltinCallMarkers` | node (Responses only) | strips `zs_*_call` **marker** items the node itself emitted from `input[]` | no — markers only, not message/reasoning/user content |
| `InjectStreamOptionsIncludeUsage` | node (streaming Chat only) | ensures `stream_options.include_usage:true` | no |

**Response path:** the node forwards the upstream response **verbatim** (sealed) — reasoning deltas (`reasoning_content`, `reasoning`, `response.reasoning_text.delta`, `response.reasoning_summary_text.delta`) are recognized only to classify frames for TTFT/billing, never dropped. The only frame ever dropped from the client stream is a node-injected standalone usage-only chunk. The proxy does **no** response-body content mutation (it unseals, verifies `body_hash`/receipt, forwards).

**The one reasoning strip in transit — `dropReasoningItems` (node):** applied **only** when building the next **server-side tool-loop** iteration's `input[]` (after a built-in hayai tool runs), and **only when the bound model is not a reasoning model**. It is `/v1/responses` tool-loop-only, never affects a plain single-shot turn, and is **client-safe**: the live stream still carries reasoning to the client; only the *model-facing replay between tool iterations* is withheld. (Complementary, not a strip: the responses→chat translator skips `reasoning` items when targeting a Chat-only upstream — Chat has no reasoning-item shape — but preserves the open assistant turn.)

---

## Continuation interplay

`store:false` is the default on every surface, but it does **not** break Responses-API `previous_response_id` continuation: `DefaultStoreFalse` only fills in `store` when the caller omitted it. A client that wants server-side reasoning continuation opts in by sending `store:true`, which both proxy and node preserve. (The proxy additionally pins continuation to the operator holding the session via a `previous_response_id`-keyed affinity cache.) Only the TUI exercises this; `client/` is deliberately stateless.

---

## Code map

| Surface | Replay logic | Key lines |
|---|---|---|
| `client/` | `messagesToWireInput` / `assistantOutputMessage` | `client/src/state/conversation/response-item.ts:356-394, 413-508`; stateless invariant at `client/src/operators/dispatch-candidates.ts:282-288` |
| `tui/` | `runResponsesTurn` / `printStreamResponse` | `tui/main.go:512-643, 3213-3450`; reasoning carve-out `tui/main.go:3252-3254, 3772-3773` |
| transit | `inject.*` mutators | `proto/go/inject/{store,tools,routing,safety,stream_options}.go`; proxy `proxy/internal/server/hayai_dispatch.go:105-125`; node `node/internal/server/handlers.go:1135-1186`; `dropReasoningItems` `node/internal/server/tool_loop.go:641-679` |

See also [`operator-node-selection.md`](./operator-node-selection.md) for routing, and [`../SPEC.md`](../SPEC.md) for the wire format and retention rules.
