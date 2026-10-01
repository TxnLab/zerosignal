# Confidential-mode nodes (TEE)

Protocol-level threat model and encryption walk for ZeroSignal nodes that opt into hardware-backed confidential computing — NVIDIA H100 / H200 / Blackwell GPU Confidential Computing inside an Intel TDX or AMD SEV-SNP confidential VM (CVM).

This document is the long-form rationale that [`SPEC.md`](./SPEC.md) §3e points at. Operator-facing setup lives in the [confidential compute guide](https://docs.zerosignal.ai/concepts/confidential-compute). The wire format does not change between standard and confidential nodes — TEE is a **routing-time decision** layered on top of the existing envelope spec, not a new protocol.

## 1. Why this exists

The default ZeroSignal threat model ([`SPEC.md` §8](./SPEC.md)) protects the request body against *every party between the proxy and the node* but explicitly **trusts the node operator**. Once the node calls `wire.DecryptRequest` the prompt lives in plaintext through tool-loop, body injections, and the upstream-LLM HTTP call, until it is re-sealed for the response. An operator with root on the host — or anyone who has compromised the host — can read every prompt and every response. SPEC.md "Prompt and response non-retention" is enforced as a **policy** on operators, not a cryptographic property.

A confidential-mode node closes that gap. The relying party (proxy) gets a cryptographic guarantee that:

- The prompt is sealed to a public key whose corresponding private key was minted **inside attested hardware** the operator cannot read.
- The decrypted prompt only ever exists inside CVM-encrypted RAM and the GPU's CC-protected memory region.
- The binary doing the decryption is a **specific, measured** `zs-node` image — not a tampered fork that secretly logs prompts.

The trust shift: instead of trusting the operator, the relying party trusts the CPU vendor (Intel TDX or AMD SEV-SNP), NVIDIA (GPU CC + the Remote Attestation Service signing the GPU's evidence), and the published `zs-node` CVM measurement. The operator becomes a hosting provider with no privileged access — the same threat model as a sealed appliance running in a colocated rack.

## 2. End-to-end flow with TEE

```
[Client] ──► [Proxy]
                │  plaintext (proxy is trusted)
                ▼
       wire.WrapRequest(plaintext, …, node ephemeral recipient)
                │  age envelope (X25519 → ChaCha20-Poly1305)
                ▼
═══ host-visible network ═══════════ ciphertext ═══
                ▼
       ╭─── CVM boundary (TDX or SEV-SNP RAM encryption) ───╮
       │                                                    │
       │   [Node binary]                                    │
       │     wire.DecryptRequest                            │
       │     plaintext lives in CVM-encrypted RAM           │
       │            │                                       │
       │            │  loopback HTTP (never leaves CVM)     │
       │            ▼                                       │
       │   [llama-server / vLLM]                            │
       │            │                                       │
       │            │  PCIe DMA, AES-256-GCM via per-boot   │
       │            │  bounce buffer                        │
       │            ▼                                       │
       │   ════ host-visible PCIe bus ═══ ciphertext ══     │
       │            ▼                                       │
       ╰──── [GPU in CC mode, HBM firewalled on-die] ───────╯
                          │
                          ▼   compute, response tokens stream back
       ╭──────────── back through the same chain ───────────╮
       │   GPU → PCIe (encrypted) → llama-server →          │
       │   Node binary → ResponseSealer.SealBody            │
       ╰────────────────────────────────────────────────────╯
                ▼
═══ host-visible network ═══════════ ciphertext ═══
                ▼
       [Proxy] decrypts, returns plaintext to client
```

## 3. The four cryptographic layers

Every observation surface available to the host operator is closed by exactly one of the four layers below. None of the layers is novel — they are off-the-shelf hardware features documented by Intel, AMD, and NVIDIA — but they only achieve the threat model when combined.

### 3.1 Wire (proxy ↔ node)

**Same as the standard ZeroSignal envelope.** The proxy seals the request body to the node's signed ephemeral X25519 recipient with AAD-bound ChaCha20-Poly1305 ([SPEC.md §6](./SPEC.md)). Anyone watching the operator-visible network — host NIC, datacenter switches, ISP — sees ciphertext only.

What's *different* about TEE mode is what the public key represents. In the standard model the node's age pubkey could correspond to a private key the operator chose (or stole, or substituted). In TEE mode the proxy verifies attestation evidence proving the private key was generated inside attested hardware (§4 below) before it will seal anything to that pubkey.

### 3.2 CPU RAM (inside the node process)

**This is what TEE adds to the existing scheme.** The whole node binary, plus the colocated inference subprocess, runs inside an Intel TDX or AMD SEV-SNP confidential VM. The CVM's RAM is encrypted with a hardware-generated key the host hypervisor does not have. The CPU's memory controller decrypts on-die into registers and caches; everything that spills back to DRAM is ciphertext.

The practical consequences:

- `ptrace`, `/proc/<pid>/mem`, `gcore`, kernel-debug interfaces — all see ciphertext for any CVM-resident memory.
- Hypervisor introspection, `qemu monitor`, and live-migration snapshots see ciphertext.
- A malicious operator with root on the host can pause the VM, schedule it elsewhere, give it less CPU — but cannot read what's inside it.

`wire.DecryptRequest` still happens in the node code at the same call site (`node/internal/server/handlers.go`). The output plaintext now lives in CVM-encrypted RAM. The same is true for tool-loop bodies, body-injection mutations, and every intermediate buffer.

### 3.3 PCIe (CPU ↔ GPU)

**NVIDIA CC mode.** When the GPU is booted with CC enabled, the NVIDIA driver inside the CVM and the GPU's on-die security processor establish a session key. Every DMA transfer between the CVM and the GPU is encrypted with AES-256-GCM via a per-boot bounce buffer.

A host operator sniffing the PCIe bus — IOMMU shimming, a malicious PCIe endpoint, a hardware probe — sees ciphertext for tensor uploads, prompt token streams, and KV-cache transfers. Hopper (H100/H200) implements this in software via the bounce buffer; Blackwell adds NVLink and is TEE-I/O capable so the encryption is closer to the hardware boundary.

### 3.4 GPU HBM

**Access control on-die — not encryption at rest, and the difference is load-bearing.** Once data lands on the GPU it lives in the CC-protected memory region, which the GPU's security processor firewalls off from the host, the hypervisor, and every other context on the board. On **Hopper (H100/H200) that region is not encrypted at rest**: confidentiality rests on those hardware firewalls plus the physical security of the board, and CC mode additionally disables the performance counters that would otherwise leak execution state. Blackwell extends the protected domain across NVLink, so a multi-GPU configuration keeps the same boundary between cards.

The practical consequence is a narrower claim than "sees ciphertext". A host operator driving the documented interfaces — the driver, the hypervisor, vendor diagnostic paths — is **refused**, not handed ciphertext. An attacker with **physical** access to the board is a different adversary, and this layer does not stop them (§7: physical and EM attacks are out of scope). That gap is the argument for renting a confidential instance from a hyperscaler rather than owning the box, and it is why `../node/docs/tee.md` tells an operator picking a SKU the same thing.

Compute happens inside that protected region; intermediate activations, attention scores, and output token logits never leave it in a form the host can address.

## 4. The load-bearing piece — key binding

Wire encryption alone is not enough: if the operator holds a copy of the node's age private key, sealed envelopes are useless. The key-binding protocol is what makes the rest cryptographic rather than merely policy-based.

### 4.1 In-CVM key generation

Under mandatory forward secrecy ([`SPEC.md`](./SPEC.md) § 8) the node holds **no persistent age key** — the sealing recipient is the short-lived **ephemeral** the node rotates in memory (~20 min, advertised + signed at `/v1/zs/details`, § 3c). In confidential mode that ephemeral is minted *inside the CVM*:

1. The node binary, running inside the CVM, generates the ephemeral X25519 age identity using the in-enclave RNG (`age.GenerateX25519Identity()`), on every rotation.
2. The private key lives **only in CVM-encrypted RAM** — never written to disk, not even to a CVM-encrypted volume — and is zeroed on rotation (`wire.ZeroEphemeralIdentity`). There is no `node.key` file.
3. The public key is advertised, signed under the operator's on-chain Ed25519 `signing` key (`ephemeral_sig`, § 3c).

Crucially, **the private key never exists outside CVM-encrypted memory** at any point in its lifecycle, and never outlives its rotation window. There is no on-host generation step, no key import, no copy held by the operator. If the operator tries to inject a key they generated themselves, step 4.2 below fails. This is **in-CVM forward secrecy**: even a future leak of the running CVM's memory cannot recover ciphertext sealed to an already-rotated, already-zeroed ephemeral — and the payoff is larger here than in the non-TEE tier, because a TEE operator never sees plaintext at all, so captured ciphertext + a later in-CVM key leak is the *entire* attack surface.

### 4.2 Attestation report binding

The CPU produces a TDX or SEV-SNP attestation report (signed by Intel or AMD); the GPU produces an NVIDIA Entity Attestation Token (EAT, a signed JWT verifiable against NRAS). Both reports include a `report_data` (TDX) / `REPORT_DATA` (SEV-SNP) / `nonce` (EAT) field whose contents the binary chooses and the hardware signs. On TDX the field is 64 bytes, and the binary fills both halves:

```
report_data[0:32]  = SHA-256(ephemeral_age_pubkey || be64(operator_id))                  key binding
report_data[32:64] = SHA-256("zs-aux-v2\0" || be64(node_id) || H_app || H_posture || nonce)   aux binding (9.9; posture 9.10)
```

The **key binding** ties the evidence to the node's current sealing key. The **aux binding** ties it to four more things:

- the node id, so a sibling node's bundle does not verify;
- `H_app`, a hash over the model catalog the node advertises: each model's id, source, weights digest, and whether that digest was measured or only declared;
- `H_posture`, a hash over the `posture` block, meaning where plaintext terminates and, for a named upstream, which one. The upstream a payer judges is therefore the one the measured binary derived from its effective config, not a self-report a relay could rewrite;
- an optional caller nonce, so a verifier can demand evidence minted for it.

The bundle publishes the catalog as `app_models` and the posture as `posture`, so a verifier can recompute both digests. A zero upper half means the node is older than 9.9 and is refused. The exact encoding, the decoding rules and the verifier checks are in [`SPEC.md`](./SPEC.md) § 3e ("Model measurement", "Posture measurement", and verifier steps 6–7).

The key binding **binds the attested measurement to the per-rotation ephemeral**. The on-chain record anchors only *identity* — the Ed25519 `signing` key — and carries no durable encryption anchor at all ([`SPEC.md`](./SPEC.md) § 8). Because the bound key rotates, the binary **re-mints evidence when the ephemeral rotates**, so `report_data` always tracks the live sealing key. **The actual mint cadence is therefore the faster of rotation (~20 min) and the configured `tee.attestation.refresh_interval` (default 1h) — but `refresh_seconds` on the wire reports only the latter**, so it is an upper bound on how long evidence may go unrefreshed, never a description of how often it is. Don't read it as the rotation period. If the operator tries to advertise a key whose private half lives outside the CVM, they cannot produce a matching attestation report — the hardware refuses to sign a `report_data` that is not what the in-enclave binary asked it to sign.

**Persisting a key across a rotation is defeated by something else, and it is worth naming which.** Not by the report: the old report already binds that key, `generated_at` is unsigned, and the quote body carries no timestamp of its own (its PCK chain has validity dates; the attestation does not) — so an operator *can* re-serve it, and can sign a fresh advertisement window over the same recipient, because the signing key is theirs.

What defeats it is that there is nothing left to retain. The private half exists only in CVM-encrypted RAM and is dropped once it ages out of the overlap window — demoted `current` → `previous` at rotation, then zeroed `overlapWindow` later, so it is decryptable for `rotationPeriod + overlapWindow` (30 min) and gone after. **The hard guarantee is the measurement plus non-persistence, not the memset**: `wire.ZeroEphemeralIdentity` reaches age's unexported field by reflection and its own godoc warns that an upstream rename turns it into a silent no-op. So the load-bearing statement is that the measured binary never writes the key anywhere and never hands it out — and a binary that does either is a different measurement, refused at step 2 of § 4.3. The replay itself is a self-DoS: it advertises a recipient nobody can decrypt to.

### 4.3 What the proxy verifies before sealing

When an operator advertises `tee.mode != none` on `/v1/zs/details`, the proxy fetches `/v1/zs/attestation` and runs the following checks before treating the operator as TEE-capable:

1. **CPU report signature** — verify the TDX quote against Intel's TDX-QV / PCK certificate chain, or the SEV-SNP report against AMD's KDS / VCEK. A revoked or expired chain fails the check.
2. **CPU measurement** — the report's measurement field must match a known-good `zs-node` CVM image (the published reference build, or an operator-pinned build the proxy is configured to trust).
3. **GPU EAT signature** — verify the JWT against NVIDIA's Remote Attestation Service (NRAS). The EAT asserts the GPU is in CC mode and reports its firmware/RIM measurements.
4. **Key binding** — confirm `report_data[0:32] == SHA-256(eph || be64(operator_id))`, where `eph` is the operator's advertised, **signature-verified** ephemeral recipient (its `ephemeral_sig` checked under the on-chain `signing_addr`, § 3c) — *not* the bundle's self-reported `node_pubkey`. Without this check, an operator could attest a real CVM but advertise a different pubkey alongside it.
5. **Aux binding** — recompute `report_data[32:64]` from the chain-resolved `node_id`, `H_app` over the bundle's `app_models`, and the nonce, and confirm it matches. A zero upper half, a changed catalog, or a withheld one each fail. The verifier reports the attested model list but does not route on it, because the list can lag `/v1/zs/details` by about 75 s after a catalog change.
6. **Evidence freshness** — `|now − generated_at|` within `min(2 × refresh_seconds, ceiling)`, where the ceiling is the verifier's own absolute bound (`2 × MaxEphemeralLifetime` in both reference verifiers). `generated_at` is node-authored and unsigned, and so is `refresh_seconds`, so a rule stated only in the node's own terms is no rule; the ceiling is what the payer contributes. See SPEC.md §3e step 2.

Only operators that pass *all six* checks are eligible to receive `Require-TEE` requests. A failure causes silent demotion to non-TEE status; a request that explicitly required TEE returns `503 no_tee_capacity` rather than silently routing to a plaintext operator. Silent fallback would defeat the entire feature.

## 5. Why the operator cannot log it — even if they want to

The honest framing: every observation surface is closed, and any binary modification that would open one breaks attestation.

| What the operator might try | Why it fails |
|---|---|
| `tcpdump` on the host NIC | Ciphertext (existing wire encryption). |
| `ptrace` the node process / read `/proc/<pid>/mem` | CVM RAM is encrypted to the host. |
| Snapshot the VM and analyze offline | Snapshot is ciphertext outside the CVM. |
| Sniff the PCIe bus | AES-256-GCM bounce buffer (GPU CC). |
| Probe GPU HBM from the host | The CC-protected region is firewalled off by the GPU's security processor. **This row is access control, not encryption at rest** (§3.4) — an attacker with physical access to the board is a different adversary and §7 does not claim to stop them. |
| Modify the node binary to add prompt logging | Measurement changes; the attestation report stops matching a known-good `zs-node` image; proxy verifier refuses; `Require-TEE` requests stop landing on this operator. |
| Extract the age private key | Key was minted in-enclave; the attestation report cryptographically asserts the binding; no copy exists outside the CVM. |
| Run a non-CC GPU and lie about CC mode | NVIDIA EAT is signed by NRAS and asserts the actual hardware state; the lie fails verification. |
| Run a CC GPU but with a hostile binary in the CVM | Different binary measurement; attestation reveals it; proxy verifier refuses. |

The set is exhaustive against the documented threat model. It is *not* exhaustive against side channels (§7).

## 6. What stays the same

Confidential-mode is a **routing-time addition**, not a wire-format break. The following are unchanged:

- Envelope format (`application/vnd.zs+json`, `RequestEnvelope` shape, AAD layout).
- Two-phase admission (reserve → ticket → admission tag → sealed request).
- AEAD primitives (`age` v1 for the request, ChaCha20-Poly1305 with AAD for the response and frames).
- Receipt format, settle group composition, escrow contract semantics.
- Discovery surface: `/v1/zs/details`, `/v1/zs/reserve`. The TEE capability is a new field on `/v1/zs/details`; verification is a new GET on `/v1/zs/attestation`. Neither changes the request/response shapes.

Concretely: a non-TEE proxy talking to a confidential-mode node sees a normal ZeroSignal node. The proxy without TEE-aware code just doesn't route TEE-required traffic to it. This is intentional — TEE support needs no coordinated flag day across implementations.

The decision to **not bind attestation evidence into per-request AAD** is deliberate. The attestation evidence is large and expensive to mint — far too expensive to put on a per-request path, whatever the re-mint cadence happens to be (§ 4.2: the faster of rotation and the configured interval). Treating it as a routing-time decision rather than a per-request authentication primitive keeps the wire format frozen and allows the evidence shape to change without touching the envelope. See SPEC.md §3e for the formal statement.

## 7. Residual side channels and honest limits

TEE is hardware-level isolation, not magic. The following are **not** mitigated by anything in this document:

- **Metadata** — ticket IDs, operator/payer IDs, model names, token counts, request and response sizes, timestamps, latency. The proxy and operator both see these. They are required for billing and observability.
- **Resource curves** — CVM CPU%, RAM pressure, GPU utilization, NIC throughput. The host operator sees these because scheduling has to happen somewhere.
- **Timing channels** — request latency varies with prompt length, model, KV cache state, token output count. This is observable end-to-end and can leak coarse-grained information about the prompt.
- **Power and EM analysis** — local physical access to the GPU/CPU could in principle leak information through power draw or electromagnetic emanations. Not in scope for ZeroSignal's threat model; out of scope for any pure-software defense.
- **Cache contention and microarchitectural side channels** — Spectre/Meltdown-class attacks targeting the CVM are an active research area. Both Intel and AMD ship microcode/firmware mitigations; operators must keep CPUs patched.
- **Compromised attestation roots** — if Intel's PCK-signing infrastructure or NVIDIA's NRAS is compromised, the verifier's ground truth is compromised. The protocol does not mitigate vendor-root compromise.
- **Bugs in the node binary** — TEE proves a *specific* binary is running. If that binary has a memory-disclosure bug, TEE doesn't fix it. The standard ZeroSignal non-retention rules still apply: do not log prompt content; the binary doesn't, but operators forking the code must preserve the property.

ZeroSignal's confidential-mode threat model is "the operator cannot read the prompt or response **content** under normal hardware operation" — not "no information leaks anywhere ever". Side-channel-resistant inference is a separate research problem (constant-time kernels, oblivious memory access patterns) and is out of scope here.

## 8. The trust shift

The baseline protocol trusts:

- **Proxy**: holds the user's plaintext.
- **Operator**: holds the post-decrypt plaintext on the node.
- **Upstream LLM provider** (when configured): receives the plaintext prompt directly.

Confidential mode trusts:

- **The sealing party**: holds the user's plaintext before it is sealed. That party is client-side either way — the `client/` app seals directly to the node with no proxy hop, and the `proxy/` daemon runs on the user's own machine — so it sits inside the user's trust boundary rather than being a remote intermediary.
- **CPU vendor (Intel or AMD)**: TDX / SEV-SNP attestation roots and microcode.
- **NVIDIA**: GPU CC implementation, RIM measurements, NRAS signing key.
- **Published `zs-node` CVM measurement**: the binary the proxy is configured to verify against. Reproducible builds make this auditable.
- **The operator**, *only* for liveness — they can refuse to serve, throttle, or unplug the machine. They cannot read what they serve.
- **Whatever the caller's own `tools[]` reaches**, and nothing more. A built-in tool such as `zs_web_search` or `zs_web_read` runs for a request only because the caller listed that type (SPEC § 3d), so its backend — a search engine, an arbitrary page — is a party the *caller* added to this list for that request. A caller that lists none adds none. This is the one entry the payer controls directly, and the reason `plaintext_terminates` is scoped to the inference route rather than to every byte.

Where inference itself runs is the `tee.dataflow` decision, and the two answers trust different sets. `sealed_local` removes the upstream-LLM dimension by construction: the engine runs *inside* the same CVM as the node binary, either as the supervised `LocalLlamaProvider` or as a digest-pinned sidecar service in the same measured compose. `attested_passthrough` keeps it, but narrowed to exactly one named API whose zero-retention the node confirms on every response, with the forwarding behaviour fixed by the measured image. Both are configuration invariants enforced at startup by `node/internal/config/config.go`, not deployment recommendations.

## 9. Implementation sketch

The full per-component breakdown lives in the implementation plan and the operator guide. This section captures the protocol-relevant surface only.

### 9.1 Node-side surface

- **`/v1/zs/details`** — gains a `tee` object:

  ```json
  {
    "...existing fields...": "...",
    "tee": {
      "mode": "dstack-tdx",
      "attested_at": "2026-04-29T12:34:56Z",
      "evidence_url": "/v1/zs/attestation"
    }
  }
  ```

  Mode values: `none` (default), `stub` (dev only), `dstack-tdx`, `nvidia-cc-tdx`, `nvidia-cc-snp`. Stub mode produces a deterministic, well-formed-but-untrusted bundle so the verifier pipeline is exercisable on a developer laptop.

  **`dstack-tdx` is the only mode implemented end to end**, and the examples here lead with it for that reason. It is CPU-only: it carries no `gpu_eat`, makes no NRAS call, and publishes an `event_log` (and, since 9.6, the `app_compose` preimage) so a verifier recovers the compose and OS-image measurements by replaying the log against the hardware-signed RTMR3. The two `nvidia-cc-*` rungs are specified below and refused at startup by the node; their verifier branch returns `verifier_not_implemented`. See `proto/SPEC.md` § 3e for the normative wire shape.

- **`/v1/zs/attestation`** (new) — plaintext GET. Returns the cached evidence bundle:

  ```json
  {
    "mode":            "nvidia-cc-tdx",
    "cpu_report":      "<base64 TDX or SEV-SNP report>",
    "gpu_eat":         "<NVIDIA EAT JWT>",
    "node_pubkey":     "age1...",
    "operator_id":     42,
    "report_data":     "<base64 SHA-256(node_pubkey || be64(operator_id)), the key binding only — for proxy convenience>",
    "app_models":      [{"model_id": "...", "source": "...", "weights_digest": "sha256:...", "weights_state": 1}],
    "generated_at":    "2026-04-29T12:34:56Z",
    "refresh_seconds": 3600
  }
  ```

  `app_models` is the preimage of `H_app` in the aux binding (§ 4.2). `GET /v1/zs/attestation?nonce=<64 hex>` mints a fresh bundle over the caller's nonce, echoed as `nonce`.

  Refreshes on the configured cadence; serving evidence older than `2 × refresh_seconds` returns `503 stale_attestation`. Plaintext, no envelope (mirrors the other `/v1/zs/*` discovery endpoints).

### 9.2 Proxy-side surface

- **Verifier interface** — `TEEVerifier`, with `NRASVerifier` as its implementation. The interface exists so a `LocalNvtrustVerifier` or alternative-vendor implementation lands as a config switch, not a refactor.
- **Capability cache** — `Operator.TEE *TEEStatus` carrying mode, last-attested timestamp, verifier name, and (on failure) a tagged failure reason for telemetry. Verifier failures demote the operator to non-TEE for routing purposes.
- **Routing filter** — when a request carries `X-Zs-Require-TEE: nvidia-cc` (or an equivalent proxy-side policy fires), `pickCandidates` filters to operators with `Operator.IsTEEAttested()` — `TEE != nil && TEE.Verified`. `Verified` is the routing-relevant bit; `TEE.FailureTag` carries the verdict tag for telemetry and is empty exactly when `Verified` is true. No survivor → `503 no_tee_capacity`. Silent fallback is forbidden.

### 9.3 Off-chain advertising

Capability is advertised off-chain via `/v1/zs/details` (the `tee.mode` field, plus matching evidence on `/v1/zs/attestation`) and verified directly by the proxy via `proxy/internal/hayai/attestation.go::NRASVerifier`.

**This section is the source of truth for the deferred on-chain migration. Do not duplicate it.**

Adding a `teeCapabilities` field to `OperatorRecord` (`contracts/ZeroSignalEscrow.algo.ts` + `proto/go/escrow/operators.go`) — so the directory layer carries a tamper-resistant capability hint — was considered and explicitly deferred:

- The evidence shape (`TEEAdvertisement` / `TEEEvidenceBundle` in `proto/go/inject/tee.go`) is still iterating through the real-evidence verifier slice. Locking it into the contract now would freeze it prematurely.
- The proxy already verifies attestation cryptographically at refresh time. An on-chain capability would only add tamper-evidence at the *directory* layer — useful for a third party auditing operator advertisements without speaking the protocol, but it adds zero security to the per-request seal path.
- `OperatorRecord` is a wire-breaking contract change. Bundling this with other contract work is cheaper than a single-purpose migration.

**Conditions that would unblock it:**

- The evidence shape has been stable across at least one verifier-ecosystem rotation (NRAS → local-nvtrust, or another vendor's attestation service), proving the capability declaration needs no format-specific fields beyond `mode`.
- There is demand for tamper-resistant directory entries — e.g. a marketplace UI ranking attested operators that does not run its own verifier.
- A second proto implementation (`proto/ts/`) is on the wire, so a contract change benefits more than just the Go reference.

**Shape when it lands:** a small `uint8` enum on `OperatorRecord` (0=none, 1=stub, 2=nvidia-cc-tdx, 3=nvidia-cc-snp), with the off-chain advertisement still required for the dynamic `attested_at` / `evidence_url` values. The verifier path stays unchanged.

## 10. Sources and further reading

Hardware and attestation:

- [NVIDIA H100 Confidential Computing tech blog](https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/)
- [NVIDIA Secure AI with Blackwell and Hopper whitepaper (Aug 2025)](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)
- [NVIDIA CC Deployment Guide TDX (April 2026)](https://docs.nvidia.com/cc-deployment-guide-tdx.pdf)
- [NVIDIA Remote Attestation Service (NRAS) docs](https://docs.attestation.nvidia.com/NRAS/nras_releases.html)
- [nvtrust SDK on GitHub](https://github.com/NVIDIA/nvtrust)
- [Intel TDX architecture spec](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
- [AMD SEV-SNP whitepaper](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)

Reference architectures:

- [dstack confidential-AI docs](https://github.com/Dstack-TEE/dstack/blob/master/docs/confidential-ai.md)
- [Phala GPU TEE / `private-ml-sdk`](https://phala.com/gpu-tee)

Research:

- ["Confidential Prompting" — sealed channel from attested key (arxiv 2409.19134)](https://arxiv.org/abs/2409.19134)
- [GPU TEE benchmark study (arxiv 2409.03992)](https://arxiv.org/abs/2409.03992)

Operator-facing setup, deployment recipes (Phala Cloud, Azure NCC H100 v5), and troubleshooting live in the [confidential compute guide](https://docs.zerosignal.ai/concepts/confidential-compute).
