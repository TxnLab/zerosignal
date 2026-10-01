# ZeroSignal wire protocol changelog

History of `wire.ProtoVersion` — the `<major>.<minor>` generation each build advertises.
Newest first.

- The **rules** for what a major vs. a minor bump means, and how `proto_version` relates to
  the cryptographic domain tags, live in [`SPEC.md` §3c "Protocol version
  negotiation"](./SPEC.md). They are not repeated here.
- The **current value** is the `ProtoVersion` constant in
  [`go/wire/version.go`](./go/wire/version.go), mirrored in `ts/src/wire/version.ts`.

Two recurring notes, true of every entry below unless it says otherwise:

- **Bumping the major IS the gating mechanism.** There is no per-feature capability flag for
  a breaking change: `ProtoVersionCompatible` is major-equality, so the version filter drops
  incompatible peers from a candidate set up front rather than letting them fail after a
  wasted reserve.
- **A signing-tag change is not a contract redeploy.** The tags are off-chain only — the
  `ZeroSignalEscrow` contract verifies a digest passed as an ABI arg and never recomputes the
  pre-image.

---

## Unversioned — verifier behavior

Changes to this module that consumers depend on but that do **not** move `ProtoVersion`, so
they carry no generation number and no peer ever advertises them. They still ride both
publish gates, and a consumer sees them only after a pin bump. Newest first, dated.

Kept above the version history rather than inside it because a heading here that named a
generation would make "does this peer speak it?" unanswerable — nothing on the wire carries
the answer.

### 2026-10-01 — public module and package names

The Go module is now `github.com/TxnLab/zerosignal/go` (was `github.com/TxnLab/hayai-proto/go`)
and the npm package is now `@txnlab/zs-proto` (was `@txnlab/hayai-proto`), published with public
access. Exported identifiers no longer carry the old project name:

| Old | New |
|---|---|
| `tools.IsHayaiBuiltinType` | `tools.IsBuiltinToolType` |
| `tools.FrameToolCallHayai` | `tools.FrameToolCallBuiltin` |
| `tools.StripHayaiCallMarkers` | `tools.StripBuiltinCallMarkers` |
| `selection.ExtractRequestedHayaiTools` | `selection.ExtractRequestedBuiltinTools` |
| `isHayaiBuiltinType` (TS, `inject`) | `isBuiltinToolType` |
| `extractRequestedHayaiTools` (TS, `selection`) | `extractRequestedBuiltinTools` |

**Consumer-visible at build time only.** A consumer must rewrite its import paths (Go) or its
dependency name (npm) and the identifiers above. Nothing on the wire changes and no golden
vector moves.

First public release: **0.1.1** of both — Go `go/v0.1.1` (`go get …/zerosignal/go@v0.1.1`) and
npm `@txnlab/zs-proto@0.1.1`. From here the two release in **lockstep**: every release tags
`go/vX.Y.Z` and `ts/vX.Y.Z` on the same commit, so equal version numbers mean the two
implementations agree byte-for-byte. Under 0.x a minor bump is breaking, a patch is not.
(`go/v0.1.0` exists on the seed commit with the same Go code; it predates the lockstep rule.)

### 2026-09-25 — the root-backdoor carve-out now requires a scanned guest image

`ComposePolicy.AllowedRootBackdoorEnvs` used to be honoured on any guest image. It is now
honoured **only** when the replayed `os-image-hash` is named in the new
`ComposePolicy.RootBackdoorSafeOSImages`, which `ACIUpstreamComposePolicy` populates from
`OSImagesWithoutSSHDaemon()`. An absent or unlisted image drops the concession and the strict
rule fires — fail-closed.

Why it was wrong before: the concession's whole justification is that the image ships no way to
consume an `authorized_keys` file, which is a property of that image and of no other. Waiving
the rule on an image nobody had enumerated waived it on the strength of a different image's
scan. `OSImagesWithoutSSHDaemon()` is deliberately shorter than `TrustedDstackOSImages()` —
trusting an image says its measurement maps to a published artifact; listing it here says
someone opened it and looked. `dstack-nvidia-0.5.9` is trusted and **not** scanned, so the GPU
line gets the strict rule.

**Consumer-visible.** An upstream that verified before may now refuse, and the refusal names the
observed image so the cause is not mistaken for the concession failing to apply. The TS mirror
(`proto/ts/src/attest/compose.ts`) models no concession at all and so owes no change;
`shared_policy.allowed_root_backdoor_envs` in `testdata/compose_vectors.json` stays `[]`.

### 2026-09-24 — a confidential node may advertise the egress built-in tools

`plaintext_terminates` (§ 3e) and `models[].retention` (§ 3c) are scoped explicitly to the
**inference route**: where the node sends the prompt in order to produce an answer. A node
MAY therefore advertise `in_enclave` or `named_upstream` alongside `zs_web_search` /
`zs_web_read` / `zs_image_search` in `builtin_tools[]`, because those run for a request only
when the caller lists the type in `tools[]` (§ 3d).

**Nothing on the wire changed and `ProtoVersion` does not move**, which is exactly why this
belongs here: a verifier holding an allowlisted measurement could previously *infer* "this
posture implies no egress built-ins", because the reference node refused to boot with them
enabled. That inference is no longer sound, and no field signals its loss. Verifier step 7
now states it normatively — `builtin_tools[]` MUST NOT be cross-checked against `posture`,
and a verifier MUST NOT demote on the pair. A consumer that never drew the inference needs no
change.

The image route is unaffected and is still held to the posture: the operator points
`image_llm` somewhere with no caller involvement.

### 2026-09-02 — compose skeletons admit a digest-pinned sidecar

`ExtractComposeSkeleton` / `extractComposeSkeleton` previously refused any
`docker_compose_file` with more than one `image:` line, which made the `sealed_local` rung —
an inference engine running as a second service inside the same measurement — unable to match
a published release at all. Such a node could only ever be verified by a hand-configured
per-deployment hash, which says nothing about *which software* it runs.

A second service is now admitted under two conditions that together make it a pin rather than
an exception:

- **Only the FIRST `image:` is lifted.** Later ones stay in the skeleton as literal text, so
  the release's own engine digest is inside the structure an operator may not vary. Lifting
  the engine instead would mean two references checked against one flat `TrustedNodeImages`
  list, where a released *engine* would pass as a released *node*.
- **A later `image:` MUST be `<repository>@sha256:<64 lowercase hex>`**, else
  `ErrComposeUnpinnedSidecar` / `'unpinned_sidecar'`. `docker_compose_file` is hashed *before*
  environment substitution, so a sidecar written `${ENGINE_IMAGE}` would publish one skeleton
  digest covering every engine the operator later supplies — to the process that sees
  plaintext prompts. This is the same attack `TrustedNodeImages` stops for the first image.

  `${` is refused **anywhere in the reference**, the repository half included. Be precise
  about why, because the obvious reason is wrong for that half: `${REPO}@sha256:<hex>` still
  content-addresses the bytes, so a hostile registry can only serve them or fail. It is
  refused because the rule is spelled `<repository>@sha256:<hex>`, no registry accepts `${`
  in a repository name, and a check that admitted it would leave the sentence above true only
  of the digest half.

Which service is "first" needs no parser: reordering changes the skeleton *and* hands the
release-image check the engine's reference, so a reordered document matches nothing.

`ErrComposeManyImages` / the `'many_images'` `SkeletonErrorCode` are removed; neither had a
caller. Consumers gain a new refusal code and lose one.

---

## 9.10 — the posture is bound into `report_data` (minor, but BREAKING for `dstack-tdx`)

The bundle's `posture` block was a self-report bound to nothing, and verifiers checked it only
for internal coherence. So nothing tied the upstream a payer was shown to the upstream the
node actually sends prompts to. It is now hashed into the aux binding:

```
H_posture = SHA-256( "zs-posture-v1\0" || u8(0) )                                  absent
H_posture = SHA-256( "zs-posture-v1\0" || u8(1) || lenStr(plaintext_terminates)
                     || lenStr(upstream_base_url) || u8(zero_retention)
                     || u8(upstream_attested) )                                     present
aux       = SHA-256( "zs-aux-v2\0" || be64(node_id) || H_app || H_posture || nonce )
```

The node hashes the posture it derived from its **effective** config: after env overrides,
and after dstack's `${VAR}` substitution, which happens outside the compose hash. That is why
the verifier does not parse `NODE_CONFIG_YAML` out of `app_compose`: the literal text is not
what the node runs.

**Flag day, same shape as 9.9.** The aux tag moved to `zs-aux-v2`, so a 9.9 node's binding is
`aux_binding_mismatch` at a 9.10 verifier. `SplitReportData` is unchanged, and there is still
one rule. An absent posture is committed as absent rather than refused, so a relay can
neither strip one nor add one. A posture `HPosture` refuses (one that is not an object, a
wrongly typed field, or in Go a string field that is not valid UTF-8) gets the new tag
`posture_preimage_invalid`. Go's bundle decoder marks a wrongly typed posture
(`TEEPosture.Malformed`) instead of failing the whole bundle, as it already did for `nonce` and
`app_models`, so both languages report the same tag. `VerifyAux` / `verifyAux` take the bundle's posture as a new
argument, and `AuxBinding` / `auxBinding` take `H_posture`. Both are API breaks for every
caller.

**Verifier rule** (SPEC § 3e step 7): a `named_upstream` posture is admissible only if
`upstream_base_url` is `https`, carries no userinfo, and `inferDialect(url)` is `xai` with
`zero_retention` set, or the posture's new bound `upstream_attested` bit is set and the
bundle carries an `upstream_attestation` block with protocol `aci/1`
(`inject.UpstreamAttested` / `upstreamAttested`). The block is unsigned, so the bit is what
stops a relay adding one; the node sets the bit from `tee.upstream_attestation` being
configured, not from its lease, and omits the block while the lease is down.

**`InferDialect` matches exact hosts** (`inject.InferDialect`, plus a new TypeScript
`inferDialect`, pinned together by `testdata/dialect_vectors.json`). It used to match
substrings of the whole URL, so `https://api.x.ai.attacker.example`, `https://api.x.ai@attacker.example`
and `https://attacker.example/api.x.ai` all counted as xAI. Under `attested_passthrough`,
that let an operator send prompts to their own server under an attested-passthrough
verdict. It now takes the dialed host (`url.Parse` → `Hostname()`) and matches a vendor
domain on a label boundary. The accepted subset is deliberately narrow: a scheme, no
userinfo, a plain LDH host with no escapes, and no control byte or malformed `%` escape anywhere
in the URL. `HostMatchesDomain` refuses non-ASCII input. Go's `url.Parse` and WHATWG `URL` disagree at
the edges, and both sides must name the same host. A vendor name that is not the vendor's
own domain no longer infers a dialect, for example a proxy host with `moonshot` in its name.

## 9.9 — the other 32 bytes of `report_data` (minor, but BREAKING for `dstack-tdx`)

The upper half of the TDX `report_data` field was zero padding. It is now an **aux binding**:
a hash over the node's chain-resolved `node_id`, the model catalog it advertises on
`/v1/zs/details`, and an optional caller nonce. SPEC § 3e, "Model measurement".

```
H_app = SHA-256( "zs-happ-v1\0" || be32(n) || [lenStr(id) lenStr(src) lenStr(digest) u8(state)]… )
aux   = SHA-256( "zs-aux-v1\0" || be64(node_id) || H_app || nonce )
```

`TEEEvidenceBundle` gains two optional fields:

- **`app_models`**: the catalog entries the node hashed, so a verifier can recompute `H_app`.
  `weights_state` is a number: `1` measured, `2` declared, `3` unverifiable. `0` is refused.
- **`nonce`**: the caller's `?nonce=` challenge, echoed as hex. Absent on the cached bundle.

The node answers `GET /v1/zs/attestation?nonce=<64 hex>` with a freshly minted bundle that
it does not cache.

**Verifier rules** (`ReportDataHalves.VerifyAux` / `verifyAux`, pinned by the `aux_verify`
vectors):

- A verifier that sent a challenge refuses a bundle whose `nonce` is absent or different,
  then hashes its own challenge. A verifier that sent none hashes the bundle's `nonce` if
  present, or 32 zero bytes.
- An empty or absent `app_models` whose binding does not match is `happ_preimage_missing`.
  Any other mismatch is `aux_binding_mismatch`. An `app_models` that `HApp` refuses is
  `happ_preimage_invalid`. `AuxFailureTag` / `auxFailureTag` map errors to these tags.
- Entries are decoded strictly: a missing key, a null, or a value of the wrong type is
  refused with error `malformed_model_entry` (tag `happ_preimage_invalid`). Go and
  TypeScript defaulted such fields differently, so without this the two verifiers hashed
  different preimages for one bundle, and the TypeScript one accepted a measured entry that
  had no digest. The `h_app_json` vectors cover these shapes.
- Go matches bundle keys exactly, as JavaScript does, at the top level and inside
  `posture`, `collateral` and `upstream_attestation`, and refuses a body that is not valid
  UTF-8. TypeScript callers must decode with `parseEvidenceBundle`: `res.json()` replaces
  invalid bytes with U+FFFD instead of refusing them, so it would hash model ids differently
  from Go.
- A `nonce` that is not a string, or an `app_models` that is not an array, no longer fails
  the whole decode in Go. Go substitutes values `VerifyAux` refuses, so both languages
  return the same tag (`aux_binding_mismatch` or `happ_preimage_invalid`).
- A verifier's own all-zero challenge is refused (`zero_challenge`), since it hashes the
  same as no challenge.

**0.42.0 is incompatible.** `@txnlab/hayai-proto` 0.42.0 and the Go pseudo-versions at
`0f1825d` through `9f86b37` (the one node and proxy pinned) shipped 9.9 with `weights_state`
numbered 0/1/2 and a lenient TypeScript decoder. The same bytes mean different states there,
so nothing may pin these versions. Use 0.43.0 or later, and a Go pseudo-version at or after
the commit that carries this entry.

**This is a flag day.** `SplitReportData` used to require the upper half to be zero, and now
refuses a zero upper half as `aux_binding_absent`. There is no version switch. With that
error it still returns the lower half, so a verifier checks the key binding first and reports
a key mismatch as `key_binding_mismatch`.

**Why a minor bump.** `ProtoVersionCompatible` compares majors, so 9.8 and 9.9 stay
compatible for everything except dstack-tdx attestation, and non-TEE routing is unaffected. A
major bump would drop every plain node from routing for a rule they do not use. The cost:

- A 9.9 verifier refuses a 9.8 node with `aux_binding_absent`.
- A 9.8 verifier refuses a 9.9 node with `key_binding_mismatch`, because its
  `SplitReportData` requires the upper half to be zero. Deployed 9.8 code emits that tag;
  only upgrading the verifier changes it.

**Consequences.**

- A node can no longer present a sibling node's bundle: the aux binding hashes `node_id`
  (SPEC § 3e, "Why `report_data` omits `node_id`").
- `SplitReportData` no longer refuses a non-zero upper half, so it no longer stops a node from
  getting 32 bytes of its choice signed by real hardware. That now depends on the verifier
  calling `VerifyAux`.

## 9.8 — upstream attestation (minor)

One additive optional field on `TEEEvidenceBundle` (§ 3e), present only on a node whose
`tee.dataflow` is `attested_passthrough` and which verifies its upstream's enclave:

- **`upstream_attestation`** — `protocol`, `base_url`, `report_url`, `keyset_digest`,
  `verified_at`, `lease_expires_at`, `carve_outs`. It describes the enclave the node forwards
  plaintext **to**, and says nothing about the node itself.

**It carries pointers and digests, never the upstream's evidence, and that is the design.**
The evidence is fetchable by the payer directly from the upstream without an API key
(measured 2026-09-24 against `inference.phala.com`: `/v1/aci/attestation` and
`/v1/aci/sessions/{id}` both answer unauthenticated, the latter with a ~267 KB per-session
blob). Relaying it would add a quarter-megabyte to every `/v1/zs/attestation` fetch in order
to save the payer a request they should make anyway — **a report fetched with the payer's own
nonce proves freshness that a relayed one cannot.** The node's own verdict is deliberately
absent for the same reason a measurement is: a verdict is the one thing a payer must not take
from the party under appraisal.

**What a payer CANNOT re-check, and the block must not be read as implying otherwise.** The
appraisal half is independently reproducible — `report_url` with the payer's own nonce, the
keyset digest, the event-log replay, the compose gate. The **per-request** half is not: ACI/1
§ 7.6 binds a receipt to the credential that fetched it, so the receipts proving where each
individual prompt went are retrievable by the **node** and by nobody else. So this block says
"the enclave I forward to is one you can appraise yourself, and I check every response against
a signed receipt you cannot see." Both halves are real; only the first is verifiable from
outside.

**`carve_outs` is normative and must not be omitted when non-empty.** It names every rule the
node's upstream appraisal downgraded rather than enforced — today only
`root_backdoor_env:<ENV_NAME>`. Both of Phala's tiers declare a dstack root-shell env channel
that our own compose policy refuses on our own nodes, so an operator accepting one from an
upstream has conceded something a payer is entitled to see. A verifier MUST read a non-empty
`carve_outs` as **capping what a clean appraisal means**, not as a footnote on one: dstack
measures env *names* and not *values*, so nobody can tell whether the channel was used, and
RTMR3 records boot rather than runtime, so a shell changes what runs while every other check
keeps passing. An absent list means the node enforced every rule its policy carries; it does
**not** mean the policy was strict.

Minor rather than major: the field is optional and additive, and a 9.7 verifier that ignores
it reaches the same verdict about the node it already reached. What it loses is the ability
to see the upstream half at all, which is why a payer that does not recognize `protocol` MUST
treat the block as unverifiable rather than skip it and accept the rest.

**Conformance, stated rather than implied.** This change ships the **producer** — the node's
verifier, boot gate, per-request enforcement and this field. The payer-side MUSTs in § 3e
rules 1–4 are **not yet implemented** in `proxy/internal/hayai/attestation_dstack.go` or
`client/src/operators/tee-verify.ts`: both ignore the field, as they ignore any field a newer
node adds. That is inert today and stops being inert the moment a retention tier reads the
upstream half — a verifier that has not implemented rule 4 would then accept a tier it never
appraised. **So rules 1–4 are a prerequisite of that tier, not a follow-up to it**, and the
tier's own change must land them in both verifiers. Nothing executable spans producer and
consumer here, which is why it is written down.

> **Numbering note.** `plans/future/tee/report-data-aux-9-8.md` reserved 9.8 for a different,
> not-started design (filling the unused upper 32 bytes of `report_data`). That plan is
> design-stage and gated on an unanswered platform question, so the number went to the change
> that shipped, and the plan was renumbered to
> `report-data-aux-9-9.md` on 2026-09-24.

---

## 9.7 — node-carried Intel collateral (minor)

One additive optional field on `TEEEvidenceBundle` (§ 3e), present only on `dstack-tdx`:

- **`collateral`** — the Intel-signed collateral set for the quote's platform: PCK CRL, root
  CA CRL, TCB info for the quote's FMSPC, QE identity, each with its issuer chain. Field
  names and encodings mirror Intel's QVL structure verbatim, so both verifiers pass them to a
  third-party implementation untouched; `tcb_info` and `qe_identity` are the signed inner
  documents byte-for-byte, for the same reason `app_compose` is.

**It is a resilience fallback, and the spec says so in normative terms because the shape
invites the opposite reading.** A node cannot forge any of it — every document is Intel-signed
and re-validated against the verifier's own embedded Intel root — but nothing stops it
choosing which validly-signed *vintage* to send, and the only freshness bound a verifier can
apply is each document's own validity window (~30 days for TCB info). That is enough to
conceal a TCB level downgraded by a newer publication, or a PCK certificate revoked since the
CRL it sent. So: fetch from a PCCS first, use the carried set only when that fetch was
unreachable (never when a fetch ran and refused — that is an answer), apply a freshness floor
tighter than Intel's own, and treat a partial set as an absent one.

What it buys is availability rather than latency: a verdict during a PCCS outage or, for a
browser payer, a CORS regression — where the alternative is every confidential operator
reading as unverifiable at once. Absent is routine, not a verdict, so there is deliberately no
`PublishesCollateral` version gate to pair with `PublishesAppCompose`.

**Amended after both consumers implemented it: the precedence is three-deep, not two.** The
original rules said "PCCS, else this", which left the verifier's own cache of PCCS responses
unaddressed — and a verifier that has one holds a document whose vintage the operator did not
choose, i.e. strictly better evidence than the carried set. § 3e rule 2 now states the order
(PCCS → the verifier's own cache → the node's copy) and the two consequences that neither
implementation got right on the first pass: a cached document that was consulted and
**refused** the quote must not fall through to the carried set (that is the rollback rule 1
exists to prevent, applied to the one case where we already hold a signed "no"), and such a
refusal is nevertheless reported as `collateral_unreachable` rather than as invalid evidence,
because its cause is not attributable from the verifier's position. No wire change: the field,
its encodings, and its optionality are exactly as shipped.

---

## 9.6 — the compose preimage (minor)

One additive optional field on `TEEEvidenceBundle` (§ 3e), present only on `dstack-tdx`:

- **`app_compose`** — the dstack `app-compose.json` document verbatim. It is the **preimage**
  of the `compose-hash` the RTMR3 replay recovers: `sha256(app_compose)` equals that
  measurement exactly, which is a property of how dstack builds the digest, not a convention
  we chose.

**Why this does not contradict 9.5's "no `compose_hash` field, deliberately".** That rule bans
a self-reported *measurement* — a value a verifier could read instead of replaying. This is the
opposite object: bytes whose only use is to be hashed and compared against the replay's own
answer. Substituting a friendlier document moves the digest, so there is nothing here to trust,
and the cheap-wrong-implementation failure the rule guards against is not available — a verifier
that skips the hash check is not reading a measurement, it is reading an operator-authored
document with no measurement attached.

**What it buys, which is the reason it exists.** `compose-hash` covers the operator's own
configuration, so it is distinct per operator *and per redeploy*. Nothing can enumerate that, so
a hash allowlist did not scale past a handful of hand-blessed nodes — which left `dstack-tdx`
verifiers checking that a node was measured without ever checking **what** it runs. With the
preimage in hand a verifier checks the document's *content* against per-release rules, and what
remains enumerable is a per-**release** list.

Three rules ride with it, each stated in § 3e because each is a way to implement this and get a
well-formed wrong answer:

- **Hash first, read second.** A verifier that reads a single field before checking the digest
  has verified nothing at all.
- **Carried byte-for-byte.** Any re-encoding — including a re-marshal that only reorders keys —
  moves the digest and makes the bundle unverifiable everywhere while looking fine at the node.
- **Absent or empty is never a check that passed — and never automatically a rejection
  either.** An empty document still hashes to a well-formed digest, so the tempting shape is to
  skip quietly and report clean; that is the reading § 3e forbids. Refusing outright is equally
  wrong today, because every guest agent predating 9.6 publishes nothing and a hard failure
  would report an honest fleet as compromised. The verifier records that the compose was not
  content-validated and may still accept the node through a hand-configured hash allowlist.

The node self-verifies the same equality before publishing, for the same reason it already
replays its own event log: otherwise it advertises evidence every relying party rejects, and
nothing in its own logs says why. A node that *cannot* produce a preimage — its guest agent
does not publish the document, or its event log carries no `compose-hash` to anchor it to —
publishes the quote and event log without it rather than going dark. `wire.AppComposeMinVersion`
/ `publishesAppCompose` is what lets a verifier tell that case from a 9.6 node withholding it:
absent from a pre-9.6 peer is a build fact, absent from a 9.6 peer is about the node.

**The content rules, and the shape of the `docker_compose_file` check.** Both reference
verifiers now call `VerifyAppCompose` — the proxy at step 4c of its dstack verifier, the browser
client at step 4b — each hashing the document against its own replay before reading a field.
`trusted_compose_hashes` remains the proxy's actual gate; the content rules are an additional
filter, and the case they catch that a hash allowlist structurally cannot is a node whose hash
someone blessed by hand that nonetheless declares `DSTACK_AUTHORIZED_KEYS`.

`docker_compose_file` is checked by a **whole-file template match**, not a deny-list. A verifier
lifts out the two spans an operator may vary — the `image:` reference and the
`NODE_CONFIG_YAML:` block body — hashes the rest as text against published release *skeletons*,
and checks the image against a list of published release images. Nothing enumerates what is
forbidden: a bind mount, a `privileged: true`, a second service, an extra port are all text the
release compose does not contain. (A second service became admissible on 2026-09-02, under the
two conditions recorded in the unversioned section at the top; everything else in this
paragraph still holds.) This replaced an enumerated deny-list because enumerating
hazards over YAML needs a parser per language, and two parsers disagreeing about anchors or
duplicate keys is two verifiers reaching opposite verdicts on identical evidence, silently. The
cost is real and is the operator's: the compose becomes a published artifact, comments included,
and reformatting it is indistinguishable from tampering.

**The template match is in force.** `ZeroSignalComposePolicy` still leaves `EnforceComposeSkeleton`
unset with empty lists — the per-release data moves on each consumer's own cadence, like the
trusted OS-image list — but both shipped consumers now supply it: zs-proxy from its config
defaults and the browser client from a bundled constant. So a clean `VerifyAppCompose` on either
of them now means "runs a published zs-node release", not "nothing structurally disqualifying".
Two rules come with that, both in § 3e: a whole-document pin such as `trusted_compose_hashes`
narrows and must never substitute for the release match, and an absent `app_compose` preimage is
**refused** rather than skipped wherever the match is enforced — the skip was only ever safe
behind a hand-blessed digest. A library caller taking the shared policy verbatim still gets the
weaker check and should say so.

**Also in this release, from review of the above.** Go's `strings.TrimSpace` and JavaScript's
`String.prototype.trim` are different predicates — U+0085 is space to Go only, U+FEFF to JS only
— and using each language's built-in put a verdict split into the compose rules at eleven call
sites. Both now use one explicitly-written ASCII class for value normalization and one
explicitly-written union class for the vacuous-document test, and
`proto/testdata/compose_vectors.json` pins every observable across the two languages. That file
is what caught the remaining divergences: a `docker_compose_file` of one invisible character
sidestepped `empty_docker_compose` entirely, and `null` was malformed in one language and a pile
of policy violations in the other.

## 9.5 — dstack TDX attestation mode (minor)

`tee.mode` gains `"dstack-tdx"`: an Intel TDX confidential VM managed by dstack (Phala Cloud
and self-hosted dstack alike). CPU-only — it carries no `gpu_eat` and makes no NRAS call — so
its verifier branch is disjoint from the `nvidia-cc-*` ones rather than a case inside them.

Two additive fields on `TEEEvidenceBundle` (§ 3e), both absent on every existing mode, so the
`nvidia-cc-*` wire shape does not move a byte:

- **`event_log`** — dstack's runtime measurement log, as raw JSON. It exists because dstack
  extends RTMR3 with a log rather than publishing measurements directly, so a verifier
  *recomputes* `compose-hash` and `os-image-hash` by replaying it against the hardware-signed
  RTMR3. Untrusted input whose only power is to be checkable, which is what makes it safe to
  take from the node.

  There is deliberately **no `compose_hash` / `os_image_hash` field**. Carrying them would
  invite a verifier to read the self-report instead of replaying — a cheap wrong verifier that
  is indistinguishable from the correct one on every honest node.

- **`posture`** — where plaintext comes to rest: `in_enclave`, or `named_upstream` plus the
  one API it is forwarded to. A quote says which software ran; it does not say whether that
  software keeps the prompt. The block is a **routing hint the verifier cross-checks against
  the allowlisted measurement**, never the authority — reading it as evidence gets you a claim
  signed by nobody. Contrast the trust *tier*, which is the verifier's own conclusion and
  never travels on the wire at all.

Also pinned in § 3e, because each is the kind of check that reads as covered while being
vacuous: the vendor chain is selected from the **report bytes** (TDX v4 `tee_type == 0x81`),
never from the node-authored `mode`; `report_data` is checked in **both halves** (`[32:64]`
must be zero, or the high half is a free "get Intel to sign 32 attacker-chosen bytes" oracle);
and the replay fails closed on a zero-event replay, an all-zero RTMR3, or an undecodable
payload.

## 9.4 — built-in tool round actions (minor)

The sealed status frames of SPEC §5.3.1 (`response.zs_tool_call.in_progress` / `.completed`)
gain an optional `action` object describing what the round is actually doing —
`{"type":"search","query":…,"sources":[…]}` for `zs_web_search` / `zs_image_search` and
`{"type":"open_page","url":…}` for `zs_web_read` — so a streaming client can render
"Searching for X" and list sources as they land instead of a bare "Searching the web".

The shape mirrors OpenAI's `web_search_call.action`, so a consumer that already renders
OpenAI's native web search renders ours with the same code. Sources carry a URL and no
title: that matches OpenAI's source shape, and the URL/title pairs already reach the client
as `url_citation` annotations, so the scraped third-party title never needs to ride a frame.

**Favicon bytes, not URLs.** The completed frame's action also carries an optional `icons`
map — each source site's favicon, as bytes, keyed by lowercased host. A ZeroSignal extension
with no OpenAI counterpart, carrying bytes rather than a URL on purpose: a consumer
rendering `<img src="https://thatsite.com/favicon.ico">` would disclose its IP and a render
timestamp to every host in a search result — an attacker-influenceable set, since results
come from a third-party backend steered by a model-chosen query — which makes it a beacon
channel rather than a decoration. Inlined and sealed, a relay learns nothing and the consumer
contacts nobody. Keyed by host rather than nested per source so several results from one site
share one copy. The MIME is sniffed from the bytes, never read off the serving site's
`Content-Type`, and `image/svg+xml` is excluded: SVG is an active document format and these
bytes end up inlined in a consumer's page. See `tools.IconMimeFromBytes` / `tools.IconHostKey`.

**Why a minor**, and weaker than 9.1–9.3: one optional field on an existing sealed frame, on
a channel whose consumers already skip unknown shapes by spec (§5.3.1's "MUST treat unknown
`type` values as skippable"). No canonical-bytes, signing-tag, or envelope-shape change, and
nothing is REQUIRED of any peer, so there is no capability predicate or min-version constant:
the proxy never reads the sealed plaintext, a 9.3 client against a 9.4 node ignores the
field, and a 9.4 client against a 9.3 node sees it absent. Both render today's generic labels.

**One deliberate asymmetry**: `zs_web_read` carries NO action on the `in_progress` frame.
Those frames are emitted for every call in an iteration BEFORE any of them run, while the
read's provenance gate runs later, per-call — so advertising the URL up front would render
"Reading \<attacker URL\>" in the caller's UI for a read the node then refuses, handing
attacker-chosen text a trusted-looking surface. Its URL appears only on the completed frame,
sourced from `ToolEffect.Action`, which the loop sets on the success path alone (gate-passed
AND returned without error). See `tools.ActionForCallPreflight`.

Landing this also tightened the terminal-frame classifier next door (`stream_terminal.go`):
putting the model's own words on a sealed frame meant a prompt could contain the literal
string `response.completed` and trip a raw-substring match, letting caller content steer a
payer-safety verdict. The `/v1/responses` path now confirms the frame's top-level `type`
after the substring prefilter. Vectored, mirrored in TS, and not itself a wire change — a
classifier reads bytes that were always shaped this way.

## 9.3 — long-context surcharge pricing (minor)

`/v1/zs/details` gains four advertised `long_context_*` fields
(`long_context_threshold_tokens` plus high-tier input / output / cache-read rates) so an
operator can price the context-size cliff xAI (Grok) bills with — a prompt at or above the
threshold pays a higher rate set for the whole request.

No canonical-bytes or signing-tag change: the tier is resolved at reserve from the ticket's
already-signed `input_count` (`pricing.IsLongContext`) and the tier-appropriate rates are
pinned onto the EXISTING `InputRate` / `OutputRate` / `CacheReadRate` ticket fields, so the
ticket and receipt digests are untouched. Nothing is required of a peer — the fields are
additive JSON a 9.0/9.1/9.2 node omits and a 9.3 verifier resolves the base tier for.

**Backward compat during rollover holds, but only just**, and it depends on a node-side
validation rule rather than on luck alone:

- **Input/output rates**: an old, non-tier-aware verifier bounds a tier-2 ticket's signed
  rates against base × `RateMaxMultiple` (2.0), so a legitimate exactly-2× surcharge passes
  (boundary `<=` — a coincidence, not headroom). Any future >2× tier requires tier-aware
  verifiers deployed first.
- **The cache-read rate has no such coincidence**, because a discount makes the high/base
  ratio far larger than 2×. A tier whose high cache-read rate is omitted advertises only the
  BASE discount, and an old verifier then bounds the high-tier ticket's cache-read rate
  against base × 2.0 and refuses every one of them. The node therefore RESOLVES an unset high
  cache-read rate to the base one scaled by the input rate's step-up whenever the base tier
  discounts, and refuses a config that explicitly declares no high-tier discount while the
  base has one — so the high rate is always advertised and the old verifier bounds
  like-for-like.

## 9.2 — tightened reserve input-token bound (minor)

Adds `tokenize.InputTokenBoundV2` and the `input_bound_version` field that selects it on the
reserve request. Nothing about canonical bytes, signing tags, or envelope shape changes, and
the capability is negotiated per-request rather than assumed, so 9.0/9.1/9.2 nodes stay in
each other's candidate and relay pools.

A caller only sizes with v2 against a node advertising >= 9.2 (`UsesTightInputBound`);
everyone else keeps sizing with v1, which every 9.x node still implements and enforces. The
gate is load-bearing in one direction and merely wasteful in the other: sizing v2 against a
pre-9.2 node is a hard failure — v2 is TIGHTER than v1 on prose, tool schemas, and images, so
the node's v1 measurement of the same body exceeds the smaller reserved `input_count` and
admission fails closed with `input_budget_exceeded`. Sizing v1 against a 9.2 node merely
over-reserves, and the node honours the declared version, so nothing breaks.

## 9.1 — relay hop marker (minor)

A relaying node now sets `RelayHopHeader` (`X-Zs-Relay-Hop`) on every response it produces on
`RelayPath`, and skips that key when copying the target's headers back — so its presence
proves the relay's own handler ran, and its ABSENCE (from a node advertising >= 9.1) proves
the request died at the relay's front door without reaching it.

That distinction was previously unavailable: a CDN 504 in front of the relay and a target's
504 forwarded verbatim were byte-identical, both classified `transient.AttrUnknown`, so
neither hop was ever charged and a relay behind a broken gateway stayed in rotation while
every draw benched a healthy target.

**Why a minor, and the distinction is load-bearing**: `ProtoVersionCompatible` is
major-EQUALITY, so 9.0 and 9.1 nodes remain in each other's candidate and relay pools. A 9.0
relay simply doesn't set the header, a 9.1 caller reads its absence as no-evidence
(`SetsRelayHopHeader` returns false), and nothing is dropped. A major would partition the
fleet over a diagnostic header. No canonical-bytes or signing-tag change — the same additive
shape as the 7.1 videoprice and 8.1 payer-sig minors.

## 9.0 — cached-token pricing (major)

`Ticket.CanonicalBytes()` gained `CacheReadRate` and `UsageReceipt.CanonicalBytes()` gained
`CachedInputCount`, both appended at their respective tails, and the ticket and receipt
signing tags bumped their v1 → v2 generation — so 8.x and 9.0 ticket *and* receipt signatures
are mutually unverifiable (a hard pre-image break on BOTH digests, the direct analog of the
5.0 usage-type bump).

Lets an operator price the cached-read subset of the prompt (tokens an upstream served from a
prefix/prompt cache) at a discounted `CacheReadRate` instead of the flat `InputRate`; the node
signs the cached count onto the receipt so the proxy can verify the discount it was charged.
Without the major bump a 9.0 caller would treat an 8.x node as compatible and only fail at
ticket/receipt verification after a wasted reserve. Not a contract redeploy, but the whole
fleet still cuts over together, like 5.0.

## 8.1 — reserve-request payer signature (minor)

`ReserveRequest` gained two optional fields inside the sealed body — `payer_sig` (base64
Ed25519 over the new `zs-reserve-v1\x00` canonical bytes) and `payer_issued_at` —
authenticating `payer_addr` so the node's per-account limiter, funds gate, and abuse tracking
key on a proven identity instead of a spoofable claim (SPEC.md §3a "Reserve-request
signature"). The signature also binds the target `(operator_id, node_id)` and
`proxy_recipient` as unsent signed context.

**Why a minor**: the fields are additive JSON an 8.0 node ignores, and a node accepts a
missing signature until its `zs.require_payer_sig` knob flips (verify-if-present) — so 8.0 and
8.1 peers interoperate. Mirrors the videoprice 7.1 additive-minor precedent; no new
signing-tag break for the existing digests (`zs-reserve-v1` is a fresh, independent domain).
The later enforcement flip is operational, not a wire change.

## 8.0 — relay metadata minimization (major)

The relay now forwards opaque bytes in BOTH directions on BOTH legs. 3.0 sealed the reserve
*request* and declared that a relay "cannot read the payer"; that was not true, because three
cleartext channels survived and a relay forwards a request's reserve and inference legs alike
(see `relay.exactAllowedInnerPaths`). All three close here, and **they only close together** —
leaving any one open re-exposes the payer to the same relay on the same request:

- **(a)** The reserve RESPONSE is sealed to `proxy_recipient` (`SealedReserveResponseContentType`
  / `SealReserveResponse`). Its `presigned_open_txn` named the payer twice, decodable with no
  chain lookup.
- **(b)** The inference REQUEST envelope is ciphertext-only: `algorand_tx_id`, `ticket_id`,
  `admission_tag`, and `reply_to_public_key` moved into an age-sealed inner-request frame
  (`inner.go`). The first two resolve to the payer via the `open()` tx and the `TicketRecord`
  box.
- **(c)** The inference RESPONSE metadata is sealed under `K_response` with the new header AAD
  (`BuildHeaderAAD` / `SealHeader`): `X-Zs-Receipt` and `X-Zs-Settle-Group`, plus the
  `zs-settle-group` SSE frame, which previously shipped the payer-ack template — payer address
  in cleartext — on the reasoning that its txns go on chain anyway. True for a chain observer;
  false for a relay that also holds the client IP.

`ResponseEnvelope` drops its `algorand_tx_id` echo as part of (b): both sides reconstruct the
AAD from state they hold, so the echo only fed the relay.

The AAD *layout* and every signing tag are unchanged from 7.0 — a framing break, not a crypto
one — but a 7.0 envelope decrypts to a body with no inner-request magic and is rejected, and a
7.0 caller cannot parse a sealed reserve response, so the majors must not mix. **The residual
is timing**: `open()` is a public transaction, so a relay can still correlate
(client IP, target, τ) against the chain. See SPEC.md §3f.

## 7.0 — full hayai → zs rename (major)

Two breaks ship together:

- **(a) Transport labels.** The `X-Hayai-*` HTTP headers became `X-Zs-*`; the SSE event tags
  `hayai` / `hayai-receipt` / `hayai-settle-group` / `hayai.usage` became `zs` / `zs-receipt` /
  `zs-settle-group` / `zs.usage`; the envelope MIME `application/vnd.hayai+json` (and the
  sealed-reserve `…-reserve+json`) became `application/vnd.zs+json`; and the HTTP routes
  themselves — `/v1/hayai/{details,reserve,relay,operators,attestation}` — became `/v1/zs/{…}`.
  The OpenAI-compat routes (`/v1/models`, `/v1/chat/completions`, `/v1/responses`, …) are
  untouched.
- **(b) Cryptographic domain-separation tags.** The AAD protocol tag (`aadProtocolTag`
  `"hayai"` → `"zs"`) AND every signing domain (`AdmissionTagDomain`, `ticketSigningTag`,
  `receiptSigningTag`, the ephemeral tag) were renamed `hayai-*` → `zs-*` AND every suffix was
  reset to v1, giving `zs-admission-v1` / `zs-ticket-v1` / `zs-receipt-v1` / `zs-ephemeral-v1`
  — a fresh `zs-*` namespace with a clean v1 baseline. This changes every signature digest AND
  every AEAD AAD, so 6.0 and 7.0 signatures and sealed frames are mutually unverifiable: a hard
  crypto break, not just a framing one. The canonical-byte LAYOUT is unchanged (field order and
  encoding identical to 6.0); only the domain-tag bytes differ, and the suffix reset is cosmetic
  (the prefix change alone already breaks compat). Not a contract redeploy.

Either break alone already makes 6.0 and 7.0 peers non-interoperable.

**Note how (a) changed the way a cross-major mismatch surfaces.** Earlier majors kept
`/v1/hayai/details` stable, so a caller could read a peer's `proto_version` and drop it with an
explicit version-mismatch. Under 7.0 a 7.0 caller probes `/v1/zs/details`, so an un-upgraded
6.0 node (still serving `/v1/hayai/details`) returns 404 and is dropped as *unreachable* rather
than *version-incompatible* — a blunter signal, but the node is excluded from the candidate set
either way, which is the only property the filter needs on a hard cutover.

## 6.0 — ephemeral advertisement binds node_id (major)

The `EphemeralAdvertisement` signed canonical bytes gained `u64(NodeID)` right after
`OperatorID` and the ephemeral signing tag bumped v2 → v3, closing the sibling-node
substitution hole: under 5.0 an operator that reused one signing key across its nodes could
have node A's advert validate as node B's, sealing traffic to a key node B cannot decrypt.

v2 and v3 ephemeral signatures are mutually unverifiable, so a 6.0 verifier rejects every 5.0
node's advertisement and vice versa — the version filter drops them up front instead of failing
at the ephemeral-verify step after a wasted probe. Ticket and receipt canonical bytes and tags
are unchanged from 5.0.

## 5.0 — usage-type wire bump (major)

`Ticket` AND `UsageReceipt` `CanonicalBytes()` gained `UsageType` discriminators at the tail
and the ticket and receipt signing tags bumped to their v2 generation — so 4.0 and 5.0 ticket
*and* receipt signatures are mutually unverifiable (a hard pre-image break on BOTH digests,
unlike 4.0, which left `UsageReceipt` unchanged).

Shipped with dedicated-route image microUSDC pricing (`imageprice`) plus the price-independent
`serves_image_gen` / `serves_image_edit` eligibility flags. 4.0 left the signing tags at v1, so
without this bump a 5.0 caller would treat a 4.0 node as compatible and only fail at
ticket/receipt verification after a wasted reserve.

## 4.0 — operator/node split (major)

The off-chain `Ticket` now carries `node_id`, and `Ticket.CanonicalBytes()` commits to it right
after `operator_id` — so 3.0 and 4.0 ticket signatures are mutually unverifiable (a hard
pre-image break, the same gating role as the 2.0 digest change).

Shipped alongside the fresh-deploy `ZeroSignalEscrow` contract that splits `OperatorRecord`
into a per-owner operator plus many `NodeRecord` boxes; `/v1/zs/details` advertises
`(operator_id, node_id)`. The whole fleet cuts over together with the new app id.
`UsageReceipt` canonical bytes are unchanged.

## 3.0 — transport privacy activated (major)

Single-hop operator-as-relay (SPEC.md §3f). The relay route and selection primitive shipped
DORMANT at 2.0; 3.0 turns them on: privacy defaults ON at the proxy and client, and the reserve
request body is now sealed confidentiality-only (`SealedReserveContentType` /
`SealReserveRequest`) so a relay can no longer read the caller's `payer_addr`.

There is no relay capability flag, so the version-negotiation filter (`ProtoVersionCompatible`
→ `pickCandidates`) drops every pre-relay 2.0/1.0 node from relay-using candidate sets. A 3.0
node only ever talks to 3.0 peers, so the node's reserve handler is sealed-only (415 on
plaintext).

## 2.0 — ticket/receipt digest prefix removal (major)

Removed the obsolete `"MX"` prefix from the ticket and receipt signing digest. The digest is
now `sha256(domain_tag || canonical_bytes)` with the domain tag living inside
`CanonicalBytes()` (unchanged); the pre-image differs from 1.0 by two bytes, so 1.0 and 2.0
signatures are mutually unverifiable.

## 1.0 — initial generation

The baseline. Also the value `LegacyProtoVersion` substitutes for a missing `proto_version`
field on the wire, which marks pre-field nodes incompatible with every current caller.
