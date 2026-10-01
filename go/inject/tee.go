/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// AttestationContentType is the Content-Type for the GET
// /v1/zs/attestation response body. Plaintext JSON (no envelope) —
// like /v1/zs/details, attestation evidence is a discovery
// surface, not a payment-gated request. The proxy's TEE verifier
// reads this directly during its per-operator probe loop.
const AttestationContentType = "application/json"

// TEE mode values carried on the wire — node-advertised on
// /v1/zs/details (TEEAdvertisement.Mode) and inside the evidence
// bundle (TEEEvidenceBundle.Mode). Proxy and node both reference
// these constants so a typo on either side fails fast at compile
// time rather than producing silent verifier mismatches.
//
// Empty string and TEEModeNone are equivalent: they both mean "this
// operator does not advertise TEE". Routing treats them identically.
const (
	TEEModeNone           = "none"
	TEEModeStub           = "stub"
	TEEModeNvidiaCCTDX    = "nvidia-cc-tdx"
	TEEModeNvidiaCCSEVSNP = "nvidia-cc-snp"

	// TEEModeDstackTDX is an Intel TDX confidential VM managed by
	// dstack (Phala Cloud and self-hosted dstack alike). CPU-only: it
	// carries no GPUEAT and makes no NRAS call, which is why the
	// verifier branch for it is disjoint from the nvidia-cc-* ones
	// rather than a special case inside them.
	//
	// What distinguishes it on the wire is EventLog. dstack extends
	// RTMR3 with a runtime event log the node publishes alongside the
	// quote, so a verifier recovers the CVM's compose and OS-image
	// measurements by REPLAYING that log against the hardware-signed
	// RTMR3 — no field on this bundle is trusted for them.
	TEEModeDstackTDX = "dstack-tdx"
)

// TEEAdvertisement is the compact "this operator is TEE-capable"
// advertisement carried inside OperatorDetails on GET /v1/zs/details.
// It tells a discoverer (1) which TEE platform the node claims to run
// on, (2) when its cached evidence was last successfully refreshed,
// and (3) where to fetch the full evidence bundle for verification.
//
// The full evidence is served as TEEEvidenceBundle on the
// EvidenceURL endpoint (typically GET /v1/zs/attestation). The
// proxy verifies the bundle out-of-band before sealing TEE-required
// requests. See proto/TEE.md for the protocol-level threat model and
// proto/SPEC.md §3e for the wire-spec rationale (attestation evidence
// is intentionally NOT bound into per-request AAD — it is a
// routing-time decision).
type TEEAdvertisement struct {
	// Mode is one of "stub", "nvidia-cc-tdx", "nvidia-cc-snp",
	// "dstack-tdx". Empty or absent means the operator does not
	// advertise TEE. "stub" is dev-only — production proxies reject
	// stub evidence unless explicitly opted in via
	// attestation.allow_stub.
	Mode string `json:"mode"`

	// AttestedAt is the GeneratedAt timestamp of the most recent
	// successfully minted evidence bundle. The proxy can use this to
	// gate routing: a node whose advertised AttestedAt is older than
	// 2× the operator's refresh interval is treated as having stale
	// evidence and demoted from the TEE-eligible set.
	AttestedAt time.Time `json:"attested_at"`

	// EvidenceURL is the absolute or path-relative URL where the
	// proxy fetches the full TEEEvidenceBundle. Always
	// /v1/zs/attestation in v1 — kept explicit so a future
	// version can move the endpoint without breaking discovery.
	EvidenceURL string `json:"evidence_url"`
}

// Values for TEEPosture.PlaintextTerminates — where decrypted prompt
// material comes to rest relative to the attested boundary.
const (
	// PlaintextInEnclave the node decrypts and infers inside the
	// measured CVM; plaintext reaches no other host to be answered.
	// Local weights supervised by the node binary. Read the scoping
	// note on TEEPosture before taking "no other host" wider than the
	// inference route.
	PlaintextInEnclave = "in_enclave"

	// PlaintextNamedUpstream the node decrypts inside the measured CVM
	// and forwards the prompt to exactly one named third-party
	// inference API under that API's zero-retention terms. The
	// operator is not that party and — because the forwarding
	// behaviour is fixed by the measured image — cannot become it.
	PlaintextNamedUpstream = "named_upstream"
)

// TEEPosture describes what the attested software DOES with plaintext,
// which the measurement alone does not tell a reader. Two nodes can
// present equally valid quotes and mean very different things by them:
// one runs weights in-CVM, the other forwards to a named API. A payer
// choosing between them needs that difference on the wire rather than
// out of our marketing.
//
// SIGNED BY THE MEASURED BINARY, THEN JUDGED. On dstack-tdx the node
// hashes this block into report_data (attest.HPosture, since 9.10), so a
// verifier that passed the aux binding holds the posture an allowlisted
// image derived from its effective config — after env overrides and
// ${VAR} substitution, which the compose hash never covers. That is why
// it is bound rather than read out of the measured compose: the compose
// text is not the config the binary ran.
//
// Signed is not the same as acceptable. The image validated this value
// at boot, and the verifier re-judges it anyway (NamedUpstreamAdmissible)
// so that one bug in the image's validation does not by itself admit a
// lookalike upstream. On a mode with no aux binding the block is still
// unsigned, and reading it as evidence there gets you a claim signed by
// nobody.
//
// Contrast the trust TIER, which is the verifier's conclusion about a
// node and deliberately never travels on the wire in either direction.
// Posture is the node's CONFIGURED BEHAVIOUR, a different thing.
//
// SCOPE: THIS IS THE INFERENCE ROUTE, not "no prompt-derived byte can
// ever leave". Built-in tools (SPEC § 3d) are caller-initiated — a
// zs_web_search, zs_web_read or zs_image_search call exists for a
// request only because the caller listed that type in the body's
// tools[] — so a node MAY advertise in_enclave and ALSO advertise those
// tools in OperatorDetails.BuiltinTools, and a consumer MUST NOT read
// the pair as a contradiction or demote on it.
//
// TWO THINGS MAKE THAT SOUND AND NEITHER IS SUFFICIENT ALONE, which is
// the half that gets dropped on a re-read. The caller's request fixes
// what was ASKED FOR: omit the types and the admission tag over
// sha256(body) commits to the omission, so no relay can add one. The
// MEASUREMENT fixes what the node does with that — an allowlisted image
// is one known to dispatch a built-in only on a caller-listed type.
// Sealed bytes alone say something about the caller and nothing about
// the node, the same gap this godoc already names for posture itself.
//
// It does not extend to routes the NODE picks. An image backend is one
// the operator points somewhere, invisible to the caller and reachable
// by a dedicated image model with no tool involved, so it is held to
// this block: in-enclave under in_enclave, or an upstream whose
// zero-retention the node confirms per response under named_upstream.
type TEEPosture struct {
	// PlaintextTerminates is PlaintextInEnclave or
	// PlaintextNamedUpstream. An unrecognized value is treated as
	// unknown — never as the stronger of the two.
	PlaintextTerminates string `json:"plaintext_terminates"`

	// UpstreamBaseURL names the single API plaintext is forwarded to
	// when PlaintextTerminates is PlaintextNamedUpstream; empty
	// otherwise. Naming it is the whole point of the weaker posture:
	// "readable by exactly one party" is a claim about a party the
	// payer can identify, so a posture that declines to name one is
	// not making the claim.
	UpstreamBaseURL string `json:"upstream_base_url,omitempty"`

	// ZeroRetention is true when the node refuses to serve a response
	// the named upstream did not confirm zero-retention on — the
	// enforcement the measured image performs, not a promise about the
	// upstream's terms of service.
	ZeroRetention bool `json:"zero_retention,omitempty"`

	// UpstreamAttested is true when the node is configured to appraise
	// its named upstream's own enclave (tee.upstream_attestation). The
	// bundle's upstream_attestation block is unsigned, so this bound bit
	// is what stops a relay from adding one to a node that never
	// verified its upstream: NamedUpstreamAdmissible requires both.
	UpstreamAttested bool `json:"upstream_attested,omitempty"`

	// malformed marks a posture the bundle carried with a wrong type,
	// which TypeScript's hPosture refuses rather than hashes; see
	// TEEEvidenceBundle.UnmarshalJSON.
	malformed bool
}

// Malformed reports a posture decoded from a wrongly typed block. It has
// no hash: attest.HPosture refuses it, as TypeScript's hPosture does.
func (p *TEEPosture) Malformed() bool { return p != nil && p.malformed }

// NamedUpstreamAdmissible is the verifier's judgement of a named_upstream
// posture — the one decision the proxy and client/ must make identically
// about the upstream a payer is told reads their prompt. It is meaningful
// only on a posture the aux binding verified (attest.HPosture), since before
// 9.10 anything on the path could rewrite this block.
//
// Admissible means: the upstream is https with a host in the subset both
// languages parse the same way, and EITHER it is xAI and the node enforces
// xAI's per-response zero-retention header, OR the node is configured to
// appraise the upstream's own enclave (the ACI gateway path) and the bundle
// carries that appraisal.
//
// The ACI branch takes two inputs because only one is signed. The posture's
// UpstreamAttested bit is bound; upstreamAttested (UpstreamAttested of the
// bundle's block) is not, so a relay could add a block but cannot set the
// bit. The block is still required: the node drops it while its appraisal of
// the upstream has lapsed, and admitting on the bit alone would route to a
// node that is refusing requests for exactly that reason. This does not
// verify the block's contents; a payer who wants that fetches report_url.
//
// Every input the decision rests on is bound, so this repeats the node's
// boot validation as defense in depth: a bug in either one alone does not
// admit a lookalike.
func NamedUpstreamAdmissible(p *TEEPosture, upstreamAttested bool) bool {
	if p == nil || p.malformed || p.PlaintextTerminates != PlaintextNamedUpstream {
		return false
	}
	if _, ok := HTTPSUpstreamHost(p.UpstreamBaseURL); !ok {
		return false
	}
	if p.UpstreamAttested && upstreamAttested {
		return true
	}
	return p.ZeroRetention && InferDialect(p.UpstreamBaseURL) == DialectXAI
}

// TEEEvidenceBundle is the body of GET /v1/zs/attestation. It
// carries the cryptographic evidence the proxy needs to verify a
// node runs in confidential mode: the CPU TEE report (Intel TDX or
// AMD SEV-SNP, base64-encoded), the NVIDIA GPU Entity Attestation
// Token (EAT JWT), and the (NodePubkey, OperatorID) pair whose
// SHA-256 binding into the report's report_data / REPORT_DATA /
// nonce field the proxy must re-verify (see proto/TEE.md §4 for the
// key-binding protocol).
//
// Not every field applies to every mode, and which ones do is decided
// by Mode: the nvidia-cc-* modes carry GPUEAT and no EventLog,
// dstack-tdx carries EventLog and no GPUEAT. A verifier branches on
// the PLATFORM IT DERIVED FROM CPUReport's bytes rather than on this
// self-reported Mode string — otherwise Mode becomes a vendor-chain
// selector the operator controls.
//
// Stub mode (Stub == true) produces a deterministic bundle with
// empty CPUReport / GPUEAT — production proxies MUST reject Stub ==
// true unless explicitly opted in. Stub mode exists so the whole
// pipeline (config gate, /v1/zs/attestation handler, /details
// surface, proxy verifier path, UI badge, routing filter) can be
// exercised on a developer laptop without H100 hardware.
type TEEEvidenceBundle struct {
	// Mode mirrors the same field on TEEAdvertisement.
	Mode string `json:"mode"`

	// CPUReport is the base64-encoded TDX or SEV-SNP attestation
	// report (whichever the host produces). Empty in stub mode.
	CPUReport string `json:"cpu_report,omitempty"`

	// GPUEAT is the NVIDIA Entity Attestation Token JWT (signed by
	// NRAS or — in self-hosted deployments — verifiable via the
	// nvtrust SDK). Empty in stub mode and on CPU-only modes such as
	// TEEModeDstackTDX.
	GPUEAT string `json:"gpu_eat,omitempty"`

	// EventLog is the platform's runtime measurement log as raw JSON,
	// carried only by modes that have one (TEEModeDstackTDX). It is
	// the input to a REPLAY: the verifier recomputes RTMR3 from these
	// events and compares against the RTMR3 the hardware signed inside
	// CPUReport. A log that does not replay to the quote's value tells
	// the verifier nothing, which is the point — the log is untrusted
	// data whose only power is to be checkable against the quote.
	//
	// The measurements a verifier actually gates on — compose-hash and
	// os-image-hash — are RECOVERED FROM THE REPLAY, and deliberately
	// have no fields of their own on this bundle. Carrying them
	// separately would invite a verifier to read the self-report
	// instead of replaying, which is the entire failure the replay
	// exists to prevent; the cheap wrong implementation would then
	// look identical to the correct one and pass every test.
	//
	// Empty in stub mode and on modes with no runtime log.
	EventLog string `json:"event_log,omitempty"`

	// AppCompose is the dstack `app-compose.json` document verbatim —
	// the PREIMAGE of the compose-hash the replay recovers, not a
	// second path to its value. That distinction is the whole reason
	// this is allowed to exist beside the rule stated on EventLog
	// above: a verifier hashes these bytes and refuses them unless the
	// digest equals the measured compose-hash, so a hostile operator
	// substituting a friendly-looking document changes the digest and
	// is caught. There is nothing here to trust and therefore nothing
	// to self-report.
	//
	// It exists because a hash alone cannot be allowlisted at fleet
	// scale. compose-hash covers the operator's own configuration, so
	// every operator and every redeploy produces a distinct value, and
	// no verifier can enumerate those. With the preimage in hand a
	// verifier checks the document's CONTENT and what remains
	// enumerable is a per-RELEASE list. See attest.VerifyAppCompose,
	// which is the one implementation of those rules per language.
	//
	// WHAT VerifyAppCompose CHECKS TODAY, and the gap, because the
	// difference decides whether a passing result means anything:
	// manifest version, runner, allowed_envs, pre-launch script digest
	// and the platform toggles are enforced. THE IMAGE IS NOT. Nothing
	// yet parses docker_compose_file beyond a non-emptiness test, so a
	// compose pinning `image: ${SOME_VAR}` — a stable hash over
	// arbitrary code, which our own probe compose demonstrates —
	// passes every rule in the package. Do not describe a clean
	// VerifyAppCompose as "content-validated" until that lands; it
	// means "nothing structurally disqualifying, image unchecked".
	//
	// Present on TEEModeDstackTDX only — empty in stub mode and on
	// every mode that has no such document. Within that mode a
	// verifier MUST NOT treat an absent or empty value as a check that
	// passed: skipping is exactly the state a node with something to
	// hide would engineer. It is not automatically a rejection either
	// — a verifier MAY still accept such a node through an explicit,
	// hand-configured compose-hash allowlist — but never as
	// content-validated.
	AppCompose string `json:"app_compose,omitempty"`

	// Posture is the node's description of where plaintext terminates.
	// On dstack-tdx it is bound into report_data (see TEEPosture); on
	// other modes it is unsigned. Absent on modes that have not defined
	// one.
	Posture *TEEPosture `json:"posture,omitempty"`

	// NodePubkey is the node's current signed ephemeral age recipient
	// — the EphemeralAgePubkey on /v1/zs/details, i.e. the key requests
	// are actually sealed to. Deliberately NOT the on-chain signing
	// address: attesting the identity key would prove only that the
	// enclave controls the operator identity, leaving the hop from that
	// key to the sealing key operator-attested. Because the ephemeral
	// rotates (~20 min), the node re-mints on rotation; a rotated but
	// not-yet-re-minted node fails closed until the next probe.
	//
	// A verifier MUST cross-check this against the ephemeral it
	// independently verified for the operator rather than trusting the
	// self-report — see proto/SPEC.md §3e checks 1 and 3.
	NodePubkey string `json:"node_pubkey"`

	// OperatorID is the operator's on-chain id — the second input
	// to the report_data binding hash.
	OperatorID uint64 `json:"operator_id"`

	// ReportData is the base64-encoded SHA-256(NodePubkey ||
	// be64(OperatorID)) value the in-enclave binary asked the CPU to
	// embed into the attestation report. The proxy recomputes it from
	// the ephemeral recipient it INDEPENDENTLY verified this cycle plus
	// the chain-resolved operator id — never from this bundle's
	// self-report of either, or a hostile operator could pair a real
	// attestation report with a substituted key — and compares;
	// mismatch is `key_binding_mismatch` per proto/TEE.md.
	ReportData string `json:"report_data"`

	// AppModels is the H_app preimage: the model catalog the node
	// advertises on /v1/zs/details, as it hashed it into report_data's
	// upper half.
	//
	// The bundle publishes the entries rather than H_app so a verifier can
	// recompute H_app itself and compare the result with the signed half:
	//
	//     report_data[32:64] == attest.AuxBinding(
	//         node_id,                    // chain-resolved, never from the bundle
	//         attest.HApp(app_models),    // this field, as received
	//         nonce,                      // see Nonce
	//     )
	//
	// Call attest.ReportDataHalves.VerifyAux rather than assembling that
	// by hand. It also makes the nonce and empty-list decisions, which
	// every verifier must make identically.
	//
	// The bundle does not carry node_id; the verifier must use the
	// chain-resolved id. An id taken from the bundle would let a node
	// present a sibling's bundle, since the sibling's id recomputes the
	// sibling's binding.
	//
	// Order does not matter: HApp sorts internally. `omitempty` means an
	// empty catalog and an absent field look the same on the wire; both
	// hash as HAppPending, and AuxBinding over that is non-zero. A verifier
	// must read an empty or absent list as the node attesting that it
	// serves no models.
	//
	// Decoded by exact key (see UnmarshalJSON), like Nonce.
	AppModels []ModelEntry `json:"app_models,omitempty"`

	// Nonce is the caller's `?nonce=` challenge, echoed as hex. Absent on
	// the cached bundle.
	//
	// A verifier that sent a challenge N passes N to VerifyAux, which
	// refuses the bundle unless this field decodes to N. A verifier that
	// sent none passes nil, and VerifyAux hashes this field if present or
	// 32 zero bytes if absent.
	Nonce string `json:"nonce,omitempty"`

	// GeneratedAt is when the bundle was minted (UTC). The proxy
	// considers a bundle older than 2× the node's refresh interval
	// stale and demotes the operator out of the TEE-eligible set.
	GeneratedAt time.Time `json:"generated_at"`

	// RefreshSeconds advertises the node's configured refresh
	// cadence so the proxy can size its own re-verification loop.
	RefreshSeconds int `json:"refresh_seconds"`

	// Stub is true for the dev-only stub provider (see godoc above).
	// Production proxies MUST reject Stub == true unless explicitly
	// opted in.
	Stub bool `json:"stub,omitempty"`

	// UpstreamAttestation describes the enclave this node forwards
	// plaintext TO, when the node verifies one. Absent on every
	// sealed_local node, because there is no upstream.
	//
	// It says nothing about THIS node — the rest of this bundle does
	// that. Read the two together or not at all: an attested upstream
	// under an unattested node is a stronger-sounding claim than
	// either half supports.
	UpstreamAttestation *UpstreamAttestation `json:"upstream_attestation,omitempty"`

	// Collateral is the Intel-signed collateral set for THIS quote's
	// platform, fetched by the node at mint time. Optional and
	// additive.
	//
	// A FALLBACK FOR VERIFIERS, NOT THEIR DEFAULT SOURCE, and the
	// distinction is the reason this godoc is long. Nothing here can
	// be forged: every document is signed by Intel and re-validated
	// against the verifier's own embedded Intel root before use, so a
	// node that substitutes, edits, or truncates any of it produces a
	// verification failure rather than a false pass.
	//
	// But unforgeable contents are not an honest CHOICE OF VINTAGE.
	// Each document carries a validity window (TCB info and QE
	// identity issueDate/nextUpdate; thisUpdate/nextUpdate on both
	// CRLs) and a verifier can only enforce that window — which for
	// TCB info is roughly thirty days. Inside it a node may serve any
	// older, still-validly-signed publication, including one from
	// before its own platform TCB was downgraded to OutOfDate, or a
	// CRL from before its PCK certificate was revoked. Preferring
	// node-served collateral would therefore let the party being
	// attested choose the criteria it is attested against. Verifiers
	// SHOULD fetch from a PCCS and use this only when that fetch
	// fails, and SHOULD apply a freshness floor tighter than Intel's
	// own nextUpdate to what they accept here.
	//
	// What it buys, then, is availability rather than latency: a
	// verdict during a PCCS outage or (in a browser) a CORS
	// regression, on a path where the alternative is every
	// confidential operator reading as unverifiable at once. It also
	// spares a relay-mode browser the direct PCCS connection that
	// discloses the payer's IP, platform, and timing to a third party
	// — real, but a weaker leak than the operator learning the same,
	// and not on its own a reason to prefer this over fetching.
	//
	// Absent in stub mode and on modes with no Intel collateral.
	Collateral *TEECollateral `json:"collateral,omitempty"`
}

// Upstream-attestation protocols. Named for the protocol, not the vendor:
// Phala runs one ACI/1 deployment under three hostnames, and anyone else
// speaking it verifies the same way.
const UpstreamProtocolACI1 = "aci/1"

// UpstreamAttested reports whether a bundle's upstream_attestation block
// counts for NamedUpstreamAdmissible: present, and naming a protocol this
// build recognizes. Anything else is unverifiable, per the Protocol field's
// MUST. The TypeScript upstreamAttested takes the raw JSON value and must
// agree; the dialect vectors pin the two together.
func UpstreamAttested(ua *UpstreamAttestation) bool {
	return ua != nil && ua.Protocol == UpstreamProtocolACI1
}

// UpstreamAttestation is what a node publishes about the enclave it forwards
// plaintext TO, under tee.dataflow=attested_passthrough.
//
// WHAT IS AND IS NOT CARRIED HERE, because the choice is the design. This
// struct holds POINTERS AND DIGESTS, not the upstream's evidence. The
// evidence itself is fetchable by the payer directly from the upstream,
// unauthenticated — measured 2026-09-24: `/v1/aci/attestation` answers without
// an API key, and so does `/v1/aci/sessions/{id}`, whose per-session blob runs
// to ~267 KB. Carrying that would put a quarter-megabyte on every
// /v1/zs/attestation fetch to save the payer a request they should be making
// anyway, because a report fetched WITH THE PAYER'S OWN NONCE proves freshness
// that a report relayed by the node cannot.
//
// So this block's job is to say what to fetch, what it must hash to, and what
// this node conceded when it appraised the same evidence — not to be the
// evidence. The node's own verdict is deliberately absent: a verdict is the
// one thing a payer must never take from the party under appraisal.
type UpstreamAttestation struct {
	// Protocol is the verifier class, e.g. UpstreamProtocolACI1. A
	// payer that does not recognize it MUST treat this block as
	// unverifiable rather than ignore it and accept the rest.
	Protocol string `json:"protocol"`

	// BaseURL is the upstream the node forwards to, and the host whose
	// TLS key the node pinned. Same value as TEEPosture.UpstreamBaseURL
	// and carried again here so this block is self-contained.
	BaseURL string `json:"base_url"`

	// ReportURL is where the upstream's own attestation report lives.
	// A payer SHOULD fetch it with a fresh nonce of their own; that is
	// what makes it evidence rather than a recording.
	ReportURL string `json:"report_url,omitempty"`

	// KeysetDigest is the sha256(JCS(workload_keyset)) the upstream's
	// quote commits to in report_data — the root of the whole chain,
	// since the keyset carries both the serving TLS key and the
	// receipt-signing key. Rendered "sha256:<hex>".
	KeysetDigest string `json:"keyset_digest,omitempty"`

	// VerifiedAt is when this node last completed a full appraisal
	// (UTC), and LeaseExpiresAt is when that verdict stops being
	// reusable — never later than the upstream keyset's own not_after.
	//
	// Both are the NODE's self-report and bound nothing on their own.
	// They are here so a payer can see a node holding a stale verdict
	// without having to re-derive the upstream's expiry.
	//
	// LeaseExpiresAt uses `omitzero` rather than `omitempty`, which has
	// no effect on a struct and would have emitted a zero timestamp
	// while reading as though it suppressed one.
	VerifiedAt     time.Time `json:"verified_at"`
	LeaseExpiresAt time.Time `json:"lease_expires_at,omitzero"`

	// CarveOuts names every rule the node's upstream appraisal
	// DOWNGRADED rather than enforced, as "<violation_code>:<detail>"
	// — today only `root_backdoor_env:<ENV_NAME>`.
	//
	// THIS FIELD IS THE HONEST HALF OF THE TIER AND MUST NOT BE
	// OMITTED WHEN NON-EMPTY. Both Phala tiers declare a dstack
	// root-shell env channel today, which our own compose policy
	// refuses on our own nodes; an operator may accept that from an
	// upstream, and a payer is entitled to know they did. dstack
	// measures env NAMES and not VALUES, so nobody — including the
	// node — can tell whether the channel was used; and RTMR3 records
	// boot rather than runtime, so a shell changes what runs while
	// every other check keeps passing.
	//
	// A verifier MUST therefore treat a non-empty CarveOuts as capping
	// what a clean appraisal means, not as a footnote on one. An empty
	// or absent list means the node enforced every rule its policy
	// carries — it does NOT mean the policy was strict.
	CarveOuts []string `json:"carve_outs,omitempty"`
}

// TEECollateral is the Intel-signed collateral a verifier needs to
// judge a TDX quote's platform TCB: the revocation lists, the TCB
// info for the quote's FMSPC, and the QE identity — each with the
// issuer chain that roots it at Intel.
//
// FIELD NAMES AND ENCODINGS MIRROR INTEL'S QVL COLLATERAL STRUCTURE
// verbatim, deliberately. Both verifiers in this project consume a
// third-party implementation of it (Go: go-tdx-guest; TS:
// @phala/dcap-qvl), and inventing our own spelling would mean a
// translation layer on both sides whose bugs would look exactly like
// attestation failures.
//
// Nothing here is believed on the node's say-so — see the Collateral
// field's godoc. A verifier MUST validate each issuer chain against
// its own embedded Intel root CA and MUST NOT skip a check because a
// document is absent: a missing field is a check that did not run,
// which is the state a node with something to hide would engineer.
// Fall back to fetching, or refuse; never pass. A PARTIAL set is the
// same thing as an absent one and must be treated as such — accepting
// eight of these nine fields and shrugging at the ninth is precisely
// the hole worth engineering.
type TEECollateral struct {
	// PCKCRLIssuerChain is the PEM certificate chain that signs
	// PCKCRL.
	//
	// PERCENT-DECODED PEM, not the header value verbatim. A PCCS
	// serves these chains URL-encoded, because PEM's newlines cannot
	// ride an HTTP header raw (measured against Phala's mirror:
	// spaces arrive as %20, "+" as %2B, newlines as %0A). A producer
	// that copies the header through ships something that parses to
	// ZERO certificates at every verifier while looking present in
	// its own logs — so decode before assigning. Decode with the
	// path form, not the query form: query decoding turns "+" into a
	// space, and while Intel encodes "+" as %2B today, a mirror that
	// does not would silently corrupt the base64.
	PCKCRLIssuerChain string `json:"pck_crl_issuer_chain"`

	// RootCACRL is the Intel root CA revocation list, hex-encoded
	// DER. Hex rather than base64 because that is what a PCCS
	// serves and what both verifiers already parse.
	RootCACRL string `json:"root_ca_crl"`

	// PCKCRL is the PCK revocation list for this platform's CA,
	// hex-encoded DER.
	PCKCRL string `json:"pck_crl"`

	// TCBInfoIssuerChain is the PEM chain that signs TCBInfo,
	// percent-decoded — see PCKCRLIssuerChain.
	TCBInfoIssuerChain string `json:"tcb_info_issuer_chain"`

	// TCBInfo is the `tcbInfo` object of the PCCS response,
	// serialized verbatim — the exact bytes the signature covers.
	// Re-serializing it through a struct would reorder keys and
	// break the signature, so it travels as an opaque string.
	TCBInfo string `json:"tcb_info"`

	// TCBInfoSignature is the signature over TCBInfo, hex-encoded.
	TCBInfoSignature string `json:"tcb_info_signature"`

	// QEIdentityIssuerChain is the PEM chain that signs QEIdentity,
	// percent-decoded — see PCKCRLIssuerChain.
	QEIdentityIssuerChain string `json:"qe_identity_issuer_chain"`

	// QEIdentity is the `enclaveIdentity` object of the PCCS
	// response, serialized verbatim. Same signature-coverage rule as
	// TCBInfo.
	QEIdentity string `json:"qe_identity"`

	// QEIdentitySignature is the signature over QEIdentity,
	// hex-encoded.
	QEIdentitySignature string `json:"qe_identity_signature"`
}

// Complete reports whether all nine members are present.
//
// EXECUTABLE FORM OF THE "a partial set is an absent set" RULE, which
// the struct godoc above states and SPEC.md §3e states normatively.
// Prose cannot be the only home for it: the rule's whole point is that
// accepting eight of nine fields is the hole a node with something to
// hide would engineer, and a MUST asserted in three documents and
// executed nowhere is one careless consumer away from being false.
// Producers call it before publishing; verifiers call it before
// believing.
//
// Note what it is deliberately NOT: a validity check. Whether the
// documents verify is dcap-qvl's / go-tdx-guest's answer, given against
// Intel's root. This only answers "is there a complete set here to ask
// that question about".
//
// A nil receiver is not complete, so an absent bundle field needs no
// separate nil check at the call site.
func (c *TEECollateral) Complete() bool {
	if c == nil {
		return false
	}
	return !slices.Contains([]string{
		c.PCKCRLIssuerChain,
		c.RootCACRL,
		c.PCKCRL,
		c.TCBInfoIssuerChain,
		c.TCBInfo,
		c.TCBInfoSignature,
		c.QEIdentityIssuerChain,
		c.QEIdentity,
		c.QEIdentitySignature,
	}, "")
}

// ---------------------------------------------------------------------------
// The H_app preimage — proto 9.9
//
// The entry list the node publishes so a verifier can recompute H_app and
// compare it with the aux binding in report_data's upper half. attest.HApp
// aliases both types instead of defining its own, so a verifier hashes the
// struct it decoded, with no conversion step that could drop a field.
// ---------------------------------------------------------------------------

// WeightsState says what an entry's weights digest is based on. Measured
// and declared digests are the same kind of string, so without this field a
// verifier could not tell a hash the node computed from one the operator
// typed into its config.
//
// Zero is not a state. A producer that forgets to set State, or a JSON entry
// that omits weights_state, must not decode as the strongest claim, so HApp
// refuses 0 as an unknown state.
type WeightsState uint8

const (
	// WeightsMeasured: code inside the node hashed the weight files, or took
	// the digest from a runtime that reports what it loaded.
	WeightsMeasured WeightsState = 1
	// WeightsDeclared: the operator pinned the digest in config and the node
	// did not confirm it.
	WeightsDeclared WeightsState = 2
	// WeightsUnverifiable: no digest. Hosted passthrough, image models and
	// models whose files the node could not hash are in this state, and it
	// is a valid entry.
	WeightsUnverifiable WeightsState = 3
)

// String is for logs and CLI output. The wire form is the number.
func (s WeightsState) String() string {
	switch s {
	case WeightsMeasured:
		return "measured"
	case WeightsDeclared:
		return "declared"
	case WeightsUnverifiable:
		return "unverifiable"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// ModelEntry is one advertised model as it enters H_app.
//
// Every field enters the digest, including empty ones: an empty Source is a
// four-byte zero length in the preimage. None of the fields has `omitempty`,
// so every key is present in the JSON a node produces.
//
// Decoding is strict (UnmarshalJSON): an entry with a missing key, a null,
// or a value of the wrong type is marked malformed, and HApp refuses it. A
// lenient Go decoder would read a missing weights_digest as "" and a missing
// weights_state as 0, while JSON.parse leaves them undefined, so the two
// verifiers would hash different preimages for one bundle.
type ModelEntry struct {
	// ModelID is the id the node advertises and a caller puts in `model`.
	ModelID string `json:"model_id"`
	// Source is the provenance ref (a HuggingFace repo, typically), empty
	// when the node resolved none.
	Source string `json:"source"`
	// WeightsDigest is "sha256:<hex>", or empty for WeightsUnverifiable.
	//
	// The FORMAT is deliberately not validated. The state/emptiness rule
	// is the invariant that carries meaning; pinning the string shape here
	// would make a future digest scheme a breaking change to a signature
	// format, for a check that catches nothing an attacker would do — they
	// would supply a well-formed digest of the wrong bytes.
	WeightsDigest string `json:"weights_digest"`
	// State says what the digest is based on. See WeightsState.
	State WeightsState `json:"weights_state"`

	// malformed is set by UnmarshalJSON; see Malformed.
	malformed bool
}

// Malformed reports whether the JSON this entry was decoded from lacked a
// key, carried a null, or had a value of the wrong type. HApp refuses a
// malformed entry. An entry built in Go is never malformed.
func (e ModelEntry) Malformed() bool { return e.malformed }

// UnmarshalJSON decodes one entry strictly. It never returns an error for a
// bad entry: it marks the entry malformed so HApp refuses it with
// ErrMalformedModelEntry, the same code the TypeScript hApp throws, and
// verifiers report both as happ_preimage_invalid rather than as a bundle
// that failed to parse.
//
// weights_state is read as a JSON number and must be an integer. An integer
// outside 0..255 is stored as 0, which HApp refuses as an unknown state, so
// 300 fails the same way in Go and TypeScript. 1.0 is accepted as 1, as
// JSON.parse does.
func (e *ModelEntry) UnmarshalJSON(b []byte) error {
	*e = ModelEntry{malformed: true}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || raw == nil {
		return nil
	}
	str := func(key string, dst *string) bool {
		v, ok := raw[key]
		if !ok || string(v) == "null" {
			return false
		}
		return json.Unmarshal(v, dst) == nil
	}
	var id, src, digest string
	if !str("model_id", &id) || !str("source", &src) || !str("weights_digest", &digest) {
		return nil
	}
	v, ok := raw["weights_state"]
	if !ok || string(v) == "null" {
		return nil
	}
	var f float64
	if json.Unmarshal(v, &f) != nil || f != math.Trunc(f) {
		return nil
	}
	state := WeightsState(0)
	if f >= 0 && f <= 255 {
		state = WeightsState(f)
	}
	*e = ModelEntry{ModelID: id, Source: src, WeightsDigest: digest, State: state}
	return nil
}

// jsonKeys returns T's json tag names. It panics on an exported field with no
// tag, because Go would decode that field under its Go name with case
// folding, which is what decodeExact exists to prevent.
func jsonKeys[T any]() map[string]bool {
	t := reflect.TypeFor[T]()
	keys := make(map[string]bool, t.NumField())
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" {
			panic(fmt.Sprintf("inject: %s.%s has no json tag", t.Name(), f.Name))
		}
		if name != "-" {
			keys[name] = true
		}
	}
	return keys
}

var (
	bundleKeys     = jsonKeys[TEEEvidenceBundle]()
	postureKeys    = jsonKeys[TEEPosture]()
	collateralKeys = jsonKeys[TEECollateral]()
	upstreamKeys   = jsonKeys[UpstreamAttestation]()
)

// decodeExact decodes a JSON object into v using only the keys that exactly
// match one of v's json tags. Go's default decoding matches keys
// case-insensitively (with Unicode folding, so "ſ" matches "s") and keeps the
// last match, while JavaScript reads the exact key, so an object carrying
// both "tcb_info" and "TCB_INFO" would otherwise give the Go and TypeScript
// verifiers different documents. fix, if set, may rewrite the kept values
// before they are decoded.
//
// v must be a method-less alias of the type being decoded, or its
// UnmarshalJSON would call itself.
func decodeExact[T any](data []byte, v *T, keys map[string]bool, fix func(map[string]json.RawMessage)) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	maps.DeleteFunc(raw, func(k string, _ json.RawMessage) bool { return !keys[k] })
	if fix != nil {
		fix(raw)
	}
	// Re-encoding changes whitespace and escaping and sorts the keys; every
	// kept value decodes to what it did before.
	exact, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(exact, v)
}

// UnmarshalJSON decodes a bundle so that the Go and TypeScript verifiers
// reach the same verdict from the same bytes.
//
// It refuses a body that is not valid UTF-8. Both decoders replace invalid
// bytes with U+FFFD, but Go writes one per bad byte and TextDecoder one per
// maximal subpart, so a model id carrying bad bytes would hash differently
// in each.
//
// Keys are matched exactly, here and in posture, collateral and
// upstream_attestation (see decodeExact).
//
// A wrongly typed nonce, app_models or posture does not fail the decode.
// TypeScript reads those values as they are and refuses them in verifyAux,
// with a tag that names the node, so Go replaces them with values VerifyAux
// refuses the same way: a nonce that is not 64 hex characters, an app_models
// holding one malformed entry, and a posture marked Malformed. A wrongly
// typed field outside the aux binding still fails the whole decode.
func (b *TEEEvidenceBundle) UnmarshalJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("inject: evidence bundle is not valid UTF-8")
	}
	type plain TEEEvidenceBundle
	var malformedPosture bool
	err := decodeExact(data, (*plain)(b), bundleKeys, func(raw map[string]json.RawMessage) {
		coerceAuxFields(raw)
		if v, ok := raw["posture"]; ok && !postureWellTyped(v) {
			delete(raw, "posture")
			malformedPosture = true
		}
	})
	if err == nil && malformedPosture {
		b.Posture = &TEEPosture{malformed: true}
	}
	return err
}

// postureWellTyped reports whether v has the shape TypeScript's hPosture
// hashes rather than refuses: null, or an object whose four fields are each
// absent, null, or of their type. Other keys are ignored on both sides.
func postureWellTyped(v json.RawMessage) bool {
	if jsonKindIs(v, 'n') {
		return true
	}
	var fields map[string]json.RawMessage
	if !jsonKindIs(v, '{') || json.Unmarshal(v, &fields) != nil {
		return false
	}
	for key, kinds := range map[string][]byte{
		"plaintext_terminates": {'"', 'n'},
		"upstream_base_url":    {'"', 'n'},
		"zero_retention":       {'t', 'f', 'n'},
		"upstream_attested":    {'t', 'f', 'n'},
	} {
		if f, ok := fields[key]; ok && !jsonKindIs(f, kinds...) {
			return false
		}
	}
	return true
}

// coerceAuxFields replaces a nonce that is not a string or null, and an
// app_models that is not an array or null; see TEEEvidenceBundle.UnmarshalJSON.
func coerceAuxFields(raw map[string]json.RawMessage) {
	if v, ok := raw["nonce"]; ok && !jsonKindIs(v, '"', 'n') {
		raw["nonce"] = json.RawMessage(`"not a nonce"`)
	}
	if v, ok := raw["app_models"]; ok && !jsonKindIs(v, '[', 'n') {
		raw["app_models"] = json.RawMessage(`[null]`)
	}
}

// jsonKindIs reports whether v's first byte is one of kinds: '"' a string,
// '[' an array, '{' an object, 't'/'f' a boolean, 'n' null.
func jsonKindIs(v json.RawMessage, kinds ...byte) bool {
	v = bytes.TrimLeft(v, " \t\r\n")
	return len(v) > 0 && slices.Contains(kinds, v[0])
}

// UnmarshalJSON matches keys exactly; see decodeExact.
func (p *TEEPosture) UnmarshalJSON(data []byte) error {
	type plain TEEPosture
	return decodeExact(data, (*plain)(p), postureKeys, nil)
}

// UnmarshalJSON matches keys exactly; see decodeExact.
func (c *TEECollateral) UnmarshalJSON(data []byte) error {
	type plain TEECollateral
	return decodeExact(data, (*plain)(c), collateralKeys, nil)
}

// UnmarshalJSON matches keys exactly; see decodeExact.
func (u *UpstreamAttestation) UnmarshalJSON(data []byte) error {
	type plain UpstreamAttestation
	return decodeExact(data, (*plain)(u), upstreamKeys, nil)
}
