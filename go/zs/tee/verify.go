/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package tee verifies the attestation evidence a ZeroSignal node
// publishes: the bundle-level checks every platform shares, the dstack TDX
// verifier, and the process-wide cache of Intel collateral both use. The
// payer SDK (package zs) fetches the evidence and calls a Verifier; a
// program that inspects a node's evidence on its own can call the same
// functions without the rest of the SDK.
package tee

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
)

// EvidenceMaxAgeCeiling is the widest evidence-age window this verifier
// will apply, whatever the bundle's own refresh_seconds says. It exists
// because refresh_seconds is node-authored: without a ceiling, "2× the
// advertised cadence" is a bound the attested party chooses for itself,
// and omitting the field removed the check entirely.
//
// IT CANNOT REJECT AN HONEST NODE, which is what makes it safe to apply
// unconditionally rather than as a config knob. The bound that matters
// is ticket.MaxEphemeralLifetime, because that is the widest signed
// window this verifier will accept an ephemeral over at all — so no
// bundle whose binding we accept can be usefully older than that plus
// ticket.DefaultEphemeralSkew, whatever it claims. 2× leaves the
// ceiling outside it, which is what TestEvidenceMaxAgeCeilingCovers-
// EphemeralWindow pins. (Separately and more loosely: an honest node
// re-mints on rotation, server.EphemeralRotationPeriod ~20m, so its
// bundles are far younger still. That is why the ceiling is never felt
// in practice — but it is not the load-bearing bound, and the ceiling
// is deliberately derived from the constant a verifier enforces rather
// than from a node-side setting it cannot see.)
//
// Note what this does NOT say. It is not "an accepted bundle is always
// young": IssuedAt is operator-authored on exactly the same footing as
// GeneratedAt, so a node CAN sign a fresh advertisement window over a
// key it minted long ago (proto/TEE.md § 4.2), and the signed window
// bounds the age of the ADVERTISEMENT, not of the key or the evidence.
// What defeats that is the private half being gone, not this ceiling.
// The ceiling's job is narrower and worth stating exactly: it stops
// refresh_seconds — the node's own field — from being the only bound a
// payer has on evidence age.
//
// THE LITERAL IS DELIBERATE — do not rewrite it as
// 2*ticket.MaxEphemeralLifetime. The twin, EVIDENCE_MAX_AGE_CEILING_MS
// in sdk/src/tee/tags.ts, is a hand-written millisecond literal, and a
// derived value here would track a MaxEphemeralLifetime change on its
// own while the TypeScript side sat still — two verifiers disagreeing,
// both suites green. TestEvidenceMaxAgeCeilingCoversEphemeralWindow
// fails instead, which is the prompt to move both by hand.
const EvidenceMaxAgeCeiling = 80 * time.Minute

// Verifier failure tags. These are the canonical tags proto/SPEC.md §3e
// "Verifier responsibilities" names step by step, and they populate the
// FailureTag field on zs.TEEStatus. (proto/TEE.md §4.3 walks the same
// checks in prose and names no tags — don't look for a column there.)
// They are the canonical telemetry handles for diagnosing verification
// problems — keep them stable so dashboards / alerts / logs can be
// indexed against them.
const (
	FailureKeyBindingMismatch    = "key_binding_mismatch"
	FailureStubNotAllowed        = "stub_not_allowed"
	FailureVerifierNotImpl       = "verifier_not_implemented"
	FailureVendorChainInvalid    = "vendor_chain_invalid"
	FailureNRASUnreachable       = "nras_unreachable"
	FailureAdvertisementMismatch = "advertisement_mismatch"
	FailureFetchFailed           = "fetch_failed"
	FailureStaleEvidence         = "stale_evidence"

	// The aux-binding tags come from proto (attest.AuxFailureTag), so the
	// proxy and client report identical strings; see attest.Err* for each.
	// They are separate from FailureKeyBindingMismatch because the fix
	// differs: that tag means the node attested the wrong key, these mean
	// the node predates 9.9, published a catalog that cannot be hashed, or
	// published a catalog, node id or nonce that does not match what the
	// hardware signed.
	FailureAuxBindingAbsent       = attest.TagAuxBindingAbsent
	FailureAuxBindingMismatch     = attest.TagAuxBindingMismatch
	FailureHAppPreimageMissing    = attest.TagHAppPreimageMissing
	FailureHAppPreimageInvalid    = attest.TagHAppPreimageInvalid
	FailurePosturePreimageInvalid = attest.TagPosturePreimageInvalid

	// FailurePostureUpstreamUnverifiable: a bound named_upstream posture
	// names an upstream inject.NamedUpstreamAdmissible refuses. Either the
	// URL is not https with a plain host, or it is neither xAI with
	// zero_retention set nor accompanied by an aci/1 upstream attestation.
	// SPEC §3e verifier step 7.
	FailurePostureUpstreamUnverifiable = attest.TagPostureUpstreamUnverifiable
)

// VerifierIDBuiltin stamps a verdict that BundleVerifier decided on its
// own — a stub bundle, or a mode with no platform verifier behind it.
// Mirrored from the proxy config's TEEVerifierBuiltin so the package
// boundary doesn't force a cross-import every time it's referenced.
//
// A verdict that reached a platform verifier carries THAT verifier's id
// instead (VerifierIDDstack), so this value surviving to the operator's
// zs.TEEStatus is itself informative: no platform chain was checked.
const VerifierIDBuiltin = "builtin"

// Node is what a verifier checks evidence against: the node it came from,
// as discovery knows it.
type Node struct {
	OperatorID uint64
	NodeID     uint64
	// EphemeralRecipientPubkey is the age recipient the payer will seal the
	// prompt to, already verified against the node's signed advertisement;
	// empty when no verified one is current. See BundleVerifier.Verify for
	// why the evidence must bind this key rather than the signing key.
	EphemeralRecipientPubkey string
}

// Verdict is the outcome of a single Verifier.Verify call. Pass is
// the routing-relevant bit; FailureTag is empty iff Pass is true and
// otherwise carries one of the Failure* constants. AttestedAt is the
// bundle's GeneratedAt — surfaced so the caller can stamp it on the
// operator's zs.TEEStatus regardless of the pass/fail outcome (the
// dashboard wants to show "evidence generated at X but failed
// verification" cases too).
type Verdict struct {
	Pass       bool
	FailureTag string
	VerifierID string
	AttestedAt time.Time

	// AttestedModelIDs are the model ids in the bundle's app_models, set
	// only on a passing dstack verdict, where VerifyAux matched that list
	// against the signed aux binding. The list is the node's advertised
	// catalog at mint time, including models it forwards to a hosted
	// upstream.
	//
	// MUST stay nil on any refusal: whichever step refused, the list is
	// unverified, and a caller cannot tell ids on a refused verdict from
	// verified ones.
	//
	// A non-nil empty slice is a verified claim that the node serves no
	// models. Nil means there is no verified list (a refusal, a stub
	// bundle, or a verifier that produces none).
	AttestedModelIDs []string
}

// Verifier verifies an evidence bundle against an advertisement.
// A typed interface (rather than a free function) so a future
// LocalNvtrustVerifier (or alternative-vendor implementation) lands
// behind the same shape as a config-switch, not a refactor.
//
// Implementations MUST always populate VerifierID on the returned
// Verdict and SHOULD populate AttestedAt from bundle.GeneratedAt
// regardless of whether Pass is true. Pass=false MUST come with a
// non-empty FailureTag drawn from the Failure* constants.
type Verifier interface {
	Verify(ctx context.Context, advertised inject.TEEAdvertisement, bundle inject.TEEEvidenceBundle, node Node) Verdict
}

// BundleVerifier checks everything about an evidence bundle that does
// not depend on which TEE produced it, then hands the platform-specific
// remainder to a platform verifier. It performs:
//
//  1. Always-on key-binding check — `report_data == sha256(NodePubkey
//     || be64(OperatorID))`, with the *advertised* NodePubkey (from
//     /v1/zs/details) used as ground truth so a malicious operator
//     cannot substitute pubkeys between the two endpoints.
//  2. Stub-mode short-circuit — bundle.Stub == true passes only when
//     AllowStub is true (dev). Production deployments leave AllowStub
//     false; stub bundles are then rejected with FailureStubNotAllowed.
//  3. Dispatch on bundle.Mode — dstack-tdx reaches DstackVerifier;
//     nvidia-cc-tdx / nvidia-cc-snp return FailureVerifierNotImpl until
//     VCEK chain + NRAS EAT verification land. The interface shape does
//     not change when they do; a new case does.
//
// It was called NRASVerifier, which named the one path that has never
// run: the working path is Intel TDX and contacts NVIDIA's attestation
// service exactly never. That the split is bundle-level vs
// platform-level, rather than vendor-level, is the thing the name
// should say — the checks above are the ones no platform is trusted to
// do for itself, which is why they run BEFORE any dispatch.
//
// Operators that don't advertise TEE never reach a verifier — the
// zs fetcher only calls Verify when the details probe surfaced a TEE
// advertisement.
type BundleVerifier struct {
	AllowStub bool

	// TrustedComposeHashes / TrustedOSImages are the measurement
	// allowlists handed to the dstack branch. An empty TrustedOSImages
	// verifies nothing there; an empty TrustedComposeHashes verifies
	// nothing only without ComposePolicy.EnforceComposeSkeleton — see
	// DstackVerifier.
	TrustedComposeHashes []string
	TrustedOSImages      []string

	// ComposePolicy is the content rule set for the published compose
	// document — see DstackVerifier.ComposePolicy, which explains why it
	// runs alongside TrustedComposeHashes rather than replacing it.
	ComposePolicy attest.ComposePolicy

	// VerifyChain overrides the Intel PCK verification on the dstack
	// branch. Nil uses the real one; tests inject a stub so the steps
	// AFTER the chain check are exercisable without reaching Intel.
	VerifyChain quoteChainVerifier

	// VerifyChainCarried overrides the node-carried-collateral last
	// resort. Carried alongside VerifyChain rather than left off,
	// because a struct that forwards one seam and not its twin makes
	// a stub at this layer silently partial.
	VerifyChainCarried carriedChainVerifier

	Log *slog.Logger
}

// Verify implements Verifier. See BundleVerifier for the layered
// check semantics.
func (v *BundleVerifier) Verify(ctx context.Context, advertised inject.TEEAdvertisement, bundle inject.TEEEvidenceBundle, op Node) Verdict {
	verdict := Verdict{
		VerifierID: VerifierIDBuiltin,
		AttestedAt: bundle.GeneratedAt,
	}

	// Cross-check the bundle's self-reported (Mode, OperatorID,
	// NodePubkey) against ground truth for this operator. The bundle
	// is served from operator-controlled infrastructure, so nothing it
	// says about itself is load-bearing; anything that disagrees with
	// op is a misadvertisement.
	//
	// KEY-BINDING TARGET: the node's current **ephemeral age recipient** —
	// the key this proxy will actually seal the prompt to. Deliberately not
	// the on-chain SigningAddr: attesting the identity key would prove only
	// that the enclave controls the operator identity, leaving the hop from
	// that key to the sealing key operator-attested (an Ed25519 advertisement
	// signature nothing proves was produced inside the CVM). An operator
	// holding a copy of the signing key outside the enclave could then point
	// traffic at an ephemeral whose private half lives on the plain host and
	// still pass every check.
	//
	// EphemeralRecipientPubkey is the right ground truth precisely because
	// zs's applyEphemeralAdvertisement has already vetted it this same refresh
	// pass — signature-verified under the on-chain Ed25519 key, bound to
	// (operator_id, node_id), issued-at checked and capped at
	// MaxEphemeralLifetime — so the attested key is provably fresh and
	// short-lived, not merely self-consistent.
	//
	// Because that key rotates (node: server.EphemeralRotationPeriod), the
	// node re-mints evidence on rotation. Both are read in one refresh pass
	// (zs's applyEphemeralAdvertisement then probeAttestation), so a matching pair
	// is the steady state; the brief window where the node has rotated but
	// not yet re-minted fails closed here and clears on the next probe.
	if op.EphemeralRecipientPubkey == "" {
		// No verified ephemeral this cycle (never advertised, expired, or
		// the signature failed). There is nothing to bind to, and the
		// operator is unsealable anyway — fail closed rather than fall
		// through to a binding hash over an empty key.
		verdict.FailureTag = FailureKeyBindingMismatch
		return verdict
	}
	if bundle.Mode != advertised.Mode {
		verdict.FailureTag = FailureAdvertisementMismatch
		return verdict
	}
	if bundle.OperatorID != op.OperatorID {
		verdict.FailureTag = FailureAdvertisementMismatch
		return verdict
	}
	nodePubkey := op.EphemeralRecipientPubkey
	if bundle.NodePubkey != nodePubkey {
		// The bundle attests a different key than the one this proxy would
		// seal to — a node mid-rotation that hasn't re-minted, or an
		// operator attesting a key other than its live sealing recipient.
		// Either way the evidence says nothing about where the plaintext
		// lands, so it cannot be accepted.
		verdict.FailureTag = FailureAdvertisementMismatch
		return verdict
	}

	// Freshness: the bundle advertises its own refresh cadence and we
	// reject anything outside 2× that, but never wider than
	// EvidenceMaxAgeCeiling. The node should also have returned 503
	// stale_attestation before we got here, but a hostile node can lie.
	//
	// THE CADENCE IS THE NODE'S OWN NUMBER, so a rule expressed purely
	// in terms of it is a rule the node sets for itself — see
	// EvidenceMaxAgeCeiling's godoc for what the ceiling does and does
	// not buy.
	//
	// THE WINDOW IS ABSOLUTE, and the future half is the one that is
	// easy to omit and useless without. This read `time.Since(...) >
	// maxAge`, which a timestamp in the FUTURE defeats outright:
	// time.Since of a future instant is negative and never exceeds the
	// bound, so a node that mints once and stamps 2126 satisfies the
	// rule forever while advertising a compliant cadence. GeneratedAt
	// is operator-authored, and a well-formed future date is a strictly
	// better bypass than a malformed one because it survives any later
	// timestamp-validity hardening. Found by mutation testing the
	// client mirror, which had inherited the same shape.
	//
	// What bounds the damage beyond this, and is why the check is
	// defence in depth rather than the load-bearing one: the bundle
	// must also attest the operator's CURRENT ephemeral recipient,
	// which rotates on server.EphemeralRotationPeriod, so evidence
	// cannot outlive that key however it is dated. Don't let that decay
	// the check — the rotation period is a node-side setting and this
	// is the only place the payer bounds evidence age themselves.
	//
	// RefreshSeconds is a plain int decoded from operator-controlled JSON,
	// so it is clamped to the ceiling before it is doubled: any cadence that
	// long already earns the ceiling, and the nanosecond product can then
	// never wrap. Unclamped, ~4.6e9 wrapped negative and 2197108676271213
	// wrapped to a 1024ns window, refusing a node SPEC §3e step 2 gives the
	// ceiling. A cadence of zero or less is no cadence, and gets the
	// ceiling too.
	maxAge := EvidenceMaxAgeCeiling
	if refresh := min(bundle.RefreshSeconds, int(EvidenceMaxAgeCeiling/time.Second)); refresh > 0 {
		maxAge = min(maxAge, 2*time.Duration(refresh)*time.Second)
	}
	if skew := time.Since(bundle.GeneratedAt); skew > maxAge || skew < -maxAge {
		verdict.FailureTag = FailureStaleEvidence
		return verdict
	}

	// Key binding: report_data must equal sha256(NodePubkey ||
	// be64(operator_id)) over the verified ephemeral recipient. The
	// bundle.NodePubkey == nodePubkey check above means we could
	// equivalently hash bundle.NodePubkey here; hashing nodePubkey makes
	// the security property — "the binding is to the key the proxy will
	// actually seal to" — explicit at the call site.
	expected := computeReportData(nodePubkey, op.OperatorID)
	got, err := base64.StdEncoding.DecodeString(bundle.ReportData)
	if err != nil || subtle.ConstantTimeCompare(expected, got) != 1 {
		verdict.FailureTag = FailureKeyBindingMismatch
		return verdict
	}

	// Stub-mode short-circuit. CPUReport / GPUEAT are empty by
	// construction (see proto/go/inject/tee.go) so chain
	// verification is structurally impossible — gate purely on the
	// proxy's allow-stub knob.
	if bundle.Stub {
		if v.AllowStub {
			verdict.Pass = true
			// AttestedModelIDs stays nil: a stub bundle has no quote, so
			// VerifyAux never ran and bundle.AppModels is unverified.
			return verdict
		}
		verdict.FailureTag = FailureStubNotAllowed
		return verdict
	}

	// Real evidence path.
	switch bundle.Mode {
	case inject.TEEModeDstackTDX:
		// The dstack branch derives the platform from the quote bytes
		// rather than from the Mode string it just switched on — the
		// switch picks which VERIFIER runs, the bytes decide which
		// vendor chain it checks against. Conflating the two would let
		// an operator choose their own judge.
		dv := &DstackVerifier{
			TrustedComposeHashes: v.TrustedComposeHashes,
			TrustedOSImages:      v.TrustedOSImages,
			ComposePolicy:        v.ComposePolicy,
			VerifyChain:          v.VerifyChain,
			VerifyChainCarried:   v.VerifyChainCarried,
			Log:                  v.Log,
		}
		verdict.VerifierID = VerifierIDDstack
		if tag := dv.Verify(ctx, bundle, op); tag != "" {
			verdict.FailureTag = tag
			return verdict
		}
		verdict.Pass = true
		// dv.Verify returned "", so VerifyAux matched this list. Built
		// non-nil even when empty; see Verdict.AttestedModelIDs.
		ids := make([]string, 0, len(bundle.AppModels))
		for _, m := range bundle.AppModels {
			ids = append(ids, m.ModelID)
		}
		verdict.AttestedModelIDs = ids
		return verdict
	case inject.TEEModeNvidiaCCTDX, inject.TEEModeNvidiaCCSEVSNP:
		// A clearly-named placeholder so operators advertising
		// nvidia-cc-* don't silently look attested in a build that
		// hasn't yet wired NRAS. A follow-up replaces this with
		// PCK / VCEK chain verification + NRAS POST + EAT JWT.
		verdict.FailureTag = FailureVerifierNotImpl
		return verdict
	default:
		// Unrecognized mode that nonetheless passed the
		// advertisement-mismatch check above (mode strings agreed
		// between advertisement and bundle, but neither matches a
		// known wire constant). Treat as not-attested.
		verdict.FailureTag = FailureVerifierNotImpl
		return verdict
	}
}

// computeReportData is attest.ReportData. It used to be a hand-kept
// copy, "defined here rather than imported so the proxy doesn't take a
// build-time dep on node internals" — a real constraint answered the
// wrong way. Both sides already depend on the protocol module, which is
// where arithmetic two implementations must agree on belongs; the copy
// bought independence from `node/internal` at the price of a
// disagreement that would surface as `key_binding_mismatch` on evidence
// that is entirely valid.
func computeReportData(nodePubkey string, operatorID uint64) []byte {
	return attest.ReportData(nodePubkey, operatorID)
}
