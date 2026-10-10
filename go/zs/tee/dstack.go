/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	tdxverify "github.com/google/go-tdx-guest/verify"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
)

// FailureMeasurementMismatch is the failure tag for evidence whose
// measurement is not one this proxy trusts: the event log did not
// replay to the quote's RTMR3, or the compose / OS image it recovered
// is absent from the configured allowlist.
//
// Distinct from FailureVendorChainInvalid on purpose. That one says
// "this is not a real quote"; this one says "this is a real quote from
// software I do not recognise", which is a different operator problem
// with a different fix.
const FailureMeasurementMismatch = "measurement_mismatch"

// FailureCollateralUnreachable means verification could not COMPLETE
// because Intel's PCS was unreachable — it says nothing about this
// operator's evidence.
//
// It is a separate tag from FailureVendorChainInvalid because the two
// are opposite claims and both are actionable, in different
// directions. Folding them together would, during one Intel outage,
// stamp "this node's evidence is invalid" on every dstack operator in
// the fleet at once — indistinguishable in a dashboard from an actual
// attack, and pointing whoever reads it at the wrong system.
//
// The routing outcome is identical (fail closed, no Require-TEE
// traffic). Only the diagnosis differs, which is the entire value.
//
// The nvidia-cc-* twin is FailureNRASUnreachable.
const FailureCollateralUnreachable = "collateral_unreachable"

// VerifierIDDstack identifies verdicts produced by DstackVerifier.
const VerifierIDDstack = "dstack-tdx"

// quoteChainVerifier verifies a raw TDX quote against Intel's PCK
// chain. A field on DstackVerifier rather than a direct call so tests
// can exercise the replay, allowlist, binding and posture logic
// offline — the real implementation reaches Intel's PCS for
// collateral, which a unit test must not depend on.
//
// Tests that stub this MUST still be read as testing only the steps
// AFTER it. The chain check is the step that makes every other one
// mean something, and it has its own network-gated test.
type quoteChainVerifier func(ctx context.Context, quote []byte) error

// carriedChainVerifier is quoteChainVerifier against collateral the NODE
// supplied rather than any we hold. Separate from quoteChainVerifier
// because the extra parameter is the whole difference: a caller must
// pass the evidence bundle's own set, so no wiring can reach this path
// without having decided to accept node-supplied criteria.
type carriedChainVerifier func(ctx context.Context, quote []byte, c *inject.TEECollateral) error

// DstackVerifier verifies dstack-managed Intel TDX evidence
// (tee.mode=dstack-tdx). CPU-only: no GPU EAT, no NRAS call.
//
// It implements SPEC §3e steps 5–7 for this platform, in SPEC's order, and
// the ORDER is load-bearing. Items 1–4 are SPEC step 5:
//
//  1. Derive the platform from the QUOTE BYTES, never from the
//     bundle's self-reported Mode.
//  2. Verify the quote against Intel's PCK chain.
//  3. Replay the event log into RTMR3 and compare against the quote.
//  4. Check the recovered compose and OS-image hashes against the
//     allowlist, then — for a node that publishes the preimage —
//     validate the compose document's CONTENT. Content runs last so a
//     dev OS image is reported as a dev OS image; the verdict is the
//     same either way.
//
// Then SPEC step 6 checks report_data from the quote: the key half, then the
// aux binding over node id, catalog and nonce. SPEC step 7 cross-checks the
// posture block against the allowlisted measurement.
//
// Steps 0-4 of SPEC §3e (advertisement, staleness, the base64
// report_data comparison, stub gating) already ran in BundleVerifier
// before this is reached; this type is deliberately not a standalone
// entry point.
type DstackVerifier struct {
	// TrustedOSImages is the known-good guest-image allowlist. EMPTY MEANS
	// NOTHING VERIFIES — an empty list read as "accept anything" would make
	// an unconfigured proxy accept a quote from any CVM running any image,
	// while looking exactly like the feature working.
	TrustedOSImages []string

	// TrustedComposeHashes pins whole-document digests. It NARROWS; it does
	// not substitute, and empty means "no constraint" ONLY because the
	// release match below is what gates now.
	//
	// This field used to be the gate, back when the release lists did not
	// exist and there was nothing else to identify a workload — so empty
	// meant nothing verified, the same fail-closed reading TrustedOSImages
	// still has. Now a payer who sets it is asking for a hand-vetted subset
	// of an already-matched fleet, and one who leaves it empty gets the
	// release match alone, which is the stronger claim of the two: a
	// compose_hash says WHICH deployment, a skeleton says WHAT it runs.
	//
	// The empty-means-no-constraint reading is exactly the fail-open shape
	// this package argues against elsewhere, so it is legal here only while
	// ComposePolicy.EnforceComposeSkeleton is true — see the guard in
	// Verify, which restores the fail-closed reading whenever the release
	// match is off.
	TrustedComposeHashes []string

	// ComposePolicy is the content rule set applied to the compose
	// document the node publishes, once its digest has been checked
	// against the replay.
	//
	// WITH EnforceComposeSkeleton SET, THIS IS THE GATE. It answers the
	// question a hash allowlist never could — that the document is a
	// published zs-node release rather than merely some document a payer
	// once blessed — which is why an absent preimage is now a refusal
	// rather than a skip, and why TrustedComposeHashes above may be empty.
	//
	// The zero value runs no content rules and enforces no release match.
	// That is a widening, and it is safe only in the configuration where
	// TrustedComposeHashes gates instead; Verify enforces that pairing
	// rather than trusting a caller to construct it correctly.
	ComposePolicy attest.ComposePolicy

	// VerifyChain defaults to the real Intel PCK verification when nil.
	VerifyChain quoteChainVerifier

	// VerifyChainCarried defaults to VerifyTDXQuoteChainCarried when
	// nil — the SPEC §3e last resort, reached only when Intel's PCS and
	// our own cache have both come up empty.
	VerifyChainCarried carriedChainVerifier

	Log *slog.Logger
}

// verifyQuoteChain runs SPEC §3e's collateral precedence — Intel's PCS,
// then our own stale cache, then the node's carried copy — and returns
// the FIRST rung's error when every rung fails, since that is the one
// that describes our link to Intel rather than this operator's evidence.
//
// THE ORDERING IS THE SECURITY PROPERTY, and only its first two rungs
// live below: VerifyChain already tries PCS and falls back to our cache
// internally (cachingGetter), so reaching here with
// ErrCollateralUnavailable means BOTH came up empty.
//
// WHY ErrStaleCollateralRejected DOES NOT TRIGGER THE FALLBACK, which is
// the subtle half. That sentinel means our own cached document was
// consulted and REFUSED the quote. Falling through to the node's set
// would then discard a signed Intel statement we hold, of a vintage the
// operator did not choose, in favour of one it did — which is exactly
// the rollback the precedence rule exists to prevent, and it is strictly
// worse than the ErrCollateralUnavailable case where we hold no
// statement at all. §3e's "our stale cache -> the node's copy" step is
// about our cache having no ANSWER (no entry, or one past
// collateralStaleMax); both of those surface as ErrCollateralUnavailable
// and are already covered.
func (v *DstackVerifier) verifyQuoteChain(ctx context.Context, quote []byte, carried *inject.TEECollateral, opID uint64) error {
	verifyChain := v.VerifyChain
	if verifyChain == nil {
		verifyChain = VerifyTDXQuoteChain
	}
	err := verifyChain(ctx, quote)
	if err == nil || !errors.Is(err, ErrCollateralUnavailable) {
		return err
	}

	verifyCarried := v.VerifyChainCarried
	if verifyCarried == nil {
		verifyCarried = VerifyTDXQuoteChainCarried
	}
	if cerr := verifyCarried(ctx, quote, carried); cerr != nil {
		// Deliberately NOT returned: it describes the node's set, and
		// the caller is deciding a failure tag for a verification that
		// failed first because we could not reach Intel. Reporting the
		// last resort's complaint would turn one outage into a fleet of
		// operators whose collateral looks defective.
		v.log().Debug("attestation: node-carried collateral did not rescue an unreachable-PCS verification",
			slog.Uint64("operator_id", opID), slog.Any("err", cerr))
		return err
	}
	// WARN, not Info: this verdict rests on collateral the attested
	// party supplied, bounded only by attest.EmbeddedCollateralMaxAge.
	// It is a real pass and routing treats it as one, but an operator
	// reading their logs should see how often their proxy is reaching
	// for it — a permanent state of it means egress to Intel is broken.
	v.log().Warn("attestation: verified a TDX quote against the NODE'S OWN collateral because Intel PCS was unreachable",
		slog.Uint64("operator_id", opID), slog.Any("pcs_err", err))
	return nil
}

// Verify runs the dstack branch and returns a failure tag, or "" on
// success. op supplies the independently-verified ephemeral recipient
// the binding must be to.
func (v *DstackVerifier) Verify(ctx context.Context, bundle inject.TEEEvidenceBundle, op Node) string {
	quote, err := base64.StdEncoding.DecodeString(bundle.CPUReport)
	if err != nil || len(quote) == 0 {
		return FailureVendorChainInvalid
	}

	// 1. PLATFORM FROM THE BYTES. Reading bundle.Mode here would make
	// the mode string a vendor-chain selector the operator controls:
	// they would pick which chain their evidence is judged against, and
	// could route a quote to whichever verifier is weakest.
	teeType, ok := attest.QuoteTEEType(quote)
	if !ok || teeType != attest.TEETypeTDX {
		v.log().Debug("attestation: report is not a TDX v4 quote",
			slog.Uint64("operator_id", op.OperatorID), slog.Uint64("tee_type", uint64(teeType)))
		return FailureVendorChainInvalid
	}

	// 2. The vendor chain. Everything below is a statement about
	// software; this is the step that makes it a statement about
	// software running on real Intel hardware.
	if err := v.verifyQuoteChain(ctx, quote, bundle.Collateral, op.OperatorID); err != nil {
		// ErrStaleCollateralRejected joins the outage tag HERE and only
		// here. Routing cannot tell whether our aging document or the
		// node's evidence caused the refusal, both tags fail closed, and
		// the wrong guess in the other direction marks the whole
		// confidential fleet as forging evidence. `tee inspect` splits
		// them the other way — see ErrStaleCollateralRejected.
		if errors.Is(err, ErrCollateralUnavailable) || errors.Is(err, ErrStaleCollateralRejected) {
			// OUR dependency failed, not this operator's evidence.
			// Logged at WARN with a different message so an outage
			// reads as an outage rather than as a fleet of bad nodes.
			//
			// THE TAG IS SHARED, THE MESSAGE IS NOT. SPEC §3e rule 2
			// allows exactly this split ("a verifier's diagnostic
			// surfaces MAY distinguish the two; its routing decision need
			// not"), and a log line is a diagnostic surface: saying
			// "could not reach Intel PCS" about a quote our cached
			// collateral CONSULTED and refused is false, and log messages
			// are what get grepped when a fleet goes quiet. The cause
			// would otherwise survive only inside the err attribute.
			msg := "attestation: could not reach Intel PCS to verify a TDX quote"
			if errors.Is(err, ErrStaleCollateralRejected) {
				msg = "attestation: TDX quote refused by our own cached Intel collateral " +
					"during a PCS outage — cause not attributable from here"
			}
			v.log().Warn(msg, slog.Uint64("operator_id", op.OperatorID), slog.Any("err", err))
			return FailureCollateralUnreachable
		}
		v.log().Warn("attestation: TDX quote failed vendor-chain verification",
			slog.Uint64("operator_id", op.OperatorID), slog.Any("err", err))
		return FailureVendorChainInvalid
	}

	// 3 + 4. Replay, then read the measurements off the REPLAY.
	// attest.VerifyEventLog fails closed on a zero-event replay, an
	// all-zero RTMR3, and an undecodable payload — each of which
	// otherwise compares equal for the wrong reason.
	measurements, err := attest.VerifyEventLog(bundle.EventLog, quote)
	if err != nil {
		v.log().Warn("attestation: event log does not replay to the quote's RTMR3",
			slog.Uint64("operator_id", op.OperatorID), slog.Any("err", err))
		return FailureMeasurementMismatch
	}
	// THE WHOLE-DOCUMENT PIN, and the condition is the interesting part.
	//
	// An empty list is skipped only when the release match below is on:
	// there, this field narrows an already-identified fleet and having no
	// opinion is a coherent thing to want. With the release match OFF it is
	// the only thing that identifies a workload at all, so empty keeps its
	// original fail-closed meaning and refuses everything. Reading empty as
	// "no constraint" in that configuration is the exact shape this package
	// argues against everywhere else — a check that vanishes while looking
	// like the feature working.
	if len(v.TrustedComposeHashes) > 0 || !v.ComposePolicy.EnforceComposeSkeleton {
		if !containsHexFold(v.TrustedComposeHashes, measurements[attest.EventComposeHash]) {
			v.log().Warn("attestation: compose hash is not in the trusted set",
				slog.Uint64("operator_id", op.OperatorID),
				slog.String("compose_hash", measurements[attest.EventComposeHash]))
			return FailureMeasurementMismatch
		}
	}
	// The OS image is required, not optional hardening: without it a
	// node can present a valid quote taken on a dstack DEV image, where
	// every other check passes identically and the platform's hardening
	// guarantees do not hold.
	if !containsHexFold(v.TrustedOSImages, measurements[attest.EventOSImageHash]) {
		v.log().Warn("attestation: OS image hash is not in the trusted set",
			slog.Uint64("operator_id", op.OperatorID),
			slog.String("os_image_hash", measurements[attest.EventOSImageHash]))
		return FailureMeasurementMismatch
	}

	// 4c. THE COMPOSE DOCUMENT ITSELF. The hash above says WHICH
	// deployment; this says what that deployment actually is.
	//
	// VerifyAppCompose hashes the published preimage against the same
	// replayed measurement before reading a single field, so a node
	// substituting a friendlier document moves the digest and is caught
	// here rather than believed.
	//
	// LAST, and below the OS-image check, to keep the DIAGNOSIS right
	// rather than the verdict: both refusals are FailureMeasurementMismatch,
	// so ordering cannot change who routes, but a node on a dev image whose
	// compose also violates policy should be told about the dev image — it
	// is the more fundamental fault and the one config.example.yaml is
	// written around. The TypeScript twin (sdk/src/tee/dstack.ts) keeps
	// the same order, so the two report the same fault on the same node.
	//
	// AN ABSENT DOCUMENT IS A REFUSAL under the release match, and a skip
	// without it. That split is the whole reason this branch is not simply
	// `if bundle.AppCompose != ""` any more.
	//
	// The skip was never safe on its own — it was safe because a hand-blessed
	// TrustedComposeHashes entry stood behind it. Its cost was sharper than
	// the substitution attack the content rules catch: an operator whose hash
	// was already blessed evaded every rule below by simply OMITTING the
	// field, which is strictly easier than substituting a document. With the
	// release match as the gate there is nothing behind the skip, so keeping
	// it would make every content rule opt-out — a node declines to publish
	// and is verified anyway.
	//
	// It stays a skip when the release match is off, because that is the
	// configuration where a pre-9.6 guest agent must not read as compromised
	// for publishing no preimage it was never able to publish.
	if bundle.AppCompose == "" {
		if v.ComposePolicy.EnforceComposeSkeleton {
			v.log().Warn("attestation: node published no app_compose, so the release "+
				"match has nothing to check — refusing rather than skipping",
				slog.Uint64("operator_id", op.OperatorID))
			return FailureMeasurementMismatch
		}
	} else {
		if _, err := attest.VerifyAppCompose(bundle.AppCompose, measurements, v.ComposePolicy); err != nil {
			// Split by cause, because the two say different things to
			// an operator and one of the messages would be a lie.
			// A policy violation names something actionable — an
			// unexpected env name, a boot hook, a compose that is not
			// a published release — and without it an operator sees
			// `measurement_mismatch` with no way to learn which rule.
			// A provenance failure means the logged document is not
			// the measured compose at all, so calling it "the measured
			// compose" would misname the subject.
			var pe *attest.ComposePolicyError
			if errors.As(err, &pe) {
				v.log().Warn("attestation: the measured compose violates policy",
					slog.Uint64("operator_id", op.OperatorID), slog.Any("err", err))
			} else {
				v.log().Warn("attestation: the published compose is not the one this quote measured",
					slog.Uint64("operator_id", op.OperatorID), slog.Any("err", err))
			}
			return FailureMeasurementMismatch
		}
	}

	// SPEC step 6: both halves of the quote's report_data. The caller
	// compared bundle.ReportData, a self-report; this reads
	// the bytes Intel signed. The signature covers all 64, so an unchecked
	// half would let a node get 32 bytes of its choice signed by real
	// hardware.
	halves, err := attest.SplitReportData(quote)
	if errors.Is(err, attest.ErrReportDataAbsent) {
		v.log().Warn("attestation: quote is too short to hold report_data",
			slog.Uint64("operator_id", op.OperatorID))
		return FailureKeyBindingMismatch
	}

	// 6.1. The lower half: the key we would seal to. Checked before the
	// upper half's zero test (SplitReportData returns KeyBinding with
	// ErrAuxBindingAbsent), so a quote over the wrong key is reported as
	// that, not as an out-of-date node.
	expected := computeReportData(op.EphemeralRecipientPubkey, op.OperatorID)
	if subtle.ConstantTimeCompare(halves.KeyBinding[:], expected) != 1 {
		v.log().Warn("attestation: the quote binds a different key than the one we would seal to",
			slog.Uint64("operator_id", op.OperatorID))
		return FailureKeyBindingMismatch
	}
	if errors.Is(err, attest.ErrAuxBindingAbsent) {
		v.log().Warn("attestation: report_data upper half is all zero — node predates proto 9.9",
			slog.Uint64("operator_id", op.OperatorID), slog.Uint64("node_id", op.NodeID))
		return FailureAuxBindingAbsent
	}

	// 6.2–6.5. The upper half. op.NodeID is chain-resolved; the bundle does not
	// carry one. No challenge is sent, so a bundle minted for another
	// caller's ?nonce= verifies here too. It proves no freshness to us;
	// stale_evidence and ephemeral rotation bound its age.
	if err := halves.VerifyAux(op.NodeID, bundle.AppModels, bundle.Posture, bundle.Nonce, nil); err != nil {
		tag := attest.AuxFailureTag(err)
		v.log().Warn("attestation: aux binding refused",
			slog.Uint64("operator_id", op.OperatorID), slog.Uint64("node_id", op.NodeID),
			slog.String("tag", tag), slog.Int("published_models", len(bundle.AppModels)),
			slog.Any("err", err))
		return tag
	}

	// SPEC step 7: posture. Since 9.10 VerifyAux above has bound
	// bundle.Posture into report_data, so this judges what the measured
	// binary derived rather than a self-report — and it must judge that same
	// value, never a copy read from anywhere else.
	if tag := v.checkPosture(bundle.Posture, inject.UpstreamAttested(bundle.UpstreamAttestation), op); tag != "" {
		return tag
	}
	return ""
}

// checkPosture judges the bound posture block: first for internal coherence
// (an incoherent block is a node misreporting itself), then, for a
// named_upstream posture, whether the upstream it names is one a payer can
// hold to its claim (inject.NamedUpstreamAdmissible — shared with the TS SDK so
// the two verifiers cannot disagree about which upstreams are acceptable).
//
// An ABSENT posture is accepted: the field is optional on the wire and
// a node that publishes none is making no claim, which is the honest
// outcome for a verifier to pass through. VerifyAux has already committed
// the absence, so a relay cannot have stripped one.
func (v *DstackVerifier) checkPosture(p *inject.TEEPosture, upstreamAttested bool, op Node) string {
	if p == nil {
		return ""
	}
	switch p.PlaintextTerminates {
	case inject.PlaintextInEnclave:
		// Naming (or attesting) an upstream while claiming the prompt never
		// leaves is self-contradictory. Refuse rather than pick a reading.
		if p.UpstreamBaseURL != "" || p.UpstreamAttested {
			v.log().Warn("attestation: in_enclave posture names an upstream",
				slog.Uint64("operator_id", op.OperatorID))
			return FailureAdvertisementMismatch
		}
	case inject.PlaintextNamedUpstream:
		// "Readable by exactly one party" is a claim about a party the
		// payer can identify. A posture that declines to name one is
		// not making the claim.
		if p.UpstreamBaseURL == "" {
			v.log().Warn("attestation: named_upstream posture names no upstream",
				slog.Uint64("operator_id", op.OperatorID))
			return FailureAdvertisementMismatch
		}
		if !inject.NamedUpstreamAdmissible(p, upstreamAttested) {
			v.log().Warn("attestation: named_upstream posture names an upstream the payer cannot hold to its claim",
				slog.Uint64("operator_id", op.OperatorID),
				slog.String("upstream_base_url", p.UpstreamBaseURL),
				slog.Bool("zero_retention", p.ZeroRetention),
				slog.Bool("upstream_attested", upstreamAttested))
			return FailurePostureUpstreamUnverifiable
		}
	default:
		// Unrecognized values are unknown, and unknown must never be
		// read as the stronger of the two.
		v.log().Warn("attestation: unrecognized posture",
			slog.Uint64("operator_id", op.OperatorID),
			slog.String("plaintext_terminates", p.PlaintextTerminates))
		return FailureAdvertisementMismatch
	}
	return ""
}

func (v *DstackVerifier) log() *slog.Logger {
	if v.Log != nil {
		return v.Log
	}
	return slog.Default()
}

// containsHexFold reports whether want appears in list, comparing
// lowercased hex with any 0x prefix stripped. An empty want is never
// a member — an absent measurement must not match an allowlist entry
// that is also empty.
//
// EMPTINESS IS TESTED AFTER NORMALIZING, on both sides. Testing want
// before it meant "0x" (and "  ") normalized to "" and then matched a
// blank list entry, so a config carrying a stray `- ""` — which YAML
// makes easy and which no validation rejects — turned a measurement
// the node barely reported into a member. Skipping blank entries is the
// same guard from the other end: a list is a set of things to trust,
// and an entry naming nothing cannot be one of them.
func containsHexFold(list []string, want string) bool {
	want = normalizeHex(want)
	if want == "" {
		return false
	}
	for _, v := range list {
		if n := normalizeHex(v); n != "" && n == want {
			return true
		}
	}
	return false
}

// MeasurementTrusted exports containsHexFold for `zs-proxy tee inspect`,
// which annotates a replayed measurement with whether the configured
// allowlist holds it.
//
// A WRAPPER RATHER THAN A SECOND COPY. The reporter and the gate must answer
// this identically or the diagnostic would tell an operator their OS image is
// trusted while the verifier drops them — the two disagreeing about the one
// thing the tool exists to explain, with nothing failing.
func MeasurementTrusted(list []string, want string) bool { return containsHexFold(list, want) }

func normalizeHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "0x")
}

// ---------------------------------------------------------------------------
// Intel PCK chain verification
// ---------------------------------------------------------------------------

// CollateralTimeout bounds one verification's Intel PCS traffic.
//
// Sized against the REFRESH CYCLE, not against PCS: the whole cycle —
// chain read plus every operator's probes — runs under
// zs.DefaultRefreshTimeout (30s), so a ceiling anywhere near that
// lets one unreachable third party cost the proxy a complete refresh.
// A warm cache makes this moot (the artifacts move on Intel's
// publication cadence, days to weeks); it bounds the cold path and the
// hour-boundary refetch. Measured cold against real PCS: ~1.1s.
const CollateralTimeout = 8 * time.Second

// collateralTTL is how long a fetched Intel PCS artifact is reused.
// The collateral (TCB info, QE identity, CRLs) moves on Intel's
// publication cadence — days to weeks — while the probe loop runs
// every refresh interval against every TEE operator. Without a cache
// that is a request to Intel per operator per cycle, which is both
// rude and a hard dependency on PCS being up for routing to work.
//
// It is the REFRESH trigger, not the refusal bound — see
// collateralStaleMax.
const collateralTTL = time.Hour

// collateralStaleMax is how far past collateralTTL a cached artifact may
// be served when Intel's PCS cannot be reached at all.
//
// WITHOUT THIS, A PCS OUTAGE LONGER THAN AN HOUR TAKES EVERY TEE
// OPERATOR OUT OF ROUTING. That is not a diagnosable event for the
// proxy's actual callers — long-lived agent sessions, where nobody is
// reading the log — so an outage presents as the session breaking on
// whoever is mid-task.
//
// Serving a stale document is the SAFEST fallback available, and the
// reason is who chose the vintage. Node-carried collateral is a last
// resort because Intel's signature proves contents but not which
// validly-signed vintage the party under judgement handed over; an entry
// here was fetched by US, from Intel, before the outage, so the operator
// cannot steer it.
//
// HOW FAR THAT ARGUMENT REACHES, precisely: it is a claim about the
// in-memory cache, where the entry and the fetch that produced it are the
// same process's. Once collateral_store.go persists the map, provenance
// rests on the state file's ownership and mode, and nothing
// re-establishes it at load — a rewritten file is believed. That is a
// deliberate trade (the alternative is the restart hole the store exists
// to close) and the exposure is bounded by the same two windows below,
// but it is not the same statement as "we fetched this".
//
// It also cannot resurrect an EXPIRED document: go-tdx-guest validates
// each artifact's own nextUpdate during RawTdxQuote, so Intel's window
// (~30 days for TCB info) bounds this regardless. What the constant
// actually bounds is the narrower case of a document still inside its
// Intel window that has since been superseded — a platform revoked
// during the outage. Note the corollary, which is what
// verifyGetter.unreachable is for: a served entry inside this bound can
// still be past its own nextUpdate, so a stale serve can turn into a
// verification failure, and that failure is ours rather than the
// operator's.
const collateralStaleMax = 7 * 24 * time.Hour

// VerifyTDXQuoteChain verifies a raw TDX v4 quote against Intel's PCK
// certificate chain, with collateral and revocation checks fetched
// from Intel's PCS.
//
// CheckRevocations and GetCollateral are both ON. Without collateral,
// verification degrades to "the embedded PCK chain signs this quote
// and roots at Intel" — which a revoked platform, or one at a TCB
// level Intel has since withdrawn, satisfies perfectly.
func VerifyTDXQuoteChain(ctx context.Context, quote []byte) error {
	_, err := VerifyTDXQuoteChainStale(ctx, quote)
	return err
}

// VerifyTDXQuoteChainStale is VerifyTDXQuoteChain, additionally
// reporting whether any artifact was served from cache past its refresh
// window because PCS could not be reached (see collateralStaleMax).
//
// FOR DIAGNOSTICS, NOT FOR ROUTING. A stale pass is a pass — that is the
// entire point of the fallback, and gating routing on it would restore
// the outage it exists to survive. But `zs-proxy tee inspect` reports
// "verified against Intel's PCK chain, with revocation and TCB
// collateral" to an operator, and saying that about week-old cached
// documents is the quiet inaccuracy that tool exists to avoid.
func VerifyTDXQuoteChainStale(ctx context.Context, quote []byte) (bool, error) {
	return verifyTDXQuoteChainWith(ctx, quote, sharedCollateralCache())
}

// verifyTDXQuoteChainWith is VerifyTDXQuoteChain against a supplied
// collateral source, so tests can drive the failure and stall paths —
// the ones that decide whether an Intel outage reads as an outage or as
// a fleet of forged quotes — without depending on Intel being down.
func verifyTDXQuoteChainWith(ctx context.Context, quote []byte, cache contextGetter) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, CollateralTimeout)
	defer cancel()

	getter := &verifyGetter{inner: cache, ctx: ctx}

	opts := tdxverify.DefaultOptions()
	opts.TrustedRoots = attest.IntelSGXRootCAs()
	opts.GetCollateral = true
	opts.CheckRevocations = true
	opts.Getter = getter

	if err := tdxverify.RawTdxQuote(quote, opts); err != nil {
		// WHY WE ASK THE GETTER RATHER THAN READING THE ERROR: the two
		// failures mean opposite things about the operator, and the
		// library flattens them into one string. "Intel is
		// unreachable" is OUR problem and says nothing about this
		// node; "the chain does not verify" is a claim that its
		// evidence is forged. Reporting the first as the second would,
		// during one PCS outage, mark every dstack operator in the
		// fleet as presenting invalid evidence — indistinguishable in
		// a dashboard from an actual attack.
		//
		// The getter is per-call, so this cannot race with another
		// verification, and it is exact rather than a string match on
		// a message the library is free to reword.
		//
		// ONE ASSUMPTION HOLDS THIS UP, and it is a property of Intel's
		// certificate rather than of our code: that a recorded fetch
		// error means the verification could not complete. True because
		// obtainCollateral aborts at the first failed Get — for
		// getTcbInfo, getQeIdentity and getPckCrl. getRootCrl is the
		// exception: it LOOPS over the QE identity issuer root's
		// CRLDistributionPoints and succeeds if any one answers
		// (verify.go:443-464). With two CDPs, a first-URL failure would
		// latch fetchErr while the verification ran to completion on
		// fresh collateral and produced a genuine refusal — reported here
		// as an outage, and then handed to the node's own collateral,
		// which SPEC §3e rule 1 forbids.
		//
		// Unreachable today: Intel's SGX Root CA carries exactly one CDP.
		// Written down because the fallback made this load-bearing in a
		// way it was not before. The thing that would change it is an
		// Intel reissue: our trusted copy (attest/intel_sgx_root_ca.pem)
		// is fingerprint-pinned, so a reissue fails that test, but nothing
		// checks the CDP count of the issuer root the collateral carries.
		//
		// THIS ARM WINS WHEN BOTH SLOTS ARE SET, and the precedence is a
		// decision rather than an accident of statement order. Both can be
		// set in one verification — the ordinary shape of a partly-warm
		// cache during an outage, where TCB info is served stale and QE
		// identity has no entry and hard-fails. But obtainCollateral
		// ABORTS at the first failed Get, so a hard error means gathering
		// never finished and NO verdict was reached: "we could not check"
		// is the true statement, and the stale serve that preceded it is
		// incidental. staleCause only means "a verdict was reached, partly
		// on our aging document" when gathering COMPLETED, which is
		// exactly the case where err() is nil. Swapping these two denies
		// the rung-3 fallback on a verification that never ran.
		if fetchErr := getter.err(); fetchErr != nil {
			return false, fmt.Errorf("%w: %v", ErrCollateralUnavailable, fetchErr)
		}
		// A REJECTION REACHED ON OUR OWN STALE COLLATERAL IS ITS OWN
		// OUTCOME, and it is neither of the two above.
		//
		// It is not ErrCollateralUnavailable: collateral WAS obtained
		// and it WAS consulted, so "we could not check" is false, and a
		// consumer that reads that tag as "no verdict was reached" would
		// carry on as if nothing had been refused.
		//
		// It is not a plain chain failure either: collateralStaleMax
		// measures from OUR fetch while a document's nextUpdate measures
		// from Intel's issue, so an artifact well inside the first can be
		// past the second and go-tdx-guest rejects it — which would
		// stamp "this node's evidence is forged" on every dstack operator
		// at once during one Intel outage.
		//
		// So callers get a third tag and decide for themselves. Routing
		// treats it as our outage (fail-safe: both tags refuse anyway,
		// and accusing the whole fleet is the worse error). `tee inspect`
		// treats it as a FAILURE, because the alternative is a security
		// diagnostic that prints a rejected quote's own allowlist values.
		if staleCause := getter.staleCause(); staleCause != nil {
			return false, fmt.Errorf("%w: %v (Intel PCS was unreachable: %v)",
				ErrStaleCollateralRejected, err, staleCause)
		}
		return false, fmt.Errorf("tdx quote verification: %w", err)
	}

	// A PASS THAT CONSULTED NO COLLATERAL IS NOT A PASS. Flipping
	// GetCollateral off degrades verification to "the embedded PCK
	// chain signs this and roots at Intel" — which a revoked platform,
	// or one at a TCB level Intel has withdrawn, satisfies perfectly. A
	// genuine quote verifies either way, so the only observable
	// difference is that no PCS request is made. Cache hits count, so a
	// warm cache does not trip this.
	//
	// IT COVERS ONLY THE GetCollateral HALF. With CheckRevocations off
	// the TCB fetch still happens, so the count stays positive and this
	// guard says nothing — an earlier version of this comment claimed
	// otherwise. That half is pinned by
	// TestVerifyTDXQuoteChain_RequestsRevocationLists, which asserts a
	// CRL endpoint was among the URLs requested, and which has to live
	// behind the network tag because the library asks for a CRL only
	// after the TCB fetch succeeds.
	return getter.staleUsed(), requireCollateralFetched(getter.count())
}

// requireCollateralFetched refuses a verification that consulted no
// Intel PCS collateral.
//
// A separate function ONLY so it can be tested. Reaching zero fetches
// through the real options is impossible — turning GetCollateral off is
// an edit, not an input — so an integration-shaped test cannot drive
// this branch, and one that tried went green on the library's own
// parsing error without ever reaching the guard.
func requireCollateralFetched(fetches int) error {
	if fetches == 0 {
		return errors.New("tdx quote verification completed without consulting any Intel PCS collateral — " +
			"revocation and TCB checks were skipped, so this verdict is not one to route on")
	}
	return nil
}

// ErrCollateralUnavailable means verification could not complete
// because Intel's PCS could not be reached — NOT that the quote failed
// to verify. The caller maps it to its own failure tag.
var ErrCollateralUnavailable = errors.New("attestation: Intel PCS collateral unavailable")

// ErrStaleCollateralRejected means the quote was REFUSED, by collateral
// this proxy served from cache because Intel's PCS was unreachable.
//
// A THIRD OUTCOME, not a flavour of either neighbour, and the reason is
// that its two possible causes cannot be told apart from here: the node's
// evidence really is bad, or our own document has been superseded since
// we fetched it (collateralStaleMax measures from our fetch, a document's
// nextUpdate from Intel's issue — an artifact inside the first can be
// past the second).
//
// Consumers must decide, and the two in this repo decide OPPOSITE ways on
// purpose:
//
//   - ROUTING treats it as our outage. Both tags refuse, so nothing is
//     admitted either way, and reporting it as forged evidence would
//     accuse every dstack operator in the fleet at once during one Intel
//     outage — indistinguishable in a dashboard from an actual attack.
//   - `zs-proxy tee inspect` treats it as a FAILURE that stops the
//     report. That tool's most dangerous output is a compose-skeleton
//     digest an operator pastes into an allowlist, and the replay it
//     prints reads RTMR3 out of the quote and authenticates nothing — so
//     a refused quote must never reach the part that names its own trust
//     values. "We could not check" is the one thing this outcome is not.
var ErrStaleCollateralRejected = errors.New("attestation: quote refused by cached Intel collateral")

var (
	collateralOnce  sync.Once
	collateralCache *cachingGetter
)

func sharedCollateralCache() *cachingGetter {
	collateralOnce.Do(func() {
		// No store until PersistCollateral attaches one.
		collateralCache = &cachingGetter{
			inner:       &pcsGetter{},
			entries:     make(map[string]collateralEntry),
			ttl:         collateralTTL,
			staleWarned: make(map[string]bool),
		}
	})
	return collateralCache
}

// pcsGetter fetches one Intel PCS artifact under the caller's deadline.
//
// IT REPLACES trust.DefaultHTTPSGetter, AND THAT IS THE POINT, not a
// preference. The library default is a RetryHTTPSGetter with its OWN
// 2-minute budget wrapping a bare http.Get on http.DefaultClient —
// which carries no timeout at all — and it consults a context only
// BETWEEN retries. So on the exact condition this code is written to
// survive (PCS unreachable, or accepting the connection and going
// silent), a single artifact fetch blocks for two minutes or forever,
// and CollateralTimeout would only ever have skipped the artifacts
// AFTER the one that hung.
//
// That is not one slow probe. The per-operator probes run under a
// shared WaitGroup inside one refresh cycle bounded by
// zs.DefaultRefreshTimeout (30s), so one stalled dstack operator delays
// discovery for the whole fleet — the precise outcome CollateralTimeout
// was sized to prevent. Correctly declining to cache failures means
// every dstack operator pays it independently.
//
// No retry loop here on purpose: the refresh cycle is itself periodic,
// so a transient PCS failure is retried by the next cycle under a fresh
// deadline rather than by burning this one.
type pcsGetter struct{}

func (g *pcsGetter) Get(url string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("attestation: pcsGetter requires a context; use getWithContext")
}

// Always a nil staleCause: this is the fetching path, so anything it
// returns came off the wire just now. Staleness is the cache's answer to
// give.
func (g *pcsGetter) getWithContext(ctx context.Context, url string) (map[string][]string, []byte, error, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := pcsHTTPClient.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCollateralBytes))
	if err != nil {
		return nil, nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.Header, body, nil, fmt.Errorf("intel PCS %s returned %d", url, resp.StatusCode)
	}
	return resp.Header, body, nil, nil
}

// maxCollateralBytes bounds one PCS artifact. TCB info and CRLs are a
// few KB; the cap keeps a misbehaving or hijacked endpoint from
// streaming an unbounded body into the proxy's memory.
const maxCollateralBytes = 4 << 20

// pcsHTTPClient carries a whole-request timeout as a backstop for the
// case a context somehow does not reach it. The context is the primary
// bound; this is defence in depth against exactly the shape of bug this
// getter exists to fix.
var pcsHTTPClient = &http.Client{Timeout: CollateralTimeout}

type collateralEntry struct {
	header  map[string][]string
	body    []byte
	fetched time.Time
}

// cachingGetter memoizes Intel PCS responses for collateralTTL, and
// serves them past it when PCS cannot be reached (collateralStaleMax).
//
// Only SUCCESSES are cached. Caching a failure would pin a transient
// PCS outage across the whole TTL and take every TEE operator out of
// routing for an hour on one bad minute.
//
// now is injectable so the TTL can be tested without sleeping; nil
// means time.Now.
type cachingGetter struct {
	inner   contextGetter
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]collateralEntry

	// store persists entries across restarts. nil disables persistence,
	// which is what the tests want and what a proxy with no resolvable
	// state directory falls back to.
	store *collateralStore

	// log is the first Client's Config.Logger, the cache being the
	// process's; nil uses slog.Default(). Guarded by mu.
	log *slog.Logger

	// persistDebounce overrides collateralPersistDebounce; zero means the
	// constant. It exists so a test can observe the write itself rather
	// than only the scheduling of it — a five-second wait would push the
	// test into either sleeping or asserting on the timer, and the second
	// passes for a save that never lands.
	persistDebounce time.Duration

	// staleWarned dedupes the stale-serve diagnostic per artifact, and
	// is CLEARED on a successful fetch so a recovery followed by a
	// relapse warns again. Keyed by URL rather than by operator on
	// purpose: staleness is a fact about this cache's relationship with
	// Intel, so attributing it per node would emit one global condition
	// once per TEE operator per refresh.
	staleWarned map[string]bool
}

// contextGetter is a fetcher that honours a deadline. The library's
// trust.HTTPSGetter interface has no context parameter, which is the
// root of the stall this package's pcsGetter exists to avoid, so the
// cache is defined against this shape instead.
//
// `staleCause` is non-nil when the artifact came from cache PAST its TTL,
// and holds the fetch failure that forced it. It carries the CAUSE rather
// than a bool because a bool cannot answer the question the caller has to
// ask on a failed verification — a document served from cache may itself
// be the reason the quote was refused, so the outcome is neither a clean
// chain failure nor a clean outage, and reporting it needs the cause (see
// ErrStaleCollateralRejected). It rides the interface rather than a side
// channel so the compiler makes every implementation answer it — a later
// getter that silently returned fresh-looking stale bytes would defeat
// the dedup, the operator diagnostic, and that attribution.
type contextGetter interface {
	getWithContext(ctx context.Context, url string) (
		header map[string][]string, body []byte, staleCause error, err error)
}

func (g *cachingGetter) getWithContext(ctx context.Context, url string) (map[string][]string, []byte, error, error) {
	nowFn := g.now
	if nowFn == nil {
		nowFn = time.Now
	}

	g.mu.Lock()
	e, ok := g.entries[url]
	g.mu.Unlock()
	// A NEGATIVE AGE IS NOT FRESHNESS. nowFn().Sub(fetched) is negative
	// for an entry stamped in the future, which satisfies "< ttl" and
	// short-circuits to a serve — skipping the fetch AND never reaching
	// collateralStaleMax, so both bounds are off at once. A host with a
	// fast RTC (snapshot restore, unsynced boot) writes such entries and
	// persists them, so this survives the restart that would otherwise
	// clear it. Refusing to call it fresh costs one fetch; accepting it
	// serves a CRL predating a revocation for as long as the clock is
	// ahead.
	if age := nowFn().Sub(e.fetched); ok && age >= 0 && age < g.ttl {
		return e.header, e.body, nil, nil
	}

	// The inner cause is forwarded rather than dropped. pcsGetter always
	// answers nil and nothing nests two caches today, so this is inert —
	// but the interface's contract is that the cause rides it, and a
	// layer inserted below that swallowed one would silently disable the
	// attribution in verifyTDXQuoteChainWith.
	header, body, innerStale, err := g.inner.getWithContext(ctx, url)
	if err != nil {
		// STALE-WHILE-REVALIDATE. The entry we already hold is a better
		// answer than refusing: we fetched it from Intel ourselves, so
		// unlike node-carried collateral its vintage is not the
		// operator's choice. Bounded by collateralStaleMax, and
		// go-tdx-guest still rejects anything past its own nextUpdate.
		//
		// The fetch error travels back with the bytes, which is what lets
		// a verification that then FAILS be reported as its own outcome
		// rather than as the operator's forged evidence — see
		// ErrStaleCollateralRejected.
		//
		// A FUTURE-DATED ENTRY IS SERVED HERE, unlike in the fresh arm
		// above, and the asymmetry is the point. Up there a negative age
		// SKIPS the refetch, so both bounds go off at once. Down here the
		// refetch has already been attempted and failed, so the only
		// question left is whether to serve what we have — and refusing
		// is the fleet-wide outage this whole file exists to prevent. A
		// clock stepped backwards (NTP correction after a fast-RTC boot;
		// the JSON round trip strips the monotonic reading, so only disk
		// entries can go negative) would otherwise poison every entry at
		// once, with no successful fetch available to re-stamp them.
		// go-tdx-guest still enforces each document's own nextUpdate, so
		// Intel's ~30-day window remains the backstop — the same one
		// collateralStaleMax's godoc names.
		age := nowFn().Sub(e.fetched)
		if age < 0 {
			age = 0
		}
		if ok && age < collateralStaleMax {
			g.warnStale(url, age, err)
			return e.header, e.body, err, nil
		}
		return header, body, innerStale, err
	}
	g.mu.Lock()
	g.entries[url] = collateralEntry{header: header, body: body, fetched: nowFn()}
	delete(g.staleWarned, url)
	g.mu.Unlock()
	g.persistSoon()
	return header, body, nil, nil
}

// warnStale emits the stale-serve diagnostic once per artifact per
// outage episode. The probe loop re-runs every refresh interval against
// every TEE operator, so an undeduped line here would be the dominant
// content of the log for the whole outage.
func (g *cachingGetter) warnStale(url string, age time.Duration, cause error) {
	g.mu.Lock()
	if g.staleWarned == nil {
		g.staleWarned = map[string]bool{}
	}
	first := !g.staleWarned[url]
	g.staleWarned[url] = true
	log := g.loggerLocked()
	g.mu.Unlock()
	if !first {
		return
	}
	log.Warn("attestation: Intel PCS unreachable, serving cached collateral past its refresh window",
		slog.String("artifact", url),
		slog.Duration("age", age.Round(time.Minute)),
		slog.Duration("refuse_after", collateralStaleMax),
		slog.Any("err", cause))
}

// verifyGetter adapts the ctx-aware cache to the library's
// trust.HTTPSGetter interface for ONE verification. It does two things
// the cache cannot:
//
//   - carries the caller's deadline across an interface boundary that
//     has no ctx parameter, so the fetch itself stops when the probe
//     that asked for it has given up — not merely between fetches;
//   - remembers the first transport failure, so VerifyTDXQuoteChain can
//     tell "we could not reach Intel" from "this quote does not
//     verify". See the comment at that call.
//
// One per verification, which is what makes the error slot safe to read
// without coordinating with concurrent probes.
type verifyGetter struct {
	inner contextGetter
	ctx   context.Context

	mu       sync.Mutex
	fetchErr error
	fetches  int

	// stale is the fetch failure behind the FIRST stale serve, kept apart
	// from fetchErr because the two mean different things to the caller.
	// fetchErr is "this Get returned nothing"; stale is "this Get
	// succeeded, but only from cache, because Intel was unreachable".
	// Only the second can coexist with a completed verification, so
	// folding them into one slot would make a stale serve
	// indistinguishable from a hard failure at count() and at the success
	// path.
	stale error
}

func (g *verifyGetter) Get(url string) (map[string][]string, []byte, error) {
	if err := g.ctx.Err(); err != nil {
		g.record(err)
		return nil, nil, err
	}
	g.mu.Lock()
	g.fetches++
	g.mu.Unlock()

	header, body, staleCause, err := g.inner.getWithContext(g.ctx, url)
	if err != nil {
		g.record(err)
	}
	if staleCause != nil {
		g.mu.Lock()
		if g.stale == nil {
			g.stale = staleCause
		}
		g.mu.Unlock()
	}
	return header, body, err
}

// count reports how many fetches were attempted. Used to assert that
// collateral was actually gathered rather than silently skipped.
func (g *verifyGetter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fetches
}

// staleUsed reports whether ANY artifact in this verification came from
// cache past its TTL. One stale document is enough to qualify the whole
// verdict, so this is a latch rather than a count.
func (g *verifyGetter) staleUsed() bool {
	return g.staleCause() != nil
}

// staleCause reports the PCS failure that forced a stale serve during
// this verification, if any.
//
// ONLY MEANINGFUL ONCE RawTdxQuote HAS ALREADY FAILED, and it says
// nothing about WHICH of the two possible causes produced that failure —
// the node's evidence, or our own aging document. That ambiguity is
// irreducible here and is why the caller reports a distinct outcome
// rather than picking one: a stale artifact still inside
// collateralStaleMax can be past its OWN nextUpdate (the two windows are
// measured from different instants and bound different things), and
// go-tdx-guest rejects such a document exactly as it rejects a forged
// quote.
//
// Deliberately separate from err(): that answers "did a Get return
// nothing", which is false here — a stale serve succeeds.
func (g *verifyGetter) staleCause() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stale
}

// record keeps the FIRST failure. A later one is usually a consequence
// of the first (the library keeps fetching after one artifact fails),
// so the first is the one that explains the outcome.
func (g *verifyGetter) record(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fetchErr == nil {
		g.fetchErr = err
	}
}

func (g *verifyGetter) err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fetchErr
}
