/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/inject"
)

// DefaultAttestationFetchTimeout bounds a single
// /v1/zs/attestation probe. Same default as DefaultDetailsFetchTimeout
// since the two probes share the per-operator deadline.
const DefaultAttestationFetchTimeout = 2 * time.Second

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
// 2*ticket.MaxEphemeralLifetime. The twin in
// client/src/operators/tee-verify.ts is a hand-written millisecond
// literal (client/ pins a published @txnlab/zs-proto, so it cannot
// import this package's constants), and a derived value here would
// track a MaxEphemeralLifetime change on its own while the TypeScript
// side sat still — two verifiers disagreeing, both suites green.
// TestEvidenceMaxAgeCeilingCoversEphemeralWindow fails instead, which
// is the prompt to move both by hand.
//
// Mirrors EVIDENCE_MAX_AGE_CEILING_MS in
// client/src/operators/tee-verify.ts. Not golden-vectored: the
// TypeScript twin lives in client/, not proto/ts, so there is nothing
// here to vector it against.
const EvidenceMaxAgeCeiling = 80 * time.Minute

// Verifier failure tags. These are the canonical tags proto/SPEC.md §3e
// "Verifier responsibilities" names step by step, and they populate the
// FailureTag field on TEEStatus. (proto/TEE.md §4.3 walks the same
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

// maxOperatorResponseBytes caps how much we'll read from an
// operator-controlled HTTP response body. The cap exists to keep a
// hostile or buggy operator from streaming a multi-GB body and OOM-ing
// the proxy; the per-operator probe loop in fetcher.enrich runs
// concurrently, so one bad operator would otherwise amplify into
// N×size pressure.
//
// The headroom is narrower than it was. This used to say bundles are
// "well under 64 KB in practice", which stopped being true at proto
// 9.6: an evidence bundle now carries the app_compose PREIMAGE, which
// is ~22 KB on the 2026-08 capture and grows with the operator's own
// NODE_CONFIG_YAML, since that config is literal text inside the
// measured document. 256 KiB still holds with room to spare, and an
// over-cap body fails closed at json.Unmarshal rather than truncating
// into a plausible document — but the number to watch is now the
// config, which an operator controls, not the fixed fields.
const maxOperatorResponseBytes = 256 << 10 // 256 KiB

// VerifierIDBuiltin stamps a verdict that BundleVerifier decided on its
// own — a stub bundle, or a mode with no platform verifier behind it.
// Mirrored from the proxy config's TEEVerifierBuiltin so the package
// boundary doesn't force a cross-import every time it's referenced.
//
// A verdict that reached a platform verifier carries THAT verifier's id
// instead (VerifierIDDstack), so this value surviving to the operator's
// TEEStatus is itself informative: no platform chain was checked.
const VerifierIDBuiltin = "builtin"

// Verdict is the outcome of a single TEEVerifier.Verify call. Pass is
// the routing-relevant bit; FailureTag is empty iff Pass is true and
// otherwise carries one of the Failure* constants. AttestedAt is the
// bundle's GeneratedAt — surfaced so the caller can stamp it on the
// operator's TEEStatus regardless of the pass/fail outcome (the
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

// TEEVerifier verifies an evidence bundle against an advertisement.
// A typed interface (rather than a free function) so a future
// LocalNvtrustVerifier (or alternative-vendor implementation) lands
// behind the same shape as a config-switch, not a refactor.
//
// Implementations MUST always populate VerifierID on the returned
// Verdict and SHOULD populate AttestedAt from bundle.GeneratedAt
// regardless of whether Pass is true. Pass=false MUST come with a
// non-empty FailureTag drawn from the Failure* constants.
type TEEVerifier interface {
	Verify(ctx context.Context, advertised inject.TEEAdvertisement, bundle inject.TEEEvidenceBundle, op Operator) Verdict
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
// fetcher only calls Verify when the details probe surfaced a TEE
// advertisement.
type BundleVerifier struct {
	AllowStub bool

	// TrustedComposeHashes / TrustedOSImages are the measurement
	// allowlists handed to the dstack branch. EMPTY MEANS NOTHING
	// VERIFIES on that branch — see DstackVerifier.
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

// Verify implements TEEVerifier. See BundleVerifier for the layered
// check semantics.
func (v *BundleVerifier) Verify(ctx context.Context, advertised inject.TEEAdvertisement, bundle inject.TEEEvidenceBundle, op Operator) Verdict {
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
	// applyEphemeralAdvertisement has already vetted it this same refresh
	// pass — signature-verified under the on-chain Ed25519 key, bound to
	// (operator_id, node_id), issued-at checked and capped at
	// MaxEphemeralLifetime — so the attested key is provably fresh and
	// short-lived, not merely self-consistent.
	//
	// Because that key rotates (node: server.EphemeralRotationPeriod), the
	// node re-mints evidence on rotation. Both are read in one refresh pass
	// (applyEphemeralAdvertisement then probeAttestation), so a matching pair
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
	if bundle.OperatorID != op.ID {
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
	// The `advertisedMaxAge > 0` guard is doing two jobs, and the second
	// is not obvious: it subsumes the RefreshSeconds > 0 check, and it
	// catches the int64 OVERFLOW. RefreshSeconds is a plain int decoded
	// from operator-controlled JSON, so ~4.6e9 makes the nanosecond
	// product wrap negative — which would sail past a bare `<` and pin
	// maxAge negative, failing every bundle from that node. Fail-closed
	// either way, but the TypeScript twin computes in float64 and lands
	// on the ceiling, so without this the two verifiers return opposite
	// verdicts on one bundle.
	maxAge := EvidenceMaxAgeCeiling
	if advertisedMaxAge := 2 * time.Duration(bundle.RefreshSeconds) * time.Second; advertisedMaxAge > 0 && advertisedMaxAge < maxAge {
		maxAge = advertisedMaxAge
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
	expected := computeReportData(nodePubkey, op.ID)
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

// AttestationClient fetches /v1/zs/attestation from a node. Mirrors
// the shape of DetailsClient (see details.go) so the per-operator
// probe layer doesn't need a second timeout / HTTP-pool model.
type AttestationClient struct {
	HTTP    *http.Client
	Timeout time.Duration
}

// NewAttestationClient constructs an AttestationClient. timeout falls
// back to DefaultAttestationFetchTimeout when non-positive. Pass an
// existing *http.Client to share connection pools across operators;
// per-fetch deadlines are enforced via context inside Fetch (we do not
// set http.Client.Timeout because the proxy's project-wide convention
// is to keep client timeouts at zero and rely on the request context).
func NewAttestationClient(client *http.Client, timeout time.Duration) *AttestationClient {
	if timeout <= 0 {
		timeout = DefaultAttestationFetchTimeout
	}
	if client == nil {
		// Timeout 0: the per-fetch deadline is enforced via context in Fetch.
		// The tuned transport gives a short dial timeout and a per-host idle
		// pool, matching DetailsClient (see details.go).
		client = httpx.Client(0, httpx.Options{})
	}
	return &AttestationClient{HTTP: client, Timeout: timeout}
}

// Fetch joins evidenceURL onto baseURL (so a node can advertise an
// absolute or relative path) and issues a GET. Any error (network,
// non-2xx, malformed JSON) is returned to the caller — Fetch does not
// silently swallow them; the fetcher logs each failure with the
// FailureFetchFailed tag. A 404 is treated as a normal error here
// (operator advertised TEE but the endpoint is absent / misrouted) —
// the caller handles it the same as any other fetch failure.
// When hop is non-nil the probe is routed through that relay (transport-privacy
// mode). The relay forwards to the target's standard /v1/zs/attestation path
// (the only attestation path on the relay allow-list); an operator advertising
// a non-standard / absolute evidence URL cannot be relay-probed for attestation
// under privacy mode — a known limitation tracked for the privacy rollout.
func (c *AttestationClient) Fetch(ctx context.Context, baseURL, evidenceURL string, hop *RelayHop) (inject.TEEEvidenceBundle, error) {
	endpoint, err := joinAttestationURL(baseURL, evidenceURL)
	if err != nil {
		return inject.TEEEvidenceBundle{}, err
	}

	fetchCtx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", inject.AttestationContentType)
	if err := ApplyRelay(req, hop, "/v1/zs/attestation", http.MethodGet); err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("apply relay: %w", err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("attestation request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("attestation endpoint returned %d %s", resp.StatusCode, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOperatorResponseBytes))
	if err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("read attestation body: %w", err)
	}
	var bundle inject.TEEEvidenceBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("decode attestation: %w", err)
	}
	return bundle, nil
}

// joinAttestationURL resolves evidenceURL against baseURL. Handles
// three shapes the node may advertise:
//
//   - empty           → falls back to "/v1/zs/attestation"
//   - "/path/..."     → joined onto baseURL
//   - "http(s)://..." → used verbatim (the node has TLS-terminated the
//     attestation endpoint behind a different host than its base URL)
//
// Only http and https schemes are accepted on absolute URLs to
// prevent a malicious operator from steering the proxy at file:// or
// gopher:// targets via a crafted EvidenceURL.
func joinAttestationURL(baseURL, evidenceURL string) (string, error) {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return "", errors.New("empty operator base_url")
	}
	if evidenceURL == "" {
		return trimmed + "/v1/zs/attestation", nil
	}
	if strings.HasPrefix(evidenceURL, "http://") || strings.HasPrefix(evidenceURL, "https://") {
		return evidenceURL, nil
	}
	if !strings.HasPrefix(evidenceURL, "/") {
		evidenceURL = "/" + evidenceURL
	}
	return trimmed + evidenceURL, nil
}
