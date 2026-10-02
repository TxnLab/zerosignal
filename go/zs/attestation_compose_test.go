/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
)

// capturedAppCompose recovers the app-compose document from the same live
// Phala CVM the quote and event log came from.
//
// ONE CVM, three files. Splitting the document across captures would let the
// hash gate pass while the two halves described different machines — which is
// precisely the substitution the gate exists to catch, so a fixture that
// allowed it would make every test here vacuous.
//
// THE FILE IS 56 KB AND ONLY tcb_info.app_compose IS READ, which looks like
// waste and is deliberate. It is the guest agent's /Info response VERBATIM:
// an 18 KB app_cert, a tcb_info.event_log duplicating ds_event_log.json, and
// the measurement fields, none of which any test here touches. Trimming to the
// used field would turn a real capture into an edited artifact, and the
// property every test in this file rests on — that these bytes came off one
// machine, unmodified — is exactly the one an edit makes unverifiable. It is
// also why proxy/ keeps its own copy rather than reading proto/testdata: an
// out-of-workspace CI build clones this repo alone.
func capturedAppCompose(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/ds_info.json")
	if err != nil {
		t.Fatalf("read /Info capture: %v", err)
	}
	var info struct {
		TCBInfo string `json:"tcb_info"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("parse capture: %v", err)
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal([]byte(info.TCBInfo), &tcb); err != nil {
		t.Fatalf("parse tcb_info: %v", err)
	}
	if tcb.AppCompose == "" {
		t.Fatal("the capture carries no app_compose, so nothing below asserts anything")
	}
	return tcb.AppCompose
}

// TestDstackVerifier_RefusesABackdooredCompose is the point of wiring the
// content rules in at all.
//
// The captured CVM's compose hash IS in the trusted list — this fixture is
// the one the rest of the suite treats as healthy — and it installs an
// operator-held root SSH key anyway (`phala deploy` appended the deploying
// machine's public key as DSTACK_AUTHORIZED_KEYS without a prompt). A hash
// allowlist cannot see that; only reading the document can.
//
// So this asserts the thing the whole phase is for: a node can be
// hand-blessed and still refused on what it actually runs.
func TestDstackVerifier_RefusesABackdooredCompose(t *testing.T) {
	v, op, bundle := dstackFixture(t)
	v.ComposePolicy = attest.ZeroSignalComposePolicy()
	bundle.AppCompose = capturedAppCompose(t)

	verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
	if verdict.Pass {
		t.Fatal("a compose installing a root SSH key verified clean, on a node whose " +
			"compose hash is in the trusted list — the content rules are not wired in")
	}
	if verdict.FailureTag != FailureMeasurementMismatch {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureMeasurementMismatch)
	}
}

// TestDstackVerifier_RefusesASubstitutedCompose covers the gate that makes
// the document safe to read at all: it is hashed against the measurement
// recovered from the REPLAY, not against anything the node said.
//
// Without it a node could publish a clean-looking compose alongside a quote
// that measured something else entirely, and every content rule would pass
// while describing a document the hardware never saw.
func TestDstackVerifier_RefusesASubstitutedCompose(t *testing.T) {
	v, op, bundle := dstackFixture(t)
	v.ComposePolicy = attest.ZeroSignalComposePolicy()
	// Policy-clean, and not the measured document.
	bundle.AppCompose = `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services:\n  zs-node:\n    image: ghcr.io/txnlab/zs-node@sha256:00\n"}`

	if verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op); verdict.FailureTag != FailureMeasurementMismatch {
		t.Fatalf("FailureTag = %q (pass=%v), want %q — a document that is not the "+
			"measured one must be refused before a single field is read",
			verdict.FailureTag, verdict.Pass, FailureMeasurementMismatch)
	}
}

// TestDstackVerifier_AbsentComposeStillVerifies pins the rollout ordering as
// a DECISION rather than an oversight.
//
// The content rules run in addition to trusted_compose_hashes, not instead of
// it, so a node that publishes no preimage — an older guest agent, or one
// whose /Info was briefly unreachable when its evidence was minted — is still
// verified by the hash allowlist exactly as before.
//
// This must flip the day the skeleton and release-image lists are populated:
// once content validation is sufficient, an absent document means the
// compose was never checked, and accepting it would be the fail-open shape
// proto/SPEC.md §3e refuses. The test is here so that change is deliberate.
// TestDstackVerifier_AbsentComposeSplitsOnTheReleaseMatch pins both halves of
// the skip, because each is wrong in the other's configuration.
//
// Skipping is right when the release match is off: a guest agent predating
// proto 9.6 cannot publish a preimage, and refusing it would read every such
// node as compromised for a capability gap. Skipping is a HOLE the moment the
// release match is the gate — there is no longer a hand-blessed compose_hash
// standing behind it, so every content rule becomes opt-out and a node declines
// to publish and is verified anyway. That is strictly easier than substituting
// a document, which is the attack the rules are written against.
//
// Both cases must assert, and the enforced one must assert on the ABSENCE
// specifically: with enforcement on, a fixture whose document is present also
// fails (the captured CVM is not a published release), so a test that only
// checked "enforced ⇒ refused" would pass with this branch deleted.
func TestDstackVerifier_AbsentComposeSplitsOnTheReleaseMatch(t *testing.T) {
	t.Run("skipped while the release match is off", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		v.ComposePolicy = attest.ZeroSignalComposePolicy()
		bundle.AppCompose = ""

		if verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op); !verdict.Pass {
			t.Fatalf("FailureTag = %q, want a pass — with no release match, a node with "+
				"no preimage is no worse off than before the field existed",
				verdict.FailureTag)
		}
	})

	t.Run("refused once the release match is the gate", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		policy := attest.ZeroSignalComposePolicy()
		policy.EnforceComposeSkeleton = true
		policy.TrustedComposeSkeletons = []string{strings.Repeat("cd", 32)}
		policy.TrustedNodeImages = []string{"ghcr.io/txnlab/zs-node@sha256:" + strings.Repeat("ef", 32)}
		v.ComposePolicy = policy
		bundle.AppCompose = ""

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("a node publishing no app_compose passed under the release match — " +
				"the content rules are opt-out, which is easier to exploit than the " +
				"document substitution they exist to catch")
		}
		if verdict.FailureTag != FailureMeasurementMismatch {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureMeasurementMismatch)
		}
	})
}

// TestDstackVerifier_ComposeHashPinNarrowsButDoesNotSubstitute covers the
// reading of an EMPTY TrustedComposeHashes, which changed meaning and is the
// one fail-open shape this file now contains.
//
// Empty is "no constraint" only under the release match, where the field
// narrows an already-identified fleet. With the release match off it is the
// only thing identifying a workload, so empty must keep refusing everything —
// the reading TestDstackVerifier_FailsClosed's "empty compose allowlist"
// case pins from the other side.
//
// The third case is the one that would be missed: a populated pin does NOT
// become a bypass. A payer who blesses a specific deployment still gets the
// release match applied on top, or "pin your own hash" would be a documented
// route around it.
func TestDstackVerifier_ComposeHashPinNarrowsButDoesNotSubstitute(t *testing.T) {
	// EVERY CASE HERE ASSERTS ON THE LOG, NOT ON Pass, and that is forced by
	// the fixtures rather than chosen for convenience.
	//
	// The only real document in this tree is the BACKDOOR capture: it installs
	// a root SSH key and runs Phala's boot hook, and BOTH of those rules are
	// unconditional — they fire even against a zero-value policy, so no
	// configuration of this verifier admits this document. It cannot be
	// swapped for a clean one either, because the hash gate requires the
	// MEASURED document and there is exactly one.
	//
	// So `Pass` is false in every case below and carries no information. What
	// does carry it is WHICH rule refused, which the WARN names. A pin that
	// fired logs "compose hash is not in the trusted set"; a pin that was
	// skipped does not, and the release match logs a policy violation
	// instead. Asserting both halves is what keeps these from passing on the
	// backdoor rule alone — measured: they did, until the document was
	// attached and the log assertions replaced a bare Pass check.
	permissive := func() attest.ComposePolicy { return attest.ComposePolicy{} }
	enforcing := func() attest.ComposePolicy {
		p := permissive()
		p.EnforceComposeSkeleton = true
		p.TrustedComposeSkeletons = []string{strings.Repeat("cd", 32)}
		p.TrustedNodeImages = []string{"ghcr.io/txnlab/zs-node@sha256:" + strings.Repeat("ef", 32)}
		return p
	}

	// EVERY CASE CARRIES THE REAL DOCUMENT, and that is not incidental.
	// dstackFixture leaves AppCompose empty, so without this each subtest is
	// refused by the absent-preimage branch above and passes no matter what
	// the pin does — measured: all of them were green with the pin change
	// reverted until the document was attached.
	withDoc := func(t *testing.T) (*BundleVerifier, Operator, inject.TEEEvidenceBundle) {
		t.Helper()
		v, op, bundle := dstackFixture(t)
		bundle.AppCompose = capturedAppCompose(t)
		return v, op, bundle
	}

	t.Run("empty pin is skipped under the release match", func(t *testing.T) {
		v, op, bundle := withDoc(t)
		v.TrustedComposeHashes = nil
		v.ComposePolicy = enforcing()
		// The captured CVM is not a published release, so it is refused on
		// the skeleton either way. What this asserts is WHICH rule refused
		// it: with the pin still gating, the refusal comes earlier and names
		// the compose hash. Both halves are asserted, because the absence
		// alone would also hold if nothing ran at all.
		logs := &bytes.Buffer{}
		v.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

		v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if strings.Contains(logs.String(), "compose hash is not in the trusted set") {
			t.Error("an empty TrustedComposeHashes refused the node even though the " +
				"release match is on — the pin is still acting as the gate")
		}
		if !strings.Contains(logs.String(), "the measured compose violates policy") {
			t.Errorf("expected the refusal to come from the release match, got:\n%s", logs)
		}
	})

	t.Run("empty pin still refuses everything without the release match", func(t *testing.T) {
		v, op, bundle := withDoc(t)
		v.TrustedComposeHashes = nil
		v.ComposePolicy = permissive()
		logs := &bytes.Buffer{}
		v.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

		if verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op); verdict.Pass {
			t.Fatal("an unconfigured proxy accepted a quote from any CVM — empty read " +
				"as 'accept anything' is the check vanishing while looking like the " +
				"feature working")
		}
		// Named, not just refused: this document satisfies the shared content
		// rules, so without the pin firing there is nothing else to refuse it
		// and a bare Pass check could not tell the two apart.
		if !strings.Contains(logs.String(), "compose hash is not in the trusted set") {
			t.Errorf("expected the empty pin to be what refused, got:\n%s", logs)
		}
	})

	t.Run("a non-matching pin still refuses under the release match", func(t *testing.T) {
		// THE CASE THE OTHERS CANNOT SEE, and without it the guard's whole
		// len()>0 clause is inert: mutating it to `if
		// !v.ComposePolicy.EnforceComposeSkeleton` — making a populated pin a
		// no-op whenever the match is on — passed the entire proxy module.
		//
		// Neither sibling catches that. Two pass a nil pin, and the matching-pin
		// case cannot distinguish "pin satisfied" from "pin never consulted".
		// Only a pin the node FAILS separates them.
		//
		// It matters because it is the payer who configured MORE ending up with
		// LESS: a hand-vetted narrowing that silently does nothing.
		v, op, bundle := withDoc(t)
		v.TrustedComposeHashes = []string{strings.Repeat("aa", 32)}
		v.ComposePolicy = enforcing()
		logs := &bytes.Buffer{}
		v.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

		if verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op); verdict.Pass {
			t.Fatal("a node outside the payer's compose-hash pin was admitted")
		}
		if !strings.Contains(logs.String(), "compose hash is not in the trusted set") {
			t.Errorf("the pin was never consulted under the release match — a payer's "+
				"narrowing is inert. Log:\n%s", logs)
		}
	})

	t.Run("a matching pin does not bypass the release match", func(t *testing.T) {
		v, op, bundle := withDoc(t)
		// The pin matches this exact deployment, so it is satisfied and
		// contributes no refusal of its own. The release match must still
		// run and still refuse — a pin that substituted would leave nothing
		// complaining about the skeleton at all.
		v.TrustedComposeHashes = []string{capturedComposeHash}
		v.ComposePolicy = enforcing()
		logs := &bytes.Buffer{}
		v.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

		if verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op); verdict.Pass {
			t.Fatal("a hand-pinned compose_hash admitted a node that is not a published " +
				"release — the pin narrows, it must never substitute")
		}
		if !strings.Contains(logs.String(), string(attest.ViolationComposeSkeleton)) {
			t.Errorf("a satisfied pin suppressed the release match — expected a %q "+
				"violation, got:\n%s", attest.ViolationComposeSkeleton, logs)
		}
	})
}

// TestDstackVerifier_PolicyIsActuallyThreadedThrough covers the wiring the
// refusal tests above cannot.
//
// Those pass with the policy replaced by its zero value (measured), because
// the root-backdoor rule is UNCONDITIONAL — every policy refuses that
// document, so they prove VerifyAppCompose is called and nothing about which
// rules reach it. The env allowlist is the part that only fires when the
// shared policy is threaded, so this asserts on a document whose sole defect
// is an env name.
//
// It must drive BundleVerifier.Verify, not read the field back. An earlier
// version of this test built a DstackVerifier by re-doing the copy in the test
// body and then asserted on the value it had just assigned — which is no
// assertion at all: BOTH wiring lines (app.go's policy and
// BundleVerifier.Verify's copy into DstackVerifier) could be deleted with the
// whole module green. The only thing that exercises them is a real Verify.
//
// The observable is the LOG, because the verdict cannot carry the difference:
// every refusal here is FailureMeasurementMismatch, so a threaded policy and
// an unthreaded one produce identical Verdicts and differ only in which
// violations the warning names.
func TestDstackVerifier_PolicyIsActuallyThreadedThrough(t *testing.T) {
	doc := capturedAppCompose(t)
	measured := map[string]string{attest.EventComposeHash: capturedComposeHash}

	// Precondition: with the shared policy the capture must fail on the
	// env allowlist specifically, not only on the back door. If it stops
	// doing so, the assertion below is testing the unconditional rule
	// again and this test has gone quietly vacuous.
	_, err := attest.VerifyAppCompose(doc, measured, attest.ZeroSignalComposePolicy())
	if err == nil || !strings.Contains(err.Error(), "env_not_allowed") {
		t.Fatalf("the shared policy no longer refuses the capture's probe env names, "+
			"so this test can no longer distinguish it from the zero policy: %v", err)
	}
	// ...and with the env allowlist off, that specific violation is gone.
	relaxed := attest.ZeroSignalComposePolicy()
	relaxed.EnforceEnvAllowlist = false
	_, err = attest.VerifyAppCompose(doc, measured, relaxed)
	if err != nil && strings.Contains(err.Error(), "env_not_allowed") {
		t.Fatal("env_not_allowed fires with EnforceEnvAllowlist off, so it cannot " +
			"distinguish a threaded policy from an unthreaded one")
	}

	var logs bytes.Buffer
	v, op, bundle := dstackFixture(t)
	v.Log = slog.New(slog.NewTextHandler(&logs, nil))
	v.ComposePolicy = attest.ZeroSignalComposePolicy()
	bundle.AppCompose = doc

	if verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op); verdict.Pass {
		t.Fatal("the captured compose verified clean")
	}
	if got := logs.String(); !strings.Contains(got, "env_not_allowed") {
		t.Errorf("the refusal names no env_not_allowed violation, so the shared policy "+
			"did not reach VerifyAppCompose — app.go's field or BundleVerifier's copy "+
			"into DstackVerifier is not wired.\nlog: %s", got)
	}
}

// TestDstackVerifier_ComposePolicyIsTheSharedOne guards against the rule set
// being re-spelled here.
//
// The proxy and the browser client must reach the same verdict on the same
// document; two hand-maintained copies is how they stop doing that, and the
// divergence would be silent — each side would be internally consistent and
// they would disagree only about real nodes.
func TestDstackVerifier_ComposePolicyIsTheSharedOne(t *testing.T) {
	p := attest.ZeroSignalComposePolicy()
	if !p.EnforceEnvAllowlist {
		t.Error("the shared policy does not enforce the env allowlist, which is what " +
			"stops the unmeasured env channel overriding the measured config")
	}
	if len(p.AllowedEnvNames) == 0 {
		t.Error("the shared policy permits no secret env names, so every real node fails")
	}
	// The per-release half is deliberately empty until a release compose
	// is published — see app.go. If this starts failing, the lists were
	// populated and EnforceComposeSkeleton needs turning on with them.
	if p.EnforceComposeSkeleton {
		t.Error("EnforceComposeSkeleton is set but the release lists ship empty, " +
			"which fails closed and refuses every node")
	}
}

// TestCapturedCompose_IsTheMeasuredOne is the precondition the two refusal
// tests above rest on, asserted separately so a broken fixture cannot look
// like a working check.
//
// If the capture stopped hashing to the measurement, TestDstackVerifier_
// RefusesABackdooredCompose would still pass — for the wrong reason, on the
// hash gate rather than on the backdoor rule it is named for.
func TestCapturedCompose_IsTheMeasuredOne(t *testing.T) {
	doc := capturedAppCompose(t)
	if err := attest.VerifyComposeHash(doc,
		map[string]string{attest.EventComposeHash: capturedComposeHash}); err != nil {
		t.Fatalf("the captured document does not hash to the captured measurement: %v", err)
	}

	// And it really does carry the back door, or the refusal test is
	// asserting against a clean document.
	_, err := attest.VerifyAppCompose(doc,
		map[string]string{attest.EventComposeHash: capturedComposeHash},
		attest.ZeroSignalComposePolicy())
	if err == nil || !strings.Contains(err.Error(), "root_backdoor_env") {
		t.Fatalf("the capture no longer carries the root back door: %v", err)
	}
}
