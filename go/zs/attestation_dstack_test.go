/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
)

// The captured quote is real hardware output from a live Phala
// tdx.small CVM, so it binds the values the probe minted it with and
// nothing else. Driving the verifier with them is what makes these
// tests statements about real evidence rather than about a mock that
// agrees with the verifier by construction.
const (
	capturedKey         = "age1probeplaceholderrecipientvalue000000000000000000"
	capturedOperatorID  = 42
	capturedComposeHash = "6e6f3898b6c20ee50c12713a80453da2c992de95e857d64791b909037f157485"
	capturedOSImage     = "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
)

func loadDstackVectors(t *testing.T) (quote []byte, eventLog string) {
	t.Helper()
	qhex, err := os.ReadFile("testdata/ds_quote_hex.txt")
	if err != nil {
		t.Fatalf("read quote vector: %v", err)
	}
	quote, err = hex.DecodeString(strings.TrimSpace(string(qhex)))
	if err != nil {
		t.Fatalf("decode quote vector: %v", err)
	}
	log, err := os.ReadFile("testdata/ds_event_log.json")
	if err != nil {
		t.Fatalf("read event log vector: %v", err)
	}
	return quote, string(log)
}

// capturedNodeID is the fixture's chain-resolved node id. Deliberately
// non-zero, so that a verifier ignoring op.NodeID — passing 0, or dropping
// the field from the preimage — fails the happy path instead of agreeing
// with the fixture by accident. It says nothing about byte order: the
// fixture and the verifier both call attest.AuxBinding, so no endianness
// error is observable from this side. proto/testdata/attest_vectors.json
// is what pins that.
const capturedNodeID = uint64(0x0102030405060708)

// capturedModels is the catalog the fixture node attests. Returned fresh
// each call rather than shared, so a test that mutates it to build a
// mismatch cannot corrupt the next fixture.
//
// All three states, so the fixture reaches every HApp branch a real
// node's catalog can. The hashing itself is pinned by proto's h_app
// vectors, not here.
func capturedModels() []inject.ModelEntry {
	return []inject.ModelEntry{
		{ModelID: "qwen3-30b", Source: "hf/Qwen/Qwen3-30B", WeightsDigest: "sha256:aa11", State: inject.WeightsMeasured},
		{ModelID: "glm-4.6", Source: "hf/zai-org/GLM-4.6", WeightsDigest: "sha256:bb22", State: inject.WeightsDeclared},
		{ModelID: "grok-4", Source: "", WeightsDigest: "", State: inject.WeightsUnverifiable},
	}
}

// withAuxBinding returns a copy of quote with report_data's upper 32
// bytes replaced by the aux binding the given inputs produce.
//
// The offset is this file's own constant rather than one imported from
// attest — attest's are unexported, and a helper deriving them from the
// same source the code under test uses could not catch an offset error in
// either. quoteReportDataOffset carries a test pinning it against the
// field attest actually reads, which a second literal here would not.
func withAuxBinding(t *testing.T, quote []byte, nodeID uint64, entries []inject.ModelEntry, posture *inject.TEEPosture, nonce *[32]byte) []byte {
	t.Helper()
	hApp, err := attest.HApp(entries)
	if err != nil {
		t.Fatalf("HApp over the fixture catalog: %v", err)
	}
	hPosture, err := attest.HPosture(posture)
	if err != nil {
		t.Fatalf("HPosture over the fixture posture: %v", err)
	}
	aux := attest.AuxBinding(nodeID, hApp, hPosture, nonce)
	const upperHalf = quoteReportDataOffset + 32
	out := make([]byte, len(quote))
	copy(out, quote)
	copy(out[upperHalf:upperHalf+32], aux[:])
	return out
}

// dstackFixture builds the operator + bundle a healthy dstack node
// would present, plus a verifier whose chain check is stubbed out.
//
// STUBBING THE CHAIN CHECK NARROWS WHAT THESE TESTS PROVE, and that is
// deliberate: they cover the replay, allowlist, binding and posture
// steps, all of which are pure functions of the captured bytes. The
// chain step reaches Intel's PCS and has its own network-gated test —
// TestVerifyTDXQuoteChain_RealQuote. A green run here is NOT evidence
// that a forged quote is rejected.
func dstackFixture(t *testing.T) (*BundleVerifier, Operator, inject.TEEEvidenceBundle) {
	t.Helper()
	quote, eventLog := loadDstackVectors(t)

	op := Operator{
		ID:                       capturedOperatorID,
		NodeID:                   capturedNodeID,
		SigningAddr:              "SIGNING-ADDR-NOT-THE-BINDING-TARGET",
		EphemeralRecipientPubkey: capturedKey,
	}
	// The capture is a PRE-9.9 quote: its upper 32 bytes are the guest
	// agent's zero padding, which 9.9 refuses. Splicing in the aux
	// binding this operator/catalog pair produces is what makes the
	// fixture a 9.9 node. The spliced quote is NOT signature-valid, which
	// is harmless here only because dstackFixture stubs VerifyChain — see
	// its godoc. A genuine 9.9 capture replaces this once a 9.9 node runs
	// on real hardware.
	quote = withAuxBinding(t, quote, capturedNodeID, capturedModels(), fixturePosture(), nil)
	bundle := inject.TEEEvidenceBundle{
		Mode:           inject.TEEModeDstackTDX,
		CPUReport:      base64.StdEncoding.EncodeToString(quote),
		EventLog:       eventLog,
		NodePubkey:     capturedKey,
		OperatorID:     capturedOperatorID,
		ReportData:     base64.StdEncoding.EncodeToString(computeReportData(capturedKey, capturedOperatorID)),
		AppModels:      capturedModels(),
		GeneratedAt:    time.Now().UTC(),
		RefreshSeconds: 1200,
		Posture:        fixturePosture(),
	}
	v := &BundleVerifier{
		TrustedComposeHashes: []string{capturedComposeHash},
		TrustedOSImages:      []string{capturedOSImage},
		VerifyChain:          func(context.Context, []byte) error { return nil },
	}
	return v, op, bundle
}

// fixturePosture is the posture dstackFixture's quote commits to. A fresh
// pointer per call, so a test mutating its bundle's copy cannot move the
// value another test splices into its quote.
func fixturePosture() *inject.TEEPosture {
	return &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream,
		UpstreamBaseURL:     "https://api.x.ai/v1",
		ZeroRetention:       true,
	}
}

func dstackAdvertisement() inject.TEEAdvertisement {
	return inject.TEEAdvertisement{Mode: inject.TEEModeDstackTDX, EvidenceURL: "/v1/zs/attestation"}
}

func TestDstackVerifier_PassesRealEvidence(t *testing.T) {
	v, op, bundle := dstackFixture(t)

	verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
	if !verdict.Pass {
		t.Fatalf("verdict = %+v, want Pass", verdict)
	}
	if verdict.FailureTag != "" {
		t.Errorf("FailureTag = %q on a passing verdict", verdict.FailureTag)
	}
	if verdict.VerifierID != VerifierIDDstack {
		t.Errorf("VerifierID = %q, want %q", verdict.VerifierID, VerifierIDDstack)
	}
	if !verdict.AttestedAt.Equal(bundle.GeneratedAt) {
		t.Errorf("AttestedAt = %v, want %v", verdict.AttestedAt, bundle.GeneratedAt)
	}
}

func TestDstackVerifier_FailsClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*BundleVerifier, *Operator, *inject.TEEEvidenceBundle)
		want string
	}{
		{
			// The step every other one rests on. report_data is signed
			// BLINDLY: without the chain check, the quote is just bytes
			// an operator wrote.
			name: "vendor chain rejects the quote",
			mut: func(v *BundleVerifier, _ *Operator, _ *inject.TEEEvidenceBundle) {
				v.VerifyChain = func(context.Context, []byte) error { return errors.New("bad chain") }
			},
			want: FailureVendorChainInvalid,
		},
		{
			// An unreachable Intel PCS is OUR outage, and must not be
			// reported as this operator's evidence being forged —
			// otherwise one bad minute at Intel stamps
			// vendor_chain_invalid across the whole fleet, which reads
			// in a dashboard exactly like an attack.
			name: "unreachable collateral is not a forged quote",
			mut: func(v *BundleVerifier, _ *Operator, _ *inject.TEEEvidenceBundle) {
				v.VerifyChain = func(context.Context, []byte) error {
					return fmt.Errorf("%w: dial tcp: i/o timeout", ErrCollateralUnavailable)
				}
			},
			want: FailureCollateralUnreachable,
		},
		{
			// EMPTY ALLOWLIST MUST NOT MEAN "ACCEPT ANYTHING". An
			// unconfigured proxy reading it that way would accept a
			// quote from any CVM running any image while looking
			// exactly like the feature working.
			name: "empty compose allowlist verifies nothing",
			mut: func(v *BundleVerifier, _ *Operator, _ *inject.TEEEvidenceBundle) {
				v.TrustedComposeHashes = nil
			},
			want: FailureMeasurementMismatch,
		},
		{
			// The OS-image allowlist is required, not optional
			// hardening: a quote taken on a dstack DEV image passes
			// every other check identically.
			name: "empty OS image allowlist verifies nothing",
			mut: func(v *BundleVerifier, _ *Operator, _ *inject.TEEEvidenceBundle) {
				v.TrustedOSImages = nil
			},
			want: FailureMeasurementMismatch,
		},
		{
			// Cut inside report_data (offset 568), after RTMR3, so the
			// replay still passes. Real DCAP refuses this at the chain;
			// with the chain stubbed it reaches the split, which must
			// refuse rather than treat an unreadable field as a pass.
			name: "quote truncated inside report_data",
			mut: func(_ *BundleVerifier, _ *Operator, b *inject.TEEEvidenceBundle) {
				q, err := base64.StdEncoding.DecodeString(b.CPUReport)
				if err != nil {
					panic(err)
				}
				b.CPUReport = base64.StdEncoding.EncodeToString(q[:600])
			},
			want: FailureKeyBindingMismatch,
		},
		{
			name: "compose hash not in the allowlist",
			mut: func(v *BundleVerifier, _ *Operator, _ *inject.TEEEvidenceBundle) {
				v.TrustedComposeHashes = []string{strings.Repeat("aa", 32)}
			},
			want: FailureMeasurementMismatch,
		},
		{
			name: "OS image not in the allowlist",
			mut: func(v *BundleVerifier, _ *Operator, _ *inject.TEEEvidenceBundle) {
				v.TrustedOSImages = []string{strings.Repeat("bb", 32)}
			},
			want: FailureMeasurementMismatch,
		},
		{
			// An appended runtime event changes the accumulator, so a
			// log that is not the one the hardware measured must not
			// verify — otherwise the log could carry any compose-hash
			// the operator liked.
			name: "event log has an appended event",
			mut: func(_ *BundleVerifier, _ *Operator, b *inject.TEEEvidenceBundle) {
				b.EventLog = strings.TrimSuffix(strings.TrimSpace(b.EventLog), "]") +
					`,{"imr":3,"event_type":134217729,"digest":"","event":"extra","event_payload":"00"}]`
			},
			want: FailureMeasurementMismatch,
		},
		{
			name: "event log is absent",
			mut: func(_ *BundleVerifier, _ *Operator, b *inject.TEEEvidenceBundle) {
				b.EventLog = ""
			},
			want: FailureMeasurementMismatch,
		},
		{
			// The zero-extend guard: a log whose events are all
			// non-runtime replays to 48 zero bytes, which compares
			// equal to an unmeasured RTMR3.
			name: "event log extends nothing",
			mut: func(_ *BundleVerifier, _ *Operator, b *inject.TEEEvidenceBundle) {
				b.EventLog = `[{"imr":0,"event_type":2147483649,"digest":"","event":"boot","event_payload":"aabb"}]`
			},
			want: FailureMeasurementMismatch,
		},
		{
			name: "cpu_report is not base64",
			mut: func(_ *BundleVerifier, _ *Operator, b *inject.TEEEvidenceBundle) {
				b.CPUReport = "!!!not base64!!!"
			},
			want: FailureVendorChainInvalid,
		},
		{
			// Platform comes from the BYTES. A quote that is not TDX v4
			// must not be judged against the TDX chain just because the
			// node called itself dstack-tdx.
			name: "report is not a TDX quote",
			mut: func(_ *BundleVerifier, _ *Operator, b *inject.TEEEvidenceBundle) {
				raw, _ := base64.StdEncoding.DecodeString(b.CPUReport)
				raw[4] = 0x00 // tee_type: SGX rather than TDX
				b.CPUReport = base64.StdEncoding.EncodeToString(raw)
			},
			want: FailureVendorChainInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, op, bundle := dstackFixture(t)
			tc.mut(v, &op, &bundle)

			verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
			if verdict.Pass {
				t.Fatalf("verdict passed; want %q", tc.want)
			}
			if verdict.FailureTag != tc.want {
				t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, tc.want)
			}
			if verdict.AttestedModelIDs != nil {
				t.Errorf("AttestedModelIDs = %v on a refusal", verdict.AttestedModelIDs)
			}
			// The VerifierID must survive the failure paths, not just
			// the success one. It is the diagnosis channel these two
			// new failure tags were split apart to serve, so a dstack
			// failure surfacing on the dashboard as "builtin" defeats
			// the reason for splitting them.
			if verdict.VerifierID != VerifierIDDstack {
				t.Errorf("VerifierID = %q, want %q on a dstack failure",
					verdict.VerifierID, VerifierIDDstack)
			}
		})
	}
}

// DstackVerifier is exported and its godoc states that op supplies the
// independently-verified ephemeral the binding must be to — but nothing
// held it there. Calling it DIRECTLY is the point: reached through
// BundleVerifier, an earlier check has already forced
// bundle.NodePubkey == op.EphemeralRecipientPubkey, so the two are
// interchangeable and a mutation swapping them is invisible.
//
// The failure this pins: anyone constructing DstackVerifier on its own,
// or reordering the bundle-level equality check, silently moves the
// binding target to a field the operator authors.
func TestDstackVerifier_BindsToTheVerifiedEphemeralNotTheSelfReport(t *testing.T) {
	bv, op, bundle := dstackFixture(t)
	dv := &DstackVerifier{
		TrustedComposeHashes: bv.TrustedComposeHashes,
		TrustedOSImages:      bv.TrustedOSImages,
		VerifyChain:          bv.VerifyChain,
	}

	// Sanity: the fixture verifies when the two agree, so a failure
	// below is the substitution and not a broken fixture.
	if tag := dv.Verify(context.Background(), bundle, op); tag != "" {
		t.Fatalf("baseline failed with %q", tag)
	}

	// Move ONLY the verified ephemeral, leaving the bundle's self-report
	// as the captured key. The direction matters: a verifier hashing
	// bundle.NodePubkey still matches the quote here and PASSES, while
	// one hashing the key the proxy would actually seal to does not.
	// (Moving bundle.NodePubkey instead proves nothing — the correct
	// code never reads it, so the result is unchanged either way.)
	moved := op
	moved.EphemeralRecipientPubkey = "age1differentkey000000000000000000000000000000000000"
	if bundle.NodePubkey != capturedKey {
		t.Fatal("fixture drift: the self-report must stay the captured key for this to discriminate")
	}
	if tag := dv.Verify(context.Background(), bundle, moved); tag != FailureKeyBindingMismatch {
		t.Errorf("tag = %q, want %q — the binding is being taken from the bundle's self-report "+
			"rather than the independently-verified ephemeral", tag, FailureKeyBindingMismatch)
	}

	// THE SECOND INPUT TO THE SAME HASH, which has the identical
	// hazard and was unpinned. report_data is
	// SHA-256(ephemeral || be64(operator_id)), so an operator-authored
	// id is exactly as bad as an operator-authored key — and reached
	// through BundleVerifier the two are pre-forced equal, so a mutation
	// swapping them is invisible there for the same reason.
	idMoved := op
	idMoved.ID = 43
	if bundle.OperatorID != capturedOperatorID {
		t.Fatal("fixture drift: the bundle's self-reported id must stay the captured one")
	}
	if tag := dv.Verify(context.Background(), bundle, idMoved); tag != FailureKeyBindingMismatch {
		t.Errorf("tag = %q, want %q — the operator id in the binding is being taken from "+
			"the bundle rather than the chain-resolved operator", tag, FailureKeyBindingMismatch)
	}
}

// The hardware field is 64 bytes and the binding hash is 32. Checking
// only the low half leaves the high half a free "get Intel to sign 32
// attacker-chosen bytes" oracle riding alongside legitimate evidence,
// because the signature covers the whole field.
func TestDstackVerifier_ChecksBothHalvesOfReportData(t *testing.T) {
	// Pins the VerifyAux call: flipping any byte of [32:64] must refuse
	// with aux_binding_mismatch. SplitReportData accepts any non-zero upper
	// half, so without the call these bytes would be the node's choice,
	// signed by real hardware. Every byte, because a comparison over a
	// prefix would pass the rest.
	t.Run("attacker bytes anywhere in the upper half are refused", func(t *testing.T) {
		for i := 32; i < 64; i++ {
			v, op, bundle := dstackFixture(t)
			raw, err := base64.StdEncoding.DecodeString(bundle.CPUReport)
			if err != nil {
				t.Fatal(err)
			}
			// XOR so the byte always changes, whatever the real aux
			// binding happens to hold at this offset.
			raw[quoteReportDataOffset+i] ^= 0xff
			bundle.CPUReport = base64.StdEncoding.EncodeToString(raw)

			verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
			if verdict.Pass {
				t.Fatalf("byte %d: a quote with attacker bytes in the aux binding verified", i)
			}
			if verdict.FailureTag != FailureAuxBindingMismatch {
				t.Errorf("byte %d: FailureTag = %q, want %q",
					i, verdict.FailureTag, FailureAuxBindingMismatch)
			}
		}
	})

	// Pins the tag: a zero upper half must report aux_binding_absent, not
	// the aux_binding_mismatch the subtest above expects, because the fix
	// (upgrade the node) differs.
	t.Run("a pre-9.9 zero upper half is refused as such", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		raw, err := base64.StdEncoding.DecodeString(bundle.CPUReport)
		if err != nil {
			t.Fatal(err)
		}
		for i := 32; i < 64; i++ {
			raw[quoteReportDataOffset+i] = 0
		}
		bundle.CPUReport = base64.StdEncoding.EncodeToString(raw)

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("a pre-9.9 zero upper half verified")
		}
		if verdict.FailureTag != FailureAuxBindingAbsent {
			t.Errorf("FailureTag = %q, want %q — the remedy is upgrading the node, and "+
				"a binding-mismatch tag sends the operator after a key problem instead",
				verdict.FailureTag, FailureAuxBindingAbsent)
		}
	})

	t.Run("the signed binding is what is compared", func(t *testing.T) {
		// The bundle's own ReportData field is a self-report. Make it
		// AGREE with a substituted ephemeral so the earlier
		// base64-comparison check passes, and confirm the verifier still
		// refuses — because the bytes Intel signed bind the original
		// key. A verifier that trusted the self-report passes here.
		v, op, bundle := dstackFixture(t)
		other := "age1someotherrecipient00000000000000000000000000000"
		op.EphemeralRecipientPubkey = other
		bundle.NodePubkey = other
		bundle.ReportData = base64.StdEncoding.EncodeToString(computeReportData(other, capturedOperatorID))

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("evidence bound to a different key verified")
		}
		if verdict.FailureTag != FailureKeyBindingMismatch {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureKeyBindingMismatch)
		}
	})

	// The lower half is checked before the upper half's zero test. A
	// quote over the wrong key with a zero upper half is a key mismatch,
	// not an out-of-date node.
	t.Run("a wrong key is reported before a zero upper half", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		raw, err := base64.StdEncoding.DecodeString(bundle.CPUReport)
		if err != nil {
			t.Fatal(err)
		}
		for i := 32; i < 64; i++ {
			raw[quoteReportDataOffset+i] = 0
		}
		bundle.CPUReport = base64.StdEncoding.EncodeToString(raw)
		other := "age1someotherrecipient00000000000000000000000000000"
		op.EphemeralRecipientPubkey = other
		bundle.NodePubkey = other
		bundle.ReportData = base64.StdEncoding.EncodeToString(computeReportData(other, capturedOperatorID))

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.FailureTag != FailureKeyBindingMismatch {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureKeyBindingMismatch)
		}
	})
}

// TestDstackVerifier_AuxFailureTagsAreDistinct pins that the proxy reports
// the tag attest.AuxFailureTag chose, not a flattened mismatch. The
// decision itself is pinned by proto's aux_verify vectors; this checks the
// proxy passes it through.
func TestDstackVerifier_AuxFailureTagsAreDistinct(t *testing.T) {
	t.Run("a catalog the node did not publish is not ordinary disagreement", func(t *testing.T) {
		// The quote commits to the three-model catalog; the bundle
		// publishes none of it.
		v, op, bundle := dstackFixture(t)
		bundle.AppModels = nil

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("a node that published none of the catalog it attested verified")
		}
		if verdict.FailureTag != FailureHAppPreimageMissing {
			t.Errorf("FailureTag = %q, want %q — an operator told %q looks for a catalog "+
				"that disagrees, when the real fault is a catalog that is absent",
				verdict.FailureTag, FailureHAppPreimageMissing, FailureAuxBindingMismatch)
		}
	})

	t.Run("a catalog that cannot be hashed is not disagreement either", func(t *testing.T) {
		// A duplicate model id: HApp refuses the list, so nothing was
		// compared.
		v, op, bundle := dstackFixture(t)
		dup := capturedModels()
		dup[1].ModelID = dup[0].ModelID
		bundle.AppModels = dup

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("a bundle whose model list cannot be hashed verified")
		}
		if verdict.FailureTag != FailureHAppPreimageInvalid {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureHAppPreimageInvalid)
		}
	})

	t.Run("a malformed entry from the wire is invalid, not a mismatch", func(t *testing.T) {
		// Decoded from JSON the way the fetcher decodes a bundle.
		// weights_digest's KEY is absent, so the strict decoder marks the
		// entry malformed (the state/digest rule needs the key present and
		// empty).
		v, op, bundle := dstackFixture(t)
		var entries []inject.ModelEntry
		if err := json.Unmarshal([]byte(`[{"model_id":"qwen3-30b","source":"hf/Qwen/Qwen3-30B","weights_state":1}]`), &entries); err != nil {
			t.Fatal(err)
		}
		bundle.AppModels = entries

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("an entry missing its weights_digest key verified")
		}
		if verdict.FailureTag != FailureHAppPreimageInvalid {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureHAppPreimageInvalid)
		}
	})
}

// stubVerifier hands probeAttestation a fixed verdict, so the test is about the
// plumbing between the verdict and TEEStatus rather than about verification.
type stubVerifier struct{ v Verdict }

func (s stubVerifier) Verify(context.Context, inject.TEEAdvertisement, inject.TEEEvidenceBundle, Operator) Verdict {
	return s.v
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestBundleVerifier_CarriesTheVerifiedCatalog pins that the verified catalog
// reaches callers, and only on a pass: on a refusal the published list is
// unverified and must not appear.
func TestBundleVerifier_CarriesTheVerifiedCatalog(t *testing.T) {
	t.Run("a pass carries the ids the hardware vouched for", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if !verdict.Pass {
			t.Fatalf("verdict = %+v, want Pass", verdict)
		}
		want := []string{"qwen3-30b", "glm-4.6", "grok-4"}
		if !slices.Equal(verdict.AttestedModelIDs, want) {
			t.Errorf("AttestedModelIDs = %v, want %v", verdict.AttestedModelIDs, want)
		}
	})

	t.Run("an empty verified set is non-nil, because it is a claim", func(t *testing.T) {
		// A node attesting an empty catalog made a checkable claim. Nil would
		// read as "no verified list", i.e. unknown, which loses it.
		v, op, bundle := dstackFixture(t)
		quote, _ := loadDstackVectors(t)
		bundle.CPUReport = base64.StdEncoding.EncodeToString(
			withAuxBinding(t, quote, capturedNodeID, nil, fixturePosture(), nil))
		// NIL, not []ModelEntry{} — that is what a real node's empty catalog
		// decodes to. AppModels is `omitempty`, so an empty slice marshals to no
		// key at all and comes back nil. Testing the in-process `[]` shape would
		// pin an input production cannot produce.
		bundle.AppModels = nil

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if !verdict.Pass {
			t.Fatalf("a node attesting an empty catalog was refused: %+v", verdict)
		}
		if verdict.AttestedModelIDs == nil {
			t.Error("AttestedModelIDs is nil on a passing empty-catalog verdict; nil means " +
				"NO verified list, and this node verifiably attested zero models")
		}
		if len(verdict.AttestedModelIDs) != 0 {
			t.Errorf("AttestedModelIDs = %v, want empty", verdict.AttestedModelIDs)
		}
	})

	t.Run("a refusal carries nothing, whatever the node published", func(t *testing.T) {
		// A well-formed list that simply is not the one the hardware signed.
		v, op, bundle := dstackFixture(t)
		other := capturedModels()
		other[0].ModelID = "something-else"
		bundle.AppModels = other

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass {
			t.Fatal("a mismatched catalog verified")
		}
		if verdict.AttestedModelIDs != nil {
			t.Errorf("a refused verdict carries AttestedModelIDs = %v; an unverified claim "+
				"on a refusal is indistinguishable from a verified one", verdict.AttestedModelIDs)
		}
	})

	// A stub bundle has no quote, so no aux binding was checked. Ids here
	// would be the node's own claim presented as verified.
	t.Run("a passing STUB verdict carries no ids", func(t *testing.T) {
		v := &BundleVerifier{AllowStub: true}
		op := Operator{ID: capturedOperatorID, NodeID: capturedNodeID, EphemeralRecipientPubkey: capturedKey}
		bundle := inject.TEEEvidenceBundle{
			Mode:       inject.TEEModeStub,
			Stub:       true,
			NodePubkey: capturedKey,
			OperatorID: capturedOperatorID,
			ReportData: base64.StdEncoding.EncodeToString(computeReportData(capturedKey, capturedOperatorID)),
			// A well-formed list, which is the point: nothing about its shape
			// is wrong, only that nothing checked it.
			AppModels:      capturedModels(),
			GeneratedAt:    time.Now().UTC(),
			RefreshSeconds: 1200,
		}

		verdict := v.Verify(context.Background(), inject.TEEAdvertisement{Mode: inject.TEEModeStub}, bundle, op)
		if !verdict.Pass {
			t.Fatalf("stub bundle refused under AllowStub: %+v", verdict)
		}
		if verdict.AttestedModelIDs != nil {
			t.Errorf("a stub verdict carries AttestedModelIDs = %v; no aux binding was "+
				"checked, so these are the node's own claim presented as verified",
				verdict.AttestedModelIDs)
		}
	})

	// Pins the line in probeAttestation that copies the verified list onto
	// TEEStatus. Every other test builds a TEEStatus literal by hand, so
	// nulling that line leaves them green.
	t.Run("the verified ids survive the hand-off to TEEStatus", func(t *testing.T) {
		node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", inject.AttestationContentType)
			_ = json.NewEncoder(w).Encode(inject.TEEEvidenceBundle{Mode: inject.TEEModeDstackTDX})
		}))
		defer node.Close()

		src := &ChainOperatorSource{TEEVerifier: stubVerifier{Verdict{
			Pass:             true,
			VerifierID:       VerifierIDDstack,
			AttestedModelIDs: []string{"qwen3-30b"},
		}}}
		op := &Operator{ID: capturedOperatorID, NodeID: capturedNodeID, BaseURL: node.URL}
		details := inject.OperatorDetails{TEE: &inject.TEEAdvertisement{
			Mode: inject.TEEModeDstackTDX, EvidenceURL: "/v1/zs/attestation",
		}}

		src.probeAttestation(context.Background(), op, details,
			NewAttestationClient(nil, 0), nil, quietLogger())

		if op.TEE == nil {
			t.Fatal("probeAttestation left op.TEE nil on a passing verdict")
		}
		if !slices.Equal(op.TEE.AttestedModelIDs, []string{"qwen3-30b"}) {
			t.Errorf("the verified model list did not reach TEEStatus: %+v", op.TEE.AttestedModelIDs)
		}
	})
}

// TestDstackVerifier_AuxNonce covers bundles that carry a nonce. This proxy
// sends no challenge, but a bundle minted for another caller's ?nonce= can
// still reach it, and must verify.
func TestDstackVerifier_AuxNonce(t *testing.T) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1) // non-zero: all-zero hashes the same as absent
	}

	t.Run("an echoed nonce is fed into the comparison", func(t *testing.T) {
		// The quote commits with the nonce, so a verifier that hashed 32
		// zero bytes instead would refuse it.
		v, op, bundle := dstackFixture(t)
		quote, _ := loadDstackVectors(t)
		bundle.CPUReport = base64.StdEncoding.EncodeToString(
			withAuxBinding(t, quote, capturedNodeID, capturedModels(), fixturePosture(), &nonce))
		bundle.Nonce = hex.EncodeToString(nonce[:])

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if !verdict.Pass {
			t.Fatalf("a correctly nonced bundle was refused: %+v", verdict)
		}
	})

	t.Run("a malformed nonce is refused, never downgraded to unnonced", func(t *testing.T) {
		// The fixture's quote is bound with no nonce, so treating an
		// unparseable nonce as absent would make this bundle verify.
		for _, bad := range []string{
			"zz",                           // not hex
			hex.EncodeToString(nonce[:16]), // hex, wrong length
			hex.EncodeToString(nonce[:]) + "00",
		} {
			v, op, bundle := dstackFixture(t)
			bundle.Nonce = bad

			verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
			if verdict.Pass {
				t.Fatalf("nonce %q: an unparseable challenge was treated as no challenge", bad)
			}
			if verdict.FailureTag != FailureAuxBindingMismatch {
				t.Errorf("nonce %q: FailureTag = %q, want %q", bad, verdict.FailureTag, FailureAuxBindingMismatch)
			}
		}
	})
}

// Each case's quote is re-minted over its own posture, so the aux binding
// verifies and what is under test is step 7's judgement of a BOUND posture —
// i.e. what a genuine measured binary could have signed.
func TestDstackVerifier_Posture(t *testing.T) {
	named := func(url string, zr bool) *inject.TEEPosture {
		return &inject.TEEPosture{PlaintextTerminates: inject.PlaintextNamedUpstream, UpstreamBaseURL: url, ZeroRetention: zr}
	}
	gateway := func() *inject.TEEPosture {
		p := named("https://gateway.example/v1", false)
		p.UpstreamAttested = true
		return p
	}
	cases := []struct {
		name     string
		posture  *inject.TEEPosture
		attested bool // bundle carries an upstream_attestation block
		// attestation is that block; nil means a well-formed aci/1 one.
		attestation *inject.UpstreamAttestation
		wantTag     string // "" means it must pass
	}{
		{
			// Absent is a node making no claim, which is honest and
			// must pass — the measurement is the authority regardless.
			name: "absent",
		},
		{
			name:    "in_enclave",
			posture: &inject.TEEPosture{PlaintextTerminates: inject.PlaintextInEnclave},
		},
		{
			name:    "named_upstream xAI with zero retention",
			posture: named("https://api.x.ai/v1", true),
		},
		{
			// "Readable by exactly one party" is a claim about a party
			// the payer can identify. Declining to name one is not
			// making the claim.
			name:    "named_upstream naming nobody",
			posture: &inject.TEEPosture{PlaintextTerminates: inject.PlaintextNamedUpstream},
			wantTag: FailureAdvertisementMismatch,
		},
		{
			name: "in_enclave naming an upstream is self-contradictory",
			posture: &inject.TEEPosture{
				PlaintextTerminates: inject.PlaintextInEnclave,
				UpstreamBaseURL:     "https://api.x.ai/v1",
			},
			wantTag: FailureAdvertisementMismatch,
		},
		{
			// The block is unbound, so a relay can add it: it must never be
			// what refuses an honest in_enclave node.
			name:     "in_enclave with a relay-added upstream_attestation block",
			posture:  &inject.TEEPosture{PlaintextTerminates: inject.PlaintextInEnclave},
			attested: true,
		},
		{
			name: "in_enclave claiming an attested upstream is self-contradictory",
			posture: &inject.TEEPosture{
				PlaintextTerminates: inject.PlaintextInEnclave,
				UpstreamAttested:    true,
			},
			wantTag: FailureAdvertisementMismatch,
		},
		{
			// Unknown must never be read as the stronger of the two.
			name:    "unrecognized value",
			posture: &inject.TEEPosture{PlaintextTerminates: "in_enclave_probably"},
			wantTag: FailureAdvertisementMismatch,
		},
		// The lookalike attack, as a binary that classified by substring
		// would have signed it. The binding verifies — it proves only what
		// the binary derived — so step 7 is what must refuse.
		{
			name:    "lookalike host signed as xAI",
			posture: named("https://api.x.ai.attacker.example/v1", true),
			wantTag: FailurePostureUpstreamUnverifiable,
		},
		{
			name:    "userinfo lookalike",
			posture: named("https://api.x.ai@attacker.example/v1", true),
			wantTag: FailurePostureUpstreamUnverifiable,
		},
		{
			name:    "xAI over plain http",
			posture: named("http://api.x.ai/v1", true),
			wantTag: FailurePostureUpstreamUnverifiable,
		},
		{
			name:    "xAI without zero-retention enforcement",
			posture: named("https://api.x.ai/v1", false),
			wantTag: FailurePostureUpstreamUnverifiable,
		},
		{
			name:     "ACI gateway with an upstream attestation",
			posture:  gateway(),
			attested: true,
		},
		{
			// The node drops the block while its appraisal has lapsed.
			name:    "ACI gateway without one",
			posture: gateway(),
			wantTag: FailurePostureUpstreamUnverifiable,
		},
		{
			// The block is unsigned; the bound bit is what a relay cannot add.
			name:     "block injected for a node that never signed upstream_attested",
			posture:  named("https://gateway.example/v1", false),
			attested: true,
			wantTag:  FailurePostureUpstreamUnverifiable,
		},
		{
			name:        "ACI gateway with an empty block",
			posture:     gateway(),
			attested:    true,
			attestation: &inject.UpstreamAttestation{},
			wantTag:     FailurePostureUpstreamUnverifiable,
		},
		{
			name:        "ACI gateway with an unknown protocol",
			posture:     gateway(),
			attested:    true,
			attestation: &inject.UpstreamAttestation{Protocol: "aci/2"},
			wantTag:     FailurePostureUpstreamUnverifiable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, op, bundle := dstackFixture(t)
			quote, _ := loadDstackVectors(t)
			bundle.CPUReport = base64.StdEncoding.EncodeToString(
				withAuxBinding(t, quote, capturedNodeID, capturedModels(), tc.posture, nil))
			bundle.Posture = tc.posture
			if tc.attested {
				bundle.UpstreamAttestation = tc.attestation
				if bundle.UpstreamAttestation == nil {
					bundle.UpstreamAttestation = &inject.UpstreamAttestation{Protocol: inject.UpstreamProtocolACI1}
				}
			}

			verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
			if want := tc.wantTag == ""; verdict.Pass != want {
				t.Fatalf("Pass = %v (tag %q), want %v", verdict.Pass, verdict.FailureTag, want)
			}
			if verdict.FailureTag != tc.wantTag {
				t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, tc.wantTag)
			}
		})
	}
}

// The posture cases compare the verdict against the proxy's own constants, so
// a changed value moves both sides together. client/ reports these exact
// strings for the same bytes; pin them as literals.
func TestDstackVerifier_PostureTagSpellings(t *testing.T) {
	for got, want := range map[string]string{
		FailurePostureUpstreamUnverifiable: "posture_upstream_unverifiable",
		FailurePosturePreimageInvalid:      "posture_preimage_invalid",
	} {
		if got != want {
			t.Errorf("tag %q, want %q", got, want)
		}
	}
}

// Before 9.10 anything on the path could rewrite the posture a verifier
// judged. Now the quote commits to it: an honest node's bundle whose
// upstream is rewritten in transit, or whose posture is stripped, fails the
// aux binding before step 7 ever sees it.
func TestDstackVerifier_PostureIsBound(t *testing.T) {
	for name, mutate := range map[string]func(*inject.TEEEvidenceBundle){
		"upstream rewritten": func(b *inject.TEEEvidenceBundle) {
			b.Posture.UpstreamBaseURL = "https://api.x.ai.attacker.example/v1"
		},
		"zero_retention flipped": func(b *inject.TEEEvidenceBundle) { b.Posture.ZeroRetention = false },
		"posture stripped":       func(b *inject.TEEEvidenceBundle) { b.Posture = nil },
	} {
		t.Run(name, func(t *testing.T) {
			v, op, bundle := dstackFixture(t)
			mutate(&bundle)
			verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
			if verdict.Pass || verdict.FailureTag != FailureAuxBindingMismatch {
				t.Errorf("verdict = pass %v tag %q, want %q", verdict.Pass, verdict.FailureTag, FailureAuxBindingMismatch)
			}
		})
	}

	// The reverse direction: a node that published no posture committed to
	// that absence, so a relay cannot add a flattering one.
	t.Run("posture added", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		quote, _ := loadDstackVectors(t)
		bundle.CPUReport = base64.StdEncoding.EncodeToString(
			withAuxBinding(t, quote, capturedNodeID, capturedModels(), nil, nil))
		bundle.Posture = fixturePosture()
		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass || verdict.FailureTag != FailureAuxBindingMismatch {
			t.Errorf("verdict = pass %v tag %q, want %q", verdict.Pass, verdict.FailureTag, FailureAuxBindingMismatch)
		}
	})

	// A wrongly typed posture decodes to a marked one rather than failing the
	// fetch, so the payer sees the tag client/ reports for the same bytes.
	t.Run("posture wrongly typed", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		var decoded inject.TEEEvidenceBundle
		if err := json.Unmarshal([]byte(`{"posture":{"zero_retention":"yes"}}`), &decoded); err != nil {
			t.Fatal(err)
		}
		bundle.Posture = decoded.Posture
		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.Pass || verdict.FailureTag != FailurePosturePreimageInvalid {
			t.Errorf("verdict = pass %v tag %q, want %q", verdict.Pass, verdict.FailureTag, FailurePosturePreimageInvalid)
		}
	})
}

// The dstack branch must be reached only through the earlier checks.
// A bundle that fails advertisement or staleness must never get as far
// as measurement verification, because those checks establish the
// operator identity the binding is compared against.
func TestDstackVerifier_EarlierChecksStillApply(t *testing.T) {
	t.Run("advertisement mismatch", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		adv := dstackAdvertisement()
		adv.Mode = inject.TEEModeStub

		verdict := v.Verify(context.Background(), adv, bundle, op)
		if verdict.FailureTag != FailureAdvertisementMismatch {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureAdvertisementMismatch)
		}
	})

	t.Run("stale evidence", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		bundle.GeneratedAt = time.Now().Add(-3 * time.Hour)

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.FailureTag != FailureStaleEvidence {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureStaleEvidence)
		}
	})

	t.Run("no verified ephemeral", func(t *testing.T) {
		v, op, bundle := dstackFixture(t)
		op.EphemeralRecipientPubkey = ""

		verdict := v.Verify(context.Background(), dstackAdvertisement(), bundle, op)
		if verdict.FailureTag != FailureKeyBindingMismatch {
			t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureKeyBindingMismatch)
		}
	})
}

// The nvidia modes must keep their placeholder verdict rather than
// falling into the dstack branch — those bundles carry no event log,
// so a shared branch would report measurement_mismatch and tell an
// operator to fix an allowlist that is not their problem.
func TestBundleVerifier_NvidiaStillNotImplemented(t *testing.T) {
	v, op, bundle := dstackFixture(t)
	bundle.Mode = inject.TEEModeNvidiaCCTDX
	adv := dstackAdvertisement()
	adv.Mode = inject.TEEModeNvidiaCCTDX

	verdict := v.Verify(context.Background(), adv, bundle, op)
	if verdict.FailureTag != FailureVerifierNotImpl {
		t.Errorf("FailureTag = %q, want %q", verdict.FailureTag, FailureVerifierNotImpl)
	}
}

// quoteReportDataOffset is the absolute offset of the 64-byte
// REPORTDATA field in a TDX v4 quote — the 48-byte header plus the
// body offset. Declared here rather than exported from attest, since
// only a test that tampers with a quote needs it.
const quoteReportDataOffset = 48 + 520

func TestQuoteReportDataOffsetMatchesAttest(t *testing.T) {
	// Pins the local constant against the package that actually parses
	// quotes. Without this, a tamper test could be poking at a byte
	// outside report_data entirely and still "pass" for the wrong
	// reason.
	quote, _ := loadDstackVectors(t)
	rd, ok := attest.QuoteReportData(quote)
	if !ok {
		t.Fatal("QuoteReportData failed on the captured quote")
	}
	if string(quote[quoteReportDataOffset:quoteReportDataOffset+len(rd)]) != string(rd) {
		t.Error("quoteReportDataOffset does not point at the field attest reads")
	}
}
