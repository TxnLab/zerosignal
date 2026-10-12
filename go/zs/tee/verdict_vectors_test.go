/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

// Generates / verifies proto/testdata/tee_verdict_vectors.json: an evidence
// bundle as a node serves it, the verifier's configuration and the chain
// step's outcome in, the verdict out. sdk/test/tee-verdict-vectors.test.ts
// replays every case through the TypeScript BundleVerifier, so the two
// verifiers are held to one verdict rather than to two suites that each
// agree with themselves.
//
//	cd proto/go && go test ./zs/tee -run TestVerdictVectors -update
//
// The chain step is stubbed on both sides, as in dstack_test.go, so these
// cases pin every step around it and say nothing about whether a forged quote
// is refused. The quotes are the real capture with report_data (and, for the
// measured release, RTMR3) spliced, which only a stubbed chain lets through.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/pcs"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/inject"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/tee_verdict_vectors.json")

const (
	verdictVectorsPath    = "../../../testdata/tee_verdict_vectors.json"
	collateralVectorsPath = "../../../testdata/collateral_vectors.json"
)

type verdictVectorsFile struct {
	Version   int               `json:"version"`
	Comment   string            `json:"comment"`
	Constants verdictConstants  `json:"constants"`
	Quotes    map[string]string `json:"quotes"`
	EventLogs map[string]string `json:"event_logs"`
	Cases     []verdictCase     `json:"cases"`
}

type verdictConstants struct {
	EvidenceMaxAgeCeilingMs    int64             `json:"evidence_max_age_ceiling_ms"`
	EmbeddedCollateralMaxAgeMs int64             `json:"embedded_collateral_max_age_ms"`
	AcceptedTCBStatus          string            `json:"accepted_tcb_status"`
	FailureTags                map[string]string `json:"failure_tags"`
	VerifierIDs                map[string]string `json:"verifier_ids"`
}

// verdictCase is one verification. Bundle is the node's JSON minus the three
// fields a replay supplies. cpu_report and event_log name entries in Quotes
// and EventLogs, so 6 KB of capture is not repeated per case; a literal
// cpu_report carries a value that is not a quote at all. generated_at is
// dated by each side against its own clock: Go's BundleVerifier reads the
// real one, the TypeScript verifier takes now_unix_ms. A nil offset means
// the bundle carries no generated_at.
type verdictCase struct {
	Name                string         `json:"name"`
	Advertisement       map[string]any `json:"advertisement"`
	Bundle              map[string]any `json:"bundle"`
	CPUReportQuote      string         `json:"cpu_report_quote,omitempty"`
	CPUReport           *string        `json:"cpu_report,omitempty"`
	EventLog            string         `json:"event_log,omitempty"`
	GeneratedAtOffsetMs *int64         `json:"generated_at_offset_ms"`
	Node                verdictNode    `json:"node"`
	Policy              verdictPolicy  `json:"policy"`
	AllowStub           bool           `json:"allow_stub"`
	Chain               string         `json:"chain"`
	Carried             string         `json:"carried"`
	Collateral          string         `json:"collateral"`
	NowUnixMs           int64          `json:"now_unix_ms"`
	Expect              verdictExpect  `json:"expect"`
}

// Decimal strings, because the ids are uint64 and a JSON number past 2^53
// would reach TypeScript rounded.
type verdictNode struct {
	OperatorID               string `json:"operator_id"`
	NodeID                   string `json:"node_id"`
	EphemeralRecipientPubkey string `json:"ephemeral_recipient_pubkey"`
}

// ComposePolicy is a NAME each side maps to its own constructor, so the
// vector pins that the two build the same policy rather than restating
// either. "none" is the zero policy and "shape_only" the shared rules without
// the release match. "shipped" is Go's DefaultComposePolicy, which TypeScript
// builds inline from zeroSignalComposePolicy and the generated trust lists:
// what it pins is that the release match is on, while the list contents are
// pinned by the trust-list generator test. "release" is the shared rules
// enforcing the two lists carried here.
type verdictPolicy struct {
	TrustedOSImages         []string `json:"trusted_os_images"`
	TrustedComposeHashes    []string `json:"trusted_compose_hashes"`
	ComposePolicy           string   `json:"compose_policy"`
	TrustedComposeSkeletons []string `json:"trusted_compose_skeletons,omitempty"`
	TrustedNodeImages       []string `json:"trusted_node_images,omitempty"`
}

// AttestedModelIDs is null for no verified list and [] for a verified empty
// one; the two must not collapse. A null FailureTag means "refused, tag not
// asserted": SPEC §3e step 2 leaves the tag for an absent generated_at to the
// implementation, so a replay checks only that some tag refused.
type verdictExpect struct {
	Pass             bool     `json:"pass"`
	FailureTag       *string  `json:"failure_tag"`
	VerifierID       string   `json:"verifier_id"`
	AttestedModelIDs []string `json:"attested_model_ids"`
	CarriedCalled    bool     `json:"carried_called"`
	// MeasurementChecks is null on a refusal and on a stub pass. Routing
	// reads it, so the two verifiers must agree on it as on the pass itself.
	MeasurementChecks *verdictChecks `json:"measurement_checks"`
	// UpstreamCarveOuts is absent unless the verdict reports some.
	UpstreamCarveOuts []string `json:"upstream_carve_outs,omitempty"`
}

type verdictChecks struct {
	OSImage        bool `json:"os_image"`
	ComposeRelease bool `json:"compose_release"`
	ComposeHash    bool `json:"compose_hash"`
}

// verdictFailureTags maps the TypeScript FailureTag key to the Go constant.
// The Go names are listed too so TestVerdictVectors can check them against
// the package source: a tag added here without a vector entry fails there.
var verdictFailureTags = []struct{ goName, tsKey, value string }{
	{"FailureKeyBindingMismatch", "KeyBindingMismatch", FailureKeyBindingMismatch},
	{"FailureStubNotAllowed", "StubNotAllowed", FailureStubNotAllowed},
	{"FailureVerifierNotImpl", "VerifierNotImplemented", FailureVerifierNotImpl},
	{"FailureVendorChainInvalid", "VendorChainInvalid", FailureVendorChainInvalid},
	{"FailureNRASUnreachable", "NRASUnreachable", FailureNRASUnreachable},
	{"FailureAdvertisementMismatch", "AdvertisementMismatch", FailureAdvertisementMismatch},
	{"FailureFetchFailed", "FetchFailed", FailureFetchFailed},
	{"FailureStaleEvidence", "StaleEvidence", FailureStaleEvidence},
	{"FailureEphemeralUnavailable", "EphemeralUnavailable", FailureEphemeralUnavailable},
	{"FailureMeasurementMismatch", "MeasurementMismatch", FailureMeasurementMismatch},
	{"FailureCollateralUnreachable", "CollateralUnreachable", FailureCollateralUnreachable},
	{"FailureAuxBindingAbsent", "AuxBindingAbsent", FailureAuxBindingAbsent},
	{"FailureAuxBindingMismatch", "AuxBindingMismatch", FailureAuxBindingMismatch},
	{"FailureHAppPreimageMissing", "HAppPreimageMissing", FailureHAppPreimageMissing},
	{"FailureHAppPreimageInvalid", "HAppPreimageInvalid", FailureHAppPreimageInvalid},
	{"FailurePosturePreimageInvalid", "PosturePreimageInvalid", FailurePosturePreimageInvalid},
	{"FailurePostureUpstreamUnverifiable", "PostureUpstreamUnverifiable", FailurePostureUpstreamUnverifiable},
}

// verdictUnreachableTags are tags BundleVerifier never returns: the fetcher
// owns fetch_failed and ephemeral_unavailable, and nras_unreachable waits on
// an NVIDIA verifier. They are pinned as constants only.
var verdictUnreachableTags = []string{FailureFetchFailed, FailureEphemeralUnavailable, FailureNRASUnreachable}

const (
	verdictOtherKey      = "age1someoneelse000000000000000000000000000000000000000"
	verdictGatewayURL    = "https://gateway.example/v1"
	verdictStaleSkewDays = 1
)

var verdictReleaseImage = "ghcr.io/txnlab/zs-node@sha256:" + strings.Repeat("ab", 32)

func TestVerdictVectors(t *testing.T) {
	f := buildVerdictVectors(t)
	got, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	checkFailureTagsMatchSource(t)

	// Replayed from the serialized bytes, so Go is checked against exactly
	// what TypeScript reads rather than against the structs that produced it.
	var parsed verdictVectorsFile
	dec := json.NewDecoder(bytes.NewReader(got))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		t.Fatalf("decode generated vectors: %v", err)
	}
	checkVerdictCoverage(t, parsed.Cases)
	for _, c := range parsed.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := replayVerdictCase(&parsed, c)
			if err != nil {
				t.Fatal(err)
			}
			if c.Expect.FailureTag == nil {
				if v.Pass || *v.FailureTag == "" {
					t.Fatalf("verdict = %+v, want a refusal with some tag", v)
				}
				v.FailureTag = nil
			}
			if !reflect.DeepEqual(v, c.Expect) {
				t.Errorf("verdict = %+v, want %+v", v, c.Expect)
			}
		})
	}
	if t.Failed() {
		return
	}

	if *updateVectors {
		if err := os.WriteFile(verdictVectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", verdictVectorsPath, err)
		}
		return
	}
	prev, err := os.ReadFile(verdictVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", verdictVectorsPath, err)
	}
	if !bytes.Equal(got, prev) {
		t.Fatalf("%s is stale; regenerate with:\n  cd proto/go && go test ./zs/tee -run TestVerdictVectors -update",
			verdictVectorsPath)
	}
}

// replayVerdictCase builds the bundle body, decodes it with the real decoder
// and runs BundleVerifier over it.
func replayVerdictCase(f *verdictVectorsFile, c verdictCase) (verdictExpect, error) {
	raw := maps.Clone(c.Bundle)
	switch {
	case c.CPUReportQuote != "":
		q, ok := f.Quotes[c.CPUReportQuote]
		if !ok {
			return verdictExpect{}, fmt.Errorf("no quote named %q", c.CPUReportQuote)
		}
		raw["cpu_report"] = q
	case c.CPUReport != nil:
		raw["cpu_report"] = *c.CPUReport
	}
	if c.EventLog != "" {
		l, ok := f.EventLogs[c.EventLog]
		if !ok {
			return verdictExpect{}, fmt.Errorf("no event log named %q", c.EventLog)
		}
		raw["event_log"] = l
	}
	if c.GeneratedAtOffsetMs != nil {
		at := time.Now().Add(time.Duration(*c.GeneratedAtOffsetMs) * time.Millisecond)
		raw["generated_at"] = at.UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return verdictExpect{}, err
	}
	var bundle inject.TEEEvidenceBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return verdictExpect{}, fmt.Errorf("the bundle does not decode, so it belongs in tee_bundle_vectors.json: %w", err)
	}
	advBody, err := json.Marshal(c.Advertisement)
	if err != nil {
		return verdictExpect{}, err
	}
	var adv inject.TEEAdvertisement
	if err := json.Unmarshal(advBody, &adv); err != nil {
		return verdictExpect{}, fmt.Errorf("advertisement: %w", err)
	}
	opID, err := strconv.ParseUint(c.Node.OperatorID, 10, 64)
	if err != nil {
		return verdictExpect{}, err
	}
	nodeID, err := strconv.ParseUint(c.Node.NodeID, 10, 64)
	if err != nil {
		return verdictExpect{}, err
	}
	policy, err := verdictComposePolicy(c.Policy)
	if err != nil {
		return verdictExpect{}, err
	}
	chainErr, err := verdictChainOutcome(c.Chain)
	if err != nil {
		return verdictExpect{}, err
	}
	carriedErr, err := verdictCarriedOutcome(c.Carried)
	if err != nil {
		return verdictExpect{}, err
	}

	now := time.UnixMilli(c.NowUnixMs)
	called := false
	v := &BundleVerifier{
		AllowStub:            c.AllowStub,
		TrustedComposeHashes: c.Policy.TrustedComposeHashes,
		TrustedOSImages:      c.Policy.TrustedOSImages,
		ComposePolicy:        policy,
		VerifyChain:          func(context.Context, []byte) error { return chainErr },
		// The stub replaces VerifyTDXQuoteChainCarried whole, guard included,
		// and that guard reads the real clock. So the stub re-applies it
		// against the case's clock, as the TypeScript verifier applies its
		// own guard before calling the host. Only the routing around the
		// guard is pinned here; its arithmetic is collateral_vectors.json's.
		// So on this side the absent, incomplete and stale cases exercise
		// this copy (Go's real guard is pinned by collateral_embedded_test.go),
		// while on the TypeScript side they pin the SDK's own guard.
		VerifyChainCarried: func(_ context.Context, _ []byte, coll *inject.TEECollateral) error {
			if !coll.Complete() || !attest.CollateralFreshEnough(coll, now, attest.EmbeddedCollateralMaxAge) {
				return ErrNoUsableCarriedCollateral
			}
			called = true
			return carriedErr
		},
		Log: slog.New(slog.DiscardHandler),
	}
	verdict := v.Verify(context.Background(), adv, bundle, Node{
		OperatorID:               opID,
		NodeID:                   nodeID,
		EphemeralRecipientPubkey: c.Node.EphemeralRecipientPubkey,
	})
	got := verdictExpect{
		Pass:              verdict.Pass,
		FailureTag:        &verdict.FailureTag,
		VerifierID:        verdict.VerifierID,
		AttestedModelIDs:  verdict.AttestedModelIDs,
		CarriedCalled:     called,
		UpstreamCarveOuts: verdict.UpstreamCarveOuts,
	}
	if c := verdict.MeasurementChecks; c != nil {
		got.MeasurementChecks = &verdictChecks{OSImage: c.OSImage, ComposeRelease: c.ComposeRelease, ComposeHash: c.ComposeHash}
	}
	return got, nil
}

func verdictComposePolicy(p verdictPolicy) (attest.ComposePolicy, error) {
	switch p.ComposePolicy {
	case "none":
		return attest.ComposePolicy{}, nil
	case "shape_only":
		pol := attest.ZeroSignalComposePolicy()
		pol.EnforceComposeSkeleton = false
		return pol, nil
	case "shipped":
		return DefaultComposePolicy(), nil
	case "release":
		pol := attest.ZeroSignalComposePolicy()
		pol.EnforceComposeSkeleton = true
		pol.TrustedComposeSkeletons = p.TrustedComposeSkeletons
		pol.TrustedNodeImages = p.TrustedNodeImages
		return pol, nil
	}
	return attest.ComposePolicy{}, fmt.Errorf("unknown compose policy %q", p.ComposePolicy)
}

// verdictChainOutcome maps a chain outcome onto what VerifyTDXQuoteChain
// returns. A status other than UpToDate is a plain error because go-tdx-guest
// refuses it inside the chain check; on our stale cache that refusal is
// ErrStaleCollateralRejected. The TypeScript chain verifier reports the status
// instead and its DstackVerifier reaches the same tag.
func verdictChainOutcome(s string) (error, error) {
	upToDate := string(pcs.TcbComponentStatusUpToDate)
	switch {
	case s == "ok":
		return nil, nil
	case s == "unavailable":
		return fmt.Errorf("%w: dial tcp: no route to host", ErrCollateralUnavailable), nil
	case s == "stale_rejected":
		return fmt.Errorf("%w: crl expired", ErrStaleCollateralRejected), nil
	case s == "invalid":
		return errors.New("tdx quote verification: signature mismatch"), nil
	case strings.HasPrefix(s, "tcb:"):
		if status := strings.TrimPrefix(s, "tcb:"); status != upToDate {
			return fmt.Errorf("tdx quote verification: TCB Status is not %q, found %q", upToDate, status), nil
		}
		return nil, nil
	case strings.HasPrefix(s, "stale_tcb:"):
		if status := strings.TrimPrefix(s, "stale_tcb:"); status != upToDate {
			return fmt.Errorf("%w: TCB Status is not %q, found %q", ErrStaleCollateralRejected, upToDate, status), nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unknown chain outcome %q", s)
}

func verdictCarriedOutcome(s string) (error, error) {
	upToDate := string(pcs.TcbComponentStatusUpToDate)
	switch {
	case s == "ok":
		return nil, nil
	case s == "invalid":
		return errors.New("tdx quote verification: chain does not root at Intel"), nil
	case strings.HasPrefix(s, "tcb:"):
		if status := strings.TrimPrefix(s, "tcb:"); status != upToDate {
			return fmt.Errorf("tdx quote verification: TCB Status is not %q, found %q", upToDate, status), nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unknown carried outcome %q", s)
}

// checkFailureTagsMatchSource fails when a Failure* constant in this package
// has no vector entry, which would leave TypeScript free to lack it.
func checkFailureTagsMatchSource(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				for _, id := range spec.(*ast.ValueSpec).Names {
					if strings.HasPrefix(id.Name, "Failure") {
						declared = append(declared, id.Name)
					}
				}
			}
		}
	}
	var listed []string
	for _, tag := range verdictFailureTags {
		listed = append(listed, tag.goName)
	}
	slices.Sort(declared)
	slices.Sort(listed)
	if !slices.Equal(declared, listed) {
		t.Fatalf("Failure* constants in the package = %v, verdictFailureTags = %v", declared, listed)
	}
}

// checkVerdictCoverage keeps the case list from rotting into a file that no
// longer reaches what its names claim.
func checkVerdictCoverage(t *testing.T, cases []verdictCase) {
	t.Helper()
	tags := map[string]bool{}
	ids := map[string]bool{}
	names := map[string]bool{}
	var called, notCalled bool
	// The three shapes of a pass routing tells apart: on a release, without
	// one, and with no checks at all.
	var releasePass, noReleasePass, uncheckedPass bool
	for _, c := range cases {
		if names[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		names[c.Name] = true
		switch m := c.Expect.MeasurementChecks; {
		case !c.Expect.Pass && m != nil:
			t.Errorf("%s: a refusal carries measurement checks", c.Name)
		case c.Expect.Pass && m == nil:
			uncheckedPass = true
		case c.Expect.Pass && m.ComposeRelease:
			releasePass = true
		case c.Expect.Pass:
			noReleasePass = true
		}
		if c.Expect.FailureTag != nil {
			tags[*c.Expect.FailureTag] = true
		}
		ids[c.Expect.VerifierID] = true
		if c.Expect.CarriedCalled {
			called = true
		} else if c.Chain == "unavailable" {
			notCalled = true
		}
	}
	for _, tag := range verdictFailureTags {
		if !tags[tag.value] && !slices.Contains(verdictUnreachableTags, tag.value) {
			t.Errorf("no case produces %s", tag.value)
		}
	}
	for _, id := range []string{VerifierIDBuiltin, VerifierIDDstack} {
		if !ids[id] {
			t.Errorf("no case produces verifier id %s", id)
		}
	}
	if !called || !notCalled {
		t.Errorf("the carried rung must be both reached and refused: called=%v notCalled=%v", called, notCalled)
	}
	if !releasePass || !noReleasePass || !uncheckedPass {
		t.Errorf("passes must cover a release match, no release match and no checks: %v %v %v",
			releasePass, noReleasePass, uncheckedPass)
	}
}

// verdictFixture holds the pieces cases are built from.
type verdictFixture struct {
	t          *testing.T
	quote      []byte
	eventLog   string
	quotes     map[string]string
	eventLogs  map[string]string
	collateral map[string]any
	issuedMs   int64
}

func buildVerdictVectors(t *testing.T) verdictVectorsFile {
	quote, eventLog := loadDstackVectors(t)
	fx := &verdictFixture{
		t: t, quote: quote, eventLog: eventLog,
		quotes:    map[string]string{},
		eventLogs: map[string]string{"captured": eventLog},
	}
	fx.loadCollateral()

	tags := map[string]string{}
	for _, tag := range verdictFailureTags {
		tags[tag.tsKey] = tag.value
	}
	return verdictVectorsFile{
		Version: 1,
		Comment: "Generated by proto/go/zs/tee/verdict_vectors_test.go. Do not hand-edit; " +
			"regenerate with `cd proto/go && go test ./zs/tee -run TestVerdictVectors -update`.",
		Constants: verdictConstants{
			EvidenceMaxAgeCeilingMs:    EvidenceMaxAgeCeiling.Milliseconds(),
			EmbeddedCollateralMaxAgeMs: attest.EmbeddedCollateralMaxAge.Milliseconds(),
			AcceptedTCBStatus:          string(pcs.TcbComponentStatusUpToDate),
			FailureTags:                tags,
			VerifierIDs:                map[string]string{"builtin": VerifierIDBuiltin, "dstack": VerifierIDDstack},
		},
		Cases:     fx.cases(),
		Quotes:    fx.quotes,
		EventLogs: fx.eventLogs,
	}
}

// loadCollateral reads the complete, dated set collateral_vectors.json pins as
// fresh at its own now, so the carried guard's inputs are ones both sides
// already agree on.
func (fx *verdictFixture) loadCollateral() {
	raw, err := os.ReadFile(collateralVectorsPath)
	if err != nil {
		fx.t.Fatalf("read %s: %v", collateralVectorsPath, err)
	}
	var file struct {
		CollateralFresh []struct {
			Name       string         `json:"name"`
			Collateral map[string]any `json:"collateral"`
			NowUnixMs  int64          `json:"now_unix_ms"`
			Fresh      bool           `json:"fresh"`
		} `json:"collateral_fresh"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		fx.t.Fatalf("parse %s: %v", collateralVectorsPath, err)
	}
	for _, c := range file.CollateralFresh {
		if c.Name == "all_now" && c.Fresh {
			fx.collateral = c.Collateral
			fx.issuedMs = c.NowUnixMs
			return
		}
	}
	fx.t.Fatalf("%s has no fresh all_now case", collateralVectorsPath)
}

// quoteNamed registers a quote and returns its name.
func (fx *verdictFixture) quoteNamed(name string, q []byte) string {
	fx.quotes[name] = base64.StdEncoding.EncodeToString(q)
	return name
}

// boundQuote is the capture with both report_data halves replaced: the key
// binding in the lower, the aux binding in the upper.
func (fx *verdictFixture) boundQuote(key string, nodeID uint64, models []inject.ModelEntry, posture *inject.TEEPosture, nonce *[32]byte) []byte {
	return spliceReportData(fx.quote, attest.ReportData(key, capturedOperatorID), fx.aux(nodeID, models, posture, nonce))
}

func (fx *verdictFixture) aux(nodeID uint64, models []inject.ModelEntry, posture *inject.TEEPosture, nonce *[32]byte) [32]byte {
	hApp, err := attest.HApp(models)
	if err != nil {
		fx.t.Fatalf("HApp: %v", err)
	}
	hPosture, err := attest.HPosture(posture)
	if err != nil {
		fx.t.Fatalf("HPosture: %v", err)
	}
	return attest.AuxBinding(nodeID, hApp, hPosture, nonce)
}

func spliceReportData(quote, lower []byte, upper [32]byte) []byte {
	out := bytes.Clone(quote)
	copy(out[quoteReportDataOffset:quoteReportDataOffset+32], lower)
	copy(out[quoteReportDataOffset+32:quoteReportDataOffset+64], upper[:])
	return out
}

// measuredRelease returns a quote, event log and compose hash for a document
// the hardware measured: the log's compose-hash event is rewritten to the
// document's digest and the replayed RTMR3 written into the quote. Rewriting
// the document alone would leave every case stopping at the hash gate.
func (fx *verdictFixture) measuredRelease(doc string) (quote []byte, eventLog, composeHash string) {
	sum := sha256.Sum256([]byte(doc))
	composeHash = hex.EncodeToString(sum[:])

	var events []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fx.eventLog), &events); err != nil {
		fx.t.Fatalf("parse event log: %v", err)
	}
	rewritten := false
	for _, e := range events {
		var name string
		if json.Unmarshal(e["event"], &name) == nil && name == attest.EventComposeHash {
			e["event_payload"], _ = json.Marshal(composeHash)
			rewritten = true
		}
	}
	if !rewritten {
		fx.t.Fatal("the capture has no compose-hash event to rewrite")
	}
	logBytes, err := json.Marshal(events)
	if err != nil {
		fx.t.Fatal(err)
	}
	parsed, err := attest.ParseEventLog(string(logBytes))
	if err != nil {
		fx.t.Fatal(err)
	}
	rtmr3, _, err := attest.ReplayRTMR3(parsed)
	if err != nil {
		fx.t.Fatal(err)
	}
	quote = fx.boundQuote(capturedKey, capturedNodeID, capturedModels(), nil, nil)
	reg, ok := attest.QuoteRTMR(quote, 3)
	if !ok {
		fx.t.Fatal("the capture has no RTMR3")
	}
	copy(reg, rtmr3)
	return quote, string(logBytes), composeHash
}

// cleanAppCompose is a document in the shape the deploy recipe publishes,
// clean under the shared rules.
func cleanAppCompose(t *testing.T) (doc, dockerCompose string) {
	dockerCompose = "services:\n" +
		"  zs-node:\n" +
		"    image: " + verdictReleaseImage + "\n" +
		"    volumes:\n" +
		"      - /var/run/dstack.sock:/var/run/dstack.sock\n" +
		"      - zs-node-state:/data\n" +
		"    ports:\n" +
		"      - \"9090:9090\"\n" +
		"    environment:\n" +
		"      NODE_CONFIG_YAML: |\n" +
		"        zs: { operator_id: 1, node_id: 2 }\n" +
		"      NODE_LLM_OPENAI_API_KEY: ${NODE_LLM_OPENAI_API_KEY}\n" +
		"    restart: always\n" +
		"volumes:\n" +
		"  zs-node-state: {}\n"
	b, err := json.Marshal(map[string]any{
		"manifest_version":           2,
		"name":                       "zs-node",
		"runner":                     "docker-compose",
		"docker_compose_file":        dockerCompose,
		"pre_launch_script":          "",
		"allowed_envs":               []string{"NODE_LLM_OPENAI_API_KEY", "OPERATOR_SIGNING_MNEMONIC"},
		"features":                   []string{},
		"gateway_enabled":            true,
		"tproxy_enabled":             false,
		"kms_enabled":                true,
		"local_key_provider_enabled": false,
		"no_instance_id":             false,
		"secure_time":                false,
		"public_logs":                false,
		"public_sysinfo":             false,
		"public_tcbinfo":             true,
		"storage_fs":                 "",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b), dockerCompose
}

// base is a healthy dstack node: the capture bound to our key, catalog and
// node id, fresh, under the shape rules with the capture's compose hash
// pinned and no app_compose published.
func (fx *verdictFixture) base(name string) verdictCase {
	offset := int64(-5 * time.Minute / time.Millisecond)
	return verdictCase{
		Name:          name,
		Advertisement: map[string]any{"mode": inject.TEEModeDstackTDX, "evidence_url": "/v1/zs/attestation"},
		Bundle: map[string]any{
			"mode":            inject.TEEModeDstackTDX,
			"node_pubkey":     capturedKey,
			"operator_id":     capturedOperatorID,
			"report_data":     attest.ReportDataB64(capturedKey, capturedOperatorID),
			"app_models":      capturedModels(),
			"refresh_seconds": 1200,
		},
		CPUReportQuote:      "bound",
		EventLog:            "captured",
		GeneratedAtOffsetMs: &offset,
		Node: verdictNode{
			OperatorID:               strconv.FormatUint(capturedOperatorID, 10),
			NodeID:                   strconv.FormatUint(capturedNodeID, 10),
			EphemeralRecipientPubkey: capturedKey,
		},
		Policy: verdictPolicy{
			TrustedOSImages:      []string{capturedOSImage},
			TrustedComposeHashes: []string{capturedComposeHash},
			ComposePolicy:        "shape_only",
		},
		Chain:      "ok",
		Carried:    "ok",
		Collateral: "absent",
		NowUnixMs:  fx.issuedMs + time.Minute.Milliseconds(),
		Expect: verdictExpect{
			Pass:              true,
			FailureTag:        tagp(""),
			VerifierID:        VerifierIDDstack,
			AttestedModelIDs:  modelIDs(capturedModels()),
			MeasurementChecks: baseChecks(),
		},
	}
}

// baseChecks is what base's pass rests on: the trusted image and the pinned
// compose hash, with the release match off.
func baseChecks() *verdictChecks { return &verdictChecks{OSImage: true, ComposeHash: true} }

func tagp(tag string) *string { return &tag }

func modelIDs(models []inject.ModelEntry) []string {
	ids := []string{}
	for _, m := range models {
		ids = append(ids, m.ModelID)
	}
	return ids
}

func (c *verdictCase) refuse(tag, verifierID string) {
	c.Expect = verdictExpect{FailureTag: tagp(tag), VerifierID: verifierID}
}

func (c *verdictCase) offset(d time.Duration) {
	ms := d.Milliseconds()
	c.GeneratedAtOffsetMs = &ms
}

func (c *verdictCase) literalCPUReport(s string) {
	c.CPUReportQuote = ""
	c.CPUReport = &s
}

// withCollateral sets the carried set and, for "stale", moves the clock a day
// past the floor.
func (fx *verdictFixture) withCollateral(c *verdictCase, state string) {
	c.Collateral = state
	switch state {
	case "absent":
		delete(c.Bundle, "collateral")
	case "incomplete":
		coll := maps.Clone(fx.collateral)
		coll["pck_crl"] = ""
		c.Bundle["collateral"] = coll
	case "fresh":
		c.Bundle["collateral"] = maps.Clone(fx.collateral)
	case "stale":
		c.Bundle["collateral"] = maps.Clone(fx.collateral)
		c.NowUnixMs = fx.issuedMs + (attest.EmbeddedCollateralMaxAge + verdictStaleSkewDays*24*time.Hour).Milliseconds()
	default:
		fx.t.Fatalf("unknown collateral state %q", state)
	}
}

func (fx *verdictFixture) stub(name string) verdictCase {
	c := fx.base(name)
	c.Advertisement["mode"] = inject.TEEModeStub
	c.Bundle["mode"] = inject.TEEModeStub
	c.Bundle["stub"] = true
	c.EventLog = ""
	c.CPUReportQuote = ""
	return c
}

func (fx *verdictFixture) cases() []verdictCase {
	t := fx.t
	models := capturedModels()
	fx.quoteNamed("bound", fx.boundQuote(capturedKey, capturedNodeID, models, nil, nil))
	bound := fx.boundQuote(capturedKey, capturedNodeID, models, nil, nil)

	var cases []verdictCase
	add := func(c verdictCase, mutate func(*verdictCase)) {
		mutate(&c)
		cases = append(cases, c)
	}
	none := func(*verdictCase) {}

	// The bundle-level checks.
	add(fx.base("dstack_pass_with_models"), none)
	add(fx.base("dstack_pass_signed_empty_catalog"), func(c *verdictCase) {
		// A signed empty catalog is a checkable claim. Absent from the body
		// because a node marshals app_models with omitempty.
		c.CPUReportQuote = fx.quoteNamed("bound_empty_catalog", fx.boundQuote(capturedKey, capturedNodeID, []inject.ModelEntry{}, nil, nil))
		delete(c.Bundle, "app_models")
		c.Expect.AttestedModelIDs = []string{}
	})
	add(fx.base("no_verified_ephemeral"), func(c *verdictCase) {
		c.Node.EphemeralRecipientPubkey = ""
		c.refuse(FailureKeyBindingMismatch, VerifierIDBuiltin)
	})
	add(fx.base("mode_disagrees_with_advertisement"), func(c *verdictCase) {
		c.Advertisement["mode"] = inject.TEEModeStub
		c.refuse(FailureAdvertisementMismatch, VerifierIDBuiltin)
	})
	add(fx.base("operator_id_disagrees_with_chain"), func(c *verdictCase) {
		c.Bundle["operator_id"] = capturedOperatorID + 1
		c.refuse(FailureAdvertisementMismatch, VerifierIDBuiltin)
	})
	add(fx.base("node_pubkey_is_not_the_sealing_key"), func(c *verdictCase) {
		c.Bundle["node_pubkey"] = verdictOtherKey
		c.refuse(FailureAdvertisementMismatch, VerifierIDBuiltin)
	})

	// Freshness. Offsets sit minutes from every window edge: Go dates the
	// bundle against the real clock, which cannot land on an edge exactly.
	add(fx.base("stale_past_twice_the_cadence"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 60
		c.offset(-10 * time.Minute)
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
	})
	add(fx.base("future_dated_past_the_ceiling"), func(c *verdictCase) {
		c.offset(2 * time.Hour)
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
	})
	add(fx.base("future_dated_past_twice_the_cadence"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 60
		c.offset(10 * time.Minute)
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
	})
	add(fx.base("huge_cadence_capped_by_the_ceiling"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 86400
		c.offset(-2 * time.Hour)
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
	})
	add(fx.base("huge_cadence_inside_the_ceiling"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 86400
		c.offset(-60 * time.Minute)
	})
	add(fx.base("zero_cadence_inside_the_ceiling"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 0
		c.offset(-10 * time.Minute)
	})
	add(fx.base("zero_cadence_past_the_ceiling"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 0
		c.offset(-90 * time.Minute)
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
	})
	add(fx.base("negative_cadence_falls_to_the_ceiling"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = -1
		c.offset(-10 * time.Minute)
	})
	// Cadences whose doubled nanoseconds would wrap int64: 4611686019 wraps
	// negative, 2197108676271213 to a 1024ns window. Clamped first, both get
	// the ceiling.
	for _, refresh := range []int{4611686019, 2197108676271213} {
		add(fx.base(fmt.Sprintf("int64_wrapping_cadence_%d_inside_the_ceiling", refresh)), func(c *verdictCase) {
			c.Bundle["refresh_seconds"] = refresh
			c.offset(-75 * time.Minute)
		})
		add(fx.base(fmt.Sprintf("int64_wrapping_cadence_%d_past_the_ceiling", refresh)), func(c *verdictCase) {
			c.Bundle["refresh_seconds"] = refresh
			c.offset(-90 * time.Minute)
			c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
		})
	}
	add(fx.base("generated_at_absent"), func(c *verdictCase) {
		c.GeneratedAtOffsetMs = nil
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
		c.Expect.FailureTag = nil
	})
	add(fx.base("staleness_reported_before_the_key_binding"), func(c *verdictCase) {
		c.Bundle["refresh_seconds"] = 60
		c.offset(-10 * time.Minute)
		c.Bundle["report_data"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		c.refuse(FailureStaleEvidence, VerifierIDBuiltin)
	})

	// The self-reported report_data.
	add(fx.base("report_data_wrong"), func(c *verdictCase) {
		c.Bundle["report_data"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		c.refuse(FailureKeyBindingMismatch, VerifierIDBuiltin)
	})
	add(fx.base("report_data_unpadded"), func(c *verdictCase) {
		c.Bundle["report_data"] = strings.TrimRight(attest.ReportDataB64(capturedKey, capturedOperatorID), "=")
		c.refuse(FailureKeyBindingMismatch, VerifierIDBuiltin)
	})
	add(fx.base("report_data_not_base64"), func(c *verdictCase) {
		c.Bundle["report_data"] = "!!!not b64"
		c.refuse(FailureKeyBindingMismatch, VerifierIDBuiltin)
	})
	// Go's StdEncoding skips CR and LF wherever they fall; a stricter
	// decoder would refuse nodes the proxy admits.
	add(fx.base("report_data_and_cpu_report_line_wrapped"), func(c *verdictCase) {
		c.Bundle["report_data"] = wrapBase64(attest.ReportDataB64(capturedKey, capturedOperatorID), 20)
		c.literalCPUReport(wrapBase64(base64.StdEncoding.EncodeToString(bound), 76))
	})

	// Stub gating.
	add(fx.stub("stub_allowed"), func(c *verdictCase) {
		c.AllowStub = true
		c.Expect = verdictExpect{Pass: true, FailureTag: tagp(""), VerifierID: VerifierIDBuiltin}
	})
	// The gate is the stub BOOL, ahead of the mode dispatch, so a dstack-tdx
	// bundle flagged stub never reaches DstackVerifier and attests no models.
	add(fx.base("stub_flag_on_a_dstack_bundle"), func(c *verdictCase) {
		c.AllowStub = true
		c.Bundle["stub"] = true
		c.Expect = verdictExpect{Pass: true, FailureTag: tagp(""), VerifierID: VerifierIDBuiltin}
	})
	add(fx.stub("stub_refused"), func(c *verdictCase) {
		c.refuse(FailureStubNotAllowed, VerifierIDBuiltin)
	})
	add(fx.stub("stub_with_a_wrong_binding"), func(c *verdictCase) {
		c.AllowStub = true
		c.Bundle["report_data"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
		c.refuse(FailureKeyBindingMismatch, VerifierIDBuiltin)
	})
	add(fx.stub("stub_mode_without_the_stub_flag"), func(c *verdictCase) {
		c.AllowStub = true
		delete(c.Bundle, "stub")
		c.refuse(FailureVerifierNotImpl, VerifierIDBuiltin)
	})

	// Mode dispatch.
	for _, mode := range []string{inject.TEEModeNvidiaCCTDX, inject.TEEModeNvidiaCCSEVSNP, "sev-snp-someday"} {
		add(fx.base("mode_"+mode+"_not_implemented"), func(c *verdictCase) {
			c.Advertisement["mode"] = mode
			c.Bundle["mode"] = mode
			c.refuse(FailureVerifierNotImpl, VerifierIDBuiltin)
		})
	}

	// The platform from the bytes.
	add(fx.base("quote_not_tdx"), func(c *verdictCase) {
		sgx := bytes.Clone(bound)
		sgx[4] = 0x00
		c.CPUReportQuote = fx.quoteNamed("sgx", sgx)
		c.refuse(FailureVendorChainInvalid, VerifierIDDstack)
	})
	add(fx.base("cpu_report_not_base64"), func(c *verdictCase) {
		c.literalCPUReport("!!!not base64!!!")
		c.refuse(FailureVendorChainInvalid, VerifierIDDstack)
	})
	add(fx.base("cpu_report_absent"), func(c *verdictCase) {
		c.CPUReportQuote = ""
		c.refuse(FailureVendorChainInvalid, VerifierIDDstack)
	})
	// The capture needs no padding; one byte past the signed region makes it
	// need two, which Go's StdEncoding then requires.
	add(fx.base("cpu_report_unpadded"), func(c *verdictCase) {
		longer := append(bytes.Clone(bound), 0)
		c.literalCPUReport(strings.TrimRight(base64.StdEncoding.EncodeToString(longer), "="))
		c.refuse(FailureVendorChainInvalid, VerifierIDDstack)
	})

	// The chain step and SPEC §3e's collateral precedence.
	chain := func(name, outcome, carried, collateral string, want verdictExpect) {
		add(fx.base(name), func(c *verdictCase) {
			c.Chain = outcome
			c.Carried = carried
			fx.withCollateral(c, collateral)
			want.VerifierID = VerifierIDDstack
			if want.Pass {
				want.AttestedModelIDs = modelIDs(models)
				want.MeasurementChecks = baseChecks()
			}
			c.Expect = want
		})
	}
	pass := verdictExpect{Pass: true, FailureTag: tagp("")}
	unreachable := verdictExpect{FailureTag: tagp(FailureCollateralUnreachable)}
	unreachableAfterCarried := verdictExpect{FailureTag: tagp(FailureCollateralUnreachable), CarriedCalled: true}
	invalid := verdictExpect{FailureTag: tagp(FailureVendorChainInvalid)}
	chain("chain_unavailable_carried_verifies", "unavailable", "ok", "fresh", verdictExpect{Pass: true, FailureTag: tagp(""), CarriedCalled: true})
	chain("chain_unavailable_carried_invalid", "unavailable", "invalid", "fresh", unreachableAfterCarried)
	chain("chain_unavailable_carried_out_of_date", "unavailable", "tcb:OutOfDate", "fresh", unreachableAfterCarried)
	chain("chain_unavailable_collateral_absent", "unavailable", "ok", "absent", unreachable)
	chain("chain_unavailable_collateral_incomplete", "unavailable", "ok", "incomplete", unreachable)
	chain("chain_unavailable_collateral_stale", "unavailable", "ok", "stale", unreachable)
	chain("chain_stale_cache_rejected", "stale_rejected", "ok", "fresh", unreachable)
	chain("chain_stale_cache_out_of_date", "stale_tcb:OutOfDate", "ok", "fresh", unreachable)
	chain("chain_stale_cache_up_to_date", "stale_tcb:UpToDate", "ok", "fresh", pass)
	chain("chain_out_of_date", "tcb:OutOfDate", "ok", "fresh", invalid)
	chain("chain_sw_hardening_needed", "tcb:SWHardeningNeeded", "ok", "fresh", invalid)
	chain("chain_invalid", "invalid", "ok", "fresh", invalid)

	// The replay and the measurement lists.
	add(fx.base("event_log_tampered"), func(c *verdictCase) {
		var events []map[string]any
		if err := json.Unmarshal([]byte(fx.eventLog), &events); err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if p, _ := e["event_payload"].(string); p != "" {
				e["event_payload"] = "aabb"
				break
			}
		}
		tampered, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		fx.eventLogs["tampered"] = string(tampered)
		c.EventLog = "tampered"
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("event_log_empty"), func(c *verdictCase) {
		fx.eventLogs["empty"] = "[]"
		c.EventLog = "empty"
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("os_image_not_trusted"), func(c *verdictCase) {
		c.Policy.TrustedOSImages = []string{strings.Repeat("00", 32)}
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("os_image_list_empty"), func(c *verdictCase) {
		c.Policy.TrustedOSImages = []string{}
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})

	// The compose-hash guard: an empty pin is "no constraint" only under the
	// release match.
	captured := capturedAppCompose(t)
	clean, cleanCompose := cleanAppCompose(t)
	measuredQuote, measuredLog, measuredHash := fx.measuredRelease(clean)
	fx.quoteNamed("measured_release", measuredQuote)
	fx.eventLogs["measured_release"] = measuredLog
	skeleton, _, err := attest.ExtractComposeSkeleton(cleanCompose)
	if err != nil {
		t.Fatalf("extract skeleton: %v", err)
	}
	release := func(hashes []string) verdictPolicy {
		return verdictPolicy{
			TrustedOSImages:         []string{capturedOSImage},
			TrustedComposeHashes:    hashes,
			ComposePolicy:           "release",
			TrustedComposeSkeletons: []string{attest.ComposeSkeletonDigest(skeleton)},
			TrustedNodeImages:       []string{verdictReleaseImage},
		}
	}
	measured := func(name string, policy verdictPolicy, mutate func(*verdictCase)) {
		add(fx.base(name), func(c *verdictCase) {
			c.CPUReportQuote = "measured_release"
			c.EventLog = "measured_release"
			c.Bundle["app_compose"] = clean
			c.Policy = policy
			mutate(c)
		})
	}
	add(fx.base("compose_pin_empty_release_match_off"), func(c *verdictCase) {
		c.Policy.TrustedComposeHashes = []string{}
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("compose_pin_matching_release_match_off"), func(c *verdictCase) {
		c.Policy.ComposePolicy = "none"
	})
	measured("compose_pin_empty_release_match_on", release([]string{}), func(c *verdictCase) {
		c.Expect.MeasurementChecks = &verdictChecks{OSImage: true, ComposeRelease: true}
	})
	measured("compose_pin_matching_release_match_on", release([]string{measuredHash}), func(c *verdictCase) {
		c.Expect.MeasurementChecks = &verdictChecks{OSImage: true, ComposeRelease: true, ComposeHash: true}
	})
	measured("compose_pin_not_matching_release_match_on", release([]string{strings.Repeat("aa", 32)}), func(c *verdictCase) {
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	measured("measured_document_shape_only", verdictPolicy{
		TrustedOSImages:      []string{capturedOSImage},
		TrustedComposeHashes: []string{measuredHash},
		ComposePolicy:        "shape_only",
	}, none)
	measured("measured_document_not_a_shipped_release", verdictPolicy{
		TrustedOSImages:      []string{capturedOSImage},
		TrustedComposeHashes: []string{},
		ComposePolicy:        "shipped",
	}, func(c *verdictCase) {
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("compose_pin_does_not_bypass_the_release_match"), func(c *verdictCase) {
		c.Bundle["app_compose"] = captured
		c.Policy = release([]string{capturedComposeHash})
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("app_compose_absent_under_the_release_match"), func(c *verdictCase) {
		c.Policy = verdictPolicy{TrustedOSImages: []string{capturedOSImage}, TrustedComposeHashes: []string{}, ComposePolicy: "shipped"}
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("app_compose_installs_a_root_key"), func(c *verdictCase) {
		c.Bundle["app_compose"] = captured
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})
	add(fx.base("app_compose_not_the_measured_one"), func(c *verdictCase) {
		c.Bundle["app_compose"] = clean
		c.refuse(FailureMeasurementMismatch, VerifierIDDstack)
	})

	// Both halves of the signed report_data.
	add(fx.base("aux_binding_zero_upper_half"), func(c *verdictCase) {
		c.CPUReportQuote = fx.quoteNamed("zero_upper", spliceReportData(fx.quote, attest.ReportData(capturedKey, capturedOperatorID), [32]byte{}))
		c.refuse(FailureAuxBindingAbsent, VerifierIDDstack)
	})
	add(fx.base("quote_binds_another_key"), func(c *verdictCase) {
		c.CPUReportQuote = fx.quoteNamed("wrong_key", spliceReportData(fx.quote,
			attest.ReportData(verdictOtherKey, capturedOperatorID), fx.aux(capturedNodeID, models, nil, nil)))
		c.refuse(FailureKeyBindingMismatch, VerifierIDDstack)
	})
	add(fx.base("quote_truncated_inside_report_data"), func(c *verdictCase) {
		c.CPUReportQuote = fx.quoteNamed("truncated", bound[:600])
		c.refuse(FailureKeyBindingMismatch, VerifierIDDstack)
	})
	add(fx.base("aux_binding_for_a_sibling_node"), func(c *verdictCase) {
		c.CPUReportQuote = fx.quoteNamed("sibling_node", fx.boundQuote(capturedKey, capturedNodeID+1, models, nil, nil))
		c.refuse(FailureAuxBindingMismatch, VerifierIDDstack)
	})
	add(fx.base("catalog_withheld"), func(c *verdictCase) {
		delete(c.Bundle, "app_models")
		c.refuse(FailureHAppPreimageMissing, VerifierIDDstack)
	})
	add(fx.base("catalog_entry_missing_weights_digest"), func(c *verdictCase) {
		c.Bundle["app_models"] = []map[string]any{{"model_id": "qwen3-30b", "source": "hf/Qwen/Qwen3-30B", "weights_state": 1}}
		c.refuse(FailureHAppPreimageInvalid, VerifierIDDstack)
	})
	add(fx.base("catalog_duplicate_model_id"), func(c *verdictCase) {
		dup := capturedModels()
		dup[1].ModelID = dup[0].ModelID
		c.Bundle["app_models"] = dup
		c.refuse(FailureHAppPreimageInvalid, VerifierIDDstack)
	})
	add(fx.base("catalog_substituted"), func(c *verdictCase) {
		other := capturedModels()
		other[0].ModelID = "something-else"
		c.Bundle["app_models"] = other
		c.refuse(FailureAuxBindingMismatch, VerifierIDDstack)
	})
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 0xa0)
	}
	add(fx.base("nonce_echoed_in_upper_case"), func(c *verdictCase) {
		c.CPUReportQuote = fx.quoteNamed("bound_nonce", fx.boundQuote(capturedKey, capturedNodeID, models, nil, &nonce))
		c.Bundle["nonce"] = strings.ToUpper(hex.EncodeToString(nonce[:]))
	})
	add(fx.base("nonce_malformed"), func(c *verdictCase) {
		c.Bundle["nonce"] = "zz"
		c.refuse(FailureAuxBindingMismatch, VerifierIDDstack)
	})

	// The posture, bound into the quote it is published with.
	posture := func(name string, p *inject.TEEPosture, mutate func(*verdictCase)) {
		add(fx.base(name), func(c *verdictCase) {
			c.CPUReportQuote = fx.quoteNamed(name, fx.boundQuote(capturedKey, capturedNodeID, models, p, nil))
			c.Bundle["posture"] = p
			mutate(c)
		})
	}
	posture("posture_in_enclave", &inject.TEEPosture{PlaintextTerminates: inject.PlaintextInEnclave}, none)
	posture("posture_in_enclave_claims_an_attested_upstream", &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextInEnclave, UpstreamAttested: true,
	}, func(c *verdictCase) { c.refuse(FailureAdvertisementMismatch, VerifierIDDstack) })
	// Unknown must never read as the stronger claim.
	posture("posture_unrecognised_termination", &inject.TEEPosture{PlaintextTerminates: "somewhere_else"},
		func(c *verdictCase) { c.refuse(FailureAdvertisementMismatch, VerifierIDDstack) })
	posture("posture_in_enclave_names_an_upstream", &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextInEnclave, UpstreamBaseURL: "https://x",
	}, func(c *verdictCase) { c.refuse(FailureAdvertisementMismatch, VerifierIDDstack) })
	posture("posture_named_upstream_names_nobody", &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream, ZeroRetention: true,
	}, func(c *verdictCase) { c.refuse(FailureAdvertisementMismatch, VerifierIDDstack) })
	posture("posture_xai_zero_retention", &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream, UpstreamBaseURL: "https://api.x.ai/v1", ZeroRetention: true,
	}, none)
	posture("posture_gateway_without_attestation", &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream, UpstreamBaseURL: verdictGatewayURL,
	}, func(c *verdictCase) { c.refuse(FailurePostureUpstreamUnverifiable, VerifierIDDstack) })
	attested := &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream, UpstreamBaseURL: verdictGatewayURL, UpstreamAttested: true,
	}
	posture("posture_gateway_attested_with_aci", attested, func(c *verdictCase) {
		c.Bundle["upstream_attestation"] = map[string]any{"protocol": inject.UpstreamProtocolACI1, "base_url": verdictGatewayURL}
	})
	carveOuts := []string{"root_backdoor_env:DSTACK_ROOT_PUBLIC_KEY"}
	posture("posture_gateway_attested_reports_carve_outs", attested, func(c *verdictCase) {
		c.Bundle["upstream_attestation"] = map[string]any{
			"protocol": inject.UpstreamProtocolACI1, "base_url": verdictGatewayURL, "carve_outs": carveOuts,
		}
		c.Expect.UpstreamCarveOuts = carveOuts
	})
	posture("posture_gateway_attested_empty_carve_outs", attested, func(c *verdictCase) {
		c.Bundle["upstream_attestation"] = map[string]any{
			"protocol": inject.UpstreamProtocolACI1, "base_url": verdictGatewayURL, "carve_outs": []string{},
		}
	})
	// Without the bound appraisal bit the block is not what the node vouches
	// for, so its list is not reported either.
	posture("posture_xai_carve_outs_not_reported", &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream, UpstreamBaseURL: "https://api.x.ai/v1", ZeroRetention: true,
	}, func(c *verdictCase) {
		c.Bundle["upstream_attestation"] = map[string]any{
			"protocol": inject.UpstreamProtocolACI1, "base_url": "https://api.x.ai/v1", "carve_outs": carveOuts,
		}
	})
	// xAI passes on zero retention alone, so the bound bit can be set with no
	// block the verifier credits: neither case reports a list.
	xaiClaimsAppraisal := &inject.TEEPosture{
		PlaintextTerminates: inject.PlaintextNamedUpstream, UpstreamBaseURL: "https://api.x.ai/v1",
		ZeroRetention: true, UpstreamAttested: true,
	}
	posture("posture_appraisal_bit_without_a_block", xaiClaimsAppraisal, none)
	posture("posture_appraisal_bit_with_an_unknown_protocol", xaiClaimsAppraisal, func(c *verdictCase) {
		c.Bundle["upstream_attestation"] = map[string]any{
			"protocol": "other/1", "base_url": "https://api.x.ai/v1", "carve_outs": carveOuts,
		}
	})
	posture("posture_gateway_attested_without_a_block", attested, func(c *verdictCase) {
		c.refuse(FailurePostureUpstreamUnverifiable, VerifierIDDstack)
	})
	add(fx.base("posture_unhashable"), func(c *verdictCase) {
		c.Bundle["posture"] = map[string]any{"zero_retention": "yes"}
		c.refuse(FailurePosturePreimageInvalid, VerifierIDDstack)
	})
	add(fx.base("posture_added_after_the_quote"), func(c *verdictCase) {
		c.Bundle["posture"] = &inject.TEEPosture{PlaintextTerminates: inject.PlaintextInEnclave}
		c.refuse(FailureAuxBindingMismatch, VerifierIDDstack)
	})

	return cases
}

// wrapBase64 inserts CRLF every n characters.
func wrapBase64(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(s[i:min(i+n, len(s))])
	}
	return b.String()
}
