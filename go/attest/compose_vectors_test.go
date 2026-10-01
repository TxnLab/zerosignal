/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Cross-implementation vectors for the COMPOSE rules, written to
// proto/testdata/compose_vectors.json and read by both this file and
// proto/ts/test/attest-compose-vectors.test.ts.
//
// Regenerate: cd proto/go && go test ./attest -run TestComposeVectors -update-compose
//
// WHY THIS EXISTS, and it is not a general preference for vectors. The
// compose rules shipped with their Go↔TS parity pinned by exactly one literal
// digest over one benign fixture, plus a `realisticCompose` HAND-DUPLICATED in
// both languages with a comment asserting the two were byte-identical and
// nothing enforcing it. Under that, a review found a live divergence: every
// whitespace decision was strings.TrimSpace on one side and
// String.prototype.trim on the other, which are different predicates (U+0085
// is space to Go only, U+FEFF to JS only). It produced opposite verdicts on
// adversary-chosen bytes — including a fail-open on empty_docker_compose, the
// only rule guarding docker_compose_file while consumers ship
// EnforceComposeSkeleton false — and BOTH hand-written suites stayed green,
// because each asserted about its own language.
//
// That was the second divergence of the same class in consecutive commits. So
// the fixtures move here, where one file is the input to both languages and
// they cannot end up agreeing about different bytes.
//
// WHAT IS PINNED IS EVERY OBSERVABLE, not just the happy path: the skeleton
// digest, the extracted image reference, the refusal code when extraction
// fails, and the SORTED violation codes for each document/policy pair. A
// wrong implementation reproduces all of these as well-formed, plausible,
// entirely wrong values — that is the whole hazard in this package.
var updateComposeVectors = flag.Bool("update-compose", false,
	"regenerate proto/testdata/compose_vectors.json")

const composeVectorsPath = "../../testdata/compose_vectors.json"

// skeletonVector pins one ExtractComposeSkeleton call.
//
// ErrorCode and the two success fields are mutually exclusive, and both are
// emitted either way: a language that silently returned ("", "", nil) on a
// document it could not read would satisfy an assertion that only checked the
// error.
type skeletonVector struct {
	Name          string `json:"name"`
	Why           string `json:"why"`
	DockerCompose string `json:"docker_compose"`
	ErrorCode     string `json:"error_code,omitempty"`
	SkeletonHex   string `json:"skeleton_sha256,omitempty"`
	ImageRef      string `json:"image_ref,omitempty"`
}

// documentVector pins one VerifyAppCompose call.
//
// Violations is SORTED and carries codes only, never detail strings: the codes
// are the stable cross-language contract (a UI branches on them), while the
// details are prose that legitimately differs. Sorted because the two
// implementations walk the rules in the same order today and nothing requires
// them to keep doing so — pinning the order would fail on a reordering that
// changes no verdict.
type documentVector struct {
	Name       string   `json:"name"`
	Why        string   `json:"why"`
	AppCompose string   `json:"app_compose"`
	Policy     string   `json:"policy"`
	Sealed     bool     `json:"sealed"`
	ErrorCode  string   `json:"error_code,omitempty"`
	Violations []string `json:"violations,omitempty"`
}

type composeVectors struct {
	Comment string `json:"_comment"`

	// The release compose both languages test against, emitted as text
	// so neither has to reconstruct it. This is the field that stops
	// realisticCompose being hand-mirrored.
	ReleaseCompose string `json:"release_compose"`
	ReleaseImage   string `json:"release_image"`
	ReleaseConfig  string `json:"release_config"`

	// The sealed_local two-service compose, same purpose. Emitted rather
	// than derived from a document vector because the policy it backs must
	// be built from the UNSWAPPED shape — a policy rebuilt per-document
	// from that document's own bytes would accept every swap it is there
	// to catch.
	SidecarCompose string `json:"sidecar_compose"`
	SidecarEngine  string `json:"sidecar_engine"`

	// The shared policy, emitted so TS can assert its own copy against
	// Go's rather than against a hand-typed list.
	SharedPolicy sharedPolicyVector `json:"shared_policy"`

	Skeletons []skeletonVector `json:"skeletons"`
	Documents []documentVector `json:"documents"`
}

type sharedPolicyVector struct {
	ManifestVersion        int      `json:"manifest_version"`
	Runner                 string   `json:"runner"`
	AllowedEnvNames        []string `json:"allowed_env_names"`
	AllowedEnvSuffixes     []string `json:"allowed_env_suffixes"`
	EnforceEnvAllowlist    bool     `json:"enforce_env_allowlist"`
	PreLaunchScriptDigests []string `json:"pre_launch_script_digests"`
	EnforceComposeSkeleton bool     `json:"enforce_compose_skeleton"`
	RootBackdoorEnvs       []string `json:"root_backdoor_envs"`

	// AllowedRootBackdoorEnvs on the SHARED policy, which must be empty.
	//
	// Carried across the wire specifically so TS asserts it. The Go-side
	// unit test protects Go alone: the browser ships its OWN
	// zeroSignalComposePolicy(), so an exemption added there would be
	// caught by nothing. An empty array in the JSON is the whole point of
	// the field — it is not a placeholder for a value that arrives later.
	AllowedRootBackdoorEnvs []string `json:"allowed_root_backdoor_envs"`

	// TrustedOSImages is the production dstack guest-image allowlist.
	//
	// Carried for the same reason as the field above and against a sharper
	// hazard: these digests move when Phala ships an image, on NO
	// automation, and every consumer holds its own copy —
	// attest.TrustedDstackOSImages here (which zs-proxy and zs-node both
	// read), client/src/operators/tee-allowlist.ts in the browser, and
	// node/internal/tee/dstackprobe.sh. A stale entry refuses nodes
	// silently: the deploy succeeds, the quote verifies, and payers route
	// elsewhere with nothing logged.
	//
	// The assertion against it is in client/src/operators/tee-allowlist.test.ts,
	// NOT in proto/ts — the browser holds the second copy of these digests, and
	// proto/ts holds none, so there is nothing there to compare. Carrying the
	// field is therefore necessary and not sufficient: publishing it and
	// asserting nothing would read exactly like coverage.
	TrustedOSImages []string `json:"trusted_os_images"`
}

// composePolicies are the named policies a vector may reference. Named rather
// than inlined so a TS reader resolves the same object Go used, instead of
// rebuilding one from a JSON description and testing its own rebuild.
func composePolicies(t *testing.T) map[string]ComposePolicy {
	t.Helper()

	skel, ref, err := ExtractComposeSkeleton(realisticCompose(realImage, someConfig))
	if err != nil {
		t.Fatalf("extract the release skeleton: %v", err)
	}

	enforced := ZeroSignalComposePolicy()
	enforced.EnforceComposeSkeleton = true
	enforced.TrustedComposeSkeletons = []string{ComposeSkeletonDigest(skel)}
	enforced.TrustedNodeImages = []string{ref}

	// The sealed_local two-service shape under its OWN release lists. A
	// distinct policy from "enforced" because the sidecar's skeleton is a
	// distinct value — the engine ref is preserved verbatim, so the two shapes
	// can never share a digest.
	sidecarSkel, sidecarRef, err := ExtractComposeSkeleton(sidecarCompose(realImage, engineImage))
	if err != nil {
		t.Fatalf("extract the sidecar skeleton: %v", err)
	}
	sidecarEnforced := ZeroSignalComposePolicy()
	sidecarEnforced.EnforceComposeSkeleton = true
	sidecarEnforced.TrustedComposeSkeletons = []string{ComposeSkeletonDigest(sidecarSkel)}
	sidecarEnforced.TrustedNodeImages = []string{sidecarRef}

	// The same, with the references emptied. Separate from "enforced"
	// because empty-plus-enforced is the fail-CLOSED reading and is worth
	// pinning across languages on its own — an implementation that read an
	// empty list as "no constraint" passes every other vector here.
	closed := ZeroSignalComposePolicy()
	closed.EnforceComposeSkeleton = true

	// The lists populated with the switch left off — no check runs, and
	// nothing distinguishes it from a build that meant to leave it off.
	// That is why it is a violation about the VERIFIER.
	misconfigured := ZeroSignalComposePolicy()
	misconfigured.TrustedComposeSkeletons = []string{ComposeSkeletonDigest(skel)}
	misconfigured.TrustedNodeImages = []string{ref}

	// Pins the encrypted-FS backend, which the shared policy leaves
	// unchecked because the correct value is unsettled across releases.
	storage := ZeroSignalComposePolicy()
	storage.StorageFS = "ext4"

	return map[string]ComposePolicy{
		"empty":            {},
		"zerosignal":       ZeroSignalComposePolicy(),
		"enforced":         enforced,
		"sidecar_enforced": sidecarEnforced,
		"closed":           closed,
		"misconfigured":    misconfigured,
		"storage":          storage,
	}
}

// emptyIfNil renders a nil slice as `[]` rather than `null` in the vectors.
// A TS reader comparing against `[]` would otherwise have to special-case
// null, and "the field is absent" and "the list is empty" must not be
// spellable as different things here — both mean "concedes nothing".
func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func buildComposeVectors(t *testing.T) composeVectors {
	t.Helper()

	release := realisticCompose(realImage, someConfig)
	policies := composePolicies(t)

	v := composeVectors{
		Comment: "Generated by proto/go/attest/compose_vectors_test.go " +
			"(go test ./attest -run TestComposeVectors -update-compose). " +
			"Read by Go and TypeScript so neither can be right alone.",
		ReleaseCompose: release,
		ReleaseImage:   realImage,
		ReleaseConfig:  someConfig,
		SidecarCompose: sidecarCompose(realImage, engineImage),
		SidecarEngine:  engineImage,
		SharedPolicy: sharedPolicyVector{
			ManifestVersion:        ZeroSignalComposePolicy().ManifestVersion,
			Runner:                 ZeroSignalComposePolicy().Runner,
			AllowedEnvNames:        ZeroSignalSecretEnvNames(),
			AllowedEnvSuffixes:     ZeroSignalComposePolicy().AllowedEnvSuffixes,
			EnforceEnvAllowlist:    ZeroSignalComposePolicy().EnforceEnvAllowlist,
			PreLaunchScriptDigests: PhalaPreLaunchDigests(),
			EnforceComposeSkeleton: ZeroSignalComposePolicy().EnforceComposeSkeleton,
			RootBackdoorEnvs:       RootBackdoorEnvs(),
			// Read off the policy rather than written as []string{}, so
			// this goes red if the policy ever starts conceding one.
			AllowedRootBackdoorEnvs: emptyIfNil(ZeroSignalComposePolicy().AllowedRootBackdoorEnvs),
			TrustedOSImages:         TrustedDstackOSImages(),
		},
		Skeletons: buildSkeletonVectors(t, release),
		Documents: buildDocumentVectors(t, release, policies),
	}
	return v
}

// commentedRelease is realisticCompose with comments, which the shared fixture
// deliberately has none of.
//
// It exists because the published compose is mostly prose — the deploy command,
// the rationale, the warnings — and a fixture with no comment lines cannot
// express "an operator edited one". Kept local to the vectors rather than added
// to realisticCompose: that fixture's digest is pinned by name in both
// languages, so commenting it would churn every skeleton in this file to test
// something none of those cases are about.
//
// Mutators run over the assembled text so a case says WHICH edit it makes
// rather than restating the whole document.
func commentedRelease(image, config string, edits ...func(string) string) string {
	out := "# ZeroSignal node — the published release compose.\n" +
		"# Every byte of this file is measured, and that includes this line.\n" +
		"services:\n" +
		"  zs-node:\n" +
		"    # Pinned by digest, never a tag: a tag would let the image move\n" +
		"    # under a compose_hash that did not.\n" +
		"    image: " + image + "\n" +
		"    volumes:\n" +
		"      # Without this the node mints nothing.\n" +
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
	for _, e := range edits {
		out = e(out)
	}
	return out
}

// dropComment removes one whole comment line — the tidy-up edit.
func dropComment(s string) string {
	return strings.Replace(s, "      # Without this the node mints nothing.\n", "", 1)
}

// rewordComment keeps the line and changes its text, so line count and
// structure are identical and only the bytes differ.
func rewordComment(s string) string {
	return strings.Replace(s,
		"# Without this the node mints nothing.",
		"# Required: the guest-agent socket.", 1)
}

func buildSkeletonVectors(t *testing.T, release string) []skeletonVector {
	t.Helper()

	// The two codepoints where Go's and JS's built-in whitespace notions
	// disagree, computed rather than written — see compose_unicode_test.go.
	nel, bom := string(rune(0x0085)), string(rune(0xFEFF))

	cases := []struct{ name, why, compose string }{
		{"release", "the published shape, unmodified", release},
		{
			"different_config",
			"a second operator's config must produce the SAME skeleton — that is the design",
			realisticCompose(realImage, "        zs:\n          operator_id: 99\n"),
		},
		{
			"different_image",
			"a different release must produce the same skeleton and a different image ref",
			realisticCompose("ghcr.io/txnlab/zs-node@sha256:"+
				"2222222222222222222222222222222222222222222222222222222222222222", someConfig),
		},
		{
			"host_bind_mount",
			"forbidden by construction: text the release compose does not contain",
			release[:len(release)-len("volumes:\n  zs-node-state: {}\n")] +
				"    volumes:\n      - /:/host\nvolumes:\n  zs-node-state: {}\n",
		},
		{
			"comment_added",
			"the comments are IN the skeleton — asserted in four doc copies and, before " +
				"this vector, by no test at all",
			"# a comment the release does not have\n" + release,
		},
		// The three cases above and below cover the direction an operator
		// actually meets, which `comment_added` does not: the published
		// compose is roughly 90% comments, so the realistic edit is trimming
		// or rewording one that is already there — and `realisticCompose`
		// carries none, so no fixture could model it. The distinction
		// matters because the operator docs promise the edit is caught, and
		// an operator who trims the header to tidy it up gets no error from
		// anything: the deploy succeeds, the node boots, its quote verifies,
		// and payers quietly route elsewhere.
		{
			"commented_release",
			"the baseline for the two below — a release shape that HAS comments to edit",
			commentedRelease(realImage, someConfig),
		},
		{
			"comment_deleted",
			"an operator trimming a comment they thought was decoration",
			commentedRelease(realImage, someConfig, dropComment),
		},
		{
			"comment_reworded",
			"same line count, different text: the digest is over bytes, not structure",
			commentedRelease(realImage, someConfig, rewordComment),
		},
		{
			"comment_in_config_block",
			"the ONE comment that must NOT move the digest — it is inside the span a " +
				"verifier lifts out, so it is the operator's to edit freely",
			commentedRelease(realImage, someConfig+"          # a note to myself\n"),
		},
		{
			"nel_in_config_block",
			"U+0085 ends the block scalar for both languages, or it does not for either",
			realisticCompose(realImage, someConfig+nel+"\n"),
		},
		{
			"bom_in_config_block",
			"U+FEFF, the same in the other direction",
			realisticCompose(realImage, someConfig+bom+"\n"),
		},
		{
			"nel_after_image",
			"trailing U+0085 must not be trimmed off the reference in either language",
			realisticCompose(realImage+nel, someConfig),
		},
		{
			"bom_after_image",
			"trailing U+FEFF, likewise",
			realisticCompose(realImage+bom, someConfig),
		},
		{"tab_indent", "refused: YAML forbids it and it makes 'deeper' ambiguous",
			"services:\n\tzs-node:\n    image: " + realImage + "\n"},
		{"no_image", "refused: a compose naming no image measures nothing",
			"services:\n  zs-node:\n    restart: always\n"},
		{"two_identical_images",
			"the FIRST image is lifted and the second stays literal — so the two " +
				"languages must agree on which one is the reference AND on the " +
				"bytes of the one they left behind",
			"services:\n  a:\n    image: " + realImage +
				"\n  b:\n    image: " + realImage + "\n"},
		{"sidecar_distinct_images",
			"the sealed_local shape: two DIFFERENT images, so a language that " +
				"lifted the wrong one produces a different ref AND a different " +
				"skeleton, which the same-image case above cannot distinguish",
			sidecarCompose(realImage, engineImage)},
		{"sidecar_engine_swapped",
			"same document, different engine digest — pinned by a RELATION to " +
				"sidecar_distinct_images, since 'the engine is part of the " +
				"measured artifact' is otherwise asserted only by the staleness diff",
			sidecarCompose(realImage, otherEngineImage)},
		{"sidecar_reordered",
			"the engine listed first: the lifted ref becomes the ENGINE's (which " +
				"no node release list contains) and the structure moves with it",
			sidecarCompose(engineImage, realImage)},
		{"sidecar_substituted_image", "refused: a `${VAR}` second image is pinned by " +
			"nothing — dstack hashes this document BEFORE expansion, so one skeleton " +
			"digest would cover every engine the operator later supplies",
			sidecarCompose(realImage, "${ENGINE_IMAGE}")},
		{"sidecar_tagged_image", "refused: a tag is mutable, so the same skeleton " +
			"digest covers whatever the registry serves under it tomorrow",
			sidecarCompose(realImage, "ghcr.io/ardanlabs/kronk:latest-cuda")},
		{"engine_config",
			"the THIRD lifted span: the engine's own config, so two operators on " +
				"different hardware can size it differently and still match one release",
			engineConfigCompose(someEngineConfig)},
		{"engine_config_varied",
			"a different engine config must produce the SAME skeleton as engine_config " +
				"— pinned by that RELATION, which is the whole reason the span is lifted",
			engineConfigCompose("      unsloth/gemma-4-31B-it-BF16:\n" +
				"        context-window: 131072\n        swa-full: false\n")},
		{"engine_config_foreign_content",
			"a `content:` under a DIFFERENT entry is NOT lifted — `content` is the " +
				"compose spec's fixed key, so lifting it on sight would put any future " +
				"config entry's body outside the measurement in one language only",
			"configs:\n  some-other-config:\n    content: |\n      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n"},
		{"engine_config_disarmed",
			"the sentinel followed by an intervening KEY: the later `content:` is " +
				"ordinary text, so the arming window must close on the next " +
				"non-blank line in both languages",
			"configs:\n  zs-engine-config:\n    file: ./x.yaml\n    content: |\n" +
				"      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n"},
		// The other half of that rule, and the one nothing pinned: a BLANK line
		// is not an intervening key, so it must NOT close the window. Both
		// languages held the window open across it and neither suite noticed
		// when that stopped — and with EnforceComposeSkeleton off, the content
		// rule is the only thing reading this document, so a closed window
		// there turns the adapter/template refusal off entirely. Pinned as a
		// RELATION between the next two, because the blank line is itself
		// measured text and these cannot share a digest with engine_config.
		{"engine_config_blank_line",
			"a blank line between the sentinel and `content:` must leave the span " +
				"lifted — see engine_config_blank_line_varied for the assertion",
			engineConfigComposeBlankLine(someEngineConfig)},
		{"engine_config_blank_line_varied",
			"the same document with a different engine config: it must produce the " +
				"SAME skeleton as engine_config_blank_line, which is what proves one " +
				"blank line did not silently close the arming window",
			engineConfigComposeBlankLine("      m:\n        context-window: 131072\n")},
		{"engine_config_content_at_sentinel_indent",
			"a `content:` at the sentinel's OWN indent is a sibling entry, not that " +
				"entry's body, so it must not be lifted — the depth test is strictly " +
				"deeper, and a `<` there measured a document TS and Go disagreed about",
			"configs:\n  zs-engine-config:\n  content: |\n      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n"},
		{"engine_config_sentinel_carries_a_value",
			"a sentinel with a value after the colon is not the mapping this lifts, " +
				"so the arming must not fire and the following `content:` stays " +
				"measured — dropping that check let a `privileged: true` out of the " +
				"skeleton in one language only",
			"configs:\n  zs-engine-config: something\n    content: |\n" +
				"      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n"},
		// The five below are cheap and they are the ONLY mechanism that can
		// catch a Go↔TS divergence in the pin rule: the per-language unit tests
		// each assert their own implementation, so a TS "fix" accepting
		// uppercase (a registry returned it that way, say) turns nothing red.
		// Case-folding and length are exactly where two hand-rolled
		// implementations drift, and length is where Go's bytes and TS's UTF-16
		// code units could disagree in principle.
		{"sidecar_uppercase_digest", "refused: lowercase only, or one reference " +
			"spelled two ways yields two skeletons — and this is the rule most " +
			"likely to be relaxed independently in one language",
			sidecarCompose(realImage, "ghcr.io/ardanlabs/kronk@sha256:"+
				strings.ToUpper("2222222222222222222222222222222222222222222222222222222222222222"[:32])+
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		{"sidecar_long_digest", "refused: 65 hex characters. Every other refusal " +
			"fixture here is too SHORT, so the upper bound was unpinned — and it " +
			"is the bound whose two implementations count different units",
			sidecarCompose(realImage, "ghcr.io/ardanlabs/kronk@sha256:"+
				strings.Repeat("a", 65))},
		{"sidecar_bare_repository", "refused: no digest at all",
			sidecarCompose(realImage, "ghcr.io/ardanlabs/kronk")},
		{"sidecar_empty_repository", "refused: the repository half is empty, so " +
			"the reference names bytes without saying where they come from",
			sidecarCompose(realImage, "@sha256:"+strings.Repeat("a", 64))},
		{"sidecar_wrong_algorithm", "refused: sha512 is not the algorithm the " +
			"rule names, and a well-formed digest of the wrong kind is the shape " +
			"a lenient prefix check waves through",
			sidecarCompose(realImage, "ghcr.io/ardanlabs/kronk@sha512:"+
				strings.Repeat("a", 64))},
		{"sidecar_interpolated_repository", "refused: the digest half is literal, " +
			"so this DOES content-address the bytes — it is refused because the " +
			"rule is spelled `<repository>@sha256:<hex>` and no registry accepts " +
			"`${` in a repository name. Pins that `${VAR}` is rejected wherever " +
			"it appears, not only when it covers the whole reference.",
			sidecarCompose(realImage, "${ENGINE_REPO}@sha256:"+strings.Repeat("2", 64))},
	}

	out := make([]skeletonVector, 0, len(cases))
	for _, c := range cases {
		sv := skeletonVector{Name: c.name, Why: c.why, DockerCompose: c.compose}
		skel, ref, err := ExtractComposeSkeleton(c.compose)
		if err != nil {
			sv.ErrorCode = skeletonErrorCode(err)
			if sv.ErrorCode == "" {
				t.Fatalf("%s: unmapped skeleton error %v", c.name, err)
			}
		} else {
			sv.SkeletonHex = ComposeSkeletonDigest(skel)
			sv.ImageRef = ref
		}
		out = append(out, sv)
	}
	return out
}

// skeletonErrorCode maps a sentinel to the stable string the vectors carry.
// The sentinels are Go values; TS raises a ComposeSkeletonError with a `code`.
// This is the one place the two vocabularies are joined, so a new sentinel
// without a code fails loudly here rather than serializing as "".
func skeletonErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrComposeTabIndent):
		return "tab_indent"
	case errors.Is(err, ErrComposeNoImage):
		return "no_image"
	case errors.Is(err, ErrComposeUnpinnedSidecar):
		return "unpinned_sidecar"
	default:
		return ""
	}
}

func buildDocumentVectors(t *testing.T, release string, policies map[string]ComposePolicy) []documentVector {
	t.Helper()

	doc := func(fields string) string {
		return `{"manifest_version":2,"runner":"docker-compose",` + fields + `}`
	}
	composeField := func(c string) string {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal compose: %v", err)
		}
		return `"docker_compose_file":` + string(b)
	}

	nel, bom := string(rune(0x0085)), string(rune(0xFEFF))

	cases := []struct{ name, why, appCompose, policy string }{
		{
			"release_under_shared_policy",
			"the shape a real node publishes: clean under the shipped policy",
			doc(composeField(release) + `,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"release_under_enforced_policy",
			"the same, with the per-release lists populated — the state this is all for",
			doc(composeField(release) + `,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"enforced",
		},
		{
			"release_under_closed_policy",
			"enforcement on with EMPTY lists must refuse, never wave through",
			doc(composeField(release) + `,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"closed",
		},
		{
			"sidecar_under_enforced_policy",
			"the sealed_local shape all the way through check(), not just through the " +
				"extractor: a digest-pinned engine is CLEAN under its own release lists",
			doc(composeField(sidecarCompose(realImage, engineImage)) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"sidecar_enforced",
		},
		{
			"sidecar_engine_swapped_under_enforced_policy",
			"the half that makes the vector above mean something: swap ONLY the engine " +
				"and the same policy must refuse. An implementation that ignored the " +
				"second image entirely passes the clean vector and fails this one.",
			doc(composeField(sidecarCompose(realImage, otherEngineImage)) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"sidecar_enforced",
		},
		{
			"sidecar_unpinned_engine_under_enforced_policy",
			"a tagged engine cannot be preserved into a skeleton, so it must refuse at " +
				"the extractor rather than reaching a digest comparison at all",
			doc(composeField(sidecarCompose(realImage, "ghcr.io/ardanlabs/kronk:latest-cuda")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"sidecar_enforced",
		},
		{
			"engine_config_sizing_only",
			"the lifted span used as intended: pure sizing keys are CLEAN, or the " +
				"third span would be a ban on itself",
			doc(composeField(engineConfigCompose(someEngineConfig)) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_declares_adapters",
			"a LoRA adapter changes what the model SAYS while the weights digest keeps " +
				"reporting a byte-perfect match, so the payer's policy must refuse it — " +
				"the node-side check protects an honest operator and no payer",
			doc(composeField(engineConfigCompose(
				"      m:\n        context-window: 4096\n        adapters:\n          - id: x\n")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_declares_template_in_flow_style",
			"the same refusal reached through flow style, which a start-of-line scan " +
				"misses — and a miss here is invisible to every other check in the chain",
			doc(composeField(engineConfigCompose(
				"      m: {context-window: 4096, template: /kronk/jinja/mine.jinja}\n")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_declares_adapters_uppercase",
			"the key match is CASE-FOLDED, and only Go said so: YAML keys are " +
				"case-sensitive to a loader, but this is a refusal rule rather than a " +
				"parser, so the near-miss spelling has to refuse too — dropping the fold " +
				"in TS alone had the proxy refuse this node and the client admit it",
			doc(composeField(engineConfigCompose(
				"      m:\n        ADAPTERS:\n          - id: x\n")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_blank_line_declares_adapters",
			"the content rule must reach a span the sentinel armed across a BLANK " +
				"line — the skeleton pair proves the span is still lifted, this proves " +
				"the rule still reads it, and with EnforceComposeSkeleton off that rule " +
				"is the only thing reading this document at all",
			doc(composeField(engineConfigComposeBlankLine(
				"      m:\n        adapters:\n          - id: evil\n")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_decoy_in_node_config",
			"THE ATTACK THE PARALLEL WALK ALLOWED: a decoy `zs-engine-config:` planted " +
				"in the operator-authored NODE_CONFIG_YAML body, which is itself lifted, " +
				"so the skeleton digest is byte-identical to the honest release while a " +
				"scan that re-walked the document latched onto the decoy and never " +
				"reached the real span. Both languages must still refuse.",
			doc(composeField(engineConfigComposeWithNodeConfig(
				"        zs:\n          operator_id: 1\n"+
					"        zs-engine-config:\n          content: |\n            harmless: true\n",
				"      m:\n        adapters:\n          - id: evil\n")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_second_span",
			"the walk lifts EVERY engine span, so a scan stopping at the first left the " +
				"rest outside both the measurement and the rule",
			doc(composeField(engineConfigCompose(someEngineConfig)+
				"  "+ComposeEngineConfigKey+":\n    content: |\n"+
				"      m2:\n        adapters:\n          - id: evil\n") +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_evades_key_position",
			"a space before the colon is valid YAML and walked straight through a scan " +
				"that matched key POSITIONS; enumerating those means enumerating YAML, " +
				"which is what this package refuses to do in front of a security question",
			doc(composeField(engineConfigCompose("      m:\n        adapters : [x]\n")) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"engine_config_malformed_is_a_violation",
			"a tab anywhere used to make the content rule report 'no span' and produce " +
				"nothing — and with EnforceComposeSkeleton off it is the only rule " +
				"reading this document, so failing open there failed open entirely",
			doc(composeField(strings.Replace(
				engineConfigCompose("      m:\n        adapters:\n          - id: evil\n"),
				"        zs:\n", "\tzs:\n", 1)) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"zerosignal",
		},
		{
			"sidecar_reordered_under_enforced_policy",
			"SPEC §5 says a reorder is refused TWICE OVER — it moves the skeleton AND " +
				"hands the release-image check the engine's reference. Asserted only at " +
				"the extractor until now; this is the vector that would catch a check() " +
				"which skipped the image comparison on a multi-image document.",
			doc(composeField(sidecarCompose(engineImage, realImage)) +
				`,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"sidecar_enforced",
		},
		{
			"empty_compose",
			"the vacuous-measurement shape: a well-formed hash over nothing",
			doc(`"docker_compose_file":""`),
			"zerosignal",
		},
		{
			"whitespace_only_compose",
			"the same, spelled with spaces",
			doc(`"docker_compose_file":"   "`),
			"zerosignal",
		},
		{
			"nel_only_compose",
			"THE FAIL-OPEN THAT SHIPPED: space to Go, content to JS. Whatever the " +
				"verdict is, it must be the same one in both.",
			doc(`"docker_compose_file":"` + nel + `"`),
			"zerosignal",
		},
		{
			"bom_only_compose",
			"the same, in the other direction",
			doc(`"docker_compose_file":"` + bom + `"`),
			"zerosignal",
		},
		{
			"root_backdoor_env",
			"an operator-held root credential — unconditional, fires under any policy",
			doc(composeField(release) + `,"allowed_envs":["DSTACK_AUTHORIZED_KEYS"]`),
			"empty",
		},
		{
			"config_override_env",
			"the unmeasured channel used as a config override: applyEnv runs AFTER the " +
				"measured document is unmarshalled",
			doc(composeField(release) + `,"allowed_envs":["NODE_LLM_OPENAI_BASE_URL"]`),
			"zerosignal",
		},
		{
			"mnemonic_suffix_allowed",
			"the one secret channel a policy cannot enumerate: an operator-chosen prefix",
			doc(composeField(release) + `,"allowed_envs":["OPERATOR_SIGNING_MNEMONIC"]`),
			"zerosignal",
		},
		{
			"unknown_boot_hook",
			"operator-authored bash running as root before the container",
			doc(composeField(release) + `,"pre_launch_script":"#!/bin/sh\necho hi\n"`),
			"zerosignal",
		},
		{
			"unknown_top_level_field",
			"a dstack release adding a field no rule covers must not ride through clean",
			doc(composeField(release) + `,"some_future_channel":"x"`),
			"zerosignal",
		},
		{
			"wrong_manifest_version",
			"a document shaped for a different dstack generation",
			`{"manifest_version":1,"runner":"docker-compose",` + composeField(release) + `}`,
			"zerosignal",
		},
		{
			"wrong_runner",
			"not docker-compose at all",
			`{"manifest_version":2,"runner":"bare","` +
				`docker_compose_file":"services: {}\n"}`,
			"zerosignal",
		},
		{
			"local_key_provider",
			"the one toggle pinned on evidence rather than taste",
			doc(composeField(release) + `,"local_key_provider_enabled":true`),
			"zerosignal",
		},
		{
			"unparseable_compose_under_enforcement",
			"extraction FAILURE must record a violation, never skip the check — the " +
				"shape that would let an operator disable it by writing a compose we " +
				"cannot read",
			doc(composeField("services:\n\tzs-node:\n    image: " + realImage + "\n")),
			"enforced",
		},
		{
			"substituted_image_under_enforcement",
			"image: ${VAR} — a stable compose_hash over arbitrary code, the attack the " +
				"whole skeleton design exists to answer",
			doc(composeField(realisticCompose("${NODE_IMAGE}", someConfig))),
			"enforced",
		},
		{
			"allowed_features",
			"the features a real dstack deployment declares — kms and the gateway",
			doc(composeField(release) + `,"features":["kms","tproxy-net"]`),
			"zerosignal",
		},
		{
			"disallowed_feature",
			"a dstack feature switch this policy does not permit. Was UNREADABLE before " +
				"the rule existed: `features` was listed in knownAppComposeFields, which " +
				"suppressed unknown_field, and no rule read the value.",
			doc(composeField(release) + `,"features":["kms","some-future-switch"]`),
			"zerosignal",
		},
		{
			"wrong_storage_fs",
			"the encrypted-FS backend, likewise modelled and unread until now",
			doc(composeField(release) + `,"storage_fs":"btrfs"`),
			"storage",
		},
		{
			"misconfigured_verifier",
			"reference lists populated with the switch off: no check runs, and it looks " +
				"exactly like a build that meant to leave it off. The one violation here " +
				"that is about the verifier rather than the node.",
			doc(composeField(release) + `,"allowed_envs":["NODE_LLM_OPENAI_API_KEY"]`),
			"misconfigured",
		},
		{
			"malformed_json",
			"not a document at all",
			`{"manifest_version":`,
			"zerosignal",
		},
		{
			"json_null",
			"valid JSON, not an object",
			`null`,
			"zerosignal",
		},
	}

	out := make([]documentVector, 0, len(cases))
	for _, c := range cases {
		pol, ok := policies[c.policy]
		if !ok {
			t.Fatalf("%s: unknown policy %q", c.name, c.policy)
		}
		dv := documentVector{
			Name:       c.name,
			Why:        c.why,
			AppCompose: c.appCompose,
			Policy:     c.policy,
			Sealed:     true,
		}
		_, err := VerifyAppCompose(c.appCompose, sealed(c.appCompose), pol)
		switch {
		case err == nil:
		default:
			dv.ErrorCode, dv.Violations = classifyComposeErr(err)
		}
		out = append(out, dv)
	}
	return out
}

// classifyComposeErr reduces an error to the two things both languages agree
// about: a stable error code, and the sorted violation codes when it is a
// policy failure. Detail strings are deliberately excluded — they are prose
// and legitimately differ.
func classifyComposeErr(err error) (string, []string) {
	var pe *ComposePolicyError
	if errors.As(err, &pe) {
		codes := make([]string, 0, len(pe.Violations))
		for _, v := range pe.Violations {
			codes = append(codes, string(v.Code))
		}
		sort.Strings(codes)
		return "compose_policy", codes
	}
	switch {
	case errors.Is(err, ErrAppComposeMalformed):
		return "app_compose_malformed", nil
	case errors.Is(err, ErrComposeHashMismatch):
		return "compose_hash_mismatch", nil
	case errors.Is(err, ErrNoComposeHash):
		return "no_compose_hash", nil
	case errors.Is(err, ErrNoAppCompose):
		return "no_app_compose", nil
	default:
		return "unclassified:" + err.Error(), nil
	}
}

func TestComposeVectors(t *testing.T) {
	v := buildComposeVectors(t)

	// Self-checks on the fixture set itself. Each is a way the file could
	// be regenerated into something that pins nothing.
	var refusals, policyFails, clean int
	for _, s := range v.Skeletons {
		if s.ErrorCode != "" {
			refusals++
			continue
		}
		if s.SkeletonHex == "" || s.ImageRef == "" {
			t.Errorf("skeleton %q succeeded with an empty digest or image ref", s.Name)
		}
	}
	for _, d := range v.Documents {
		switch {
		case d.ErrorCode == "":
			clean++
		case d.ErrorCode == "compose_policy" && len(d.Violations) == 0:
			t.Errorf("document %q reports compose_policy with no violations", d.Name)
		default:
			policyFails++
		}
	}
	// A vector set that only refuses proves the rules fire; one that only
	// accepts proves they do not. Both directions have to be present or a
	// TS reader can pass by hard-coding one answer.
	if refusals == 0 || policyFails == 0 || clean == 0 {
		t.Fatalf("vectors are one-sided: %d skeleton refusals, %d document failures, "+
			"%d clean documents — all three must be non-zero", refusals, policyFails, clean)
	}

	// The design claims, stated as RELATIONS between vectors rather than as
	// independently pinned digests.
	//
	// Without these, every claim in this file rests on the staleness diff at
	// the bottom — which reports "the file is stale, regenerate", the same
	// weak signal for a deliberate fixture change and for a rule that died.
	// Worse, the documented recovery is to regenerate, so a broken rule gets
	// pinned as correct by an operator following the instructions. (TS would
	// still catch it, having its own implementation — but only on a run the
	// message can beg for and cannot compel.) A relation fails by NAME and
	// says which claim broke.
	skel := make(map[string]skeletonVector, len(v.Skeletons))
	for _, s := range v.Skeletons {
		skel[s.Name] = s
	}
	sameSkeleton := func(a, b, why string) {
		t.Helper()
		if skel[a].SkeletonHex != skel[b].SkeletonHex {
			t.Errorf("%s and %s must share a skeleton (%s), got %s vs %s",
				a, b, why, skel[a].SkeletonHex, skel[b].SkeletonHex)
		}
	}
	differentSkeleton := func(a, b, why string) {
		t.Helper()
		if skel[a].SkeletonHex == skel[b].SkeletonHex {
			t.Errorf("%s and %s must NOT share a skeleton (%s), both are %s",
				a, b, why, skel[a].SkeletonHex)
		}
	}
	differentImageRef := func(a, b, why string) {
		t.Helper()
		if skel[a].ImageRef == skel[b].ImageRef {
			t.Errorf("%s and %s must NOT share an image ref (%s), both are %q",
				a, b, why, skel[a].ImageRef)
		}
	}

	// The two spans an operator may vary. These are the whole template-match
	// design: vary either and you are still running the published release.
	sameSkeleton("release", "different_config",
		"a second operator's config must not change the workload's identity")
	sameSkeleton("release", "different_image",
		"the image ref is lifted out and checked against its own list")
	if skel["release"].ImageRef == skel["different_image"].ImageRef {
		t.Errorf("different_image must yield a different image ref; both are %q",
			skel["release"].ImageRef)
	}
	sameSkeleton("commented_release", "comment_in_config_block",
		"a comment INSIDE the config block is inside the lifted span")

	// The third span, same shape of claim. engine_config_varied has said "must
	// produce the SAME skeleton as engine_config" in its `why` since it was
	// written, and nothing asserted it — a `why` is a comment, and the staleness
	// diff only ever says "regenerate".
	sameSkeleton("engine_config", "engine_config_varied",
		"two operators sizing the engine differently are running one published release")
	sameSkeleton("engine_config_blank_line", "engine_config_blank_line_varied",
		"a blank line between the sentinel and `content:` must not close the arming "+
			"window — if it did, both bodies would be hashed in and these would differ")
	differentSkeleton("engine_config", "engine_config_blank_line",
		"the blank line is itself measured text, which is why the pair above is the "+
			"assertion and 'equals engine_config' would be the wrong one")

	// Everything else is forbidden by construction — it is text the release
	// compose does not contain.
	differentSkeleton("release", "comment_added", "comments are hashed")
	differentSkeleton("commented_release", "comment_deleted",
		"deleting a comment is an edit to the measured artifact")
	differentSkeleton("commented_release", "comment_reworded",
		"the digest is over bytes, not over structure")
	differentSkeleton("release", "host_bind_mount",
		"nothing enumerates bind mounts; they are absent text")

	// The sidecar rule. Both claims the godoc's safety argument rests on are
	// pinned here as RELATIONS rather than left to the staleness diff, which
	// only ever says "regenerate" — so an operator following that instruction
	// would pin a broken rule as correct.
	differentSkeleton("sidecar_distinct_images", "sidecar_engine_swapped",
		"the engine digest is literal, so swapping it is an edit to the measured artifact")
	differentSkeleton("sidecar_distinct_images", "sidecar_reordered",
		"reordering re-points the lifted ref, and the structure must move with it")
	differentImageRef("sidecar_distinct_images", "sidecar_reordered",
		"the FIRST image is the one checked against the node release list, so a "+
			"reorder hands that check the engine's reference instead")
	for _, d := range v.Documents {
		if strings.HasPrefix(d.ErrorCode, "unclassified:") {
			t.Errorf("document %q produced an error no code covers: %s", d.Name, d.ErrorCode)
		}
	}

	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	if *updateComposeVectors {
		if err := os.WriteFile(composeVectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", composeVectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", composeVectorsPath, len(got))
		return
	}

	want, err := os.ReadFile(composeVectorsPath)
	if err != nil {
		t.Fatalf("read %s (regenerate with -update-compose): %v", composeVectorsPath, err)
	}
	if string(want) != string(got) {
		// NAME THE PRODUCTION CONSTANT FIRST, because the generic advice below
		// is the WRONG advice for this case and following it pins the new value
		// as correct. A changed trust list and a changed generator shape look
		// identical in a byte comparison, and only one of them is fixed by
		// regenerating.
		var prev composeVectors
		if err := json.Unmarshal(want, &prev); err == nil {
			for _, f := range []struct {
				name, alsoIn string
				was, now     []string
			}{
				{"shared_policy.trusted_os_images",
					"client/src/operators/tee-allowlist.ts (TRUSTED_OS_IMAGES) and " +
						"node/internal/tee/dstackprobe.sh (ds_os_image_hash)",
					prev.SharedPolicy.TrustedOSImages, v.SharedPolicy.TrustedOSImages},
				{"shared_policy.root_backdoor_envs", "nothing else",
					prev.SharedPolicy.RootBackdoorEnvs, v.SharedPolicy.RootBackdoorEnvs},
				{"shared_policy.allowed_root_backdoor_envs",
					"nothing else — and a NON-EMPTY value here means our own node policy " +
						"started conceding a root shell, which it must never do",
					prev.SharedPolicy.AllowedRootBackdoorEnvs, v.SharedPolicy.AllowedRootBackdoorEnvs},
				{"shared_policy.pre_launch_script_digests", "nothing else",
					prev.SharedPolicy.PreLaunchScriptDigests, v.SharedPolicy.PreLaunchScriptDigests},
			} {
				if slices.Equal(f.was, f.now) {
					continue
				}
				t.Fatalf("%s MOVED — this is a production trust value, not a generator "+
					"shape change.\n  was: %v\n  now: %v\n\n"+
					"Do NOT regenerate unless you meant to change it. If you did, the same "+
					"change must update: %s.\nIf you did not, revert the Go constant — "+
					"regenerating here would pin the wrong value and every consumer would "+
					"then agree with it.", f.name, f.was, f.now, f.alsoIn)
			}
		}
		t.Fatalf("%s is stale.\n\nRegenerate:\n"+
			"  cd proto/go && go test ./attest -run TestComposeVectors -update-compose\n"+
			"  cd proto/ts && pnpm test\n\n"+
			"The TS run is not optional — the file is the input to BOTH suites, and "+
			"regenerating it without re-running TS is how a divergence gets pinned "+
			"as correct.", composeVectorsPath)
	}
}
