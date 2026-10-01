/*
 * Copyright (c) 2026. TxnLab Inc.
 * All Rights reserved.
 */

package attest

import (
	"slices"
	"strings"
	"testing"
)

// TestEngineConfigViolations_ScansExactlyTheLiftedSpans is the invariant the
// whole arrangement rests on: the text the content rule reads must be the text
// the skeleton stopped covering. Asserted against a document where the two CAN
// disagree, because on the happy path any implementation passes.
func TestEngineConfigViolations_ScansExactlyTheLiftedSpans(t *testing.T) {
	// A decoy sentinel inside the operator-authored NODE_CONFIG_YAML body.
	// That body is itself lifted, so planting this moves NOTHING the verifier
	// hashes — the skeleton digest below is identical to the honest one. A scan
	// that walked the document on its own latched onto the decoy and returned
	// clean while the real span declared a LoRA adapter.
	decoy := "        zs:\n          operator_id: 1\n" +
		"        zs-engine-config:\n          content: |\n            harmless: true\n"

	honest := engineConfigComposeWithNodeConfig(
		"        zs:\n          operator_id: 1\n", someEngineConfig)
	attack := engineConfigComposeWithNodeConfig(
		decoy, "      m:\n        adapters:\n          - id: evil\n")

	hs, _, err := ExtractComposeSkeleton(honest)
	if err != nil {
		t.Fatalf("extract honest: %v", err)
	}
	as, _, err := ExtractComposeSkeleton(attack)
	if err != nil {
		t.Fatalf("extract attack: %v", err)
	}
	if ComposeSkeletonDigest(hs) != ComposeSkeletonDigest(as) {
		t.Fatal("the two documents no longer share a skeleton digest, so this test no " +
			"longer exercises the case it was written for — the decoy must be invisible " +
			"to the measurement for the attack to be worth anything")
	}
	if got := EngineConfigViolations(attack); !slices.Contains(got, "adapters") {
		t.Errorf("a decoy sentinel in the NODE_CONFIG_YAML body hid a real adapter "+
			"declaration behind an unchanged skeleton digest; violations = %v", got)
	}
}

// TestEngineConfigViolations_ScansEverySpan covers the second disagreement: the
// walk lifts every engine span, so a scan that stopped at the first left the
// rest outside both the measurement and the rule.
func TestEngineConfigViolations_ScansEverySpan(t *testing.T) {
	doc := engineConfigCompose(someEngineConfig) +
		"  " + ComposeEngineConfigKey + ":\n    content: |\n" +
		"      m2:\n        adapters:\n          - id: evil\n"

	if got := EngineConfigViolations(doc); !slices.Contains(got, "adapters") {
		t.Errorf("a SECOND engine span was lifted but never scanned; violations = %v", got)
	}
}

// TestEngineConfigViolations_MalformedIsAViolation covers the third: a document
// the walk refuses used to report "no span", hence no violations. Under the
// shipped policy (EnforceComposeSkeleton false) this rule is the only one
// looking at the document, so failing open here failed open entirely.
func TestEngineConfigViolations_MalformedIsAViolation(t *testing.T) {
	// A single tab, in the operator's own config body, far from the span.
	doc := strings.Replace(
		engineConfigCompose("      m:\n        adapters:\n          - id: evil\n"),
		"        zs:\n", "\tzs:\n", 1)

	if got := EngineConfigViolations(doc); len(got) == 0 {
		t.Error("a tab anywhere in the document silenced the content rule entirely")
	}
}

func TestEngineConfigViolations_AbsentIsNotAViolation(t *testing.T) {
	// The CPU shape has no engine to configure, and every node predating the
	// feature has no span. Refusing those would de-route the fleet.
	if got := EngineConfigViolations(realisticCompose(realImage, someConfig)); got != nil {
		t.Errorf("a document with no engine config produced violations: %v", got)
	}
	if got := EngineConfigViolations(""); got != nil {
		t.Errorf("an empty document produced violations: %v", got)
	}
}

// TestEngineConfigViolations_RefusesBehaviourKeys is the security assertion.
// The evasion table is the review's, and every row is valid YAML that the
// previous position-based scan walked straight through.
func TestEngineConfigViolations_RefusesBehaviourKeys(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		want         string
	}{
		{"block style", "      m:\n        adapters:\n          - id: x\n", "adapters"},
		{"template", "      m:\n        template: /kronk/jinja/mine.jinja\n", "template"},
		{"flow style", "      m: {context-window: 4096, adapters: [{id: x}]}\n", "adapters"},
		{"quoted", "      m:\n        \"adapters\":\n          - id: x\n", "adapters"},
		// --- the evasions ---
		{"a space before the colon", "      m:\n        adapters : [x]\n", "adapters"},
		{"a tab before the colon", "      m:\n        adapters\t: [x]\n", "adapters"},
		{"a block-sequence entry", "      m:\n        - adapters: [x]\n", "adapters"},
		{"a flow sequence of pairs", "      m: [adapters: [x]]\n", "adapters"},
		{"an explicit key", "      m:\n        ? adapters\n        : [x]\n", "adapters"},
		{"uppercase", "      m:\n        ADAPTERS:\n          - id: x\n", "adapters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := EngineConfigViolations(engineConfigCompose(tc.config))
			if !slices.Contains(got, tc.want) {
				t.Errorf("did not refuse %s: violations = %v", tc.want, got)
			}
		})
	}
}

// TestEngineConfigViolations_AdmitsSizingKeys keeps the check from being a ban
// on the whole span. Every key here is why the span is lifted at all.
func TestEngineConfigViolations_AdmitsSizingKeys(t *testing.T) {
	cfg := "      unsloth/gemma-4-31B-it-BF16:\n" +
		"        context-window: 65536\n" +
		"        nseq-max: 2\n" +
		"        queue-depth: 2\n" +
		"        ngpu-layers: 40\n" +
		"        swa-full: false\n" +
		"        cache-type-k: q8_0\n" +
		"        cache-type-v: q8_0\n" +
		"        flash-attention: auto\n" +
		"        split-mode: layer\n" +
		"        admission-timeout: 30s\n"
	if got := EngineConfigViolations(engineConfigCompose(cfg)); got != nil {
		t.Errorf("refused a pure sizing config: %v", got)
	}
}

// TestEngineConfigForbiddenKeys_CannotBeEdited pins the rule against its own
// importers: a shared slice in a security gate is one append from being wrong
// for the whole process.
func TestEngineConfigForbiddenKeys_CannotBeEdited(t *testing.T) {
	got := EngineConfigForbiddenKeys()
	if len(got) == 0 {
		t.Fatal("no forbidden keys at all")
	}
	got[0] = "not-a-key"
	if EngineConfigForbiddenKeys()[0] == "not-a-key" {
		t.Error("editing the returned slice changed the rule for every later caller")
	}
}

// TestEngineConfigPolicy_IsNotGatedOnSkeletonEnforcement pins the one thing a
// reader is most likely to "tidy up": this rule is about the document's own
// content, so it must hold for a node pinned by whole-document hash too.
func TestEngineConfigPolicy_IsNotGatedOnSkeletonEnforcement(t *testing.T) {
	doc := engineConfigCompose("      m:\n        adapters:\n          - id: x\n")

	for _, enforce := range []bool{true, false} {
		p := ComposePolicy{EnforceComposeSkeleton: enforce}
		got, _ := p.check(&AppCompose{DockerCompose: doc}, nil)

		found := false
		for _, v := range got {
			if v.Code == ViolationEngineConfigKey {
				found = true
			}
		}
		if !found {
			t.Errorf("EnforceComposeSkeleton=%v: no engine_config_key violation; got %v",
				enforce, got)
		}
	}
}
