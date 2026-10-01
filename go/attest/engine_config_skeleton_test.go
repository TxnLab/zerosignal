/*
 * Copyright (c) 2026. TxnLab Inc.
 * All Rights reserved.
 */

package attest

import (
	"strings"
	"testing"
)

// engineConfigCompose is the sealed_local shape carrying an engine config as a
// compose top-level `configs:` entry. The sentinel name is structure; only the
// `content:` body is lifted.
func engineConfigCompose(engineConfig string) string {
	return engineConfigComposeWithNodeConfig(
		"        zs:\n          operator_id: 1\n", engineConfig)
}

// engineConfigComposeWithNodeConfig varies the NODE_CONFIG_YAML body too, so a
// test can plant something in the span an operator authors freely.
func engineConfigComposeWithNodeConfig(nodeConfig, engineConfig string) string {
	return "services:\n" +
		"  zs-node:\n" +
		"    image: " + realImage + "\n" +
		"    network_mode: \"service:kronk\"\n" +
		"    environment:\n" +
		"      NODE_CONFIG_YAML: |\n" +
		nodeConfig +
		"  kronk:\n" +
		"    image: " + engineImage + "\n" +
		"    environment:\n" +
		"      KRONK_POOL_MODEL_CONFIG_FILE: /etc/zs/engine.yaml\n" +
		"    configs:\n" +
		"      - source: zs-engine-config\n" +
		"        target: /etc/zs/engine.yaml\n" +
		"configs:\n" +
		"  zs-engine-config:\n" +
		"    content: |\n" +
		engineConfig
}

// engineConfigComposeBlankLine separates the sentinel from its `content:` key
// with a blank line. Valid YAML, and the shape that distinguishes "the window
// closes on the next line" from "the window closes on the next NON-BLANK line"
// — the second being what the walk implements, because a blank line is not a
// key and cannot be the intervening entry the window exists to stop on.
//
// It is worth a named helper because it is a hole, not a curiosity: if a blank
// line closed the window the span would stop being lifted, and with
// EnforceComposeSkeleton off the content rule is the ONLY thing reading this
// document — so one blank line would silently turn the adapter/template refusal
// off for the whole node.
func engineConfigComposeBlankLine(engineConfig string) string {
	return strings.Replace(engineConfigCompose(engineConfig),
		"  "+ComposeEngineConfigKey+":\n    content: |\n",
		"  "+ComposeEngineConfigKey+":\n\n    content: |\n", 1)
}

const someEngineConfig = "      unsloth/gemma-4-31B-it-BF16:\n" +
	"        context-window: 65536\n" +
	"        nseq-max: 2\n"

// TestEngineConfigSpanIsLifted is the whole point of the third span: two
// operators on different hardware must be able to size the engine differently
// and still match one published release.
func TestEngineConfigSpanIsLifted(t *testing.T) {
	base, _, err := ExtractComposeSkeleton(engineConfigCompose(someEngineConfig))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if strings.Contains(base, "context-window") {
		t.Error("the engine config leaked into the skeleton, so every hardware " +
			"variation would need its own published release")
	}

	other, _, err := ExtractComposeSkeleton(engineConfigCompose(
		"      unsloth/gemma-4-31B-it-BF16:\n" +
			"        context-window: 131072\n\n" + // blank line INSIDE the block
			"        swa-full: false\n" +
			"        ngpu-layers: 40\n"))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if other != base {
		t.Errorf("two engine configs of the same release produced different skeletons:\n%q\n%q",
			base, other)
	}
}

// TestEngineConfigStructureIsNotLifted is the inverse, and it is the half that
// keeps the lift honest. Everything that WIRES the config in — the sentinel
// name, the mount target, the env var pointing at it — is structure an operator
// may not vary, or the span could be redirected at a file nobody measured.
func TestEngineConfigStructureIsNotLifted(t *testing.T) {
	original := engineConfigCompose(someEngineConfig)
	base, _, err := ExtractComposeSkeleton(original)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	for _, tc := range []struct{ name, from, to string }{
		{"the sentinel name", "  zs-engine-config:\n", "  zs-other-config:\n"},
		{"the mount target", "target: /etc/zs/engine.yaml", "target: /etc/zs/evil.yaml"},
		{"the env pointing at it", "KRONK_POOL_MODEL_CONFIG_FILE: /etc/zs/engine.yaml",
			"KRONK_POOL_MODEL_CONFIG_FILE: /kronk/models/model_config.yaml"},
		{"the source reference", "- source: zs-engine-config", "- source: zs-engine-cfg2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(original, tc.from, tc.to, 1)
			if doc == original {
				t.Fatal("fixture did not vary — the assertion below would be vacuous")
			}
			got, _, err := ExtractComposeSkeleton(doc)
			if err != nil {
				return // a refusal is also "did not silently match"
			}
			if got == base {
				t.Errorf("changing %s did not move the skeleton", tc.name)
			}
		})
	}
}

// TestEngineConfigLiftRequiresTheSentinel pins the reason the lift is armed by
// an exact two-line shape rather than matching `content:` on sight. `content`
// is the compose spec's fixed key, so a bare match would exclude ANY future
// config entry's body from the measurement — a span nobody checks, which is
// precisely what the block walk must never create.
func TestEngineConfigLiftRequiresTheSentinel(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{
			name: "a content block under a different entry",
			doc: "configs:\n  some-other-config:\n    content: |\n" +
				"      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n",
		},
		{
			name: "a content block with no entry above it at all",
			doc: "services:\n  zs-node:\n    image: " + realImage + "\n" +
				"    content: |\n      privileged: true\n",
		},
		{
			name: "the sentinel disarmed by an intervening line",
			doc: "configs:\n  zs-engine-config:\n    file: ./x.yaml\n    content: |\n" +
				"      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n",
		},
		{
			name: "content at the same indent as the sentinel",
			doc: "configs:\n  zs-engine-config:\n  content: |\n" +
				"      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n",
		},
		{
			name: "the sentinel carrying a value rather than a mapping",
			doc: "configs:\n  zs-engine-config: something\n    content: |\n" +
				"      privileged: true\n" +
				"services:\n  zs-node:\n    image: " + realImage + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := ExtractComposeSkeleton(tc.doc)
			if err != nil {
				return
			}
			if strings.Contains(got, skeletonEngineConfigPlaceholder) {
				t.Error("lifted a content block that the sentinel did not arm — " +
					"its body is now outside the measurement")
			}
			// The smuggled directive must still be hashed as ordinary text.
			if !strings.Contains(got, "privileged: true") {
				t.Error("the body vanished from the skeleton without being a lifted span")
			}
		})
	}
}

// TestEngineConfigBlockWalkNeverOverruns is the "too many lines" direction,
// which is the only direction that is a hole: a compose directive swallowed
// into the lifted span is a directive no verifier ever sees.
func TestEngineConfigBlockWalkNeverOverruns(t *testing.T) {
	got, _, err := ExtractComposeSkeleton(engineConfigCompose(someEngineConfig) +
		"secrets:\n  leaked:\n    external: true\n")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"secrets:", "leaked:", "external: true"} {
		if !strings.Contains(got, want) {
			t.Errorf("the block walk swallowed %q, so it sits in a span nothing checks", want)
		}
	}
}
