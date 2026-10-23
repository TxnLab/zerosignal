/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The TypeScript twin of releases.go and osimages.go is GENERATED from them
// rather than appended to alongside. Two literal lists with two sets of release
// anchors would let a release land in one and not the other, and the only
// parity check available would be a test parsing the other language's source.
// Generating the twin makes the Go lists the single source: a stale twin fails
// this test on the very pull request that changed the Go list, instead of
// de-routing every node on a release only one SDK knew about.
//
// Regenerate: cd proto/go && go test ./attest -run TestTrustListTwinVectors -update-trust-lists
//
// zs-node's release-allowlist workflow has to run that command after it appends
// to releases.go, so the pull request it opens carries both files. Without that
// step, its pull request fails this test.
var updateTrustLists = flag.Bool("update-trust-lists", false,
	"regenerate proto/ts/src/attest/trust-lists.ts from the Go trust lists")

const trustListsTSPath = "../../ts/src/attest/trust-lists.ts"

func TestTrustListTwinVectors(t *testing.T) {
	want, err := renderTrustListsTS()
	if err != nil {
		t.Fatal(err)
	}

	if *updateTrustLists {
		if err := os.WriteFile(trustListsTSPath, []byte(want), 0o644); err != nil {
			t.Fatalf("write %s: %v", trustListsTSPath, err)
		}
		return
	}

	got, err := os.ReadFile(trustListsTSPath)
	if err != nil {
		t.Fatalf("read %s: %v", trustListsTSPath, err)
	}
	if string(got) != want {
		t.Fatalf("%s is stale against the Go trust lists; regenerate with:\n"+
			"  cd proto/go && go test ./attest -run TestTrustListTwinVectors -update-trust-lists",
			trustListsTSPath)
	}
}

// Values are written into single-quoted TypeScript literals unescaped, so a
// backslash would decode to a different string while the text comparison above
// still passed, and a quote would not compile. Every legitimate entry is a hex
// digest or an image reference, so anything outside that alphabet is refused.
var tsLiteralSafe = regexp.MustCompile(`^[0-9a-z@:/._-]+$`)

func renderTrustListsTS() (string, error) {
	lists := []struct {
		name   string
		values []string
	}{
		{"trustedComposeSkeletons", TrustedComposeSkeletons()},
		{"trustedNodeImages", TrustedNodeImages()},
		{"trustedDstackOSImages", TrustedDstackOSImages()},
	}
	for _, l := range lists {
		for _, v := range l.values {
			if !tsLiteralSafe.MatchString(v) {
				return "", fmt.Errorf("%s entry %q has a character the generator does not emit", l.name, v)
			}
		}
	}
	chains := TrustedDstackBootChains()
	for _, c := range chains {
		// Empty is legal here: it is an unmeasured row's registers.
		for _, v := range append([]string{c.OSImage, c.Name, c.MRTD, c.RTMR1, c.RTMR2}, c.RTMR0...) {
			if v != "" && !tsLiteralSafe.MatchString(v) {
				return "", fmt.Errorf("boot chain %s value %q has a character the generator does not emit", c.Name, v)
			}
		}
	}

	var b strings.Builder
	b.WriteString(`/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// GENERATED from proto/go/attest/releases.go and bootchain.go. Do not edit.
//
// The Go lists are the single source. Regenerate with:
//   cd proto/go && go test ./attest -run TestTrustListTwinVectors -update-trust-lists
//
// Each function returns a fresh array, as the Go functions return a fresh
// slice: callers append to these when they build a policy, and a shared backing
// array would let one embedder's change reach the next.
`)
	for _, l := range lists {
		writeTSList(&b, l.name, l.values)
	}
	writeTSBootChains(&b, chains)
	return b.String(), nil
}

func writeTSBootChains(b *strings.Builder, chains []BootChain) {
	b.WriteString(`
/**
 * One trusted dstack image's boot measurements. Mirrors Go's attest.BootChain;
 * a row with empty registers is trusted but not yet measured, and refused.
 */
export interface BootChain {
    osImage: string
    name: string
    mrtd: string
    rtmr1: string
    rtmr2: string
    /** One value per measured instance shape. */
    rtmr0: string[]
}

export function trustedDstackBootChains(): BootChain[] {
    return [
`)
	for _, c := range chains {
		b.WriteString("        {\n")
		for _, f := range []struct{ k, v string }{
			{"osImage", c.OSImage}, {"name", c.Name}, {"mrtd", c.MRTD}, {"rtmr1", c.RTMR1}, {"rtmr2", c.RTMR2},
		} {
			fmt.Fprintf(b, "            %s: '%s',\n", f.k, f.v)
		}
		if len(c.RTMR0) == 0 {
			b.WriteString("            rtmr0: [],\n")
		} else {
			b.WriteString("            rtmr0: [\n")
			for _, v := range c.RTMR0 {
				fmt.Fprintf(b, "                '%s',\n", v)
			}
			b.WriteString("            ],\n")
		}
		b.WriteString("        },\n")
	}
	b.WriteString("    ]\n}\n")
}

func writeTSList(b *strings.Builder, name string, values []string) {
	fmt.Fprintf(b, "\nexport function %s(): string[] {\n    return [\n", name)
	for _, v := range values {
		fmt.Fprintf(b, "        '%s',\n", v)
	}
	b.WriteString("    ]\n}\n")
}
