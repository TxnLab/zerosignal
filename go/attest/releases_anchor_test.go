/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The markers zs-node's release-allowlist workflow inserts above. Spelled out
// here rather than referenced, because the point is to pin the literal text
// that another repository greps for.
var releaseListAnchors = []string{
	"zs-node-release-list: compose-skeletons",
	"zs-node-release-list: node-images",
}

// TestReleaseListAnchorsAreIntact keeps a cross-repo invariant failing in the
// repository that can actually break it.
//
// zs-node's release CI appends each new release's skeleton digest and image
// reference immediately above these markers, and it REFUSES rather than
// silently skipping when one is missing, duplicated, or no longer inside a list
// literal. That guard is correct but it lives in another repository and fires
// only when a node version tag is cut — so from here, a rename, a reorder, or a
// comment cleanup that drops an anchor leaves `go build`, `go vet` and this
// whole suite green, and surfaces days later as a blocked node release that
// nobody here connects to the edit.
//
// If you are deliberately restructuring these lists, update the anchors in
// zs-node's cmd/release-allowlist alongside, in the same change.
func TestReleaseListAnchorsAreIntact(t *testing.T) {
	lines := strings.Split(readReleases(t), "\n")

	for _, anchor := range releaseListAnchors {
		var at []int
		for i, line := range lines {
			if strings.Contains(line, anchor) {
				at = append(at, i)
			}
		}
		if len(at) != 1 {
			t.Errorf("marker %q appears %d times in releases.go, want exactly 1 — "+
				"zs-node's release-allowlist job refuses to insert against an "+
				"absent or ambiguous marker, so a node release cannot publish its "+
				"trust values until this is restored", anchor, len(at))
			continue
		}

		// Inside a list literal, not stranded in a neighbouring comment block
		// and not merely inside the enclosing FUNCTION. Both of those look
		// alike to a check that takes the nearest line ending in a brace: a
		// marker parked between `func … {` and its `return []string{` reads as
		// enclosed, and the insertion then emits a bare expression where a
		// statement belongs.
		open, ok := enclosingLiteral(lines, at[0])
		if !ok {
			t.Errorf("marker %q is not inside any literal, so an insertion there "+
				"would produce loose text", anchor)
			continue
		}
		if got := strings.TrimSpace(lines[open]); got != "return []string{" {
			t.Errorf("marker %q is not inside a list literal — its enclosing block "+
				"opens at line %d, %q — so an insertion there would produce an "+
				"expression where a statement belongs", anchor, open+1, got)
		}
	}
}

// enclosingLiteral returns the index of the line opening the literal that
// encloses the line at idx.
//
// IT WALKS BRACKET DEPTH RATHER THAN TAKING THE NEAREST OPENING LINE. A sibling
// literal that opens and closes above the marker is not an enclosure, so
// "nearest line ending in `{`" resolves to a block the marker is not in — which
// is how a marker moved into a list added between the two functions still read
// as belonging to the one above it.
//
// Counting brackets naively is sound only because of what this file's release
// lists hold: hex digests and image references, so no string literal among them
// carries a bracket, and comment lines are skipped.
func enclosingLiteral(lines []string, idx int) (int, bool) {
	depth := 0
	for i := idx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		d := 0
		for _, r := range lines[i] {
			switch r {
			case '[', '{':
				d++
			case ']', '}':
				d--
			}
		}
		switch {
		case d < 0:
			depth -= d
		case d > 0 && depth > 0:
			if depth -= d; depth < 0 {
				depth = 0
			}
		case d > 0:
			return i, true
		}
	}
	return 0, false
}

// TestReleaseListAnchorsSitInTheirLists pins WHICH lists the markers belong to.
// The test above would pass just as happily with both anchors in one list,
// which would silently send every image reference into the skeleton list —
// values that are never equal to a skeleton digest, so nothing would ever
// match and every node would be refused.
func TestReleaseListAnchorsSitInTheirLists(t *testing.T) {
	text := readReleases(t)

	for _, tc := range []struct {
		fn     string
		anchor string
	}{
		{"func TrustedComposeSkeletons() []string {", releaseListAnchors[0]},
		{"func TrustedNodeImages() []string {", releaseListAnchors[1]},
	} {
		start := strings.Index(text, tc.fn)
		if start < 0 {
			t.Errorf("%s not found — the release-allowlist workflow inserts into it", tc.fn)
			continue
		}
		end := strings.Index(text[start:], "\n}\n")
		if end < 0 {
			t.Errorf("could not find the end of %s", tc.fn)
			continue
		}
		if body := text[start : start+end]; !strings.Contains(body, tc.anchor) {
			t.Errorf("%s does not contain its marker %q", tc.fn, tc.anchor)
		}
	}
}

// Both lists land in config structs callers mutate, so an append through one
// result must not be visible in the next.
func TestReleaseLists_FreshSlicePerCall(t *testing.T) {
	for name, fn := range map[string]func() []string{
		"TrustedComposeSkeletons": TrustedComposeSkeletons,
		"TrustedNodeImages":       TrustedNodeImages,
		"TrustedDstackOSImages":   TrustedDstackOSImages,
	} {
		a := fn()
		if len(a) == 0 {
			t.Fatalf("%s is empty", name)
		}
		a[0] = "mutated"
		if b := fn(); slices.Contains(b, "mutated") {
			t.Errorf("%s shares its backing array between calls", name)
		}
	}
}

// An entry of the wrong shape can never match anything, so every node on that
// release is refused with nothing logged: a tag where a digest belongs, a
// value pasted into the other list, a truncated digest.
func TestReleaseLists_EntryShapes(t *testing.T) {
	seen := map[string]string{}
	check := func(list, v string) {
		if prev, ok := seen[v]; ok {
			t.Errorf("%q is in %s and again in %s", v, prev, list)
		}
		seen[v] = list
	}
	for _, d := range TrustedComposeSkeletons() {
		check("TrustedComposeSkeletons", d)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d) {
			t.Errorf("skeleton %q is not 64 lowercase hex, the shape ComposeSkeletonDigest returns", d)
		}
	}
	for _, ref := range TrustedNodeImages() {
		check("TrustedNodeImages", ref)
		if !strings.HasPrefix(ref, "ghcr.io/txnlab/zs-node@sha256:") || !isDigestPinnedRef(ref) {
			t.Errorf("image %q is not a digest-pinned ghcr.io/txnlab/zs-node reference, the only form a compose can carry", ref)
		}
	}
	for _, d := range TrustedDstackOSImages() {
		check("TrustedDstackOSImages", d)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(d) {
			t.Errorf("OS image %q is not 64 lowercase hex, the shape the replayed os-image-hash has", d)
		}
	}
}

// The listed skeletons are the digests of the composes zs-node released. The
// fixtures are zs-node's deploy/dstack templates at the tag in their names,
// copied verbatim (their image digest is a placeholder; the image is lifted out
// of the skeleton). Without them every check on these lists compares a list
// with itself, so a mistyped digest would pass.
func TestReleaseLists_SkeletonsOfReleasedComposes(t *testing.T) {
	skeletons := TrustedComposeSkeletons()
	for _, name := range []string{"zs-node-v0.25.0.yaml", "zs-node-gpu-v0.25.0.yaml"} {
		raw, err := os.ReadFile("testdata/release/" + name)
		if err != nil {
			t.Fatal(err)
		}
		skeleton, _, err := ExtractComposeSkeleton(string(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d := ComposeSkeletonDigest(skeleton); !slices.Contains(skeletons, d) {
			t.Errorf("%s has skeleton digest %s, which TrustedComposeSkeletons does not list", name, d)
		}
	}
}

func readReleases(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("releases.go")
	if err != nil {
		t.Fatalf("read releases.go: %v", err)
	}
	return string(raw)
}
