/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// prelaunchDir holds the pre-launch scripts captured off real CVMs, one file
// per script, named for the version it self-identifies as. The v0.0.19 script
// is NOT here: it lives inside ds_info.json, because the replay tests need it
// attached to the quote that measured it, and a second copy would be a second
// thing to keep in step.
const prelaunchDir = "../../testdata/attest"

// knownPreLaunchScripts returns digest → (byte length, where it came from) for
// every pre-launch script this repo actually holds.
func knownPreLaunchScripts(t *testing.T) map[string]struct {
	bytes  int
	origin string
} {
	t.Helper()
	out := map[string]struct {
		bytes  int
		origin string
	}{}

	add := func(script, origin string) {
		if script == "" {
			return
		}
		sum := sha256.Sum256([]byte(script))
		out[hex.EncodeToString(sum[:])] = struct {
			bytes  int
			origin string
		}{len(script), origin}
	}

	var doc AppCompose
	if err := json.Unmarshal([]byte(loadAppCompose(t)), &doc); err != nil {
		t.Fatalf("parse capture: %v", err)
	}
	add(doc.PreLaunchScript, filepath.Base(infoPath))

	files, err := filepath.Glob(filepath.Join(prelaunchDir, "prelaunch_*.txt"))
	if err != nil {
		t.Fatalf("glob %s: %v", prelaunchDir, err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		add(string(raw), filepath.Base(f))
	}
	return out
}

// TestPhalaPreLaunchDigests_EveryEntryHasItsScript is the executable form of
// the rule PhalaPreLaunchDigests' own doc states: "an entry must come from a
// script someone has actually read."
//
// Nothing else enforces it. TestPreLaunchScript_PinnedByDigest asserts the
// direction that matters for the ONE capture in testdata — that the list
// accepts it — and is satisfied no matter what else the list holds. So a
// second entry could be 64 random hex characters, or a digest someone read off
// a support ticket, and every test in this package would stay green while the
// list blessed 17KB of root-privileged bash nobody in this repo has seen.
//
// Adding a digest therefore means adding its script to testdata. That is the
// intended cost: the script is the artifact under review, the digest is only
// its name.
func TestPhalaPreLaunchDigests_EveryEntryHasItsScript(t *testing.T) {
	known := knownPreLaunchScripts(t)
	for _, digest := range PhalaPreLaunchDigests() {
		got, ok := known[digest]
		if !ok {
			t.Errorf("PhalaPreLaunchDigests() blesses %s, but no script in %s hashes to it — "+
				"the script it names cannot be read from this repo, so nobody reviewing "+
				"this list can check what it grants", digest, prelaunchDir)
			continue
		}
		t.Logf("%s  %d bytes  (%s)", digest, got.bytes, got.origin)
	}
}

// TestPhalaPreLaunchDigests_ScriptSizesAreWhatTheDocClaims pins the byte counts
// the doc comment quotes, because a truncated or newline-mangled fixture still
// produces a perfectly well-formed digest — it just isn't the one any CVM
// measures, and the test above would then fail pointing at the list rather than
// at the fixture that actually moved.
func TestPhalaPreLaunchDigests_ScriptSizesAreWhatTheDocClaims(t *testing.T) {
	want := map[string]int{
		"cec8f68ce6185b912023d886bba20cd06386dd9751af904e6107e758b9d68983": 17059, // v0.0.19
		"982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8": 17569, // v0.0.20
	}
	known := knownPreLaunchScripts(t)
	for digest, size := range want {
		got, ok := known[digest]
		if !ok {
			t.Errorf("no script in %s hashes to %s", prelaunchDir, digest)
			continue
		}
		if got.bytes != size {
			t.Errorf("%s is %d bytes, want %d (%s)", digest, got.bytes, size, got.origin)
		}
	}
}

// TestPreLaunchFixturesAreDistinct stops two fixtures from silently becoming
// one — copying an existing script into a new file, or re-saving one over
// another, leaves a repo that LOOKS like it holds a script per digest.
//
// It counts SOURCES against distinct digests rather than digests against the
// blessed list, because those are different faults and the messages must not
// trade places: a duplicated fixture is a testdata mistake, while a blessed
// digest with no script is a review-process one, and the test above already
// names that second case precisely.
func TestPreLaunchFixturesAreDistinct(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(prelaunchDir, "prelaunch_*.txt"))
	if err != nil {
		t.Fatalf("glob %s: %v", prelaunchDir, err)
	}
	sources := len(files) + 1 // the standalone files, plus the ds_info.json capture
	if got := len(knownPreLaunchScripts(t)); got != sources {
		t.Errorf("%d pre-launch script sources collapse to %d distinct digests — "+
			"two of them carry the same bytes", sources, got)
	}
}
