/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import "testing"

func TestProtoVersionCompatible(t *testing.T) {
	tests := []struct {
		name  string
		other string
		want  bool
	}{
		// Written against the constant, so the "same version" case
		// cannot quietly become a lower-minor case at the next bump —
		// which is what the hardcoded "current 9.1" here had already
		// become by 9.6.
		{"same exact (whatever this build advertises)", ProtoVersion, true},
		{"same major, lower minor (9.0 stays relay-eligible)", "9.0", true},
		// A minor no build has reached, so this stays a HIGHER minor
		// however far the constant moves inside major 9.
		{"same major, higher minor", "9.999", true},
		{"same major, no minor", "9", true},
		{"same major with patch", "9.0.7", true},
		{"empty treated as legacy 1.0 — incompatible with 9.x", "", false},
		{"explicit legacy 1.0", "1.0", false},
		{"prior major (2.0)", "2.0", false},
		{"prior major (3.0) — dropped at the 4.0 operator/node-split cutover", "3.0", false},
		{"prior major (4.0) — dropped at the 5.0 usage-type / v2-tag cutover", "4.0", false},
		{"prior major (5.0) — dropped at the 6.0 ephemeral node_id / v3-tag cutover", "5.0", false},
		{"prior major (6.0) — dropped at the 7.0 hayai→zs transport-label rename", "6.0", false},
		{"prior major (7.0) — dropped at the 8.0 relay-metadata-minimization cutover", "7.0", false},
		{"prior major (8.1) — dropped at the 9.0 cached-token / v2-tag cutover", "8.1", false},
		{"different major higher", "10.0", false},
		{"non-numeric major", "vNext", false},
		{"negative major", "-1.0", false},
		{"garbage", "not-a-version", false},
		{"dot only", ".0", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProtoVersionCompatible(tc.other); got != tc.want {
				t.Fatalf("ProtoVersionCompatible(%q) = %v, want %v", tc.other, got, tc.want)
			}
		})
	}
}

// TestProtoVersionShape pins the documented invariants of the constant
// so a careless edit (e.g. removing the minor, switching to integer)
// fails loudly here rather than at the proxy/client filter.
func TestProtoVersionShape(t *testing.T) {
	if ProtoVersion == "" {
		t.Fatal("ProtoVersion must not be empty")
	}
	if _, ok := protoMajor(ProtoVersion); !ok {
		t.Fatalf("ProtoVersion %q must parse as <major>.<minor>", ProtoVersion)
	}
	if LegacyProtoVersion == "" {
		t.Fatal("LegacyProtoVersion must not be empty")
	}
}

func TestProtoVersionAtLeast(t *testing.T) {
	tests := []struct {
		name         string
		other, floor string
		want         bool
	}{
		{"equal", "9.1", "9.1", true},
		{"same major, higher minor", "9.2", "9.1", true},
		{"same major, lower minor", "9.0", "9.1", false},
		{"bare major reads as minor zero", "9", "9.1", false},
		{"bare major meets a bare-major floor", "9", "9.0", true},
		{"patch suffix ignored, minor still counts", "9.1.3", "9.1", true},
		{"patch suffix on a lower minor still fails", "9.0.9", "9.1", false},
		{"higher major wins regardless of minor", "10.0", "9.1", true},
		{"lower major loses regardless of minor", "8.9", "9.1", false},
		{"empty reads as legacy 1.0", "", "9.1", false},
		{"explicit legacy", "1.0", "9.1", false},
		// Fails closed on both sides — an unparseable peer must never be
		// treated as capable, or every garbage advertisement gets charged for
		// a header it was never asked to set.
		{"unparseable peer fails closed", "vNext", "9.1", false},
		{"negative peer fails closed", "-1.0", "9.1", false},
		{"non-numeric minor fails closed", "9.x", "9.1", false},
		{"unparseable floor fails closed", "9.1", "nope", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProtoVersionAtLeast(tc.other, tc.floor); got != tc.want {
				t.Fatalf("ProtoVersionAtLeast(%q, %q) = %v, want %v", tc.other, tc.floor, got, tc.want)
			}
		})
	}
}

func TestSetsRelayHopHeader(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{RelayHopHeaderMinVersion, true},
		{"9.1", true},
		{"9.2", true},
		{"10.0", true},
		{"9.1.4", true},
		// The whole un-upgraded fleet. A missing marker from any of these
		// proves nothing, and treating it as evidence would charge every relay
		// alive today for a header that did not exist when it shipped.
		{"9.0", false},
		{"9", false},
		{"8.1", false},
		{"1.0", false},
		{"", false},
		{"garbage", false},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			if got := SetsRelayHopHeader(tc.version); got != tc.want {
				t.Fatalf("SetsRelayHopHeader(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestPublishesAppCompose(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{AppComposeMinVersion, true},
		{"9.6", true},
		{"9.7", true},
		{"10.0", true},
		{"9.6.1", true},
		// The pre-9.6 dstack fleet. These nodes CANNOT publish the
		// preimage, so an absent app_compose says nothing about them —
		// and they still pass major-equality, so they are routable
		// peers a verifier meets in practice, not a hypothetical.
		{"9.5", false},
		{"9.0", false},
		{"9", false},
		{"8.1", false},
		{"1.0", false},
		{"", false},
		{"garbage", false},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			if got := PublishesAppCompose(tc.version); got != tc.want {
				t.Fatalf("PublishesAppCompose(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

// TestAppComposeGateCoversThisBuild pins the gate to the constant it
// gates on. A hand-typed min-version that drifted BELOW ProtoVersion
// would be inert (everything current passes) and one ABOVE it would
// make this build's own nodes read as withholding — neither shows up in
// the table above, which only ever tests literals.
func TestAppComposeGateCoversThisBuild(t *testing.T) {
	if !PublishesAppCompose(ProtoVersion) {
		t.Fatalf("PublishesAppCompose(ProtoVersion=%q) = false — this build's own "+
			"nodes would read as having withheld a document they do publish",
			ProtoVersion)
	}
	if PublishesAppCompose("9.5") {
		t.Fatal("the gate admits 9.5, the last version that could not publish the " +
			"preimage — every pre-feature dstack node would read as withholding it")
	}
}

// TestBootstrapProtoVersion_SameMajorMinorZero is the regression pin for the
// seeding trap. Callers seed an UNPROBED peer's proto_version so cold-start
// relay selection can bootstrap (privacy mode needs a relay to run the probe
// that learns the version). That seed must stay relay-ELIGIBLE while never
// implying a minor-gated CAPABILITY: seeding the full ProtoVersion would make
// every never-probed relay read as marker-capable and eat a strike on its
// first code-less 5xx.
func TestBootstrapProtoVersion_SameMajorMinorZero(t *testing.T) {
	seed := BootstrapProtoVersion()
	if !ProtoVersionCompatible(seed) {
		t.Fatalf("BootstrapProtoVersion() = %q must stay compatible with ProtoVersion %q — "+
			"an unprobed peer has to remain relay-eligible or cold start deadlocks", seed, ProtoVersion)
	}
	if SetsRelayHopHeader(seed) {
		t.Fatalf("BootstrapProtoVersion() = %q must NOT imply hop-marker support — "+
			"a node we have never probed cannot owe us a header", seed)
	}
	major, minor, ok := protoMajorMinor(seed)
	if !ok {
		t.Fatalf("BootstrapProtoVersion() = %q must parse", seed)
	}
	if minor != 0 {
		t.Fatalf("BootstrapProtoVersion() = %q must carry minor 0, got %d", seed, minor)
	}
	selfMajor, _, _ := protoMajorMinor(ProtoVersion)
	if major != selfMajor {
		t.Fatalf("BootstrapProtoVersion() major = %d, want %d (this build's major)", major, selfMajor)
	}
}
