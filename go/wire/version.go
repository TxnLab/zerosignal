/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"strconv"
	"strings"
)

// ProtoVersion is the wire-protocol generation advertised by this build,
// in "<major>.<minor>" form. Two peers can interop iff their major
// versions match; minor differences are reserved for additive,
// backwards-compatible changes.
//
// This is a discovery / filtering signal — it is NOT a substitute for
// the cryptographic domain tags (AdmissionTagDomain, ticketSigningTag,
// receiptSigningTag) which are bumped independently when a signing or
// AEAD layout changes. A new major MAY but does not HAVE to bump a
// domain tag; bumping a domain tag SHOULD always bump the major.
//
// The companion field on the wire is the proto_version key in
// OperatorDetails (see proto/go/inject/details.go and SPEC.md §3c
// "Protocol version negotiation").
//
// What each generation changed — and why it was a major or a minor — is in
// proto/CHANGELOG.md. Add an entry there when you bump this.
const ProtoVersion = "9.10"

// LegacyProtoVersion is the value substituted for a missing
// proto_version field on the wire (nodes that predate the field). With
// ProtoVersion at "9.x", the substitution marks 1.0 (and pre-field)
// nodes as incompatible with 9.x callers — they can neither verify
// current-shape sigs nor relay/decrypt sealed reserves.
const LegacyProtoVersion = "1.0"

// ProtoVersionCompatible reports whether a peer-advertised proto_version
// string is compatible with this build's ProtoVersion. Compatibility is
// defined as major equality.
//
// Inputs:
//   - other: the peer's advertised proto_version. An empty string is
//     interpreted as LegacyProtoVersion ("1.0") per the rollout rule.
//
// Returns false if either side's version string cannot be parsed for a
// numeric major component.
func ProtoVersionCompatible(other string) bool {
	if other == "" {
		other = LegacyProtoVersion
	}
	selfMajor, ok := protoMajor(ProtoVersion)
	if !ok {
		return false
	}
	otherMajor, ok := protoMajor(other)
	if !ok {
		return false
	}
	return selfMajor == otherMajor
}

// protoMajor parses the major-version component of a "<major>.<minor>"
// (or bare "<major>") proto-version string. Patch suffixes ("1.0.3")
// are tolerated — only the segment before the first '.' is consulted.
// Uses the same strict segment parser as protoMajorMinor so
// ProtoVersionCompatible and ProtoVersionAtLeast can never disagree about what
// counts as a parseable version — and so both stay byte-identical to the TS
// port (see parseUintSegment on why strconv.Atoi alone is not enough).
func protoMajor(v string) (int, bool) {
	if v == "" {
		return 0, false
	}
	head := v
	if i := strings.IndexByte(v, '.'); i >= 0 {
		head = v[:i]
	}
	return parseUintSegment(head)
}

// protoMajorMinor generalizes protoMajor to the (major, minor) pair a
// minor-gated capability check needs: "9" → (9, 0), "9.1" → (9, 1),
// "9.1.3" → (9, 1) (a patch suffix is tolerated and ignored). A missing minor
// segment reads as 0, so a bare major and an explicit ".0" compare equal.
//
// Parsing is deliberately hand-rolled rather than strconv.Atoi, and the TS
// mirror must match it exactly. Atoi accepts a leading sign ("+9" parses as 9)
// while the TS regex does not, and JS's parseInt silently overflows a
// 20-digit number to a float while Atoi returns ErrRange — so the two ports
// disagreed in BOTH directions, and the JS direction failed OPEN (an absurd
// version read as capable), contradicting the fail-closed contract every caller
// of SetsRelayHopHeader relies on. parseUintSegment accepts exactly
// `[0-9]{1,9}` and nothing else: no sign, no whitespace, no underscore, and a
// length cap that makes overflow unrepresentable in either language.
func protoMajorMinor(v string) (major, minor int, ok bool) {
	if v == "" {
		return 0, 0, false
	}
	head, tail := v, ""
	if i := strings.IndexByte(v, '.'); i >= 0 {
		head, tail = v[:i], v[i+1:]
	}
	maj, ok := parseUintSegment(head)
	if !ok {
		return 0, 0, false
	}
	if tail == "" {
		return maj, 0, true
	}
	// Drop any patch suffix: "1.3" of "9.1.3" becomes "1".
	if i := strings.IndexByte(tail, '.'); i >= 0 {
		tail = tail[:i]
	}
	min, ok := parseUintSegment(tail)
	if !ok {
		return 0, 0, false
	}
	return maj, min, true
}

// maxVersionSegmentDigits caps a version segment's length. Nine digits fits any
// plausible version and stays far below both int32 and JS's safe-integer range,
// so neither port can overflow — the failure mode that made TS fail open.
const maxVersionSegmentDigits = 9

// parseUintSegment parses exactly one run of 1..maxVersionSegmentDigits ASCII
// digits. Anything else — empty, signed, over-long, or containing any non-digit
// — fails. Byte-for-byte mirrored by the TS regex `^[0-9]{1,9}$`.
func parseUintSegment(s string) (int, bool) {
	if len(s) == 0 || len(s) > maxVersionSegmentDigits {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ProtoVersionAtLeast reports whether a peer-advertised version `other` is at
// least `floor`, comparing (major, minor) in that order.
//
// This is deliberately NOT ProtoVersionCompatible, and the two must not be
// conflated. Compatibility is major-EQUALITY, because a major break is mutual
// non-interoperability — a 10.x peer is no more usable to a 9.x caller than an
// 8.x one. This is the ORDERED comparison an additive, minor-gated capability
// needs: "does this peer's generation include the feature I want to rely on".
//
// Inputs:
//   - other: the peer's advertised proto_version. An empty string is
//     interpreted as LegacyProtoVersion ("1.0") per the rollout rule.
//   - floor: the version at which the capability was introduced.
//
// Fails closed: if either side cannot be parsed for (major, minor), it returns
// false. A caller that cannot establish a peer's generation must never assume
// the capability — for the hop marker that inversion would turn "I can't tell
// how old you are" into "you owe me a header", and charge every unparseable
// peer for its absence.
func ProtoVersionAtLeast(other, floor string) bool {
	if other == "" {
		other = LegacyProtoVersion
	}
	oMajor, oMinor, ok := protoMajorMinor(other)
	if !ok {
		return false
	}
	fMajor, fMinor, ok := protoMajorMinor(floor)
	if !ok {
		return false
	}
	if oMajor != fMajor {
		return oMajor > fMajor
	}
	return oMinor >= fMinor
}

// RelayHopHeaderMinVersion is the first ProtoVersion at which a relaying node
// sets RelayHopHeader on every response it produces on RelayPath. Below it a
// missing marker is not evidence of anything — the relay predates the header.
const RelayHopHeaderMinVersion = "9.1"

// SetsRelayHopHeader reports whether a peer advertising protoVersion is new
// enough that a MISSING RelayHopHeader on its relay response counts as
// evidence against it (see RelayHopHeader and transient.NarrowRelayed).
//
// Fails closed via ProtoVersionAtLeast: an empty, unparseable, or
// bootstrap-seeded version returns false, leaving such a response
// unattributed exactly as it is today. Note the asymmetry this protects — a
// false positive here charges a relay for a header it was never asked to set,
// while a false negative merely preserves the status quo.
func SetsRelayHopHeader(protoVersion string) bool {
	return ProtoVersionAtLeast(protoVersion, RelayHopHeaderMinVersion)
}

// TightInputBoundMinVersion is the first ProtoVersion at which a node
// implements tokenize bound version 2 and honours input_bound_version on a
// reserve request. Below it, a caller MUST size its reserve with v1.
const TightInputBoundMinVersion = "9.2"

// UsesTightInputBound reports whether a target advertising protoVersion can be
// sent a reserve sized with tokenize.InputTokenBoundV2.
//
// This gate is load-bearing in one direction and merely wasteful in the other.
// Sizing v2 against a pre-9.2 node is a hard failure: v2 is TIGHTER than v1 on
// prose, tool schemas and images, so the node's v1 measurement of the same body
// exceeds the smaller reserved input_count and admission fails closed with
// input_budget_exceeded. Sizing v1 against a 9.2 node merely over-reserves, and
// the node honours the declared version, so nothing breaks.
//
// Fails closed via ProtoVersionAtLeast: an empty, unparseable or
// bootstrap-seeded version returns false and the caller keeps sizing with v1.
func UsesTightInputBound(protoVersion string) bool {
	return ProtoVersionAtLeast(protoVersion, TightInputBoundMinVersion)
}

// AppComposeMinVersion is the first ProtoVersion at which a dstack-tdx
// node publishes the compose preimage (TEEEvidenceBundle.AppCompose).
const AppComposeMinVersion = "9.6"

// PublishesAppCompose reports whether a node advertising protoVersion
// is new enough that a MISSING app_compose on its evidence bundle is
// evidence about the NODE rather than about its build.
//
// The gate exists because the security argument for treating an absent
// preimage harshly — "the node did not send it" is the state a node
// with something to hide would engineer — is only true of a peer that
// COULD have sent one. A 9.5 node passes major-equality and stays
// routable, so without this a minor-version difference silently
// becomes a verdict: every pre-9.6 dstack node looks like it withheld
// the document it was never able to produce.
//
// Fails closed via ProtoVersionAtLeast, and note which direction
// "closed" is here — an empty, unparseable or bootstrap-seeded version
// returns false, so the absence is attributed to the build and the
// node keeps whatever standing it had. That is the safe error: the
// alternative charges a node for withholding evidence on the strength
// of a version string we could not read. It does NOT license routing
// to such a node as content-validated — nothing absent is ever a pass
// (see proto/SPEC.md §3e); it only decides whether the absence is
// suspicious or expected.
func PublishesAppCompose(protoVersion string) bool {
	return ProtoVersionAtLeast(protoVersion, AppComposeMinVersion)
}

// There is deliberately NO PublishesCollateral twin for the 9.7
// TEEEvidenceBundle.Collateral set, and the asymmetry is the point.
//
// AppComposeMinVersion exists because an absent preimage is otherwise
// read as a node withholding evidence, so it matters whether the peer
// could have sent one. Absent COLLATERAL carries no such reading at
// all: it is the routine outcome of a PCCS the node could not reach, it
// is what every pre-9.7 node does, and per proto/SPEC.md §3e a verifier
// answers it by fetching its own copy — which it prefers anyway. A
// version gate here would guard a distinction with no consequence on
// either side of it, and would suggest to the next reader that a
// version-new node's absence IS a verdict.

// BootstrapProtoVersion is the value a caller seeds for an UNPROBED peer's
// proto_version so cold-start relay selection can break the probe/version
// deadlock: in privacy mode you need a relay to run the probe that learns the
// version, so an unprobed peer must be provisionally relay-eligible.
//
// It is this build's MAJOR with minor ZERO. Same major, so
// ProtoVersionCompatible passes and the peer stays relay-eligible exactly as
// before — but minor 0, so no minor-gated capability is ever ASSUMED of a node
// we have never heard from. Seeding the full ProtoVersion instead is a live
// trap: at 9.1 it would make every unprobed relay read as marker-capable, and
// its first code-less 5xx would be charged to it for omitting a header nobody
// had yet established it could set.
func BootstrapProtoVersion() string {
	major, ok := protoMajor(ProtoVersion)
	if !ok {
		return LegacyProtoVersion
	}
	return strconv.Itoa(major) + ".0"
}
