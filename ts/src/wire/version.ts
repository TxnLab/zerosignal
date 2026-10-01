/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Wire-protocol generation advertised by this build. Mirror of
// proto/go/wire/version.go — keep in lockstep. See SPEC.md § 3c
// "Protocol version negotiation".
//
// Two peers can interop iff their major versions match; minor differences
// are reserved for additive, backwards-compatible changes. This is a
// discovery/filtering signal — independent of the cryptographic domain
// tags (admission, ticket, receipt), which are bumped separately when a
// signing or AEAD layout changes.
//
// What each generation changed — and why it was a major or a minor — is in
// proto/CHANGELOG.md. Add an entry there when you bump this.
export const PROTO_VERSION = '9.10' as const

// LEGACY_PROTO_VERSION is the value substituted for a missing
// proto_version field on the wire (nodes that predate the field). With
// PROTO_VERSION at "9.x", the substitution marks 1.0 (and pre-field)
// nodes as incompatible with 9.x callers — they can neither verify
// current-shape sigs nor relay/decrypt sealed reserves.
export const LEGACY_PROTO_VERSION = '1.0' as const

/**
 * Reports whether a peer-advertised proto_version is compatible with
 * this build's PROTO_VERSION. Compatibility = major equality.
 *
 * An empty/undefined/null `other` is interpreted as LEGACY_PROTO_VERSION.
 * Returns false if either side's version string lacks a parseable
 * numeric major component.
 */
export function protoVersionCompatible(other: string | undefined | null): boolean {
    const peer = other == null || other === '' ? LEGACY_PROTO_VERSION : other
    const selfMajor = protoMajor(PROTO_VERSION)
    const otherMajor = protoMajor(peer)
    if (selfMajor === null || otherMajor === null) return false
    return selfMajor === otherMajor
}

/**
 * Parses exactly one run of 1..9 ASCII digits. Anything else — empty, signed,
 * over-long, or containing any non-digit — fails.
 *
 * The length cap is not cosmetic. Go's `strconv.Atoi` returns ErrRange on a
 * 20-digit number while JS's `parseInt` silently overflows it to a float, so
 * the two ports disagreed and the JS side failed OPEN (an absurd version read
 * as capable), contradicting the fail-closed contract every setsRelayHopHeader
 * caller relies on. Nine digits fits any plausible version and is
 * unrepresentably-overflowing in neither language. Byte-for-byte mirrored by
 * Go's parseUintSegment.
 */
const VERSION_SEGMENT = /^[0-9]{1,9}$/

function parseUintSegment(s: string): number | null {
    if (!VERSION_SEGMENT.test(s)) return null
    const n = Number.parseInt(s, 10)
    if (!Number.isSafeInteger(n) || n < 0) return null
    return n
}

function protoMajor(v: string): number | null {
    if (!v) return null
    const dot = v.indexOf('.')
    const head = dot >= 0 ? v.slice(0, dot) : v
    return parseUintSegment(head)
}

/**
 * Generalizes protoMajor to the (major, minor) pair a minor-gated capability
 * check needs: "9" -> [9, 0], "9.1" -> [9, 1], "9.1.3" -> [9, 1] (a patch
 * suffix is tolerated and ignored). A missing minor segment reads as 0, so a
 * bare major and an explicit ".0" compare equal.
 */
function protoMajorMinor(v: string): [number, number] | null {
    if (!v) return null
    const dot = v.indexOf('.')
    const head = dot >= 0 ? v.slice(0, dot) : v
    const major = parseUintSegment(head)
    if (major === null) return null
    if (dot < 0) return [major, 0]
    let tail = v.slice(dot + 1)
    if (tail === '') return [major, 0]
    // Drop any patch suffix: "1.3" of "9.1.3" becomes "1".
    const next = tail.indexOf('.')
    if (next >= 0) tail = tail.slice(0, next)
    const minor = parseUintSegment(tail)
    if (minor === null) return null
    return [major, minor]
}

/**
 * Reports whether a peer-advertised version `other` is at least `floor`,
 * comparing (major, minor) in that order.
 *
 * Deliberately NOT protoVersionCompatible, and the two must not be conflated.
 * Compatibility is major EQUALITY, because a major break is mutual
 * non-interoperability — a 10.x peer is no more usable to a 9.x caller than an
 * 8.x one. This is the ORDERED comparison an additive, minor-gated capability
 * needs: "does this peer's generation include the feature I want to rely on".
 *
 * An empty/undefined/null `other` is interpreted as LEGACY_PROTO_VERSION.
 * Fails closed: if either side cannot be parsed for (major, minor) it returns
 * false. A caller that cannot establish a peer's generation must never assume
 * the capability — for the hop marker that inversion would turn "I can't tell
 * how old you are" into "you owe me a header".
 */
export function protoVersionAtLeast(other: string | undefined | null, floor: string): boolean {
    const peer = other == null || other === '' ? LEGACY_PROTO_VERSION : other
    const peerPair = protoMajorMinor(peer)
    const floorPair = protoMajorMinor(floor)
    if (peerPair === null || floorPair === null) return false
    const [peerMajor, peerMinor] = peerPair
    const [floorMajor, floorMinor] = floorPair
    if (peerMajor !== floorMajor) return peerMajor > floorMajor
    return peerMinor >= floorMinor
}

/**
 * The first PROTO_VERSION at which a relaying node sets RELAY_HOP_HEADER on
 * every response it produces on RELAY_PATH. Below it a missing marker is not
 * evidence of anything — the relay predates the header.
 */
export const RELAY_HOP_HEADER_MIN_VERSION = '9.1' as const

/**
 * Reports whether a peer advertising `protoVersion` is new enough that a
 * MISSING RELAY_HOP_HEADER on its relay response counts as evidence against it
 * (see RELAY_HOP_HEADER and narrowRelayed).
 *
 * Fails closed via protoVersionAtLeast: an empty, unparseable, or
 * bootstrap-seeded version returns false, leaving such a response unattributed
 * exactly as it is today. Note the asymmetry this protects — a false positive
 * charges a relay for a header it was never asked to set, while a false
 * negative merely preserves the status quo.
 */
export function setsRelayHopHeader(protoVersion: string | undefined | null): boolean {
    return protoVersionAtLeast(protoVersion, RELAY_HOP_HEADER_MIN_VERSION)
}

/**
 * The first PROTO_VERSION at which a node implements tokenize bound version 2
 * and honours input_bound_version on a reserve request. Below it, a caller MUST
 * size its reserve with v1.
 */
export const TIGHT_INPUT_BOUND_MIN_VERSION = '9.2' as const

/**
 * Whether a target advertising `protoVersion` can be sent a reserve sized with
 * inputTokenBoundV2.
 *
 * Load-bearing in one direction and merely wasteful in the other. Sizing v2
 * against a pre-9.2 node is a hard failure: v2 is TIGHTER than v1 on prose, tool
 * schemas and images, so the node's v1 measurement of the same body exceeds the
 * smaller reserved input_count and admission fails closed with
 * input_budget_exceeded. Sizing v1 against a 9.2 node merely over-reserves, and
 * the node honours the declared version, so nothing breaks.
 *
 * Fails closed via protoVersionAtLeast: an empty, unparseable or
 * bootstrap-seeded version returns false and the caller keeps sizing with v1.
 */
export function usesTightInputBound(protoVersion: string | undefined | null): boolean {
    return protoVersionAtLeast(protoVersion, TIGHT_INPUT_BOUND_MIN_VERSION)
}

/**
 * The first PROTO_VERSION at which a dstack-tdx node publishes the compose
 * preimage (`TeeEvidenceBundle.app_compose`).
 */
export const APP_COMPOSE_MIN_VERSION = '9.6' as const

/**
 * Reports whether a node advertising protoVersion is new enough that a MISSING
 * `app_compose` on its evidence bundle is evidence about the NODE rather than
 * about its build.
 *
 * The gate exists because the security argument for treating an absent preimage
 * harshly — "the node did not send it" is the state a node with something to
 * hide would engineer — is only true of a peer that COULD have sent one. A 9.5
 * node passes major-equality and stays routable, so without this a minor-version
 * difference silently becomes a verdict: every pre-9.6 dstack node looks like it
 * withheld a document it was never able to produce.
 *
 * Fails closed via protoVersionAtLeast, and note which direction "closed" is
 * here — an empty, unparseable or bootstrap-seeded version returns false, so the
 * absence is attributed to the build and the node keeps whatever standing it
 * had. That is the safe error: the alternative charges a node for withholding
 * evidence on the strength of a version string we could not read. It does NOT
 * license routing to such a node as content-validated — nothing absent is ever a
 * pass (see proto/SPEC.md §3e); it only decides whether the absence is
 * suspicious or expected.
 */
export function publishesAppCompose(protoVersion: string | undefined | null): boolean {
    return protoVersionAtLeast(protoVersion, APP_COMPOSE_MIN_VERSION)
}

// There is deliberately NO publishesCollateral twin for the 9.7
// TEEEvidenceBundle.collateral set, and the asymmetry is the point.
//
// APP_COMPOSE_MIN_VERSION exists because an absent preimage is otherwise read as
// a node withholding evidence, so it matters whether the peer could have sent
// one. Absent COLLATERAL carries no such reading: it is the routine outcome of a
// PCCS the node could not reach, it is what every pre-9.7 node does, and per
// proto/SPEC.md §3e a verifier answers it by fetching its own copy — which it
// prefers anyway. A version gate here would guard a distinction with no
// consequence on either side of it, and would suggest to the next reader that a
// version-new node's absence IS a verdict.

/**
 * The value a caller seeds for an UNPROBED peer's proto_version so cold-start
 * relay selection can break the probe/version deadlock: in privacy mode you
 * need a relay to run the probe that learns the version, so an unprobed peer
 * must be provisionally relay-eligible.
 *
 * This build's MAJOR with minor ZERO. Same major, so protoVersionCompatible
 * passes and the peer stays relay-eligible exactly as before — but minor 0, so
 * no minor-gated capability is ever ASSUMED of a node we have never heard from.
 * Seeding the full PROTO_VERSION instead is a live trap: at 9.1 it would make
 * every unprobed relay read as marker-capable, and its first code-less 5xx
 * would be charged to it for omitting a header nobody had established it could
 * set. On the client this matters more than on the proxy, because the seeded
 * pool feeds dispatch, not just discovery.
 */
export function bootstrapProtoVersion(): string {
    const major = protoMajor(PROTO_VERSION)
    if (major === null) return LEGACY_PROTO_VERSION
    return `${major}.0`
}
