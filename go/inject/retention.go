/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import "slices"

// The Retention tiers advertised on OperatorDetailsModel.Retention: what a node
// can say about whether the prompt it serves is retained ANYWHERE, and — this
// is the part the value carries that a bare boolean could not — on what
// evidence.
//
// They live here, in the shared protocol module, rather than beside the node's
// resolver, because four consumers read them (node, proxy, client, operator
// dashboard) and a per-consumer copy of a wire enum forks the moment a tier is
// added. That is the mistake the weights trust tiers already made — they are
// declared once in node/internal/config and again in proxy/internal/server.
//
// ORDERED, strongest evidence first. The ordering is real and worth stating,
// but note carefully what it orders: how well the tier is EVIDENCED, not how
// private the deployment is. See the trust ceiling on Retention in details.go —
// RetentionUpstreamConfirmed outranks RetentionNoUpstream here while being the
// weaker posture on the axis most readers care about.
const (
	// RetentionTEEAttested local weights inside a TEE. Nothing leaves the
	// node TO ANSWER THE REQUEST, and the node's own non-retention is
	// hardware-attested rather than promised. The only tier that closes the
	// node-side half of the question. See retentionStaysLocal for the scope
	// of "nothing leaves" — it is the inference route, not every byte.
	RetentionTEEAttested = "tee_attested"

	// RetentionUpstreamConfirmed the upstream AFFIRMS zero data retention on
	// every response and the node refuses any otherwise-successful response
	// that does not. xAI's `x-zero-data-retention: true`. Evidence arrives with
	// each request, so a change on the upstream's side surfaces immediately.
	RetentionUpstreamConfirmed = "upstream_confirmed"

	// RetentionUpstreamEnforced the node pins a per-request constraint the
	// upstream's own semantics make tighten-only, so a retaining endpoint is
	// unroutable rather than merely unused. OpenRouter's `provider.zdr` +
	// `data_collection: "deny"` (EnforceUpstreamPrivacy). Verified indirectly:
	// the failure mode is a request that does not route, not one that leaks.
	//
	// TWO LIMITS THAT DO NOT APPLY TO RetentionUpstreamConfirmed, and both are
	// why this sorts below it rather than above despite preventing the leak
	// EARLIER (the pin is pre-flight; the header check reads a response to a
	// prompt already delivered). First, the constraint is ASSERTED, never
	// observed — nothing comes back saying it was honoured, so an upstream that
	// quietly ignored it is indistinguishable here from one that obeyed. That
	// is what "indirectly" means, and it is the whole of the ordering argument.
	// Second, it is scoped to the ENDPOINT THAT SERVES THE REQUEST. Where the
	// named upstream is a broker or aggregator, whatever sits between the node
	// and that endpoint also reads the prompt, and its own retention is
	// governed by settings this constraint does not set — see
	// EnforceUpstreamPrivacy, whose "nothing has to read the dashboard"
	// argument covers the routing filter and deliberately not that.
	//
	// So this tier means "no retaining endpoint served it, as far as the node
	// can tell", not "nothing between here and there kept a copy". It is the
	// honest ceiling for a pinned aggregator; a posture that has to name the
	// one party that read the prompt cannot be built on it, which is why
	// node's validateAttestedPassthrough refuses a broker outright.
	RetentionUpstreamEnforced = "upstream_enforced"

	// RetentionNoUpstream local weights, no TEE. The prompt never leaves the
	// node process to be answered, so there is no upstream to retain it — but
	// the node's own non-retention is policy the operator commits to, not
	// something a payer can check. Strictly better than the enforced tiers on
	// data flow and strictly weaker on evidence. Same scope caveat as
	// RetentionTEEAttested; see retentionStaysLocal.
	RetentionNoUpstream = "no_upstream"

	// RetentionOperatorDeclared the operator asserts a zero-retention
	// arrangement the node has no way to check — an OpenAI or Azure ZDR
	// agreement, a self-hosted runtime they control. The weakest rung, and the
	// only one an operator can put there themselves. Never overrides a tier the
	// node derived.
	RetentionOperatorDeclared = "operator_declared"
)

// knownRetentionTiers is every tier this package defines, strongest evidence
// first. Consumers enumerate from here rather than keeping their own copy — see
// the note on the consts above.
var knownRetentionTiers = []string{
	RetentionTEEAttested,
	RetentionUpstreamConfirmed,
	RetentionUpstreamEnforced,
	RetentionNoUpstream,
	RetentionOperatorDeclared,
}

// KnownRetentionTiers returns every retention tier this package defines,
// strongest evidence first. The returned slice is the caller's own.
func KnownRetentionTiers() []string {
	return slices.Clone(knownRetentionTiers)
}

// IsKnownRetention reports whether s names a retention tier this package
// defines. A consumer decoding OperatorDetailsModel.Retention should treat an
// unrecognized value as UNKNOWN — the same as empty — rather than surfacing it
// verbatim: the field is node-authored, so a value this build has never heard
// of is either a newer node or an operator's invention, and a UI cannot tell
// those apart. Displaying it verbatim lets a node mint its own reassuring
// label.
func IsKnownRetention(s string) bool {
	return slices.Contains(knownRetentionTiers, s)
}

// CombineRetention returns the strongest tier that is TRUE of both routes, for a
// model whose prompt reaches both — a chat model with `zs_image_*` tools, whose
// turns go to the text upstream and whose tool calls go to the image one.
//
// It is not simply the weaker of the two by rank, and the reason is the thing
// the ordering hides: the tiers rank by EVIDENCE, but they also make different
// claims. `no_upstream` says the prompt reaches nobody — which stops being true
// the moment the other route sends it somewhere, however well evidenced that
// destination is. Ranking alone would answer `no_upstream` for a local chat
// route paired with an xAI image route, i.e. keep the one claim that has just
// become false.
//
// So both axes are combined, the same pair the UI renders:
//
//   - DESTINATION: the prompt stays local only if BOTH routes keep it local. If
//     one leaves, the leaving route's tier is the binding one — it is the only
//     one describing where the prompt actually went.
//   - EVIDENCE: where the two are comparable, the weaker wins. A chain is worth
//     its weakest link.
//
// UNKNOWN ("" or an unrecognized value) on either side yields unknown: a route
// that can promise nothing makes the pair promise nothing. That is what absence
// means everywhere else in this field — never "retains", but never a guarantee.
func CombineRetention(a, b string) string {
	if !IsKnownRetention(a) || !IsKnownRetention(b) {
		return ""
	}
	if a == b {
		return a
	}
	switch localA, localB := retentionStaysLocal(a), retentionStaysLocal(b); {
	case localA && localB:
		// Both keep the prompt on the box, so only the evidence differs:
		// tee_attested paired with no_upstream is no_upstream, because half the
		// work is attested and half is promised.
		return weakerRetention(a, b)
	case localA:
		return b
	case localB:
		return a
	default:
		return weakerRetention(a, b)
	}
}

// retentionStaysLocal reports whether a tier claims the prompt reaches no third
// party ON THE INFERENCE ROUTE — the path the node takes to produce an answer.
// The destination axis; see CombineRetention.
//
// The scope is not a hedge. Built-in tools are caller-initiated (SPEC § 3d): a
// zs_web_search call exists for a request only because the caller listed the
// type in tools[], and a node at ANY tier may serve them. So neither this
// predicate nor the tier it reads is falsified by a node that offers them, and
// a consumer must not treat the pair as a contradiction. What the tier does
// cover is every route the OPERATOR chooses, the image backend included —
// which is why CombineRetention folds the image route in rather than ignoring
// it. TEEPosture's godoc in tee.go carries the full argument.
func retentionStaysLocal(s string) bool {
	return s == RetentionTEEAttested || s == RetentionNoUpstream
}

// weakerRetention returns whichever tier is worse evidenced, unknown last.
func weakerRetention(a, b string) string {
	if retentionRank(a) >= retentionRank(b) {
		return a
	}
	return b
}

// retentionRank orders tiers weakest-LAST, with unknown past the end so it is
// weaker than every named tier.
func retentionRank(s string) int {
	if i := slices.Index(knownRetentionTiers, s); i >= 0 {
		return i
	}
	return len(knownRetentionTiers)
}
