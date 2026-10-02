/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"log/slog"
	"strconv"

	"github.com/TxnLab/zerosignal/go/steering"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// Weights-consensus demerit — the routing consequence for an operator whose
// advertised weights digest disagrees with the operators it competes against.
//
// The fraud it targets: advertise a frontier model, charge the frontier price
// every honest operator charges for it, and serve something small and cheap.
// Nothing in the protocol charged for that before this. The weights chain
// (SPEC § 3c) made the claim *legible* — trust tier, registry corroboration,
// and the node's own runtime contradicting a pinned digest — but a legible
// claim with no consequence is a claim nobody pays for getting wrong.
//
// # What counts as evidence
//
// Only the operator's own advertised `weights_digest`, compared against what
// its PEERS advertise for the same model id. Nothing self-reported about that
// digest is trusted: the trust tier and the registry verdict are node-authored
// strings, so a liar sets them to whatever reads best, and preferring a node
// that claims `node_supervised` + `matched` would hand the boldest liar the
// best placement. A peer digest is different in kind — it comes from a party
// with no stake in this operator's story.
//
// That also decides the DIRECTION: this can only ever demote. An operator
// gains nothing here by publishing a digest, so there is no placement to farm
// with a false one, and an operator publishing nothing is untouched — which is
// what every hosted-passthrough operator legitimately is (no local weights to
// hash: grok / gpt / claude have no digest and never will).
//
// # What it does not catch, and why that is not a reason to skip it
//
// Copying the real digest off the model's public registry page. It is free, it
// needs no code, and it defeats a registry cross-check by construction since
// claim and corroboration then come from the same page. The one thing it does
// NOT defeat is the operator's own serving runtime: `reconcileWithRuntime` on
// the node advertises the runtime's digest over a contradicting declaration,
// so a copier running an honest runtime publishes the SMALL model's digest on
// the hot list and lands here as the minority. A copier who runs no
// integrity-reporting runtime, or patches theirs, still walks through — that
// gap is the behavioral layer's, not this one's (plans/future/node/
// behavioral-consensus.md).
//
// So the honest claim for this file is narrow and worth stating plainly: it
// converts "publish nothing and pay nothing" into "publish a claim your peers
// can contradict", and makes being contradicted cost placement.
//
// The vote itself — owners not nodes, a tie undecided, case-folded digests —
// is steering.WeightsConsensus, golden-vectored against its TS twin in
// proto/ts/src/steering. The client's src/operators/weights-trust.ts still
// carries its own copy until it adopts that module. What can't be shared at all
// is the input: the details envelopes THIS process managed to probe differ from
// the client's by reachability, probe rotation, and cache age.

// weightsConsensus returns the digest a decisive plurality of distinct owners
// advertise for model across ops, or "" when there is none. Operators with no
// OwnerAddr supply no evidence but are still judged by the result.
func weightsConsensus(ops []hayai.Operator, model string) string {
	claims := make([]steering.DigestClaim, len(ops))
	for i, op := range ops {
		claims[i] = steering.DigestClaim{Owner: op.OwnerAddr, Digest: op.ModelCapacities[model].WeightsDigest}
	}
	return steering.WeightsConsensus(claims)
}

// contradictsWeightsConsensus reports whether op advertises a digest for model
// that disagrees with an established consensus. Publishing none never does.
func contradictsWeightsConsensus(op hayai.Operator, model, consensus string) bool {
	return steering.ContradictsWeightsConsensus(op.ModelCapacities[model].WeightsDigest, consensus)
}

// demoteContradictedWeights moves candidates whose advertised weights digest
// contradicts the peer consensus for model to the tail, preserving relative
// order within each group (stable partition). It returns the reordered list and
// the refs it moved, so the caller can say why the order changed.
//
// Demote, never drop, matching demoteBackedOffTargets and the relay-reputation
// downrank: a contradiction is "this operator serves different bytes than its
// peers", which a legitimate requant produces honestly, and a model with one
// serving node must stay reachable. The write-once hard exclusion
// (hayai.NodeExcluder) is reserved for a node contradicting its own SIGNATURE
// — a weights claim carries none, so it can't reach that bar.
//
// `evidence` is the wider operator set the consensus is computed over, not just
// the candidates: a peer held out of this request by price ceiling, staging, or
// the caller's provider prefs still says something true about which bytes the
// model is, and narrowing the vote to the candidate set would let a small
// eligible slice hand the lead to a liar.
//
// `preferred`, when non-nil, is exempt — reserved for a genuine SESSION
// CONTINUATION pin, where the pinned node is the only correct route (the
// upstream session lives in that operator's account) and trading it away is a
// correctness regression rather than a preference. **The dispatch path passes
// nil**: read the call site in hayai_dispatch.go before wiring anything into
// this parameter, because the proxy's two pins are not alike and neither one
// belongs here. It is kept as a parameter so this stays the mirror of the
// client's weights-trust.ts, which reserves it for the same future case.
//
// A contradicted candidate is reported even when the list is too short to
// reorder — being routed to the sole operator that contradicts its peers is
// exactly when the payer wants to hear about it, and returning early on
// len(ops) < 2 would make that the one case that logs nothing.
func demoteContradictedWeights(
	ops []hayai.Operator,
	preferred *hayai.Operator,
	evidence []hayai.Operator,
	model string,
) ([]hayai.Operator, []hayai.NodeRef) {
	if len(ops) == 0 {
		return ops, nil
	}
	consensus := weightsConsensus(evidence, model)
	if consensus == "" {
		return ops, nil
	}
	var pinned hayai.NodeRef
	if preferred != nil {
		pinned = hayai.RefOf(*preferred)
	}
	ok := make([]hayai.Operator, 0, len(ops))
	demoted := make([]hayai.Operator, 0)
	var refs []hayai.NodeRef
	for _, op := range ops {
		ref := hayai.RefOf(op)
		if preferred != nil && ref == pinned {
			ok = append(ok, op)
			continue
		}
		if contradictsWeightsConsensus(op, model, consensus) {
			demoted = append(demoted, op)
			refs = append(refs, ref)
			continue
		}
		ok = append(ok, op)
	}
	if len(demoted) == 0 {
		return ops, nil
	}
	return append(ok, demoted...), refs
}

// warnWeightsContradiction reports the contradicted candidates once each.
//
// One line per (model, node) for the process lifetime. The demerit is recomputed
// on every pickCandidates — once per dispatch, then once more per transient/busy
// sweep — and the operator that contradicts does so identically each time, so an
// undeduped WARN would repeat several times per request forever on a fleet where
// one operator legitimately serves a requant. That is how a level stops being
// read. The per-request answer is already on logRanking; this is the "something
// about your pool changed" line, which is only news once.
func (s *client) warnWeightsContradiction(model string, refs []hayai.NodeRef) {
	for _, ref := range refs {
		key := model + "\x00" + strconv.FormatUint(ref.Op, 10) + "\x00" + strconv.FormatUint(ref.Node, 10)
		if _, seen := s.weightsWarned.LoadOrStore(key, struct{}{}); seen {
			continue
		}
		s.log.Warn("weights digest contradicts peer consensus, deprioritizing operator",
			slog.String("model", model),
			slog.Uint64("operator_id", ref.Op),
			slog.Uint64("node_id", ref.Node))
	}
}
