/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Per-target-node HARD exclusion — the intentional exception to every other
// app-side routing signal in this package. relay_reputation.go, target_backoff.go,
// relay_latency.go, and lastReachable are all deliberately SELF-HEALING: a demote
// lapses, a single success resets the streak, a re-probe restores a node. This
// store is the opposite by design — write-once, never reset, hard drop — because
// the trigger is not a transient fault but proof of misbehaviour.
//
// The trigger: the payer's settle-ack path refused a node-composed atomic settle
// group as fraudulent (escrow.VerifySettleGroup returned *SettleGroupRejectedError
// — a RekeyTo hijacking the payer account, a non-NoOp OnCompletion bypassing the
// approval program, a non-zero payer fee, or a co-signed value that contradicts
// the node's OWN signed receipt). The node authored both halves of that group and
// the receipt, so a mismatch is the node contradicting itself, never honest
// desync — see wallet.go AckSettle and the slashing plan.
// Such a node is not "temporarily broken"; it tried to take the payer's account
// or overcharge. So we stop routing to it — as a target AND as a relay — for the
// rest of the process's life.
//
// Session-lifetime = process-lifetime here (the proxy is a localhost single-user
// process; a restart is the operator owner's explicit choice to give the node
// another chance). Like the sibling stores it is deliberately NOT in
// proto/.../selection: it is stateful and vantage-specific, so it can't be
// golden-vectored. Mirrors the TS SDK's NodeExclusionStore
// (sdk/src/routing/exclusion.ts).

// NodeExcluder is the proxy's proven-malicious-node memory. Keyed by the
// (operator id, node id) pair like every other routing store: a target/relay is a
// single node (operator/node split — see the repo AGENTS.md), so one operator's
// malicious node must never exclude its honest siblings.
type NodeExcluder interface {
	// ExcludeNode permanently (process-lifetime) bars a node from candidate
	// selection and the relay pool. Idempotent; safe for concurrent use. Call
	// ONLY on proof of settle-group fraud — never for a transient failure, which
	// belongs in TargetBackoff / relay reputation and must stay self-healing.
	ExcludeNode(target NodeRef)

	// NodeExcluded reports whether a node has been proven malicious and must be
	// hard-dropped from selection. Safe for concurrent use.
	NodeExcluded(target NodeRef) bool
}

// ExcludeNode implements NodeExcluder. Write-once, never deleted.
func (s *ChainOperatorSource) ExcludeNode(target NodeRef) {
	s.excludeMu.Lock()
	defer s.excludeMu.Unlock()
	if s.excludedNodes == nil {
		s.excludedNodes = make(map[NodeRef]struct{})
	}
	s.excludedNodes[target] = struct{}{}
}

// NodeExcluded implements NodeExcluder. Safe for concurrent use.
func (s *ChainOperatorSource) NodeExcluded(target NodeRef) bool {
	s.excludeMu.Lock()
	defer s.excludeMu.Unlock()
	_, ok := s.excludedNodes[target]
	return ok
}

var _ NodeExcluder = (*ChainOperatorSource)(nil)
