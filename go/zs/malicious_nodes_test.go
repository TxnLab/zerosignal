/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import "testing"

// The exclusion is a hard, permanent bit — unlike TargetBackoff it never clears.
func TestNodeExcluder_ExcludeIsSticky(t *testing.T) {
	s := &ChainOperatorSource{}
	ref := NodeRef{Op: 1, Node: 2}

	if s.NodeExcluded(ref) {
		t.Fatal("node excluded before any ExcludeNode call")
	}
	s.ExcludeNode(ref)
	if !s.NodeExcluded(ref) {
		t.Fatal("node not excluded after ExcludeNode")
	}
	// Idempotent: excluding again is a no-op, still excluded (no reset path).
	s.ExcludeNode(ref)
	if !s.NodeExcluded(ref) {
		t.Error("second ExcludeNode cleared the exclusion")
	}
}

// Keyed by the (operator, node) pair: one operator's malicious node must never
// exclude its honest siblings.
func TestNodeExcluder_KeyedByNodeNotOperator(t *testing.T) {
	s := &ChainOperatorSource{}
	bad := NodeRef{Op: 7, Node: 1}
	sibling := NodeRef{Op: 7, Node: 2}

	s.ExcludeNode(bad)
	if !s.NodeExcluded(bad) {
		t.Error("malicious node not excluded")
	}
	if s.NodeExcluded(sibling) {
		t.Error("a sibling node of the same operator was excluded")
	}
}

// A different operator entirely is untouched.
func TestNodeExcluder_OtherOperatorUnaffected(t *testing.T) {
	s := &ChainOperatorSource{}
	s.ExcludeNode(NodeRef{Op: 1, Node: 1})
	if s.NodeExcluded(NodeRef{Op: 2, Node: 1}) {
		t.Error("excluding operator 1 excluded operator 2")
	}
}
