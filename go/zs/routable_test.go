/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

// stubExcluder is a NodeExcluder over a fixed set. The production one hangs off
// ChainOperatorSource, which these tests don't build.
type stubExcluder struct{ excluded map[NodeRef]bool }

func (s stubExcluder) ExcludeNode(target NodeRef)       { s.excluded[target] = true }
func (s stubExcluder) NodeExcluded(target NodeRef) bool { return s.excluded[target] }

// routableIgnoringSize decides whose declared ceiling the clamp is allowed to
// read, and every predicate in it must be a HARD exclusion. MaxDeclaredOutput
// treats one undeclared cap as "the whole pool is unbounded", so an operator
// this request can never reach — a staging node, a banned node, one the
// caller's own provider preferences exclude — that answered the setup wizard's
// max_output_tokens prompt with 0 would otherwise switch the clamp off for
// every payer on that model.
//
// The asymmetry matters as much as the predicates: keeping an operator
// selection would later drop only raises the ceiling, which clamps less and
// leaves the request exactly as it behaved before the clamp existed. Dropping
// one selection would have KEPT clamps a caller below what an operator was
// ready to serve. So every false below has to be a rule selection applies
// unconditionally.
func TestRoutableIgnoringSize(t *testing.T) {
	ref := func(id uint64) selection.OperatorRef {
		return selection.OperatorRef{OperatorID: id, MatchAllNodes: true}
	}
	cases := []struct {
		name         string
		mutate       func(*Operator)
		allowStaging bool
		excluded     bool
		requireTEE   bool
		prefs        selection.RoutingPreferences
		want         bool
	}{
		{
			name: "plain serving operator is routable",
			want: true,
		},
		{
			// The realistic trigger: allow_staging defaults false, and the node
			// wizard documents 0 as a valid answer ("no separate cap beyond
			// context_window"), so a staging node with no ceiling is a shape
			// operators actually produce.
			name:   "staging node is held out by default",
			mutate: func(op *Operator) { op.Staging = true },
			want:   false,
		},
		{
			name:         "staging node counts once the payer opts in",
			mutate:       func(op *Operator) { op.Staging = true },
			allowStaging: true,
			want:         true,
		},
		{
			name:     "node proven to have handed a fraudulent settle group",
			excluded: true,
			want:     false,
		},
		{
			name:   "operator speaking a different wire generation",
			mutate: func(op *Operator) { op.ProtoVersion = "1.0" },
			want:   false,
		},
		{
			name:       "TEE required and the operator is not attested",
			requireTEE: true,
			want:       false,
		},
		{
			name:       "TEE required and the operator is attested",
			mutate:     func(op *Operator) { op.TEE = attestedTEE },
			requireTEE: true,
			want:       true,
		},
		{
			name: "signing account one microAlgo below the routing floor",
			mutate: func(op *Operator) {
				v := selection.MinSignerSpendableMicroAlgos - 1
				op.SignerSpendableMicroAlgos = &v
			},
			want: false,
		},
		{
			name: "signing account exactly at the routing floor",
			mutate: func(op *Operator) {
				v := selection.MinSignerSpendableMicroAlgos
				op.SignerSpendableMicroAlgos = &v
			},
			want: true,
		},
		{
			name:  "caller's provider.ignore excludes it",
			prefs: selection.RoutingPreferences{Ignore: []selection.OperatorRef{ref(7)}},
			want:  false,
		},
		{
			name:  "caller's provider.only names someone else",
			prefs: selection.RoutingPreferences{Only: []selection.OperatorRef{ref(9)}},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := Operator{
				ID: 7, NodeID: 1,
				Models:       []string{"big-out"},
				ProtoVersion: wire.ProtoVersion,
			}
			if tc.mutate != nil {
				tc.mutate(&op)
			}
			s := &Client{cfg: Config{Privacy: PrivacyDirect, AllowStaging: tc.allowStaging}}
			if tc.excluded {
				s.nodeExcluder = stubExcluder{excluded: map[NodeRef]bool{RefOf(op): true}}
			}
			if got := s.routableIgnoringSize(op, tc.requireTEE, tc.prefs); got != tc.want {
				t.Errorf("routableIgnoringSize = %v, want %v", got, tc.want)
			}
		})
	}
}
