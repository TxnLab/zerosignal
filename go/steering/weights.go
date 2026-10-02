/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package steering

import "strings"

// The weights demerit demotes an operator whose advertised weights digest for a
// model disagrees with what its peers advertise. It targets an operator that
// advertises a frontier model at the frontier price and serves something small.
//
// Only a peer's digest counts as evidence. The trust tier and registry verdict
// beside a digest are node-authored, so preferring a node that claims the best
// of them would reward the boldest liar. For the same reason the signal can
// only demote: publishing a digest earns nothing, so there is no placement to
// farm with a false one, and publishing none — every hosted passthrough, which
// has no local weights to hash — costs nothing.
//
// It does not catch an operator that copies the real digest off the model's
// registry page. The node's own runtime reconciliation is what defeats that,
// and only when the runtime reports integrity.

// WeightsConsensusMinOwners is how many distinct operator owners must advertise
// one digest before it is the reference for a model.
//
// Owners, never nodes: one owner's five nodes echo one config, and counting
// them five times would let a single operator out-vote an honest peer for the
// price of node registrations. Each extra owner is another operator escrow, so
// the cost of faking agreement scales with this number. Two is the floor at
// which a minority exists at all.
const WeightsConsensusMinOwners = 2

// DigestClaim is one operator's advertised weights digest for a model, with the
// owner address that makes its vote distinct. A claim with no owner can't be
// shown distinct and is not counted.
type DigestClaim struct {
	Owner  string
	Digest string
}

// WeightsConsensus returns the ASCII-lowercased digest the most distinct owners
// advertise, or "" when none holds a decisive plurality: fewer than
// WeightsConsensusMinOwners owners behind the leader, or a tie for the lead.
//
// A tie is undecided on purpose. A requantized local copy or a re-uploaded
// artifact diverges honestly often enough that disagreement alone must never
// pick a villain.
//
// Pass every operator that advertises the model, not only this request's
// candidates: a peer held out by price, staging, or the caller's preferences
// still says something true about the model's bytes, and a narrow slice could
// hand the lead to a liar.
//
// Digests compare ASCII-case-insensitively, so a pin hand-written in capitals
// agrees with the digest it matches. Only ASCII folds: a digest is node-authored
// text, and Unicode lowercasing differs between Go and JS (a final sigma), which
// would let a crafted digest split the two sides' verdicts.
func WeightsConsensus(claims []DigestClaim) string {
	owners := make(map[string]map[string]struct{})
	for _, c := range claims {
		d := asciiLower(c.Digest)
		if c.Owner == "" || d == "" {
			continue
		}
		if owners[d] == nil {
			owners[d] = make(map[string]struct{})
		}
		owners[d][c.Owner] = struct{}{}
	}
	var lead string
	var leadN, runnerUpN int
	for d, set := range owners {
		switch n := len(set); {
		case n > leadN:
			lead, leadN, runnerUpN = d, n, leadN
		case n > runnerUpN:
			runnerUpN = n
		}
	}
	if leadN < WeightsConsensusMinOwners || leadN == runnerUpN {
		return ""
	}
	return lead
}

// ContradictsWeightsConsensus reports whether digest disagrees with an
// established consensus. Advertising no digest never contradicts.
func ContradictsWeightsConsensus(digest, consensus string) bool {
	d := asciiLower(digest)
	return consensus != "" && d != "" && d != consensus
}

func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}
