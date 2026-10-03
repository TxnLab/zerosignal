/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"log/slog"

	"github.com/TxnLab/zerosignal/go/attest"
)

// DefaultComposePolicy is the compose policy a payer runs out of the box: the
// shared rules, with the published zs-node releases as the only workloads
// that verify.
//
// The release match is ENFORCED, which is what lets DefaultTEEVerifier carry
// no compose hashes: a node is identified by the release it runs, not by a
// per-deployment digest a payer would have to collect by hand.
func DefaultComposePolicy() attest.ComposePolicy {
	p := attest.ZeroSignalComposePolicy()
	p.TrustedComposeSkeletons = attest.TrustedComposeSkeletons()
	p.TrustedNodeImages = attest.TrustedNodeImages()
	p.EnforceComposeSkeleton = true
	return p
}

// DefaultTEEVerifier verifies dstack evidence against the production guest
// images and the published zs-node releases this build knows, the same trust
// zs-proxy ships with. New uses it when Config.TEEVerifier is nil.
//
// A node running a release newer than this build is refused until the build
// is updated: the lists are compiled in, because a served list would let
// whoever serves it decide which workloads count as attested.
func DefaultTEEVerifier(log *slog.Logger) *BundleVerifier {
	return &BundleVerifier{
		TrustedOSImages: attest.TrustedDstackOSImages(),
		ComposePolicy:   DefaultComposePolicy(),
		Log:             log,
	}
}
