/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

import (
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/attest"
)

// Enforcing the release match is what lets the default carry no compose
// hashes: with it off, an empty TrustedComposeHashes refuses every node.
func TestDefaultComposePolicy(t *testing.T) {
	p := DefaultComposePolicy()
	if !p.EnforceComposeSkeleton {
		t.Error("the release match is not enforced")
	}
	if !reflect.DeepEqual(p.TrustedComposeSkeletons, attest.TrustedComposeSkeletons()) ||
		!reflect.DeepEqual(p.TrustedNodeImages, attest.TrustedNodeImages()) {
		t.Error("the release lists are not attest's")
	}
	base := attest.ZeroSignalComposePolicy()
	p.TrustedComposeSkeletons, p.TrustedNodeImages, p.EnforceComposeSkeleton = nil, nil, false
	if !reflect.DeepEqual(p, base) {
		t.Error("DefaultComposePolicy changes more of the shared policy than the release match")
	}
}
