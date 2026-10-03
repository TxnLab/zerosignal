/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/attest"
)

// A caller that sets no verifier verifies released nodes; nothing else in the
// SDK would make RequireTEEModels routable.
func TestConfigDefaults_TEEVerifier(t *testing.T) {
	c := Config{}.withDefaults()
	bv, ok := c.TEEVerifier.(*BundleVerifier)
	if !ok {
		t.Fatalf("TEEVerifier = %T, want the default *BundleVerifier", c.TEEVerifier)
	}
	if !reflect.DeepEqual(bv.TrustedOSImages, attest.TrustedDstackOSImages()) {
		t.Errorf("TrustedOSImages = %v", bv.TrustedOSImages)
	}
	if !reflect.DeepEqual(bv.ComposePolicy, DefaultComposePolicy()) {
		t.Errorf("ComposePolicy is not DefaultComposePolicy")
	}
	if bv.AllowStub {
		t.Error("the default verifier accepts stub evidence")
	}
	if bv.Log != c.Logger {
		t.Error("the default verifier does not log to Config.Logger")
	}

	mine := &BundleVerifier{AllowStub: true}
	if got := (Config{TEEVerifier: mine}).withDefaults().TEEVerifier; got != TEEVerifier(mine) {
		t.Error("a supplied TEEVerifier was replaced")
	}
	for _, c := range []Config{{DisableTEE: true}, {DisableTEE: true, TEEVerifier: mine}} {
		if got := c.withDefaults().TEEVerifier; got != nil {
			t.Errorf("DisableTEE with TEEVerifier %v left %T", c.TEEVerifier, got)
		}
	}
}

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
