/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/attest"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// tee.CollateralTimeout is sized against the REFRESH CYCLE, and that
// relationship is the whole reason for its value — the probes share one
// WaitGroup under DefaultRefreshTimeout, so a ceiling near it lets one
// unreachable third party cost the proxy a complete refresh.
//
// Asserted against the thing it is sized against rather than against
// itself.
func TestCollateralTimeoutFitsTheRefreshCycle(t *testing.T) {
	if tee.CollateralTimeout >= DefaultRefreshTimeout {
		t.Errorf("tee.CollateralTimeout = %v, DefaultRefreshTimeout = %v — one stalled "+
			"operator can now consume the whole refresh cycle",
			tee.CollateralTimeout, DefaultRefreshTimeout)
	}
	// Comfortably inside, not merely under: several operators may stall
	// in the same cycle.
	if tee.CollateralTimeout > DefaultRefreshTimeout/2 {
		t.Errorf("tee.CollateralTimeout = %v is more than half of DefaultRefreshTimeout (%v)",
			tee.CollateralTimeout, DefaultRefreshTimeout)
	}
}

// A caller that sets no verifier verifies released nodes; nothing else in the
// SDK would make RequireTEEModels routable.
func TestConfigDefaults_TEEVerifier(t *testing.T) {
	c := Config{}.withDefaults()
	bv, ok := c.TEEVerifier.(*tee.BundleVerifier)
	if !ok {
		t.Fatalf("TEEVerifier = %T, want the default *tee.BundleVerifier", c.TEEVerifier)
	}
	if !reflect.DeepEqual(bv.TrustedOSImages, attest.TrustedDstackOSImages()) {
		t.Errorf("TrustedOSImages = %v", bv.TrustedOSImages)
	}
	if !reflect.DeepEqual(bv.ComposePolicy, tee.DefaultComposePolicy()) {
		t.Errorf("ComposePolicy is not tee.DefaultComposePolicy")
	}
	if bv.AllowStub {
		t.Error("the default verifier accepts stub evidence")
	}
	if bv.Log != c.Logger {
		t.Error("the default verifier does not log to Config.Logger")
	}

	mine := &tee.BundleVerifier{AllowStub: true}
	if got := (Config{TEEVerifier: mine}).withDefaults().TEEVerifier; got != tee.Verifier(mine) {
		t.Error("a supplied TEEVerifier was replaced")
	}
	for _, c := range []Config{{DisableTEE: true}, {DisableTEE: true, TEEVerifier: mine}} {
		if got := c.withDefaults().TEEVerifier; got != nil {
			t.Errorf("DisableTEE with TEEVerifier %v left %T", c.TEEVerifier, got)
		}
	}
}
