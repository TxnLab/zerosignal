//go:build tdxlive

/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

import (
	"context"
	"testing"
	"time"
)

// TestVerifyTDXQuoteChain_RealQuote is the one test that exercises the
// step every other dstack test stubs out. Build-tagged because it
// reaches Intel's PCS over the network (run from proto/go):
//
//	go test -tags tdxlive -run TestVerifyTDXQuoteChain ./zs/
//
// It matters that this exists as more than a formality. The unit tests
// inject a chain verifier that returns nil, so they prove the replay,
// allowlist, binding and posture logic and prove NOTHING about whether
// a forged quote is rejected — the whole guarantee rests on this call,
// and a green unit suite would look identical if it were deleted.
//
// A failure here is not automatically a code defect. Intel withdraws
// TCB levels and revokes platforms over time, so a capture ages out;
// read the error before concluding anything, and recapture rather than
// relaxing the options.
func TestVerifyTDXQuoteChain_RealQuote(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := VerifyTDXQuoteChain(ctx, quote); err != nil {
		t.Fatalf("VerifyTDXQuoteChain on a real capture: %v", err)
	}
}

// Revocation checking is the half of the guarantee the zero-fetch guard
// does NOT cover: with CheckRevocations off, collateral is still
// fetched for TCB info so the fetch count stays positive, and a REVOKED
// platform verifies with every offline test green.
//
// It lives here rather than beside the other collateral tests because
// the library requests a CRL only after the TCB fetch succeeds — a
// stubbed getter never gets that far, so real PCS responses are the
// only way to observe the endpoint at all.
func TestVerifyTDXQuoteChain_RequestsRevocationLists(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	rec := &recordingCollateral{inner: sharedCollateralCache()}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := verifyTDXQuoteChainWith(ctx, quote, rec); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if !rec.sawCRL() {
		t.Errorf("no CRL endpoint was requested; URLs seen: %v — revocation "+
			"checking is off, so a revoked platform would verify", rec.urls())
	}
}

// A forged quote must fail. Flipping a byte inside the TD report body
// breaks the ECDSA signature over it — which is the property the whole
// design rests on and the one thing a stubbed verifier can never show.
func TestVerifyTDXQuoteChain_RejectsTamperedQuote(t *testing.T) {
	quote, _ := loadDstackVectors(t)
	tampered := make([]byte, len(quote))
	copy(tampered, quote)
	// Inside RTMR3: the register a hostile operator would rewrite to
	// make a substituted event log replay.
	tampered[48+328+3*48] ^= 0xff

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := VerifyTDXQuoteChain(ctx, tampered); err == nil {
		t.Fatal("a quote with a rewritten RTMR3 verified against Intel's chain")
	}
}
