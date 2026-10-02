/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import (
	"testing"

	prototokenize "github.com/TxnLab/zerosignal/go/tokenize"
)

// TestSafeEstimatorMatchesProto pins the proxy's default input bound to the
// shared proto InputTokenBound. The node re-measures the decrypted body at
// inference time to enforce the reserve, so if the proxy sized input_count from
// a different bound an honest request could be flagged as over-budget.
//
// SafeEstimator now delegates to the shared bound instead of carrying a copy of
// it, which makes this test cheap rather than load-bearing — but it stays as the
// guard against someone reintroducing a local implementation.
func TestSafeEstimatorMatchesProto(t *testing.T) {
	bodies := [][]byte{
		[]byte(``),
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`),
		[]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"https://x/y.png","detail":"high","width":1024,"height":768}}]}]}`),
		[]byte(`{"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://x/z.png","detail":"low"}]}]}`),
	}
	for i, b := range bodies {
		est, err := SafeEstimator{}.Estimate(Request{Body: b})
		if err != nil {
			t.Fatalf("case %d: estimate: %v", i, err)
		}
		if got, want := est.InputTokens, prototokenize.InputTokenBound(b); got != want {
			t.Errorf("case %d: SafeEstimator input=%d, prototokenize.InputTokenBound=%d (must match)", i, got, want)
		}
	}
}
