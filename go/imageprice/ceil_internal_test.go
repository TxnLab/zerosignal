/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package imageprice

import (
	"math"
	"testing"
)

// Near the uint64 limit (a + b - 1) wraps to a tiny quotient.
func TestCeilDiv_NearLimit(t *testing.T) {
	for _, c := range []struct{ a, b, want uint64 }{
		{math.MaxUint64, 1_000_000, math.MaxUint64/1_000_000 + 1},
		{math.MaxUint64, 1, math.MaxUint64},
		{10, 5, 2},
		{11, 5, 3},
		{0, 7, 0},
	} {
		if got := ceilDiv(c.a, c.b); got != c.want {
			t.Errorf("ceilDiv(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
