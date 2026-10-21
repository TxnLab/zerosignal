/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package httpx

import (
	"net/http"
	"strconv"
	"time"
)

// LinearBackoff is the wait before the retry that follows attempt (0-based)
// on the chain clients' retrying transports, algod's and the Solana RPC's:
// linear in min (attempt 0 waits min, attempt 1 twice min, …) and capped at
// max, then raised to a longer Retry-After read at now, also capped. A
// server-asserted throttle window is honored, up to the cap. One function for
// both, so testdata/algod_retry_vectors.json's Retry-After cases pin the parse
// for both and the TS twin (sdk/src/algod-transport.ts algodBackoffMs) is one
// function too.
func LinearBackoff(attempt int, retryAfter string, now time.Time, min, max time.Duration) time.Duration {
	wait := time.Duration(attempt+1) * min
	if wait > max {
		wait = max
	}
	if ra := RetryAfter(retryAfter, now); ra > wait {
		if ra > max {
			ra = max
		}
		wait = ra
	}
	return wait
}

// RetryAfter parses an RFC 7231 Retry-After value in either of its two forms,
// a non-negative integer count of seconds or an HTTP-date, read at now.
// Anything unparseable, or a date already past, is 0: no server-supplied wait.
func RetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
