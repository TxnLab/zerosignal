/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// RetryRoundTripper wraps an *http.Transport and retries transient
// failures (network errors, 429, 503, and other 5xx) with linear
// backoff capped at RetryWaitMax. Retry attempts honor the request
// context — a canceled or deadline-exceeded ctx aborts immediately —
// and the server's Retry-After header (RFC 7231) is honored when it
// asks for a wait longer than the linear schedule.
//
// Non-retriable conditions (2xx, non-429 4xx, ctx cancellation) return
// on the first attempt. Non-idempotent algod calls — most notably
// SendRawTransaction — are still safe to retry on these statuses
// because the network deduplicates by signed-txn id.
//
// The retried request must have a replayable body. Requests built via
// http.NewRequest with *bytes.Reader / *bytes.Buffer / *strings.Reader
// payloads get this for free (the standard library populates
// Request.GetBody). Requests with a non-replayable body (e.g. an
// io.Pipe stream) are NOT silently re-issued with a half-consumed
// body — the first attempt's result is returned along with a wrapped
// error explaining the refusal, which is strictly better than
// generating a 400 from a downstream that received empty bytes.
type RetryRoundTripper struct {
	Transport  *http.Transport
	MaxRetries int
	// RetryWaitMin is both the wait before the first retry and the
	// per-attempt step of the linear backoff (1×, 2×, 3× …) clamped
	// to RetryWaitMax. A server-supplied Retry-After larger than this
	// linear value supersedes it (also clamped to RetryWaitMax).
	RetryWaitMin time.Duration
	RetryWaitMax time.Duration
}

func (rrt *RetryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	var (
		res *http.Response
		err error
	)

	for attempt := 0; attempt <= rrt.MaxRetries; attempt++ {
		if attempt > 0 {
			if rerr := rewindBody(req); rerr != nil {
				return res, rerr
			}
		}

		res, err = rrt.Transport.RoundTrip(req)

		if !shouldRetry(res, err) {
			return res, err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return res, err
		}
		if attempt == rrt.MaxRetries {
			return res, err
		}

		wait := backoff(attempt, res, rrt.RetryWaitMin, rrt.RetryWaitMax)

		slog.Default().Debug("algod transport retry",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.Any("err", err),
			slog.Int("status", statusOf(res)),
			slog.Duration("wait", wait),
			slog.Int("attempt", attempt+1),
			slog.Int("max", rrt.MaxRetries+1),
		)

		// Drain + close so the underlying connection returns to the
		// keep-alive pool before we sleep for the backoff.
		drainAndClose(res)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return res, err
}

// rewindBody resets req.Body using GetBody so a retry sees the original
// payload. Returns an error when the request has a body that cannot be
// replayed (GetBody == nil) — we refuse to retry such a request rather
// than silently re-issue with an empty body.
func rewindBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return fmt.Errorf("algod: cannot retry %s %s: non-replayable body", req.Method, req.URL.String())
	}
	body, err := req.GetBody()
	if err != nil {
		return fmt.Errorf("algod: rewind request body: %w", err)
	}
	req.Body = body
	return nil
}

func shouldRetry(res *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if res == nil {
		return false
	}
	if res.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if res.StatusCode >= 500 && res.StatusCode <= 599 {
		return true
	}
	return false
}

func statusOf(res *http.Response) int {
	if res == nil {
		return 0
	}
	return res.StatusCode
}

func drainAndClose(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}

// backoff returns the wait before the next attempt. The base schedule
// is linear in RetryWaitMin (attempt 0 → RetryWaitMin, attempt 1 →
// 2×RetryWaitMin, …) clamped to RetryWaitMax. A Retry-After header on
// the response, if present and larger, supersedes the linear value
// (also clamped to RetryWaitMax) so a server-asserted throttle window
// is always honored.
func backoff(attempt int, res *http.Response, min, max time.Duration) time.Duration {
	wait := time.Duration(attempt+1) * min
	if wait > max {
		wait = max
	}
	if ra := retryAfter(res); ra > wait {
		if ra > max {
			ra = max
		}
		wait = ra
	}
	return wait
}

// retryAfter parses an RFC 7231 Retry-After header in either of its
// two forms: a non-negative integer count of seconds, or an HTTP-date.
// Anything unparseable returns 0 (no server-supplied wait).
func retryAfter(res *http.Response) time.Duration {
	if res == nil {
		return 0
	}
	v := res.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// DefaultTransport returns the connection-pooled, retrying transport
// applied by NewClient when no WithTransport override is supplied.
//
// Pool sizing (MaxIdleConns / MaxConnsPerHost / MaxIdleConnsPerHost =
// 100) matters because both proxy and node hammer a single algod host
// from many goroutines at once — Go's defaults cap idle conns per host
// at 2, which forces a fresh dial on every concurrent caller past the
// second. The retry knobs (20 attempts, 1s→30s linear-cap backoff)
// absorb transient 429/503/5xx from hosted-node providers without
// failing admission or settlement. Per-call deadlines should still
// come from the caller's ctx — the retry budget can otherwise stretch
// to several minutes against a sustained-error backend.
func DefaultTransport() *RetryRoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100
	return &RetryRoundTripper{
		Transport:    t,
		MaxRetries:   20,
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 30 * time.Second,
	}
}
