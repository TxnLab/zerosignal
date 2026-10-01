/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestRetry(t *testing.T) *RetryRoundTripper {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	return &RetryRoundTripper{
		Transport:    tr,
		MaxRetries:   2,
		RetryWaitMin: 10 * time.Millisecond,
		RetryWaitMax: 20 * time.Millisecond,
	}
}

func TestRetryRoundTripper_RetriesOn503(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2 (one 503 + one 200)", got)
	}
}

func TestRetryRoundTripper_RetriesOn5xxOther(t *testing.T) {
	// 502 is in the 5xx band but not specifically called out; the
	// retry classifier should still pick it up.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("server calls = %d, want 3 (two 502 + one 200)", got)
	}
}

func TestRetryRoundTripper_HonorsContextCancel(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	rrt.RetryWaitMin = 200 * time.Millisecond
	rrt.RetryWaitMax = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = rrt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error from canceled context, got nil")
	}
	if ctx.Err() == nil {
		t.Fatal("expected ctx to be canceled")
	}
	// One call to land the 503; the second attempt is blocked in
	// time.After when ctx is canceled.
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 before cancel", got)
	}
}

func TestRetryRoundTripper_NoRetryOn4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (no retry on 404)", got)
	}
}

// TestRetryRoundTripper_PostBodyRewound proves the fix to the bug
// where a retried POST sent an empty body because Request.Body had
// already been consumed by the first attempt. Every attempt MUST see
// the original payload.
func TestRetryRoundTripper_PostBodyRewound(t *testing.T) {
	const want = `{"hello":"world"}`
	var (
		calls atomic.Int32
		bad   atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if string(body) != want {
			bad.Add(1)
		}
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		srv.URL,
		bytes.NewReader([]byte(want)),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2", got)
	}
	if got := bad.Load(); got != 0 {
		t.Errorf("attempts with wrong body = %d, want 0 (body must be rewound)", got)
	}
}

// TestRetryRoundTripper_NonReplayableBody covers the safety check
// that refuses to retry a request whose body cannot be rewound — we'd
// rather surface the failure than silently re-issue with empty bytes.
func TestRetryRoundTripper_NonReplayableBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("streaming-body"))
		_ = pw.Close()
	}()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// http.NewRequestWithContext sets GetBody to nil for io.Pipe.
	if req.GetBody != nil {
		t.Fatalf("test setup: expected req.GetBody == nil for io.Pipe body")
	}

	_, err = rrt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error refusing to retry non-replayable body, got nil")
	}
	if !strings.Contains(err.Error(), "non-replayable body") {
		t.Errorf("err = %v, want non-replayable body message", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1 (no retry of non-replayable body)", got)
	}
}

// TestRetryRoundTripper_MaxRetriesExhausted verifies that after
// MaxRetries+1 failed attempts the last response is returned to the
// caller unchanged, with no further retries.
func TestRetryRoundTripper_MaxRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t) // MaxRetries=2 → 3 attempts total
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	res, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.StatusCode)
	}
	if got := calls.Load(); got != int32(rrt.MaxRetries+1) {
		t.Errorf("server calls = %d, want %d", got, rrt.MaxRetries+1)
	}
}

// TestRetryRoundTripper_HonorsRetryAfter checks the RFC 7231 header
// path: a Retry-After of 50ms should win over the 10ms linear-backoff
// floor (clamped to 20ms here).
func TestRetryRoundTripper_HonorsRetryAfter(t *testing.T) {
	var (
		calls   atomic.Int32
		firstAt time.Time
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			firstAt = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	rrt := newTestRetry(t)
	rrt.RetryWaitMin = 1 * time.Millisecond
	rrt.RetryWaitMax = 200 * time.Millisecond

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	start := time.Now()
	res, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer res.Body.Close()
	elapsed := time.Since(start)
	// Retry-After of 1s, but capped at RetryWaitMax=200ms, so the
	// observed wait should be at least ~150ms (small slack for test
	// scheduling) — well above the 1ms linear floor.
	if elapsed < 150*time.Millisecond {
		t.Errorf("elapsed = %v, want >=150ms (Retry-After should dominate linear backoff)", elapsed)
	}
	if firstAt.IsZero() {
		t.Fatal("first call never recorded")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2", got)
	}
}

// TestRetryRoundTripper_NetworkErrorRetries covers the network-error
// branch of shouldRetry: a closed listener should produce a dial
// error, which the round-tripper retries until MaxRetries+1.
func TestRetryRoundTripper_NetworkErrorRetries(t *testing.T) {
	// Reserve a port and immediately close it so dials fail fast.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rrt := newTestRetry(t)
	rrt.MaxRetries = 1
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = rrt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected dial error, got nil")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected ctx.Canceled: %v", err)
	}
}

func TestBackoff_LinearScaling(t *testing.T) {
	min := 1 * time.Second
	max := 30 * time.Second
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{4, 5 * time.Second},
		{29, 30 * time.Second},
		{100, 30 * time.Second}, // clamped
	}
	for _, tc := range tests {
		got := backoff(tc.attempt, nil, min, max)
		if got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestRetryAfter_ParsesSecondsAndDate(t *testing.T) {
	// Seconds form.
	res := &http.Response{Header: http.Header{}}
	res.Header.Set("Retry-After", "5")
	if got := retryAfter(res); got != 5*time.Second {
		t.Errorf("seconds form: got %v, want 5s", got)
	}
	// Date form (in the future).
	res.Header.Set("Retry-After", time.Now().Add(2*time.Second).UTC().Format(http.TimeFormat))
	if got := retryAfter(res); got <= 0 || got > 3*time.Second {
		t.Errorf("date form: got %v, want roughly 2s", got)
	}
	// Garbage → 0.
	res.Header.Set("Retry-After", "tomorrow-ish")
	if got := retryAfter(res); got != 0 {
		t.Errorf("garbage form: got %v, want 0", got)
	}
	// Missing → 0.
	res.Header.Del("Retry-After")
	if got := retryAfter(res); got != 0 {
		t.Errorf("missing: got %v, want 0", got)
	}
}
