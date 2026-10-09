/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cryptotimer accounts the time one request spends in envelope
// encrypt/decrypt. The HTTP surface installs a timer on the request context
// and logs it; the SDK core, which does the crypto, records into it.
package cryptotimer

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Timer aggregates time spent in envelope encrypt/decrypt primitives during a
// single request. Frame-level SSE crypto is counted too, so totals include
// per-frame work across the full stream.
//
// Fields are atomic because SSE frames may be emitted from a reader goroutine
// in some provider implementations — a nanosecond of overhead is fine and the
// alternative (a mutex per frame) is worse.
type Timer struct {
	encryptNs  atomic.Int64
	decryptNs  atomic.Int64
	encryptOps atomic.Int64
	decryptOps atomic.Int64
}

func (t *Timer) RecordEncrypt(d time.Duration) {
	if t == nil {
		return
	}
	t.encryptNs.Add(int64(d))
	t.encryptOps.Add(1)
}

func (t *Timer) RecordDecrypt(d time.Duration) {
	if t == nil {
		return
	}
	t.decryptNs.Add(int64(d))
	t.decryptOps.Add(1)
}

// LogAttrs returns slog attributes describing the timer's accumulated totals.
// Returns nil when no crypto operations ran (plaintext or GET /v1/models path)
// so the request log line stays short.
func (t *Timer) LogAttrs() []slog.Attr {
	if t == nil {
		return nil
	}
	eo, do := t.encryptOps.Load(), t.decryptOps.Load()
	if eo == 0 && do == 0 {
		return nil
	}
	return []slog.Attr{
		slog.Duration("crypto_encrypt", time.Duration(t.encryptNs.Load())),
		slog.Int64("crypto_encrypt_ops", eo),
		slog.Duration("crypto_decrypt", time.Duration(t.decryptNs.Load())),
		slog.Int64("crypto_decrypt_ops", do),
	}
}

type ctxKey struct{}

// With returns a child context carrying a fresh Timer, and the timer itself so
// the caller can read totals after the request completes.
func With(ctx context.Context) (context.Context, *Timer) {
	t := &Timer{}
	return context.WithValue(ctx, ctxKey{}, t), t
}

// From extracts the per-request timer from ctx. Returns nil (which is a valid
// no-op target for Record*) if no timer has been installed.
func From(ctx context.Context) *Timer {
	t, _ := ctx.Value(ctxKey{}).(*Timer)
	return t
}
