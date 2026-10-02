/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// cryptoTimer aggregates time spent in hayai envelope encrypt/decrypt
// primitives during a single request. Frame-level SSE crypto is counted too,
// so totals include per-frame work across the full stream.
//
// Fields are atomic because SSE frames may be emitted from a reader goroutine
// in some provider implementations — a nanosecond of overhead is fine and the
// alternative (a mutex per frame) is worse.
type cryptoTimer struct {
	encryptNs  atomic.Int64
	decryptNs  atomic.Int64
	encryptOps atomic.Int64
	decryptOps atomic.Int64
}

func (t *cryptoTimer) recordEncrypt(d time.Duration) {
	if t == nil {
		return
	}
	t.encryptNs.Add(int64(d))
	t.encryptOps.Add(1)
}

func (t *cryptoTimer) recordDecrypt(d time.Duration) {
	if t == nil {
		return
	}
	t.decryptNs.Add(int64(d))
	t.decryptOps.Add(1)
}

// logAttrs returns slog attributes describing the timer's accumulated totals.
// Returns nil when no crypto operations ran (plaintext or GET /v1/models path)
// so the request log line stays short.
func (t *cryptoTimer) logAttrs() []slog.Attr {
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

type ctxKeyCryptoTimer struct{}

// withCryptoTimer returns a child context carrying a fresh cryptoTimer, and
// the timer itself so the caller can read totals after the request completes.
func withCryptoTimer(ctx context.Context) (context.Context, *cryptoTimer) {
	t := &cryptoTimer{}
	return context.WithValue(ctx, ctxKeyCryptoTimer{}, t), t
}

// cryptoTimerFrom extracts the per-request timer from ctx. Returns nil (which
// is a valid no-op target for record*) if no timer has been installed.
func cryptoTimerFrom(ctx context.Context) *cryptoTimer {
	t, _ := ctx.Value(ctxKeyCryptoTimer{}).(*cryptoTimer)
	return t
}
