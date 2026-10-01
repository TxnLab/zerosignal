/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package algod is a thin facade over github.com/algorand/go-algorand-sdk/v2's
// algod HTTP client. Proxy and node both import it so escrow group
// composition (proxy-side) and mempool admission (node-side) share one
// definition of "what the algod surface looks like" — no per-service
// client that could drift from the other.
//
// The facade intentionally keeps the exposed surface small: only the
// four operations the escrow flow needs plus the tiny amount of
// plumbing needed to make it mockable in tests. Anything beyond this
// should be added explicitly, not automatically — the point of the
// wrapper is to keep the SDK surface *bounded*.
package algod

import (
	"context"
	"fmt"
	"net/http"

	sdkalgod "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Client is the interface proxy/node code depends on. Backed by the
// real algod SDK in production (NewClient) or an in-memory fake in
// tests (see client_test.go).
type Client interface {
	// SuggestedParams returns the current suggested transaction params
	// (fee, first/last valid round, genesis id/hash). Required to
	// compose any transaction.
	SuggestedParams(ctx context.Context) (types.SuggestedParams, error)

	// SendRawTransactionGroup broadcasts a pre-signed atomic group to
	// the algod mempool and returns the group id / first txid algod
	// acks. The payload is the raw msgpack-encoded concatenation of
	// the SignedTxn entries in group order, exactly what
	// algorand_sdk's transaction composer emits.
	SendRawTransactionGroup(ctx context.Context, signed []byte) (txid string, err error)

	// PendingTransactionInformation returns the pending-pool info for
	// a single txid. The proxy polls this to detect post-admit
	// eviction (→ 402 payment_evicted).
	PendingTransactionInformation(ctx context.Context, txid string) (models.PendingTransactionInfoResponse, error)

	// PendingTransactions returns up to max pending transactions from
	// the pool (pool-wide, not address-scoped) along with the total
	// number of transactions currently pooled. The node's mempool
	// watcher filters the returned slice by group id to find the
	// envelope's payer before admitting a sealed request.
	//
	// max must be > 0. A zero value is rejected so callers don't
	// accidentally request an unbounded pool dump via an
	// uninitialized variable — pass the intended cap explicitly.
	PendingTransactions(ctx context.Context, max uint64) (total uint64, txns []types.SignedTxn, err error)

	// SDKClient returns the underlying *sdkalgod.Client for callers
	// that must pass it to AtomicTransactionComposer (which requires
	// the concrete SDK type). Use only at ATC call sites — prefer the
	// interface methods everywhere else.
	SDKClient() *sdkalgod.Client
}

// Option tunes NewClient. The zero-option form uses DefaultTransport
// (pooled + retrying) with no per-call timeout. Per-call deadlines
// come from the ctx passed to each method; use WithTransport to swap
// in a different RoundTripper (e.g., a test fake).
type Option func(*clientConfig)

type clientConfig struct {
	transport http.RoundTripper
	headers   []*common.Header
}

// WithTransport injects a custom http.RoundTripper, replacing the
// pooled+retrying DefaultTransport NewClient would otherwise install.
// Use this to apply TLS config, custom dial timeouts, or to plug a
// test RoundTripper. Request-level deadlines should still come from
// ctx — an http.Client.Timeout wrapper will NOT be honored because
// the SDK constructs its own client around the transport.
func WithTransport(rt http.RoundTripper) Option {
	return func(c *clientConfig) { c.transport = rt }
}

// WithHeader adds an extra HTTP header to every request — useful for
// reverse proxies that require a shared secret in addition to the
// algod token.
func WithHeader(name, value string) Option {
	return func(c *clientConfig) {
		c.headers = append(c.headers, &common.Header{Key: name, Value: value})
	}
}

// NewClient builds a Client talking to the given algod endpoint with
// the given API token (sent in the X-Algo-API-Token header, which is
// what algod expects). When no WithTransport is supplied, DefaultTransport
// is installed (connection-pooled + retrying on transient 429/503/5xx);
// see Option / WithTransport for overrides.
func NewClient(endpoint, token string, opts ...Option) (Client, error) {
	var cfg clientConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.transport == nil {
		cfg.transport = DefaultTransport()
	}
	c, err := sdkalgod.MakeClientWithTransport(endpoint, token, cfg.headers, cfg.transport)
	if err != nil {
		return nil, fmt.Errorf("algod: MakeClient %q: %w", endpoint, err)
	}
	return &sdkClient{c: c}, nil
}

// sdkClient is the production backing of Client. It wraps the SDK's
// builder API in the direct method form this package exposes.
type sdkClient struct {
	c *sdkalgod.Client
}

func (s *sdkClient) SuggestedParams(ctx context.Context) (types.SuggestedParams, error) {
	return s.c.SuggestedParams().Do(ctx)
}

func (s *sdkClient) SendRawTransactionGroup(ctx context.Context, signed []byte) (string, error) {
	txid, err := s.c.SendRawTransaction(signed).Do(ctx)
	if err != nil {
		return "", fmt.Errorf("algod: SendRawTransaction: %w", err)
	}
	return txid, nil
}

func (s *sdkClient) PendingTransactionInformation(ctx context.Context, txid string) (models.PendingTransactionInfoResponse, error) {
	resp, _, err := s.c.PendingTransactionInformation(txid).Do(ctx)
	if err != nil {
		return models.PendingTransactionInfoResponse{}, fmt.Errorf("algod: PendingTransactionInformation %s: %w", txid, err)
	}
	return resp, nil
}

// PendingTransactions retrieves up to max pending transactions from
// the pool. max must be > 0 (see Client.PendingTransactions for why):
// an unbounded pool dump is almost never what the caller wants and
// uninitialized-variable slip-ups would otherwise produce one
// silently. Returns (total pending, txns, err).
func (s *sdkClient) SDKClient() *sdkalgod.Client { return s.c }

func (s *sdkClient) PendingTransactions(ctx context.Context, max uint64) (uint64, []types.SignedTxn, error) {
	if max == 0 {
		return 0, nil, fmt.Errorf("algod: PendingTransactions: max must be > 0")
	}
	total, txns, err := s.c.PendingTransactions().Max(max).Do(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("algod: PendingTransactions: %w", err)
	}
	return total, txns, nil
}
