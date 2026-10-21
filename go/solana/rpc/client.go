/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package rpc is a thin Solana JSON-RPC client: the methods the payer and
// node rails call, over one pooled HTTP/2 transport with a retry policy for
// the RPC's weather, and a WebSocket client for signatureSubscribe. It decodes
// the RPC's envelopes only; account data comes back as bytes for
// solana/zsescrow's decoders.
//
// It is hand-rolled rather than solana-go, which brings zap, mongo-driver and
// more into this module, a dependency of every consumer.
//
// The TS twin is sdk/src/solana/rpc.ts and pubsub.ts. The retry budget, which
// outcomes retry, the wait before each retry and the params each method sends
// are pinned by testdata/solana_rpc_vectors.json.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/solana"
)

// Client is the RPC surface the rails depend on. HTTPClient backs it in
// production; a test hands its code a fake.
type Client interface {
	// GetAccountInfo returns ErrNotFound for an account that does not exist.
	GetAccountInfo(ctx context.Context, key solana.PublicKey, c Commitment) (*Account, error)
	GetProgramAccounts(ctx context.Context, program solana.PublicKey, c Commitment, filters ...Filter) ([]KeyedAccount, error)
	GetBalance(ctx context.Context, key solana.PublicKey, c Commitment) (uint64, error)
	GetLatestBlockhash(ctx context.Context, c Commitment) (Blockhash, error)
	GetBlockHeight(ctx context.Context, c Commitment) (uint64, error)
	GetGenesisHash(ctx context.Context) (solana.Hash, error)
	SendTransaction(ctx context.Context, tx []byte, o SendOptions) (solana.Signature, error)
	GetSignatureStatuses(ctx context.Context, sigs []solana.Signature, searchHistory bool) ([]*SignatureStatus, error)
}

// ErrNotFound is an account the RPC reports does not exist (a null value).
var ErrNotFound = errors.New("solana rpc: account not found")

// Error is a JSON-RPC error in a 2xx answer.
type Error struct {
	Method  string
	Code    int
	Message string
	// Data is the error's data member as sent, nil when absent.
	Data json.RawMessage
}

func (e *Error) Error() string {
	return fmt.Sprintf("solana rpc %s: %d %s", e.Method, e.Code, e.Message)
}

// TxErrName is the variant of a failed simulation's TransactionError (see
// TxErrName), "" for any other error. A resend of a transaction that already
// landed fails its simulation as "AlreadyProcessed": the cluster has it.
func (e *Error) TxErrName() string {
	if e.Code != CodePreflightFailure {
		return ""
	}
	// A map, not a struct: Go matches struct fields case-insensitively, and
	// the TS twin reads only the exact key.
	var data map[string]json.RawMessage
	if json.Unmarshal(e.Data, &data) != nil {
		return ""
	}
	return TxErrName(data["err"])
}

// HTTPError is a non-2xx answer.
type HTTPError struct {
	Method string
	Status int
	// Body is the answer's start, for a log line.
	Body []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("solana rpc %s: HTTP %d: %s", e.Method, e.Status, e.Body)
}

const errorBodyExcerpt = 512

// Option tunes NewClient.
type Option func(*HTTPClient)

// WithTransport replaces DefaultTransport, to set TLS or the proxy, or to
// plug a test RoundTripper. The retry policy still applies over it.
func WithTransport(rt http.RoundTripper) Option {
	return func(c *HTTPClient) { c.hc = &http.Client{Transport: rt} }
}

// WithHeader adds a header to every request, for a provider that takes its
// API key in one.
func WithHeader(name, value string) Option {
	return func(c *HTTPClient) { c.header.Add(name, value) }
}

// WithRetry replaces DefaultRetry.
func WithRetry(p RetryPolicy) Option {
	return func(c *HTTPClient) { c.retry = p }
}

// DefaultTransport is the pooled transport NewClient uses: http.DefaultTransport's
// HTTP/2 over TLS, with algod's per-host pool. The public endpoints cap new
// connections per IP at 40 per 10 s, so concurrent calls must share
// connections rather than dial their own as HTTP/1.1 does once its idle pool
// is spent.
func DefaultTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100
	return t
}

// HTTPClient is the JSON-RPC client over HTTP. It is safe for concurrent use.
type HTTPClient struct {
	endpoint string
	hc       *http.Client
	header   http.Header
	retry    RetryPolicy
	ids      atomic.Uint64
}

var _ Client = (*HTTPClient)(nil)

// NewClient returns a client for the RPC at endpoint, an http or https URL
// with any path and query a provider needs. No error spells the endpoint,
// since a provider's API key often rides in its query.
func NewClient(endpoint string, opts ...Option) (*HTTPClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("solana rpc: endpoint: %w", stripURL(err))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("solana rpc: endpoint is not http or https")
	}
	// Refused rather than sent as Basic auth, as Go's transport would: the
	// TS twin's fetch refuses such a URL, and the two take the same endpoints.
	if u.User != nil {
		return nil, errors.New("solana rpc: endpoint carries credentials; pass them with WithHeader")
	}
	c := &HTTPClient{endpoint: endpoint, header: http.Header{}, retry: DefaultRetry()}
	for _, o := range opts {
		o(c)
	}
	if c.hc == nil {
		c.hc = &http.Client{Transport: DefaultTransport()}
	}
	return c, nil
}

// stripURL drops the URL a *url.Error spells out: a provider's API key often
// rides in its query.
func stripURL(err error) error {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		return ue.Err
	}
	return err
}

type request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type response struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// call sends method with params and decodes the result into out, retrying
// the outcomes shouldRetry names under c.retry.
func (c *HTTPClient) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(request{JSONRPC: "2.0", ID: c.ids.Add(1), Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("solana rpc %s: encode params: %w", method, err)
	}
	for attempt := 0; ; attempt++ {
		result, status, retryAfter, err := c.post(ctx, method, body)
		if err == nil {
			if out == nil {
				return nil
			}
			if err := json.Unmarshal(result, out); err != nil {
				return fmt.Errorf("solana rpc %s: decode result: %w", method, err)
			}
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		rpcErr, _ := errors.AsType[*Error](err)
		if !shouldRetry(method, status, rpcErr) || attempt >= c.retry.MaxRetries {
			return err
		}
		wait := httpx.LinearBackoff(attempt, retryAfter, time.Now(), c.retry.WaitMin, c.retry.WaitMax)
		slog.Default().Debug("solana rpc retry",
			slog.String("method", method),
			slog.Any("err", err),
			slog.Int("status", status),
			slog.Duration("wait", wait),
			slog.Int("attempt", attempt+1),
			slog.Int("max", c.retry.MaxRetries+1),
		)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// post makes one attempt. status is 0 when no complete answer arrived, which
// includes a body cut off mid-read: that is the connection's failure, not
// the RPC's answer.
func (c *HTTPClient) post(ctx context.Context, method string, body []byte) (result json.RawMessage, status int, retryAfter string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, "", fmt.Errorf("solana rpc %s: %w", method, stripURL(err))
	}
	for k, v := range c.header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("solana rpc %s: %w", method, stripURL(err))
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("solana rpc %s: read answer: %w", method, err)
	}
	status, retryAfter = res.StatusCode, res.Header.Get("Retry-After")
	if status < 200 || status > 299 {
		return nil, status, retryAfter, &HTTPError{Method: method, Status: status, Body: raw[:min(len(raw), errorBodyExcerpt)]}
	}
	var r response
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, status, retryAfter, fmt.Errorf("solana rpc %s: decode answer: %w", method, err)
	}
	if r.Error != nil {
		return nil, status, retryAfter, &Error{Method: method, Code: r.Error.Code, Message: r.Error.Message, Data: r.Error.Data}
	}
	// None of these methods answers a null result, and decoding one would
	// leave a zero value that reads as a real answer (an account not found).
	if r.Result == nil || string(r.Result) == "null" {
		return nil, status, retryAfter, fmt.Errorf("solana rpc %s: answer has neither result nor error", method)
	}
	return r.Result, status, retryAfter, nil
}
