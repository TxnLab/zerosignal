/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"container/list"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
)

// AffinityPolicy controls how strictly the proxy prefers the operator
// that served a previous turn of a tool-calling conversation.
type AffinityPolicy string

const (
	// AffinityPrefer (default): try the affinity-preferred operator
	// first; on 429 or other error, fall through to normal selection.
	AffinityPrefer AffinityPolicy = "prefer"

	// AffinityStrict: only the preferred operator is attempted; if it's
	// busy the caller is expected to wait per its Retry-After rather
	// than switching operators (useful when KV-cache reuse matters more
	// than latency).
	AffinityStrict AffinityPolicy = "strict"

	// AffinityNone: ignore affinity entirely — always run normal
	// selection.
	AffinityNone AffinityPolicy = "none"
)

// ValidAffinityPolicy returns true if v is one of the recognized
// AffinityPolicy constants.
func ValidAffinityPolicy(v AffinityPolicy) bool {
	switch v {
	case AffinityPrefer, AffinityStrict, AffinityNone:
		return true
	}
	return false
}

// IDAffinity is a bounded TTL+LRU map from a string id (typically a
// tool_call_id or Responses call_id from a prior response, or a response_id
// from the Responses API) to the operator's id (the stable on-chain id, not
// the payment address). The dispatcher uses it to pin continuation requests to the
// same operator so KV-cache reuse and Responses API session state
// (which lives in the operator's upstream account) stay coherent.
//
// Safe for concurrent use.
type IDAffinity struct {
	ttl time.Duration
	max int
	now func() time.Time // injected for deterministic tests

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = most recent
}

// affinityEntry is the LRU payload. It pins to the exact (operator, node):
// continuation state — KV cache and the Responses API session — lives in a
// specific node's upstream account, so a continuation must return to that node,
// not merely to its operator (which under the operator/node split runs many).
type affinityEntry struct {
	id         string
	operatorID uint64
	nodeID     uint64
	expiresAt  time.Time
}

// NewIDAffinity constructs a cache with max entries and per-entry TTL.
// Pass nil for now to use time.Now.
func NewIDAffinity(max int, ttl time.Duration, now func() time.Time) *IDAffinity {
	if now == nil {
		now = time.Now
	}
	if max <= 0 {
		max = 1024
	}
	return &IDAffinity{
		ttl:     ttl,
		max:     max,
		now:     now,
		entries: make(map[string]*list.Element, max),
		order:   list.New(),
	}
}

// Record associates each id with the (operatorID, nodeID) that served it.
// Existing entries are overwritten (same id issued by a different node later
// wins — shouldn't happen under normal operation, but the write-wins rule
// keeps the cache consistent if it does).
func (c *IDAffinity) Record(operatorID, nodeID uint64, ids []string) {
	if operatorID == 0 || len(ids) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	expiresAt := c.now().Add(c.ttl)
	for _, id := range ids {
		if id == "" {
			continue
		}
		if el, ok := c.entries[id]; ok {
			e := el.Value.(*affinityEntry)
			e.operatorID = operatorID
			e.nodeID = nodeID
			e.expiresAt = expiresAt
			c.order.MoveToFront(el)
			continue
		}
		el := c.order.PushFront(&affinityEntry{
			id:         id,
			operatorID: operatorID,
			nodeID:     nodeID,
			expiresAt:  expiresAt,
		})
		c.entries[id] = el
	}
	c.evictLocked()
}

// Lookup returns (operatorID, nodeID, true) if id has a live entry. Expired
// entries are swept on access; misses and expiries both return (0, 0, false).
func (c *IDAffinity) Lookup(id string) (uint64, uint64, bool) {
	if id == "" {
		return 0, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[id]
	if !ok {
		return 0, 0, false
	}
	e := el.Value.(*affinityEntry)
	if c.now().After(e.expiresAt) {
		c.order.Remove(el)
		delete(c.entries, id)
		return 0, 0, false
	}
	c.order.MoveToFront(el)
	return e.operatorID, e.nodeID, true
}

// Size returns the current entry count. For tests and metrics.
func (c *IDAffinity) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *IDAffinity) evictLocked() {
	for len(c.entries) > c.max {
		back := c.order.Back()
		if back == nil {
			return
		}
		e := back.Value.(*affinityEntry)
		c.order.Remove(back)
		delete(c.entries, e.id)
	}
}

// --- request / response body parsing ---------------------------------
//
// These delegate to proto/go/selection so the proxy and the client/ chat app
// derive identical affinity keys and tool sets from a request body — proto is
// the single source of truth (see selection/extract.go).

// ExtractModel pulls the top-level "model" string from a request body.
func ExtractModel(body []byte) string { return selection.ExtractModel(body) }

// ExtractRequestedBuiltinTools returns every `zs_*` tool type in tools[], in order.
func ExtractRequestedBuiltinTools(body []byte) []string {
	return selection.ExtractRequestedBuiltinTools(body)
}

// ExtractInputToolCallIDs returns the tool-call ids a request answers, in
// order: chat tool_call_id values, then Responses input[] call_id values — the
// affinity cache keys.
func ExtractInputToolCallIDs(body []byte) []string {
	return selection.ExtractInputToolCallIDs(body)
}

// ExtractResponseToolCallIDs returns the tool-call ids a response issues: chat
// tool_calls[].id across every choice, then Responses output[] call_id values.
func ExtractResponseToolCallIDs(body []byte) []string {
	return selection.ExtractResponseToolCallIDs(body)
}

// ExtractPreviousResponseID pulls "previous_response_id" from a /v1/responses request body.
func ExtractPreviousResponseID(body []byte) string {
	return selection.ExtractPreviousResponseID(body)
}

// ExtractResponseID pulls top-level "id" from a /v1/responses non-streaming response body.
func ExtractResponseID(body []byte) string { return selection.ExtractResponseID(body) }

// ExtractResponseIDFromFrame pulls response.id from a decrypted SSE data payload
// for response.created / response.completed frames.
func ExtractResponseIDFromFrame(frameData []byte) string {
	return selection.ExtractResponseIDFromFrame(frameData)
}
