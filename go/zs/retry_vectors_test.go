/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/error_retry_vectors.json: an Error's
// kind, code and cause in, Retryable out. Every code in errorKinds is a row,
// so a new code lands in the fixture and fails the check until regenerated.
// Those are the only causeless rows: a port reads them back as the whole
// table, so give any further row a cause.
//
//	cd proto/go && go test ./zs -run TestRetryVectors -update

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"testing"
)

const retryVectorsPath = "../../testdata/error_retry_vectors.json"

type retryVectorCase struct {
	Kind Kind   `json:"kind"`
	Code string `json:"code"`
	// ProviderCode, when present, makes the cause a ProviderError with that
	// code and NodeStatus as the status of the reply that carried it (0: a
	// stream frame); NodeStatus alone makes it a NodeReply with that status.
	ProviderCode *string `json:"provider_code,omitempty"`
	NodeStatus   int     `json:"node_status,omitempty"`

	Retryable bool `json:"retryable"`
}

func retryVectorInputs() []retryVectorCase {
	var cases []retryVectorCase
	for _, code := range slices.Sorted(maps.Keys(errorKinds)) {
		cases = append(cases, retryVectorCase{Kind: errorKinds[code], Code: code})
	}
	// The node's own code on an upstream failure: the allowlist, a code that
	// is the caller's to fix, a generic one, and none.
	for _, pc := range []string{
		"provider_overloaded", "provider_error", "upstream_truncated", "rate_limit_exceeded", "payment_verification_failed",
		"context_length_exceeded", "image_generation_failed", "",
	} {
		cases = append(cases, retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &pc})
	}
	// A failed reply whose body has an error but no code: its status decides,
	// and a code it does give outranks the status.
	noCode, refused := "", "context_length_exceeded"
	cases = append(cases,
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &noCode, NodeStatus: 429},
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &noCode, NodeStatus: 502},
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &noCode, NodeStatus: 503},
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &noCode, NodeStatus: 504},
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &noCode, NodeStatus: 400},
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &noCode, NodeStatus: 507},
		retryVectorCase{Kind: KindUpstream, Code: "upstream_error", ProviderCode: &refused, NodeStatus: 503},
	)
	// A failed sealed reply that did not say why: the node retries only 429
	// and 502-504, so the 5xx either side of that run is not retryable.
	for _, st := range []int{400, 429, 500, 501, 502, 503, 504, 505, 507} {
		cases = append(cases, retryVectorCase{Kind: KindUpstream, Code: "upstream_error", NodeStatus: st})
	}
	// A paid turn the node refused before its envelope opened: a refusal a new
	// ticket gets past, one the SDK would repeat, and code-less statuses either
	// side of the line.
	for _, r := range []struct {
		code   string
		status int
	}{
		{"ticket_invalid", 402}, {"payment_verification_failed", 402},
		{"ticket_required", 402}, {"admission_tag_invalid", 402}, {"bad_envelope", 400},
		{"request_too_large", 413}, {"node_draining", 503},
		{"", 408}, {"", 429}, {"", 500}, {"", 502}, {"", 504}, {"", 507}, {"", 404},
		// The caller's cancel outranks whatever the node answered.
		{"canceled", 503},
	} {
		cases = append(cases, retryVectorCase{Kind: KindInterrupted, Code: r.code, NodeStatus: r.status})
	}
	return cases
}

func runRetryVector(c retryVectorCase) retryVectorCase {
	e := &Error{Kind: c.Kind, Code: c.Code}
	switch {
	case c.ProviderCode != nil:
		e.Err = &ProviderError{Code: *c.ProviderCode, Status: c.NodeStatus}
	case c.NodeStatus != 0:
		e.Err = &NodeReply{Status: c.NodeStatus}
	}
	c.Retryable = retryable(e)
	return c
}

func TestRetryVectors(t *testing.T) {
	var got []retryVectorCase
	for _, c := range retryVectorInputs() {
		got = append(got, runRetryVector(c))
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(retryVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(retryVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("Retryable differs from %s; if the change is intended, regenerate with -update and review the diff", retryVectorsPath)
	}
}
