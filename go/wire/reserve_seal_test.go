/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSealReserveRequest_RoundTrip(t *testing.T) {
	node := newTestIdentity(t)
	// The inner plaintext is a marshaled ticket.ReserveRequest; we only
	// exercise the seal/open transport here, so any JSON suffices.
	plaintext := []byte(`{"model":"gpt-4","input_count":1024,"max_output_count":256,"stream":true,"payer_addr":"AAAA"}`)

	sealed, err := SealReserveRequest(plaintext, node.Recipient())
	if err != nil {
		t.Fatalf("SealReserveRequest: %v", err)
	}

	// The payer_addr must not survive in the clear inside the sealed bytes.
	if bytes.Contains(sealed, []byte("payer_addr")) || bytes.Contains(sealed, []byte("AAAA")) {
		t.Fatalf("sealed reserve leaks plaintext fields: %s", sealed)
	}

	got, err := OpenReserveRequest(sealed, node)
	if err != nil {
		t.Fatalf("OpenReserveRequest: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestOpenReserveRequest_WrongIdentity(t *testing.T) {
	node := newTestIdentity(t)
	other := newTestIdentity(t)

	sealed, err := SealReserveRequest([]byte(`{"model":"m"}`), node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReserveRequest(sealed, other); err == nil {
		t.Fatal("OpenReserveRequest with wrong identity should fail")
	}
}

func TestSealReserveRequest_NilRecipient(t *testing.T) {
	if _, err := SealReserveRequest([]byte(`{}`), nil); err == nil {
		t.Fatal("SealReserveRequest with nil recipient should fail")
	}
}

func TestOpenReserveRequest_Malformed(t *testing.T) {
	node := newTestIdentity(t)

	cases := []struct {
		name string
		in   []byte
	}{
		{"not-json", []byte("not an envelope")},
		{"empty-ciphertext", []byte(`{"ciphertext":""}`)},
		{"bad-base64", []byte(`{"ciphertext":"!!!not-base64!!!"}`)},
		{"non-age-ciphertext", []byte(`{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("garbage")) + `"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OpenReserveRequest(tc.in, node); err == nil {
				t.Fatalf("OpenReserveRequest(%s) should fail", tc.name)
			}
		})
	}
}

// TestSealedReserveContentType pins the wire constant: a sealed reserve must
// be distinguishable from a sealed inference envelope by content-type alone.
func TestSealedReserveContentType(t *testing.T) {
	if SealedReserveContentType != "application/vnd.zs-reserve+json" {
		t.Errorf("SealedReserveContentType = %q, want application/vnd.zs-reserve+json", SealedReserveContentType)
	}
	if SealedReserveContentType == EncryptedContentType {
		t.Errorf("SealedReserveContentType must differ from EncryptedContentType (%q)", EncryptedContentType)
	}
}

// TestSealReserveRequest_EnvelopeShape locks the on-wire JSON to a single
// ciphertext field (no reply-to / tx_id / admission tag leaking in).
func TestSealReserveRequest_EnvelopeShape(t *testing.T) {
	node := newTestIdentity(t)
	sealed, err := SealReserveRequest([]byte(`{"model":"m"}`), node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(sealed, &fields); err != nil {
		t.Fatalf("unmarshal sealed envelope: %v", err)
	}
	if len(fields) != 1 {
		t.Errorf("sealed reserve envelope has %d fields, want 1: %v", len(fields), fields)
	}
	if _, ok := fields["ciphertext"]; !ok {
		t.Errorf("sealed reserve envelope missing ciphertext field: %v", fields)
	}
}

func TestSealReserveResponse_RoundTrip(t *testing.T) {
	proxy := newTestIdentity(t)
	body := []byte(`{"ticket":{"ticket_id":"abc"},"presigned_open_txn":"PAYERADDR"}`)

	sealed, err := SealReserveResponse(body, proxy.Recipient())
	if err != nil {
		t.Fatalf("SealReserveResponse: %v", err)
	}
	if bytes.Contains(sealed, []byte("PAYERADDR")) {
		t.Fatal("sealed reserve response leaks its plaintext")
	}
	got, err := OpenReserveResponse(sealed, proxy)
	if err != nil {
		t.Fatalf("OpenReserveResponse: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("got %q, want %q", got, body)
	}
}

func TestOpenReserveResponse_WrongIdentity(t *testing.T) {
	proxy := newTestIdentity(t)
	other := newTestIdentity(t)
	sealed, err := SealReserveResponse([]byte(`{}`), proxy.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReserveResponse(sealed, other); err == nil {
		t.Fatal("want error with wrong identity, got nil")
	}
}

func TestSealReserveResponse_NilRecipient(t *testing.T) {
	if _, err := SealReserveResponse([]byte(`{}`), nil); err == nil {
		t.Fatal("want error with nil recipient")
	}
}

func TestOpenReserveResponse_NilIdentity(t *testing.T) {
	if _, err := OpenReserveResponse([]byte(`{"ciphertext":"x"}`), nil); err == nil {
		t.Fatal("want error with nil identity")
	}
}

// The two reserve legs seal to different recipients, so neither can open the
// other's envelope even though they share a wire shape.
func TestSealedReserveResponseContentType(t *testing.T) {
	for _, other := range []string{SealedReserveContentType, EncryptedContentType} {
		if SealedReserveResponseContentType == other {
			t.Errorf("SealedReserveResponseContentType must differ from %q", other)
		}
	}
}
