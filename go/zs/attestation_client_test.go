/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// testOperatorAndPubkey returns an Operator and the string used as the bundle's
// NodePubkey, in lockstep so the verifier's cross-check passes. The TEE
// key-binding target is the node's current ephemeral age recipient.
func testOperatorAndPubkey(t *testing.T, id uint64) (Operator, string) {
	t.Helper()
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	recipient := ageID.Recipient().String()
	return Operator{
		ID:                       id,
		SigningAddr:              "SIGNING-ADDR-NOT-THE-BINDING-TARGET",
		EphemeralRecipientPubkey: recipient,
	}, recipient
}

// stubBundleFor returns a well-formed stub-mode evidence bundle bound to
// (nodePubkey, operatorID), as a node running tee.mode=stub serves it.
func stubBundleFor(nodePubkey string, operatorID uint64) inject.TEEEvidenceBundle {
	var idBytes [8]byte
	binary.BigEndian.PutUint64(idBytes[:], operatorID)
	h := sha256.New()
	h.Write([]byte(nodePubkey))
	h.Write(idBytes[:])
	return inject.TEEEvidenceBundle{
		Mode:           inject.TEEModeStub,
		NodePubkey:     nodePubkey,
		OperatorID:     operatorID,
		ReportData:     base64.StdEncoding.EncodeToString(h.Sum(nil)),
		GeneratedAt:    time.Now().UTC(),
		RefreshSeconds: 60,
		Stub:           true,
	}
}

func TestAttestationClient_FetchHappyPath(t *testing.T) {
	want := stubBundleFor("age1abc", 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/attestation" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", inject.AttestationContentType)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	c := NewAttestationClient(srv.Client(), 2*time.Second)
	got, err := c.Fetch(context.Background(), srv.URL, "/v1/zs/attestation", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Mode != want.Mode || got.NodePubkey != want.NodePubkey || got.OperatorID != want.OperatorID {
		t.Errorf("bundle round-trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestAttestationClient_FetchNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewAttestationClient(srv.Client(), 500*time.Millisecond)
	_, err := c.Fetch(context.Background(), srv.URL, "/v1/zs/attestation", nil)
	if err == nil {
		t.Fatal("Fetch should error on 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention 503: %v", err)
	}
}

func TestAttestationClient_FetchEmptyEvidenceURL(t *testing.T) {
	// Empty evidence URL → falls back to /v1/zs/attestation on
	// the operator's BaseURL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/attestation" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(stubBundleFor("age1abc", 7))
	}))
	defer srv.Close()
	c := NewAttestationClient(srv.Client(), 2*time.Second)
	if _, err := c.Fetch(context.Background(), srv.URL, "", nil); err != nil {
		t.Fatalf("empty evidence URL fallback failed: %v", err)
	}
}

func TestAttestationClient_FetchAbsoluteEvidenceURL(t *testing.T) {
	// Absolute URL (different host) is honored verbatim.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stubBundleFor("age1abc", 7))
	}))
	defer srv.Close()
	c := NewAttestationClient(srv.Client(), 2*time.Second)
	if _, err := c.Fetch(context.Background(), "http://operator.example", srv.URL, nil); err != nil {
		t.Fatalf("absolute evidence URL failed: %v", err)
	}
}

func TestJoinAttestationURL(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		evidence string
		want     string
		wantErr  bool
	}{
		{"empty evidence falls back", "https://op.example", "", "https://op.example/v1/zs/attestation", false},
		{"trailing slash stripped", "https://op.example/", "/v1/zs/attestation", "https://op.example/v1/zs/attestation", false},
		{"path normalized", "https://op.example", "v1/zs/attestation", "https://op.example/v1/zs/attestation", false},
		{"absolute http accepted", "https://op.example", "http://other.example/x", "http://other.example/x", false},
		{"absolute https accepted", "https://op.example", "https://other.example/x", "https://other.example/x", false},
		{"empty base errors", "", "/v1/zs/attestation", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := joinAttestationURL(tc.base, tc.evidence)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOperator_IsTEEAttested(t *testing.T) {
	cases := []struct {
		name string
		op   Operator
		want bool
	}{
		{"nil TEE", Operator{}, false},
		{"verified", Operator{TEE: &TEEStatus{Verified: true}}, true},
		{"populated but not verified", Operator{TEE: &TEEStatus{Verified: false, FailureTag: tee.FailureKeyBindingMismatch}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.op.IsTEEAttested(); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// The verifier sees the operator's identity and the key the payer will seal
// to, which is what the evidence must bind.
func TestOperator_TEENode(t *testing.T) {
	op := Operator{ID: 7, NodeID: 3, EphemeralRecipientPubkey: "age1key", SigningAddr: "SIGNER"}
	if got, want := op.TEENode(), (tee.Node{OperatorID: 7, NodeID: 3, EphemeralRecipientPubkey: "age1key"}); got != want {
		t.Errorf("TEENode = %+v, want %+v", got, want)
	}
}
