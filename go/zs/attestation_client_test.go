/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

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

// A pass routing refuses would otherwise be silent: the node verifies and then
// never receives Require-TEE traffic. The TS twin is the matching test in
// sdk/test/attestation.test.ts.
func TestProbeAttestation_WarnsOnAPassThatIsNotAttested(t *testing.T) {
	const msg = "operator attestation passed but is not attested for routing"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"mode":"dstack-tdx","generated_at":"2026-10-01T00:00:00Z","refresh_seconds":1200}`))
	}))
	defer srv.Close()
	details := inject.OperatorDetails{TEE: &inject.TEEAdvertisement{Mode: inject.TEEModeDstackTDX}}

	for _, tc := range []struct {
		name     string
		checks   *tee.MeasurementChecks
		wantWarn bool
	}{
		{"attested", &tee.MeasurementChecks{OSImage: true, ComposeRelease: true}, false},
		{"no published release", &tee.MeasurementChecks{OSImage: true, ComposeHash: true}, true},
		{"untrusted OS image", &tee.MeasurementChecks{ComposeRelease: true}, true},
		{"no checks, as a stub", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
			s := &ChainOperatorSource{TEEVerifier: &stubTEEVerifier{verdict: tee.Verdict{
				Pass: true, VerifierID: tee.VerifierIDDstack, MeasurementChecks: tc.checks,
			}}}
			op := Operator{ID: 7, NodeID: 2, BaseURL: srv.URL, EphemeralRecipientPubkey: "age1recipient"}
			s.probeAttestation(context.Background(), &op, details, NewAttestationClient(srv.Client(), 5*time.Second), nil, log)

			if got := strings.Contains(logged.String(), msg); got != tc.wantWarn {
				t.Fatalf("warned = %v, want %v; log: %s", got, tc.wantWarn, logged.String())
			}
			if tc.wantWarn {
				var rec map[string]any
				if err := json.Unmarshal(logged.Bytes(), &rec); err != nil {
					t.Fatalf("decode log line: %v", err)
				}
				wantOS := tc.checks != nil && tc.checks.OSImage
				wantRelease := tc.checks != nil && tc.checks.ComposeRelease
				if rec["os_image_checked"] != wantOS || rec["compose_release_checked"] != wantRelease {
					t.Fatalf("log attrs = %v", rec)
				}
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
		{"verified on both checks", Operator{TEE: &TEEStatus{Verified: true, OSImageChecked: true, ComposeReleaseChecked: true}}, true},
		{"verified on the OS image only", Operator{TEE: &TEEStatus{Verified: true, OSImageChecked: true}}, false},
		{"verified on the compose release only", Operator{TEE: &TEEStatus{Verified: true, ComposeReleaseChecked: true}}, false},
		{"verified with no checks, as a stub", Operator{TEE: &TEEStatus{Verified: true}}, false},
		{"populated but not verified", Operator{TEE: &TEEStatus{Verified: false, FailureTag: tee.FailureKeyBindingMismatch}}, false},
		{"refused, whatever the checks say", Operator{TEE: &TEEStatus{OSImageChecked: true, ComposeReleaseChecked: true}}, false},
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
