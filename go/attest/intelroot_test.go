/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

// The fingerprint is a literal, not recomputed from the embedded file: this is
// the TDX root of trust, and a test deriving its expectation from the bytes
// under test would pass for any certificate at all.
const intelSGXRootCASHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

func TestIntelSGXRootCA_IsPinned(t *testing.T) {
	sum := sha256.Sum256(intelSGXRootCA.Raw)
	if got := hex.EncodeToString(sum[:]); got != intelSGXRootCASHA256 {
		t.Fatalf("embedded Intel root fingerprint = %s, want %s", got, intelSGXRootCASHA256)
	}
	if cn := intelSGXRootCA.Subject.CommonName; cn != "Intel SGX Root CA" {
		t.Fatalf("embedded Intel root CN = %q", cn)
	}
}

func TestIntelSGXRootCAs_PoolsAreIndependent(t *testing.T) {
	a, b := IntelSGXRootCAs(), IntelSGXRootCAs()
	if a == b {
		t.Fatal("IntelSGXRootCAs returned a shared pool")
	}
	// Against a pool built here rather than a second call: a widened pool
	// (system roots plus Intel) is equal to itself on every call.
	want := x509.NewCertPool()
	want.AddCert(intelSGXRootCA)
	if !a.Equal(want) || !b.Equal(want) {
		t.Fatal("pool trusts something other than exactly the pinned Intel root")
	}
}
