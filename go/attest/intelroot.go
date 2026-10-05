/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

// intelSGXRootCAPEM is Intel's SGX Root CA, the anchor every TDX PCK chain
// and every TCB-info / QE-identity signing chain terminates at. The same
// certificate as go-tdx-guest's verify/trusted_root.pem.
//
//go:embed intel_sgx_root_ca.pem
var intelSGXRootCAPEM []byte

var intelSGXRootCA = mustParseIntelRoot()

// IntelSGXRootCAs returns a fresh pool holding only Intel's SGX Root CA, for
// go-tdx-guest's verify.Options.TrustedRoots.
//
// WHY WE PASS IT RATHER THAN LEAVE TrustedRoots NIL: nil makes go-tdx-guest
// fall back to the same certificate from an unexported variable, and log a
// warning to STDOUT through a global logger nothing here can scope, once for
// each chain it checks (three per quote) — into the output of any CLI that
// verifies a quote. Naming the anchor ourselves keeps the root of
// trust a value this module owns and pins (intelroot_test.go) instead of a
// library default that could change under a dependency bump.
//
// A fresh pool per call because x509.CertPool is mutable and shared state
// across verifiers is how an AddCert in one caller widens another's trust.
func IntelSGXRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(intelSGXRootCA)
	return pool
}

func mustParseIntelRoot() *x509.Certificate {
	block, _ := pem.Decode(intelSGXRootCAPEM)
	if block == nil {
		panic("attest: embedded Intel SGX Root CA is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("attest: embedded Intel SGX Root CA: " + err.Error())
	}
	return cert
}
