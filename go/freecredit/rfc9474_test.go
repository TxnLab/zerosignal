/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package freecredit

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// TestRFC9474Vector pins the variant: the RFC's RSABSSA-SHA384-PSS-Deterministic
// signature verifies under this package's variant, and the day signer's Sign
// reproduces its blind signature. A switch to another variant, salt length or
// hash fails here. proto/ts replays the same file.
func TestRFC9474Vector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/rfc9474_pss_deterministic.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	hexOf := func(k string) []byte {
		b, err := hex.DecodeString(v[k].(string))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	num := func(k string) *big.Int { return new(big.Int).SetBytes(hexOf(k)) }
	if v["name"] != variant.String() {
		t.Fatalf("fixture is %v, the package runs %v", v["name"], variant)
	}
	sk := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: num("n"), E: int(num("e").Int64())},
		D:         num("d"),
		Primes:    []*big.Int{num("p"), num("q")},
	}
	sk.Precompute()
	verifier, err := blindrsa.NewVerifier(variant, &sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(hexOf("msg"), hexOf("sig")); err != nil {
		t.Errorf("the RFC's signature does not verify: %v", err)
	}
	got, err := (&DaySigner{sk: sk}).Sign(hexOf("blinded_msg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hexOf("blind_sig")) {
		t.Error("Sign does not reproduce the RFC's blind signature")
	}
}
