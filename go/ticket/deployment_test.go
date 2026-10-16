/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testGenesis(fill byte) []byte { return bytes.Repeat([]byte{fill}, 32) }

func mustAlgorandID(t *testing.T, genesisFill byte, appID uint64) DeploymentID {
	t.Helper()
	d, err := AlgorandDeploymentID(testGenesis(genesisFill), appID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDeploymentID_Preimage(t *testing.T) {
	genesis := testGenesis(0xAB)
	got, err := AlgorandDeploymentID(genesis, 0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}
	var pre []byte
	pre = append(pre, "zs-deployment-v1\x00"...)
	pre = append(pre, 1)
	pre = append(pre, genesis...)
	pre = append(pre, 0, 0, 0, 8)
	pre = append(pre, 1, 2, 3, 4, 5, 6, 7, 8)
	if want := DeploymentID(sha256.Sum256(pre)); got != want {
		t.Fatalf("algorand id = %x, want %x", got, want)
	}

	program := bytes.Repeat([]byte{0x5A}, 32)
	sol, err := SolanaDeploymentID(genesis, program)
	if err != nil {
		t.Fatal(err)
	}
	pre = pre[:0]
	pre = append(pre, "zs-deployment-v1\x00"...)
	pre = append(pre, 2)
	pre = append(pre, genesis...)
	pre = binary.BigEndian.AppendUint32(pre, 32)
	pre = append(pre, program...)
	if want := DeploymentID(sha256.Sum256(pre)); sol != want {
		t.Fatalf("solana id = %x, want %x", sol, want)
	}
}

// Every input separates deployments: the rail, the genesis and the escrow id.
func TestDeploymentID_InputsSeparate(t *testing.T) {
	base := mustAlgorandID(t, 1, 100)
	if mustAlgorandID(t, 2, 100) == base {
		t.Fatal("genesis hash did not change the id")
	}
	if mustAlgorandID(t, 1, 101) == base {
		t.Fatal("app id did not change the id")
	}
	// Same 8 escrow bytes on the other rail.
	other, err := NewDeploymentID(RailSolana, testGenesis(1), binary.BigEndian.AppendUint64(nil, 100))
	if err != nil {
		t.Fatal(err)
	}
	if other == base {
		t.Fatal("rail did not change the id")
	}
}

func TestDeploymentID_RefusesBadInputs(t *testing.T) {
	cases := map[string]func() error{
		"unknown rail":  func() error { _, err := NewDeploymentID(3, testGenesis(1), []byte{1}); return err },
		"rail zero":     func() error { _, err := NewDeploymentID(0, testGenesis(1), []byte{1}); return err },
		"short genesis": func() error { _, err := NewDeploymentID(RailAlgorand, testGenesis(1)[:31], []byte{1}); return err },
		"long genesis": func() error {
			_, err := NewDeploymentID(RailAlgorand, append(testGenesis(1), 0), []byte{1})
			return err
		},
		"empty escrow":  func() error { _, err := NewDeploymentID(RailAlgorand, testGenesis(1), nil); return err },
		"app id zero":   func() error { _, err := AlgorandDeploymentID(testGenesis(1), 0); return err },
		"short program": func() error { _, err := SolanaDeploymentID(testGenesis(1), make([]byte, 31)); return err },
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDeploymentID_JSON(t *testing.T) {
	d := mustAlgorandID(t, 1, 100)
	raw, err := json.Marshal(struct {
		D DeploymentID `json:"d,omitzero"`
	}{d})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"d":"` + d.String() + `"}`; string(raw) != want {
		t.Fatalf("marshal = %s, want %s", raw, want)
	}
	var back struct {
		D DeploymentID `json:"d"`
	}
	if err := json.Unmarshal(raw, &back); err != nil || back.D != d {
		t.Fatalf("round trip = %x, %v", back.D, err)
	}

	empty, _ := json.Marshal(struct {
		D DeploymentID `json:"d,omitzero"`
	}{})
	if string(empty) != `{}` {
		t.Fatalf("zero id marshalled as %s, want omitted", empty)
	}

	for _, bad := range []string{
		`{"d":"AAAA"}`, // 3 bytes
		`{"d":"` + strings.Repeat("A", 43) + `="}`, // 32 zero bytes
		`{"d":"not base64!"}`,
	} {
		var v struct {
			D DeploymentID `json:"d"`
		}
		if err := json.Unmarshal([]byte(bad), &v); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// A ticket JSON with no deployment field is byte-identical to the pre-binding
// shape, so a payer that predates the field parses it unchanged.
func TestTicket_UnboundJSONHasNoDeploymentKey(t *testing.T) {
	raw, err := json.Marshal(sampleTicket())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("deployment")) {
		t.Fatalf("unbound ticket JSON carries a deployment key: %s", raw)
	}
}

func TestTicket_BoundLayout(t *testing.T) {
	d := mustAlgorandID(t, 1, 100)
	unbound := sampleTicket()
	bound := sampleTicket()
	bound.Deployment = d

	v2 := unbound.CanonicalBytes()
	v3 := bound.CanonicalBytes()
	// v3 = "zs-ticket-v3\x00" ‖ deployment ‖ the v2 body after its tag.
	var want []byte
	want = append(want, "zs-ticket-v3\x00"...)
	want = append(want, d[:]...)
	want = append(want, v2[len("zs-ticket-v2\x00"):]...)
	if !bytes.Equal(v3, want) {
		t.Fatalf("v3 layout:\n got %x\nwant %x", v3, want)
	}
}

func TestTicket_VerifyFor(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	mine := mustAlgorandID(t, 1, 100)
	other := mustAlgorandID(t, 2, 100)

	bound := sampleTicket()
	bound.Deployment = mine
	if err := bound.Sign(context.Background(), signer, addr); err != nil {
		t.Fatal(err)
	}
	legacy := sampleTicket()
	if err := legacy.Sign(context.Background(), signer, addr); err != nil {
		t.Fatal(err)
	}

	if err := bound.VerifyFor(pub, mine, false); err != nil {
		t.Fatalf("bound, own deployment: %v", err)
	}
	if err := bound.VerifyFor(pub, mine, true); err != nil {
		t.Fatalf("bound, own deployment, legacy allowed: %v", err)
	}
	if err := bound.VerifyFor(pub, other, true); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("bound, other deployment: %v, want ErrDeploymentMismatch", err)
	}
	if err := bound.VerifyFor(pub, DeploymentID{}, true); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("bound, verifier unbound: %v, want ErrDeploymentMismatch", err)
	}
	if err := bound.Verify(pub); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("legacy Verify on a bound ticket: %v, want ErrDeploymentMismatch", err)
	}
	if err := legacy.VerifyFor(pub, mine, true); err != nil {
		t.Fatalf("legacy, allowed: %v", err)
	}
	if err := legacy.VerifyFor(pub, mine, false); !errors.Is(err, ErrLegacySignature) {
		t.Fatalf("legacy, not allowed: %v, want ErrLegacySignature", err)
	}

	// Relabelling a signed ticket to another deployment, or stripping its
	// deployment, breaks the signature rather than passing the label check.
	relabelled := *bound
	relabelled.Deployment = other
	if err := relabelled.VerifyFor(pub, other, false); err == nil {
		t.Fatal("relabelled ticket verified")
	}
	stripped := *bound
	stripped.Deployment = DeploymentID{}
	if err := stripped.VerifyFor(pub, mine, true); err == nil {
		t.Fatal("stripped ticket verified as legacy")
	}
}

func TestReceipt_VerifyFor(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	mine := mustAlgorandID(t, 1, 100)
	other := mustAlgorandID(t, 1, 101)

	bound := sampleReceipt()
	bound.Deployment = mine
	if err := bound.Sign(context.Background(), signer, addr); err != nil {
		t.Fatal(err)
	}
	v2 := sampleReceipt().CanonicalBytes()
	var want []byte
	want = append(want, "zs-receipt-v3\x00"...)
	want = append(want, mine[:]...)
	want = append(want, v2[len("zs-receipt-v2\x00"):]...)
	if !bytes.Equal(bound.CanonicalBytes(), want) {
		t.Fatal("receipt v3 layout is not tag ‖ deployment ‖ v2 body")
	}

	if err := bound.VerifyFor(pub, mine, false); err != nil {
		t.Fatalf("bound, own deployment: %v", err)
	}
	if err := bound.VerifyFor(pub, other, true); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("bound, other deployment: %v", err)
	}
	stripped := *bound
	stripped.Deployment = DeploymentID{}
	if err := stripped.VerifyFor(pub, mine, true); err == nil {
		t.Fatal("stripped receipt verified as legacy")
	}

	legacy := sampleReceipt()
	if err := legacy.Sign(context.Background(), signer, addr); err != nil {
		t.Fatal(err)
	}
	if err := legacy.VerifyFor(pub, mine, false); !errors.Is(err, ErrLegacySignature) {
		t.Fatalf("legacy, not allowed: %v", err)
	}
	if err := legacy.VerifyFor(pub, mine, true); err != nil {
		t.Fatalf("legacy, allowed: %v", err)
	}
}

func TestReserve_VerifyFor(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	mine := mustAlgorandID(t, 1, 100)
	other := mustAlgorandID(t, 2, 100)
	issuedAt := time.Unix(1_700_000_000, 0)
	now := issuedAt.Add(5 * time.Second)

	newReq := func(d DeploymentID) *ReserveRequest {
		r := &ReserveRequest{
			Model:          "m",
			InputCount:     1,
			ProxyRecipient: fixedAgeRecipient,
			PayerIssuedAt:  issuedAt.Unix(),
			Deployment:     d,
		}
		if err := r.Sign(context.Background(), signer, addr, 42, 7); err != nil {
			t.Fatal(err)
		}
		return r
	}

	bound := newReq(mine)
	unbound := &ReserveRequest{Model: "m", InputCount: 1, ProxyRecipient: fixedAgeRecipient, PayerAddr: addr, PayerIssuedAt: issuedAt.Unix()}
	var want []byte
	want = append(want, "zs-reserve-v2\x00"...)
	want = append(want, mine[:]...)
	want = append(want, unbound.CanonicalBytes(42, 7)[len("zs-reserve-v1\x00"):]...)
	if !bytes.Equal(bound.CanonicalBytes(42, 7), want) {
		t.Fatal("reserve v2 layout is not tag ‖ deployment ‖ v1 body")
	}

	if err := bound.VerifyFor(pub, 42, 7, now, DefaultReserveSkew, mine, false); err != nil {
		t.Fatalf("bound, own deployment: %v", err)
	}
	if err := bound.VerifyFor(pub, 42, 7, now, DefaultReserveSkew, other, true); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("bound, other deployment: %v", err)
	}
	// The deployment check runs before the window, so a mismatched payer with
	// a stale signature still learns it is on the wrong network.
	if err := bound.VerifyFor(pub, 42, 7, now.Add(time.Hour), DefaultReserveSkew, other, true); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("bound, other deployment, expired: %v", err)
	}
	if err := bound.Verify(pub, 42, 7, now, DefaultReserveSkew); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("legacy Verify on a bound reserve: %v", err)
	}

	legacy := newReq(DeploymentID{})
	if err := legacy.VerifyFor(pub, 42, 7, now, DefaultReserveSkew, mine, true); err != nil {
		t.Fatalf("legacy, allowed: %v", err)
	}
	if err := legacy.VerifyFor(pub, 42, 7, now, DefaultReserveSkew, mine, false); !errors.Is(err, ErrLegacySignature) {
		t.Fatalf("legacy, not allowed: %v", err)
	}
}

func TestEphemeral_DualSignature(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	mine := mustAlgorandID(t, 1, 100)
	other := mustAlgorandID(t, 2, 100)
	now := time.Unix(1_700_000_000-60, 0)

	a := sampleAdvertisement()
	a.Deployment = mine
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	if a.Sig == "" || a.SigV2 == "" || a.Sig == a.SigV2 {
		t.Fatalf("bound advertisement needs two distinct signatures, got %q / %q", a.Sig, a.SigV2)
	}
	// A payer that predates the binding still verifies the legacy signature.
	if err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err != nil {
		t.Fatalf("legacy verify of a dual-signed advertisement: %v", err)
	}
	if err := a.VerifyFor(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew, mine, false); err != nil {
		t.Fatalf("bound verify: %v", err)
	}
	if err := a.VerifyFor(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew, other, true); !errors.Is(err, ErrDeploymentMismatch) {
		t.Fatalf("other deployment: %v", err)
	}

	// A bound advertisement is judged by SigV2: a valid Sig cannot carry a
	// forged SigV2.
	forged := *a
	forged.SigV2 = a.Sig
	if err := forged.VerifyFor(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew, mine, true); err == nil {
		t.Fatal("bound advertisement verified on the legacy signature")
	}
	// SigV2 covers the target binding too.
	if err := a.VerifyFor(pub, now, advOperatorID, advNodeID+1, DefaultEphemeralSkew, mine, false); err == nil {
		t.Fatal("bound advertisement verified for a sibling node")
	}

	// Stripping the v2 fields leaves a legacy advertisement, which passes only
	// while legacy is allowed.
	stripped := *a
	stripped.Deployment, stripped.SigV2 = DeploymentID{}, ""
	if err := stripped.VerifyFor(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew, mine, false); !errors.Is(err, ErrLegacySignature) {
		t.Fatalf("stripped, legacy refused: %v", err)
	}
	if err := stripped.VerifyFor(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew, mine, true); err != nil {
		t.Fatalf("stripped, legacy allowed: %v", err)
	}

	// The policy checks still run on the bound path.
	if err := a.VerifyFor(pub, time.Unix(a.Expiry, 0).Add(2*DefaultEphemeralSkew), advOperatorID, advNodeID, DefaultEphemeralSkew, mine, false); !errors.Is(err, ErrEphemeralExpired) {
		t.Fatalf("expired bound advertisement: %v", err)
	}
}

func TestEphemeral_UnboundSignsOnlyLegacy(t *testing.T) {
	signer, addr, _ := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	if a.SigV2 != "" {
		t.Fatal("unbound advertisement carries a v2 signature")
	}
	raw, _ := json.Marshal(a)
	if bytes.Contains(raw, []byte("ephemeral_deployment")) || bytes.Contains(raw, []byte("ephemeral_sig_v2")) {
		t.Fatalf("unbound advertisement JSON carries v2 keys: %s", raw)
	}
	// Re-signing after unbinding clears a stale SigV2.
	a.Deployment = mustAlgorandID(t, 1, 100)
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	a.Deployment = DeploymentID{}
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	if a.SigV2 != "" {
		t.Fatal("re-signing unbound kept the old v2 signature")
	}
}
