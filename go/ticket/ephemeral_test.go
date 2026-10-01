/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// fixedAgeRecipient is a well-formed age1… recipient baked as a constant
// test vector. The ephemeral primitive treats the recipient as opaque
// length-prefixed bytes (it never parses it), so any valid age1 string
// works; this one is fixed so canonical-bytes expectations are stable.
const fixedAgeRecipient = "age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s"

// advOperatorID / advNodeID are the target binding every test in this file
// signs sampleAdvertisement for. They are not struct fields — the pair is
// passed to CanonicalBytes / Sign / Verify — so the mismatch tests below vary
// the argument, not the object.
const (
	advOperatorID uint64 = 42
	advNodeID     uint64 = 7
)

// sampleAdvertisement returns an EphemeralAdvertisement with deterministic
// fields suitable for signing / verification tests. The target binding is
// supplied separately, as (advOperatorID, advNodeID).
func sampleAdvertisement() *EphemeralAdvertisement {
	return &EphemeralAdvertisement{
		AgePubkey: fixedAgeRecipient,
		Expiry:    1_700_000_000,
		// IssuedAt 1500s (25m) before Expiry so the signed window is a valid
		// honest lifetime (≤ MaxEphemeralLifetime) — the verify roundtrip tests
		// would otherwise trip the new lifetime cap.
		IssuedAt: 1_700_000_000 - 1500,
	}
}

func TestEphemeral_CanonicalBytes_ByteExact(t *testing.T) {
	a := sampleAdvertisement()

	// Hand-build the expected layout:
	//   tag ‖ u64(operatorID) ‖ u64(nodeID) ‖ u32(len(AgePubkey)) ‖ AgePubkey ‖ i64(Expiry) ‖ i64(IssuedAt)
	var want []byte
	want = append(want, []byte(ephemeralSigningTag)...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], advOperatorID)
	want = append(want, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], advNodeID)
	want = append(want, u64[:]...)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(a.AgePubkey)))
	want = append(want, u32[:]...)
	want = append(want, []byte(a.AgePubkey)...)
	binary.BigEndian.PutUint64(u64[:], uint64(a.Expiry))
	want = append(want, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(a.IssuedAt))
	want = append(want, u64[:]...)

	if got := a.CanonicalBytes(advOperatorID, advNodeID); !bytes.Equal(got, want) {
		t.Fatalf("CanonicalBytes mismatch\n got=%x\nwant=%x", got, want)
	}
}

func TestEphemeral_CanonicalBytes_IsDeterministic(t *testing.T) {
	if !bytes.Equal(sampleAdvertisement().CanonicalBytes(advOperatorID, advNodeID), sampleAdvertisement().CanonicalBytes(advOperatorID, advNodeID)) {
		t.Fatal("CanonicalBytes not deterministic for identical structs")
	}
}

func TestEphemeral_CanonicalBytes_ExcludesSig(t *testing.T) {
	a := sampleAdvertisement()
	before := append([]byte(nil), a.CanonicalBytes(advOperatorID, advNodeID)...)
	a.Sig = "anything"
	if !bytes.Equal(before, a.CanonicalBytes(advOperatorID, advNodeID)) {
		t.Fatal("CanonicalBytes depends on Sig; must not")
	}
}

// TestEphemeral_Sign_UsesCanonicalArgumentOrder pins that Sign feeds the target
// binding to the digest in the CANONICAL order — operator id first, then node
// id — by checking a real signature against a layout this test builds itself.
//
// Nothing else can catch a transposition. Sign and Verify agree with each other
// however their arguments are ordered, so every round-trip test passes; the
// mismatch tests still go red on a varied id, because varying either argument
// changes the digest either way; and TestVectors pins CanonicalBytes /
// EphemeralSigDigest in isolation, never the order their CALLERS pass. The
// layout is locked (SPEC § 3c) and the failure is entirely cross-language: a
// transposed Go node would sign advertisements no TS client accepts, and vice
// versa, with every Go suite and both golden-vector sets green.
//
// ed25519.Verify against EphemeralSigDigest would be circular — it would call
// the very function whose argument order is in question — so the preimage is
// assembled here from the spec layout, exactly as
// TestEphemeral_CanonicalBytes_ByteExact assembles its expectation.
func TestEphemeral_Sign_UsesCanonicalArgumentOrder(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}

	// tag ‖ u64(operatorID) ‖ u64(nodeID) ‖ u32(len) ‖ AgePubkey ‖ i64(Expiry) ‖ i64(IssuedAt)
	var preimage []byte
	preimage = append(preimage, []byte(ephemeralSigningTag)...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], advOperatorID)
	preimage = append(preimage, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], advNodeID)
	preimage = append(preimage, u64[:]...)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(a.AgePubkey)))
	preimage = append(preimage, u32[:]...)
	preimage = append(preimage, []byte(a.AgePubkey)...)
	binary.BigEndian.PutUint64(u64[:], uint64(a.Expiry))
	preimage = append(preimage, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(a.IssuedAt))
	preimage = append(preimage, u64[:]...)

	digest := sha256.Sum256(preimage)
	if !ed25519.Verify(pub, digest[:], sig) {
		t.Fatal("Sign produced a signature over a different preimage than the locked layout " +
			"— the (operatorID, nodeID) pair reached the digest in the wrong order")
	}
}

func TestEphemeral_SignVerify_RoundTrip(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	now := time.Unix(a.Expiry-1, 0) // well before expiry
	if err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestEphemeral_Sign_NilSigner(t *testing.T) {
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), nil, "anything", advOperatorID, advNodeID); err == nil {
		t.Fatal("want error on nil signer")
	}
}

func TestEphemeral_Sign_UnknownAddress(t *testing.T) {
	signer, _, _ := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, "OTHER_ADDR_NOT_IN_KEYSTORE_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", advOperatorID, advNodeID); err == nil {
		t.Fatal("want error when signing with an unknown address")
	}
}

func TestEphemeral_Verify_WrongKey(t *testing.T) {
	signer, addr, _ := newFakeSigner(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(a.Expiry-1, 0)
	if err := a.Verify(otherPub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err == nil {
		t.Fatal("want verify error with wrong pubkey")
	}
}

func TestEphemeral_Verify_WrongPubKeyLength(t *testing.T) {
	signer, addr, _ := newFakeSigner(t)
	a := sampleAdvertisement()
	_ = a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID)
	now := time.Unix(a.Expiry-1, 0)
	if err := a.Verify(ed25519.PublicKey([]byte{1, 2, 3}), now, advOperatorID, advNodeID, DefaultEphemeralSkew); err == nil {
		t.Fatal("want error on short pubkey")
	}
}

func TestEphemeral_Verify_TamperedField(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*EphemeralAdvertisement)
	}{
		{"age_pubkey", func(a *EphemeralAdvertisement) {
			a.AgePubkey = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsuwzd4"
		}},
		{"expiry", func(a *EphemeralAdvertisement) { a.Expiry++ }},
		{"sig", func(a *EphemeralAdvertisement) {
			raw, _ := base64.StdEncoding.DecodeString(a.Sig)
			raw[0] ^= 0xFF
			a.Sig = base64.StdEncoding.EncodeToString(raw)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signer, addr, pub := newFakeSigner(t)
			a := sampleAdvertisement()
			if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
				t.Fatal(err)
			}
			c.mutate(a)
			now := time.Unix(a.Expiry-1, 0)
			if err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err == nil {
				t.Fatalf("tampered %s: verify passed", c.name)
			}
		})
	}
}

func TestEphemeral_Verify_OperatorIDMismatch(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(a.Expiry-1, 0)
	// The signer signed for operator 42; verifying under a different
	// chain-resolved id must fail, because the id Verify is given is the one
	// that enters the recomputed digest.
	err := a.Verify(pub, now, advOperatorID+1, advNodeID, DefaultEphemeralSkew)
	if err == nil {
		t.Fatal("want verify error on operator_id mismatch")
	}
	if errors.Is(err, ErrEphemeralExpired) {
		t.Fatal("operator_id mismatch should be a signature failure, not ErrEphemeralExpired")
	}
}

// TestEphemeral_Verify_NodeIDMismatch is the sibling-node substitution case
// the node_id binding exists for: a block signed for (op, node 7) must not validate as
// (op, node 8) — even under the SAME signing key, which is exactly the
// scenario when an operator reuses one key across its nodes.
func TestEphemeral_Verify_NodeIDMismatch(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	now := time.Unix(a.Expiry-1, 0)
	err := a.Verify(pub, now, advOperatorID, advNodeID+1, DefaultEphemeralSkew)
	if err == nil {
		t.Fatal("want verify error on node_id mismatch")
	}
	if errors.Is(err, ErrEphemeralExpired) {
		t.Fatal("node_id mismatch should be a signature failure, not ErrEphemeralExpired")
	}
}

func TestEphemeral_Verify_BadSigEncoding(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	_ = a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID)
	now := time.Unix(a.Expiry-1, 0)

	a.Sig = "!!!not-base64!!!"
	if err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err == nil {
		t.Fatal("want error on non-base64 sig")
	}
	a.Sig = base64.StdEncoding.EncodeToString([]byte("too-short"))
	if err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err == nil {
		t.Fatal("want error on wrong-length sig")
	}
}

func TestEphemeral_Verify_ExpiryBoundary(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}

	expiry := time.Unix(a.Expiry, 0)
	skew := DefaultEphemeralSkew

	// Just inside the window: now == expiry+skew is still valid (Verify uses
	// strict After).
	atEdge := expiry.Add(skew)
	if err := a.Verify(pub, atEdge, advOperatorID, advNodeID, skew); err != nil {
		t.Fatalf("at expiry+skew should be valid, got %v", err)
	}

	// Just after the window: ErrEphemeralExpired sentinel.
	pastEdge := expiry.Add(skew).Add(time.Nanosecond)
	err := a.Verify(pub, pastEdge, advOperatorID, advNodeID, skew)
	if !errors.Is(err, ErrEphemeralExpired) {
		t.Fatalf("just past expiry+skew want ErrEphemeralExpired, got %v", err)
	}
}

func TestEphemeral_Verify_ForgedButUnexpired_FailsOnSignature(t *testing.T) {
	// A forged-but-unexpired block must fail on the signature (generic
	// error), never the expiry sentinel — signature is checked first.
	signer, addr, _ := newFakeSigner(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(a.Expiry-1, 0) // unexpired
	err := a.Verify(otherPub, now, advOperatorID, advNodeID, DefaultEphemeralSkew)
	if err == nil {
		t.Fatal("forged block verified")
	}
	if errors.Is(err, ErrEphemeralExpired) {
		t.Fatal("forged-but-unexpired block should fail on signature, not expiry")
	}
}

// TestEphemeral_SignVerify_WithGeneratedKeypair exercises the
// GenerateAlgorandKeypair path end to end: sign through the fake signer keyed
// by the generated address, verify under the generated pubkey.
func TestEphemeral_SignVerify_WithGeneratedKeypair(t *testing.T) {
	addr, pub, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signer := &fakeBytesSigner{keys: map[string]ed25519.PrivateKey{addr: priv}}
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	now := time.Unix(a.Expiry-1, 0)
	if err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestEphemeral_Verify_LifetimeTooLong: an authentically-signed block whose
// window Expiry-IssuedAt exceeds MaxEphemeralLifetime is rejected with the
// ErrEphemeralLifetimeTooLong sentinel — not the expiry sentinel — even though
// it is unexpired and validly signed. This is the key-retention guard.
func TestEphemeral_Verify_LifetimeTooLong(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	// Push IssuedAt far enough back that the window blows the cap, then sign so
	// the (over-long) window is authentic.
	a.IssuedAt = a.Expiry - int64((MaxEphemeralLifetime + time.Minute).Seconds())
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(a.Expiry-1, 0) // unexpired
	err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew)
	if !errors.Is(err, ErrEphemeralLifetimeTooLong) {
		t.Fatalf("want ErrEphemeralLifetimeTooLong, got %v", err)
	}
	if errors.Is(err, ErrEphemeralExpired) {
		t.Fatal("over-long lifetime must not surface as ErrEphemeralExpired")
	}
}

// TestEphemeral_Verify_AcceptsHonestLifetime: a window exactly at the cap is
// accepted (boundary is inclusive); one second over is rejected.
func TestEphemeral_Verify_LifetimeBoundary(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	maxSec := int64(MaxEphemeralLifetime.Seconds())

	atCap := sampleAdvertisement()
	atCap.IssuedAt = atCap.Expiry - maxSec
	if err := atCap.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(atCap.Expiry-1, 0)
	if err := atCap.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); err != nil {
		t.Fatalf("window exactly at MaxEphemeralLifetime should pass, got %v", err)
	}

	overCap := sampleAdvertisement()
	overCap.IssuedAt = overCap.Expiry - maxSec - 1
	if err := overCap.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	if err := overCap.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew); !errors.Is(err, ErrEphemeralLifetimeTooLong) {
		t.Fatalf("window one second over the cap want ErrEphemeralLifetimeTooLong, got %v", err)
	}
}

// TestEphemeral_Verify_FutureIssuedAt: a block whose IssuedAt is beyond now+skew
// is rejected (a node cannot advertise a key it has not minted yet).
func TestEphemeral_Verify_FutureIssuedAt(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	a := sampleAdvertisement()
	if err := a.Sign(context.Background(), signer, addr, advOperatorID, advNodeID); err != nil {
		t.Fatal(err)
	}
	// now sits well before IssuedAt (more than skew earlier).
	now := time.Unix(a.IssuedAt, 0).Add(-2 * DefaultEphemeralSkew)
	err := a.Verify(pub, now, advOperatorID, advNodeID, DefaultEphemeralSkew)
	if err == nil {
		t.Fatal("future-dated issued_at must fail verify")
	}
	if errors.Is(err, ErrEphemeralExpired) || errors.Is(err, ErrEphemeralLifetimeTooLong) {
		t.Fatalf("future issued_at should be a not-yet-valid error, got %v", err)
	}
}

// TestEphemeral_Stale exercises the SOFT relay-attribution helper independent
// of Verify: fresh inside FreshnessTarget, stale once age exceeds it.
func TestEphemeral_Stale(t *testing.T) {
	a := sampleAdvertisement()
	issued := time.Unix(a.IssuedAt, 0)

	fresh := issued.Add(FreshnessTarget - time.Second)
	if a.Stale(fresh) {
		t.Fatal("block within FreshnessTarget must not be Stale")
	}
	stale := issued.Add(FreshnessTarget + time.Second)
	if !a.Stale(stale) {
		t.Fatal("block past FreshnessTarget must be Stale")
	}
}
