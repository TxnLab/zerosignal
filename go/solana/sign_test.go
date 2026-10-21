/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"slices"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"github.com/TxnLab/zerosignal/go/solana"
)

// seededSigner holds the fixtures' keys, each the 32 bytes of its seed, and
// counts what it is asked to sign.
type seededSigner struct {
	keys  map[string]ed25519.PrivateKey
	asked []string
}

func newSeededSigner(t *testing.T) *seededSigner {
	var f struct {
		Context fixtureContext `json:"context"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	s := &seededSigner{keys: map[string]ed25519.PrivateKey{}}
	for _, k := range f.Context.Keys {
		s.keys[k.Pubkey.String()] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{k.Seed}, 32))
	}
	return s
}

func (s *seededSigner) SignTransactionMessage(_ context.Context, address string, message []byte) ([]byte, error) {
	s.asked = append(s.asked, address)
	priv, ok := s.keys[address]
	if !ok {
		return nil, errors.New("no key for " + address)
	}
	return ed25519.Sign(priv, message), nil
}

// Every transaction the program's tests signed, signed again through the
// port from empty slots, last signer first, is the wire Rust wrote: each
// signature lands in its signer's slot whatever the order.
func TestSignWithFixtures(t *testing.T) {
	var f struct {
		Transactions []txFixture `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	s := newSeededSigner(t)
	ctx := context.Background()
	for _, c := range f.Transactions {
		tx, err := solana.ParseTransaction(b64(t, c.Wire))
		if err != nil {
			t.Fatal(err)
		}
		resigned := solana.NewTransaction(&tx.Message)
		signers := slices.Clone(tx.Message.AccountKeys[:tx.Message.Header.NumRequiredSignatures])
		slices.Reverse(signers)
		for _, k := range signers {
			if err := resigned.SignWith(ctx, k, s); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
		}
		if got, err := resigned.MarshalBinary(); err != nil || !bytes.Equal(got, b64(t, c.Wire)) {
			t.Errorf("%s: re-signed through the port, %v", c.Name, err)
		}
	}
}

// identityRSignature is a signature by priv over msg whose R is the identity
// point, S = k·a: the cofactorless equation holds, so crypto/ed25519 and a
// cofactored check accept it, but R is of small order, which the runtime
// refuses.
func identityRSignature(t *testing.T, priv ed25519.PrivateKey, msg []byte) []byte {
	h := sha512.Sum512(priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		t.Fatal(err)
	}
	r := edwards25519.NewIdentityPoint().Bytes()
	kh := sha512.New()
	kh.Write(r)
	kh.Write(priv.Public().(ed25519.PublicKey))
	kh.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(kh.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return append(r, edwards25519.NewScalar().Multiply(k, a).Bytes()...)
}

type fixedSigner struct {
	sig []byte
	err error
}

func (f fixedSigner) SignTransactionMessage(context.Context, string, []byte) ([]byte, error) {
	return f.sig, f.err
}

func TestSignWithRefuses(t *testing.T) {
	var f struct {
		Transactions []txFixture `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	var open txFixture
	for _, c := range f.Transactions {
		if c.Name == "open" {
			open = c
		}
	}
	tx, err := solana.ParseTransaction(b64(t, open.Wire))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, payer := tx.Message.AccountKeys[0], tx.Message.AccountKeys[1]
	given := slices.Clone(tx.Signatures)
	fresh := func() *solana.Transaction {
		c := *tx
		c.Signatures = slices.Clone(given)
		return &c
	}
	s := newSeededSigner(t)

	// A key that is in the message but signs nothing is not asked.
	nonSigner := tx.Message.AccountKeys[tx.Message.Header.NumRequiredSignatures]
	if err := fresh().SignWith(ctx, nonSigner, s); err == nil || len(s.asked) != 0 {
		t.Fatalf("signed as a non-signer: %v, asked %v", err, s.asked)
	}

	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	nodeSig := ed25519.Sign(s.keys[node.String()], msg)
	lenient := identityRSignature(t, s.keys[payer.String()], msg)
	if !ed25519.Verify(s.keys[payer.String()].Public().(ed25519.PublicKey), msg, lenient) {
		t.Fatal("crypto/ed25519 refuses the small-order-R signature, so the case below can't tell its check from the runtime's")
	}
	boom := errors.New("custody refused")
	for name, c := range map[string]struct {
		signer solana.TransactionSigner
		want   string
	}{
		"small-order R":           {fixedSigner{sig: lenient}, "does not verify"},
		"short signature":         {fixedSigner{sig: nodeSig[:63]}, "63 bytes"},
		"long signature":          {fixedSigner{sig: append(slices.Clone(nodeSig), 0)}, "65 bytes"},
		"another key's signature": {fixedSigner{sig: nodeSig}, "does not verify"},
		"no signature":            {fixedSigner{}, "0 bytes"},
		"signer error":            {fixedSigner{err: boom}, "custody refused"},
	} {
		got := fresh()
		err := got.SignWith(ctx, payer, c.signer)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if name == "signer error" && !errors.Is(err, boom) {
			t.Errorf("%s: the signer's error is not wrapped: %v", name, err)
		}
		if !slices.Equal(got.Signatures, given) {
			t.Errorf("%s: a refused signature changed the slots", name)
		}
	}

	short := fresh()
	short.Signatures = short.Signatures[:1]
	if err := short.SignWith(ctx, payer, s); !errors.Is(err, solana.ErrMessage) {
		t.Errorf("one slot for two signers: %v", err)
	}
	// A slot past the signer count would go out with whatever it holds.
	long := fresh()
	long.Signatures = append(long.Signatures, solana.Signature{})
	padded := slices.Clone(long.Signatures)
	if err := long.SignWith(ctx, payer, s); !errors.Is(err, solana.ErrMessage) || len(s.asked) != 0 {
		t.Errorf("three slots for two signers: %v, asked %v", err, s.asked)
	}
	if !slices.Equal(long.Signatures, padded) {
		t.Error("three slots for two signers: a refused transaction changed the slots")
	}

	// The node's slot is left as given while the payer's is replaced.
	got := fresh()
	got.Signatures[1] = solana.Signature{}
	if err := got.SignWith(ctx, payer, s); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Signatures, given) {
		t.Error("the payer's signature is not the one the program's test made, or the node's slot moved")
	}
}
