/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// 24-word BIP-39 / ARC-52 xHD golden vectors. The addresses were produced by
// the client's own derivation stack — @scure/bip39 (entropyToMnemonic →
// mnemonicToSeedSync) → @algorandfoundation/xhd-wallet-api (fromSeed →
// keyGen(KeyContext.Address, 0, 0)) — in client/src/auth/crypto.ts. The
// keystore must derive the identical address from the same phrase, otherwise
// a phrase a user exported from the client would load a different account
// here. This is the cross-impl regression catch.
const (
	hdPhraseZero = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	hdAddrZero   = "IYRGHE7NYTZRYPGFFNVPH7TVCZVQLQFK2IJ57W5JONTHT4BZEYHXL3MY3E"

	hdPhraseSeq = "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware"
	hdAddrSeq   = "4BNOVXVHYUK3MV6BLZ43QSXDQANK2QUIEN6M52TZVRLYOQ7KULSA7WSF2A"
)

func TestKeyStore_HD_MatchesClientVectors(t *testing.T) {
	cases := []struct{ phrase, addr string }{
		{hdPhraseZero, hdAddrZero},
		{hdPhraseSeq, hdAddrSeq},
	}
	for _, c := range cases {
		ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "HD", Mnemonic: c.phrase}}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if !ks.HasAccount(c.addr) {
			t.Fatalf("phrase did not derive expected client address %s; loaded=%v", c.addr, ks.Addresses())
		}
	}
}

func TestKeyStore_HD_SignBytes_VerifiesVerbatim(t *testing.T) {
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "HD", Mnemonic: hdPhraseZero}}})
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello hayai from an xHD key")
	sig, err := ks.SignBytes(context.Background(), hdAddrZero, msg)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	pub, err := ticket.DecodeAlgorandAddress(hdAddrZero)
	if err != nil {
		t.Fatal(err)
	}
	// Verbatim: the extended-key signature must verify under standard
	// ed25519 against the derived address with no domain framing.
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("verbatim signature did not verify under the address pubkey")
	}
}

func TestKeyStore_HD_SignWithAccount_ProducesValidSignedTxn(t *testing.T) {
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "HD", Mnemonic: hdPhraseZero}}})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := types.DecodeAddress(hdAddrZero)
	if err != nil {
		t.Fatal(err)
	}
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:     sender,
			Fee:        1000,
			FirstValid: 1,
			LastValid:  1001,
		},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, Amount: 0},
	}

	_, stxBytes, err := ks.SignWithAccount(context.Background(), txn, hdAddrZero)
	if err != nil {
		t.Fatalf("SignWithAccount: %v", err)
	}
	var stx types.SignedTxn
	if err := msgpack.Decode(stxBytes, &stx); err != nil {
		t.Fatalf("decode SignedTxn: %v", err)
	}
	// Sender == derived address, so no rekey: AuthAddr must stay zero.
	if stx.AuthAddr != (types.Address{}) {
		t.Errorf("unexpected AuthAddr %s (sender is the derived address)", stx.AuthAddr)
	}
	pub, err := ticket.DecodeAlgorandAddress(hdAddrZero)
	if err != nil {
		t.Fatal(err)
	}
	// The signed bytes are "TX" || msgpack(txn) (rawTransactionBytesToSign).
	toSign := append([]byte("TX"), msgpack.Encode(txn)...)
	if !ed25519.Verify(pub, toSign, stx.Sig[:]) {
		t.Fatal("transaction signature did not verify under the address pubkey")
	}
}

func TestKeyStore_HD_DrivesTicketSignVerify(t *testing.T) {
	// Same end-to-end path the node uses (keystore → Ticket.Sign(BytesSigner)
	// → Verify), but backed by an xHD key.
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "HD", Mnemonic: hdPhraseSeq}}})
	if err != nil {
		t.Fatal(err)
	}
	tk := &ticket.Ticket{
		TicketID:       "AAAAAAAAAAAAAAAAAAAAAA==",
		OperatorID:     1,
		InputCount:     1,
		MaxOutputCount: 1,
		InputRate:      1,
		OutputRate:     1,
		MaxPrice:       2,
		ExpiresAt:      1_700_000_000,
		Model:          "m",
		Stream:         false,
		CommitK:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	if err := tk.Sign(context.Background(), ks, hdAddrSeq); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, err := ticket.DecodeAlgorandAddress(hdAddrSeq)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestKeyStore_HD_RejectsBadChecksum(t *testing.T) {
	// Valid words, wrong BIP-39 checksum (24×"abandon" — the zero-entropy
	// phrase ends in "art", not "abandon").
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	_, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "BADSUM", Mnemonic: bad}}})
	if err == nil {
		t.Fatal("want error for 24-word phrase with bad checksum")
	}
}

func TestKeyStore_HD_ConcurrentSign_Race(t *testing.T) {
	// The proxy signs escrow groups per-request, so the same payer hdKey is
	// signed with concurrently. The keystore promises no hot-path locking;
	// run under -race to lock in that the xHD signer (which re-derives the
	// leaf from the shared root each call) never mutates shared state.
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "HD", Mnemonic: hdPhraseZero}}})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ticket.DecodeAlgorandAddress(hdAddrZero)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("concurrent")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := ks.SignBytes(context.Background(), hdAddrZero, msg)
			if err != nil {
				t.Errorf("SignBytes: %v", err)
				return
			}
			if !ed25519.Verify(pub, msg, sig) {
				t.Error("concurrent signature did not verify")
			}
		}()
	}
	wg.Wait()
}

func TestKeyStore_MixesStdAndHDKeys(t *testing.T) {
	// A keystore loading both a 25-word Algorand key and a 24-word xHD key
	// is the realistic deployment shape — dispatch is per-entry.
	mn25, addr25 := freshMnemonic(t)
	ks, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{
		{Name: "STD", Mnemonic: mn25},
		{Name: "HD", Mnemonic: hdPhraseZero},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(ks.Addresses()); got != 2 {
		t.Fatalf("Addresses count = %d, want 2", got)
	}
	for _, addr := range []string{addr25, hdAddrZero} {
		if !ks.HasAccount(addr) {
			t.Errorf("missing address %s", addr)
		}
		sig, err := ks.SignBytes(context.Background(), addr, []byte("m"))
		if err != nil {
			t.Errorf("SignBytes(%s): %v", addr, err)
			continue
		}
		pub, err := ticket.DecodeAlgorandAddress(addr)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(pub, []byte("m"), sig) {
			t.Errorf("signature for %s did not verify", addr)
		}
	}
}

func TestKeyStore_RejectsUnsupportedWordCount(t *testing.T) {
	for _, n := range []int{23, 26} {
		words := make([]string, n)
		for i := range words {
			words[i] = "abandon"
		}
		phrase := ""
		for i, w := range words {
			if i > 0 {
				phrase += " "
			}
			phrase += w
		}
		_, err := New(context.Background(), staticProvider{entries: []MnemonicEntry{{Name: "WC", Mnemonic: phrase}}})
		if err == nil {
			t.Fatalf("want error for unsupported word count %d", n)
		}
	}
}
