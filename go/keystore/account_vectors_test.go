/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

// Generates / verifies proto/testdata/account_vectors.json: what address a
// recovery phrase loads as, or that it is refused, and what its key signs. The
// TS SDK's account subpaths (sdk/src/accounts) replay it, so a phrase a user
// moves between the proxy and a TS host loads the same account and signs
// byte-identically.
//
//	cd proto/go && go test ./keystore -run TestAccountVectors -update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/types"
	bip39 "github.com/tyler-smith/go-bip39"
)

var updateAccountVectors = flag.Bool("update", false, "regenerate testdata/account_vectors.json")

const accountVectorsPath = "../../testdata/account_vectors.json"

type accountSignature struct {
	Msg string `json:"msg"` // hex
	Sig string `json:"sig"` // hex
}

type accountTxn struct {
	Txn    string `json:"txn"`    // unsigned transaction, msgpack, base64
	Signed string `json:"signed"` // signed transaction, msgpack, base64
	TxID   string `json:"txid"`
}

type accountCase struct {
	Name    string `json:"name"`
	Phrase  string `json:"phrase"`
	Entropy string `json:"entropy,omitempty"` // hex, for a 24-word phrase built from it
	// Refused is true when the phrase loads as nothing; Address and Kind are
	// then empty.
	Refused bool   `json:"refused"`
	Address string `json:"address,omitempty"`
	Kind    string `json:"kind,omitempty"`

	Signatures []accountSignature `json:"signatures,omitempty"`
	Txn        *accountTxn        `json:"txn,omitempty"`
}

func TestAccountVectors(t *testing.T) {
	seq := func(start byte) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = start + byte(i)
		}
		return b
	}
	algo25 := func(seed []byte) string {
		m, err := mnemonic.FromPrivateKey(ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	bip24 := func(entropy []byte) string {
		m, err := bip39.NewMnemonic(entropy)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	// swapLast replaces the final word with another from the list, which
	// breaks the checksum of either form.
	swapLast := func(m, w string) string {
		f := strings.Fields(m)
		f[len(f)-1] = w
		return strings.Join(f, " ")
	}
	spaced := func(m, sep string) string { return strings.Join(strings.Fields(m), sep) }
	r := func(c rune) string { return string(c) }
	fullWidth := func(m string) string {
		return strings.Map(func(c rune) rune {
			if c >= 'a' && c <= 'z' {
				return c - 'a' + 0xff41
			}
			return c
		}, m)
	}

	a1, a2 := algo25(seq(0)), algo25(bytes.Repeat([]byte{0xff}, 32))
	x1, x2 := bip24(seq(1)), bip24(bytes.Repeat([]byte{0xa5}, 32))

	in := []accountCase{
		{Name: "algorand-25 sequential seed", Phrase: a1},
		{Name: "algorand-25 all-ones seed", Phrase: a2},
		{Name: "xhd-24 all-zero entropy", Phrase: hdPhraseZero},
		{Name: "xhd-24 client vector", Phrase: hdPhraseSeq},
		{Name: "xhd-24 sequential entropy", Phrase: x1, Entropy: hex.EncodeToString(seq(1))},
		{Name: "xhd-24 0xa5 entropy", Phrase: x2, Entropy: hex.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))},

		{Name: "algorand-25 bad checksum", Phrase: swapLast(a1, "zoo")},
		{Name: "xhd-24 bad checksum", Phrase: swapLast(hdPhraseZero, "zoo")},
		{Name: "algorand-25 unknown word", Phrase: swapLast(a1, "zzzz")},
		{Name: "23 words", Phrase: strings.Join(strings.Fields(hdPhraseZero)[:23], " ")},
		{Name: "26 words", Phrase: a1 + " abandon"},
		// A valid BIP-39 phrase of another length: its checksum passes, so
		// only the word count refuses it.
		{Name: "bip39-12 valid phrase", Phrase: strings.Repeat("abandon ", 11) + "about"},
		{Name: "empty", Phrase: ""},

		// Separators are not part of a phrase: every variant loads the
		// canonical address. Case is: the word lists are lower case.
		{Name: "algorand-25 surrounding whitespace", Phrase: "  " + a1 + "\n"},
		{Name: "xhd-24 surrounding whitespace", Phrase: "\t" + hdPhraseSeq + "\n"},
		{Name: "algorand-25 double space", Phrase: spaced(a1, "  ")},
		{Name: "xhd-24 double space", Phrase: spaced(hdPhraseSeq, "  ")},
		{Name: "algorand-25 tabs", Phrase: spaced(a1, "\t")},
		{Name: "xhd-24 newlines", Phrase: spaced(hdPhraseSeq, "\n")},
		{Name: "algorand-25 CRLF", Phrase: spaced(a1, "\r\n")},
		{Name: "algorand-25 vertical tab and form feed", Phrase: spaced(a1, "\v\f")},
		// Go's whitespace is unicode.IsSpace: NEL and NBSP separate words, a
		// byte-order mark does not. JS's \s matches a byte-order mark and not NEL.
		{Name: "xhd-24 no-break spaces", Phrase: spaced(hdPhraseSeq, r(0xa0))},
		{Name: "algorand-25 next-line separators", Phrase: spaced(a1, r(0x85))},
		{Name: "xhd-24 byte-order mark", Phrase: r(0xfeff) + hdPhraseSeq},
		{Name: "algorand-25 byte-order mark", Phrase: r(0xfeff) + a1},
		{Name: "algorand-25 no-break spaces", Phrase: spaced(a1, r(0xa0))},
		// Full-width letters NFKD-normalize to the ASCII words. Neither Go
		// form normalizes, so both refuse them.
		{Name: "xhd-24 full-width letters", Phrase: fullWidth(hdPhraseSeq)},
		{Name: "algorand-25 full-width letters", Phrase: fullWidth(a1)},
		// One look-alike word among ASCII ones is refused all the same.
		{Name: "xhd-24 one full-width word", Phrase: swapLast(hdPhraseSeq, fullWidth(strings.Fields(hdPhraseSeq)[23]))},
		{Name: "algorand-25 one full-width word", Phrase: swapLast(a1, fullWidth(strings.Fields(a1)[24]))},
		{Name: "algorand-25 upper case", Phrase: strings.ToUpper(a1)},
		{Name: "xhd-24 upper case", Phrase: strings.ToUpper(hdPhraseSeq)},
	}

	digest := sha256.Sum256([]byte("zs account vectors"))
	msgs := [][]byte{{}, []byte("hello zs"), digest[:]}
	receiver, err := types.DecodeAddress("IYRGHE7NYTZRYPGFFNVPH7TVCZVQLQFK2IJ57W5JONTHT4BZEYHXL3MY3E")
	if err != nil {
		t.Fatal(err)
	}
	gh := sha256.Sum256([]byte("zs genesis"))

	ctx := context.Background()
	for i := range in {
		c := &in[i]
		addr, kind, err := DeriveAddress(c.Phrase)
		if err != nil {
			c.Refused = true
			continue
		}
		c.Address, c.Kind = addr, kind

		ks, err := New(ctx, staticProvider{entries: []MnemonicEntry{{Name: "V", Mnemonic: c.Phrase}}})
		if err != nil {
			t.Fatalf("%s: New: %v", c.Name, err)
		}
		for _, m := range msgs {
			sig, err := ks.SignBytes(ctx, addr, m)
			if err != nil {
				t.Fatalf("%s: SignBytes: %v", c.Name, err)
			}
			c.Signatures = append(c.Signatures, accountSignature{Msg: hex.EncodeToString(m), Sig: hex.EncodeToString(sig)})
		}

		sender, err := types.DecodeAddress(addr)
		if err != nil {
			t.Fatal(err)
		}
		tx := types.Transaction{
			Type: types.PaymentTx,
			Header: types.Header{
				Sender:      sender,
				Fee:         1_000,
				FirstValid:  1_000,
				LastValid:   2_000,
				GenesisID:   "zs-vectors",
				GenesisHash: types.Digest(gh),
				Note:        []byte("account vector"),
			},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: 123_456},
		}
		txid, signed, err := ks.SignWithAccount(ctx, tx, addr)
		if err != nil {
			t.Fatalf("%s: SignWithAccount: %v", c.Name, err)
		}
		c.Txn = &accountTxn{
			Txn:    base64.StdEncoding.EncodeToString(msgpack.Encode(tx)),
			Signed: base64.StdEncoding.EncodeToString(signed),
			TxID:   txid,
		}
	}

	f := struct {
		Comment string        `json:"comment"`
		Cases   []accountCase `json:"cases"`
	}{
		Comment: "Generated by proto/go/keystore TestAccountVectors. A recovery phrase (25-word Algorand or 24-word BIP-39 / ARC-52 xHD) and the address and kind it loads as, or refused; raw Ed25519 signatures over fixed messages (hex), and a fixed payment transaction signed (msgpack, base64).",
		Cases:   in,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateAccountVectors {
		if err := os.WriteFile(accountVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(accountVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatal("account_vectors.json is stale; regenerate with -update")
	}
}
