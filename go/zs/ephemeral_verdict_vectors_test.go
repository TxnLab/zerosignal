/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/ephemeral_verdict_vectors.json: what a
// probe's ephemeral advertisement leaves a node with (checkEphemeral). The TS
// SDK mirrors it in sdk/src/catalog/ephemeral.ts.
//
//	cd proto/go && go test ./zs -run TestEphemeralVerdictVectors -update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const ephemeralVerdictVectorsPath = "../../testdata/ephemeral_verdict_vectors.json"

type ephemeralVerdictAdv struct {
	AgePubkey string `json:"ephemeral_age_pubkey"`
	Expiry    int64  `json:"ephemeral_expiry"`
	IssuedAt  int64  `json:"ephemeral_issued_at"`
	Sig       string `json:"ephemeral_sig"`
}

type ephemeralVerdictWant struct {
	Outcome ephemeralOutcome `json:"outcome"`
	Stale   bool             `json:"stale"`
}

type ephemeralVerdictCase struct {
	Name       string               `json:"name"`
	OperatorID uint64               `json:"operator_id"`
	NodeID     uint64               `json:"node_id"`
	SigningKey string               `json:"signing_key"`
	Now        int64                `json:"now"`
	Adv        ephemeralVerdictAdv  `json:"advertisement"`
	Want       ephemeralVerdictWant `json:"want"`
}

const (
	evOp    = 42
	evNode  = 7
	evNow   = 1_800_000_000
	evRecip = "age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s"
)

// bech32Encode is BIP-173 bech32 (not bech32m), the encoding age recipients
// use, so the parse cases can carry well-formed strings age still refuses.
func bech32Encode(hrp string, words []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	polymod := func(values []byte) uint32 {
		gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
		chk := uint32(1)
		for _, v := range values {
			top := chk >> 25
			chk = (chk&0x1ffffff)<<5 ^ uint32(v)
			for i := range 5 {
				if (top>>i)&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	var expanded []byte
	for _, c := range hrp {
		expanded = append(expanded, byte(c>>5))
	}
	expanded = append(expanded, 0)
	for _, c := range hrp {
		expanded = append(expanded, byte(c&31))
	}
	values := append(append(expanded, words...), 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, w := range words {
		b.WriteByte(charset[w])
	}
	for i := range 6 {
		b.WriteByte(charset[(mod>>(5*(5-i)))&31])
	}
	return b.String()
}

// toWords regroups bytes into 5-bit words, zero-padding the tail.
func toWords(data []byte) []byte {
	var words []byte
	acc, bits := uint32(0), 0
	for _, d := range data {
		acc = acc<<8 | uint32(d)
		bits += 8
		for bits >= 5 {
			bits -= 5
			words = append(words, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		words = append(words, byte(acc<<(5-bits))&31)
	}
	return words
}

func ephemeralVerdictCases() []ephemeralVerdictCase {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	key := hex.EncodeToString(pub)

	type spec struct {
		name     string
		recip    string
		issued   int64
		expiry   int64
		signOp   uint64
		signNode uint64
		now      int64
		// mutate edits the wire block after signing.
		mutate func(*ephemeralVerdictAdv)
		key    string
	}
	c := func(s spec) ephemeralVerdictCase {
		if s.recip == "" {
			s.recip = evRecip
		}
		if s.signOp == 0 {
			s.signOp = evOp
		}
		if s.signNode == 0 {
			s.signNode = evNode
		}
		if s.now == 0 {
			s.now = evNow
		}
		if s.key == "" {
			s.key = key
		}
		adv := ticket.EphemeralAdvertisement{AgePubkey: s.recip, Expiry: s.expiry, IssuedAt: s.issued}
		digest := ticket.EphemeralSigDigest(&adv, s.signOp, s.signNode)
		wireAdv := ephemeralVerdictAdv{
			AgePubkey: s.recip,
			Expiry:    s.expiry,
			IssuedAt:  s.issued,
			Sig:       base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:])),
		}
		if s.mutate != nil {
			s.mutate(&wireAdv)
		}
		return ephemeralVerdictCase{
			Name: s.name, OperatorID: evOp, NodeID: evNode, SigningKey: s.key, Now: s.now, Adv: wireAdv,
		}
	}
	const life = 25 * 60
	fresh := int64(evNow - 60)

	// Well-formed bech32 that age still refuses as an X25519 recipient.
	point := bytes.Repeat([]byte{0x5a}, 32)
	wrongHRP := bech32Encode("agf", toWords(point))
	short := bech32Encode("age", toWords(point[:31]))
	long := bech32Encode("age", toWords(append(bytes.Clone(point), 0x5a)))
	padWords := toWords(point)
	padWords[len(padWords)-1] |= 1 // 256 bits leave four padding bits; set one
	nonZeroPad := bech32Encode("age", padWords)
	zeroPoint := bech32Encode("age", toWords(make([]byte, 32)))
	badChecksum := evRecip[:len(evRecip)-1] + "q"
	if badChecksum == evRecip {
		badChecksum = evRecip[:len(evRecip)-1] + "p"
	}
	mixedCase := "age1" + strings.ToUpper(evRecip[4:5]) + evRecip[5:]

	return []ephemeralVerdictCase{
		c(spec{name: "no advertisement", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.AgePubkey = "" }}),
		c(spec{name: "a fresh, genuine block", issued: fresh, expiry: fresh + life}),
		c(spec{name: "at the freshness target is still fresh", issued: evNow - 21*60, expiry: evNow - 21*60 + life}),
		c(spec{name: "past the freshness target is stale but usable", issued: evNow - 21*60 - 1, expiry: evNow - 21*60 - 1 + life}),
		c(spec{name: "at expiry plus skew is still live", issued: evNow - 60 - life, expiry: evNow - 60}),
		c(spec{name: "past expiry plus skew is expired", issued: evNow - 61 - life, expiry: evNow - 61}),
		c(spec{name: "a lifetime at the cap", issued: fresh, expiry: fresh + 40*60}),
		c(spec{name: "a lifetime over the cap", issued: fresh, expiry: fresh + 40*60 + 1}),
		c(spec{name: "expiry before issue", issued: fresh, expiry: fresh - 1}),
		c(spec{name: "issued at the skew limit", issued: evNow + 60, expiry: evNow + 60 + life}),
		c(spec{name: "issued past the skew limit", issued: evNow + 61, expiry: evNow + 61 + life}),
		c(spec{name: "no issued_at (a pre-v2 node)", issued: 0, expiry: fresh + life}),
		c(spec{name: "signed for another operator", issued: fresh, expiry: fresh + life, signOp: evOp + 1}),
		c(spec{name: "signed for a sibling node", issued: fresh, expiry: fresh + life, signNode: evNode + 1}),
		c(spec{name: "expiry altered after signing", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.Expiry++ }}),
		c(spec{name: "recipient swapped after signing", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.AgePubkey = zeroPoint }}),
		c(spec{name: "a flipped signature byte", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) {
				sig, _ := base64.StdEncoding.DecodeString(a.Sig)
				sig[0] ^= 1
				a.Sig = base64.StdEncoding.EncodeToString(sig)
			}}),
		c(spec{name: "no signature", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.Sig = "" }}),
		c(spec{name: "a signature that is not base64", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.Sig = "!" + a.Sig[1:] }}),
		// Go's base64 decoder skips CR and LF anywhere in its input.
		c(spec{name: "a signature with a line break", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.Sig = a.Sig[:40] + "\r\n" + a.Sig[40:] }}),
		// ...but only CR and LF: any other whitespace is a bad character.
		c(spec{name: "a signature with a space", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.Sig = a.Sig[:40] + " " + a.Sig[40:] }}),
		c(spec{name: "a signature with a tab", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) { a.Sig = a.Sig[:40] + "\t" + a.Sig[40:] }}),
		// StdEncoding (not Strict) ignores the unused low bits of the character
		// before the padding; a 64-byte signature leaves four of them.
		c(spec{name: "a signature with set padding bits", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) {
				const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
				i := len(a.Sig) - 3
				a.Sig = a.Sig[:i] + string(alphabet[strings.IndexByte(alphabet, a.Sig[i])|0x0f]) + a.Sig[i+1:]
			}}),
		c(spec{name: "a short signature", issued: fresh, expiry: fresh + life,
			mutate: func(a *ephemeralVerdictAdv) {
				sig, _ := base64.StdEncoding.DecodeString(a.Sig)
				a.Sig = base64.StdEncoding.EncodeToString(sig[:63])
			}}),
		c(spec{name: "a signing key of the wrong length", issued: fresh, expiry: fresh + life, key: key[:62]}),
		c(spec{name: "a signed recipient with a bad checksum", recip: badChecksum, issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed recipient in mixed case", recip: mixedCase, issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed recipient in upper case", recip: strings.ToUpper(evRecip), issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed recipient of another type", recip: wrongHRP, issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed 31-byte recipient", recip: short, issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed 33-byte recipient", recip: long, issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed recipient with non-zero padding", recip: nonZeroPad, issued: fresh, expiry: fresh + life}),
		c(spec{name: "a signed recipient that is not bech32", recip: "age1notarecipient", issued: fresh, expiry: fresh + life}),
		// U+212A KELVIN SIGN folds to "k" under Unicode case rules; age folds
		// ASCII only, so it is not a bech32 character.
		c(spec{name: "a signed recipient with a Kelvin sign", recip: strings.Replace(evRecip, "k", string(rune(0x212a)), 1), issued: fresh, expiry: fresh + life}),
		// The window is checked before the recipient is parsed.
		c(spec{name: "an expired block with an unparseable recipient", recip: "age1notarecipient", issued: evNow - 61 - life, expiry: evNow - 61}),
		c(spec{name: "a signed all-zero recipient parses", recip: zeroPoint, issued: fresh, expiry: fresh + life}),
	}
}

func TestEphemeralVerdictVectors(t *testing.T) {
	cases := ephemeralVerdictCases()
	for i, c := range cases {
		key, err := hex.DecodeString(c.SigningKey)
		if err != nil {
			t.Fatalf("%s: signing key: %v", c.Name, err)
		}
		resp := inject.OperatorDetails{
			EphemeralAgePubkey: c.Adv.AgePubkey,
			EphemeralExpiry:    c.Adv.Expiry,
			EphemeralIssuedAt:  c.Adv.IssuedAt,
			EphemeralSig:       c.Adv.Sig,
		}
		v := checkEphemeral(resp, key, time.Unix(c.Now, 0), c.OperatorID, c.NodeID)
		cases[i].Want = ephemeralVerdictWant{Outcome: v.Outcome, Stale: v.Stale}
	}
	f := struct {
		Comment string                 `json:"comment"`
		Cases   []ephemeralVerdictCase `json:"cases"`
	}{
		Comment: "Generated by proto/go/zs TestEphemeralVerdictVectors. Each case is one probe's advertisement as the wire carries it, checked against the node's chain-resolved (operator_id, node_id) and Ed25519 signing_key (hex) at now (unix seconds). want.outcome is absent | verified | expired | rejected | unparseable; want.stale is the relay-staleness signal, set only on a verified block.",
		Cases:   cases,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(ephemeralVerdictVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(ephemeralVerdictVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("ephemeral verdicts differ from %s; if the change is intended, regenerate with -update and review the diff", ephemeralVerdictVectorsPath)
	}
}
