/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana_test

// Cross-impl parity for the codec's edges, which the program's fixtures never
// exercise because the runtime built every one of them: base58 spellings that
// name no key, compact-u16 spellings the runtime refuses, messages and
// transactions it refuses to load, signatures its verify_strict refuses,
// bumps that land on the curve, and a compile whose every privilege group
// holds keys that sort differently as bytes and as base58. Generates /
// verifies proto/testdata/solana_codec_vectors.json, which proto/ts replays,
// so the two payers accept and refuse the same bytes.
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./solana -run TestCodecVectors -update
//
// Without -update, this asserts the on-disk file matches current Go output.
// TestCodecVectorsMeanWhatTheySay checks the cases against the runtime's
// rules independently of this package, so the file can't pin a wrong answer.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"github.com/TxnLab/zerosignal/go/solana"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/solana_codec_vectors.json")

const codecVectorsPath = "../../testdata/solana_codec_vectors.json"

type base58Case struct {
	Hex    string `json:"hex"`
	Base58 string `json:"base58"`
}

type base58Refusal struct {
	Base58 string `json:"base58"`
	Size   int    `json:"size"`
	About  string `json:"about"`
}

type compactCase struct {
	Value int    `json:"value"`
	Hex   string `json:"hex"`
}

type compactRefusal struct {
	// Hex respells the open fixture's key count; Message is that message.
	Hex     string `json:"hex"`
	About   string `json:"about"`
	Message string `json:"message_base64"`
}

type refusal struct {
	Name  string `json:"name"`
	About string `json:"about"`
	Bytes string `json:"base64"`
}

type curveCase struct {
	SeedsHex []string `json:"seeds_hex"`
	Program  string   `json:"program"`
	// Address is "" where create_program_address refuses the seeds: the hash
	// lands on the curve, or a seed is too long.
	Address string `json:"address"`
}

type onCurveCase struct {
	Hex     string `json:"hex"`
	About   string `json:"about"`
	OnCurve bool   `json:"on_curve"`
}

type signatureCase struct {
	Name       string `json:"name"`
	About      string `json:"about"`
	KeyHex     string `json:"key_hex"`
	MsgHex     string `json:"message_hex"`
	SigHex     string `json:"signature_hex"`
	Valid      bool   `json:"valid"`
	Cofactored bool   `json:"valid_cofactored"`
}

type compileMeta struct {
	Pubkey     string `json:"pubkey"`
	IsSigner   bool   `json:"is_signer"`
	IsWritable bool   `json:"is_writable"`
}

type compileInstruction struct {
	ProgramID string        `json:"program_id"`
	Accounts  []compileMeta `json:"accounts"`
	Data      string        `json:"data_base64"`
}

type compileCase struct {
	Name         string               `json:"name"`
	Version      string               `json:"version"`
	FeePayer     string               `json:"fee_payer"`
	Blockhash    string               `json:"recent_blockhash"`
	Instructions []compileInstruction `json:"instructions"`
	Message      string               `json:"message_base64"`
}

type codecVectors struct {
	Version             int              `json:"version"`
	Comment             string           `json:"comment"`
	Base58              []base58Case     `json:"base58"`
	Base58Refused       []base58Refusal  `json:"base58_refused"`
	CompactU16          []compactCase    `json:"compact_u16"`
	CompactU16Refused   []compactRefusal `json:"compact_u16_refused"`
	MessagesRefused     []refusal        `json:"messages_refused"`
	MessagesAccepted    []refusal        `json:"messages_accepted"`
	TransactionsRefused []refusal        `json:"transactions_refused"`
	ProgramAddress      []curveCase      `json:"create_program_address"`
	OnCurve             []onCurveCase    `json:"on_curve"`
	Signatures          []signatureCase  `json:"signatures"`
	Compile             []compileCase    `json:"compile"`
	Builders            []builderCase    `json:"builders"`
}

// builderCase is one call of a token or compute-budget builder: numbers are
// decimal strings, keys base58.
type builderCase struct {
	Builder     string             `json:"builder"`
	Args        map[string]string  `json:"args"`
	Instruction compileInstruction `json:"instruction"`
}

func instructionJSON(ix solana.Instruction) compileInstruction {
	ci := compileInstruction{ProgramID: ix.ProgramID.String(), Data: base64.StdEncoding.EncodeToString(ix.Data), Accounts: []compileMeta{}}
	for _, a := range ix.Accounts {
		ci.Accounts = append(ci.Accounts, compileMeta{a.PublicKey.String(), a.IsSigner, a.IsWritable})
	}
	return ci
}

func buildBuilderCases() []builderCase {
	var out []builderCase
	add := func(builder string, ix solana.Instruction, args ...string) {
		c := builderCase{Builder: builder, Args: map[string]string{}, Instruction: instructionJSON(ix)}
		for i := 0; i < len(args); i += 2 {
			c.Args[args[i]] = args[i+1]
		}
		out = append(out, c)
	}
	for _, u := range []uint32{0, 200_000, math.MaxUint32} {
		add("set_compute_unit_limit", solana.SetComputeUnitLimit(u), "units", strconv.FormatUint(uint64(u), 10))
	}
	for _, p := range []uint64{0, 1, math.MaxUint64} {
		add("set_compute_unit_price", solana.SetComputeUnitPrice(p), "micro_lamports", strconv.FormatUint(p, 10))
	}
	a, b, c, d := pubOf(seedKey(31)), pubOf(seedKey(32)), pubOf(seedKey(33)), pubOf(seedKey(34))
	add("transfer_checked", solana.TransferChecked(a, b, c, d, math.MaxUint64, 6),
		"source", a.String(), "mint", b.String(), "destination", c.String(), "authority", d.String(), "amount", strconv.FormatUint(math.MaxUint64, 10), "decimals", "6")
	for _, amt := range []uint64{0, 1_000_000_000, math.MaxUint64} {
		add("mint_to", solana.MintTo(b, c, d, amt),
			"mint", b.String(), "destination", c.String(), "authority", d.String(), "amount", strconv.FormatUint(amt, 10))
	}
	for _, k := range [][3]solana.PublicKey{{a, b, c}, {a, a, c}} {
		add("create_associated_token_account_idempotent", solana.CreateAssociatedTokenAccountIdempotent(k[0], k[1], k[2]),
			"payer", k[0].String(), "owner", k[1].String(), "mint", k[2].String())
	}
	return out
}

func seedKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}

func pubOf(k ed25519.PrivateKey) solana.PublicKey {
	return solana.PublicKey(k.Public().(ed25519.PublicKey))
}

func openFixture(t *testing.T) []byte {
	var f struct {
		Transactions []txFixture `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	for _, c := range f.Transactions {
		if c.Name == "open" {
			return b64(t, c.Message)
		}
	}
	t.Fatal("no open fixture")
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Points of small order, as encoded.
const (
	order2Point = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	order8Point = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
)

func scalarOf(label string) *edwards25519.Scalar {
	h := sha512.Sum512([]byte(label))
	s, _ := edwards25519.NewScalar().SetUniformBytes(h[:])
	return s
}

func challenge(r, a, msg []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(r)
	h.Write(a)
	h.Write(msg)
	k, _ := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	return k
}

func buildSignatureCases() []signatureCase {
	sig := func(name, about string, key, msg, s []byte) signatureCase {
		var k solana.PublicKey
		copy(k[:], key)
		return signatureCase{Name: name, About: about, KeyHex: hex.EncodeToString(key), MsgHex: hex.EncodeToString(msg),
			SigHex: hex.EncodeToString(s), Valid: solana.VerifyStrict(k, msg, solana.Signature(s)), Cofactored: verifyCofactored(key, msg, s)}
	}
	msg := []byte("zs-solana signature vector")
	priv := seedKey(17)
	pub := priv.Public().(ed25519.PublicKey)
	good := ed25519.Sign(priv, msg)
	var out []signatureCase
	out = append(out, sig("valid", "a key's own signature", pub, msg, good))
	out = append(out, sig("other_message", "the signature over another message", pub, []byte("zs-solana signature vectoR"), good))

	// S + L names the same scalar, so only a canonical-S check refuses it.
	S := new(big.Int).SetBytes(reverse(good[32:]))
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	S.Add(S, L)
	nonCanonical := append(bytes.Clone(good[:32]), reverse(leftPad(S.Bytes(), 32))...)
	out = append(out, sig("s_not_canonical", "S + L in place of S", pub, msg, nonCanonical))

	identity := mustHex("0100000000000000000000000000000000000000000000000000000000000000")
	zero32 := make([]byte, 32)
	out = append(out, sig("small_order_key", "the identity as key, R the identity, S = 0: the equation holds", identity, msg, append(bytes.Clone(identity), zero32...)))
	out = append(out, sig("small_order_key_r_order_2", "the identity as key, R of order 2, S = 0", identity, msg, append(mustHex(order2Point), zero32...)))
	out = append(out, sig("noncanonical_identity_r", "the identity as key, R the identity spelled y = p + 1", identity, msg,
		append(mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), zero32...)))

	// A key with a torsion component: A' = aB + T, T of order 8. Signed with
	// a, it satisfies the cofactored equation and fails the cofactorless one
	// unless the challenge is a multiple of 8.
	a := scalarOf("mixed-order key")
	T, _ := new(edwards25519.Point).SetBytes(mustHex(order8Point))
	Ap := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(a), T)
	for i := 0; ; i++ {
		m := append([]byte("mixed-order key "), byte('a'+i))
		r := scalarOf("nonce " + string(m))
		R := new(edwards25519.Point).ScalarBaseMult(r)
		k := challenge(R.Bytes(), Ap.Bytes(), m)
		if k.Bytes()[0]%8 == 0 {
			continue
		}
		s := edwards25519.NewScalar().MultiplyAdd(k, a, r)
		out = append(out, sig("mixed_order_key", "a key aB + T, T of order 8, signed with a: valid only cofactored", Ap.Bytes(), m, append(R.Bytes(), s.Bytes()...)))
		break
	}

	// R of order 8 and S = k·a: [S]B - [k]A is the identity, not R, so only
	// the cofactored equation, which multiplies R away, holds.
	A := new(edwards25519.Point).ScalarBaseMult(a)
	k := challenge(T.Bytes(), A.Bytes(), msg)
	s := edwards25519.NewScalar().Multiply(k, a)
	out = append(out, sig("small_order_r", "R of order 8, S = k·a: valid only cofactored", A.Bytes(), msg, append(T.Bytes(), s.Bytes()...)))

	// Signatures whose cofactorless equation holds, so the key's or R's
	// small-order check is the only refusal: a forger needs no private key
	// for any of them.
	S0 := scalarOf("small-order key nonce")
	SB := new(edwards25519.Point).ScalarBaseMult(S0)
	out = append(out, sig("small_order_key_r_honest", "the identity as key, R = [S]B", identity, msg, append(SB.Bytes(), S0.Bytes()...)))
	for i := 0; ; i++ {
		m := append([]byte("order-2 key "), byte('a'+i))
		if challenge(SB.Bytes(), mustHex(order2Point), m).Bytes()[0]%2 != 0 {
			continue // [k]A is the identity only for an even challenge
		}
		out = append(out, sig("order_2_key_r_honest", "a key of order 2, an even challenge, R = [S]B", mustHex(order2Point), m, append(SB.Bytes(), S0.Bytes()...)))
		break
	}
	k = challenge(identity, A.Bytes(), msg)
	s = edwards25519.NewScalar().Multiply(k, a)
	out = append(out, sig("identity_r", "an honest key, R the identity, S = k·a", A.Bytes(), msg, append(bytes.Clone(identity), s.Bytes()...)))
	return out
}

// cofactorlessHolds is [S]B - [k]A == R on the encodings, the equation
// verify_strict checks once its point checks pass.
func cofactorlessHolds(key, msg, s []byte) bool {
	A, err := new(edwards25519.Point).SetBytes(key)
	if err != nil {
		return false
	}
	S, err := edwards25519.NewScalar().SetCanonicalBytes(s[32:])
	if err != nil {
		return false
	}
	k := challenge(s[:32], key, msg)
	R := new(edwards25519.Point).Subtract(new(edwards25519.Point).ScalarBaseMult(S), new(edwards25519.Point).ScalarMult(k, A))
	return bytes.Equal(R.Bytes(), s[:32])
}

// verifyCofactored is the RFC 8032 cofactored check, which the vectors record
// beside verify_strict's verdict to show each refusal is the strict rule's.
func verifyCofactored(key, msg, s []byte) bool {
	A, err := new(edwards25519.Point).SetBytes(key)
	if err != nil {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(s[:32])
	if err != nil {
		return false
	}
	S, err := edwards25519.NewScalar().SetCanonicalBytes(s[32:])
	if err != nil {
		return false
	}
	k := challenge(s[:32], key, msg)
	lhs := new(edwards25519.Point).ScalarBaseMult(S)
	rhs := new(edwards25519.Point).Add(R, new(edwards25519.Point).ScalarMult(k, A))
	d := new(edwards25519.Point).Subtract(lhs, rhs)
	return new(edwards25519.Point).MultByCofactor(d).Equal(edwards25519.NewIdentityPoint()) == 1
}

func reverse(b []byte) []byte {
	out := bytes.Clone(b)
	slices.Reverse(out)
	return out
}

func leftPad(b []byte, n int) []byte {
	return append(make([]byte, n-len(b)), b...)
}

// compileKeys picks n seeded keys for one privilege group whose byte order
// and base58 order differ, so a compiler sorting by string fails the vector.
func compileKeys(start byte, n int) ([]solana.PublicKey, byte) {
	for seed := start; ; seed++ {
		var ks []solana.PublicKey
		for i := range n {
			ks = append(ks, pubOf(seedKey(seed+byte(i))))
		}
		byBytes := slices.Clone(ks)
		slices.SortFunc(byBytes, solana.PublicKey.Compare)
		byString := slices.Clone(ks)
		slices.SortFunc(byString, func(a, b solana.PublicKey) int { return strings.Compare(a.String(), b.String()) })
		if !slices.Equal(byBytes, byString) {
			return ks, seed + byte(n)
		}
	}
}

func buildCompileCases(t *testing.T) []compileCase {
	ws, next := compileKeys(100, 3)
	rs, next := compileKeys(next, 3)
	wn, next := compileKeys(next, 3)
	rn, _ := compileKeys(next, 3)
	payer := pubOf(seedKey(99))
	meta := func(k solana.PublicKey, s, w bool) solana.AccountMeta {
		return solana.AccountMeta{PublicKey: k, IsSigner: s, IsWritable: w}
	}
	// Privileges arrive split across instructions and must be merged: rs[0]
	// is named readonly first and a signer later, wn[1] readonly then
	// writable.
	ixs := []solana.Instruction{
		{ProgramID: solana.ComputeBudgetProgramID, Data: []byte{2, 0x60, 0xea, 0, 0}},
		{ProgramID: solana.TokenProgramID, Accounts: []solana.AccountMeta{
			meta(rs[0], false, false), meta(wn[1], false, false), meta(ws[2], true, true), meta(rn[2], false, false),
			meta(ws[0], true, false), meta(ws[0], false, true), meta(payer, false, false),
		}, Data: []byte{12, 1, 2, 3}},
		{ProgramID: rn[0], Accounts: []solana.AccountMeta{
			meta(rs[0], true, false), meta(rs[2], true, false), meta(rs[1], true, false), meta(ws[1], true, true),
			meta(wn[1], false, true), meta(wn[0], false, true), meta(wn[2], false, true), meta(rn[1], false, false),
		}, Data: []byte("zs")},
	}
	blockhash, _ := solana.ParseHash("5TeWSsjg2gbxCyWVniXeCmwM7UtHTCK7svzJr5xYJzHf")
	var out []compileCase
	for _, v := range []solana.MessageVersion{solana.Legacy, solana.V0} {
		m, err := solana.Compile(payer, blockhash, ixs, v)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		c := compileCase{Name: "groups_" + v.String(), Version: v.String(), FeePayer: payer.String(), Blockhash: blockhash.String(), Message: base64.StdEncoding.EncodeToString(b)}
		for _, ix := range ixs {
			ci := compileInstruction{ProgramID: ix.ProgramID.String(), Data: base64.StdEncoding.EncodeToString(ix.Data), Accounts: []compileMeta{}}
			for _, a := range ix.Accounts {
				ci.Accounts = append(ci.Accounts, compileMeta{a.PublicKey.String(), a.IsSigner, a.IsWritable})
			}
			c.Instructions = append(c.Instructions, ci)
		}
		out = append(out, c)
	}
	return out
}

func buildCodecVectors(t *testing.T) codecVectors {
	v := codecVectors{
		Version: 4,
		Comment: "Generated by `cd proto/go && go test ./solana -run TestCodecVectors -update`. " +
			"base58: hex ↔ base58 both ways. base58_refused: strings that must not decode to size bytes. " +
			"compact_u16: value ↔ encoding. compact_u16_refused: the open fixture with its key count respelled, which must not parse. " +
			"messages_refused, transactions_refused: bytes a parser must refuse. messages_accepted: the same shapes just inside each bound. " +
			"create_program_address: the address, or \"\" where the seeds are refused. on_curve: whether a key decodes as a point. " +
			"signatures: verify_strict's verdict (valid), with the cofactored verdict beside it. " +
			"compile: instructions and the message they compile to. " +
			"builders: a token or compute-budget builder's arguments and the instruction it returns.",
	}
	for _, h := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"00000000000000000000000000000000000000000000000000000000000000ff",
		"0001000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000",
	} {
		var k solana.PublicKey
		copy(k[:], mustHex(h))
		v.Base58 = append(v.Base58, base58Case{Hex: h, Base58: k.String()})
	}
	var sig solana.Signature
	sig[63] = 7
	v.Base58 = append(v.Base58, base58Case{Hex: hex.EncodeToString(sig[:]), Base58: sig.String()})
	zero := solana.PublicKey{}.String()
	var ff solana.PublicKey
	for i := range ff {
		ff[i] = 0xff
	}
	max := ff.String()
	v.Base58Refused = []base58Refusal{
		{"", 32, "empty"},
		{"0" + zero[1:], 32, "0 is not in the alphabet"},
		{"O" + max[1:], 32, "O is not in the alphabet"},
		{"I" + max[1:], 32, "I is not in the alphabet"},
		{"l" + max[1:], 32, "l is not in the alphabet"},
		{zero + "1", 32, "a 33rd leading zero"},
		{zero[1:], 32, "31 zero bytes"},
		{max + "1", 32, "decodes past 32 bytes"},
		{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 32, "over 2^256"},
		{"2", 32, "one byte"},
		{max, 64, "a key where a signature belongs"},
		{strings.Repeat("z", 45), 32, "longer than any spelling of 32 bytes"},
		{strings.Repeat("z", 89), 64, "longer than any spelling of 64 bytes"},
		{strings.Repeat("1", 4096), 32, "four thousand leading zeros"},
	}
	for _, c := range []compactCase{{0, "00"}, {1, "01"}, {0x7f, "7f"}, {0x80, "8001"}, {0xff, "ff01"}, {0x3fff, "ff7f"}, {0x4000, "808001"}, {0xffff, "ffff03"}} {
		v.CompactU16 = append(v.CompactU16, c)
	}

	open := openFixture(t)
	parsed, err := solana.ParseMessage(open)
	if err != nil {
		t.Fatal(err)
	}
	nKeys := len(parsed.AccountKeys)
	if open[3] != byte(nKeys) || nKeys > 0x7f {
		t.Fatalf("the open fixture's key count is not the one byte at 3")
	}
	// Each respells the key count of a message that parses with the
	// canonical spelling, so only the canonicity and range checks refuse it.
	for _, c := range []struct{ hex, about string }{
		{"8e00", "14 in two bytes"},
		{"8e8000", "14 in three bytes"},
		{"8e808000", "14 in four bytes"},
		{"8e8004", "over u16 (65550)"},
	} {
		b := append(append(bytes.Clone(open[:3]), mustHex(c.hex)...), open[4:]...)
		if _, err := solana.ParseMessage(b); err == nil {
			t.Fatalf("%s: parses", c.hex)
		}
		v.CompactU16Refused = append(v.CompactU16Refused, compactRefusal{c.hex, c.about, base64.StdEncoding.EncodeToString(b)})
	}

	keysAt := 4 // header, then a one-byte key count
	ixAt := keysAt + 32*nKeys + 32
	refuse := func(name, about string, b []byte) {
		if _, err := solana.ParseMessage(b); err == nil {
			t.Fatalf("%s: parses", name)
		}
		v.MessagesRefused = append(v.MessagesRefused, refusal{name, about, base64.StdEncoding.EncodeToString(b)})
	}
	mutate := func(name, about string, f func(b []byte) []byte) { refuse(name, about, f(bytes.Clone(open))) }
	mutate("trailing_byte", "one byte after the last instruction", func(b []byte) []byte { return append(b, 0) })
	mutate("truncated", "the last byte cut", func(b []byte) []byte { return b[:len(b)-1] })
	mutate("duplicate_key", "static key 3 is key 2 again", func(b []byte) []byte {
		copy(b[keysAt+32*3:keysAt+32*4], b[keysAt+32*2:keysAt+32*3])
		return b
	})
	mutate("no_signers", "the header requires no signature", func(b []byte) []byte { b[0] = 0; return b })
	mutate("readonly_fee_payer", "every signer readonly, the fee payer too", func(b []byte) []byte { b[1] = b[0]; return b })
	mutate("header_overflow", "more readonly keys than keys", func(b []byte) []byte { b[2] = byte(nKeys); return b })
	mutate("version_1", "a v1 prefix", func(b []byte) []byte { return append([]byte{0x81}, b...) })
	mutate("version_127", "the highest version prefix", func(b []byte) []byte { return append([]byte{0xff}, b...) })
	mutate("program_is_fee_payer", "the first instruction calls key 0", func(b []byte) []byte {
		b[ixAt+1] = 0
		return b
	})
	mutate("program_index_past_keys", "the first instruction calls key 200", func(b []byte) []byte {
		b[ixAt+1] = 200
		return b
	})
	// compute budget twice (index, 0 accounts, 5 and 9 data bytes), then the
	// transfer: program index, account count, first account.
	accountAt := ixAt + 1 + (1 + 1 + 1 + 5) + (1 + 1 + 1 + 9) + 2
	mutate("account_index_past_keys", "the third instruction names key 200", func(b []byte) []byte {
		b[accountAt] = 200
		return b
	})
	// Each bound beside the same shape just inside it, so a bound off by one
	// fails one or the other.
	accept := func(name, about string, b []byte) {
		if _, err := solana.ParseMessage(b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v.MessagesAccepted = append(v.MessagesAccepted, refusal{name, about, base64.StdEncoding.EncodeToString(b)})
	}
	mutate("program_index_one_past_keys", "the first instruction calls the key one past the last", func(b []byte) []byte {
		b[ixAt+1] = byte(nKeys)
		return b
	})
	b := bytes.Clone(open)
	b[ixAt+1] = byte(nKeys - 1)
	accept("program_index_last_key", "the first instruction calls the last key", b)
	mutate("account_index_one_past_keys", "the third instruction names the key one past the last", func(b []byte) []byte {
		b[accountAt] = byte(nKeys)
		return b
	})
	b = bytes.Clone(open)
	b[accountAt] = byte(nKeys - 1)
	accept("account_index_last_key", "the third instruction names the last key", b)
	mutate("v0_prefix_without_lookups", "a v0 prefix on a legacy body, so no lookup count follows", func(b []byte) []byte {
		return append([]byte{0x80}, b...)
	})
	v0 := func(lookups ...solana.AddressTableLookup) []byte {
		b := append([]byte{0x80}, open...)
		b = append(b, byte(len(lookups)))
		for _, l := range lookups {
			b = append(b, l.AccountKey[:]...)
			b = append(b, byte(len(l.WritableIndexes)))
			b = append(b, l.WritableIndexes...)
			b = append(b, byte(len(l.ReadonlyIndexes)))
			b = append(b, l.ReadonlyIndexes...)
		}
		return b
	}
	if _, err := solana.ParseMessage(v0(solana.AddressTableLookup{AccountKey: solana.SysvarRentID, WritableIndexes: []uint8{0}})); err != nil {
		t.Fatalf("the v0 base does not parse: %v", err)
	}
	refuse("lookup_loads_nothing", "a v0 lookup with no indexes", v0(solana.AddressTableLookup{AccountKey: solana.SysvarRentID}))
	many := make([]uint8, 0x7f)
	refuse("over_256_keys_with_lookups", "14 static keys and 2 × 127 + 1 looked up", v0(
		solana.AddressTableLookup{AccountKey: solana.SysvarRentID, WritableIndexes: many},
		solana.AddressTableLookup{AccountKey: solana.SysvarClockID, ReadonlyIndexes: many},
		solana.AddressTableLookup{AccountKey: solana.AddressLookupTableProgramID, ReadonlyIndexes: []uint8{1}},
	))
	totalOf := func(n int) []byte {
		return v0(
			solana.AddressTableLookup{AccountKey: solana.SysvarRentID, WritableIndexes: make([]uint8, 0x7f)},
			solana.AddressTableLookup{AccountKey: solana.SysvarClockID, ReadonlyIndexes: make([]uint8, n-nKeys-0x7f)},
		)
	}
	refuse("257_keys_with_lookups", "static and looked-up keys one over 256", totalOf(257))
	accept("256_keys_with_lookups", "static and looked-up keys at 256", totalOf(256))
	static := []byte{1, 0, 0, 0x81, 0x02} // 257 keys
	for i := range 257 {
		k := sha512.Sum512([]byte{byte(i), byte(i >> 8)})
		static = append(static, k[:32]...)
	}
	static = append(static, make([]byte, 32)...)
	refuse("over_256_static_keys", "257 static keys", append(static, 0))

	// A transaction one byte over the limit, beside the same shape at it.
	sized := func(n int) []byte {
		m := solana.Message{
			Header:       solana.MessageHeader{NumRequiredSignatures: 1, NumReadonlyUnsignedAccounts: 1},
			AccountKeys:  []solana.PublicKey{pubOf(seedKey(17)), solana.SystemProgramID},
			Instructions: []solana.CompiledInstruction{{ProgramIDIndex: 1}},
		}
		base, _ := m.MarshalBinary()
		// signature count and signature, then the message, whose data length
		// grows from one byte to two at 128.
		data := n - 1 - 64 - len(base)
		if data >= 128 {
			data--
		}
		m.Instructions[0].Data = make([]byte, data)
		msg, _ := m.MarshalBinary()
		return append(append([]byte{1}, make([]byte, 64)...), msg...)
	}
	if b := sized(solana.MaxTransactionSize); len(b) != solana.MaxTransactionSize {
		t.Fatalf("sized %d", len(b))
	} else if _, err := solana.ParseTransaction(b); err != nil {
		t.Fatalf("a transaction at the limit: %v", err)
	}
	over := sized(solana.MaxTransactionSize + 1)
	if _, err := solana.ParseTransaction(over); err == nil || len(over) != solana.MaxTransactionSize+1 {
		t.Fatal("a transaction over the limit parses")
	}
	v.TransactionsRefused = append(v.TransactionsRefused, refusal{"over_size_limit", "1233 bytes, one over the limit", base64.StdEncoding.EncodeToString(over)})

	for _, c := range []struct {
		seeds [][]byte
		prog  solana.PublicKey
	}{
		{[][]byte{[]byte("config")}, zsProgram},
		{[][]byte{[]byte("config"), {255}}, zsProgram},
		{[][]byte{[]byte("config"), {254}}, zsProgram},
		{[][]byte{[]byte("config"), {252}}, zsProgram},
		{[][]byte{bytes.Repeat([]byte{1}, 33)}, zsProgram},
		{nil, solana.TokenProgramID},
	} {
		cc := curveCase{Program: c.prog.String(), SeedsHex: []string{}}
		for _, s := range c.seeds {
			cc.SeedsHex = append(cc.SeedsHex, hex.EncodeToString(s))
		}
		if k, err := solana.CreateProgramAddress(c.seeds, c.prog); err == nil {
			cc.Address = k.String()
		}
		v.ProgramAddress = append(v.ProgramAddress, cc)
	}

	// The runtime decompresses with curve25519-dalek, which accepts a y at or
	// past the field prime and an x of 0 with its sign bit set; a decoder
	// that refused either would call such a key a PDA when no program can
	// sign for it and a private key can.
	for _, c := range []struct{ hex, about string }{
		{"0100000000000000000000000000000000000000000000000000000000000000", "the identity, y = 1"},
		{"0100000000000000000000000000000000000000000000000000000000000080", "the identity with the sign bit, x = 0"},
		{"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "y = p + 1, a non-canonical identity"},
		{"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "y = p, a non-canonical 0"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "every bit set"},
		{"0200000000000000000000000000000000000000000000000000000000000000", "y = 2"},
		{order8Point, "a point of order 8"},
		{hex.EncodeToString(solana.MustPublicKey("F25s3DdjXdCxYBhh2z8FBusVEMT4b9bGNFVKJi3wFoF4").Bytes()), "a wallet key"},
		{hex.EncodeToString(solana.MustPublicKey("3rVjuc7SGmuoEH39tXujSZxTrSQKitiLifUCfvgfTS7o").Bytes()), "the config PDA"},
	} {
		var k solana.PublicKey
		copy(k[:], mustHex(c.hex))
		v.OnCurve = append(v.OnCurve, onCurveCase{Hex: c.hex, About: c.about, OnCurve: solana.IsOnCurve(k)})
	}
	v.Signatures = buildSignatureCases()
	v.Compile = buildCompileCases(t)
	v.Builders = buildBuilderCases()
	return v
}

var zsProgram = solana.MustPublicKey("2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1")

func TestCodecVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildCodecVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(codecVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(codecVectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("solana_codec_vectors.json is stale: go test ./solana -run TestCodecVectors -update")
	}
}

// fieldP is 2^255 - 19.
var fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// onCurveReference is dalek's decompress in big-integer arithmetic: y is the
// low 255 bits reduced mod p, and the point exists iff (y²-1)/(dy²+1) is a
// square or zero; the sign bit never refuses one.
func onCurveReference(b []byte) bool {
	le := reverse(b)
	le[0] &= 0x7f
	y := new(big.Int).Mod(new(big.Int).SetBytes(le), fieldP)
	d := new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), fieldP)), fieldP)
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Mod(new(big.Int).Sub(y2, big.NewInt(1)), fieldP)
	vv := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(d, y2), big.NewInt(1)), fieldP)
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, new(big.Int).ModInverse(vv, fieldP)), fieldP)
	return x2.Sign() == 0 || big.Jacobi(x2, fieldP) == 1
}

// The vectors pin what this package does; these check it is what the runtime
// does, independently of the package.
func TestCodecVectorsMeanWhatTheySay(t *testing.T) {
	v := buildCodecVectors(t)
	for _, c := range v.Base58 {
		b := mustHex(c.Hex)
		switch len(b) {
		case 32:
			k, err := solana.ParsePublicKey(c.Base58)
			if err != nil || hex.EncodeToString(k[:]) != c.Hex {
				t.Errorf("%s: %x %v", c.Base58, k, err)
			}
		case 64:
			s, err := solana.ParseSignature(c.Base58)
			if err != nil || hex.EncodeToString(s[:]) != c.Hex {
				t.Errorf("%s: %v", c.Base58, err)
			}
		}
	}
	if v.Base58[0].Base58 != "11111111111111111111111111111111" || v.Base58[5].Base58 != solana.ComputeBudgetProgramID.String() {
		t.Errorf("zero key %s, compute budget %s", v.Base58[0].Base58, v.Base58[5].Base58)
	}
	for _, c := range v.Base58Refused {
		var err error
		if c.Size == 64 {
			_, err = solana.ParseSignature(c.Base58)
		} else {
			_, err = solana.ParsePublicKey(c.Base58)
		}
		if err == nil {
			t.Errorf("%q (%s) decodes", c.Base58, c.About)
		}
	}

	// The canonical spelling of the same count parses, so each refusal is
	// the spelling's alone.
	open := openFixture(t)
	if _, err := solana.ParseMessage(open); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.CompactU16Refused {
		if !strings.HasPrefix(c.Hex, "8e") {
			t.Errorf("%s does not respell 14", c.Hex)
		}
		// Refused for its spelling, not for a short read the count it spells
		// would cause.
		if _, err := solana.ParseMessage(b64(t, c.Message)); err == nil || !strings.Contains(err.Error(), "length") {
			t.Errorf("%s (%s): %v", c.Hex, c.About, err)
		}
	}

	if v.ProgramAddress[1].Address != "" || v.ProgramAddress[3].Address != "3rVjuc7SGmuoEH39tXujSZxTrSQKitiLifUCfvgfTS7o" || v.ProgramAddress[4].Address != "" {
		t.Errorf("program addresses: %+v", v.ProgramAddress)
	}
	for _, c := range v.OnCurve {
		if want := onCurveReference(mustHex(c.Hex)); c.OnCurve != want {
			t.Errorf("%s: on curve %v, the reference says %v", c.About, c.OnCurve, want)
		}
	}

	byName := map[string]signatureCase{}
	for _, c := range v.Signatures {
		byName[c.Name] = c
		if c.Valid != (c.Name == "valid") {
			t.Errorf("%s: valid %v", c.Name, c.Valid)
		}
	}
	for _, name := range []string{"valid", "small_order_key", "mixed_order_key", "small_order_r", "small_order_key_r_honest", "order_2_key_r_honest", "identity_r"} {
		if !byName[name].Cofactored {
			t.Errorf("%s: the case is meant to pass the cofactored check, to show the strict rule refuses it", name)
		}
	}
	for _, name := range []string{"valid", "small_order_key", "small_order_key_r_honest", "order_2_key_r_honest", "identity_r"} {
		c := byName[name]
		if !cofactorlessHolds(mustHex(c.KeyHex), mustHex(c.MsgHex), mustHex(c.SigHex)) {
			t.Errorf("%s: the case is meant to pass the cofactorless equation, so only a small-order check refuses it", name)
		}
	}
	good := byName["valid"]
	if !ed25519.Verify(mustHex(good.KeyHex), mustHex(good.MsgHex), mustHex(good.SigHex)) {
		t.Error("the valid case fails crypto/ed25519")
	}
	if T, _ := new(edwards25519.Point).SetBytes(mustHex(order8Point)); new(edwards25519.Point).MultByCofactor(T).Equal(edwards25519.NewIdentityPoint()) != 1 ||
		new(edwards25519.Point).Add(T, T).Add(new(edwards25519.Point).Add(T, T), new(edwards25519.Point).Add(T, T)).Equal(edwards25519.NewIdentityPoint()) == 1 {
		t.Error("order8Point is not of order 8")
	}

	// Within every privilege group the compiled keys are in byte order,
	// which their base58 order is not.
	for _, c := range v.Compile {
		m, err := solana.ParseMessage(b64(t, c.Message))
		if err != nil {
			t.Fatal(err)
		}
		h := m.Header
		ns, rs, ru := int(h.NumRequiredSignatures), int(h.NumReadonlySignedAccounts), int(h.NumReadonlyUnsignedAccounts)
		n := len(m.AccountKeys)
		groups := [][]solana.PublicKey{m.AccountKeys[1 : ns-rs], m.AccountKeys[ns-rs : ns], m.AccountKeys[ns : n-ru], m.AccountKeys[n-ru:]}
		for i, g := range groups {
			if len(g) < 3 {
				t.Errorf("%s group %d has %d keys", c.Name, i, len(g))
			}
			if !slices.IsSortedFunc(g, solana.PublicKey.Compare) {
				t.Errorf("%s group %d is not in byte order", c.Name, i)
			}
		}
		if m.FeePayer().String() != c.FeePayer {
			t.Errorf("%s: fee payer %s", c.Name, m.FeePayer())
		}
	}
}

// MintTo has no crate-built fixture, so its layout is pinned here as SPL
// Token's interface defines it: the tag, the amount little-endian, and the
// mint, the destination and the signing authority. The stub mints test USDC
// with it against the real token program in the end-to-end suites.
func TestMintToLayout(t *testing.T) {
	m, d, a := pubOf(seedKey(1)), pubOf(seedKey(2)), pubOf(seedKey(3))
	ix := solana.MintTo(m, d, a, 0x0102030405060708)
	want := solana.Instruction{
		ProgramID: solana.TokenProgramID,
		Accounts:  []solana.AccountMeta{{PublicKey: m, IsWritable: true}, {PublicKey: d, IsWritable: true}, {PublicKey: a, IsSigner: true}},
		Data:      []byte{7, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	if ix.ProgramID != want.ProgramID || !slices.Equal(ix.Accounts, want.Accounts) || !bytes.Equal(ix.Data, want.Data) {
		t.Fatalf("MintTo = %+v, want %+v", ix, want)
	}
}

// The program's fixture writer builds the compute budget, TransferChecked and
// CreateIdempotent with their programs' interface crates, so the builders
// rebuilding each from the values in its data, flags and all, is a check this
// package can't pass by agreeing with itself.
func TestBuildersMatchTheInterfaceCrates(t *testing.T) {
	var f struct {
		Transactions []txFixture `json:"transactions"`
	}
	readFixture(t, "solana_tx_vectors.json", &f)
	built := func(name string) []solana.Instruction {
		for _, x := range f.Transactions {
			if x.Name != name {
				continue
			}
			var out []solana.Instruction
			for _, b := range x.BuiltInstructions {
				ix := solana.Instruction{ProgramID: b.ProgramID, Data: b64(t, b.Data), Accounts: []solana.AccountMeta{}}
				for _, a := range b.Accounts {
					ix.Accounts = append(ix.Accounts, solana.AccountMeta{PublicKey: a.Pubkey, IsSigner: a.IsSigner, IsWritable: a.IsWritable})
				}
				out = append(out, ix)
			}
			return out
		}
		t.Fatalf("no %s fixture", name)
		return nil
	}
	same := func(name string, got, want solana.Instruction) {
		if got.ProgramID != want.ProgramID || !slices.Equal(got.Accounts, want.Accounts) || !bytes.Equal(got.Data, want.Data) {
			t.Errorf("%s: %+v, the crate's %+v", name, got, want)
		}
	}
	ix := built("open")
	if len(ix) != 4 || ix[0].Data[0] != solana.ComputeBudgetSetComputeUnitLimit || ix[1].Data[0] != solana.ComputeBudgetSetComputeUnitPrice {
		t.Fatal("the open fixture is not compute budget, transfer, open")
	}
	same("SetComputeUnitLimit", solana.SetComputeUnitLimit(binary.LittleEndian.Uint32(ix[0].Data[1:])), ix[0])
	same("SetComputeUnitPrice", solana.SetComputeUnitPrice(binary.LittleEndian.Uint64(ix[1].Data[1:])), ix[1])
	k := ix[2].Accounts
	same("TransferChecked", solana.TransferChecked(k[0].PublicKey, k[1].PublicKey, k[2].PublicKey, k[3].PublicKey,
		binary.LittleEndian.Uint64(ix[2].Data[1:]), ix[2].Data[9]), ix[2])
	ata := built("create_ata_idempotent")
	if len(ata) != 1 {
		t.Fatal("the create_ata_idempotent fixture is not one instruction")
	}
	k = ata[0].Accounts
	same("CreateIdempotent", solana.CreateAssociatedTokenAccountIdempotent(k[0].PublicKey, k[2].PublicKey, k[3].PublicKey), ata[0])
}
