/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
)

// MaxTransactionSize is the largest serialized transaction a validator
// accepts: an IPv6 MTU less its headers.
const MaxTransactionSize = 1232

// MessageVersion is a message's format. The zero value is legacy, which has
// no version prefix on the wire.
type MessageVersion uint8

const (
	Legacy MessageVersion = iota
	V0
)

func (v MessageVersion) String() string {
	if v == V0 {
		return "v0"
	}
	return "legacy"
}

// versionPrefix marks a versioned message: a legacy message starts with its
// signature count, which is under 128, so a set high bit can't be one.
const versionPrefix = 0x80

type AccountMeta struct {
	PublicKey  PublicKey
	IsSigner   bool
	IsWritable bool
}

// Instruction is an instruction before compiling, with each account's
// privileges. A compiled message keeps only the union of each key's
// privileges, in its header.
type Instruction struct {
	ProgramID PublicKey
	Accounts  []AccountMeta
	Data      []byte
}

type MessageHeader struct {
	NumRequiredSignatures       uint8
	NumReadonlySignedAccounts   uint8
	NumReadonlyUnsignedAccounts uint8
}

// CompiledInstruction indexes the message's keys: its static keys, then a v0
// message's looked-up writable addresses, then its looked-up readonly ones.
type CompiledInstruction struct {
	ProgramIDIndex uint8
	Accounts       []uint8
	Data           []byte
}

type AddressTableLookup struct {
	AccountKey      PublicKey
	WritableIndexes []uint8
	ReadonlyIndexes []uint8
}

type Message struct {
	Version             MessageVersion
	Header              MessageHeader
	AccountKeys         []PublicKey
	RecentBlockhash     Hash
	Instructions        []CompiledInstruction
	AddressTableLookups []AddressTableLookup
}

var ErrMessage = errors.New("solana: malformed message")

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMessage, fmt.Sprintf(format, a...))
}

// checkIndex panics on an index no instruction of a parsed message can hold:
// answering for it would hand a verifier a privilege for a key that isn't
// there.
func (m *Message) checkIndex(i int) {
	if i < 0 || i >= len(m.AccountKeys)+m.lookedUp() {
		panic(fmt.Sprintf("solana: account index %d of %d", i, len(m.AccountKeys)+m.lookedUp()))
	}
}

// IsSigner reports whether account i must sign: a static key the header
// counts among the signers. A looked-up address never signs.
func (m *Message) IsSigner(i int) bool {
	m.checkIndex(i)
	return i < int(m.Header.NumRequiredSignatures)
}

// IsWritable reports whether the message grants account i write access: by
// the header for a static key, and by its lookup list for a looked-up
// address, the writable ones coming first. The runtime also demotes a
// program id or a reserved account to readonly, which this does not model: a
// verifier that asks whether a key may be written must treat this as the
// most it can get.
func (m *Message) IsWritable(i int) bool {
	m.checkIndex(i)
	h := m.Header
	n := len(m.AccountKeys)
	switch {
	case i < int(h.NumRequiredSignatures):
		return i < int(h.NumRequiredSignatures-h.NumReadonlySignedAccounts)
	case i < n:
		return i < n-int(h.NumReadonlyUnsignedAccounts)
	}
	writable := 0
	for _, l := range m.AddressTableLookups {
		writable += len(l.WritableIndexes)
	}
	return i < n+writable
}

// FeePayer is the first signer, who pays the fee and must be writable.
func (m *Message) FeePayer() PublicKey { return m.AccountKeys[0] }

// lookedUp is how many addresses the message's lookups add after its static
// keys.
func (m *Message) lookedUp() int {
	n := 0
	for _, l := range m.AddressTableLookups {
		n += len(l.WritableIndexes) + len(l.ReadonlyIndexes)
	}
	return n
}

// MarshalBinary writes the bytes every signer signs.
func (m *Message) MarshalBinary() ([]byte, error) {
	if err := m.sanitize(); err != nil {
		return nil, err
	}
	var b []byte
	if m.Version == V0 {
		b = append(b, versionPrefix)
	}
	b = append(b, m.Header.NumRequiredSignatures, m.Header.NumReadonlySignedAccounts, m.Header.NumReadonlyUnsignedAccounts)
	b = appendCompactU16(b, len(m.AccountKeys))
	for _, k := range m.AccountKeys {
		b = append(b, k[:]...)
	}
	b = append(b, m.RecentBlockhash[:]...)
	b = appendCompactU16(b, len(m.Instructions))
	for _, ix := range m.Instructions {
		b = append(b, ix.ProgramIDIndex)
		b = appendCompactU16(b, len(ix.Accounts))
		b = append(b, ix.Accounts...)
		b = appendCompactU16(b, len(ix.Data))
		b = append(b, ix.Data...)
	}
	if m.Version == V0 {
		b = appendCompactU16(b, len(m.AddressTableLookups))
		for _, l := range m.AddressTableLookups {
			b = append(b, l.AccountKey[:]...)
			b = appendCompactU16(b, len(l.WritableIndexes))
			b = append(b, l.WritableIndexes...)
			b = appendCompactU16(b, len(l.ReadonlyIndexes))
			b = append(b, l.ReadonlyIndexes...)
		}
	}
	return b, nil
}

// ParseMessage decodes a message and refuses one the runtime would refuse to
// load: trailing bytes, a header that claims more keys than there are, a
// duplicate key, an index past the keys, or a program called from a lookup
// table or from the fee payer. Every length is a canonical compact-u16, so a
// parsed message re-encodes to exactly the bytes that were signed.
func ParseMessage(b []byte) (*Message, error) {
	r := reader{b: b}
	m := &Message{}
	if len(b) > 0 && b[0]&versionPrefix != 0 {
		if v := b[0] &^ versionPrefix; v != 0 {
			return nil, malformed("message version %d", v)
		}
		m.Version = V0
		r.off++
	}
	h := r.bytes(3)
	if h == nil {
		return nil, malformed("short header")
	}
	m.Header = MessageHeader{h[0], h[1], h[2]}
	// A refused length reads as 0, so each count's error is returned before
	// a later field's short read can stand in for it.
	n := r.compactU16()
	if r.err != nil {
		return nil, r.err
	}
	for range n {
		var k PublicKey
		if !r.into(k[:]) {
			return nil, malformed("short account keys")
		}
		m.AccountKeys = append(m.AccountKeys, k)
	}
	if !r.into(m.RecentBlockhash[:]) {
		return nil, malformed("short blockhash")
	}
	nix := r.compactU16()
	if r.err != nil {
		return nil, r.err
	}
	for range nix {
		var ix CompiledInstruction
		p := r.bytes(1)
		if p == nil {
			return nil, malformed("short instruction")
		}
		ix.ProgramIDIndex = p[0]
		ix.Accounts = slices.Clone(r.bytes(r.compactU16()))
		ix.Data = slices.Clone(r.bytes(r.compactU16()))
		if r.err != nil {
			break
		}
		m.Instructions = append(m.Instructions, ix)
	}
	if m.Version == V0 {
		nl := r.compactU16()
		if r.err != nil {
			return nil, r.err
		}
		for range nl {
			var l AddressTableLookup
			if !r.into(l.AccountKey[:]) {
				return nil, malformed("short lookup")
			}
			l.WritableIndexes = slices.Clone(r.bytes(r.compactU16()))
			l.ReadonlyIndexes = slices.Clone(r.bytes(r.compactU16()))
			if r.err != nil {
				break
			}
			m.AddressTableLookups = append(m.AddressTableLookups, l)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(b) {
		return nil, malformed("%d trailing bytes", len(b)-r.off)
	}
	if err := m.sanitize(); err != nil {
		return nil, err
	}
	return m, nil
}

// sanitize is the runtime's Message::sanitize plus its duplicate-key check.
func (m *Message) sanitize() error {
	h := m.Header
	n := len(m.AccountKeys)
	switch {
	case h.NumRequiredSignatures == 0:
		return malformed("no signers")
	case h.NumReadonlySignedAccounts >= h.NumRequiredSignatures:
		return malformed("the fee payer must be writable")
	case int(h.NumRequiredSignatures)+int(h.NumReadonlyUnsignedAccounts) > n:
		return malformed("header claims %d+%d keys of %d", h.NumRequiredSignatures, h.NumReadonlyUnsignedAccounts, n)
	case n > 256:
		return malformed("%d keys", n)
	}
	if m.Version != Legacy && m.Version != V0 {
		return malformed("message version %d", m.Version)
	}
	if m.Version == Legacy && len(m.AddressTableLookups) > 0 {
		return malformed("a legacy message has lookups")
	}
	// Every length is written as a compact-u16; a longer one would wrap.
	for i, ix := range m.Instructions {
		if len(ix.Accounts) > 0xffff || len(ix.Data) > 0xffff {
			return malformed("instruction %d is over a compact-u16 length", i)
		}
	}
	if len(m.Instructions) > 0xffff || len(m.AddressTableLookups) > 0xffff {
		return malformed("over a compact-u16 count")
	}
	for i, l := range m.AddressTableLookups {
		if len(l.WritableIndexes)+len(l.ReadonlyIndexes) == 0 {
			return malformed("lookup %d loads nothing", i)
		}
	}
	total := n + m.lookedUp()
	if total > 256 {
		return malformed("%d keys with lookups", total)
	}
	seen := make(map[PublicKey]struct{}, n)
	for _, k := range m.AccountKeys {
		if _, dup := seen[k]; dup {
			return malformed("duplicate key %s", k)
		}
		seen[k] = struct{}{}
	}
	for i, ix := range m.Instructions {
		// Programs come only from static keys, and never the fee payer.
		if ix.ProgramIDIndex == 0 || int(ix.ProgramIDIndex) >= n {
			return malformed("instruction %d program index %d", i, ix.ProgramIDIndex)
		}
		for _, a := range ix.Accounts {
			if int(a) >= total {
				return malformed("instruction %d account index %d of %d", i, a, total)
			}
		}
	}
	return nil
}

// Compile builds a message the way the Solana SDK's compiler does, so the
// bytes match a transaction the program's tests built from the same
// instructions: the fee payer first, then writable signers, readonly signers,
// writable and readonly non-signers, each group in byte order of its keys,
// every key carrying the union of the privileges its instructions ask.
// A v0 message compiles with no lookup tables.
func Compile(payer PublicKey, blockhash Hash, ixs []Instruction, v MessageVersion) (*Message, error) {
	type priv struct{ signer, writable bool }
	privs := map[PublicKey]*priv{payer: {signer: true, writable: true}}
	note := func(k PublicKey, signer, writable bool) {
		p := privs[k]
		if p == nil {
			p = &priv{}
			privs[k] = p
		}
		p.signer = p.signer || signer
		p.writable = p.writable || writable
	}
	for _, ix := range ixs {
		note(ix.ProgramID, false, false)
		for _, a := range ix.Accounts {
			note(a.PublicKey, a.IsSigner, a.IsWritable)
		}
	}
	var groups [4][]PublicKey
	for k, p := range privs {
		if k == payer {
			continue
		}
		g := 3
		switch {
		case p.signer && p.writable:
			g = 0
		case p.signer:
			g = 1
		case p.writable:
			g = 2
		}
		groups[g] = append(groups[g], k)
	}
	keys := []PublicKey{payer}
	for i := range groups {
		slices.SortFunc(groups[i], PublicKey.Compare)
		keys = append(keys, groups[i]...)
	}
	if len(keys) > 256 {
		return nil, malformed("%d keys", len(keys))
	}
	index := make(map[PublicKey]uint8, len(keys))
	for i, k := range keys {
		index[k] = uint8(i)
	}
	m := &Message{
		Version: v,
		Header: MessageHeader{
			NumRequiredSignatures:       uint8(1 + len(groups[0]) + len(groups[1])),
			NumReadonlySignedAccounts:   uint8(len(groups[1])),
			NumReadonlyUnsignedAccounts: uint8(len(groups[3])),
		},
		AccountKeys:     keys,
		RecentBlockhash: blockhash,
	}
	for _, ix := range ixs {
		c := CompiledInstruction{ProgramIDIndex: index[ix.ProgramID], Data: slices.Clone(ix.Data)}
		for _, a := range ix.Accounts {
			c.Accounts = append(c.Accounts, index[a.PublicKey])
		}
		m.Instructions = append(m.Instructions, c)
	}
	if err := m.sanitize(); err != nil {
		return nil, err
	}
	return m, nil
}

// Transaction is a message and one signature per required signer, in signer
// order. An unsigned slot is all zeros.
type Transaction struct {
	Signatures []Signature
	Message    Message
}

// NewTransaction gives m an empty signature slot per required signer.
func NewTransaction(m *Message) *Transaction {
	return &Transaction{Signatures: make([]Signature, m.Header.NumRequiredSignatures), Message: *m}
}

// Sign signs the message with each key and puts the signature in that key's
// slot, leaving the others as they are, so signers can sign in any order.
func (t *Transaction) Sign(keys ...ed25519.PrivateKey) error {
	msg, err := t.Message.MarshalBinary()
	if err != nil {
		return err
	}
	for _, priv := range keys {
		var pub PublicKey
		copy(pub[:], priv.Public().(ed25519.PublicKey))
		i := slices.Index(t.Message.AccountKeys[:t.Message.Header.NumRequiredSignatures], pub)
		if i < 0 {
			return fmt.Errorf("solana: %s is not a signer of this message", pub)
		}
		copy(t.Signatures[i][:], ed25519.Sign(priv, msg))
	}
	return nil
}

// VerifySignatures checks every required signature over the message's bytes.
func (t *Transaction) VerifySignatures() error {
	msg, err := t.Message.MarshalBinary()
	if err != nil {
		return err
	}
	if len(t.Signatures) != int(t.Message.Header.NumRequiredSignatures) {
		return malformed("%d signatures for %d signers", len(t.Signatures), t.Message.Header.NumRequiredSignatures)
	}
	for i, sig := range t.Signatures {
		k := t.Message.AccountKeys[i]
		if !VerifyStrict(k, msg, sig) {
			return fmt.Errorf("solana: bad signature for %s", k)
		}
	}
	return nil
}

// MarshalBinary refuses a transaction over MaxTransactionSize, which no
// validator would take.
func (t *Transaction) MarshalBinary() ([]byte, error) {
	msg, err := t.Message.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(t.Signatures) != int(t.Message.Header.NumRequiredSignatures) {
		return nil, malformed("%d signatures for %d signers", len(t.Signatures), t.Message.Header.NumRequiredSignatures)
	}
	b := appendCompactU16(nil, len(t.Signatures))
	for _, s := range t.Signatures {
		b = append(b, s[:]...)
	}
	b = append(b, msg...)
	if len(b) > MaxTransactionSize {
		return nil, malformed("a transaction of %d bytes", len(b))
	}
	return b, nil
}

// ParseTransaction decodes a transaction. Its signatures are not checked:
// a verifier inspects an offer it has not signed yet. One over
// MaxTransactionSize is refused, as a validator would refuse it.
func ParseTransaction(b []byte) (*Transaction, error) {
	if len(b) > MaxTransactionSize {
		return nil, malformed("a transaction of %d bytes", len(b))
	}
	r := reader{b: b}
	n := r.compactU16()
	t := &Transaction{}
	for range n {
		var s Signature
		if !r.into(s[:]) {
			return nil, malformed("short signatures")
		}
		t.Signatures = append(t.Signatures, s)
	}
	if r.err != nil {
		return nil, r.err
	}
	m, err := ParseMessage(b[r.off:])
	if err != nil {
		return nil, err
	}
	if n != int(m.Header.NumRequiredSignatures) {
		return nil, malformed("%d signatures for %d signers", n, m.Header.NumRequiredSignatures)
	}
	t.Message = *m
	return t, nil
}

// appendCompactU16 is Solana's short_vec length: seven bits per byte, low
// first, the high bit set on every byte but the last.
func appendCompactU16(b []byte, n int) []byte {
	v := uint16(n)
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(b, c)
		}
		b = append(b, c|0x80)
	}
}

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = malformed("short read at %d", r.off)
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *reader) into(dst []byte) bool {
	src := r.bytes(len(dst))
	copy(dst, src)
	return src != nil
}

// compactU16 refuses an encoding the runtime refuses: more than three bytes,
// a value over u16, or a longer spelling of a value a shorter one holds.
func (r *reader) compactU16() int {
	v := 0
	for i := range 3 {
		c := r.bytes(1)
		if c == nil {
			return 0
		}
		v |= int(c[0]&0x7f) << (7 * i)
		if c[0]&0x80 == 0 {
			if i > 0 && c[0] == 0 {
				r.err = malformed("non-canonical length at %d", r.off-1)
				return 0
			}
			if v > 0xffff {
				r.err = malformed("length over u16 at %d", r.off-1)
				return 0
			}
			return v
		}
		if i == 2 {
			break
		}
	}
	r.err = malformed("length over three bytes at %d", r.off)
	return 0
}
