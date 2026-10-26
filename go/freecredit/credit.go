/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package freecredit is the free credit a payer spends on a free Solana turn:
// an RSA blind signature (RFC 9474, RSABSSA-SHA384-PSS-Deterministic) by an
// issuer's day key, over a message naming one deployment, one node and one
// UTC day. The issuer signs without seeing the message, so it cannot tell
// where a credit is spent; the node it names verifies it and keeps the spent
// set.
//
// An issuer is named by a long-lived Ed25519 key, which nodes trust. It makes
// a fresh RSA key for each day and signs a certificate binding it to that day
// and deployment, so the day a credit is good for is the issuer's choice, not
// the payer's: it certifies and signs only around today, and a payer cannot
// mint today a credit for a later day.
//
// Issuers are optional. An operator chooses which issuers its node trusts,
// any party can run one, and a node serves a payer without a credit on its
// own budget. See SPEC.md "Free credits".
//
// proto/ts/src/freecredit is its TypeScript mirror, pinned to this one by
// testdata/free_credit_vectors.json — change both and regenerate the vectors.
package freecredit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// messageTag domain-separates a credit message from every other signed layout.
const messageTag = "zs-free-credit-v1\x00"

const (
	// NonceSize is the payer's random nonce, which makes each credit distinct
	// and so spendable once.
	NonceSize = 32
	// MessageSize is the length of Message's output.
	MessageSize = len(messageTag) + len(ticket.DeploymentID{}) + 8 + 8 + 4 + NonceSize
	// EpochSeconds is one epoch: a credit is good for one UTC day.
	EpochSeconds = 86400
	// Grace is how near midnight the neighbouring day is accepted too, so a
	// payer whose clock is a little off from the issuer's or the node's is not
	// refused, and a credit minted just before midnight is still spendable
	// just after.
	Grace = 10 * time.Minute
)

// Epoch is a UTC day, counted from the Unix epoch.
type Epoch uint32

// UnmarshalJSON takes any JSON number with an integral value in range, as
// the TS twin reads one after JSON.parse: encoding/json would refuse 20752.0
// and 2.0752e4, which are 20752 there, and the two would disagree on a
// credit.
func (e *Epoch) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	if len(data) == 0 || (data[0] != '-' && (data[0] < '0' || data[0] > '9')) {
		return fmt.Errorf("%w: epoch is not a number", ErrMalformed)
	}
	f, err := strconv.ParseFloat(string(data), 64)
	if err != nil || f != math.Trunc(f) || f < 0 || f > math.MaxUint32 {
		return fmt.Errorf("%w: epoch %s is not a u32", ErrMalformed, data)
	}
	*e = Epoch(f)
	return nil
}

// EpochAt is the epoch t falls in. A time before 1970 is epoch 0.
func EpochAt(t time.Time) Epoch {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return Epoch(s / EpochSeconds)
}

// Start is the first instant of e.
func (e Epoch) Start() time.Time { return time.Unix(int64(e)*EpochSeconds, 0).UTC() }

// AcceptedEpochs are the epochs an issuer certifies and signs for, and a node
// accepts credits for, at now: the current day, and within Grace of midnight
// the day on the other side of it. A payer mints for EpochAt(now).
func AcceptedEpochs(now time.Time) []Epoch {
	e := EpochAt(now)
	out := []Epoch{e}
	if now.Sub(e.Start()) < Grace && e > 0 {
		out = append(out, e-1)
	}
	if (e+1).Start().Sub(now) <= Grace && e < ^Epoch(0) {
		out = append(out, e+1)
	}
	return out
}

// Node is the node a credit is spendable at, by its routing pair, so a credit
// for one node of an operator is worthless at another.
type Node struct {
	Operator uint64
	Node     uint64
}

// Message is the bytes the issuer blindly signs:
//
//	"zs-free-credit-v1\x00" ‖ deployment_id[32] ‖ u64be(operator_id) ‖ u64be(node_id) ‖ u32be(epoch) ‖ nonce[32]
//
// The deployment and the node do not travel with a credit. The verifying node
// supplies its own, which is what binds a credit to it.
func Message(dep ticket.DeploymentID, node Node, epoch Epoch, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrMalformed
	}
	m := make([]byte, 0, MessageSize)
	m = append(m, messageTag...)
	m = append(m, dep[:]...)
	m = binary.BigEndian.AppendUint64(m, node.Operator)
	m = binary.BigEndian.AppendUint64(m, node.Node)
	m = binary.BigEndian.AppendUint32(m, uint32(epoch))
	m = append(m, nonce...)
	return m, nil
}

// Bytes is a byte field on the wire: standard base64, padded. It decodes
// strictly and refuses line breaks, so each value has one spelling; a lax
// decoder would give a node's spent set several keys for one credit.
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	v, err := decodeStrict(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// decodeStrict is standard padded base64 with one spelling per value. The
// Strict decoder refuses set unused bits but still skips line breaks.
func decodeStrict(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%w: a line break in base64", ErrMalformed)
	}
	v, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return v, nil
}

// Credit is a spendable credit as it travels, inside the payer's sealed
// reserve request: the issuer's certified day key, then the payer's nonce and
// the day key's signature.
type Credit struct {
	DayKeyCert
	Nonce     Bytes `json:"nonce"`
	Signature Bytes `json:"signature"`
}

// SpentKey is what a node's spent set records a credit under, for a credit
// Verify accepted, whose nonce is then NonceSize bytes:
//
//	sha256(day_key_spki) ‖ u32be(epoch) ‖ nonce
//
// It is never the wire bytes or the signature, either of which a payer could
// respell to spend one credit twice (PSS signatures are salted, so one
// message has many). It names the day key rather than the issuer, because a
// credit verifies under any trusted issuer that certified its day key, and two
// that did would otherwise give it two keys.
func (c Credit) SpentKey() string {
	h := sha256.Sum256(c.DayKey)
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], uint32(c.Epoch))
	return string(h[:]) + string(e[:]) + string(c.Nonce)
}

// The refusals Verify returns. Reason names each for the wire and the vectors.
var (
	ErrMalformed     = errors.New("free credit: malformed")
	ErrUnknownIssuer = errors.New("free credit: not from a trusted issuer")
	ErrWrongEpoch    = errors.New("free credit: not for an accepted epoch")
	ErrBadDayKey     = errors.New("free credit: the day key is not the issuer's for this day")
	ErrBadSignature  = errors.New("free credit: signature does not verify")
)

// Reason is the slug for one of Verify's refusals, and "" for any other error.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrMalformed):
		return "malformed"
	case errors.Is(err, ErrUnknownIssuer):
		return "unknown_issuer"
	case errors.Is(err, ErrWrongEpoch):
		return "wrong_epoch"
	case errors.Is(err, ErrBadDayKey):
		return "bad_day_key"
	case errors.Is(err, ErrBadSignature):
		return "bad_signature"
	}
	return ""
}

// UnmarshalJSON reads the fields by their exact names; see decodeFields.
func (c *Credit) UnmarshalJSON(data []byte) error {
	var v Credit
	f := v.DayKeyCert.fields()
	f["nonce"], f["signature"] = &v.Nonce, &v.Signature
	if err := decodeFields(data, f); err != nil {
		return err
	}
	*c = v
	return nil
}

// decodeFields reads a JSON object's fields by their exact names, the last of
// a repeated name winning, as JSON.parse does in the TS twin. encoding/json
// matches names case-insensitively, so it would read "NONCE" as the nonce,
// or take a trailing "Nonce" over it, and Go and TS would read one credit two
// ways. An absent field keeps its zero value.
func decodeFields(data []byte, fields map[string]any) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if obj == nil {
		return fmt.Errorf("%w: not an object", ErrMalformed)
	}
	for name, dst := range fields {
		raw, ok := obj[name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			if errors.Is(err, ErrMalformed) {
				return err
			}
			return fmt.Errorf("%w: %s: %w", ErrMalformed, name, err)
		}
	}
	return nil
}

// ParseCredit reads a credit's JSON, refusing every malformed spelling as
// ErrMalformed.
func ParseCredit(raw []byte) (Credit, error) {
	var c Credit
	if err := json.Unmarshal(raw, &c); err != nil {
		if errors.Is(err, ErrMalformed) {
			return Credit{}, err
		}
		return Credit{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return c, nil
}

// Verify accepts c if a trusted issuer certified its day key for this
// deployment and one of epochs, and that key signed it for this node. A credit
// meant for another node, operator or deployment verifies as ErrBadSignature,
// or ErrBadDayKey for another deployment: the message the node rebuilds
// differs from the one that was signed.
//
// Verify says nothing about whether c was spent; the caller keeps that set,
// keyed by SpentKey.
func Verify(trusted []ed25519.PublicKey, dep ticket.DeploymentID, node Node, epochs []Epoch, c Credit) error {
	if len(c.Issuer) != ed25519.PublicKeySize || len(c.CertSig) != ed25519.SignatureSize ||
		len(c.DayKey) == 0 || len(c.Nonce) != NonceSize || len(c.Signature) == 0 {
		return ErrMalformed
	}
	if !slices.ContainsFunc(trusted, func(k ed25519.PublicKey) bool { return bytes.Equal(k, c.Issuer) }) {
		return ErrUnknownIssuer
	}
	if !slices.Contains(epochs, c.Epoch) {
		return ErrWrongEpoch
	}
	key, err := VerifyDayKey(trusted, dep, c.DayKeyCert)
	if err != nil {
		return err
	}
	return key.verify(dep, node, c)
}

func (k *DayKey) verify(dep ticket.DeploymentID, node Node, c Credit) error {
	msg, err := Message(dep, node, c.Epoch, c.Nonce)
	if err != nil {
		return err
	}
	// circl checks only the length, so s+N would verify too: one credit, two
	// signatures. crypto/rsa and WebCrypto both refuse s >= N.
	if len(c.Signature) != k.size() || new(big.Int).SetBytes(c.Signature).Cmp(k.pk.N) >= 0 {
		return ErrBadSignature
	}
	if err := k.verifier.Verify(msg, c.Signature); err != nil {
		return ErrBadSignature
	}
	return nil
}
