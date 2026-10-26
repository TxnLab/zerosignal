/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package freecredit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/blindsign/blindrsa"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// variant is the one RFC 9474 variant credits use. The message carries its
// own random nonce, so the randomized variant's message prefix adds nothing.
const variant = blindrsa.SHA384PSSDeterministic

// dayKeyTag domain-separates the issuer's day-key certificate.
const dayKeyTag = "zs-free-credit-day-key-v1\x00"

const (
	// DayKeyBits is the modulus size NewDaySigner makes.
	DayKeyBits = 2048
	// minKeyBits and maxKeyBits bound a day key a payer or node accepts:
	// below 2048 is breakable, and above 4096 only costs every verify.
	minKeyBits = 2048
	maxKeyBits = 4096
)

// ParseIssuerKey reads an issuer's public key, standard base64 of its 32
// Ed25519 bytes, as presets and node configs name it.
func ParseIssuerKey(s string) (ed25519.PublicKey, error) {
	b, err := decodeStrict(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("free credit issuer key %q: want standard base64 of 32 bytes", s)
	}
	return ed25519.PublicKey(b), nil
}

// MarshalIssuerPEM is an issuer's master key as a PKCS#8 "PRIVATE KEY" PEM
// block.
func MarshalIssuerPEM(master ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(master)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseIssuerPEM reads an issuer's master key from a PKCS#8 "PRIVATE KEY" PEM
// block. The key certifies day keys only; signing anything else with it
// would make that a day-key certificate too, wherever the bytes happen to
// parse as one.
func ParseIssuerPEM(data []byte) (ed25519.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("free credit issuer: want a PKCS#8 PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	sk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("free credit issuer: not an Ed25519 key")
	}
	return sk, nil
}

// DayKeyCert is an issuer's certificate for one day key, as it travels: the
// issuer's Ed25519 key, the epoch, the day key's SPKI DER, and the issuer's
// signature over DayKeyCertMessage. The issuer serves it to payers, and every
// credit carries it, so a node checks a credit with nothing but the issuer
// keys it trusts.
type DayKeyCert struct {
	Issuer  Bytes `json:"issuer"`
	Epoch   Epoch `json:"epoch"`
	DayKey  Bytes `json:"day_key"`
	CertSig Bytes `json:"day_key_sig"`
}

// UnmarshalJSON reads the fields by their exact names, as Credit's does.
func (c *DayKeyCert) UnmarshalJSON(data []byte) error {
	var v DayKeyCert
	if err := decodeFields(data, v.fields()); err != nil {
		return err
	}
	*c = v
	return nil
}

func (c *DayKeyCert) fields() map[string]any {
	return map[string]any{"issuer": &c.Issuer, "epoch": &c.Epoch, "day_key": &c.DayKey, "day_key_sig": &c.CertSig}
}

// DayKeyCertMessage is what the issuer signs to certify a day key:
//
//	"zs-free-credit-day-key-v1\x00" ‖ deployment_id[32] ‖ u32be(epoch) ‖ sha256(day_key_spki)
//
// Binding the deployment keeps a day key an issuer made for one deployment
// from passing at another that trusts the same issuer.
func DayKeyCertMessage(dep ticket.DeploymentID, epoch Epoch, spki []byte) []byte {
	h := sha256.Sum256(spki)
	m := make([]byte, 0, len(dayKeyTag)+len(dep)+4+len(h))
	m = append(m, dayKeyTag...)
	m = append(m, dep[:]...)
	m = binary.BigEndian.AppendUint32(m, uint32(epoch))
	return append(m, h[:]...)
}

// DayKey is a certified day key: what a payer blinds a credit to and a node
// verifies one with.
type DayKey struct {
	cert     DayKeyCert
	pk       *rsa.PublicKey
	verifier blindrsa.Verifier
}

// Cert is the key's certificate, as it travels.
func (k *DayKey) Cert() DayKeyCert { return k.cert }

// Epoch is the day the key is for.
func (k *DayKey) Epoch() Epoch { return k.cert.Epoch }

func (k *DayKey) size() int { return (k.pk.N.BitLen() + 7) / 8 }

// VerifyDayKey accepts cert if one of trusted issued it for dep, and its key
// meets the policy. It does not check the epoch against the clock: a payer
// compares it with the day it asked for, and Verify with the epochs it
// accepts.
func VerifyDayKey(trusted []ed25519.PublicKey, dep ticket.DeploymentID, cert DayKeyCert) (*DayKey, error) {
	if len(cert.Issuer) != ed25519.PublicKeySize || len(cert.CertSig) != ed25519.SignatureSize || len(cert.DayKey) == 0 {
		return nil, ErrMalformed
	}
	var issuer ed25519.PublicKey
	for _, k := range trusted {
		if bytes.Equal(k, cert.Issuer) {
			issuer = k
		}
	}
	if issuer == nil {
		return nil, ErrUnknownIssuer
	}
	if !ed25519.Verify(issuer, DayKeyCertMessage(dep, cert.Epoch, cert.DayKey), cert.CertSig) {
		return nil, ErrBadDayKey
	}
	pk, err := ParseDayKeySPKI(cert.DayKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadDayKey, err)
	}
	v, err := blindrsa.NewVerifier(variant, pk)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadDayKey, err)
	}
	return &DayKey{cert: cert, pk: pk, verifier: v}, nil
}

// ParseDayKeySPKI reads a day key from its SPKI DER. It refuses anything but
// an RSA key of 2048 to 4096 bits with exponent 65537, in the canonical
// encoding, so one key has one spelling.
func ParseDayKeySPKI(spki []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	if bits := pk.N.BitLen(); bits < minKeyBits || bits > maxKeyBits {
		return nil, fmt.Errorf("%d-bit modulus, want %d to %d", bits, minKeyBits, maxKeyBits)
	}
	if pk.E != 65537 {
		return nil, fmt.Errorf("exponent %d, want 65537", pk.E)
	}
	canonical, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, spki) {
		return nil, errors.New("not the canonical SPKI encoding")
	}
	return pk, nil
}

// DaySigner is an issuer's private day key and its certificate. Its key does
// RSA on whatever it is handed, so it must sign nothing but blinded credits.
type DaySigner struct {
	sk  *rsa.PrivateKey
	key *DayKey
}

// NewDaySigner makes a day key for dep and epoch and certifies it with the
// issuer's master key. A nil random reads crypto/rand.
func NewDaySigner(random io.Reader, master ed25519.PrivateKey, dep ticket.DeploymentID, epoch Epoch) (*DaySigner, error) {
	if random == nil {
		random = rand.Reader
	}
	sk, err := rsa.GenerateKey(random, DayKeyBits)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		return nil, err
	}
	cert := DayKeyCert{
		Issuer:  Bytes(master.Public().(ed25519.PublicKey)),
		Epoch:   epoch,
		DayKey:  spki,
		CertSig: ed25519.Sign(master, DayKeyCertMessage(dep, epoch, spki)),
	}
	return RestoreDaySigner(sk, master.Public().(ed25519.PublicKey), dep, cert)
}

// RestoreDaySigner rebuilds a day signer an issuer kept, checking that sk is
// the certified key's private half.
func RestoreDaySigner(sk *rsa.PrivateKey, issuer ed25519.PublicKey, dep ticket.DeploymentID, cert DayKeyCert) (*DaySigner, error) {
	key, err := VerifyDayKey([]ed25519.PublicKey{issuer}, dep, cert)
	if err != nil {
		return nil, err
	}
	if !key.pk.Equal(&sk.PublicKey) {
		return nil, errors.New("free credit: the private key is not the certified day key's")
	}
	return &DaySigner{sk: sk, key: key}, nil
}

// Key is the signer's certified public day key.
func (s *DaySigner) Key() *DayKey { return s.key }

// MarshalPEM is the private day key as a PKCS#8 "PRIVATE KEY" PEM block.
func (s *DaySigner) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s.sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseDayKeyPEM reads a private day key from a PKCS#8 "PRIVATE KEY" PEM
// block, for RestoreDaySigner.
func ParseDayKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("free credit: want a PKCS#8 PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	sk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("free credit: not an RSA key")
	}
	return sk, nil
}

// Sign is the issuer's half: the RSA operation on one blinded message. It
// learns nothing of the message underneath, so whatever gate decides who may
// have credits must run before it.
//
// circl does the RSA in math/big with base blinding, not in constant time, so
// an issuer that signs for strangers over the network should weigh a signer
// that is (node:crypto, or a hardware key) against this one.
func (s *DaySigner) Sign(blinded []byte) ([]byte, error) {
	return blindrsa.NewSigner(s.sk).BlindSign(blinded)
}
