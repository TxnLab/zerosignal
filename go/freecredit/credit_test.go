/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package freecredit_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/freecredit"
	"github.com/TxnLab/zerosignal/go/ticket"
)

var (
	testDep  = ticket.DeploymentID{1, 2, 3}
	testNode = freecredit.Node{Operator: 7, Node: 3}
)

const testEpoch = freecredit.Epoch(20_000)

type fixture struct {
	master, other ed25519.PrivateKey
	signer        *freecredit.DaySigner
}

var (
	fixtureOnce sync.Once
	fix         fixture
	fixErr      error
)

// testFixture makes the issuers and one day key once: RSA generation is the
// slow part of every test here.
func testFixture(t *testing.T) fixture {
	t.Helper()
	fixtureOnce.Do(func() {
		_, fix.master, _ = ed25519.GenerateKey(rand.Reader)
		_, fix.other, _ = ed25519.GenerateKey(rand.Reader)
		fix.signer, fixErr = freecredit.NewDaySigner(nil, fix.master, testDep, testEpoch)
	})
	if fixErr != nil {
		t.Fatal(fixErr)
	}
	return fix
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func issue(t *testing.T, s *freecredit.DaySigner, node freecredit.Node) freecredit.Credit {
	t.Helper()
	blinded, p, err := freecredit.Blind(nil, s.Key(), testDep, node)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(blinded)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Finalize(sig)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCredit_RoundTrip(t *testing.T) {
	f := testFixture(t)
	c := issue(t, f.signer, testNode)
	if err := freecredit.Verify([]ed25519.PublicKey{pub(f.master)}, testDep, testNode, []freecredit.Epoch{testEpoch}, c); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Epoch != testEpoch || string(c.Issuer) != string(pub(f.master)) {
		t.Error("the credit does not carry its day key's certificate")
	}
}

func TestVerify_Refusals(t *testing.T) {
	f := testFixture(t)
	c := issue(t, f.signer, testNode)
	trusted := []ed25519.PublicKey{pub(f.master)}
	epochs := []freecredit.Epoch{testEpoch}
	mod := func(fn func(*freecredit.Credit)) freecredit.Credit {
		m := c
		m.Issuer = slices.Clone(c.Issuer)
		m.DayKey = slices.Clone(c.DayKey)
		m.CertSig = slices.Clone(c.CertSig)
		m.Nonce = slices.Clone(c.Nonce)
		m.Signature = slices.Clone(c.Signature)
		fn(&m)
		return m
	}
	otherDay, err := freecredit.NewDaySigner(nil, f.master, testDep, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		trusted []ed25519.PublicKey
		dep     ticket.DeploymentID
		node    freecredit.Node
		epochs  []freecredit.Epoch
		c       freecredit.Credit
		want    error
	}{
		{"another node of the operator", trusted, testDep, freecredit.Node{Operator: 7, Node: 4}, epochs, c, freecredit.ErrBadSignature},
		{"another operator", trusted, testDep, freecredit.Node{Operator: 8, Node: 3}, epochs, c, freecredit.ErrBadSignature},
		{"another deployment", trusted, ticket.DeploymentID{9}, testNode, epochs, c, freecredit.ErrBadDayKey},
		{"another day", trusted, testDep, testNode, []freecredit.Epoch{testEpoch + 1}, c, freecredit.ErrWrongEpoch},
		{"the epoch field rewritten", trusted, testDep, testNode, []freecredit.Epoch{testEpoch + 1},
			mod(func(m *freecredit.Credit) { m.Epoch = testEpoch + 1 }), freecredit.ErrBadDayKey},
		{"an untrusted issuer", []ed25519.PublicKey{pub(f.other)}, testDep, testNode, epochs, c, freecredit.ErrUnknownIssuer},
		{"no trusted issuer", nil, testDep, testNode, epochs, c, freecredit.ErrUnknownIssuer},
		{"another trusted issuer named", []ed25519.PublicKey{pub(f.master), pub(f.other)}, testDep, testNode, epochs,
			mod(func(m *freecredit.Credit) { m.Issuer = freecredit.Bytes(pub(f.other)) }), freecredit.ErrBadDayKey},
		{"another of the issuer's day keys, uncertified", trusted, testDep, testNode, epochs,
			mod(func(m *freecredit.Credit) { m.DayKey = otherDay.Key().Cert().DayKey }), freecredit.ErrBadDayKey},
		{"a signature by another day key", trusted, testDep, testNode, epochs,
			mod(func(m *freecredit.Credit) {
				o := issue(t, otherDay, testNode)
				m.Nonce, m.Signature = o.Nonce, o.Signature
			}), freecredit.ErrBadSignature},
		{"a flipped signature bit", trusted, testDep, testNode, epochs, mod(func(m *freecredit.Credit) { m.Signature[10] ^= 1 }), freecredit.ErrBadSignature},
		{"a short signature", trusted, testDep, testNode, epochs, mod(func(m *freecredit.Credit) { m.Signature = m.Signature[1:] }), freecredit.ErrBadSignature},
		{"a short nonce", trusted, testDep, testNode, epochs, mod(func(m *freecredit.Credit) { m.Nonce = m.Nonce[:31] }), freecredit.ErrMalformed},
		{"a short issuer", trusted, testDep, testNode, epochs, mod(func(m *freecredit.Credit) { m.Issuer = m.Issuer[:31] }), freecredit.ErrMalformed},
		{"no signature", trusted, testDep, testNode, epochs, mod(func(m *freecredit.Credit) { m.Signature = nil }), freecredit.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := freecredit.Verify(tc.trusted, tc.dep, tc.node, tc.epochs, tc.c)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
			if freecredit.Reason(err) == "" {
				t.Errorf("Reason(%v) is empty", err)
			}
		})
	}
}

// An issuer answering with a signature by another key, or over another
// message, must fail at the payer, not at every node it is spent at.
func TestFinalize_RefusesAWrongSignature(t *testing.T) {
	f := testFixture(t)
	other, err := freecredit.NewDaySigner(nil, f.master, testDep, testEpoch)
	if err != nil {
		t.Fatal(err)
	}
	// The other key refuses a blinded message at or above its own modulus, so
	// draw until it has one below.
	var p *freecredit.Pending
	var sig []byte
	for range 64 {
		var blinded []byte
		if blinded, p, err = freecredit.Blind(nil, f.signer.Key(), testDep, testNode); err != nil {
			t.Fatal(err)
		}
		if sig, err = other.Sign(blinded); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Finalize(sig); !errors.Is(err, freecredit.ErrBadSignature) {
		t.Fatalf("Finalize over another key's signature = %v, want ErrBadSignature", err)
	}
	blinded2, _, err := freecredit.Blind(nil, f.signer.Key(), testDep, testNode)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := f.signer.Sign(blinded2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Finalize(sig2); !errors.Is(err, freecredit.ErrBadSignature) {
		t.Fatalf("Finalize over another message's signature = %v, want ErrBadSignature", err)
	}
}

// Two credits for one node and day must differ, or the spent set would refuse
// the second.
func TestBlind_DrawsAFreshNonce(t *testing.T) {
	f := testFixture(t)
	a, b := issue(t, f.signer, testNode), issue(t, f.signer, testNode)
	if string(a.Nonce) == string(b.Nonce) || a.SpentKey() == b.SpentKey() {
		t.Fatal("two credits share a nonce")
	}
}

// The spent set must not be keyed by anything a payer can respell.
func TestSpentKey_IgnoresTheSignature(t *testing.T) {
	f := testFixture(t)
	a := issue(t, f.signer, testNode)
	b := a
	b.Signature = append(freecredit.Bytes{0}, a.Signature...)
	if a.SpentKey() != b.SpentKey() {
		t.Fatal("SpentKey depends on the signature bytes")
	}
	c := a
	c.Epoch++
	if a.SpentKey() == c.SpentKey() {
		t.Fatal("SpentKey ignores the epoch")
	}
	// A second trusted issuer certifying the same day key must not make the
	// credit spendable once under each.
	d := a
	d.Issuer = freecredit.Bytes(pub(f.other))
	if a.SpentKey() != d.SpentKey() {
		t.Fatal("SpentKey depends on the issuer named, not the day key")
	}
	e := a
	e.DayKey = append(freecredit.Bytes{0}, a.DayKey...)
	if a.SpentKey() == e.SpentKey() {
		t.Fatal("SpentKey ignores the day key")
	}
}

// Presets and node configs spell an issuer key one way; JSON escapes are not
// another spelling of it.
func TestParseIssuerKey_TakesOnlyPlainBase64(t *testing.T) {
	f := testFixture(t)
	key := b64(pub(f.master))
	if got, err := freecredit.ParseIssuerKey(key); err != nil || !bytes.Equal(got, pub(f.master)) {
		t.Fatalf("ParseIssuerKey(%q) = %x, %v", key, got, err)
	}
	long := b64(append(slices.Clone(pub(f.master)), 0))
	for _, bad := range []string{`\u00` + fmt.Sprintf("%x", key[0]) + key[1:], key[:20] + "\n" + key[20:], key[:len(key)-1], "", long} {
		if _, err := freecredit.ParseIssuerKey(bad); err == nil {
			t.Errorf("ParseIssuerKey(%q) accepted", bad)
		}
	}
}

func TestParseCredit_RefusesLaxBase64(t *testing.T) {
	f := testFixture(t)
	raw := []byte(`{"issuer":"` + b64(pub(f.master)) + `","epoch":1,"day_key":"AA==","day_key_sig":"AA==","nonce":"AB==","signature":"AA=="}`)
	if _, err := freecredit.ParseCredit(raw); !errors.Is(err, freecredit.ErrMalformed) {
		t.Errorf("non-zero padding bits: ParseCredit = %v, want ErrMalformed", err)
	}
	raw = []byte(`{"issuer":"AA==","epoch":1,"day_key":"AA==","day_key_sig":"AA==","nonce":"A\nA==","signature":"AA=="}`)
	if _, err := freecredit.ParseCredit(raw); !errors.Is(err, freecredit.ErrMalformed) {
		t.Errorf("a line break: ParseCredit = %v, want ErrMalformed", err)
	}
	if _, err := freecredit.ParseCredit([]byte(`{"epoch":-1}`)); !errors.Is(err, freecredit.ErrMalformed) {
		t.Errorf("a negative epoch: ParseCredit = %v, want ErrMalformed", err)
	}
}

func TestParseDayKeySPKI_Policy(t *testing.T) {
	f := testFixture(t)
	good := f.signer.Key().Cert().DayKey
	if _, err := freecredit.ParseDayKeySPKI(good); err != nil {
		t.Fatal(err)
	}
	pk, err := x509.ParsePKIXPublicKey(good)
	if err != nil {
		t.Fatal(err)
	}
	e3, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: pk.(*rsa.PublicKey).N, E: 3})
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallDER, err := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, spki := range map[string][]byte{
		"exponent 3":    e3,
		"1024 bits":     smallDER,
		"trailing byte": append(slices.Clone(good), 0),
		"garbage":       []byte("not der"),
	} {
		if _, err := freecredit.ParseDayKeySPKI(spki); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRestoreDaySigner_RefusesAnotherPrivateKey(t *testing.T) {
	f := testFixture(t)
	pemBytes, err := f.signer.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := freecredit.ParseDayKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freecredit.RestoreDaySigner(sk, pub(f.master), testDep, f.signer.Key().Cert()); err != nil {
		t.Fatalf("restoring the signer's own key: %v", err)
	}
	stranger, err := rsa.GenerateKey(rand.Reader, freecredit.DayKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freecredit.RestoreDaySigner(stranger, pub(f.master), testDep, f.signer.Key().Cert()); err == nil {
		t.Error("restored a certificate over a private key that isn't its own")
	}
}

func TestIssuerKey_PEMRoundTrip(t *testing.T) {
	f := testFixture(t)
	pemBytes, err := freecredit.MarshalIssuerPEM(f.master)
	if err != nil {
		t.Fatal(err)
	}
	back, err := freecredit.ParseIssuerPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(f.master) {
		t.Error("the PEM reads back as another key")
	}
	if k, err := freecredit.ParseIssuerKey(b64(pub(f.master))); err != nil || !k.Equal(pub(f.master)) {
		t.Errorf("ParseIssuerKey = %v, %v", k, err)
	}
	for _, s := range []string{"", "AA==", b64(pub(f.master))[:43] + "\n"} {
		if _, err := freecredit.ParseIssuerKey(s); err == nil {
			t.Errorf("ParseIssuerKey(%q) accepted", s)
		}
	}
}

func TestEpochAt(t *testing.T) {
	for _, tc := range []struct {
		at   time.Time
		want freecredit.Epoch
	}{
		{time.Unix(0, 0), 0},
		{time.Unix(-1, 0), 0},
		{time.Unix(86399, 0), 0},
		{time.Unix(86400, 0), 1},
		{time.Date(2026, 10, 26, 23, 59, 59, 999_999_999, time.UTC), 20_752},
		{time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC), 20_753},
	} {
		if got := freecredit.EpochAt(tc.at); got != tc.want {
			t.Errorf("EpochAt(%v) = %d, want %d", tc.at, got, tc.want)
		}
	}
	if s := freecredit.Epoch(20_753).Start(); !s.Equal(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Start = %v", s)
	}
}
