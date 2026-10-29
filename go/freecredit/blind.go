/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package freecredit

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/blindsign/blindrsa"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// Pending is a credit the payer has blinded and the issuer has yet to sign.
// It holds the unblinding factor, so it never leaves the payer.
type Pending struct {
	key    *DayKey
	client blindrsa.Client
	state  blindrsa.State
	nonce  []byte
}

// Blind starts one credit for node under a certified day key, for the key's
// day: it draws the nonce and returns the blinded message to send the issuer.
// A nil random reads crypto/rand.
func Blind(random io.Reader, key *DayKey, dep ticket.DeploymentID, node Node) ([]byte, *Pending, error) {
	if random == nil {
		random = rand.Reader
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, nil, fmt.Errorf("free credit: nonce: %w", err)
	}
	msg, err := Message(dep, node, key.Epoch(), nonce)
	if err != nil {
		return nil, nil, err
	}
	c, err := blindrsa.NewClient(variant, key.pk)
	if err != nil {
		return nil, nil, fmt.Errorf("free credit: %w", err)
	}
	prepared, err := c.Prepare(random, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("free credit: %w", err)
	}
	blinded, state, err := c.Blind(random, prepared)
	if err != nil {
		return nil, nil, fmt.Errorf("free credit: blind: %w", err)
	}
	return blinded, &Pending{key: key, client: c, state: state, nonce: nonce}, nil
}

// Finalize unblinds the issuer's signature into a Credit. It verifies the
// result first, so an issuer that signed with another key, or signed
// something else, yields an error rather than a credit every node refuses.
func (p *Pending) Finalize(blindSig []byte) (Credit, error) {
	sig, err := p.client.Finalize(p.state, blindSig)
	if err != nil {
		return Credit{}, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	return Credit{DayKeyCert: p.key.Cert(), Nonce: append(Bytes(nil), p.nonce...), Signature: sig}, nil
}
