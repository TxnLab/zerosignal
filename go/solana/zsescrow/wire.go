/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The Solana values of the rail-neutral wire fields (SPEC.md § 3a, § 4), as
// the payer writes them and the node reads them:
//
//   - presigned_open_txn: the node's open offer, a wire transaction with the
//     node's signature and the payer's slot empty, in base64.
//   - payment_open: the offer with the payer's signature in its slot, in
//     base64; payment_ref: its first signature, the node's, in base58, which
//     is the transaction's id.
//   - the settle-group slot (X-Zs-Settle-Group, zs-settle-group): the open's
//     open_seq in decimal, which the payer's ack digest binds.
//   - payment_settle: the payer's Ed25519 signature over ReceiptAckDigest, in
//     base64.
//
// Every reader takes one spelling of each value, the one its writer produces,
// so two parties can never read one value two ways.

// DecodeOpenOffer reads presigned_open_txn. The transaction is not parsed:
// CompleteOpenOffer parses and verifies it.
func DecodeOpenOffer(presigned string) ([]byte, error) {
	b, err := decodeCanonicalBase64(presigned)
	if err != nil {
		return nil, fmt.Errorf("zsescrow: presigned_open_txn: %w", err)
	}
	return b, nil
}

// EncodeOpenPayment writes payment_open and payment_ref for a completed open,
// CompleteOpenOffer's result. It refuses one whose signatures don't all
// verify, as the node's reading would: CompleteOpenOffer checks the message,
// not the node's signature on it.
func EncodeOpenPayment(completed []byte) (paymentOpen, paymentRef string, err error) {
	tx, err := solana.ParseTransaction(completed)
	if err != nil {
		return "", "", fmt.Errorf("zsescrow: payment_open: %w", err)
	}
	if len(tx.Signatures) == 0 {
		return "", "", errors.New("zsescrow: payment_open: a transaction with no signer")
	}
	if err := tx.VerifySignatures(); err != nil {
		return "", "", fmt.Errorf("zsescrow: payment_open: %w", err)
	}
	return base64.StdEncoding.EncodeToString(completed), tx.Signatures[0].String(), nil
}

// DecodeOpenPayment reads payment_open and payment_ref: a transaction whose
// every signature verifies, and whose first is payment_ref. It checks nothing
// else; what the transaction does is the node's check.
func DecodeOpenPayment(paymentOpen, paymentRef string) (*solana.Transaction, error) {
	b, err := decodeCanonicalBase64(paymentOpen)
	if err != nil {
		return nil, fmt.Errorf("zsescrow: payment_open: %w", err)
	}
	tx, err := solana.ParseTransaction(b)
	if err != nil {
		return nil, fmt.Errorf("zsescrow: payment_open: %w", err)
	}
	if len(tx.Signatures) == 0 {
		return nil, errors.New("zsescrow: payment_open: a transaction with no signer")
	}
	if got := tx.Signatures[0].String(); got != paymentRef {
		return nil, fmt.Errorf("zsescrow: payment_ref %q is not payment_open's first signature %s", paymentRef, got)
	}
	if err := tx.VerifySignatures(); err != nil {
		return nil, fmt.Errorf("zsescrow: payment_open: %w", err)
	}
	return tx, nil
}

// FormatOpenSeq writes an open_seq for the settle-group slot.
func FormatOpenSeq(openSeq uint64) string { return strconv.FormatUint(openSeq, 10) }

// ParseOpenSeq reads the settle-group slot: an unsigned decimal with no
// leading zero, at most 2^64−1.
func ParseOpenSeq(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, fmt.Errorf("zsescrow: open_seq %q is not a decimal u64", s)
	}
	return v, nil
}

// SignReceiptAck writes the payer's payment_settle for a receipt: signer's
// signature, as payer, over ReceiptAckDigest. A signature that does not verify
// under payer is refused here rather than handed to the node, whose settle
// would fail on chain at its own expense.
func SignReceiptAck(ctx context.Context, signer ticket.BytesSigner, payer solana.PublicKey, d Deployment, genesis solana.Hash, operatorID, nodeID uint64, ticketID [16]byte, openSeq uint64, r *ticket.UsageReceipt) (string, error) {
	digest, err := ReceiptAckDigest(d, genesis, operatorID, nodeID, ticketID, openSeq, r)
	if err != nil {
		return "", err
	}
	sig, err := signer.SignBytes(ctx, payer.String(), digest[:])
	if err != nil {
		return "", fmt.Errorf("zsescrow: sign ack: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || !solana.VerifyStrict(payer, digest[:], solana.Signature(sig)) {
		return "", fmt.Errorf("zsescrow: sign ack: the signer's signature does not verify as %s", payer)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// DecodeAckSignature reads payment_settle: 64 bytes. Whether it verifies is
// the node's check, against the digest of the claim it settles.
func DecodeAckSignature(paymentSettle string) (solana.Signature, error) {
	b, err := decodeCanonicalBase64(paymentSettle)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("zsescrow: payment_settle: %w", err)
	}
	if len(b) != len(solana.Signature{}) {
		return solana.Signature{}, fmt.Errorf("zsescrow: payment_settle: %d bytes, want 64", len(b))
	}
	return solana.Signature(b), nil
}

// decodeCanonicalBase64 reads standard padded base64 in the one spelling
// EncodeToString writes: Go's decoder skips CR and LF and ignores the last
// character's unused bits, and the TS twin's would read those differently.
func decodeCanonicalBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("not canonical standard base64")
	}
	if len(b) == 0 {
		return nil, errors.New("empty")
	}
	return b, nil
}
