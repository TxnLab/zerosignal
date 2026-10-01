/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// UsageReceipt is the signed post-response artifact that drives
// escrow settlement (SPEC.md § 3a "Settlement"). The node
// builds one per completed request, signs it with the operator's
// SigningAddr (the same key that signed the Ticket), and
// returns it to the proxy via the X-Zs-Receipt header (non-stream)
// or a final sealed "zs-receipt" SSE event (stream).
//
// The escrow contract's `settle` method receives a digest + sig and
// disburses AmountCharged to the operator owner address, refunding
// the remainder plus the ticket's box MBR to the payer. The proxy
// independently verifies:
//   - Sig is valid under the operator's signing pubkey
//   - AmountCharged ≤ Ticket.MaxPrice
//   - BodyHash equals sha256 of the reconstructed plaintext (non-stream
//     body bytes, or plaintext frames concatenated in index order)
//
// BodyHash is hex-encoded rather than base64 so the field is small,
// case-stable, and copy-pastable in logs / dispute material. The
// signature is base64 like Ticket.Sig for consistency with the
// existing envelope types.
type UsageReceipt struct {
	TicketID          string `json:"ticket_id"`           // base64(16 bytes) — same form as Ticket.TicketID
	ActualInputCount  uint64 `json:"actual_input_count"`  // node's authoritative count
	ActualOutputCount uint64 `json:"actual_output_count"` // node's authoritative count
	AmountCharged     uint64 `json:"amount_charged"`      // microUSDC; clamped to Ticket.MaxPrice
	// TtftMs and DecodeMs are the operator-measured timings for this
	// request, carried as two separate uint64s. TtftMs is time-to-first-
	// token; DecodeMs is the decode window, which opens at the upstream's FIRST
	// FRAME of any kind rather than at the first output frame, so that thinking
	// a provider never streamed is still covered by the window its tokens are
	// divided by (SPEC.md "Where the decode window starts"). A non-stream / no-first-token
	// request sets TtftMs = total service time and DecodeMs = 0. Derive
	// throughput with TokensPerSec(). Both are committed inside the receipt
	// digest (so the operator's signature binds them) and passed verbatim as
	// the `ttftMs` / `decodeMs` ABI args on settle(); the contract's match
	// check freezes the ticket if first-half and second-half disagree. On
	// chain TtftMs drives the per-operator latency metric and DecodeMs +
	// output tokens drive the throughput EWMA.
	TtftMs   uint64 `json:"ttft_ms"`
	DecodeMs uint64 `json:"decode_ms"`
	BodyHash string `json:"body_hash"` // hex sha256(plaintext); length always 64
	// InputUsageType / OutputUsageType (v2) discriminate the unit each
	// direction was metered in; settle() routes ActualOutputCount into
	// outputUnits[OutputUsageType] and gates the latency/throughput EWMAs on
	// OutputUsageType == Tokens. AuxOutputUsageType / AuxOutputCount carry the
	// one inline secondary modality a single response can mix (the tool path's
	// produced images alongside chat tokens) so the metrics record both without
	// a co-signed billing tuple — AmountCharged stays one microUSDC scalar.
	// All four ride the tail of CanonicalBytes (three bytes + one uint64).
	// Zero values (UsageTypeNone / 0) describe a plain token receipt.
	InputUsageType     UsageType `json:"input_usage_type"`
	OutputUsageType    UsageType `json:"output_usage_type"`
	AuxOutputUsageType UsageType `json:"aux_output_usage_type"`
	AuxOutputCount     uint64    `json:"aux_output_count"`
	// CachedInputCount (v2) is the subset of ActualInputCount that the upstream
	// served from a prefix/prompt cache (invariant: <= ActualInputCount). The
	// node bills it at the ticket's CacheReadRate instead of InputRate, so the
	// operator can pass an upstream cache discount through to the payer. 0 on
	// dedicated image routes and whenever the upstream reports no cached count.
	// Rides one uint64 at the tail of CanonicalBytes.
	CachedInputCount uint64 `json:"cached_input_count"`
	Sig              string `json:"sig"` // base64(Ed25519 over sha256(receiptSigningTag || canonical bytes))
}

// receiptSigningTag domain-separates UsageReceipt signatures from
// Ticket signatures and from any other Ed25519 the system may
// introduce. Trailing NUL matches ticketSigningTag's convention —
// keeps the tag self-terminating in concatenations.
//
// Version history mirrors ticketSigningTag: v1 covered the base receipt and,
// later, the appended UsageType discriminators + aux output slot (that append
// stayed under v1 — the bytes are themselves the break). Bumped v1 → v2
// alongside ticketSigningTag when CachedInputCount was appended for
// cached-token pricing.
const receiptSigningTag = "zs-receipt-v2\x00"

// CanonicalBytes returns the unambiguous byte sequence Ed25519 signs
// (and verifies). Identical encoding rules to Ticket.CanonicalBytes:
// length-prefixed strings, fixed-width big-endian numbers. Sig is
// excluded (that's what we're computing). Independent of any JSON
// encoder so a non-Go reimplementation can reproduce the exact bytes.
func (r *UsageReceipt) CanonicalBytes() []byte {
	b := make([]byte, 0, 128)
	b = append(b, receiptSigningTag...)
	b = appendLenStr(b, r.TicketID)
	b = appendU64(b, r.ActualInputCount)
	b = appendU64(b, r.ActualOutputCount)
	b = appendU64(b, r.AmountCharged)
	// TtftMs then DecodeMs join the canonical bytes after AmountCharged so
	// the receipt digest commits to both. The settle() ABI passes the same
	// two values as separate uint64 args; the contract's match check gates
	// them across both halves of the co-signed settlement.
	b = appendU64(b, r.TtftMs)
	b = appendU64(b, r.DecodeMs)
	b = appendLenStr(b, r.BodyHash)
	// The usage-type discriminators + aux output slot append at the tail
	// (three bytes then the aux count). They commit the metrics split into the
	// receipt digest so the operator can't inflate its own modality reputation.
	b = appendU8(b, byte(r.InputUsageType))
	b = appendU8(b, byte(r.OutputUsageType))
	b = appendU8(b, byte(r.AuxOutputUsageType))
	b = appendU64(b, r.AuxOutputCount)
	// v2: the cached-read count appends after the aux slot (the new tail).
	b = appendU64(b, r.CachedInputCount)
	return b
}

// TokensPerSec derives generation throughput (output tokens / sec) from the
// decode window. Returns 0 when there's no decode window (DecodeMs == 0),
// matching the contract's throughput-EWMA exclusion so callers can treat 0
// as "no throughput signal".
func (r *UsageReceipt) TokensPerSec() uint64 {
	if r.DecodeMs == 0 {
		return 0
	}
	return r.ActualOutputCount * 1000 / r.DecodeMs
}

// Sign populates r.Sig with an Ed25519 signature over the 32-byte
// digest ReceiptSigDigest(r) = sha256(CanonicalBytes()).
// CanonicalBytes() already prepends the receipt-specific tag
// ("zs-receipt-v2\x00") so the digest binds that tag and the
// receipt fields — cross-protocol / replay reuse can't produce a
// valid signature.
//
// Signing the digest (not the raw message) is required so the escrow
// contract's op.ed25519verifyBare(digest, sig, pub) call succeeds
// with the same signature the proxy verifies off-chain. AVM's
// ed25519verify_bare opcode accepts larger messages, but committing
// to the digest keeps on-chain cost constant as the receipt shape
// evolves.
func (r *UsageReceipt) Sign(ctx context.Context, signer BytesSigner, signingAddr string) error {
	if signer == nil {
		return errors.New("receipt sign: signer is nil")
	}
	digest := ReceiptSigDigest(r)
	sig, err := signer.SignBytes(ctx, signingAddr, digest[:])
	if err != nil {
		return fmt.Errorf("receipt sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("receipt sign: signer returned %d-byte signature, want %d", len(sig), ed25519.SignatureSize)
	}
	r.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify returns nil if r.Sig is a valid Ed25519 signature of
// ReceiptSigDigest(r) under pub. Callers typically recover pub
// from the operator's SigningAddr via DecodeAlgorandAddress.
// Verifying the same digest the contract verifies means off-chain
// Verify and on-chain ed25519verify_bare agree byte-for-byte.
func (r *UsageReceipt) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(r.Sig)
	if err != nil {
		return fmt.Errorf("decode receipt sig: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length %d", len(sig))
	}
	digest := ReceiptSigDigest(r)
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("receipt signature verification failed")
	}
	return nil
}

// ReceiptSigDigest returns sha256(CanonicalBytes(r)) — the 32-byte
// value both Sign and the escrow contract's op.ed25519verifyBare
// feed to ed25519. CanonicalBytes() already includes the
// "zs-receipt-v2\x00" domain tag so the digest is cross-protocol
// safe. Exposed so callers composing settle() or protest() groups
// pass the exact same bytes as the `receiptDigest` ABI arg.
func ReceiptSigDigest(r *UsageReceipt) [sha256.Size]byte {
	return sha256.Sum256(r.CanonicalBytes())
}

// EncodeReceiptHeader returns the base64(JSON) form the node writes
// to the X-Zs-Receipt header. The inverse of DecodeReceiptHeader.
func (r *UsageReceipt) EncodeReceiptHeader() (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode receipt header json: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// DecodeReceiptHeader parses the base64(JSON) shape the node writes to
// X-Zs-Receipt. The inverse of EncodeReceiptHeader; proxy uses this
// before Verify.
func DecodeReceiptHeader(value string) (UsageReceipt, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return UsageReceipt{}, fmt.Errorf("decode receipt header base64: %w", err)
	}
	var r UsageReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return UsageReceipt{}, fmt.Errorf("decode receipt header json: %w", err)
	}
	return r, nil
}

// SetBodyHashBytes sets BodyHash from raw sha256 output (32 bytes).
// Matches what BodyHashOfBody / BodyHashFromFrames return.
func (r *UsageReceipt) SetBodyHashBytes(sum [32]byte) {
	r.BodyHash = hex.EncodeToString(sum[:])
}

// BodyHashBytes returns the 32-byte sha256 represented by BodyHash, or
// an error when the field isn't a valid 64-char hex string.
func (r *UsageReceipt) BodyHashBytes() ([32]byte, error) {
	var out [32]byte
	if len(r.BodyHash) != 2*len(out) {
		return out, fmt.Errorf("body_hash must be %d hex chars, got %d", 2*len(out), len(r.BodyHash))
	}
	raw, err := hex.DecodeString(r.BodyHash)
	if err != nil {
		return out, fmt.Errorf("decode body_hash hex: %w", err)
	}
	copy(out[:], raw)
	return out, nil
}
