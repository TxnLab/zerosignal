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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/TxnLab/zerosignal/go/wire"
)

// Ticket is a signed admission credential issued by a node's reserve
// endpoint. It commits the operator to a price ceiling, a pre-chosen
// response symmetric key (via CommitK), and an expiry after which the
// ticket must be consumed. See SPEC.md § 3a.
//
// Integer fields are microUSDC (price/rates) or unix seconds (ExpiresAt).
// USDC has 6 decimals and is dollar-pegged, so 1 USDC = 1,000,000 microUSDC
// and rates convert from operator USD/1M config by a straight 1e6 scale at
// reserve time (no oracle in the pricing path). The contract escrows USDC,
// not ALGO — see SPEC.md §3.3a — so these amounts are what the
// `usdcPayment` AssetTransfer in the open group transfers.
//
// The TicketID and CommitK binary values are transported as their base64
// forms in JSON but signed in a separate canonical encoding — see
// CanonicalBytes — so the signature is independent of JSON formatting.
type Ticket struct {
	TicketID       string `json:"ticket_id"`        // base64(16 bytes) — opaque to the proxy; node maps to K_response
	OperatorID     uint64 `json:"operator_id"`      // sequential operator id assigned by ZeroSignalEscrow.createOperator; the contract resolves the owner (payout) address from the operator box
	NodeID         uint64 `json:"node_id"`          // node id within OperatorID that issued this ticket; the contract's open() snapshots (operatorId, nodeId) and resolves the node's signing key. Verifiers check Sig against that node's signing address.
	InputCount     uint64 `json:"input_count"`      // exact count the proxy committed to at reserve time
	MaxOutputCount uint64 `json:"max_output_count"` // ceiling; actual drives settlement refund
	InputRate      uint64 `json:"input_rate"`       // microUSDC per 1,000,000 input tokens (operator-derived from USD/1M at reserve time)
	OutputRate     uint64 `json:"output_rate"`      // microUSDC per 1,000,000 output tokens (same derivation)
	MaxPrice       uint64 `json:"max_price"`        // microUSDC; computed by the issuing node per SPEC.md §3a — the exact rate-based ceiling ceil(input_count*input_rate/1e6)+ceil(max_output_count*output_rate/1e6), bumped up to MinPrice when that floor is larger (tiny paid requests). Immutable for the life of the ticket. The contract's open() locks exactly this many microUSDC into escrow. Invariant: MaxPrice >= MinPrice.
	MinPrice       uint64 `json:"min_price"`        // microUSDC; per-request minimum amount_charged on non-zero usage (see SPEC.md §3a "Minimum charge"). max(token component = ceil(min_charge.output_tokens*output_rate/1e6), µALGO component = ceil(min_charge.algo_txns*1000*algo_usd)). 0 only when both components are 0 — i.e. a free model, OR (token component off: hayai.min_charge.output_tokens=0 or output_rate=0) AND (µALGO component off: hayai.min_charge.algo_txns=0 — the default — or oracle unavailable at reserve). With stock config (output_tokens=1000) a paid model's ticket has a non-zero MinPrice. The (0,0) inference-failure path still charges 0 (refund in full) regardless of MinPrice.
	ExpiresAt      int64  `json:"expires_at"`       // unix seconds
	Model          string `json:"model"`            // requested model id
	Stream         bool   `json:"stream"`           // whether the sealed request will stream
	CommitK        string `json:"commit_k"`         // base64(sha256(K_response)) — binds payment to this specific response key
	// InputUsageType / OutputUsageType (v2) discriminate the unit each
	// direction is priced in (see UsageType). Chat is Tokens/Tokens; a
	// dedicated image route is None-or-Tokens/Images. They ride one byte each
	// at the tail of CanonicalBytes. Zero value (UsageTypeNone) is what a v1
	// issuer would have implied; the issuing node sets them explicitly under v2.
	InputUsageType  UsageType `json:"input_usage_type"`
	OutputUsageType UsageType `json:"output_usage_type"`
	// CacheReadRate (v2) is the microUSDC-per-1,000,000-tokens rate applied to
	// the cached-read subset of the input (the prompt tokens an upstream served
	// from a prefix/prompt cache — reported as CachedInputCount on the receipt).
	// It is always <= InputRate; 0 means cached reads are free. When the operator
	// leaves cache_read_rate unset, the issuing node resolves it to InputRate, so
	// the wire value is a concrete rate and a v1-era flat charge is reproduced
	// exactly (no discount). Rides one uint64 at the tail of CanonicalBytes.
	CacheReadRate uint64 `json:"cache_read_rate"`
	Sig           string `json:"sig"` // base64(Ed25519 over CanonicalBytes) — filled by Sign
}

// ticketSigningTag domain-separates Ticket signatures from any other
// Ed25519 signatures the system may introduce later. The trailing NUL is
// intentional (keeps the tag self-terminating in any concatenation).
//
// Version history: v1 covered the base ticket and, later, the appended
// InputUsageType / OutputUsageType discriminators (that append changed the
// canonical bytes but was left under the v1 tag — the appended bytes are
// themselves the hard signature break). Bumped v1 → v2 when CacheReadRate was
// appended for cached-token pricing. A verifier and issuer on different tag
// generations produce different signatures, which is the intended hard cutover.
const ticketSigningTag = "zs-ticket-v2\x00"

// CanonicalBytes returns the unambiguous byte sequence Ed25519 signs (and
// verifies). Strings are encoded as uint32 big-endian length followed by
// raw bytes; numeric fields are fixed-width big-endian; the boolean is a
// single byte (0 or 1). This format is independent of any JSON encoder so
// a non-Go reimplementation can reproduce the exact bytes.
//
// Sig is excluded (that's what we're computing).
func (t *Ticket) CanonicalBytes() []byte {
	b := make([]byte, 0, 256)
	b = append(b, ticketSigningTag...)
	b = appendLenStr(b, t.TicketID)
	b = appendU64(b, t.OperatorID)
	b = appendU64(b, t.NodeID)
	b = appendU64(b, t.InputCount)
	b = appendU64(b, t.MaxOutputCount)
	b = appendU64(b, t.InputRate)
	b = appendU64(b, t.OutputRate)
	b = appendU64(b, t.MaxPrice)
	b = appendU64(b, t.MinPrice)
	b = appendI64(b, t.ExpiresAt)
	b = appendLenStr(b, t.Model)
	if t.Stream {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendLenStr(b, t.CommitK)
	// The usage-type discriminators append at the tail (one byte each).
	b = appendU8(b, byte(t.InputUsageType))
	b = appendU8(b, byte(t.OutputUsageType))
	// v2: the cached-read rate appends after the usage types (the new tail).
	b = appendU64(b, t.CacheReadRate)
	return b
}

// Sign populates t.Sig with Ed25519(priv, TicketSigDigest(t)) where
// TicketSigDigest = sha256(t.CanonicalBytes()). CanonicalBytes()
// already prepends the ticket-specific domain tag
// ("zs-ticket-v2\x00"), so the digest binds that tag plus every
// ticket field — cross-protocol reuse (e.g. replaying a receipt
// signature as a ticket signature) cannot produce a valid signature.
//
// Signing the digest (not the raw message) keeps the on-chain
// op.ed25519verifyBare cost constant regardless of how the ticket
// shape evolves, and lets the contract verify the exact same bytes
// off-chain code does. The signing key is whatever signer holds for
// signingAddr (the operator's signing Algorand account, distinct
// from the payment account — see SPEC.md §3 / §3a). Routing through
// BytesSigner lets the actual key live in a mnemonic-backed keystore,
// an HSM, or any other custody backend without proto needing to know.
func (t *Ticket) Sign(ctx context.Context, signer BytesSigner, signingAddr string) error {
	if signer == nil {
		return errors.New("ticket sign: signer is nil")
	}
	digest := TicketSigDigest(t)
	sig, err := signer.SignBytes(ctx, signingAddr, digest[:])
	if err != nil {
		return fmt.Errorf("ticket sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("ticket sign: signer returned %d-byte signature, want %d", len(sig), ed25519.SignatureSize)
	}
	t.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify returns nil if t.Sig is a valid Ed25519 signature of
// TicketSigDigest(t) under pub. Callers typically recover pub from
// an Algorand address via DecodeAlgorandAddress. Verifying the same
// digest the contract verifies means off-chain Verify and on-chain
// ed25519verify_bare agree byte-for-byte.
func (t *Ticket) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(t.Sig)
	if err != nil {
		return fmt.Errorf("decode ticket sig: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length %d", len(sig))
	}
	digest := TicketSigDigest(t)
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("ticket signature verification failed")
	}
	return nil
}

// CommitResponseKey returns sha256(K) — the commitment a node places in
// Ticket.CommitK at reserve time. The proxy recovers K via
// UnwrapResponseKey and recomputes this to verify the operator sealed the
// response with the pre-committed key.
func CommitResponseKey(k [wire.ResponseKeySize]byte) [sha256.Size]byte {
	return sha256.Sum256(k[:])
}

// TicketSigDigest returns sha256(CanonicalBytes(t)) — the 32-byte
// value both Ticket.Sign and any consumer's ed25519 verify call feed
// to ed25519. CanonicalBytes() already includes the
// "zs-ticket-v2\x00" domain tag so the digest is cross-protocol
// safe. Committing to a fixed-size digest keeps any on-chain
// ed25519verify_bare cost constant regardless of how the ticket
// shape evolves.
//
// By colocating the digest derivation with Ticket.Sign, any future
// change to the signing payload stays single-source — wallet code
// never reaches into Ticket internals to re-implement the formula.
func TicketSigDigest(t *Ticket) [sha256.Size]byte {
	return sha256.Sum256(t.CanonicalBytes())
}

func appendU8(b []byte, v byte) []byte {
	return append(b, v)
}

func appendU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendI64(b []byte, v int64) []byte {
	return appendU64(b, uint64(v))
}

func appendLenStr(b []byte, s string) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(len(s)))
	b = append(b, tmp[:]...)
	return append(b, s...)
}
