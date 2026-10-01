/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package wire implements the hayai encrypted-envelope layer shared by the
// hayai proxy and a hayai node. SPEC.md in this module is the authoritative
// wire specification; the symbols exported here cite section numbers where
// behavior is non-obvious.
//
// Proxy-side entry points: WrapRequest, UnwrapResponseKey, DecryptBody,
// DecryptSSEDataValue. Node-side entry points: DecryptRequest, ResponseSealer.
// Both sides share the constants, envelope JSON types, and AAD helpers
// defined below.
package wire

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol constants. Changing any of these is a wire-breaking change.
// The protocol is still in active development; wire shape is not yet
// frozen. See SPEC.md.
const (
	EncryptedContentType = "application/vnd.zs+json"
	ResponseKeyHeader    = "X-Zs-Response-Key"
	ReceiptHeader        = "X-Zs-Receipt"
	// SettleGroupHeader carries the operator's pre-signed atomic
	// settle group (base64+msgpack of [op_first_half, payer_ack_template]).
	// Optional — when present, the proxy uses SubmitPresignedSettleGroup
	// to atomically settle with payer ALGO net = 0. When absent, the
	// proxy falls back to ComposeSettleStandalone (5,000 µALGO payer
	// fee). See SPEC.md "Operator authentication".
	SettleGroupHeader  = "X-Zs-Settle-Group"
	StreamEventMarker  = "zs"
	StreamEventReceipt = "zs-receipt"
	// StreamEventSettleGroup carries the operator-pre-signed atomic
	// settle group on streaming responses (the analogue of
	// X-Zs-Settle-Group on non-streaming). Emitted at stream end, just
	// *before* the `zs-receipt` frame, so the consumer has the group
	// cached by the time it verifies the receipt and acks.
	//
	// Sealed under K_response with BuildHeaderAAD(…, SealedHeaderSettleGroup),
	// so it consumes no frame index — the `zs-receipt` frame after it must land
	// on the index the content frames left off at. It is sealed because the
	// group names the payer address (gtxn[1]'s sender, both txns'
	// ForeignAccounts). That these are operator-signed Algorand transactions
	// bound for the chain settles their *integrity*, not their confidentiality:
	// a relay forwarding this stream also holds the client's IP, and the chain
	// does not. Plaintext until 8.0 — see version.go.
	StreamEventSettleGroup = "zs-settle-group"
	ResponseKeySize        = 32
	NonceSize              = chacha20poly1305.NonceSize // 12

	// Transport-privacy (single-hop operator-as-relay) constants. RelayPath
	// is the route every node exposes to forward an inner request to another
	// operator on a client's behalf, hiding the client's IP from the target.
	// The relay is a dumb byte forwarder: the request stays sealed to the
	// *target's* age key, so these transport headers carry no payload secret
	// — only routing metadata the relay needs (which it sees anyway, since it
	// must connect to the target). See SPEC.md "Transport bindings".
	RelayPath = "/v1/zs/relay"
	// RelayTargetHeader carries the on-chain operator id of the destination.
	// Paired with RelayTargetNodeHeader (the node id within that operator):
	// the relay resolves the (operator, node) pair to a base URL via its own
	// on-chain directory — it never trusts a client-supplied URL (SSRF
	// boundary).
	RelayTargetHeader = "X-Zs-Relay-Target"
	// RelayTargetNodeHeader carries the on-chain node id (within the operator
	// named by RelayTargetHeader) of the destination. Since the operator/node
	// split a base URL belongs to a node, so the relay needs both ids to
	// resolve the forward target.
	RelayTargetNodeHeader = "X-Zs-Relay-Target-Node"
	// RelayPathHeader carries the inner request path the relay reconstructs
	// against the target (validated against a closed allow-list).
	RelayPathHeader = "X-Zs-Relay-Path"
	// RelayMethodHeader carries the inner request method (GET or POST).
	RelayMethodHeader = "X-Zs-Relay-Method"

	// RelayHopHeader is the one RESPONSE-side relay header (every other
	// X-Zs-Relay-* constant above rides the request). A relaying node sets it
	// on EVERY response it produces on RelayPath — as the first statement of
	// its handler, before the drain shed, before header validation, before the
	// forward — and its header-copy step SKIPS this key from the target's
	// header set, so a target can neither forge nor erase it.
	//
	// It exists because two very different failures used to be byte-identical
	// to the caller: the relay's own CDN / ingress / LB answering a code-less
	// 504 (the relay's handler NEVER RAN — we were blocked at its front door),
	// versus the relay running, forwarding, and copying the TARGET's code-less
	// 504 back verbatim. Both arrive as "504, no error.code", and before this
	// header a caller could only shrug at both (transient.AttrUnknown), which
	// let a relay behind a broken gateway stay in rotation indefinitely while
	// its every draw benched a healthy target.
	//
	// Presence means exactly "the zs relay handler ran". The two inferences a
	// caller draws are in transient.NarrowRelayed; the gate on absence is
	// SetsRelayHopHeader (see version.go) — below RelayHopHeaderMinVersion a
	// missing marker proves nothing, because the relay simply predates it.
	//
	// This leaks nothing: the caller already knows which relay it chose, the
	// header never travels to the target, and a proxy strips every X-Zs-* on
	// the way back to its own client. See SPEC.md §3f and §10.
	RelayHopHeader = "X-Zs-Relay-Hop"
	// RelayHopHeaderValue is the only value RelayHopHeader carries. The signal
	// is presence, not content; the value is a reserved generation marker so a
	// later revision can say more without needing a second header.
	RelayHopHeaderValue = "1"
)

// RequestEnvelope is the JSON body the proxy sends to the node. It carries
// nothing but ciphertext: the request's identifiers (algorand_tx_id,
// ticket_id), its admission tag, and the reply-to recipient all ride inside
// the age-sealed plaintext as an inner-request frame (see inner.go).
//
// The single-field shape is the invariant that makes relay metadata
// minimization auditable: a byte-transparent relay forwards an opaque blob and
// a test can assert the envelope JSON has exactly one key. Sealing the
// identifiers costs no ordering: the admission tag commits to sha256(the
// plaintext body), so the node must age-decrypt before it can admit anything —
// there is no pre-decrypt gate to lose by moving them inside. See SPEC.md § 4.
type RequestEnvelope struct {
	Ciphertext string `json:"ciphertext"`
}

// ResponseEnvelope is the JSON body the node returns for non-streaming
// encrypted responses. The node also sets the X-Zs-Response-Key header
// so the proxy can recover the symmetric key used to seal Ciphertext.
//
// algorand_tx_id is NOT echoed here. It is bound into the body AAD, which both
// sides reconstruct from state they already hold, so echoing it bought a
// redundant equality check at the cost of handing a relay the identifier that
// resolves to the payer on chain.
type ResponseEnvelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// AAD framing: each AEAD-sealed payload (non-streaming body or streaming
// frame) is bound to the request's algorand_tx_id via ChaCha20-Poly1305's
// Additional Authenticated Data. A domain tag distinguishes body AAD from
// frame AAD so a body ciphertext cannot be replayed as a frame or vice
// versa; the frame AAD additionally carries a monotonic 64-bit index so
// reordering, dropping, or duplicating frames within a stream breaks
// authentication. See SPEC.md § 6.
const (
	aadProtocolTag  = "zs"
	aadBodyDomain   = "body"
	aadFrameDomain  = "frame"
	aadHeaderDomain = "hdr"
)

// Sealed-metadata names. Each names one piece of post-response metadata
// sealed under K_response with BuildHeaderAAD, so a relay forwarding the
// response cannot read it. The name is bound into the AAD, which is what
// stops a receipt ciphertext from being replayed as a settle group.
//
// Both carry payer-linkable data and so cannot ride in cleartext through a
// relay: the settle group's payer-ack template names the payer address
// outright (gtxn[1] sender, plus both txns' ForeignAccounts), and the receipt
// carries ticket_id, which resolves to TicketRecord.payer on chain. See
// SPEC.md § 3f.
const (
	SealedHeaderReceipt     = "receipt"
	SealedHeaderSettleGroup = "settle-group"
)

// BuildBodyAAD returns the AEAD associated-data for a non-streaming
// response body bound to (txID, ticketID). ticketID MAY be empty at this
// layer; the trailing separator still distinguishes the field from an AAD
// that omits it. A prompt-carrying node always has one — a missing
// ticket_id is refused at admission with 402 ticket_required.
func BuildBodyAAD(txID, ticketID string) []byte {
	out := make([]byte, 0, len(aadProtocolTag)+1+len(aadBodyDomain)+1+len(txID)+1+len(ticketID))
	out = append(out, aadProtocolTag...)
	out = append(out, 0)
	out = append(out, aadBodyDomain...)
	out = append(out, 0)
	out = append(out, txID...)
	out = append(out, 0)
	out = append(out, ticketID...)
	return out
}

// BuildFrameAAD returns the AEAD associated-data for the frameIndex-th
// encrypted SSE frame (0-indexed) of the stream bound to (txID, ticketID).
// ticketID MAY be empty.
func BuildFrameAAD(txID, ticketID string, frameIndex uint64) []byte {
	out := make([]byte, 0, len(aadProtocolTag)+1+len(aadFrameDomain)+1+len(txID)+1+len(ticketID)+1+8)
	out = append(out, aadProtocolTag...)
	out = append(out, 0)
	out = append(out, aadFrameDomain...)
	out = append(out, 0)
	out = append(out, txID...)
	out = append(out, 0)
	out = append(out, ticketID...)
	out = append(out, 0)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], frameIndex)
	out = append(out, idx[:]...)
	return out
}

// BuildHeaderAAD returns the AEAD associated-data for a sealed piece of
// response metadata (a SealedHeader* name) bound to (txID, ticketID). It has
// its own domain so a sealed header can never be opened as a body or a stream
// frame, and it carries no index: header metadata is emitted at most once per
// name per response, so it does not participate in the frame counter.
func BuildHeaderAAD(txID, ticketID, name string) []byte {
	out := make([]byte, 0, len(aadProtocolTag)+1+len(aadHeaderDomain)+1+len(txID)+1+len(ticketID)+1+len(name))
	out = append(out, aadProtocolTag...)
	out = append(out, 0)
	out = append(out, aadHeaderDomain...)
	out = append(out, 0)
	out = append(out, txID...)
	out = append(out, 0)
	out = append(out, ticketID...)
	out = append(out, 0)
	out = append(out, name...)
	return out
}
