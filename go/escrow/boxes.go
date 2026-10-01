/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Box key prefixes mirror the contract's BoxMap declarations in
// contracts/ZeroSignalEscrow.algo.ts — `t:` for the ticket map keyed by the
// 16-byte ticket id, `o:` for the operator map keyed by the 8-byte
// big-endian uint64 operator id assigned by ZeroSignalEscrow.createOperator,
// `n:` for the node map keyed by the compound 16-byte (operatorId ‖ nodeId)
// big-endian pair. Kept as unexported slices so callers go through the
// TicketBoxKey / OperatorBoxKey / NodeBoxKey helpers and nobody builds a key
// by hand.
// `q:` is the free-ticket quota map, keyed by the payer's raw 32-byte public
// key (an Algorand address decodes to exactly that).
var (
	ticketBoxPrefix    = []byte("t:")
	operatorBoxPrefix  = []byte("o:")
	nodeBoxPrefix      = []byte("n:")
	freeQuotaBoxPrefix = []byte("q:")
)

// TicketBoxKey returns the full box key for a ticket: `"t:" +
// ticketIDRaw`. Callers must pass the 16-byte raw id — the contract's
// MBR accounting and the on-wire BoxReferences array both assume that
// exact length.
func TicketBoxKey(ticketIDRaw []byte) []byte {
	k := make([]byte, 0, len(ticketBoxPrefix)+len(ticketIDRaw))
	k = append(k, ticketBoxPrefix...)
	return append(k, ticketIDRaw...)
}

// OperatorBoxKey returns the full box key for an operator: `"o:" +
// operator_id_be8` (10 bytes total). The contract's BoxMap is keyed by
// uint64; the on-wire encoding is 8-byte big-endian — matching what
// puya emits for uint64 BoxMap keys.
func OperatorBoxKey(operatorID uint64) []byte {
	k := make([]byte, 0, len(operatorBoxPrefix)+8)
	k = append(k, operatorBoxPrefix...)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], operatorID)
	return append(k, buf[:]...)
}

// NodeBoxKey returns the full box key for a node: `"n:" + operator_id_be8 +
// node_id_be8` (18 bytes total). The compound key matches what the contract's
// nodeKey() helper builds (itob(operatorId) ‖ itob(nodeId)) under the `n:`
// BoxMap prefix. operatorId comes first so NodeBoxPrefixForOperator can
// prefix-scan a single operator's nodes.
func NodeBoxKey(operatorID, nodeID uint64) []byte {
	k := make([]byte, 0, len(nodeBoxPrefix)+16)
	k = append(k, nodeBoxPrefix...)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], operatorID)
	k = append(k, buf[:]...)
	binary.BigEndian.PutUint64(buf[:], nodeID)
	return append(k, buf[:]...)
}

// FreeQuotaBoxKey returns the full box key for a payer's free-ticket quota:
// `"q:" + payer_pubkey_32` (34 bytes total). The contract's BoxMap is keyed by
// Account, whose native encoding is the raw 32-byte public key underlying the
// address — not the 58-char base32 form.
//
// This box is app-owned on purpose: the quota it holds must survive a payer
// opting out (CloseOut, or a unilateral ClearState), which payer local state
// cannot. A FREE (maxPrice == 0) open() references it — whether or not the payer
// has one yet, since the reference is what lets the contract create it — but a
// PAID open() does not: the contract touches freeQuotas[payer] only inside its
// `maxPrice == 0` guard, so on a paid open the reference is dead weight and
// needlessly writes a payer-derived box name onto the chain. OpenBoxReferences
// encodes that rule for both open() composers.
func FreeQuotaBoxKey(payer types.Address) []byte {
	k := make([]byte, 0, len(freeQuotaBoxPrefix)+len(payer))
	k = append(k, freeQuotaBoxPrefix...)
	return append(k, payer[:]...)
}

// OpenBoxReferences returns the foreign-box array for an open() app call.
// operators[operatorID], nodes[operatorID,nodeID] and tickets[ticketIDRaw] are
// always present — open() reads or writes all three, and a missing one is a
// hard admission failure. The free-quota box is added ONLY on a free
// (maxPrice == 0) open, because the contract touches freeQuotas[payer]
// exclusively inside its `maxPrice == 0` guard: on a paid open the reference is
// unused, and omitting it keeps the payer-derived `q:` box name (a stable
// payer pseudonym) off the chain. Conditioning is safe because
// VerifyOpenAppCall / VerifyOpenGroup validate ABI args only, never box
// references.
func OpenBoxReferences(operatorID, nodeID uint64, ticketIDRaw []byte, payer types.Address, maxPrice uint64) []types.AppBoxReference {
	refs := []types.AppBoxReference{
		{AppID: 0, Name: OperatorBoxKey(operatorID)},
		{AppID: 0, Name: NodeBoxKey(operatorID, nodeID)},
		{AppID: 0, Name: TicketBoxKey(ticketIDRaw)},
	}
	if maxPrice == 0 {
		refs = append(refs, types.AppBoxReference{AppID: 0, Name: FreeQuotaBoxKey(payer)})
	}
	return refs
}

// FreeQuotaBoxKeyFromAddr is FreeQuotaBoxKey for a base32 address string.
func FreeQuotaBoxKeyFromAddr(payerAddr string) ([]byte, error) {
	addr, err := types.DecodeAddress(payerAddr)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode payer addr for quota box key: %w", err)
	}
	return FreeQuotaBoxKey(addr), nil
}

// ticketIDFromBoxName parses the raw 16-byte ticket id out of a full
// `t:`-prefixed ticket box name — the inverse of TicketBoxKey, used to decode
// names returned by a box listing. ok is false for a name that isn't a
// well-formed ticket box (wrong prefix, or a suffix that isn't a 16-byte id);
// such a box is not one this contract writes, so callers skip it rather than
// guess at it. The returned id is a copy, safe to retain after the listing
// buffer is reused.
func ticketIDFromBoxName(name []byte) ([]byte, bool) {
	if len(name) != len(ticketBoxPrefix)+16 || !bytes.HasPrefix(name, ticketBoxPrefix) {
		return nil, false
	}
	id := make([]byte, 16)
	copy(id, name[len(ticketBoxPrefix):])
	return id, true
}

// operatorIDFromBoxName parses the operator id out of a full `o:`-prefixed
// operator box name (`o:` + operator_id_be8). ok is false for a name that
// isn't a well-formed operator box (wrong prefix or length) — the inverse of
// OperatorBoxKey, used to decode names returned by a box listing.
func operatorIDFromBoxName(name []byte) (uint64, bool) {
	if len(name) != len(operatorBoxPrefix)+8 || !bytes.HasPrefix(name, operatorBoxPrefix) {
		return 0, false
	}
	return binary.BigEndian.Uint64(name[len(operatorBoxPrefix):]), true
}

// nodeIDsFromBoxName parses (operatorId, nodeId) out of a full `n:`-prefixed
// node box name (`n:` + operator_id_be8 + node_id_be8) — the inverse of
// NodeBoxKey.
func nodeIDsFromBoxName(name []byte) (operatorID, nodeID uint64, ok bool) {
	if len(name) != len(nodeBoxPrefix)+16 || !bytes.HasPrefix(name, nodeBoxPrefix) {
		return 0, 0, false
	}
	body := name[len(nodeBoxPrefix):]
	return binary.BigEndian.Uint64(body[:8]), binary.BigEndian.Uint64(body[8:16]), true
}

// NodeBoxPrefixForOperator returns `"n:" + operator_id_be8` — the box-name
// prefix shared by every node under operatorID. Pass it to a box listing to
// enumerate just that operator's nodes (when the algod build supports the
// box-name prefix filter); otherwise iterate node ids 1..nextNodeId from the
// operator record.
func NodeBoxPrefixForOperator(operatorID uint64) []byte {
	k := make([]byte, 0, len(nodeBoxPrefix)+8)
	k = append(k, nodeBoxPrefix...)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], operatorID)
	return append(k, buf[:]...)
}
