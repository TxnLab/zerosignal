/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/age"
)

// SettleAckPath is where a payer hands a node its signed half of the atomic
// settle group, for the node to submit (SPEC.md § 3a "Settle ack"). Before
// SettleAckMinVersion the payer broadcast the group itself, from its own IP,
// and the group names the payer as gtxn[1]'s sender: every settle linked the
// payer's IP to its address at whichever algod it used.
const SettleAckPath = "/v1/zs/settle-ack"

// SealedSettleAckContentType is the Content-Type of a sealed settle ack. The
// body is a SealedReserveEnvelope (a lone ciphertext field) whose plaintext is
// a marshaled SettleAck, sealed to the node's ephemeral recipient: the group
// names the payer, and the ack usually rides a relay.
const SealedSettleAckContentType = "application/vnd.zs-settle-ack+json"

// SettleAckMinVersion is the first ProtoVersion at which a node serves
// SettleAckPath.
const SettleAckMinVersion = "9.12"

// TakesSettleAck reports whether a node advertising protoVersion serves
// SettleAckPath. Fails closed: a payer that cannot tell broadcasts the group
// itself, as before, which settles the same ticket at the old privacy cost.
func TakesSettleAck(protoVersion string) bool {
	return ProtoVersionAtLeast(protoVersion, SettleAckMinVersion)
}

// SettleAck is the plaintext of a sealed settle ack.
type SettleAck struct {
	TicketID string `json:"ticket_id"`
	// SettleGroup is the completed atomic settle group in
	// escrow.EncodeSettleGroup's form: the node's own gtxn[0] as it sent it,
	// and the payer-signed gtxn[1].
	SettleGroup string `json:"settle_group"`
}

// SealSettleAck marshals ack and age-seals it to the node's recipient.
func SealSettleAck(ack SettleAck, nodeRecipient age.Recipient) ([]byte, error) {
	if nodeRecipient == nil {
		return nil, errors.New("seal settle ack: nil node recipient")
	}
	body, err := json.Marshal(ack)
	if err != nil {
		return nil, fmt.Errorf("marshal settle ack: %w", err)
	}
	return sealReserveEnvelope(body, nodeRecipient)
}

// OpenSettleAck is the node-side inverse of SealSettleAck, trying
// nodeIdentities in order as DecryptRequest does.
func OpenSettleAck(envelopeJSON []byte, nodeIdentities ...age.Identity) (SettleAck, error) {
	if len(nodeIdentities) == 0 {
		return SettleAck{}, errors.New("open settle ack: no node identities supplied")
	}
	body, err := openReserveEnvelope(envelopeJSON, nodeIdentities...)
	if err != nil {
		return SettleAck{}, err
	}
	var ack SettleAck
	if err := json.Unmarshal(body, &ack); err != nil {
		return SettleAck{}, fmt.Errorf("parse settle ack: %w", err)
	}
	if ack.TicketID == "" || ack.SettleGroup == "" {
		return SettleAck{}, errors.New("settle ack missing ticket_id or settle_group")
	}
	return ack, nil
}
