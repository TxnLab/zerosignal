/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// The inner-request frame is the plaintext sealed into RequestEnvelope.Ciphertext.
// It carries the request's routing/admission metadata ahead of the untouched
// request body:
//
//	"zsrq" || uint8(version) || uint32_be(headerLen) || headerJSON || body
//
// Framing rather than a JSON wrapper because the body must survive byte-for-byte:
// the admission tag and the receipt's body_hash both commit to sha256(body), and
// re-marshaling arbitrary caller JSON does not round-trip its bytes. Length-prefixing
// the header keeps the body a raw suffix — no escaping, no base64 inflation on the
// multi-megabyte image-edit bodies.
const (
	innerRequestVersion = 1

	// innerHeaderMaxLen bounds the declared header length so a corrupt or
	// hostile frame cannot drive a huge allocation before the JSON parse
	// fails. The header holds four short strings; 64 KiB is orders of
	// magnitude of slack.
	innerHeaderMaxLen = 64 << 10

	innerPrefixLen = len(innerRequestMagic) + 1 + 4
)

// innerRequestMagic tags the frame so a peer that seals a bare body — a
// pre-8.0 caller whose envelope still carried the identifiers in cleartext —
// fails with a clear framing error rather than a JSON parse error deep in the
// provider path.
var innerRequestMagic = [4]byte{'z', 's', 'r', 'q'}

// innerRequestHeader is the metadata half of the frame. These fields were the
// plaintext outer RequestEnvelope fields before 8.0; they moved inside so a
// relay cannot read ticket_id / algorand_tx_id and resolve the payer on chain.
type innerRequestHeader struct {
	ReplyToPublicKey string `json:"reply_to_public_key"`
	AlgorandTxID     string `json:"algorand_tx_id"`
	TicketID         string `json:"ticket_id,omitempty"`
	AdmissionTag     string `json:"admission_tag,omitempty"`
}

// encodeInnerRequest builds the frame. body is appended verbatim.
func encodeInnerRequest(h innerRequestHeader, body []byte) ([]byte, error) {
	headerJSON, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshal inner request header: %w", err)
	}
	if len(headerJSON) > innerHeaderMaxLen {
		return nil, fmt.Errorf("inner request header %d bytes exceeds max %d", len(headerJSON), innerHeaderMaxLen)
	}

	out := make([]byte, 0, innerPrefixLen+len(headerJSON)+len(body))
	out = append(out, innerRequestMagic[:]...)
	out = append(out, innerRequestVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(headerJSON)))
	out = append(out, headerJSON...)
	out = append(out, body...)
	return out, nil
}

// decodeInnerRequest is the inverse. The returned body aliases raw — callers
// hold the decrypted plaintext for the life of the request, so there is no
// copy to make.
func decodeInnerRequest(raw []byte) (innerRequestHeader, []byte, error) {
	var h innerRequestHeader
	if len(raw) < innerPrefixLen {
		return h, nil, errors.New("inner request frame truncated")
	}
	if [4]byte(raw[:4]) != innerRequestMagic {
		return h, nil, errors.New("inner request frame bad magic")
	}
	if v := raw[4]; v != innerRequestVersion {
		return h, nil, fmt.Errorf("inner request frame version %d, want %d", v, innerRequestVersion)
	}
	headerLen := binary.BigEndian.Uint32(raw[5:innerPrefixLen])
	if headerLen > innerHeaderMaxLen {
		return h, nil, fmt.Errorf("inner request header %d bytes exceeds max %d", headerLen, innerHeaderMaxLen)
	}
	end := innerPrefixLen + int(headerLen)
	if end > len(raw) {
		return h, nil, errors.New("inner request header length past end of frame")
	}
	if err := json.Unmarshal(raw[innerPrefixLen:end], &h); err != nil {
		return h, nil, fmt.Errorf("parse inner request header: %w", err)
	}
	return h, raw[end:], nil
}
