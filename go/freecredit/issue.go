/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package freecredit

// The issue wire, which every issuer speaks so a payer can use any of them.
// Both calls are POSTs of JSON to the issuer's base URL:
//
//	DayKeyPath  DayKeyRequest → DayKeyCert   the day key to blind to
//	IssuePath   IssueRequest  → IssueResponse
//
// An issuer answers only for the epochs AcceptedEpochs gives at its clock,
// and 400 CodeEpochNotIssuable for any other. It may sign fewer messages than
// it was sent, the first len(Signatures) of them, when the caller's cap for
// that epoch is nearly spent, and answers 429 CodeCreditsExhausted with a
// Retry-After once it is. The cap counts credits per epoch, not per request
// day. Who may have credits is the issuer's own business, decided from the
// headers the payer's host adds.
const (
	DayKeyPath = "/v1/zs/credits/key"
	IssuePath  = "/v1/zs/credits"
)

// MaxIssueBatch caps the blinded messages in one IssueRequest, so a request
// stays one small body and one bounded amount of RSA work.
const MaxIssueBatch = 20

const (
	// CodeCreditsExhausted is the issuer's error code once the caller's cap
	// for the epoch is spent.
	CodeCreditsExhausted = "credits_exhausted"
	// CodeEpochNotIssuable refuses an epoch outside AcceptedEpochs.
	CodeEpochNotIssuable = "epoch_not_issuable"
)

// DayKeyRequest asks for the issuer's day key for a deployment and epoch.
type DayKeyRequest struct {
	Deployment Bytes `json:"deployment"`
	Epoch      Epoch `json:"epoch"`
}

// IssueRequest asks the issuer to sign Blinded with its day key for
// Deployment and Epoch.
type IssueRequest struct {
	Deployment Bytes   `json:"deployment"`
	Epoch      Epoch   `json:"epoch"`
	Blinded    []Bytes `json:"blinded"`
}

// IssueResponse holds the blind signatures, in Blinded's order.
type IssueResponse struct {
	Signatures []Bytes `json:"signatures"`
}
