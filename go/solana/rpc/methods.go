/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TxnLab/zerosignal/go/solana"
)

// Commitment is how settled the state a call reads must be. The zero value
// sends none, so the RPC applies its default, finalized.
type Commitment string

const (
	Processed Commitment = "processed"
	Confirmed Commitment = "confirmed"
	Finalized Commitment = "finalized"
)

// Account is an account as the RPC reports it. The owner is the caller's to
// check before it trusts Data: zsescrow's decoders read the data alone.
type Account struct {
	Lamports   uint64
	Owner      solana.PublicKey
	Data       []byte
	Executable bool
}

// KeyedAccount is one account of a getProgramAccounts answer.
type KeyedAccount struct {
	Key     solana.PublicKey
	Account Account
}

// Filter narrows getProgramAccounts on the RPC, so a registry read moves only
// the accounts of one type rather than every account the program owns.
type Filter struct {
	dataSize *uint64
	memcmp   *memcmp
}

type memcmp struct {
	Offset   uint64 `json:"offset"`
	Bytes    string `json:"bytes"`
	Encoding string `json:"encoding"`
}

// DataSize keeps the accounts whose data is exactly n bytes.
func DataSize(n uint64) Filter { return Filter{dataSize: &n} }

// Memcmp keeps the accounts whose data holds b at offset. The RPC refuses
// more than 128 bytes.
func Memcmp(offset uint64, b []byte) Filter {
	return Filter{memcmp: &memcmp{Offset: offset, Bytes: base64.StdEncoding.EncodeToString(b), Encoding: "base64"}}
}

func (f Filter) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		DataSize *uint64 `json:"dataSize,omitempty"`
		Memcmp   *memcmp `json:"memcmp,omitempty"`
	}{f.dataSize, f.memcmp})
}

// Blockhash is a recent blockhash and the last block height a transaction
// naming it can land at.
type Blockhash struct {
	Hash                 solana.Hash
	LastValidBlockHeight uint64
}

// SendOptions is sendTransaction's config.
type SendOptions struct {
	SkipPreflight bool
	// PreflightCommitment is the state the simulation runs against; the zero
	// value is the RPC's default, finalized, which is older state than a
	// just-funded payer's.
	PreflightCommitment Commitment
	// MaxRetries is how often the RPC itself resends; nil leaves its default,
	// which resends until the blockhash expires. A caller that rebroadcasts
	// on its own sets 0.
	MaxRetries *uint64
}

// SignatureStatus is a transaction's status, or nil in its place when the
// RPC knows none.
type SignatureStatus struct {
	Slot uint64
	// Confirmations is nil once the block is rooted.
	Confirmations *uint64
	// Err is the TransactionError the transaction landed with, nil for a
	// success (see TxErrName).
	Err                json.RawMessage
	ConfirmationStatus Commitment
}

type config struct {
	Encoding                 string     `json:"encoding,omitempty"`
	Commitment               Commitment `json:"commitment,omitempty"`
	Filters                  []Filter   `json:"filters,omitempty"`
	SkipPreflight            bool       `json:"skipPreflight,omitempty"`
	PreflightCommitment      Commitment `json:"preflightCommitment,omitempty"`
	MaxRetries               *uint64    `json:"maxRetries,omitempty"`
	SearchTransactionHistory bool       `json:"searchTransactionHistory,omitempty"`
	MinContextSlot           uint64     `json:"minContextSlot,omitempty"`
}

// wireAccount holds each field so that a missing or null one is seen: read as
// its zero value it would pass for a real answer (no lamports, the system
// program as owner, no data), and the TS twin refuses it. Executable is raw,
// not *bool: it may be absent (false) but not null, and a pointer reads both
// as nil.
type wireAccount struct {
	Data       []*string         `json:"data"`
	Executable json.RawMessage   `json:"executable"`
	Lamports   *uint64           `json:"lamports"`
	Owner      *solana.PublicKey `json:"owner"`
}

func (w *wireAccount) account() (Account, error) {
	if len(w.Data) != 2 || w.Data[0] == nil || w.Data[1] == nil || *w.Data[1] != "base64" {
		return Account{}, errors.New("account data is not [data, \"base64\"]")
	}
	data, err := base64.StdEncoding.DecodeString(*w.Data[0])
	if err != nil {
		return Account{}, fmt.Errorf("account data: %w", err)
	}
	if w.Lamports == nil {
		return Account{}, errors.New("account lamports is missing or null")
	}
	if w.Owner == nil {
		return Account{}, errors.New("account owner is missing or null")
	}
	// An account the RPC sends without executable is not a program; a null
	// one is no boolean.
	var executable bool
	if w.Executable != nil && (string(w.Executable) == "null" || json.Unmarshal(w.Executable, &executable) != nil) {
		return Account{}, errors.New("account executable is not a boolean")
	}
	return Account{Lamports: *w.Lamports, Owner: *w.Owner, Data: data, Executable: executable}, nil
}

func (c *HTTPClient) GetAccountInfo(ctx context.Context, key solana.PublicKey, cm Commitment) (*Account, error) {
	a, _, err := c.getAccountInfo(ctx, key, cm, 0, false)
	return a, err
}

func (c *HTTPClient) GetAccountInfoAt(ctx context.Context, key solana.PublicKey, cm Commitment, minContextSlot uint64) (*Account, uint64, error) {
	return c.getAccountInfo(ctx, key, cm, minContextSlot, true)
}

// getAccountInfo reads key, sending minContextSlot when it is not 0. withSlot
// refuses an answer without its context slot, which GetAccountInfoAt returns.
func (c *HTTPClient) getAccountInfo(ctx context.Context, key solana.PublicKey, cm Commitment, minContextSlot uint64, withSlot bool) (*Account, uint64, error) {
	var r struct {
		// Raw, so a read that does not want the slot never refuses an answer
		// over it, as the TS twin's does not.
		Context json.RawMessage `json:"context"`
		// Raw, so a missing value is told from a null one: only null means
		// the account does not exist.
		Value json.RawMessage `json:"value"`
	}
	cfg := config{Encoding: "base64", Commitment: cm, MinContextSlot: minContextSlot}
	if err := c.call(ctx, "getAccountInfo", []any{key.String(), cfg}, &r); err != nil {
		return nil, 0, err
	}
	var slot uint64
	if withSlot {
		var cx struct {
			Slot *uint64 `json:"slot"`
		}
		if json.Unmarshal(r.Context, &cx) != nil || cx.Slot == nil {
			return nil, 0, fmt.Errorf("solana rpc getAccountInfo %s: answer has no context slot", key)
		}
		slot = *cx.Slot
	}
	switch string(r.Value) {
	case "":
		return nil, 0, fmt.Errorf("solana rpc getAccountInfo %s: answer has no value", key)
	case "null":
		return nil, slot, ErrNotFound
	}
	var w wireAccount
	if err := json.Unmarshal(r.Value, &w); err != nil {
		return nil, 0, fmt.Errorf("solana rpc getAccountInfo %s: decode account: %w", key, err)
	}
	a, err := w.account()
	if err != nil {
		return nil, 0, fmt.Errorf("solana rpc getAccountInfo %s: %w", key, err)
	}
	return &a, slot, nil
}

func (c *HTTPClient) GetProgramAccounts(ctx context.Context, program solana.PublicKey, cm Commitment, filters ...Filter) ([]KeyedAccount, error) {
	// Pointers, so a null or missing member is refused rather than read as
	// the zero key or an empty account.
	var r []*struct {
		Pubkey  *solana.PublicKey `json:"pubkey"`
		Account *wireAccount      `json:"account"`
	}
	if err := c.call(ctx, "getProgramAccounts", []any{program.String(), config{Encoding: "base64", Commitment: cm, Filters: filters}}, &r); err != nil {
		return nil, err
	}
	out := make([]KeyedAccount, len(r))
	for i, ka := range r {
		if ka == nil || ka.Pubkey == nil || ka.Account == nil {
			return nil, fmt.Errorf("solana rpc getProgramAccounts %s: entry %d is not {pubkey, account}", program, i)
		}
		a, err := ka.Account.account()
		if err != nil {
			return nil, fmt.Errorf("solana rpc getProgramAccounts %s: %w", *ka.Pubkey, err)
		}
		out[i] = KeyedAccount{Key: *ka.Pubkey, Account: a}
	}
	return out, nil
}

func (c *HTTPClient) GetBalance(ctx context.Context, key solana.PublicKey, cm Commitment) (uint64, error) {
	var r struct {
		Value uint64 `json:"value"`
	}
	if err := c.call(ctx, "getBalance", []any{key.String(), config{Commitment: cm}}, &r); err != nil {
		return 0, err
	}
	return r.Value, nil
}

func (c *HTTPClient) GetLatestBlockhash(ctx context.Context, cm Commitment) (Blockhash, error) {
	var r struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getLatestBlockhash", []any{config{Commitment: cm}}, &r); err != nil {
		return Blockhash{}, err
	}
	h, err := solana.ParseHash(r.Value.Blockhash)
	if err != nil {
		return Blockhash{}, fmt.Errorf("solana rpc getLatestBlockhash: %w", err)
	}
	return Blockhash{Hash: h, LastValidBlockHeight: r.Value.LastValidBlockHeight}, nil
}

func (c *HTTPClient) GetBlockHeight(ctx context.Context, cm Commitment) (uint64, error) {
	var h uint64
	if err := c.call(ctx, "getBlockHeight", []any{config{Commitment: cm}}, &h); err != nil {
		return 0, err
	}
	return h, nil
}

func (c *HTTPClient) GetGenesisHash(ctx context.Context) (solana.Hash, error) {
	var s string
	if err := c.call(ctx, "getGenesisHash", []any{}, &s); err != nil {
		return solana.Hash{}, err
	}
	h, err := solana.ParseHash(s)
	if err != nil {
		return solana.Hash{}, fmt.Errorf("solana rpc getGenesisHash: %w", err)
	}
	return h, nil
}

func (c *HTTPClient) GetMinimumBalanceForRentExemption(ctx context.Context, dataLen uint64, cm Commitment) (uint64, error) {
	var lamports uint64
	if err := c.call(ctx, "getMinimumBalanceForRentExemption", []any{dataLen, config{Commitment: cm}}, &lamports); err != nil {
		return 0, err
	}
	return lamports, nil
}

// SendTransaction submits signed transaction bytes and returns the
// signature the RPC reports. A simulation failure is an *Error whose
// TxErrName names the TransactionError.
func (c *HTTPClient) SendTransaction(ctx context.Context, tx []byte, o SendOptions) (solana.Signature, error) {
	cfg := config{Encoding: "base64", SkipPreflight: o.SkipPreflight, PreflightCommitment: o.PreflightCommitment, MaxRetries: o.MaxRetries}
	var s string
	if err := c.call(ctx, "sendTransaction", []any{base64.StdEncoding.EncodeToString(tx), cfg}, &s); err != nil {
		return solana.Signature{}, err
	}
	sig, err := solana.ParseSignature(s)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("solana rpc sendTransaction: %w", err)
	}
	return sig, nil
}

// GetSignatureStatuses returns one status per signature, in order. Without
// searchHistory the RPC searches only its recent status cache, which forgets
// a transaction some minutes after it lands: a restart recovering an older
// one needs the history.
func (c *HTTPClient) GetSignatureStatuses(ctx context.Context, sigs []solana.Signature, searchHistory bool) ([]*SignatureStatus, error) {
	keys := make([]string, len(sigs))
	for i, s := range sigs {
		keys[i] = s.String()
	}
	var r struct {
		Value []*struct {
			Slot               uint64          `json:"slot"`
			Confirmations      *uint64         `json:"confirmations"`
			Err                json.RawMessage `json:"err"`
			ConfirmationStatus Commitment      `json:"confirmationStatus"`
		} `json:"value"`
	}
	if err := c.call(ctx, "getSignatureStatuses", []any{keys, config{SearchTransactionHistory: searchHistory}}, &r); err != nil {
		return nil, err
	}
	if len(r.Value) != len(sigs) {
		return nil, fmt.Errorf("solana rpc getSignatureStatuses: %d statuses for %d signatures", len(r.Value), len(sigs))
	}
	out := make([]*SignatureStatus, len(sigs))
	for i, v := range r.Value {
		if v == nil {
			continue
		}
		switch v.ConfirmationStatus {
		case "", Processed, Confirmed, Finalized:
		default:
			return nil, fmt.Errorf("solana rpc getSignatureStatuses: confirmationStatus %q is not a commitment", v.ConfirmationStatus)
		}
		out[i] = &SignatureStatus{Slot: v.Slot, Confirmations: v.Confirmations, Err: nullToNil(v.Err), ConfirmationStatus: v.ConfirmationStatus}
	}
	return out, nil
}

func nullToNil(raw json.RawMessage) json.RawMessage {
	if string(raw) == "null" {
		return nil
	}
	return raw
}
