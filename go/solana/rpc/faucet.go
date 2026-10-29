/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// The public clusters' genesis hashes, which say what cluster an RPC serves
// whatever its URL.
const (
	DevnetGenesis  = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
	TestnetGenesis = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
	MainnetGenesis = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
)

// FaucetCluster is whether a CLI may ask the RPC at endpoint, which serves
// genesis, for an airdrop: on devnet's genesis, or on a validator on this
// machine serving neither mainnet's nor testnet's. A loopback URL can be a
// tunnel or a local RPC node on mainnet, so the genesis decides first.
func FaucetCluster(genesis solana.Hash, endpoint string) bool {
	switch genesis.String() {
	case DevnetGenesis:
		return true
	case MainnetGenesis, TestnetGenesis:
		return false
	}
	return zsescrow.LoopbackEndpoint(endpoint)
}

// RequestAirdrop is the requestAirdrop JSON-RPC call, which only a test
// cluster serves, so Client leaves it out. It returns the airdrop's
// signature, for Confirm to wait on. No error quotes the endpoint, whose path
// or query can carry a provider's key.
func RequestAirdrop(ctx context.Context, endpoint string, to solana.PublicKey, lamports uint64) (solana.Signature, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "requestAirdrop", "params": []any{to.String(), lamports}})
	if err != nil {
		return solana.Signature{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return solana.Signature{}, errors.New("build the request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// A *url.Error quotes the whole endpoint.
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return solana.Signature{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return solana.Signature{}, err
	}
	var answer struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decodeErr := json.Unmarshal(raw, &answer)
	switch {
	case decodeErr == nil && answer.Error != nil:
		return solana.Signature{}, fmt.Errorf("%d %s", answer.Error.Code, answer.Error.Message)
	case resp.StatusCode/100 != 2:
		return solana.Signature{}, fmt.Errorf("HTTP %s", resp.Status)
	case decodeErr != nil:
		return solana.Signature{}, fmt.Errorf("decode the answer: %w", decodeErr)
	case answer.Result == "":
		return solana.Signature{}, errors.New("no signature in the answer")
	}
	return solana.ParseSignature(answer.Result)
}
