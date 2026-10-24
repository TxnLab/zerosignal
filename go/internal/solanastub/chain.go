/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package solanastub is a stand-in Solana node for end-to-end tests: enough
// of a node to serve a real payer SDK against the zs_escrow program on a local
// validator, with knobs for the endings a payer drives. It is test tooling,
// not a node: it keeps everything in memory and trusts its own clock. It
// serves only once the open is confirmed, so a run never covers a payer
// reading a ticket account its open hasn't reached yet.
package solanastub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// Chain is a cluster running zs_escrow, as the stub and its tests reach it.
type Chain struct {
	Endpoint   string
	RPC        *rpc.HTTPClient
	Deployment zsescrow.Deployment
	Config     *zsescrow.Config
	Genesis    solana.Hash
}

// Dial reads the program's Config on the cluster at endpoint.
func Dial(ctx context.Context, endpoint string, program solana.PublicKey) (*Chain, error) {
	c, err := rpc.NewClient(endpoint)
	if err != nil {
		return nil, err
	}
	ch := &Chain{Endpoint: endpoint, RPC: c, Deployment: zsescrow.Deployment{Program: program}}
	if err := ch.Refresh(ctx); err != nil {
		return nil, err
	}
	if ch.Genesis, err = c.GetGenesisHash(ctx); err != nil {
		return nil, err
	}
	return ch, nil
}

// Refresh rereads the Config, which SetConfig changes.
func (ch *Chain) Refresh(ctx context.Context) error {
	acct, err := ch.RPC.GetAccountInfo(ctx, ch.Deployment.Config(), rpc.Confirmed)
	if err != nil {
		return fmt.Errorf("solanastub: read Config: %w", err)
	}
	cfg, err := zsescrow.DecodeConfig(acct.Data)
	if err != nil {
		return err
	}
	ch.Config = cfg
	ch.Deployment.Mint = cfg.USDCMint
	return nil
}

// Send signs ixs with feePayer first and the other signers after, sends them
// and waits until they are confirmed. A transaction that lands and fails is an
// error naming the program's error.
func (ch *Chain) Send(ctx context.Context, ixs []solana.Instruction, feePayer ed25519.PrivateKey, signers ...ed25519.PrivateKey) (solana.Signature, error) {
	bh, err := ch.RPC.GetLatestBlockhash(ctx, rpc.Confirmed)
	if err != nil {
		return solana.Signature{}, err
	}
	m, err := solana.Compile(PublicKey(feePayer), bh.Hash, ixs, solana.Legacy)
	if err != nil {
		return solana.Signature{}, err
	}
	tx := solana.NewTransaction(m)
	if err := tx.Sign(append([]ed25519.PrivateKey{feePayer}, signers...)...); err != nil {
		return solana.Signature{}, err
	}
	return ch.SendSigned(ctx, tx, bh.LastValidBlockHeight)
}

// SendSigned sends a signed transaction and waits until it is confirmed.
func (ch *Chain) SendSigned(ctx context.Context, tx *solana.Transaction, lastValid uint64) (solana.Signature, error) {
	raw, err := tx.MarshalBinary()
	if err != nil {
		return solana.Signature{}, err
	}
	sig, err := ch.RPC.SendTransaction(ctx, raw, rpc.SendOptions{PreflightCommitment: rpc.Processed})
	if err != nil {
		return solana.Signature{}, err
	}
	res, err := rpc.Confirm(ctx, ch.RPC, sig, lastValid, rpc.Confirmed, rpc.ConfirmOptions{Poll: 200 * time.Millisecond})
	if err != nil {
		return sig, err
	}
	if res.Err != nil {
		return sig, fmt.Errorf("solanastub: %s landed and failed: %s", sig, res.Err)
	}
	return sig, nil
}

// Ticket reads a ticket account; nil when it does not exist.
func (ch *Chain) Ticket(ctx context.Context, operatorID, nodeID uint64, ticketID [16]byte) (*zsescrow.Ticket, error) {
	key := ch.Deployment.Ticket(ch.Deployment.Node(operatorID, nodeID), ticketID)
	acct, err := ch.RPC.GetAccountInfo(ctx, key, rpc.Confirmed)
	if errors.Is(err, rpc.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return zsescrow.DecodeTicket(acct.Data)
}

// Node reads a node account.
func (ch *Chain) Node(ctx context.Context, operatorID, nodeID uint64) (*zsescrow.Node, error) {
	acct, err := ch.RPC.GetAccountInfo(ctx, ch.Deployment.Node(operatorID, nodeID), rpc.Confirmed)
	if err != nil {
		return nil, err
	}
	return zsescrow.DecodeNode(acct.Data)
}

// USDC is owner's balance in its associated token account; 0 when it has none.
func (ch *Chain) USDC(ctx context.Context, owner solana.PublicKey) (uint64, error) {
	acct, err := ch.RPC.GetAccountInfo(ctx, ch.Deployment.TokenAccount(owner), rpc.Confirmed)
	if errors.Is(err, rpc.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	ta, err := zsescrow.DecodeTokenAccount(acct.Data)
	if err != nil {
		return 0, err
	}
	return ta.Amount, nil
}

// Airdrop asks the cluster's faucet for lamports, which only a test cluster
// has, and waits until they arrive.
func (ch *Chain) Airdrop(ctx context.Context, to solana.PublicKey, lamports uint64) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "requestAirdrop", "params": []any{to.String(), lamports}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Result string          `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("solanastub: airdrop: %w", err)
	}
	if out.Error != nil {
		return fmt.Errorf("solanastub: airdrop: %s", out.Error)
	}
	sig, err := solana.ParseSignature(out.Result)
	if err != nil {
		return err
	}
	height, err := ch.RPC.GetBlockHeight(ctx, rpc.Confirmed)
	if err != nil {
		return err
	}
	// The faucet chose the blockhash; one is valid for 150 blocks.
	_, err = rpc.Confirm(ctx, ch.RPC, sig, height+151, rpc.Confirmed, rpc.ConfirmOptions{Poll: 200 * time.Millisecond})
	return err
}

// MintUSDC creates owner's token account if it has none and mints amount
// base units to it; authority is the test mint's.
func (ch *Chain) MintUSDC(ctx context.Context, authority ed25519.PrivateKey, owner solana.PublicKey, amount uint64) error {
	mint := ch.Deployment.Mint
	_, err := ch.Send(ctx, []solana.Instruction{
		solana.CreateAssociatedTokenAccountIdempotent(PublicKey(authority), owner, mint),
		mintTo(mint, ch.Deployment.TokenAccount(owner), PublicKey(authority), amount),
	}, authority)
	return err
}

// tokenMintTo is SPL Token's MintTo tag.
const tokenMintTo = 7

func mintTo(mint, destination, authority solana.PublicKey, amount uint64) solana.Instruction {
	return solana.Instruction{
		ProgramID: solana.TokenProgramID,
		Accounts: []solana.AccountMeta{
			{PublicKey: mint, IsWritable: true},
			{PublicKey: destination, IsWritable: true},
			{PublicKey: authority, IsSigner: true},
		},
		Data: binary.LittleEndian.AppendUint64([]byte{tokenMintTo}, amount),
	}
}

// RegisterNode creates an operator owned by owner and its first node, signing
// with signing and reachable at baseURL. The owner pays the operator stake;
// the first node's is waived.
func (ch *Chain) RegisterNode(ctx context.Context, owner ed25519.PrivateKey, signing solana.PublicKey, baseURL string) (operatorID, nodeID uint64, err error) {
	if err := ch.Refresh(ctx); err != nil {
		return 0, 0, err
	}
	d, ownerKey := ch.Deployment, PublicKey(owner)
	operatorID = ch.Config.NextOperatorID
	if _, err := ch.Send(ctx, []solana.Instruction{d.CreateOperator(ownerKey, d.TokenAccount(ownerKey), operatorID)}, owner); err != nil {
		return 0, 0, fmt.Errorf("solanastub: create operator %d: %w", operatorID, err)
	}
	acct, err := ch.RPC.GetAccountInfo(ctx, d.Operator(operatorID), rpc.Confirmed)
	if err != nil {
		return 0, 0, err
	}
	op, err := zsescrow.DecodeOperator(acct.Data)
	if err != nil {
		return 0, 0, err
	}
	nodeID = op.NextNodeID
	if _, err := ch.Send(ctx, []solana.Instruction{d.CreateNode(ownerKey, d.TokenAccount(ownerKey), operatorID, nodeID, signing, baseURL)}, owner); err != nil {
		return 0, 0, fmt.Errorf("solanastub: create node %d/%d: %w", operatorID, nodeID, err)
	}
	return operatorID, nodeID, nil
}

// PublicKey is key's public half.
func PublicKey(key ed25519.PrivateKey) solana.PublicKey {
	return solana.PublicKey(key.Public().(ed25519.PublicKey))
}

// ReadKeypair reads a solana-keygen keypair file: a JSON array of the 64
// bytes of the seed and the public key.
func ReadKeypair(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b []byte
	var ints []int
	if err := json.Unmarshal(raw, &ints); err != nil {
		return nil, fmt.Errorf("solanastub: %s is not a keypair file: %w", path, err)
	}
	for _, v := range ints {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("solanastub: %s is not a keypair file", path)
		}
		b = append(b, byte(v))
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("solanastub: %s holds %d bytes, want %d", path, len(b), ed25519.PrivateKeySize)
	}
	key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	if !bytes.Equal(key[ed25519.SeedSize:], b[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("solanastub: %s: the public key is not the seed's", path)
	}
	return key, nil
}
