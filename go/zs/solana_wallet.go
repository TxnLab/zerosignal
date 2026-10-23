/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// SolanaWallet opens tickets on the Solana rail, as Wallet does on Algorand:
// it checks the node's open offer against the ticket and the node's
// registered signing key, funds the payer's rent pool, and signs the offer.
// It never submits the open. The node does, from the sealed request's
// payment_open, so the wallet needs a node that reads the rail-neutral names.
type SolanaWallet struct {
	rpc        rpc.Client
	confirm    rpc.ConfirmOptions
	deployment zsescrow.Deployment
	signer     SolanaSigner
	payer      solana.PublicKey
	payerUSDC  solana.PublicKey
	decimals   uint8
	pool       *SolanaRentPool
	slots      uint64
	now        func() time.Time

	// depositMu and depositReady are Wallet's: one top-up at a time, and none
	// once the pool covers the working set.
	depositMu    sync.Mutex
	depositReady bool

	signedMu sync.Mutex
	// signed holds each ticket this wallet signed an open for, by id, with
	// its expires_at. The ack binds the node's open_seq, which is safe only
	// while the payer signs one open per ticket id at a node (SPEC.md § 3a
	// "The open and the ack on Solana"): a second offer for the same ticket,
	// on a fresh blockhash, could open it again once the first closed.
	signed map[[16]byte]int64
}

// signedOpenRetention is how long past a ticket's expires_at the wallet
// remembers signing its open. The program refuses an open past expires_at by
// the cluster's clock, which may trail this machine's; the margin is generous
// because each ticket costs the wallet one map entry.
const signedOpenRetention = 10 * time.Minute

// SolanaWalletConfig is what NewSolanaWallet needs.
type SolanaWalletConfig struct {
	RPC        rpc.Client
	Deployment zsescrow.Deployment
	Signer     SolanaSigner
	// DepositSlots is the rent pool's working set; 0 is DefaultDepositSlots.
	DepositSlots uint64
	// Confirm tunes the wait for a rent deposit or an ack to land; the zero
	// value polls.
	Confirm rpc.ConfirmOptions
}

// NewSolanaWallet reads the deployment's Config for the mint's decimals,
// which an offer's transfer must carry. The Config must name the deployment's
// mint: the wallet would otherwise check offers against one mint while the
// program draws on another.
func NewSolanaWallet(ctx context.Context, cfg SolanaWalletConfig) (*SolanaWallet, error) {
	if cfg.RPC == nil || cfg.Signer == nil {
		return nil, errors.New("solana wallet: RPC and Signer are required")
	}
	payer, err := solana.ParsePublicKey(cfg.Signer.Address())
	if err != nil {
		return nil, fmt.Errorf("solana wallet: payer address: %w", err)
	}
	acct, err := cfg.RPC.GetAccountInfo(ctx, cfg.Deployment.Config(), rentCommitment)
	if err != nil {
		return nil, fmt.Errorf("solana wallet: read config: %w", err)
	}
	if acct == nil || acct.Owner != cfg.Deployment.Program {
		return nil, fmt.Errorf("solana wallet: program %s has no Config", cfg.Deployment.Program)
	}
	c, err := zsescrow.DecodeConfig(acct.Data)
	if err != nil {
		return nil, fmt.Errorf("solana wallet: %w", err)
	}
	if c.USDCMint != cfg.Deployment.Mint {
		return nil, fmt.Errorf("solana wallet: the Config's mint is %s, not the deployment's %s", c.USDCMint, cfg.Deployment.Mint)
	}
	return &SolanaWallet{
		rpc:        cfg.RPC,
		confirm:    cfg.Confirm,
		deployment: cfg.Deployment,
		signer:     cfg.Signer,
		payer:      payer,
		payerUSDC:  cfg.Deployment.TokenAccount(payer),
		decimals:   c.USDCDecimals,
		pool:       &SolanaRentPool{RPC: cfg.RPC, Deployment: cfg.Deployment, Signer: cfg.Signer, Confirm: cfg.Confirm},
		slots:      cfg.DepositSlots,
		now:        time.Now,
		signed:     map[[16]byte]int64{},
	}, nil
}

// PayerAddr is the payer's base58 address.
func (w *SolanaWallet) PayerAddr() string { return w.payer.String() }

// Open refuses: dispatch calls it only for a node that doesn't submit the
// open itself, and on Solana the node always does.
func (w *SolanaWallet) Open(context.Context, *ticket.Ticket, Operator, string) (*OpenHandle, error) {
	return nil, errors.New("wallet: open: on Solana the node submits the open (OpenForNode)")
}

func errRailNeutralNames(op Operator) error {
	return fmt.Errorf("wallet: open: node runs protocol %q; a Solana open needs %s or later", op.ProtoVersion, wire.RailNeutralNamesMinVersion)
}

// OpenForNode checks the node's offer (presigned_open_txn) against tk and op,
// tops up the rent pool, and signs the offer. The handle carries the signed
// transaction as OpenGroup (payment_open) and its id as AppCallTxID
// (payment_ref). Nothing is broadcast: the open lands when the node submits
// it, before tk's expires_at or not at all.
func (w *SolanaWallet) OpenForNode(ctx context.Context, tk *ticket.Ticket, op Operator, presignedOpen string) (*OpenHandle, error) {
	if !wire.UsesRailNeutralNames(op.ProtoVersion) {
		return nil, errRailNeutralNames(op)
	}
	if tk == nil {
		return nil, errors.New("wallet: open: ticket is nil")
	}
	if op.ID == 0 {
		return nil, errors.New("wallet: open: operator id is unset")
	}
	if op.OwnerAddr == "" || op.SigningAddr == "" {
		return nil, errors.New("wallet: open: operator addresses incomplete")
	}
	if presignedOpen == "" {
		return nil, errors.New("wallet: open: presigned open offer is empty (operator did not return one on reserve)")
	}
	offer, err := zsescrow.DecodeOpenOffer(presignedOpen)
	if err != nil {
		return nil, fmt.Errorf("wallet: open: decode presigned open offer: %w", err)
	}
	ticketIDRaw, err := decodeTicketID(tk.TicketID)
	if err != nil {
		return nil, fmt.Errorf("wallet: decode ticket id: %w", err)
	}
	// As on Algorand: VerifyReceipt refuses a receipt for any other spelling.
	if canonical := base64.StdEncoding.EncodeToString(ticketIDRaw); canonical != tk.TicketID {
		return nil, fmt.Errorf("wallet: decode ticket id: %q is not the canonical spelling %q", tk.TicketID, canonical)
	}
	ticketID := [16]byte(ticketIDRaw)
	nodeSigning, err := solana.ParsePublicKey(op.SigningAddr)
	if err != nil {
		return nil, fmt.Errorf("wallet: decode node signing addr: %w", err)
	}
	// Every value from the signature-verified ticket, the operator's
	// chain-resolved signing key and the Config, never from the offer.
	spec := zsescrow.OpenOfferSpec{
		NodeSigning: nodeSigning,
		OperatorID:  tk.OperatorID,
		NodeID:      tk.NodeID,
		Payer:       w.payer,
		PayerUSDC:   w.payerUSDC,
		Decimals:    w.decimals,
		TicketID:    ticketID,
		MaxPrice:    tk.MaxPrice,
		ExpiresAt:   tk.ExpiresAt,
	}
	// Claimed before the deposit, so a ticket already signed for costs no
	// top-up, and released if nothing gets signed.
	if err := w.claimOpen(ticketID, tk.ExpiresAt); err != nil {
		return nil, err
	}
	signed := false
	defer func() {
		if !signed {
			w.releaseOpen(ticketID)
		}
	}()
	// The open draws the ticket's rent from the pool and fails without it.
	// Nothing reached the chain, so a pool too short at submit surfaces at
	// the node, which refuses the request, and dispatch answers that with
	// RecheckDeposit.
	if err := w.ensureDepositForServe(ctx); err != nil {
		return nil, fmt.Errorf("wallet: ensure rent deposit: %w", err)
	}
	completed, err := zsescrow.CompleteOpenOffer(ctx, w.deployment, offer, spec, w.signer)
	if err != nil {
		return nil, fmt.Errorf("wallet: complete open offer: %w", err)
	}
	signed = true
	paymentOpen, paymentRef, err := zsescrow.EncodeOpenPayment(completed)
	if err != nil {
		return nil, fmt.Errorf("wallet: complete open offer: %w", err)
	}
	return &OpenHandle{
		AppCallTxID: paymentRef,
		TicketID:    tk.TicketID,
		Operator:    op,
		MaxPrice:    tk.MaxPrice,
		SignedGroup: [][]byte{completed},
		OpenGroup:   paymentOpen,
		solana:      w,
	}, nil
}

// claimOpen records that the wallet is about to sign an open for id, or
// refuses when it has signed one already or another call is signing one. It
// forgets tickets whose opens can no longer land.
func (w *SolanaWallet) claimOpen(id [16]byte, expiresAt int64) error {
	w.signedMu.Lock()
	defer w.signedMu.Unlock()
	horizon := w.now().Add(-signedOpenRetention).Unix()
	for k, exp := range w.signed {
		if exp < horizon {
			delete(w.signed, k)
		}
	}
	if _, ok := w.signed[id]; ok {
		return fmt.Errorf("wallet: open: already signed, or is signing, an open for ticket %s", base64.StdEncoding.EncodeToString(id[:]))
	}
	w.signed[id] = expiresAt
	return nil
}

func (w *SolanaWallet) releaseOpen(id [16]byte) {
	w.signedMu.Lock()
	defer w.signedMu.Unlock()
	delete(w.signed, id)
}

// ensureDepositForServe is Wallet.ensureDepositForServe for the rent pool: a
// top-up the payer can't afford, or one that fell short, still serves while
// the pool can fund this one ticket.
func (w *SolanaWallet) ensureDepositForServe(ctx context.Context) error {
	w.depositMu.Lock()
	defer w.depositMu.Unlock()
	if w.depositReady {
		return nil
	}
	_, _, err := w.pool.EnsureDeposit(ctx, w.slots)
	if err == nil {
		w.depositReady = true
		return nil
	}
	if errors.Is(err, ErrDepositUnaffordable) || errors.Is(err, ErrDepositBelowTarget) {
		if free, ferr := w.pool.FreeSlots(ctx); ferr == nil && free >= 1 {
			return nil
		}
	}
	return err
}

// RecheckDeposit clears the ready latch, so the next open reads the pool
// again: a node refused an open the wallet signed, perhaps for a pool emptied
// outside this wallet.
func (w *SolanaWallet) RecheckDeposit() {
	w.depositMu.Lock()
	w.depositReady = false
	w.depositMu.Unlock()
}
