/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"github.com/TxnLab/zerosignal/go/settle"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// What a Solana payer's host needs beyond the serving path: the reads and
// calls Algorand's hosts make through the escrow client, for a CLI's fund,
// status, tickets and recovery.

// ReadSolanaConfig reads and decodes the program's Config, which names the
// USDC mint, its decimals and the protocol fee.
func ReadSolanaConfig(ctx context.Context, rc rpc.Client, program solana.PublicKey) (*zsescrow.Config, error) {
	return readSolanaConfig(ctx, rc, zsescrow.Deployment{Program: program})
}

// The production Solana wallet must satisfy feeRateCapable, as Wallet does;
// without it a Solana payer's /v1/models carries no price and its reserve
// check bounds the fee by the cap instead of the Config's.
var _ feeRateCapable = (*SolanaWallet)(nil)

// ProtocolFeeBps reads the Config's fee_bps, the protocol fee on top of an
// operator's charge that a ticket opened now pays. set_config can change it,
// so it is read each time rather than kept from NewSolanaWallet.
func (w *SolanaWallet) ProtocolFeeBps(ctx context.Context) (uint64, error) {
	c, err := readSolanaConfig(ctx, w.rpc, w.deployment)
	if err != nil {
		return 0, fmt.Errorf("solana wallet: %w", err)
	}
	return uint64(c.FeeBps), nil
}

// USDCAccount is the payer's associated USDC account, which every offer
// draws on and every refund pays.
func (w *SolanaWallet) USDCAccount() string { return w.payerUSDC.String() }

// EnsureUSDCAccount creates the payer's USDC account when the token program
// holds none at its address, and returns the transaction's signature, "" when
// the account was there. Nothing is checked beyond existence: a frozen
// account, or one of another mint, is the node's to refuse and doctor's to
// report.
func (w *SolanaWallet) EnsureUSDCAccount(ctx context.Context) (string, error) {
	acct, err := getAccount(ctx, w.rpc, w.payerUSDC)
	if err != nil {
		return "", fmt.Errorf("solana wallet: read the payer's token account: %w", err)
	}
	if acct != nil && acct.Owner == solana.TokenProgramID {
		return "", nil
	}
	r, err := w.send(ctx, "create usdc account", []solana.Instruction{
		solana.CreateAssociatedTokenAccountIdempotent(w.payer, w.payer, w.deployment.Mint),
	}, solanaSignatureFee)
	return r.Sig, err
}

// ErrSolanaTicketGone is a ticket with no account: never opened, or ended.
var ErrSolanaTicketGone = errors.New("solana wallet: no ticket account: never opened, or already ended")

// RecoverTicket ends one of this payer's tickets with the call the program
// allows now, by zsescrow.Classify on a fresh read: refund_inactive or
// settle_lapsed, which anyone may send and the node's own sweep races. It
// returns the verdict, and the signature when it sent one; any other verdict
// sends nothing. It is the CLI's manual path for what the refund watchdog and
// the reconciler missed. The deadline is padded by reconcileSkew, as the
// reconciler's is, since the program reads the cluster's clock.
func (w *SolanaWallet) RecoverTicket(ctx context.Context, operatorID, nodeID uint64, id [16]byte) (settle.Verdict, string, error) {
	t, err := w.readTicket(ctx, operatorID, nodeID, id)
	if err != nil {
		return settle.VerdictUnknown, "", err
	}
	if t == nil {
		return settle.VerdictUnknown, "", ErrSolanaTicketGone
	}
	if err := w.ownsTicket("recover", t); err != nil {
		return settle.VerdictUnknown, "", err
	}
	verdict := zsescrow.Classify(t, w.now().Add(-reconcileSkew))
	// The ending is built from this read: a second one could find the
	// ticket closed by the race and report it as something else.
	var r solanaAck
	switch verdict {
	case settle.VerdictRefund:
		r, err = w.endRead(ctx, "refund-inactive", t, operatorID, nodeID, id, w.deployment.RefundInactive)
	case settle.VerdictLapse:
		r, err = w.endRead(ctx, "settle-lapsed", t, operatorID, nodeID, id, w.deployment.SettleLapsed)
	}
	return verdict, r.Sig, err
}

// CloseRentPool closes the payer's rent pool (SolanaRentPool.Close) and
// clears the ready latch, as Wallet.CloseDeposit does, so the next open tops
// the pool up again rather than signing an offer the program refuses for
// want of one.
func (w *SolanaWallet) CloseRentPool(ctx context.Context) (sig string, returned uint64, err error) {
	sig, returned, err = w.pool.Close(ctx)
	w.RecheckDeposit()
	return sig, returned, err
}

// RentPool is the wallet's rent pool, for a host's status and withdraw.
func (w *SolanaWallet) RentPool() *SolanaRentPool { return w.pool }

// SolanaPayerTicket is one of a payer's live tickets and the node it is at.
type SolanaPayerTicket struct {
	Address    solana.PublicKey
	OperatorID uint64
	NodeID     uint64
	Ticket     *zsescrow.Ticket
}

// SolanaUnreadableTicket is an account that matched the payer's filter but
// can't be read as one of its tickets, and why.
type SolanaUnreadableTicket struct {
	Address solana.PublicKey
	Err     error
}

// SolanaPayerTickets is what one read says about a payer's tickets.
type SolanaPayerTickets struct {
	// Tickets are ordered by deadline, the soonest first.
	Tickets []SolanaPayerTicket
	// Unreadable are accounts carrying the payer's key where a ticket keeps
	// it that this build can't decode or place, which escrow.FetchAllTickets
	// reports as Unreadable. Unlike Algorand's, they are the payer's: the
	// filter matched its key.
	Unreadable []SolanaUnreadableTicket
}

// FetchSolanaPayerTickets lists payer's live tickets: every Ticket account
// the program holds with payer at TicketPayerOffset, each placed at its node
// by reading the node's account. A ticket account exists only until its
// ticket ends, so this is what still holds the payer's USDC and rent.
func FetchSolanaPayerTickets(ctx context.Context, rc rpc.Client, d zsescrow.Deployment, payer solana.PublicKey) (SolanaPayerTickets, error) {
	var out SolanaPayerTickets
	if rc == nil {
		return out, errors.New("solana tickets: RPC is required")
	}
	accts, err := rc.GetProgramAccounts(ctx, d.Program, rentCommitment,
		solanaAccountFilter("Ticket"), rpc.Memcmp(zsescrow.TicketPayerOffset, payer[:]))
	if err != nil {
		return out, fmt.Errorf("solana tickets: %w", err)
	}
	nodes := map[solana.PublicKey]*solanaNodeIDs{}
	for _, a := range accts {
		t, err := zsescrow.DecodeTicket(a.Account.Data)
		if err != nil {
			out.Unreadable = append(out.Unreadable, SolanaUnreadableTicket{a.Key, err})
			continue
		}
		ids, seen := nodes[t.Node]
		if !seen {
			ids, err = readNodeIDs(ctx, rc, d, t.Node)
			if err != nil {
				return SolanaPayerTickets{}, err
			}
			nodes[t.Node] = ids
		}
		switch {
		case ids == nil:
			err = fmt.Errorf("its node %s is not a readable node of the program", t.Node)
		case d.Ticket(t.Node, t.TicketID) != a.Key:
			err = fmt.Errorf("its stored ticket id %s doesn't derive its address", base64.StdEncoding.EncodeToString(t.TicketID[:]))
		}
		if err != nil {
			out.Unreadable = append(out.Unreadable, SolanaUnreadableTicket{a.Key, err})
			continue
		}
		out.Tickets = append(out.Tickets, SolanaPayerTicket{Address: a.Key, OperatorID: ids.operator, NodeID: ids.node, Ticket: t})
	}
	slices.SortFunc(out.Tickets, func(a, b SolanaPayerTicket) int {
		return cmp.Or(cmp.Compare(a.Ticket.Deadline(), b.Ticket.Deadline()), bytes.Compare(a.Address[:], b.Address[:]))
	})
	return out, nil
}

type solanaNodeIDs struct{ operator, node uint64 }

// readNodeIDs is the operator and node id of the node account at key, nil
// when no node of the program is there. A read that fails is an error, so a
// flaky RPC fails the listing rather than marking tickets unreadable.
func readNodeIDs(ctx context.Context, rc rpc.Client, d zsescrow.Deployment, key solana.PublicKey) (*solanaNodeIDs, error) {
	acct, err := getAccount(ctx, rc, key)
	if err != nil {
		return nil, fmt.Errorf("solana tickets: read node %s: %w", key, err)
	}
	if acct == nil || acct.Owner != d.Program {
		return nil, nil
	}
	n, err := zsescrow.DecodeNode(acct.Data)
	if err != nil || d.Node(n.OperatorID, n.NodeID) != key {
		return nil, nil
	}
	return &solanaNodeIDs{n.OperatorID, n.NodeID}, nil
}
