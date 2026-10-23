/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// railSentinel is a Solana sentinel that also matches its Algorand twin, so
// the serving path's branches on ErrDepositUnaffordable and
// ErrDepositBelowTarget take the rent pool's errors the same way, while the
// message names SOL.
type railSentinel struct {
	msg  string
	twin error
}

func (e *railSentinel) Error() string        { return e.msg }
func (e *railSentinel) Is(target error) bool { return target == e.twin }

var (
	// ErrRentDepositUnaffordable is ErrDepositUnaffordable on the Solana
	// rail: the payer's SOL can't complete another ticket's rent plus the
	// deposit's fee (and the pool's own rent on a first deposit).
	ErrRentDepositUnaffordable error = &railSentinel{"wallet: insufficient SOL to fund the ticket rent pool", ErrDepositUnaffordable}
	// ErrRentDepositBelowTarget is ErrDepositBelowTarget on the Solana rail:
	// the deposit landed, short of the working set.
	ErrRentDepositBelowTarget error = &railSentinel{"wallet: ticket rent pool funded below the configured working set", ErrDepositBelowTarget}
)

// solanaSignatureFee is the lamports a fee payer pays for each signature. A
// deposit carries the payer's alone and sets no priority fee.
const solanaSignatureFee uint64 = 5_000

// rentCommitment is confirmed, as the registry reads: a payer that just
// funded its wallet sees the lamports in about a second.
const rentCommitment = rpc.Confirmed

// getAccount reads key at rentCommitment, nil when it has no account: the RPC
// client reports that as rpc.ErrNotFound, and every account the payer reads
// may be absent (a first-time payer's pool, a closed ticket or token account).
func getAccount(ctx context.Context, c rpc.Client, key solana.PublicKey) (*rpc.Account, error) {
	a, err := c.GetAccountInfo(ctx, key, rentCommitment)
	if errors.Is(err, rpc.ErrNotFound) {
		return nil, nil
	}
	return a, err
}

// rentPoolReading is the payer's rent pool as the chain shows it.
type rentPoolReading struct {
	// exists is a pool the program owns. Lamports someone sent to the
	// address before the first deposit don't make one: the deposit still
	// creates it, so it is planned as though the address were empty.
	exists      bool
	lamports    uint64
	openTickets uint64
}

// rentPoolGross is what the pool backs counting its live tickets, whose rent
// sits in the tickets rather than the pool, saturating: the basis
// planPoolDeposit sizes on, as Algorand's gross AlgoBalance is.
func rentPoolGross(ticketRent, poolRent uint64, pool rentPoolReading) uint64 {
	if !pool.exists {
		return 0
	}
	available := pool.lamports - min(pool.lamports, poolRent)
	hi, live := bits.Mul64(pool.openTickets, ticketRent)
	gross, carry := bits.Add64(available, live, 0)
	if hi != 0 || carry != 0 {
		return math.MaxUint64
	}
	return gross
}

// planRentDeposit sizes a top-up of the Solana rent pool by planDeposit's
// rule, with a ticket's rent as the slot. There is no quota term, and the
// overhead is the deposit's fee plus, on a first deposit, the pool's own rent,
// which deposit_rent charges the payer on top of the amount. spendable is the
// payer's lamports above its own reserve. Pinned by
// testdata/rent_deposit_plan_vectors.json. ticketRent must be non-zero.
func planRentDeposit(slots, ticketRent, poolRent uint64, pool rentPoolReading, spendable uint64) depositPlan {
	overhead := solanaSignatureFee
	if !pool.exists {
		overhead += poolRent
	}
	return planPoolDeposit(slots, ticketRent, 0, rentPoolGross(ticketRent, poolRent, pool), overhead, spendable)
}

// SolanaRentPool funds a payer's ticket rent pool on the Solana rail, as
// Wallet.EnsureDeposit funds Algorand's prepaid MBR pool. The pool pays each
// ticket's rent at open, and a ticket's ending returns it.
type SolanaRentPool struct {
	RPC        rpc.Client
	Deployment zsescrow.Deployment
	Signer     SolanaSigner
	// Confirm tunes the wait for a deposit to land; the zero value polls.
	Confirm rpc.ConfirmOptions
}

type rentPoolState struct {
	payer      solana.PublicKey
	pool       rentPoolReading
	ticketRent uint64
	poolRent   uint64
}

func (p *SolanaRentPool) read(ctx context.Context) (rentPoolState, error) {
	var s rentPoolState
	if p.RPC == nil || p.Signer == nil {
		return s, errors.New("solana rent pool: RPC and Signer are required")
	}
	payer, err := solana.ParsePublicKey(p.Signer.Address())
	if err != nil {
		return s, fmt.Errorf("solana rent pool: payer address: %w", err)
	}
	s.payer = payer
	if s.ticketRent, err = p.RPC.GetMinimumBalanceForRentExemption(ctx, zsescrow.TicketSize, rentCommitment); err != nil {
		return s, fmt.Errorf("solana rent pool: ticket rent: %w", err)
	}
	if s.ticketRent == 0 {
		return s, errors.New("solana rent pool: the cluster quotes no ticket rent")
	}
	if s.poolRent, err = p.RPC.GetMinimumBalanceForRentExemption(ctx, zsescrow.RentPoolSize, rentCommitment); err != nil {
		return s, fmt.Errorf("solana rent pool: pool rent: %w", err)
	}
	acct, err := getAccount(ctx, p.RPC, p.Deployment.RentPool(payer))
	if err != nil {
		return s, fmt.Errorf("solana rent pool: read pool: %w", err)
	}
	if acct != nil && acct.Owner == p.Deployment.Program {
		rp, err := zsescrow.DecodeRentPool(acct.Data)
		if err != nil {
			return s, fmt.Errorf("solana rent pool: %w", err)
		}
		s.pool = rentPoolReading{exists: true, lamports: acct.Lamports, openTickets: rp.OpenTickets}
	}
	return s, nil
}

// FreeSlots is how many more tickets the pool can fund right now: an open
// needs one, so the serving path proceeds on a pool short of its working set
// while this is at least 1, as freeDepositSlots does for Algorand.
func (p *SolanaRentPool) FreeSlots(ctx context.Context) (uint64, error) {
	s, err := p.read(ctx)
	if err != nil {
		return 0, err
	}
	if !s.pool.exists {
		return 0, nil
	}
	return (s.pool.lamports - min(s.pool.lamports, s.poolRent)) / s.ticketRent, nil
}

// EnsureDeposit makes sure the pool is sized for slots concurrent tickets (0:
// DefaultDepositSlots), creating it on the first deposit, and returns the
// deposit's signature and lamports. It has EnsureDeposit's contract: a no-op
// when the pool already covers the set, ErrRentDepositBelowTarget beside a real
// deposit that fell short, and ErrRentDepositUnaffordable, naming the lamports
// needed, before anything is signed. It returns once the deposit is confirmed;
// a deposit sent but not confirmed returns its signature beside the error.
//
// Not single-flight: two concurrent calls can each read the pool short and
// both deposit.
func (p *SolanaRentPool) EnsureDeposit(ctx context.Context, slots uint64) (sig string, deposited uint64, err error) {
	if slots == 0 {
		slots = DefaultDepositSlots
	}
	s, err := p.read(ctx)
	if err != nil {
		return "", 0, err
	}
	target := poolTarget(slots, s.ticketRent, 0)
	gross := rentPoolGross(s.ticketRent, s.poolRent, s.pool)
	if gross >= target {
		return "", 0, nil
	}
	balance, err := p.RPC.GetBalance(ctx, s.payer, rentCommitment)
	if err != nil {
		return "", 0, fmt.Errorf("solana rent pool: balance: %w", err)
	}
	spendable := solanaSpendableLamports(balance)

	plan := planRentDeposit(slots, s.ticketRent, s.poolRent, s.pool, spendable)
	if plan.Amount == 0 {
		var firstDeposit string
		if !s.pool.exists {
			firstDeposit = fmt.Sprintf(" + %d pool rent", s.poolRent)
		}
		return "", 0, fmt.Errorf("%w: the pool backs %d of %d slot(s); one more slot needs %d lamports (%d + %d fee%s), have %d lamports spendable — fund the wallet with more SOL",
			ErrRentDepositUnaffordable, gross/s.ticketRent, slots, plan.Need, s.ticketRent-gross%s.ticketRent, solanaSignatureFee, firstDeposit, spendable)
	}

	bh, err := p.RPC.GetLatestBlockhash(ctx, rentCommitment)
	if err != nil {
		return "", 0, fmt.Errorf("solana rent pool: blockhash: %w", err)
	}
	msg, err := solana.Compile(s.payer, bh.Hash, []solana.Instruction{p.Deployment.DepositRent(s.payer, plan.Amount)}, solana.Legacy)
	if err != nil {
		return "", 0, fmt.Errorf("solana rent pool: %w", err)
	}
	tx := solana.NewTransaction(msg)
	if err := tx.SignWith(ctx, s.payer, p.Signer); err != nil {
		return "", 0, fmt.Errorf("solana rent pool: %w", err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return "", 0, fmt.Errorf("solana rent pool: %w", err)
	}
	// Preflight at the commitment the plan read, not the RPC's finalized
	// default, which may not see the lamports the plan counted.
	txSig, err := p.RPC.SendTransaction(ctx, raw, rpc.SendOptions{PreflightCommitment: rentCommitment})
	if err != nil {
		return "", 0, fmt.Errorf("solana rent pool: send deposit: %w", err)
	}
	r, err := rpc.Confirm(ctx, p.RPC, txSig, bh.LastValidBlockHeight, rentCommitment, p.Confirm)
	if err != nil {
		// Unless it expired, the deposit may still land: the signature lets
		// the caller look before it sends another.
		return txSig.String(), 0, fmt.Errorf("solana rent pool: deposit %s: %w", txSig, err)
	}
	if r.Err != nil {
		return "", 0, fmt.Errorf("solana rent pool: deposit %s failed: %s", txSig, rpc.TxErrName(r.Err))
	}
	if plan.BelowTarget {
		return txSig.String(), plan.Amount, fmt.Errorf("%w: deposited %d lamports, still %d lamports short of %d slot(s) — add SOL and deposit again",
			ErrRentDepositBelowTarget, plan.Amount, target-min(gross+plan.Amount, target), slots)
	}
	return txSig.String(), plan.Amount, nil
}
