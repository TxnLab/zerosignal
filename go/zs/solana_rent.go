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

var (
	// ErrNoRentPool is a withdraw or close on a payer with no rent pool.
	ErrNoRentPool = errors.New("solana rent pool: this payer has no rent pool")
	// ErrRentPoolTicketsOpen is a close while tickets the pool funded are
	// live: their rent returns to the pool when each ends, and the program
	// refuses the close until then.
	ErrRentPoolTicketsOpen = errors.New("solana rent pool: tickets the pool funded are still open")
)

// SolanaRentPoolStatus is a payer's rent pool as the chain shows it, with the
// cluster's rent figures it is read against.
type SolanaRentPoolStatus struct {
	// Exists is a pool the program owns; lamports someone sent to the address
	// before the first deposit don't make one.
	Exists bool
	// Lamports is the pool account's, its own rent included.
	Lamports    uint64
	OpenTickets uint64
	// TicketRent is a ticket's rent exemption, what each open draws; never 0.
	TicketRent uint64
	// PoolRent is the pool account's own rent exemption.
	PoolRent uint64
}

// Available is what an open can draw and a withdraw can take: the pool's
// lamports above its own rent exemption. A live ticket's rent sits in the
// ticket, not here.
func (s SolanaRentPoolStatus) Available() uint64 {
	if !s.Exists {
		return 0
	}
	return s.Lamports - min(s.Lamports, s.PoolRent)
}

// FreeSlots is how many more tickets the pool can fund right now. The zero
// status, which a failed read returns, has none.
func (s SolanaRentPoolStatus) FreeSlots() uint64 {
	if s.TicketRent == 0 {
		return 0
	}
	return s.Available() / s.TicketRent
}

// BackedSlots is how many concurrent tickets the pool backs counting the live
// ones, the figure a working set is compared against.
func (s SolanaRentPoolStatus) BackedSlots() uint64 {
	if s.TicketRent == 0 {
		return 0
	}
	return rentPoolGross(s.TicketRent, s.PoolRent, s.reading()) / s.TicketRent
}

// Shortfall is DepositShortfall on Solana: the lamports the pool needs to back
// slots tickets, on the gross basis EnsureDeposit sizes on, so tickets in
// flight don't read as a shortfall. A first deposit also pays the pool's own
// rent, which this leaves out, as EnsureDeposit's target does.
func (s SolanaRentPoolStatus) Shortfall(slots uint64) uint64 {
	if s.TicketRent == 0 {
		return 0
	}
	target := poolTarget(slots, s.TicketRent, 0)
	if gross := rentPoolGross(s.TicketRent, s.PoolRent, s.reading()); gross < target {
		return target - gross
	}
	return 0
}

// Excess is DepositExcess on Solana: what the pool holds above slots tickets'
// rent, on the same gross basis. It sizes a shrink and is not what a withdraw
// can take, which is bounded by Available: live tickets hold the difference.
func (s SolanaRentPoolStatus) Excess(slots uint64) uint64 {
	if s.TicketRent == 0 {
		return 0
	}
	target := poolTarget(slots, s.TicketRent, 0)
	if gross := rentPoolGross(s.TicketRent, s.PoolRent, s.reading()); gross > target {
		return gross - target
	}
	return 0
}

func (s SolanaRentPoolStatus) reading() rentPoolReading {
	return rentPoolReading{exists: s.Exists, lamports: s.Lamports, openTickets: s.OpenTickets}
}

// ReadSolanaRentPool reads payer's rent pool without a signer, so a host can
// show it for a wallet it has not unlocked.
func ReadSolanaRentPool(ctx context.Context, rc rpc.Client, d zsescrow.Deployment, payer solana.PublicKey) (SolanaRentPoolStatus, error) {
	var s SolanaRentPoolStatus
	if rc == nil {
		return s, errors.New("solana rent pool: RPC is required")
	}
	var err error
	if s.TicketRent, err = rc.GetMinimumBalanceForRentExemption(ctx, zsescrow.TicketSize, rentCommitment); err != nil {
		return s, fmt.Errorf("solana rent pool: ticket rent: %w", err)
	}
	if s.TicketRent == 0 {
		return s, errors.New("solana rent pool: the cluster quotes no ticket rent")
	}
	if s.PoolRent, err = rc.GetMinimumBalanceForRentExemption(ctx, zsescrow.RentPoolSize, rentCommitment); err != nil {
		return s, fmt.Errorf("solana rent pool: pool rent: %w", err)
	}
	acct, err := getAccount(ctx, rc, d.RentPool(payer))
	if err != nil {
		return s, fmt.Errorf("solana rent pool: read pool: %w", err)
	}
	if acct != nil && acct.Owner == d.Program {
		rp, err := zsescrow.DecodeRentPool(acct.Data)
		if err != nil {
			return s, fmt.Errorf("solana rent pool: %w", err)
		}
		s.Exists, s.Lamports, s.OpenTickets = true, acct.Lamports, rp.OpenTickets
	}
	return s, nil
}

type rentPoolState struct {
	payer      solana.PublicKey
	pool       rentPoolReading
	ticketRent uint64
	poolRent   uint64
}

func (p *SolanaRentPool) payer() (solana.PublicKey, error) {
	if p.RPC == nil || p.Signer == nil {
		return solana.PublicKey{}, errors.New("solana rent pool: RPC and Signer are required")
	}
	payer, err := solana.ParsePublicKey(p.Signer.Address())
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("solana rent pool: payer address: %w", err)
	}
	return payer, nil
}

func (p *SolanaRentPool) read(ctx context.Context) (rentPoolState, error) {
	payer, err := p.payer()
	if err != nil {
		return rentPoolState{}, err
	}
	st, err := ReadSolanaRentPool(ctx, p.RPC, p.Deployment, payer)
	if err != nil {
		return rentPoolState{}, err
	}
	return rentPoolState{payer: payer, pool: st.reading(), ticketRent: st.TicketRent, poolRent: st.PoolRent}, nil
}

// Status is the signer's pool, as ReadSolanaRentPool reads it.
func (p *SolanaRentPool) Status(ctx context.Context) (SolanaRentPoolStatus, error) {
	payer, err := p.payer()
	if err != nil {
		return SolanaRentPoolStatus{}, err
	}
	return ReadSolanaRentPool(ctx, p.RPC, p.Deployment, payer)
}

// FreeSlots is how many more tickets the pool can fund right now: an open
// needs one, so the serving path proceeds on a pool short of its working set
// while this is at least 1, as freeDepositSlots does for Algorand.
func (p *SolanaRentPool) FreeSlots(ctx context.Context) (uint64, error) {
	s, err := p.Status(ctx)
	if err != nil {
		return 0, err
	}
	return s.FreeSlots(), nil
}

// Withdraw takes lamports back from the pool, at most its Available, as
// Algorand's withdrawMbr. It returns once the withdraw is confirmed; one sent
// but not confirmed returns its signature beside the error.
func (p *SolanaRentPool) Withdraw(ctx context.Context, lamports uint64) (string, error) {
	s, err := p.read(ctx)
	if err != nil {
		return "", err
	}
	if !s.pool.exists {
		return "", ErrNoRentPool
	}
	available := SolanaRentPoolStatus{Exists: true, Lamports: s.pool.lamports, PoolRent: s.poolRent}.Available()
	if lamports == 0 || lamports > available {
		return "", fmt.Errorf("solana rent pool: withdraw %d lamports: the pool holds %d above its own rent", lamports, available)
	}
	return p.send(ctx, s.payer, "withdraw", p.Deployment.WithdrawRent(s.payer, lamports))
}

// Close closes the pool and returns all of it, its own rent included, as
// Algorand's closeDeposit, and the lamports it held. It refuses before
// signing while a ticket the pool funded is open.
func (p *SolanaRentPool) Close(ctx context.Context) (sig string, returned uint64, err error) {
	s, err := p.read(ctx)
	if err != nil {
		return "", 0, err
	}
	if !s.pool.exists {
		return "", 0, ErrNoRentPool
	}
	if s.pool.openTickets > 0 {
		return "", 0, fmt.Errorf("%w: %d", ErrRentPoolTicketsOpen, s.pool.openTickets)
	}
	sig, err = p.send(ctx, s.payer, "close", p.Deployment.CloseRentPool(s.payer))
	if err != nil {
		return sig, 0, err
	}
	return sig, s.pool.lamports, nil
}

// send signs ix as the payer's own transaction, sends it and waits for it to
// confirm. A transaction sent but not confirmed returns its signature beside
// the error: unless it expired it may still land, so the caller looks before
// it sends another.
func (p *SolanaRentPool) send(ctx context.Context, payer solana.PublicKey, what string, ix solana.Instruction) (string, error) {
	bh, err := p.RPC.GetLatestBlockhash(ctx, rentCommitment)
	if err != nil {
		return "", fmt.Errorf("solana rent pool: blockhash: %w", err)
	}
	msg, err := solana.Compile(payer, bh.Hash, []solana.Instruction{ix}, solana.Legacy)
	if err != nil {
		return "", fmt.Errorf("solana rent pool: %w", err)
	}
	tx := solana.NewTransaction(msg)
	if err := tx.SignWith(ctx, payer, p.Signer); err != nil {
		return "", fmt.Errorf("solana rent pool: %w", err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("solana rent pool: %w", err)
	}
	// Preflight at the commitment the plan read, not the RPC's finalized
	// default, which may not see the lamports the plan counted.
	txSig, err := p.RPC.SendTransaction(ctx, raw, rpc.SendOptions{PreflightCommitment: rentCommitment})
	if err != nil {
		return "", fmt.Errorf("solana rent pool: send %s: %w", what, err)
	}
	r, err := rpc.Confirm(ctx, p.RPC, txSig, bh.LastValidBlockHeight, rentCommitment, p.Confirm)
	if err != nil {
		return txSig.String(), fmt.Errorf("solana rent pool: %s %s: %w", what, txSig, err)
	}
	if r.Err != nil {
		return "", fmt.Errorf("solana rent pool: %s %s failed: %s", what, txSig, rpc.TxErrName(r.Err))
	}
	return txSig.String(), nil
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

	txSig, err := p.send(ctx, s.payer, "deposit", p.Deployment.DepositRent(s.payer, plan.Amount))
	if err != nil {
		return txSig, 0, err
	}
	if plan.BelowTarget {
		return txSig, plan.Amount, fmt.Errorf("%w: deposited %d lamports, still %d lamports short of %d slot(s) — add SOL and deposit again",
			ErrRentDepositBelowTarget, plan.Amount, target-min(gross+plan.Amount, target), slots)
	}
	return txSig, plan.Amount, nil
}
