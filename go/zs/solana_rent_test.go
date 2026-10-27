/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

const (
	testTicketRent = (128 + zsescrow.TicketSize) * 6_960
	testPoolRent   = (128 + zsescrow.RentPoolSize) * 6_960
)

// testSolanaSigner signs as one in-memory key.
type testSolanaSigner struct{ key ed25519.PrivateKey }

func newTestSolanaSigner() testSolanaSigner {
	return testSolanaSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))}
}

func (s testSolanaSigner) pub() solana.PublicKey {
	return solana.PublicKey(s.key.Public().(ed25519.PublicKey))
}
func (s testSolanaSigner) Address() string { return s.pub().String() }
func (s testSolanaSigner) SignBytes(_ context.Context, _ string, digest []byte) ([]byte, error) {
	return ed25519.Sign(s.key, digest), nil
}
func (s testSolanaSigner) SignTransactionMessage(_ context.Context, _ string, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.key, msg), nil
}

// rentChain is a cluster holding one payer and its pool. A deposit it is sent
// lands at once, moving the lamports as deposit_rent does, unless land says
// otherwise.
type rentChain struct {
	d     zsescrow.Deployment
	payer solana.PublicKey

	mu        sync.Mutex
	balance   uint64
	pool      *rpc.Account // nil: no account at the pool's address
	sent      []*solana.Transaction
	sendOpts  []rpc.SendOptions
	balReads  int
	land      func(amount uint64) *rpc.SignatureStatus // nil: lands, confirmed
	height    uint64
	statusFor map[solana.Signature]*rpc.SignatureStatus
	blockhash solana.Hash // zero: {9}
}

func newRentChain(t *testing.T, s testSolanaSigner, balance uint64) *rentChain {
	t.Helper()
	return &rentChain{
		d:         zsescrow.Deployment{Program: zsescrow.ProgramID},
		payer:     s.pub(),
		balance:   balance,
		statusFor: map[solana.Signature]*rpc.SignatureStatus{},
	}
}

func (c *rentChain) withPool(lamports, open uint64) *rentChain {
	c.pool = &rpc.Account{Lamports: lamports, Owner: c.d.Program, Data: encodeRentPool(c.payer, open)}
	return c
}

// encodeRentPool writes payer's RentPool account in the program's layout.
func encodeRentPool(payer solana.PublicKey, open uint64) []byte {
	data := make([]byte, zsescrow.RentPoolSize)
	disc := sha256.Sum256([]byte("account:RentPool"))
	copy(data, disc[:8])
	data[8], data[9] = zsescrow.AccountVersion, 255
	binary.LittleEndian.PutUint64(data[10:], open)
	copy(data[18:], payer[:])
	return data
}

func (c *rentChain) GetMinimumBalanceForRentExemption(_ context.Context, n uint64, cm rpc.Commitment) (uint64, error) {
	if cm != rpc.Confirmed {
		panic("rent read at " + string(cm))
	}
	return (128 + n) * 6_960, nil
}

func (c *rentChain) GetAccountInfo(_ context.Context, k solana.PublicKey, cm rpc.Commitment) (*rpc.Account, error) {
	if k != c.d.RentPool(c.payer) || cm != rpc.Confirmed {
		panic("read of " + k.String() + " at " + string(cm))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pool == nil {
		return nil, rpc.ErrNotFound
	}
	a := *c.pool
	return &a, nil
}

// accountReader answers every GetAccountInfo with its account and err.
type accountReader struct {
	rpc.Client
	acct *rpc.Account
	err  error
}

func (r accountReader) GetAccountInfo(context.Context, solana.PublicKey, rpc.Commitment) (*rpc.Account, error) {
	return r.acct, r.err
}

// getAccount reads no account only from rpc.ErrNotFound, wrapped or not; any
// other failure stays one, or a pool the RPC failed to read would be created
// again and a refund the payer could take forfeited.
func TestGetAccountReadsOnlyNotFoundAsAbsent(t *testing.T) {
	acct := &rpc.Account{Lamports: 1}
	down := errors.New("rpc down")
	for _, c := range []struct {
		name    string
		r       accountReader
		want    *rpc.Account
		wantErr error
	}{
		{"not found", accountReader{err: rpc.ErrNotFound}, nil, nil},
		{"not found, wrapped", accountReader{err: fmt.Errorf("call: %w", rpc.ErrNotFound)}, nil, nil},
		{"another error", accountReader{err: down}, nil, down},
		{"an account", accountReader{acct: acct}, acct, nil},
	} {
		got, err := getAccount(t.Context(), c.r, solana.PublicKey{})
		if got != c.want || !errors.Is(err, c.wantErr) || (c.wantErr == nil) != (err == nil) {
			t.Errorf("%s: %v, %v", c.name, got, err)
		}
	}
}

func (c *rentChain) GetBalance(_ context.Context, k solana.PublicKey, cm rpc.Commitment) (uint64, error) {
	if k != c.payer || cm != rpc.Confirmed {
		panic("balance of " + k.String() + " at " + string(cm))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.balReads++
	return c.balance, nil
}

func (c *rentChain) GetLatestBlockhash(_ context.Context, cm rpc.Commitment) (rpc.Blockhash, error) {
	if cm != rpc.Confirmed {
		panic("blockhash at " + string(cm))
	}
	if c.blockhash != (solana.Hash{}) {
		return rpc.Blockhash{Hash: c.blockhash, LastValidBlockHeight: 150}, nil
	}
	return rpc.Blockhash{Hash: solana.Hash{9}, LastValidBlockHeight: 150}, nil
}

func (c *rentChain) SendTransaction(_ context.Context, raw []byte, o rpc.SendOptions) (solana.Signature, error) {
	tx, err := solana.ParseTransaction(raw)
	if err != nil {
		return solana.Signature{}, err
	}
	if err := tx.VerifySignatures(); err != nil {
		return solana.Signature{}, err
	}
	data := tx.Message.Instructions[0].Data
	var amount uint64
	if len(data) >= 16 {
		amount = binary.LittleEndian.Uint64(data[len(data)-8:])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent, c.sendOpts = append(c.sent, tx), append(c.sendOpts, o)
	st := &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed}
	if c.land != nil {
		st = c.land(amount)
	}
	if st != nil && st.Err == nil {
		c.balance -= solanaSignatureFee
		switch {
		case bytes.Equal(data, c.d.CloseRentPool(c.payer).Data):
			c.balance += c.pool.Lamports
			c.pool = nil
		case bytes.HasPrefix(data, c.d.WithdrawRent(c.payer, 0).Data[:8]):
			c.pool.Lamports -= amount
			c.balance += amount
		default:
			if c.pool == nil || c.pool.Owner != c.d.Program {
				c.withPool(testPoolRent, 0)
				c.balance -= testPoolRent
			}
			c.pool.Lamports += amount
			c.balance -= amount
		}
	}
	c.statusFor[tx.Signatures[0]] = st
	return tx.Signatures[0], nil
}

func (c *rentChain) GetSignatureStatuses(_ context.Context, sigs []solana.Signature, _ bool) ([]*rpc.SignatureStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return []*rpc.SignatureStatus{c.statusFor[sigs[0]]}, nil
}

func (c *rentChain) GetBlockHeight(context.Context, rpc.Commitment) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.height += 100
	return c.height, nil
}

func (*rentChain) GetProgramAccounts(context.Context, solana.PublicKey, rpc.Commitment, ...rpc.Filter) ([]rpc.KeyedAccount, error) {
	panic("unused")
}
func (*rentChain) GetGenesisHash(context.Context) (solana.Hash, error) { panic("unused") }

func rentPool(c *rentChain, s testSolanaSigner) *SolanaRentPool {
	return &SolanaRentPool{RPC: c, Deployment: c.d, Signer: s,
		Confirm: rpc.ConfirmOptions{Poll: time.Millisecond, HeightCheck: time.Millisecond}}
}

func TestSolanaRentPoolFirstDepositCreatesThePool(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 1_000_000_000)
	sig, deposited, err := rentPool(c, s).EnsureDeposit(t.Context(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if deposited != 3*testTicketRent {
		t.Fatalf("deposited %d, want %d", deposited, 3*testTicketRent)
	}
	if len(c.sent) != 1 {
		t.Fatalf("%d transactions sent", len(c.sent))
	}
	tx := c.sent[0]
	if sig != tx.Signatures[0].String() {
		t.Fatalf("signature %s, sent %s", sig, tx.Signatures[0])
	}
	// The payer pays its own fee, and the transaction is the builder's
	// instruction and nothing else.
	want, err := solana.Compile(c.payer, solana.Hash{9}, []solana.Instruction{c.d.DepositRent(c.payer, deposited)}, solana.Legacy)
	if err != nil {
		t.Fatal(err)
	}
	wantMsg, _ := want.MarshalBinary()
	gotMsg, _ := tx.Message.MarshalBinary()
	if !bytes.Equal(wantMsg, gotMsg) {
		t.Fatal("deposit message is not DepositRent alone with the payer as fee payer")
	}
	if c.sendOpts[0].PreflightCommitment != rpc.Confirmed {
		t.Fatalf("preflight at %q", c.sendOpts[0].PreflightCommitment)
	}
	// The pool now covers the set, so a second pass sends nothing.
	if sig, n, err := rentPool(c, s).EnsureDeposit(t.Context(), 3); err != nil || sig != "" || n != 0 || len(c.sent) != 1 {
		t.Fatalf("second pass = %q, %d, %v; %d sent", sig, n, err, len(c.sent))
	}
}

func TestSolanaRentPoolCoveredReadsNoBalance(t *testing.T) {
	s := newTestSolanaSigner()
	// Live tickets' rent sits in the tickets: 2 in the pool and 8 out cover 10.
	c := newRentChain(t, s, 0).withPool(testPoolRent+2*testTicketRent, 8)
	sig, n, err := rentPool(c, s).EnsureDeposit(t.Context(), 0)
	if err != nil || sig != "" || n != 0 {
		t.Fatalf("EnsureDeposit = %q, %d, %v", sig, n, err)
	}
	if c.balReads != 0 || len(c.sent) != 0 {
		t.Fatalf("%d balance reads, %d sent", c.balReads, len(c.sent))
	}
}

func TestSolanaRentPoolUnaffordableSendsNothing(t *testing.T) {
	s := newTestSolanaSigner()
	// One lamport short of the pool's rent, a slot and the fee above the reserve.
	c := newRentChain(t, s, solanaSignerReserveLamports+testPoolRent+testTicketRent+solanaSignatureFee-1)
	_, _, err := rentPool(c, s).EnsureDeposit(t.Context(), 1)
	if !errors.Is(err, ErrRentDepositUnaffordable) || !errors.Is(err, ErrDepositUnaffordable) || errors.Is(err, ErrDepositBelowTarget) {
		t.Fatalf("err = %v", err)
	}
	if len(c.sent) != 0 {
		t.Fatal("sent a deposit it can't afford")
	}
	for _, part := range []string{"backs 0 of 1", "needs 4382840 lamports", "+ 1461600 pool rent", "have 4382839 lamports spendable"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q lacks %q", err, part)
		}
	}
}

func TestSolanaRentPoolBelowTargetReportsTheDeposit(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, solanaSignerReserveLamports+2*testTicketRent+solanaSignatureFee).withPool(testPoolRent, 0)
	sig, n, err := rentPool(c, s).EnsureDeposit(t.Context(), 10)
	if !errors.Is(err, ErrRentDepositBelowTarget) || !errors.Is(err, ErrDepositBelowTarget) || errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("err = %v", err)
	}
	if sig == "" || n != 2*testTicketRent {
		t.Fatalf("EnsureDeposit = %q, %d", sig, n)
	}
	if !strings.Contains(err.Error(), "still 23329920 lamports short of 10") {
		t.Errorf("error %q", err)
	}
	if free, err := rentPool(c, s).FreeSlots(t.Context()); err != nil || free != 2 {
		t.Fatalf("FreeSlots = %d, %v", free, err)
	}
}

func TestSolanaRentPoolPlansLamportsAtTheAddressAsNoPool(t *testing.T) {
	s := newTestSolanaSigner()
	// Exactly a first deposit's cost: the stray lamports don't lower it.
	c := newRentChain(t, s, solanaSignerReserveLamports+testPoolRent+testTicketRent+solanaSignatureFee)
	c.pool = &rpc.Account{Lamports: 5 * testTicketRent, Owner: solana.SystemProgramID}
	if _, n, err := rentPool(c, s).EnsureDeposit(t.Context(), 1); err != nil || n != testTicketRent {
		t.Fatalf("EnsureDeposit = %d, %v", n, err)
	}
	if free, err := (&SolanaRentPool{RPC: c, Deployment: c.d, Signer: s}).FreeSlots(t.Context()); err != nil || free == 0 {
		t.Fatalf("FreeSlots = %d, %v", free, err)
	}
}

func TestSolanaRentPoolFreeSlotsWithoutAPool(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 0)
	if free, err := rentPool(c, s).FreeSlots(t.Context()); err != nil || free != 0 {
		t.Fatalf("FreeSlots = %d, %v", free, err)
	}
}

func TestSolanaRentPoolReportsAFailedLanding(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 1_000_000_000)
	c.land = func(uint64) *rpc.SignatureStatus {
		return &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: json.RawMessage(`{"InstructionError":[0,{"Custom":6053}]}`)}
	}
	sig, n, err := rentPool(c, s).EnsureDeposit(t.Context(), 1)
	if err == nil || sig != "" || n != 0 || !strings.Contains(err.Error(), "failed: InstructionError") {
		t.Fatalf("EnsureDeposit = %q, %d, %v", sig, n, err)
	}
	if errors.Is(err, ErrDepositBelowTarget) || errors.Is(err, ErrDepositUnaffordable) {
		t.Fatalf("a failed landing reads as a sizing outcome: %v", err)
	}
}

func TestSolanaRentPoolReportsAnExpiredDeposit(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 1_000_000_000)
	c.land = func(uint64) *rpc.SignatureStatus { return nil }
	sig, n, err := rentPool(c, s).EnsureDeposit(t.Context(), 1)
	if !errors.Is(err, rpc.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	// What was sent is named, and nothing counts as deposited.
	if sig != c.sent[0].Signatures[0].String() || n != 0 {
		t.Fatalf("EnsureDeposit = %q, %d", sig, n)
	}
}

// sentAlone checks c sent one transaction more, ix alone with the payer as
// fee payer, preflighted at confirmed.
func sentAlone(t *testing.T, c *rentChain, ix solana.Instruction) {
	t.Helper()
	tx := c.sent[len(c.sent)-1]
	want, err := solana.Compile(c.payer, solana.Hash{9}, []solana.Instruction{ix}, solana.Legacy)
	if err != nil {
		t.Fatal(err)
	}
	wantMsg, _ := want.MarshalBinary()
	gotMsg, _ := tx.Message.MarshalBinary()
	if !bytes.Equal(wantMsg, gotMsg) {
		t.Fatal("the message is not the builder's instruction alone with the payer as fee payer")
	}
	if o := c.sendOpts[len(c.sendOpts)-1]; o.PreflightCommitment != rpc.Confirmed {
		t.Fatalf("preflight at %q", o.PreflightCommitment)
	}
}

func TestSolanaRentPoolStatus(t *testing.T) {
	s := newTestSolanaSigner()
	// Three slots' rent in the pool, two more in live tickets, and a few
	// lamports short of a fourth.
	c := newRentChain(t, s, 0).withPool(testPoolRent+4*testTicketRent-1, 2)
	want := SolanaRentPoolStatus{Exists: true, Lamports: testPoolRent + 4*testTicketRent - 1, OpenTickets: 2, TicketRent: testTicketRent, PoolRent: testPoolRent}
	got, err := ReadSolanaRentPool(t.Context(), c, c.d, c.payer)
	if err != nil || got != want {
		t.Fatalf("ReadSolanaRentPool = %+v, %v; want %+v", got, err, want)
	}
	if got.Available() != 4*testTicketRent-1 || got.FreeSlots() != 3 || got.BackedSlots() != 5 {
		t.Errorf("available %d, free %d, backed %d; want %d, 3, 5", got.Available(), got.FreeSlots(), got.BackedSlots(), 4*testTicketRent-1)
	}
	if st, err := rentPool(c, s).Status(t.Context()); err != nil || st != want {
		t.Errorf("Status = %+v, %v", st, err)
	}
	// The live tickets count toward the working set, so six slots is short
	// by the one lamport the fourth free slot lacks, and two is all of
	// Available over.
	if got.Shortfall(6) != 1 || got.Shortfall(5) != 0 || got.Excess(6) != 0 {
		t.Errorf("shortfall(6) %d, shortfall(5) %d, excess(6) %d; want 1, 0, 0", got.Shortfall(6), got.Shortfall(5), got.Excess(6))
	}
	if got.Excess(2) != 4*testTicketRent-1 || got.Excess(5) != testTicketRent-1 || got.Shortfall(2) != 0 {
		t.Errorf("excess(2) %d, excess(5) %d, shortfall(2) %d; want %d, %d, 0", got.Excess(2), got.Excess(5), got.Shortfall(2), 4*testTicketRent-1, testTicketRent-1)
	}
	// The excess counts the live tickets' rent, which a withdraw can't take,
	// so a shrink below them is over by more than the pool holds.
	if got.Excess(1) != 5*testTicketRent-1 || got.Excess(1) <= got.Available() {
		t.Errorf("excess(1) %d, available %d; want %d, above available", got.Excess(1), got.Available(), 5*testTicketRent-1)
	}
	// A working set whose rent overflows saturates rather than wrapping, so
	// it reads as short, never as an excess. This count's product wraps to
	// less than one ticket's rent.
	huge := uint64(math.MaxUint64)/testTicketRent + 1
	gross := uint64(6*testTicketRent - 1)
	if got.Shortfall(huge) != math.MaxUint64-gross || got.Excess(huge) != 0 {
		t.Errorf("saturated: shortfall %d, excess %d; want %d, 0", got.Shortfall(huge), got.Excess(huge), uint64(math.MaxUint64)-gross)
	}

	// The zero status a failed read returns has no slots rather than a
	// division by zero, and sizes nothing.
	if (SolanaRentPoolStatus{}).FreeSlots() != 0 || (SolanaRentPoolStatus{}).BackedSlots() != 0 {
		t.Error("the zero status has slots")
	}
	if (SolanaRentPoolStatus{}).Shortfall(3) != 0 || (SolanaRentPoolStatus{}).Excess(0) != 0 {
		t.Error("the zero status sizes a deposit")
	}
	// Without a ticket's rent there is no target to be over, whatever the
	// pool holds.
	if ex := (SolanaRentPoolStatus{Exists: true, Lamports: 5 * testTicketRent}).Excess(1); ex != 0 {
		t.Errorf("no ticket rent: excess %d", ex)
	}
	// No pool yet is short the whole working set.
	if none := (SolanaRentPoolStatus{TicketRent: testTicketRent, PoolRent: testPoolRent}); none.Shortfall(3) != 3*testTicketRent {
		t.Errorf("no pool: shortfall(3) %d; want %d", none.Shortfall(3), 3*testTicketRent)
	}

	// A pool holding less than its own rent has nothing to draw.
	c.withPool(testPoolRent-1, 0)
	if got, _ := ReadSolanaRentPool(t.Context(), c, c.d, c.payer); got.Available() != 0 || got.FreeSlots() != 0 || got.BackedSlots() != 0 {
		t.Errorf("under its rent: available %d, free %d, backed %d", got.Available(), got.FreeSlots(), got.BackedSlots())
	}
	// Lamports at the address are no pool.
	c.pool = &rpc.Account{Lamports: 5 * testTicketRent, Owner: solana.SystemProgramID}
	if got, _ := ReadSolanaRentPool(t.Context(), c, c.d, c.payer); got.Exists || got.Available() != 0 || got.BackedSlots() != 0 {
		t.Errorf("stray lamports read as a pool: %+v", got)
	}
}

func TestSolanaRentPoolWithdraw(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 0).withPool(testPoolRent+3*testTicketRent, 1)
	p := rentPool(c, s)
	// More than the pool holds above its rent, or nothing, is refused unsent.
	for _, n := range []uint64{0, 3*testTicketRent + 1} {
		if _, err := p.Withdraw(t.Context(), n); err == nil || len(c.sent) != 0 {
			t.Fatalf("Withdraw(%d) = %v; %d sent", n, err, len(c.sent))
		}
	}
	// All of it, to the lamport.
	sig, err := p.Withdraw(t.Context(), 3*testTicketRent)
	if err != nil || sig != c.sent[0].Signatures[0].String() {
		t.Fatalf("Withdraw = %q, %v", sig, err)
	}
	sentAlone(t, c, c.d.WithdrawRent(c.payer, 3*testTicketRent))
	if st, _ := p.Status(t.Context()); st.Available() != 0 || st.OpenTickets != 1 {
		t.Errorf("after the withdraw: %+v", st)
	}
}

func TestSolanaRentPoolClose(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 0).withPool(testPoolRent+2*testTicketRent, 1)
	p := rentPool(c, s)
	if _, _, err := p.Close(t.Context()); !errors.Is(err, ErrRentPoolTicketsOpen) || len(c.sent) != 0 {
		t.Fatalf("Close with a ticket open = %v; %d sent", err, len(c.sent))
	}
	c.withPool(testPoolRent+2*testTicketRent, 0)
	sig, returned, err := p.Close(t.Context())
	if err != nil || sig != c.sent[0].Signatures[0].String() || returned != testPoolRent+2*testTicketRent {
		t.Fatalf("Close = %q, %d, %v", sig, returned, err)
	}
	sentAlone(t, c, c.d.CloseRentPool(c.payer))
	if c.balance != testPoolRent+2*testTicketRent-solanaSignatureFee {
		t.Errorf("balance %d after the close", c.balance)
	}
}

func TestSolanaRentPoolWithoutAPoolRefuses(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 1_000_000_000)
	p := rentPool(c, s)
	if _, err := p.Withdraw(t.Context(), 1); !errors.Is(err, ErrNoRentPool) {
		t.Errorf("Withdraw = %v", err)
	}
	if _, _, err := p.Close(t.Context()); !errors.Is(err, ErrNoRentPool) {
		t.Errorf("Close = %v", err)
	}
	if len(c.sent) != 0 {
		t.Errorf("%d sent", len(c.sent))
	}
}

func TestSolanaRentPoolReportsAFailedWithdraw(t *testing.T) {
	s := newTestSolanaSigner()
	c := newRentChain(t, s, 0).withPool(testPoolRent+testTicketRent, 0)
	c.land = func(uint64) *rpc.SignatureStatus {
		return &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: json.RawMessage(`{"InstructionError":[0,{"Custom":6000}]}`)}
	}
	if sig, err := rentPool(c, s).Withdraw(t.Context(), testTicketRent); err == nil || sig != "" || !strings.Contains(err.Error(), "withdraw") {
		t.Fatalf("Withdraw = %q, %v", sig, err)
	}
	c.land = func(uint64) *rpc.SignatureStatus { return nil }
	sig, _, err := rentPool(c, s).Close(t.Context())
	if !errors.Is(err, rpc.ErrExpired) || sig != c.sent[1].Signatures[0].String() {
		t.Fatalf("Close = %q, %v; want the expired close's signature", sig, err)
	}
}

func TestRentSentinelsMatchOnlyTheirTwins(t *testing.T) {
	if errors.Is(ErrRentDepositUnaffordable, ErrDepositBelowTarget) || errors.Is(ErrRentDepositBelowTarget, ErrDepositUnaffordable) {
		t.Fatal("a rent sentinel matches the other twin")
	}
	if errors.Is(ErrDepositUnaffordable, ErrRentDepositUnaffordable) {
		t.Fatal("the Algorand sentinel matches the Solana one")
	}
}
