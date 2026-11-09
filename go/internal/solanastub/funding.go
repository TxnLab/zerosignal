/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// Funding is where a run's SOL and test USDC come from. Exactly one key is
// set.
//
// Authority is the test mint's authority, which a localnet is bootstrapped
// with as the Config's admin too: it airdrops and mints, and it can lower the
// grace and resolve a frozen ticket. Its keypair is also devnet's admin and
// upgrade authority, so a run holding it stays on this machine.
//
// Funder is a wallet holding SOL and test USDC, which it transfers. It holds
// no power over the program, so a run with it may reach any cluster, devnet's
// included, where nobody can airdrop or mint on demand.
type Funding struct {
	Authority ed25519.PrivateKey
	Funder    ed25519.PrivateKey
}

func (f Funding) check() error {
	if (f.Authority == nil) == (f.Funder == nil) {
		return errors.New("solanastub: fund a run with the mint's authority or a funder, one of them")
	}
	return nil
}

// Admin is the Config's admin when the run holds it, else nil.
func (f Funding) Admin() ed25519.PrivateKey { return f.Authority }

// Source is the key the run's SOL and USDC came from, where a payer returns
// what it has left.
func (f Funding) Source() solana.PublicKey {
	if f.Funder != nil {
		return PublicKey(f.Funder)
	}
	return PublicKey(f.Authority)
}

// FundSOL gives to lamports.
func (ch *Chain) FundSOL(ctx context.Context, f Funding, to solana.PublicKey, lamports uint64) error {
	if f.Funder == nil {
		return ch.Airdrop(ctx, to, lamports)
	}
	_, err := ch.Send(ctx, []solana.Instruction{solana.SystemTransfer(PublicKey(f.Funder), to, lamports)}, f.Funder)
	if err != nil {
		return fmt.Errorf("solanastub: send SOL: %w", err)
	}
	return nil
}

// FundUSDC creates owner's token account if it has none and gives it amount
// base units of test USDC.
func (ch *Chain) FundUSDC(ctx context.Context, f Funding, owner solana.PublicKey, amount uint64) error {
	if f.Funder == nil {
		return ch.MintUSDC(ctx, f.Authority, owner, amount)
	}
	d, funder := ch.Deployment, PublicKey(f.Funder)
	_, err := ch.Send(ctx, []solana.Instruction{
		solana.CreateAssociatedTokenAccountIdempotent(funder, owner, d.Mint),
		solana.TransferChecked(d.TokenAccount(funder), d.Mint, d.TokenAccount(owner), funder, amount, ch.Config.USDCDecimals),
	}, f.Funder)
	if err != nil {
		return fmt.Errorf("solanastub: send test USDC: %w", err)
	}
	return nil
}

// TopUpSOL brings to up to lamports when it holds less than floor, so a
// long-lived key, a registered stub's signing key paying its endings, is
// funded once its balance runs low rather than on every run.
func (ch *Chain) TopUpSOL(ctx context.Context, f Funding, to solana.PublicKey, floor, lamports uint64) error {
	have, err := ch.RPC.GetBalance(ctx, to, rpc.Confirmed)
	if err != nil {
		return err
	}
	if have >= floor {
		return nil
	}
	return ch.FundSOL(ctx, f, to, lamports-have)
}

// ReturnFunds sends what owner holds back to the run's source: its test USDC,
// then its token account's rent and its SOL, in one transaction that closes
// the token account and leaves the account empty. It is how a test payer on a
// shared cluster hands back what the run gave it; the rent pool must be
// closed first, or its lamports stay behind.
func (ch *Chain) ReturnFunds(ctx context.Context, f Funding, owner ed25519.PrivateKey) error {
	d, from, to := ch.Deployment, PublicKey(owner), f.Source()
	lamports, err := ch.RPC.GetBalance(ctx, from, rpc.Confirmed)
	if err != nil {
		return err
	}
	var ixs []solana.Instruction
	acct, err := ch.RPC.GetAccountInfo(ctx, d.TokenAccount(from), rpc.Confirmed)
	switch {
	case errors.Is(err, rpc.ErrNotFound):
	case err != nil:
		return err
	default:
		ta, err := zsescrow.DecodeTokenAccount(acct.Data)
		if err != nil {
			return err
		}
		// No create for the source's token account: the source's own rent
		// would come out of the SOL this transaction sends, and a funder holds
		// one already, since the USDC came from it.
		if ta.Amount > 0 {
			ixs = append(ixs, solana.TransferChecked(d.TokenAccount(from), d.Mint, d.TokenAccount(to), from, ta.Amount, ch.Config.USDCDecimals))
		}
		ixs = append(ixs, solana.CloseAccount(d.TokenAccount(from), from, from))
		lamports += acct.Lamports
	}
	if lamports > signatureFee {
		ixs = append(ixs, solana.SystemTransfer(from, to, lamports-signatureFee))
	}
	if len(ixs) == 0 {
		return nil
	}
	if _, err := ch.Send(ctx, ixs, owner); err != nil {
		return fmt.Errorf("solanastub: return %s's funds: %w", from, err)
	}
	return nil
}

// signatureFee is a one-signature transaction's fee on every cluster today.
const signatureFee = 5_000
