/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// A node's signing account pays the pooled fees of every open() group and
// atomic settle it signs, so the shared selection policy drops a node whose
// account is known to be below selection.MinSignerSpendableMicroAlgos. This
// file supplies the reading.
//
// Every signer in the fleet is read on every chain refresh, never just the
// nodes a request is about to use. The open() group this process submits
// already names its node to the same algod, but a read aimed at one node would
// signal the choice ahead of it — including for requests that never open — so
// the reads stay demand-independent (proto/SPEC.md § 3f "Signer-funding gate").

const (
	// signerBalanceConcurrency bounds in-flight account reads. Each is a ~400
	// byte GET; the bound exists for public algod rate limits, not our sockets.
	signerBalanceConcurrency = 8
	// signerBalanceTimeout caps the whole pass inside the registry's refresh
	// budget (DefaultRefreshTimeout, shared with the details probes). A signer
	// not read in time keeps its last-known value.
	signerBalanceTimeout = 10 * time.Second
)

// fillSignerBalances sets SignerSpendableMicroAlgos on every op from a fresh
// read of each distinct signing address, falling back to the last successful
// reading when a read fails. An address never read successfully leaves the
// field nil (eligible).
func (s *ChainOperatorSource) fillSignerBalances(ctx context.Context, ops []Operator) {
	read := s.readSpendable
	if read == nil {
		if s.Algod == nil {
			return
		}
		read = s.algodSpendable
	}

	seen := make(map[string]struct{}, len(ops))
	addrs := make([]string, 0, len(ops))
	for _, op := range ops {
		if op.SigningAddr == "" {
			continue
		}
		if _, dup := seen[op.SigningAddr]; dup {
			continue
		}
		seen[op.SigningAddr] = struct{}{}
		addrs = append(addrs, op.SigningAddr)
	}
	if len(addrs) == 0 {
		return
	}
	// Reads queue on the semaphore in slice order, so a pass that hits its
	// deadline skips the tail. Chain order would skip the same tail every
	// cycle, and a tail signer last read as broke would then stay excluded
	// after a top-up.
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })

	passCtx, cancel := context.WithTimeout(ctx, signerBalanceTimeout)
	defer cancel()
	type reading struct {
		spendable uint64
		err       error
	}
	results := make([]reading, len(addrs))
	sem := make(chan struct{}, signerBalanceConcurrency)
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-passCtx.Done():
				results[i].err = passCtx.Err()
				return
			}
			defer func() { <-sem }()
			results[i].spendable, results[i].err = read(passCtx, addr)
		})
	}
	wg.Wait()

	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	var failed int
	var firstErr error

	s.signerMu.Lock()
	if s.signerSpendable == nil {
		s.signerSpendable = make(map[string]uint64, len(addrs))
	}
	for i, addr := range addrs {
		if err := results[i].err; err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			log.Debug("signing-account balance read failed; keeping last-known value",
				slog.String("signing_addr", addr),
				slog.Any("err", err))
			continue
		}
		s.signerSpendable[addr] = results[i].spendable
	}
	for addr := range s.signerSpendable {
		if _, live := seen[addr]; !live {
			delete(s.signerSpendable, addr)
		}
	}
	for i := range ops {
		if v, ok := s.signerSpendable[ops[i].SigningAddr]; ok {
			ops[i].SignerSpendableMicroAlgos = &v
		}
	}
	s.signerMu.Unlock()

	// One line per pass, not per address: a rate-limited algod fails a
	// fraction of reads every cycle, and those signers route on stale values.
	if failed > 0 {
		log.Warn("signing-account balance reads failed; routing those nodes on last-known values",
			slog.Int("failed", failed),
			slog.Int("signers", len(addrs)),
			slog.Any("err", firstErr))
	}
}

// algodSpendable reads addr's spendable ALGO. exclude=all drops the
// asset/app lists from the response; algod still computes min-balance from
// the account totals, so the figure is exact.
func (s *ChainOperatorSource) algodSpendable(ctx context.Context, addr string) (uint64, error) {
	acct, err := s.Algod.SDKClient().AccountInformation(addr).Exclude([]string{"all"}).Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("account info %s: %w", addr, err)
	}
	return spendableMicroAlgos(acct.Amount, acct.MinBalance), nil
}

// spendableMicroAlgos is amount − min-balance, floored at zero. An account
// below its own minimum can't send anything, so zero is the honest reading.
func spendableMicroAlgos(amount, minBalance uint64) uint64 {
	if amount < minBalance {
		return 0
	}
	return amount - minBalance
}
