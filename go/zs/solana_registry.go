/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// SolanaChainReader reads the zs_escrow program's Operator and Node accounts
// into the Operators the Algorand box walk builds, field for field, so the
// probes, selection and the routers treat a node alike on either rail. The TS
// SDK's SolanaChainReader (sdk/src/registry/solana.ts) is the twin, pinned by
// testdata/solana_registry_vectors.json.
//
// Where the rails' records differ:
//   - An operator's name is a name-service account (Operator.NameRef), not an
//     NFD, so NFDAppID stays 0, as for an Algorand operator with no NFD.
//   - Neither record carries an age recipient; the seal key is the node's
//     signed ephemeral, from its details probe, on both rails.
//   - The signing key is the account's 32 raw bytes, so SigningAddr is its
//     base58 address and TicketSigningKey those bytes.
//   - Only an evicted operator hides its nodes, and the node status byte is
//     not read: the Algorand read's rules. An operator status a later program
//     adds routes there too.
//   - An account that won't decode fails the read, as a malformed box does.
//   - Stake, accruals, live tickets, input and output units and the
//     admin-resolution counters are on both records and on neither Operator.
//   - The signer's balance is SignerSpendableLamports, which
//     ChainOperatorSource's balance pass reads through
//     ReadSignerSpendableLamports, not SignerSpendableMicroAlgos.
type SolanaChainReader struct {
	RPC rpc.Client
	// Program is the zs_escrow program id; zero is zsescrow.ProgramID.
	Program solana.PublicKey
	// OperatorIDs, when non-empty, restricts the read to these operators, each
	// of which must exist, as ChainOperatorSource.OperatorIDs does.
	OperatorIDs []uint64
	// Log receives the accounts the read skips; nil is slog.Default().
	Log *slog.Logger

	// clock overrides the day the revenue windows end on in tests; nil =
	// time.Now.
	clock func() time.Time
}

var (
	_ ChainReader          = (*SolanaChainReader)(nil)
	_ SignerLamportsReader = (*SolanaChainReader)(nil)
)

// solanaSignerReserveLamports bounds the rent-exempt minimum of a signer's own
// account from above: no data, so the 128-byte account overhead at 6,960
// lamports a byte, the ceiling selection.MinSignerSpendableLamports prices the
// Ticket's rent at (the current rate can be lower; see there). The runtime
// refuses a transaction that leaves its fee payer above zero but below its
// minimum (InsufficientFundsForRent), so the minimum is the Solana account's
// min-balance, and the spendable reading is what lies above this bound, as
// spendableMicroAlgos reads above algod's.
const solanaSignerReserveLamports uint64 = 890_880

// solanaRegistryCommitment is confirmed rather than the RPC's default,
// finalized, so a key rotation or an eviction reaches routing in about a
// second instead of finalization's dozen or so. A confirmed block that never
// finalizes costs one refresh routed on a registry the next read corrects.
const solanaRegistryCommitment = rpc.Confirmed

func (c *SolanaChainReader) program() solana.PublicKey {
	if c.Program.IsZero() {
		return zsescrow.ProgramID
	}
	return c.Program
}

func (c *SolanaChainReader) log() *slog.Logger {
	if c.Log == nil {
		return slog.Default()
	}
	return c.Log
}

// ReadDeployment derives the deployment id from the cluster's genesis hash
// and the program id.
func (c *SolanaChainReader) ReadDeployment(ctx context.Context) (ticket.DeploymentID, error) {
	if c.RPC == nil {
		return ticket.DeploymentID{}, errors.New("SolanaChainReader.RPC is nil")
	}
	rctx, cancel := context.WithTimeout(ctx, escrowConfigTimeout)
	defer cancel()
	g, err := c.RPC.GetGenesisHash(rctx)
	if err != nil {
		return ticket.DeploymentID{}, fmt.Errorf("zs: read genesis hash: %w", err)
	}
	p := c.program()
	d, err := ticket.SolanaDeploymentID(g[:], p[:])
	if err != nil {
		return ticket.DeploymentID{}, fmt.Errorf("zs: %w", err)
	}
	return d, nil
}

// ReadSignerSpendableLamports reads addr's balance at the registry's
// commitment, so a node is judged on a balance from about the slot its
// registry was read at, and returns what lies above the account's own
// reserve. getBalance answers 0 for an account that does not exist, which is
// the honest reading of a signer nobody funded.
func (c *SolanaChainReader) ReadSignerSpendableLamports(ctx context.Context, addr string) (uint64, error) {
	if c.RPC == nil {
		return 0, errors.New("SolanaChainReader.RPC is nil")
	}
	key, err := solana.ParsePublicKey(addr)
	if err != nil {
		return 0, fmt.Errorf("signing address %q: %w", addr, err)
	}
	lamports, err := c.RPC.GetBalance(ctx, key, solanaRegistryCommitment)
	if err != nil {
		return 0, fmt.Errorf("balance %s: %w", addr, err)
	}
	return solanaSpendableLamports(lamports), nil
}

// solanaSpendableLamports is lamports less the signer's reserve, floored at
// zero, as spendableMicroAlgos is.
func solanaSpendableLamports(lamports uint64) uint64 {
	if lamports < solanaSignerReserveLamports {
		return 0
	}
	return lamports - solanaSignerReserveLamports
}

// solanaAccountFilter selects one account type by its discriminator alone.
// A dataSize filter would hide an account a later program grew, where the
// decoder refuses it with a warning naming it.
func solanaAccountFilter(name string) rpc.Filter {
	d := zsescrow.AccountDiscriminator(name)
	return rpc.Memcmp(0, d[:])
}

// ReadChain reads the operators, then their nodes. A second call for the
// nodes rather than one for every program account keeps tickets, which
// outnumber nodes by far, off the wire.
func (c *SolanaChainReader) ReadChain(ctx context.Context) ([]Operator, error) {
	if c.RPC == nil {
		return nil, errors.New("SolanaChainReader.RPC is nil")
	}
	program, log := c.program(), c.log()
	opAccts, err := c.RPC.GetProgramAccounts(ctx, program, solanaRegistryCommitment, solanaAccountFilter("Operator"))
	if err != nil {
		return nil, fmt.Errorf("fetch operators: %w", err)
	}
	ops, err := solanaOperators(program, opAccts, c.OperatorIDs, log)
	if err != nil {
		return nil, fmt.Errorf("fetch operators: %w", err)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w for zs_escrow program %s", errNoOperators, program)
	}
	nodeAccts, err := c.RPC.GetProgramAccounts(ctx, program, solanaRegistryCommitment, solanaAccountFilter("Node"))
	if err != nil {
		return nil, fmt.Errorf("fetch nodes: %w", err)
	}
	now := time.Now
	if c.clock != nil {
		now = c.clock
	}
	out, err := solanaNodes(program, ops, nodeAccts, uint64(now().Unix())/escrow.SecondsPerDay, log)
	if err != nil {
		return nil, fmt.Errorf("fetch nodes: %w", err)
	}
	return out, nil
}

// solanaOperators decodes the operator accounts by id, restricted to ids
// when it is non-empty, every one of which must be there.
//
// An account that won't decode fails the read, as a malformed box fails the
// Algorand one: the registry then keeps routing on its last good snapshot
// through the carry window, and the error names the account version a later
// program wrote, where skipping would drop the node at once and could
// report a fleet of unreadable operators as an empty one.
func solanaOperators(program solana.PublicKey, accts []rpc.KeyedAccount, ids []uint64, log *slog.Logger) (map[uint64]*zsescrow.Operator, error) {
	byID := make(map[uint64]*zsescrow.Operator, len(accts))
	for _, a := range accts {
		if !solanaProgramOwns(program, a, log) {
			continue
		}
		op, err := zsescrow.DecodeOperator(a.Account.Data)
		if err != nil {
			return nil, fmt.Errorf("decode operator account %s: %w", a.Key, err)
		}
		byID[op.ID] = op
	}
	if len(ids) == 0 {
		return byID, nil
	}
	kept := make(map[uint64]*zsescrow.Operator, len(ids))
	for _, id := range ids {
		op, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("operator %d not found on chain", id)
		}
		kept[id] = op
	}
	return kept, nil
}

// solanaNodes resolves the nodes of ops, sorted by (operator id, node id), as
// the Algorand box listing returns them. A node whose operator is not in ops
// (unrequested, or with no operator account) is left out silently, as the
// Algorand read leaves out an unrequested operator's. A node account that
// won't decode fails the read, for solanaOperators' reason.
func solanaNodes(program solana.PublicKey, ops map[uint64]*zsescrow.Operator, accts []rpc.KeyedAccount, currentDay uint64, log *slog.Logger) ([]Operator, error) {
	out := make([]Operator, 0, len(accts))
	for _, a := range accts {
		if !solanaProgramOwns(program, a, log) {
			continue
		}
		n, err := zsescrow.DecodeNode(a.Account.Data)
		if err != nil {
			return nil, fmt.Errorf("decode node account %s: %w", a.Key, err)
		}
		op, ok := ops[n.OperatorID]
		if !ok || op.Status == zsescrow.OperatorStatusEvicted {
			continue
		}
		o, err := resolveSolanaNode(op, n, currentDay)
		if err != nil {
			log.Warn("skipping unparseable node record",
				slog.Uint64("operator_id", n.OperatorID),
				slog.Uint64("node_id", n.NodeID),
				slog.Any("err", err))
			continue
		}
		out = append(out, o)
	}
	slices.SortFunc(out, func(a, b Operator) int {
		return cmp.Or(cmp.Compare(a.ID, b.ID), cmp.Compare(a.NodeID, b.NodeID))
	})
	return out, nil
}

// solanaProgramOwns checks what the decoders leave to their caller.
// getProgramAccounts answers only with the program's accounts, so a miss is an
// RPC answering wrongly, and its data is not the program's to trust.
func solanaProgramOwns(program solana.PublicKey, a rpc.KeyedAccount, log *slog.Logger) bool {
	if a.Account.Owner == program {
		return true
	}
	log.Warn("skipping registry account the program does not own",
		slog.String("account", a.Key.String()),
		slog.String("owner", a.Account.Owner.String()))
	return false
}

// resolveSolanaNode is resolveOperatorNode for a Solana node: identity from
// its operator's account, signing key, base URL, staging flag and track record
// from its own, with the same base-URL rules. currentDay (Unix seconds /
// 86400) ends the revenue windows.
func resolveSolanaNode(op *zsescrow.Operator, n *zsescrow.Node, currentDay uint64) (Operator, error) {
	// The Algorand decoder trims the zero padding of its fixed-width field;
	// trimming here too reads the same stored string as the same URL.
	baseURL := strings.TrimRight(strings.TrimRight(n.BaseURL, "\x00"), "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return Operator{}, fmt.Errorf("operator %d node %d: base_url %q must start with http:// or https://", op.ID, n.NodeID, baseURL)
	}
	// The windowed reads are the Algorand ring's: the program writes its ring
	// by the same day-index rule, and 0 is the same never-written sentinel.
	ring := escrow.RecordMetrics{BucketsLastDay: nonNegative(n.RingDay), RevenueBuckets: n.RingRevenue}
	return Operator{
		ID:               n.OperatorID,
		NodeID:           n.NodeID,
		OwnerAddr:        op.Owner.String(),
		SigningAddr:      n.Signing.String(),
		TicketSigningKey: ed25519.PublicKey(n.Signing[:]),
		BaseURL:          baseURL,
		Staging:          n.Staging != 0,
		Metrics: OperatorMetrics{
			LastActivityAt:            nonNegative(n.LastActivityAt),
			TicketsOpened:             n.OpensTotal,
			TicketsSettled:            n.SettledCount,
			TicketsLapsedSettled:      n.LapsedCount,
			TicketsRefundedInactive:   n.RefundedCount,
			TicketsProtested:          n.ProtestedCount,
			TicketsFrozenDispute:      n.FrozenDisputeCount,
			TotalRefundedInactiveUsdc: n.RefundedTotal,
			TotalProtestedUsdc:        n.ProtestedTotal,
			TotalFrozenDisputeUsdc:    n.FrozenDisputeTotal,
			LatencyTotalMs:            n.LatencyTotalMs,
			LatencyEwmaMs:             n.TTFTEwmaMs,
			LatencySamples:            n.LatencySamples,
			TokensPerSecEwma:          n.DecodeTPSEwma,
			TotalRevenueGross:         n.RevenueTotal,
			Revenue24hUsdc:            ring.Revenue24h(currentDay),
			Revenue7dUsdc:             ring.Revenue7d(currentDay),
			Revenue30dUsdc:            ring.Revenue30d(currentDay),
		},
	}, nil
}

// nonNegative reads one of the program's i64 times as the Algorand record's
// u64. The program writes only clock times there, so a negative one is a
// corrupt account, and reads as never.
func nonNegative(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}
