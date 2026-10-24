/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// SolanaDoctorReadings are DoctorReadings for the Solana rail: what Diagnose
// reads from the RPC, the program and the fleet, and all SolanaDoctorChecks
// judges. A read that failed carries its error text and leaves its values
// zero. Pinned with SolanaDoctorChecks by the solanaCases of
// testdata/doctor_vectors.json, which the TS SDK's solanaDoctorChecks replays.
type SolanaDoctorReadings struct {
	// Network is the cluster preset, empty for a cluster named only by its
	// endpoint.
	Network       string `json:"network"`
	Address       string `json:"address"`
	Slots         uint64 `json:"slots,string"`
	RelayRequired bool   `json:"relayRequired"`
	AllowStaging  bool   `json:"allowStaging"`

	RPCErr      string `json:"rpcErr,omitempty"`
	BlockHeight uint64 `json:"blockHeight,string"`
	// Genesis is the genesis hash of the cluster the RPC serves.
	Genesis string `json:"genesis"`

	Program   string `json:"program"`
	ConfigErr string `json:"configErr,omitempty"`
	// ConfigGenesis is the genesis hash the program's Config binds every ack
	// digest to.
	ConfigGenesis string `json:"configGenesis"`
	Mint          string `json:"mint"`
	// ConfigPaused is the admin's pause, under which every open fails.
	ConfigPaused bool `json:"configPaused"`
	// TicketRent and PoolRent are the cluster's rent-exempt minimums for a
	// ticket and a rent pool account.
	TicketRent uint64 `json:"ticketRent,string"`
	PoolRent   uint64 `json:"poolRent,string"`

	AccountErr string `json:"accountErr,omitempty"`
	Lamports   uint64 `json:"lamports,string"`

	// The payer's associated token account for the Config's mint.
	UsdcErr     string `json:"usdcErr,omitempty"`
	UsdcAccount bool   `json:"usdcAccount"`
	UsdcFrozen  bool   `json:"usdcFrozen"`
	UsdcBalance uint64 `json:"usdcBalance,string"`

	PoolErr      string `json:"poolErr,omitempty"`
	PoolExists   bool   `json:"poolExists"`
	PoolLamports uint64 `json:"poolLamports,string"`
	OpenTickets  uint64 `json:"openTickets,string"`

	OperatorsErr string       `json:"operatorsErr,omitempty"`
	Nodes        []DoctorNode `json:"nodes"`
}

// SolanaDoctorChecks judges readings, in order: rpc, program, sol,
// usdc_account, usdc_balance, rent_pool, operators.
func SolanaDoctorChecks(r SolanaDoctorReadings) []DoctorCheck {
	net := r.Network
	if net == "" {
		net = "this cluster"
	}
	rpcOK := r.RPCErr == ""
	programOK := rpcOK && r.ConfigErr == "" && r.TicketRent > 0 && r.ConfigGenesis == r.Genesis
	accountOK := rpcOK && r.AccountErr == ""
	usdcOK := programOK && r.UsdcErr == "" && r.UsdcAccount && !r.UsdcFrozen
	var out []DoctorCheck
	add := func(id string, s DoctorStatus, format string, a ...any) {
		out = append(out, DoctorCheck{ID: id, Status: s, Message: fmt.Sprintf(format, a...)})
	}
	const needsRPC = "needs the RPC"

	if rpcOK {
		add("rpc", DoctorPass, "the Solana RPC for %s answers at block height %d", net, r.BlockHeight)
	} else {
		add("rpc", DoctorFail, "can't reach the Solana RPC for %s: %s", net, r.RPCErr)
	}

	switch {
	case !rpcOK:
		add("program", DoctorSkip, needsRPC)
	case r.ConfigErr != "":
		add("program", DoctorFail, "can't read program %s's Config: %s", r.Program, r.ConfigErr)
	case r.TicketRent == 0:
		add("program", DoctorFail, "the cluster quotes no rent for program %s's tickets", r.Program)
	// The ack digest binds the Config's genesis hash, so an RPC serving
	// another cluster reads a program nothing here can pay through.
	case r.ConfigGenesis != r.Genesis:
		add("program", DoctorFail, "program %s's Config is for the cluster with genesis %s, but the RPC serves genesis %s", r.Program, r.ConfigGenesis, r.Genesis)
	// A pause leaves the account readings valid, so it fails only this check
	// and the account checks still run.
	case r.ConfigPaused:
		add("program", DoctorFail, "program %s is paused; no ticket can open until its admin unpauses it", r.Program)
	default:
		add("program", DoctorPass, "program %s: %s SOL rent per ticket, USDC mint %s", r.Program, lamportsSOL(r.TicketRent), r.Mint)
	}

	spendable := solanaSpendableLamports(r.Lamports)
	switch {
	case !rpcOK:
		add("sol", DoctorSkip, needsRPC)
	case r.AccountErr != "":
		add("sol", DoctorFail, "can't read %s: %s", r.Address, r.AccountErr)
	// Unlike an Algorand account, a Solana payer with no SOL still holds its
	// token account and signs, and the node pays the open's fee, so a pool
	// already at its working set serves; rent_pool judges whether it is.
	case r.Lamports == 0:
		add("sol", DoctorWarn, "%s holds no SOL on %s; topping up the ticket rent pool, and the payer's own acks and refunds, pay fees in SOL", r.Address, net)
	default:
		add("sol", DoctorPass, "%s holds %s SOL, %s spendable", r.Address, lamportsSOL(r.Lamports), lamportsSOL(spendable))
	}

	switch {
	case !programOK:
		add("usdc_account", DoctorSkip, "needs the program read")
	case r.UsdcErr != "":
		add("usdc_account", DoctorFail, "can't read the USDC token account: %s", r.UsdcErr)
	case !r.UsdcAccount:
		add("usdc_account", DoctorFail, "no USDC token account (mint %s); create it before paying for requests", r.Mint)
	case r.UsdcFrozen:
		add("usdc_account", DoctorFail, "the USDC token account (mint %s) is frozen; requests can't be paid from it", r.Mint)
	default:
		add("usdc_account", DoctorPass, "has a USDC token account (mint %s)", r.Mint)
	}

	switch {
	case !usdcOK:
		add("usdc_balance", DoctorSkip, "needs the USDC token account")
	case r.UsdcBalance == 0:
		add("usdc_balance", DoctorWarn, "holds no USDC; requests are paid in USDC")
	default:
		add("usdc_balance", DoctorPass, "holds %s USDC", micros(r.UsdcBalance))
	}

	switch {
	case !accountOK || !programOK:
		add("rent_pool", DoctorSkip, "needs the account and program reads")
	case r.PoolErr != "":
		add("rent_pool", DoctorFail, "can't read the ticket rent pool: %s", r.PoolErr)
	default:
		s, msg := rentPoolVerdict(r, spendable)
		add("rent_pool", s, "%s", msg)
	}

	switch {
	case !rpcOK:
		add("operators", DoctorSkip, needsRPC)
	case r.OperatorsErr != "":
		add("operators", DoctorFail, "can't read the operators: %s", r.OperatorsErr)
	case len(r.Nodes) == 0:
		add("operators", DoctorFail, "no nodes are registered on %s", net)
	default:
		s, msg := operatorsVerdict(r.Nodes, r.RelayRequired, r.AllowStaging, "SOL")
		add("operators", s, "%s", msg)
	}
	return out
}

// rentPoolVerdict is the prepaid_pool verdict for the rent pool. The pool's
// own rent is no ticket's, so a pool counts what it holds past that, plus
// the rent its live tickets hold, as the wallet's top-up does.
func rentPoolVerdict(r SolanaDoctorReadings, spendable uint64) (DoctorStatus, string) {
	pool := rentPoolReading{exists: r.PoolExists, lamports: r.PoolLamports, openTickets: r.OpenTickets}
	p := planRentDeposit(r.Slots, r.TicketRent, r.PoolRent, pool, spendable)
	gross := rentPoolGross(r.TicketRent, r.PoolRent, pool)
	backed := gross / r.TicketRent
	has := lamportsSOL(spendable) + " SOL is spendable"
	held := fmt.Sprintf("%s SOL deposited, backing %d of %d tickets, %d in use", lamportsSOL(gross), backed, r.Slots, r.OpenTickets)
	switch {
	case !r.PoolExists && p.Unaffordable:
		return DoctorFail, fmt.Sprintf("no rent pool yet, and the first request's deposit needs %s SOL; %s", lamportsSOL(p.Need), has)
	case !r.PoolExists:
		return DoctorWarn, fmt.Sprintf("no rent pool yet; the first request deposits %s SOL", lamportsSOL(p.Amount))
	case p.Unaffordable:
		return DoctorFail, fmt.Sprintf("the pool backs no ticket and the next deposit needs %s SOL; %s", lamportsSOL(p.Need), has)
	// Every slot held by a live ticket, with nothing the next request would
	// add: its open fails until one settles or is refunded.
	case p.Amount == 0 && backed > 0 && r.OpenTickets >= backed:
		return DoctorWarn, fmt.Sprintf("%s; a new request can't open a ticket until one settles or is refunded", held)
	case p.BelowTarget && p.Amount == 0:
		return DoctorWarn, fmt.Sprintf("the pool backs %d of %d tickets, and another deposit needs %s SOL; %s", backed, r.Slots, lamportsSOL(p.Need), has)
	case p.Amount > 0:
		return DoctorPass, fmt.Sprintf("%s; the next request adds %s SOL", held, lamportsSOL(p.Amount))
	default:
		return DoctorPass, held
	}
}

// lamportsSOL renders lamports in whole SOL, with no trailing zeros.
func lamportsSOL(v uint64) string {
	s := strconv.FormatUint(v/1_000_000_000, 10)
	if frac := v % 1_000_000_000; frac != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%09d", frac), "0")
	}
	return s
}

// diagnoseSolana is Diagnose on the Solana rail.
func diagnoseSolana(ctx context.Context, cfg Config, address string) (DoctorReport, error) {
	payer, err := solana.ParsePublicKey(address)
	if err != nil {
		return DoctorReport{}, configError(fmt.Sprintf("address %q is not a Solana address: %v", address, err))
	}
	cfg.Signer = nil
	cfg.SolanaSigner = readOnlySigner(address)
	cfg = cfg.withDefaults()
	dep, warnings, err := cfg.validate()
	if err != nil {
		return DoctorReport{}, err
	}
	sn := dep.Solana
	base := solanaDoctorBase(cfg, sn, address)
	var r SolanaDoctorReadings
	rc, err := rpc.NewClient(sn.RPCEndpoint, rpc.WithTransport(cfg.solanaTransport()))
	if err != nil {
		r = base
		r.RPCErr = err.Error()
	} else {
		r = gatherSolanaDoctorReadings(ctx, &rpcDoctorChain{cfg: cfg, rpc: rc, program: sn.Program, payer: payer}, base)
	}
	return doctorReport(r.Network, address, SolanaDoctorChecks(r), warnings), nil
}

// solanaDoctorBase is the readings a defaulted cfg decides before anything is
// read.
func solanaDoctorBase(cfg Config, sn SolanaNetwork, address string) SolanaDoctorReadings {
	return SolanaDoctorReadings{
		Network:       sn.Cluster,
		Address:       address,
		Slots:         uint64(cfg.ConcurrentSlots),
		RelayRequired: cfg.Privacy == PrivacyRelayRequired,
		AllowStaging:  cfg.AllowStaging,
		Program:       sn.Program.String(),
	}
}

// solanaDoctorChain is what diagnoseSolana reads, apart from the reading of
// it so a test can supply the answers.
type solanaDoctorChain interface {
	cluster(ctx context.Context) (blockHeight uint64, genesis solana.Hash, err error)
	// config returns the program's Config and the cluster's rent for a
	// ticket and a rent pool.
	config(ctx context.Context) (c *zsescrow.Config, ticketRent, poolRent uint64, err error)
	balance(ctx context.Context) (uint64, error)
	// usdcAccount is the payer's token account for mint, nil when there is
	// none. It is read only after config succeeded.
	usdcAccount(ctx context.Context, mint solana.PublicKey) (*zsescrow.TokenAccount, error)
	rentPool(ctx context.Context) (rentPoolReading, error)
	nodes(ctx context.Context) ([]Operator, error)
}

// gatherSolanaDoctorReadings fills r from c. A failed cluster read ends it,
// since every other read goes through the same RPC.
func gatherSolanaDoctorReadings(ctx context.Context, c solanaDoctorChain, r SolanaDoctorReadings) SolanaDoctorReadings {
	height, genesis, err := c.cluster(ctx)
	if err != nil {
		r.RPCErr = err.Error()
		return r
	}
	r.BlockHeight, r.Genesis = height, genesis.String()

	type fleet struct {
		ops []Operator
		err error
	}
	done := make(chan fleet, 1)
	go func() {
		ops, err := c.nodes(ctx)
		done <- fleet{ops, err}
	}()

	if cfg, ticketRent, poolRent, err := c.config(ctx); err != nil {
		r.ConfigErr = err.Error()
	} else {
		r.ConfigGenesis, r.Mint, r.ConfigPaused = cfg.GenesisHash.String(), cfg.USDCMint.String(), cfg.Paused
		r.TicketRent, r.PoolRent = ticketRent, poolRent
		switch t, err := c.usdcAccount(ctx, cfg.USDCMint); {
		case err != nil:
			r.UsdcErr = err.Error()
		case t != nil:
			r.UsdcAccount, r.UsdcFrozen, r.UsdcBalance = true, t.State == zsescrow.TokenFrozen, t.Amount
		}
	}
	if r.Lamports, err = c.balance(ctx); err != nil {
		r.AccountErr, r.Lamports = err.Error(), 0
	}
	if p, err := c.rentPool(ctx); err != nil {
		r.PoolErr = err.Error()
	} else {
		r.PoolExists, r.PoolLamports, r.OpenTickets = p.exists, p.lamports, p.openTickets
	}

	f := <-done
	switch {
	case errors.Is(f.err, errNoOperators):
		// An empty fleet, which the operators check names as such.
	case f.err != nil:
		r.OperatorsErr = f.err.Error()
	}
	for _, o := range f.ops {
		r.Nodes = append(r.Nodes, DoctorNode{
			Owner:                   o.OwnerAddr,
			Reachable:               o.Reachable,
			ProtoVersion:            o.ProtoVersion,
			Staging:                 o.Staging,
			SignerSpendableLamports: o.SignerSpendableLamports,
		})
	}
	return r
}

// rpcDoctorChain reads the cluster through one RPC client, at the commitment
// the wallet and the registry read at.
type rpcDoctorChain struct {
	cfg     Config
	rpc     rpc.Client
	program solana.PublicKey
	payer   solana.PublicKey
}

func (c *rpcDoctorChain) cluster(ctx context.Context) (uint64, solana.Hash, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	h, err := c.rpc.GetBlockHeight(ctx, rentCommitment)
	if err != nil {
		return 0, solana.Hash{}, err
	}
	g, err := c.rpc.GetGenesisHash(ctx)
	if err != nil {
		return 0, solana.Hash{}, err
	}
	return h, g, nil
}

func (c *rpcDoctorChain) config(ctx context.Context) (*zsescrow.Config, uint64, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	cfg, err := readSolanaConfig(ctx, c.rpc, zsescrow.Deployment{Program: c.program})
	if err != nil {
		return nil, 0, 0, err
	}
	ticketRent, err := c.rpc.GetMinimumBalanceForRentExemption(ctx, zsescrow.TicketSize, rentCommitment)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("ticket rent: %w", err)
	}
	poolRent, err := c.rpc.GetMinimumBalanceForRentExemption(ctx, zsescrow.RentPoolSize, rentCommitment)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("pool rent: %w", err)
	}
	return cfg, ticketRent, poolRent, nil
}

func (c *rpcDoctorChain) balance(ctx context.Context) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	return c.rpc.GetBalance(ctx, c.payer, rentCommitment)
}

func (c *rpcDoctorChain) usdcAccount(ctx context.Context, mint solana.PublicKey) (*zsescrow.TokenAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	key := zsescrow.Deployment{Program: c.program, Mint: mint}.TokenAccount(c.payer)
	acct, err := getAccount(ctx, c.rpc, key)
	if err != nil || acct == nil {
		return nil, err
	}
	if acct.Owner != solana.TokenProgramID {
		return nil, fmt.Errorf("%s is not a token account", key)
	}
	t, err := zsescrow.DecodeTokenAccount(acct.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return t, nil
}

func (c *rpcDoctorChain) rentPool(ctx context.Context) (rentPoolReading, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	acct, err := getAccount(ctx, c.rpc, zsescrow.Deployment{Program: c.program}.RentPool(c.payer))
	if err != nil || acct == nil || acct.Owner != c.program {
		return rentPoolReading{}, err
	}
	rp, err := zsescrow.DecodeRentPool(acct.Data)
	if err != nil {
		return rentPoolReading{}, err
	}
	return rentPoolReading{exists: true, lamports: acct.Lamports, openTickets: rp.OpenTickets}, nil
}

func (c *rpcDoctorChain) nodes(ctx context.Context) ([]Operator, error) {
	// The source derives the deployment from the chain before it probes, so
	// the doctor drops a node advertising another one, as a Client does.
	src := newDiscoverySource(c.cfg, ticket.DeploymentID{})
	src.Chain = &SolanaChainReader{RPC: c.rpc, Program: c.program, OperatorIDs: c.cfg.Discovery.OperatorIDs, Log: c.cfg.Logger}
	ctx, cancel := context.WithTimeout(ctx, bootFetchTimeout)
	defer cancel()
	return src.Fetch(ctx)
}
