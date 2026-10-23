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
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// DoctorStatus is one check's verdict. Only DoctorFail means a request from
// this address can't succeed as things stand.
type DoctorStatus string

const (
	DoctorPass DoctorStatus = "pass"
	DoctorWarn DoctorStatus = "warn"
	DoctorFail DoctorStatus = "fail"
	// DoctorSkip is a check that needs a reading an earlier check failed to get.
	DoctorSkip DoctorStatus = "skip"
)

// DoctorCheck is one line of a doctor report.
type DoctorCheck struct {
	ID      string       `json:"id"`
	Status  DoctorStatus `json:"status"`
	Message string       `json:"message"`
}

// DoctorReport is what Diagnose found for one payer address.
type DoctorReport struct {
	// Network is empty for a chain named only by its endpoint.
	Network string        `json:"network"`
	Address string        `json:"address"`
	Checks  []DoctorCheck `json:"checks"`
	// Failed is set when any check failed.
	Failed bool `json:"failed"`
	// Warnings are config settings that work but are probably mistakes.
	Warnings []string `json:"warnings"`
}

// DoctorReadings are what Diagnose reads from the chain and the fleet, and
// all DoctorChecks judges. A read that failed carries its error text and
// leaves its values zero. Pinned with DoctorChecks by
// testdata/doctor_vectors.json, which the TS SDK's doctorChecks replays.
type DoctorReadings struct {
	// Network is the resolved network name, empty for a chain named only by
	// its endpoint.
	Network string `json:"network"`
	Address string `json:"address"`
	// Slots is the working set the prepaid pool is funded for.
	Slots uint64 `json:"slots,string"`
	// RelayRequired and AllowStaging are the Config's, which decide which
	// nodes a request could reach.
	RelayRequired bool `json:"relayRequired"`
	AllowStaging  bool `json:"allowStaging"`

	AlgodErr  string `json:"algodErr,omitempty"`
	LastRound uint64 `json:"lastRound,string"`
	MinFee    uint64 `json:"minFee,string"`

	EscrowAppID uint64 `json:"escrowAppId,string"`
	EscrowErr   string `json:"escrowErr,omitempty"`
	TicketMbr   uint64 `json:"ticketMbr,string"`
	// QuotaDue is the free-quota box MBR the pool still has to cover.
	QuotaDue    uint64 `json:"quotaDue,string"`
	UsdcAssetID uint64 `json:"usdcAssetId,string"`

	AccountErr  string `json:"accountErr,omitempty"`
	Amount      uint64 `json:"amount,string"`
	MinBalance  uint64 `json:"minBalance,string"`
	UsdcOptedIn bool   `json:"usdcOptedIn"`
	UsdcBalance uint64 `json:"usdcBalance,string"`
	PoolOptedIn bool   `json:"poolOptedIn"`

	PoolErr     string `json:"poolErr,omitempty"`
	AlgoBalance uint64 `json:"algoBalance,string"`
	OpenTickets uint64 `json:"openTickets,string"`

	OperatorsErr string       `json:"operatorsErr,omitempty"`
	Nodes        []DoctorNode `json:"nodes"`
}

// DoctorNode is what the operators check reads off one discovered node.
type DoctorNode struct {
	// Owner is the operator's owner address: a relay must be another's.
	Owner        string `json:"owner"`
	Reachable    bool   `json:"reachable"`
	ProtoVersion string `json:"protoVersion"`
	Staging      bool   `json:"staging"`
	// SignerSpendable is nil when the signing account was never read, which
	// routes, as in selection.
	SignerSpendable *uint64 `json:"signerSpendable,omitempty,string"`
}

// DoctorChecks judges readings, in order: algod, escrow, algo, usdc_opt_in,
// usdc_balance, prepaid_pool, operators.
func DoctorChecks(r DoctorReadings) []DoctorCheck {
	net := r.Network
	if net == "" {
		net = "this network"
	}
	algodOK := r.AlgodErr == ""
	escrowOK := algodOK && r.EscrowErr == "" && r.TicketMbr > 0
	accountOK := algodOK && r.AccountErr == ""
	var out []DoctorCheck
	add := func(id string, s DoctorStatus, format string, a ...any) {
		out = append(out, DoctorCheck{ID: id, Status: s, Message: fmt.Sprintf(format, a...)})
	}
	const needsAlgod = "needs algod"

	if algodOK {
		add("algod", DoctorPass, "algod on %s answers at round %d", net, r.LastRound)
	} else {
		add("algod", DoctorFail, "can't reach algod on %s: %s", net, r.AlgodErr)
	}

	switch {
	case !algodOK:
		add("escrow", DoctorSkip, needsAlgod)
	case r.EscrowErr != "":
		add("escrow", DoctorFail, "can't read escrow app %d: %s", r.EscrowAppID, r.EscrowErr)
	case r.TicketMbr == 0:
		add("escrow", DoctorFail, "escrow app %d reports no ticket MBR", r.EscrowAppID)
	default:
		add("escrow", DoctorPass, "escrow app %d: %s ALGO per ticket, USDC asset %d", r.EscrowAppID, micros(r.TicketMbr), r.UsdcAssetID)
	}

	spendable := uint64(0)
	if r.Amount > r.MinBalance {
		spendable = r.Amount - r.MinBalance
	}
	switch {
	case !algodOK:
		add("algo", DoctorSkip, needsAlgod)
	case r.AccountErr != "":
		add("algo", DoctorFail, "can't read %s: %s", r.Address, r.AccountErr)
	case r.Amount == 0:
		add("algo", DoctorFail, "%s holds no ALGO on %s; fund it with ALGO for fees and the ticket pool", r.Address, net)
	default:
		add("algo", DoctorPass, "%s holds %s ALGO, %s spendable", r.Address, micros(r.Amount), micros(spendable))
	}

	const needsAccount = "needs the account and escrow reads"
	switch {
	case !accountOK || !escrowOK:
		add("usdc_opt_in", DoctorSkip, needsAccount)
	case r.UsdcOptedIn:
		add("usdc_opt_in", DoctorPass, "opted in to USDC (asset %d)", r.UsdcAssetID)
	default:
		add("usdc_opt_in", DoctorFail, "not opted in to USDC (asset %d); opt in before paying for requests", r.UsdcAssetID)
	}

	switch {
	case !accountOK || !escrowOK || !r.UsdcOptedIn:
		add("usdc_balance", DoctorSkip, "needs the USDC opt-in")
	case r.UsdcBalance == 0:
		add("usdc_balance", DoctorWarn, "holds no USDC; requests are paid in USDC")
	default:
		add("usdc_balance", DoctorPass, "holds %s USDC", micros(r.UsdcBalance))
	}

	switch {
	case !accountOK || !escrowOK:
		add("prepaid_pool", DoctorSkip, needsAccount)
	case r.PoolErr != "":
		add("prepaid_pool", DoctorFail, "can't read the prepaid ticket pool: %s", r.PoolErr)
	default:
		dep := escrow.PayerDeposit{AlgoBalance: r.AlgoBalance, OpenTickets: r.OpenTickets}
		p := planDeposit(r.Slots, r.TicketMbr, r.QuotaDue, dep, r.PoolOptedIn, spendable, r.MinFee)
		backed := r.AlgoBalance / r.TicketMbr
		has := micros(spendable) + " ALGO is spendable"
		held := fmt.Sprintf("%s ALGO deposited, backing %d of %d tickets, %d in use", micros(r.AlgoBalance), backed, r.Slots, r.OpenTickets)
		switch {
		case !r.PoolOptedIn && p.Unaffordable:
			add("prepaid_pool", DoctorFail, "not opted in, and the first request's deposit needs %s ALGO; %s", micros(p.Need), has)
		case !r.PoolOptedIn:
			add("prepaid_pool", DoctorWarn, "not opted in; the first request deposits %s ALGO", micros(p.Amount))
		case p.Unaffordable:
			add("prepaid_pool", DoctorFail, "the pool backs no ticket and the next deposit needs %s ALGO; %s", micros(p.Need), has)
		// Every slot held by a live ticket, with nothing the next request
		// would add: its open reverts until one settles or is refunded, and a
		// frozen ticket never is.
		case p.Amount == 0 && backed > 0 && r.OpenTickets >= backed:
			add("prepaid_pool", DoctorWarn, "%s; a new request can't open a ticket until one settles or is refunded", held)
		case p.BelowTarget && p.Amount == 0 && backed >= r.Slots:
			add("prepaid_pool", DoctorWarn, "the pool backs all %d tickets but not the free-quota box, which needs %s ALGO; %s", r.Slots, micros(p.Need), has)
		case p.BelowTarget && p.Amount == 0:
			add("prepaid_pool", DoctorWarn, "the pool backs %d of %d tickets, and another deposit needs %s ALGO; %s", backed, r.Slots, micros(p.Need), has)
		case p.Amount > 0:
			add("prepaid_pool", DoctorPass, "%s; the next request adds %s ALGO", held, micros(p.Amount))
		default:
			add("prepaid_pool", DoctorPass, "%s", held)
		}
	}

	switch {
	case !algodOK:
		add("operators", DoctorSkip, needsAlgod)
	case r.OperatorsErr != "":
		add("operators", DoctorFail, "can't read the operators: %s", r.OperatorsErr)
	case len(r.Nodes) == 0:
		add("operators", DoctorFail, "no nodes are registered on %s", net)
	default:
		s, msg := operatorsVerdict(r)
		add("operators", s, "%s", msg)
	}
	return out
}

func operatorsVerdict(r DoctorReadings) (DoctorStatus, string) {
	// A relay must belong to another owner, so a fleet of one owner has none
	// to probe through, and its nodes read as unreachable for that alone.
	owners := map[string]bool{}
	for _, n := range r.Nodes {
		owners[n.Owner] = true
	}
	var usable, noRelay, unreachable, incompatible, staging, unfunded int
	for _, n := range r.Nodes {
		switch {
		case !n.Reachable && r.RelayRequired && len(owners) == 1:
			noRelay++
		case !n.Reachable:
			unreachable++
		case !wire.ProtoVersionCompatible(n.ProtoVersion):
			incompatible++
		case n.Staging && !r.AllowStaging:
			staging++
		case n.SignerSpendable != nil && *n.SignerSpendable < selection.MinSignerSpendableMicroAlgos:
			unfunded++
		default:
			usable++
		}
	}
	var parts []string
	for _, c := range []struct {
		n    int
		what string
	}{
		{noRelay, "with no relay of another operator"},
		{unreachable, "unreachable"},
		{incompatible, "on an incompatible protocol version"},
		{staging, "staging"},
		{unfunded, "with a signing account short of fee ALGO"},
	} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.what))
		}
	}
	why := strings.Join(parts, ", ")
	switch {
	case usable == 0:
		return DoctorFail, "no node can serve a request: " + why
	case why == "":
		return DoctorPass, fmt.Sprintf("%d of %d nodes can serve a request", usable, len(r.Nodes))
	default:
		return DoctorPass, fmt.Sprintf("%d of %d nodes can serve a request; the rest: %s", usable, len(r.Nodes), why)
	}
}

// micros renders a 6-decimal base-unit amount (µALGO, micro-USDC) in whole
// units, with no trailing zeros.
func micros(v uint64) string {
	s := strconv.FormatUint(v/1_000_000, 10)
	if frac := v % 1_000_000; frac != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%06d", frac), "0")
	}
	return s
}

// doctorReadTimeout bounds each of Diagnose's algod reads, which ride a
// transport that retries a failing algod for minutes; the TS SDK's default
// request timeout.
const doctorReadTimeout = 30 * time.Second

// Diagnose reads, without signing anything, what a Client paying from address
// would need: algod, the escrow app, the account's ALGO and USDC, the prepaid
// ticket pool, and one discovery cycle over the fleet. cfg is read as New reads
// it, its signers ignored. An error is a config Diagnose can't run on; every
// failed read is a check in the report instead. It reads Algorand only.
func Diagnose(ctx context.Context, cfg Config, address string) (DoctorReport, error) {
	if cfg.Network.Rail == ticket.RailSolana {
		return DoctorReport{}, configError("Diagnose reads the Algorand rail only; Network.Rail is solana")
	}
	cfg.SolanaSigner = nil
	if _, err := types.DecodeAddress(address); err != nil {
		return DoctorReport{}, configError(fmt.Sprintf("address %q is not an Algorand address: %v", address, err))
	}
	cfg.Signer = readOnlySigner(address)
	cfg = cfg.withDefaults()
	dep, warnings, err := cfg.validate()
	if err != nil {
		return DoctorReport{}, err
	}
	ac, appID := dep.Algod, dep.EscrowAppID
	base := doctorBase(cfg, ac, appID, address)
	var r DoctorReadings
	chain, err := algod.NewClient(ac.ResolvedEndpoint, ac.ResolvedToken, algod.WithTransport(cfg.algodTransport()))
	if err != nil {
		r = base
		r.AlgodErr = err.Error()
	} else {
		r = gatherDoctorReadings(ctx, &algodDoctorChain{cfg: cfg, chain: chain, appID: appID, address: address}, base)
	}
	checks := DoctorChecks(r)
	rep := DoctorReport{Network: r.Network, Address: address, Checks: checks, Warnings: warnings}
	for _, c := range checks {
		rep.Failed = rep.Failed || c.Status == DoctorFail
	}
	return rep, nil
}

// doctorBase is the readings a defaulted cfg decides before anything is read.
func doctorBase(cfg Config, ac algod.Config, appID uint64, address string) DoctorReadings {
	return DoctorReadings{
		Network:       string(ac.ResolvedNetwork),
		Address:       address,
		Slots:         uint64(cfg.ConcurrentSlots),
		RelayRequired: cfg.Privacy == PrivacyRelayRequired,
		AllowStaging:  cfg.AllowStaging,
		EscrowAppID:   appID,
	}
}

// doctorChain is what Diagnose reads, apart from the reading of it so a test
// can supply the answers.
type doctorChain interface {
	status(ctx context.Context) (lastRound, minFee uint64, err error)
	escrowConfig(ctx context.Context) (ticketMbr, usdcAssetID, quotaDue uint64, err error)
	account(ctx context.Context) (models.Account, error)
	// payerDeposit is read only after escrowConfig succeeded.
	payerDeposit(ctx context.Context) (escrow.PayerDeposit, error)
	nodes(ctx context.Context) ([]Operator, error)
}

// gatherDoctorReadings fills r from c. A failed algod read ends it, since
// every other read needs algod.
func gatherDoctorReadings(ctx context.Context, c doctorChain, r DoctorReadings) DoctorReadings {
	var err error
	if r.LastRound, r.MinFee, err = c.status(ctx); err != nil {
		r.AlgodErr = err.Error()
		return r
	}

	// Discovery probes every node, the slow part, so it runs beside the rest.
	type fleet struct {
		ops []Operator
		err error
	}
	done := make(chan fleet, 1)
	go func() {
		ops, err := c.nodes(ctx)
		done <- fleet{ops, err}
	}()

	if r.TicketMbr, r.UsdcAssetID, r.QuotaDue, err = c.escrowConfig(ctx); err != nil {
		r.EscrowErr = err.Error()
		r.TicketMbr, r.UsdcAssetID, r.QuotaDue = 0, 0, 0
	}
	if acct, err := c.account(ctx); err != nil {
		r.AccountErr = err.Error()
	} else {
		r.Amount, r.MinBalance = acct.Amount, acct.MinBalance
		for _, h := range acct.Assets {
			if r.UsdcAssetID != 0 && h.AssetId == r.UsdcAssetID {
				r.UsdcOptedIn, r.UsdcBalance = true, h.Amount
			}
		}
		for _, ls := range acct.AppsLocalState {
			if ls.Id == r.EscrowAppID {
				r.PoolOptedIn = true
			}
		}
	}
	// Only an opted-in payer has a pool to read.
	if r.PoolOptedIn && r.EscrowErr == "" {
		if dep, err := c.payerDeposit(ctx); err != nil {
			r.PoolErr = err.Error()
		} else {
			r.AlgoBalance, r.OpenTickets = dep.AlgoBalance, dep.OpenTickets
		}
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
			Owner:           o.OwnerAddr,
			Reachable:       o.Reachable,
			ProtoVersion:    o.ProtoVersion,
			Staging:         o.Staging,
			SignerSpendable: o.SignerSpendableMicroAlgos,
		})
	}
	return r
}

// algodDoctorChain reads algod. Its simulates are sent as the application
// account rather than the payer, as the TS SDK's are: the payer this is most
// often run for holds no ALGO yet, and a simulate sent from an account not in
// the ledger fails. The fee sink New uses exists only on public networks.
type algodDoctorChain struct {
	cfg     Config
	chain   algod.Client
	appID   uint64
	address string
	ec      *escrow.Client
}

func (a *algodDoctorChain) status(ctx context.Context) (uint64, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	st, err := a.chain.SDKClient().Status().Do(ctx)
	if err != nil {
		return 0, 0, err
	}
	sp, err := a.chain.SuggestedParams(ctx)
	if err != nil {
		return 0, 0, err
	}
	return st.LastRound, sp.MinFee, nil
}

func (a *algodDoctorChain) escrowConfig(ctx context.Context) (uint64, uint64, uint64, error) {
	ec, err := escrow.NewClient(a.appID, a.chain)
	if err != nil {
		return 0, 0, 0, err
	}
	rctx, cancel := context.WithTimeout(ctx, escrowConfigTimeout)
	defer cancel()
	if err := ec.RefreshConfig(rctx, ec.AppAddr.String()); err != nil {
		return 0, 0, 0, err
	}
	a.ec = ec
	return ec.TicketMbr, ec.UsdcAssetID, ec.FreeQuotaMbrDueFor(rctx, a.address), nil
}

func (a *algodDoctorChain) account(ctx context.Context) (models.Account, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	return a.chain.SDKClient().AccountInformation(a.address).Do(ctx)
}

func (a *algodDoctorChain) payerDeposit(ctx context.Context) (escrow.PayerDeposit, error) {
	ctx, cancel := context.WithTimeout(ctx, doctorReadTimeout)
	defer cancel()
	return a.ec.ReadPayerDeposit(ctx, a.address)
}

func (a *algodDoctorChain) nodes(ctx context.Context) ([]Operator, error) {
	// No deployment: the doctor reports reachability, which the legacy
	// ephemeral signature answers for every node version.
	src := newChainSource(a.cfg, a.appID, a.chain, ticket.DeploymentID{})
	src.ProxyPayerAddr = crypto.GetApplicationAddress(a.appID).String()
	ctx, cancel := context.WithTimeout(ctx, bootFetchTimeout)
	defer cancel()
	return src.Fetch(ctx)
}

// readOnlySigner names the address Diagnose reads for and signs nothing.
type readOnlySigner string

var errReadOnlySigner = errors.New("zs: Diagnose signs nothing")

func (s readOnlySigner) Address() string          { return string(s) }
func (s readOnlySigner) HasAccount(a string) bool { return a == string(s) }
func (readOnlySigner) SignBytes(context.Context, string, []byte) ([]byte, error) {
	return nil, errReadOnlySigner
}

func (readOnlySigner) SignWithAccount(context.Context, types.Transaction, string) (string, []byte, error) {
	return "", nil, errReadOnlySigner
}
