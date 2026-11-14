/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// Deployment is a resolved Network: the rail, the escrow on it, and how to
// reach it. Key names it for local state; ticket.DeploymentID is its signed
// identity, and needs a genesis read this does not make.
type Deployment struct {
	Rail ticket.Rail
	// Network is the label Key carries (see ResolveNetwork), not necessarily
	// the network the config named.
	Network string
	// Algod and EscrowAppID are the Algorand rail's, Solana the Solana
	// rail's; each is zero on the other rail.
	Algod       algod.Config // resolved
	EscrowAppID uint64
	Solana      SolanaNetwork // resolved: the cluster lowered, the preset applied
}

// The Solana cluster presets. The table is zsescrow's, which a node reads
// without the SDK; these names keep the SDK's API unchanged.
const (
	SolanaClusterDevnet   = zsescrow.ClusterDevnet
	SolanaClusterLocalnet = zsescrow.ClusterLocalnet
)

// SolanaClusters are the preset names.
func SolanaClusters() []string { return zsescrow.Clusters() }

// SolanaClusterPreset is a preset's RPC endpoint and program id, and false
// for a name that is none.
func SolanaClusterPreset(name string) (rpcEndpoint string, program solana.PublicKey, ok bool) {
	c, ok := zsescrow.ClusterPreset(name)
	return c.RPCEndpoint, c.Program, ok
}

// FreeCreditIssuer is a free-credit issuer: its key and where it serves.
type FreeCreditIssuer = zsescrow.FreeCreditIssuer

// SolanaClusterFreeCreditIssuers is a preset's default free-credit issuers,
// and false for a name that is no preset.
func SolanaClusterFreeCreditIssuers(name string) ([]FreeCreditIssuer, bool) {
	c, ok := zsescrow.ClusterPreset(name)
	return c.FreeCreditIssuers, ok
}

// RailName is a rail as Key and the TS SDK spell it.
func RailName(r ticket.Rail) string {
	switch r {
	case ticket.RailAlgorand:
		return "algorand"
	case ticket.RailSolana:
		return "solana"
	}
	return fmt.Sprintf("rail%d", r)
}

// FeeUnit is the coin a rail's network fees are paid in. A fee amount is in
// its base units, Decimals of them to the coin.
type FeeUnit struct {
	Currency string
	Decimals int
}

// FeeUnitOf is rail r's fee unit. The zero rail is Algorand, as
// Network.Rail's is; a rail neither names has none.
func FeeUnitOf(r ticket.Rail) FeeUnit {
	switch r {
	case 0, ticket.RailAlgorand:
		return FeeUnit{Currency: "ALGO", Decimals: 6}
	case ticket.RailSolana:
		return FeeUnit{Currency: "SOL", Decimals: 9}
	}
	return FeeUnit{}
}

// algoOnly is v for a field named for ALGO (µALGO fees, the ALGO/USD rate)
// when fees are in ALGO, and 0 otherwise: those fields never carry another
// coin's units.
func algoOnly[T uint64 | float64](u FeeUnit, v T) T {
	if u.Currency != "ALGO" {
		return 0
	}
	return v
}

// nativeUSD is the reserve's USD rate for u's coin: each rail's node sends its
// own coin's rate, and a rate for another coin would price u's fees wrong.
func nativeUSD(u FeeUnit, rt *ReservedTicket) float64 {
	switch u.Currency {
	case "ALGO":
		return rt.AlgoUSDPrice
	case "SOL":
		return rt.SOLUSDPrice
	}
	return 0
}

// FeeUnit is the coin the deployment's network fees are paid in.
func (d Deployment) FeeUnit() FeeUnit { return FeeUnitOf(d.Rail) }

// Local reports whether d is a development chain on this machine: the localnet
// preset, reached at a loopback endpoint. Nothing there is real money and its
// nodes run on this machine, so a payer's defaults loosen (Config.Privacy,
// Config.AllowPrivateHosts). The endpoint check is what keeps a config that
// names localnet but points at another chain from loosening them: a program id
// says nothing about the chain (the localnet preset's is deployed on devnet
// too), so the label alone proves nothing.
func (d Deployment) Local() bool {
	if d.Network != "localnet" {
		return false
	}
	endpoint := d.Algod.ResolvedEndpoint
	if d.Rail == ticket.RailSolana {
		endpoint = d.Solana.RPCEndpoint
	}
	return zsescrow.LoopbackEndpoint(endpoint)
}

// publicGenesis names the public chains by their genesis hash, in each rail's
// usual encoding.
var publicGenesis = map[ticket.Rail]map[string]string{
	ticket.RailAlgorand: {
		"wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=": "mainnet",
		"SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=": "testnet",
		"mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=": "betanet",
	},
	ticket.RailSolana: {
		rpc.MainnetGenesis: "mainnet-beta",
		rpc.TestnetGenesis: "testnet",
		rpc.DevnetGenesis:  "devnet",
	},
}

// PublicChain names the public chain whose genesis hash genesis is, or ""
// for any other. Local's endpoint check reads only a URL, and a loopback URL
// can be a tunnel or a forwarder to a public chain, so a payer whose defaults
// Local loosened checks the chain itself before it trusts them.
func PublicChain(rail ticket.Rail, genesis []byte) string {
	enc := base64.StdEncoding.EncodeToString(genesis)
	if rail == ticket.RailSolana {
		if len(genesis) != len(solana.Hash{}) {
			return ""
		}
		enc = solana.Hash(genesis).String()
	}
	return publicGenesis[rail][enc]
}

// Escrow is the escrow's id on its rail, as text: the app id, or the program
// id in base58.
func (d Deployment) Escrow() string {
	if d.Rail == ticket.RailSolana {
		return d.Solana.Program.String()
	}
	return strconv.FormatUint(d.EscrowAppID, 10)
}

// Key names the deployment's local state: journal, catalog and spend files,
// storage keys. Readable rather than the hash of ticket.DeploymentID, because
// hosts open those files before anything reads the chain, and a localnet's
// genesis is per instance. It is never signed and never sent.
func (d Deployment) Key() string {
	return RailName(d.Rail) + "-" + d.Network + "-" + d.Escrow()
}

// LegacyKey is the name the same state had before keys carried the rail and
// network: the bare app id.
func (d Deployment) LegacyKey() string {
	if d.Rail != ticket.RailAlgorand {
		return ""
	}
	return d.Escrow()
}

// Owns reports whether a journal row belongs to this deployment. A row
// written before rows named their deployment matches on the app id alone,
// which is how it was scoped then.
func (d Deployment) Owns(r TicketRecord) bool {
	if r.Deployment != "" {
		return r.Deployment == d.Key()
	}
	return d.Rail == ticket.RailAlgorand && r.EscrowAppID == d.EscrowAppID
}

// StateFile is the file named prefix-<key>.json in dir, and the name it had
// before as prefix-<legacy key>.json; legacy is empty where there was none.
func StateFile(dir, prefix string, d Deployment) (path, legacy string) {
	path = filepath.Join(dir, prefix+"-"+d.Key()+".json")
	if lk := d.LegacyKey(); lk != "" {
		legacy = filepath.Join(dir, prefix+"-"+lk+".json")
	}
	return path, legacy
}

// AdoptLegacyFile moves legacy to current when current does not exist, and
// otherwise leaves both. It links rather than renames because a rename
// replaces a current that appeared after the check, with the older file. A
// journal needs OpenFileJournal's merge instead.
func AdoptLegacyFile(legacy, current string) error {
	if legacy == "" || legacy == current {
		return nil
	}
	if err := os.Link(legacy, current); err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.Remove(legacy)
}

// ResolveNetwork applies the presets and overrides to n without reading the
// chain, and returns warnings for settings that work but are probably
// mistakes. The zero Network is mainnet.
//
// The label in Key is the preset an app id belongs to, so a config naming
// mainnet and one naming only its endpoint share files, as the proxy's spend
// file always has. Any other app id takes the network the config names, since
// app ids are per network and testnet's app 42 is not mainnet's: sharing a
// journal, a mainnet Client would forget a testnet row whose box it cannot
// find. Only an endpoint alone is "custom", which splits that config's state
// from the same deployment named as localnet; the cost is rows left in the
// other's file, not rows lost.
//
// On Solana the label is the cluster the config names, or "custom" for an
// endpoint alone: a localnet can load any build at any id, so unlike an app id
// a program id says nothing about which chain it is on.
func ResolveNetwork(n Network) (Deployment, []string, error) {
	switch n.Rail {
	case 0, ticket.RailAlgorand:
		return resolveAlgorand(n)
	case ticket.RailSolana:
		return resolveSolana(n)
	}
	return Deployment{}, nil, configError(fmt.Sprintf("Network.Rail %s is not supported", RailName(n.Rail)))
}

func resolveAlgorand(n Network) (Deployment, []string, error) {
	if n.Solana != (SolanaNetwork{}) {
		return Deployment{}, nil, configError("Network.Solana is the Solana rail's; set Network.Rail to ticket.RailSolana")
	}
	rail := ticket.RailAlgorand
	ac := n.Algod
	if ac.Network == "" && ac.Endpoint == "" {
		// Only a Network left wholly unset means mainnet. A token or an app id
		// on its own was meant for some chain, and guessing mainnet for it
		// would pay there.
		if ac.Token != "" || n.EscrowAppID != 0 {
			return Deployment{}, nil, configError("Network.Algod.Network or Endpoint is required when Token or EscrowAppID is set")
		}
		ac.Network = string(algod.NetworkMainnet)
	}
	if err := ac.Resolve(); err != nil {
		return Deployment{}, nil, configError(err.Error())
	}
	var warnings []string
	appID := n.EscrowAppID
	if appID == 0 {
		appID = algod.EscrowAppID(string(ac.ResolvedNetwork))
		if ac.EndpointOverrides() {
			warnings = append(warnings, fmt.Sprintf(
				"Network.Algod.Endpoint overrides the %s preset but the escrow app id is still that preset's (%d); set Network.EscrowAppID if the endpoint is another chain",
				ac.ResolvedNetwork, appID))
		}
	}
	if appID == 0 {
		return Deployment{}, nil, configError("Network.EscrowAppID is required for this network")
	}
	return Deployment{
		Rail:        rail,
		Network:     deploymentLabel(appID, ac.ResolvedNetwork),
		Algod:       ac,
		EscrowAppID: appID,
	}, warnings, nil
}

func resolveSolana(n Network) (Deployment, []string, error) {
	if n.Algod != (algod.Config{}) || n.EscrowAppID != 0 {
		return Deployment{}, nil, configError("Network.Algod and Network.EscrowAppID are the Algorand rail's; a Solana Network sets Network.Solana")
	}
	s := n.Solana
	// Lowered but not trimmed, as algod.Config.Resolve does.
	s.Cluster = strings.ToLower(s.Cluster)
	if s.Cluster == "" && s.RPCEndpoint == "" {
		return Deployment{}, nil, configError("Network.Solana.Cluster or RPCEndpoint is required on the Solana rail")
	}
	var p zsescrow.Cluster
	if s.Cluster != "" {
		var ok bool
		if p, ok = zsescrow.ClusterPreset(s.Cluster); !ok {
			return Deployment{}, nil, configError(fmt.Sprintf("Network.Solana.Cluster must be one of %s (case-insensitive), got %q",
				strings.Join(SolanaClusters(), "|"), n.Solana.Cluster))
		}
	}
	var warnings []string
	if s.Program.IsZero() {
		s.Program = p.Program
		if s.Cluster != "" && s.RPCEndpoint != "" && s.RPCEndpoint != p.RPCEndpoint {
			warnings = append(warnings, fmt.Sprintf(
				"Network.Solana.RPCEndpoint overrides the %s preset but the program is still that preset's (%s); set Network.Solana.Program if the endpoint is another cluster",
				s.Cluster, s.Program))
		}
	}
	if s.Program.IsZero() {
		return Deployment{}, nil, configError("Network.Solana.Program is required for this network")
	}
	if s.RPCEndpoint == "" {
		s.RPCEndpoint = p.RPCEndpoint
	}
	label := s.Cluster
	if label == "" {
		label = "custom"
	}
	return Deployment{Rail: ticket.RailSolana, Network: label, Solana: s}, warnings, nil
}

func deploymentLabel(appID uint64, named algod.Network) string {
	for _, p := range []algod.Network{algod.NetworkTestnet, algod.NetworkMainnet} {
		if algod.EscrowAppID(string(p)) == appID {
			return string(p)
		}
	}
	if named != "" {
		return string(named)
	}
	return "custom"
}
