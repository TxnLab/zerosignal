/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// Deployment is a resolved Network: the rail, the escrow on it, and how to
// reach it. Key names it for local state; ticket.DeploymentID is its signed
// identity, and needs a genesis read this does not make.
type Deployment struct {
	Rail ticket.Rail
	// Network is the label Key carries (see ResolveNetwork), not necessarily
	// the network the config named.
	Network     string
	Algod       algod.Config // resolved
	EscrowAppID uint64
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

// Escrow is the escrow's id on its rail, as text.
func (d Deployment) Escrow() string { return strconv.FormatUint(d.EscrowAppID, 10) }

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
func ResolveNetwork(n Network) (Deployment, []string, error) {
	rail := n.Rail
	if rail == 0 {
		rail = ticket.RailAlgorand
	}
	if rail != ticket.RailAlgorand {
		return Deployment{}, nil, configError(fmt.Sprintf("Network.Rail %s is not supported yet", RailName(rail)))
	}
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
