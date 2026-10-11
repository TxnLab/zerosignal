/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// catalogFormatVersion guards the on-disk schema. Bump it when persistedOperator
// changes incompatibly; LoadCatalog rejects a mismatched file (the proxy then
// starts cold and rewrites it on the next refresh).
const catalogFormatVersion = 1

// persistedCatalog is the on-disk form of the routing/discovery catalog.
// Persisting it lets a restart warm-start from the last-known catalog instead of
// rediscovering the whole fleet over bounded-probing sweep cycles.
//
// It deliberately EXCLUDES:
//   - the short-lived forward-secret ephemeral seal key (EphemeralRecipient /
//     Pubkey / Expiry / IssuedAt) — it would be expired on restart and must be
//     re-probed; persisting it would risk a stale/downgraded seal target;
//   - the TEE verdict (re-verified on the next attestation probe);
//   - the signing account's spendable ALGO (SignerSpendableMicroAlgos). It moves
//     on every settle, so persisting it would defeat the unchanged-catalog write
//     skip, and nothing would read it: the catalog seeds routing only when the
//     startup chain read FAILED, and FetchChain re-reads balances whenever that
//     read succeeds;
//   - the this-cycle transients (Reachable / Probed / LastRefreshAt).
//
// It keeps identity + the expensive-to-rediscover capability data + the
// ReachableAsOf carry clock, so a loaded node is immediately advertised/routable
// via the carry window while dispatch's ReprobeEphemeral self-heals
// its seal key on first use.
type persistedCatalog struct {
	Version   int                 `json:"version"`
	Operators []persistedOperator `json:"operators"`
}

type persistedOperator struct {
	ID                    uint64                   `json:"id"`
	NodeID                uint64                   `json:"node_id"`
	NFDAppID              uint64                   `json:"nfd_app_id,omitempty"`
	OwnerAddr             string                   `json:"owner_addr"`
	SigningAddr           string                   `json:"signing_addr"`
	TicketSigningKey      []byte                   `json:"ticket_signing_key,omitempty"`
	BaseURL               string                   `json:"base_url"`
	Staging               bool                     `json:"staging,omitempty"`
	Models                []string                 `json:"models,omitempty"`
	ModelCapacities       map[string]ModelCapacity `json:"model_capacities,omitempty"`
	BuiltinTools          []BuiltinToolDef         `json:"builtin_tools,omitempty"`
	MaxToolIters          int                      `json:"max_tool_iters,omitempty"`
	ToolHeadroom          uint64                   `json:"tool_headroom_per_iteration,omitempty"`
	NodeVersion           string                   `json:"node_version,omitempty"`
	ProtoVersion          string                   `json:"proto_version,omitempty"`
	ReachableAsOf         time.Time                `json:"reachable_as_of,omitempty"`
	Metrics               OperatorMetrics          `json:"metrics"`
	MinChargeOutputTokens uint64                   `json:"min_charge_output_tokens,omitempty"`
	MinChargeAlgoTxns     uint64                   `json:"min_charge_algo_txns,omitempty"`
	MinChargeMicroUSDC    uint64                   `json:"min_charge_microusdc,omitempty"`
}

func toPersisted(op Operator) persistedOperator {
	return persistedOperator{
		ID:                    op.ID,
		NodeID:                op.NodeID,
		NFDAppID:              op.NFDAppID,
		OwnerAddr:             op.OwnerAddr,
		SigningAddr:           op.SigningAddr,
		TicketSigningKey:      op.TicketSigningKey,
		BaseURL:               op.BaseURL,
		Staging:               op.Staging,
		Models:                op.Models,
		ModelCapacities:       op.ModelCapacities,
		BuiltinTools:          op.BuiltinTools,
		MaxToolIters:          op.MaxToolIters,
		ToolHeadroom:          op.ToolHeadroomPerIteration,
		NodeVersion:           op.NodeVersion,
		ProtoVersion:          op.ProtoVersion,
		ReachableAsOf:         op.ReachableAsOf,
		Metrics:               op.Metrics,
		MinChargeOutputTokens: op.MinChargeOutputTokens,
		MinChargeAlgoTxns:     op.MinChargeAlgoTxns,
		MinChargeMicroUSDC:    op.MinChargeMicroUSDC,
	}
}

// minorFloor drops a restored proto_version to "<major>.0".
//
// A version read off disk says what a peer advertised the LAST time this proxy
// ran, which is not evidence about what it is running now — and the seed
// snapshot is served immediately, before any probe, so it really does drive
// sizing. This is the same reasoning as wire.BootstrapProtoVersion, which seeds
// an unprobed peer at minor 0 precisely so no minor-gated capability is ASSUMED
// of a node we have not heard from; a stale persisted version is the same hazard
// one step removed.
//
// It matters because the gates are asymmetric. Assuming too HIGH a version is a
// hard failure: sizing the reserve with input-bound v2 against an operator that
// rolled back to 9.1 makes the node measure the same body with v1 and reject it
// AFTER escrow.open, where there is no failover. Assuming too low merely
// forgoes the tightening for one refresh interval — which is exactly the
// behaviour that shipped before v2 existed.
//
// The MAJOR is preserved, so compatibility filtering (major equality) is
// unaffected and a restored peer stays in the candidate and relay pools.
func minorFloor(version string) string {
	if version == "" {
		return ""
	}
	major, _, ok := strings.Cut(version, ".")
	if !ok || major == "" {
		return version
	}
	return major + ".0"
}

func (p persistedOperator) toOperator() Operator {
	var key ed25519.PublicKey
	if len(p.TicketSigningKey) > 0 {
		key = ed25519.PublicKey(p.TicketSigningKey)
	}
	// Reachable/Probed stay false and the ephemeral/TEE fields stay nil: a loaded
	// node is "not probed this cycle", so the carry window (ReachableAsOf) governs
	// its advertising and the next refresh / ReprobeEphemeral re-establishes the
	// live seal key.
	return Operator{
		ID:                       p.ID,
		NodeID:                   p.NodeID,
		NFDAppID:                 p.NFDAppID,
		OwnerAddr:                p.OwnerAddr,
		SigningAddr:              p.SigningAddr,
		TicketSigningKey:         key,
		BaseURL:                  p.BaseURL,
		Staging:                  p.Staging,
		Models:                   p.Models,
		ModelCapacities:          p.ModelCapacities,
		BuiltinTools:             p.BuiltinTools,
		MaxToolIters:             p.MaxToolIters,
		ToolHeadroomPerIteration: p.ToolHeadroom,
		NodeVersion:              p.NodeVersion,
		ProtoVersion:             minorFloor(p.ProtoVersion),
		ReachableAsOf:            p.ReachableAsOf,
		Metrics:                  p.Metrics,
		MinChargeOutputTokens:    p.MinChargeOutputTokens,
		MinChargeAlgoTxns:        p.MinChargeAlgoTxns,
		MinChargeMicroUSDC:       p.MinChargeMicroUSDC,
	}
}

// marshalCatalog encodes ops in the on-disk form. Split from writeCatalog so a
// caller can hash the bytes and skip an unchanged write (see the registry's
// persist).
func marshalCatalog(ops []Operator) ([]byte, error) {
	pc := persistedCatalog{Version: catalogFormatVersion, Operators: make([]persistedOperator, len(ops))}
	for i, op := range ops {
		pc.Operators[i] = toPersisted(op)
	}
	return json.Marshal(pc)
}

// writeCatalog writes data to path atomically (temp file + rename), 0600, first
// creating path's directory when ensureDir is set. It deliberately does NOT
// fsync the temp file or the parent directory: persistence is best-effort, and
// a crash that leaves a torn/zero-length file is caught by LoadCatalog (bad JSON
// → error → cold start), so a missing fsync only ever costs a colder next start,
// never correctness — keeping it off the refresh path.
func writeCatalog(path string, data []byte, ensureDir bool) error {
	if ensureDir {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("catalog dir: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write catalog: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename catalog: %w", err)
	}
	return nil
}

// SaveCatalog writes ops to path atomically (temp file + rename), 0600. It is
// best-effort: the caller logs and continues on error — a failed save only costs
// a colder next start, never correctness.
func SaveCatalog(path string, ops []Operator) error {
	data, err := marshalCatalog(ops)
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}
	return writeCatalog(path, data, true)
}

// LoadCatalog reads a previously-saved catalog. A missing file returns
// (nil, nil) — a fresh install starts cold. A malformed / wrong-version file
// returns (nil, err) so the caller can log and start cold (and overwrite it on
// the next refresh).
func LoadCatalog(path string) ([]Operator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	return decodeCatalog(data)
}

// decodeCatalog is LoadCatalog after the read, so
// testdata/persisted_catalog_vectors.json can pin it for the TS SDK.
func decodeCatalog(data []byte) ([]Operator, error) {
	var pc persistedCatalog
	if err := json.Unmarshal(data, &pc); err != nil {
		return nil, fmt.Errorf("unmarshal catalog: %w", err)
	}
	if pc.Version != catalogFormatVersion {
		return nil, fmt.Errorf("catalog format version %d != supported %d", pc.Version, catalogFormatVersion)
	}
	ops := make([]Operator, len(pc.Operators))
	for i, po := range pc.Operators {
		ops[i] = po.toOperator()
	}
	return ops, nil
}

// MergeCatalog fills each fresh operator not confirmed live this fetch
// (Reachable=false) with last-known capabilities from base, bounded by
// maxCarryAge (0 = DefaultMaxCarryAge). It is the startup counterpart of the
// registry's carry-forward: a warm restart merges the persisted catalog into a
// partial or bounded live probe so nodes stay advertised/routable immediately
// rather than filling in over sweep cycles. Fresh probe results always win.
func MergeCatalog(base, fresh []Operator, maxCarryAge time.Duration) []Operator {
	return mergeCatalogAt(base, fresh, maxCarryAge, time.Now())
}

// mergeCatalogAt is MergeCatalog at a given now, so
// testdata/registry_cycle_vectors.json can pin it for the TS SDK.
func mergeCatalogAt(base, fresh []Operator, maxCarryAge time.Duration, now time.Time) []Operator {
	if maxCarryAge <= 0 {
		maxCarryAge = DefaultMaxCarryAge
	}
	byRef := make(map[NodeRef]Operator, len(base))
	for _, op := range base {
		byRef[RefOf(op)] = op
	}
	out := append([]Operator(nil), fresh...)
	carryWithin(byRef, out, now, maxCarryAge)
	return out
}
