/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/wire"
)

// ErrOperatorUnknown is returned by RegistryProvider.Resolve when the
// requested operator id isn't in the registry.
var ErrOperatorUnknown = errors.New("operator unknown")

// TEE capability is advertised off-chain (`/v1/zs/details`) and verified here
// against the operator's attestation evidence — there is no on-chain
// OperatorRecord.teeCapabilities field. That migration was considered and
// deferred; proto/TEE.md § 9.3 records the reasons, the conditions that would
// unblock it, and the field shape it would take.

// RegistryProvider is the proxy's view of the set of operators it can
// dispatch to. The interface is shaped so that a future on-chain backend
// (Algorand app with box storage per operator, Phase 2 in the plan) is a
// drop-in replacement for StaticRegistryProvider.
//
// Operators returns every operator that advertises support for model, in
// the registry's selection-preference order. An empty slice means no
// operator is available for that model; the caller translates that into
// an OpenAI-shaped 503 for the client.
//
// Resolve returns one specific operator by its id (the on-chain
// operator id allocated by ZeroSignalEscrow.createOperator) — used by the
// tool-call affinity path to re-dispatch to the same operator
// regardless of current selection order.
//
// AllModels returns the deduplicated union of every model ID advertised
// by any *reachable* operator in the registry. Used to serve GET /v1/models
// without forwarding to an upstream. Operators with Reachable=false are
// excluded — their carried-forward model lists are kept in the snapshot
// so dispatch's reserve path can still try them, but the discovery surface
// must reflect what's currently servable. Returns nil when no reachable
// operator has declared a model list — callers should fall back to the
// upstream when they observe both an empty model list AND no operators
// at all (true passthrough mode); a non-empty operator slice with empty
// AllModels means every operator is offline and should surface as such
// rather than as a passthrough.
//
// AllBuiltinTools returns the deduplicated union of every hayai built-in
// tool advertised by any *reachable* operator. Keyed by Type; when two
// operators advertise the same type the first-seen definition wins
// (registry order). Used to serve GET /v1/zs/details on the proxy so
// downstream clients (TUI, SDKs) can discover the aggregate tool surface
// without probing each node. Returns nil when no reachable operator has
// advertised any tools.
//
// AllModelDetails returns the deduplicated union of model capability info
// across all *reachable* operators. For each model ID, InputModalities and
// OutputModalities are the union across operators (most permissive wins).
// Context sizing fields take the minimum across operators that declare them
// (a zero means "undeclared" and is skipped). Returns nil when no reachable
// operator has declared a model list.
//
// AllOperators returns a copy of the full operator slice — every operator
// the registry currently knows about, regardless of which model they
// serve. Used to render the per-operator view on /v1/zs/operators
// (and the TUI's /operators command) without collapsing into a UNION
// the way AllModels and AllModelDetails do. The returned slice is
// independent of the registry's internal storage; mutating it does not
// affect future reads. It is the one aggregate NOT staging-filtered — the
// relay pool is built from it; see the implementations.
//
// The three UNION aggregates above additionally hold out nodes flagged staging
// on-chain unless the payer set zs.allow_staging, and nodes whose signing
// account is below the routing floor, so the proxy advertises exactly what it
// routes to. Operators(ctx, model) does not — dispatch needs the full
// model-serving set to tell "held out for staging" (503 no_production_operator)
// or "held out for funding" (503 no_funded_operator) from "nobody serves this
// model".
type RegistryProvider interface {
	Operators(ctx context.Context, model string) ([]Operator, error)
	Resolve(ctx context.Context, operatorID, nodeID uint64) (Operator, error)
	AllModels(ctx context.Context) []string
	AllBuiltinTools(ctx context.Context) []BuiltinToolDef
	AllModelDetails(ctx context.Context) []inject.OperatorDetailsModel
	AllNodeVersions(ctx context.Context) []string
	AllOperators(ctx context.Context) []Operator
	// ReprobeEphemeral live-re-probes op out of band from the scheduled refresh
	// to refresh its forward-secrecy ephemeral recipient, returning the
	// refreshed operator and whether it can now seal. The dispatch path calls it
	// to self-heal a candidate skipped for a stale/missing ephemeral (typically a
	// just-restarted node) instead of failing the request until the next
	// scheduled refresh. Implementations without a live probe (static configs)
	// re-check the operator as-is.
	ReprobeEphemeral(ctx context.Context, op Operator) (Operator, bool)

	// RecordModelDemand notes that a model was just requested so the background
	// refresh can prioritize re-probing its servers (bounded demand-driven
	// probing). Advisory — a no-op on providers that probe everything
	// (static configs).
	RecordModelDemand(model string)
}

// NodeRef is the (operator id, node id) compound key the registry — and the
// proxy's dispatch map-back — address a single running node by. Under the
// operator/node split an operator runs many nodes (each its own Operator record
// sharing ID with a distinct NodeID), so both key by node, not by operator id
// alone (keying by id would collapse an operator's nodes to whichever was last
// ingested, and the duplicate-id guard would reject the 2nd node outright).
type NodeRef struct {
	Op   uint64
	Node uint64
}

func (r NodeRef) String() string { return fmt.Sprintf("%d/%d", r.Op, r.Node) }

// RefOf is the NodeRef of an Operator.
func RefOf(o Operator) NodeRef { return NodeRef{Op: o.ID, Node: o.NodeID} }

// StaticRegistryProvider serves a fixed set of operators loaded at config
// time. Goroutine-safe for reads (the slice is never mutated after
// construction).
type StaticRegistryProvider struct {
	operators []Operator
	byNode    map[NodeRef]Operator
	// allowStaging is the payer's opt-in to on-chain staging nodes, the twin of
	// DynamicRegistryProvider.allowStaging: see advertisable.
	allowStaging bool
}

// StaticRegistryConfig carries the tunables for a StaticRegistryProvider,
// mirroring DynamicRegistryConfig's shape so the two providers express the same
// knob the same way.
type StaticRegistryConfig struct {
	// AllowStaging opts the payer in to nodes their operator flagged staging
	// on-chain (zs.allow_staging). False — the zero value and the default —
	// holds them out of every discovery aggregate; see advertisable.
	AllowStaging bool
}

// NewStaticRegistryProvider builds a registry from the given operators with
// default tunables — notably staging-OFF, the production-safe default. Callers
// that need to vary those use NewStaticRegistryProviderWithConfig.
//
// Each operator must carry a ProtoVersion this build can speak, or it surfaces
// on no discovery aggregate — see wireIncompatible. The dynamic provider gets
// this from its details probe; here it is the caller's job.
func NewStaticRegistryProvider(ops []Operator) (*StaticRegistryProvider, error) {
	return NewStaticRegistryProviderWithConfig(ops, StaticRegistryConfig{})
}

// NewStaticRegistryProviderWithConfig builds a registry from the given operators.
// Duplicate (id, node id) values are rejected — the pair must be unique for
// Resolve to be unambiguous, but multiple nodes may share an operator id.
// Operators with ID == 0 are also rejected: id 0 is reserved as the "unset"
// sentinel both off-chain configs and the contract counter agree on.
func NewStaticRegistryProviderWithConfig(ops []Operator, cfg StaticRegistryConfig) (*StaticRegistryProvider, error) {
	byNode := make(map[NodeRef]Operator, len(ops))
	for _, op := range ops {
		if op.ID == 0 {
			return nil, errors.New("operator missing id (0 is reserved)")
		}
		ref := RefOf(op)
		if _, dup := byNode[ref]; dup {
			return nil, fmt.Errorf("duplicate node %d/%d", op.ID, op.NodeID)
		}
		byNode[ref] = op
	}
	return &StaticRegistryProvider{
		operators:    append([]Operator(nil), ops...),
		byNode:       byNode,
		allowStaging: cfg.AllowStaging,
	}, nil
}

// HeldOutStaging reports whether op is a node its operator flagged staging
// on-chain that the payer has not opted in to. One spelling of the rule, shared
// by every discovery gate: the aggregates here and in registry_dynamic.go, and
// the /v1/zs/operators handler, which cannot go through advertisable because its
// source (AllOperators) must stay unfiltered for the relay pool.
//
// Exported for that handler. It is deliberately NOT what
// server.routableIgnoringSize uses — that one mirrors SelectTargets' golden-
// vectored hard excludes, a different authority that happens to agree today.
func HeldOutStaging(op Operator, allowStaging bool) bool {
	return op.Staging && !allowStaging
}

// wireIncompatible reports whether op speaks a different wire-protocol
// generation than this build, so dispatch could never seal a request for it.
// The second half of "advertise exactly what you can route to", alongside
// HeldOutStaging — SelectTargets refuses these at its wire-version step and
// answers 503 no_compatible_operator.
//
// Note an EMPTY ProtoVersion counts as incompatible: ProtoVersionCompatible maps
// it to wire.LegacyProtoVersion ("1.0"), a different major than this build's.
//
// On the DYNAMIC provider that is safe because ProtoVersion is written in the
// same straight-line block as Reachable/ReachableAsOf when a details probe
// succeeds (fetcher.go), and carried forward with them — so Reachable implies a
// version, and the one reachable-but-empty state left is a node whose probe
// returned no proto_version at all. Dispatch refuses exactly that state on
// exactly this field, so the two agree rather than the catalog inventing a rule.
//
// On the STATIC provider there is no probe cycle, so the requirement is on the
// CALLER: an operator handed to NewStaticRegistryProvider(WithConfig) without a
// ProtoVersion is invisible to all four aggregates. That is only reachable from
// tests today, but both constructors are exported, so it is part of their
// contract.
//
// Unlike staging there is no opt-in knob, which is why /v1/zs/operators
// deliberately keeps listing these with their proto_version: an operator on the
// wrong major has to be able to see that somewhere.
func wireIncompatible(op Operator) bool {
	return !wire.ProtoVersionCompatible(op.ProtoVersion)
}

// advertisable reports whether op's capabilities should surface on the discovery
// aggregates — the static twin of DynamicRegistryProvider.advertisable, minus the
// carry window (a static registry has no probe cycle to carry across). See that
// method for why staging, wire-incompatible and underfunded nodes are held out.
func (p *StaticRegistryProvider) advertisable(op Operator) bool {
	return op.Reachable && !HeldOutStaging(op, p.allowStaging) && !wireIncompatible(op) && !op.SignerUnderfunded()
}

// Operators returns every operator whose Models contains model, in
// configured order. Operators with an empty Models list are treated as
// model-agnostic and included for every request.
func (p *StaticRegistryProvider) Operators(_ context.Context, model string) ([]Operator, error) {
	out := make([]Operator, 0, len(p.operators))
	for _, op := range p.operators {
		if op.ServesModel(model) {
			out = append(out, op)
		}
	}
	return out, nil
}

// Resolve returns the node (operatorID, nodeID), or ErrOperatorUnknown.
func (p *StaticRegistryProvider) Resolve(_ context.Context, operatorID, nodeID uint64) (Operator, error) {
	op, ok := p.byNode[NodeRef{Op: operatorID, Node: nodeID}]
	if !ok {
		return Operator{}, ErrOperatorUnknown
	}
	return op, nil
}

// ReprobeEphemeral re-checks whether op currently has a usable forward-secrecy
// ephemeral recipient. A static registry has no live probe — its operators come
// from config, not /v1/zs/details — so there is nothing to refresh: it
// reports the operator unchanged plus whether it can seal right now. The dynamic
// registry is the one that performs the live re-probe self-heal.
func (p *StaticRegistryProvider) ReprobeEphemeral(_ context.Context, op Operator) (Operator, bool) {
	_, err := op.SealRecipient(time.Now())
	return op, err == nil
}

// RecordModelDemand is a no-op for the static registry: it probes nothing on a
// schedule, so there is no bounded probe set to prioritize.
func (p *StaticRegistryProvider) RecordModelDemand(_ string) {}

// AllModels returns the deduplicated union of every model ID across all
// advertisable operators, so the discovery surface only advertises what dispatch
// can currently serve.
func (p *StaticRegistryProvider) AllModels(_ context.Context) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, op := range p.operators {
		if !p.advertisable(op) {
			continue
		}
		for _, m := range op.Models {
			if _, ok := seen[m]; !ok {
				seen[m] = struct{}{}
				out = append(out, m)
			}
		}
	}
	return out
}

// AllBuiltinTools returns the deduplicated union of every built-in tool
// advertised by any operator. First-seen wins on collision: the
// downstream client only needs the Type to advertise on the wire, and
// the node's rewriter uses its own local definition when a request
// arrives, so a disagreement on Name/Description/Parameters between
// operators is harmless as long as one operator is available to serve
// the request.
func (p *StaticRegistryProvider) AllBuiltinTools(_ context.Context) []BuiltinToolDef {
	seen := make(map[string]struct{})
	var out []BuiltinToolDef
	for _, op := range p.operators {
		if !p.advertisable(op) {
			continue
		}
		for _, t := range op.BuiltinTools {
			if _, ok := seen[t.Type]; ok {
				continue
			}
			seen[t.Type] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// AllNodeVersions returns the sorted, deduplicated list of every
// non-empty NodeVersion advertised by any operator. Empty strings
// (operators that haven't been probed yet or whose node pre-dates the
// field) are skipped. Returns nil when no operator advertises a
// version — `omitempty` keeps the field absent from the proxy's
// /v1/zs/details response in that case.
func (p *StaticRegistryProvider) AllNodeVersions(_ context.Context) []string {
	return collectNodeVersions(p.operators, p.allowStaging)
}

// AllModelDetails returns the deduplicated union of model capability info
// across all operators. Modalities are unioned; sizing fields take the
// minimum of declared (non-zero) values across operators. Pricing fields
// take the lowest declared (non-zero) USD/1M rate across operators — a
// "from $X" advertising number. The authoritative per-request rate is
// whichever operator's ticket the proxy actually consumes.
func (p *StaticRegistryProvider) AllModelDetails(_ context.Context) []inject.OperatorDetailsModel {
	type entry struct {
		inject.OperatorDetailsModel
	}
	seen := make(map[string]*inject.OperatorDetailsModel)
	// Coordinates need every value before a majority can be picked, so they are
	// collected here and folded in a second pass (the streaming merge below
	// can't compute a mode). The vote is one per reachable NODE — like every
	// other aggregation in this function (pricing-min, modality-union), an
	// operator running N nodes casts N votes (operator/node split). Advisory,
	// so per-node vs per-operator weighting is immaterial.
	coordsByModel := make(map[string][]*inject.ModelCoordinates)
	// Like coordinates, the weights digests need every operator's value before a
	// cross-operator consensus/mismatch can be computed, so they are collected
	// here and folded in the same second pass.
	digestsByModel := make(map[string][]string)
	// The model IDENTITY keys (declared HF source, else the frontier canonical for
	// a sourceless closed-weights model) are likewise consensus-folded in the
	// second pass, so the aggregate carries a value only when operators agree.
	sourcesByModel := make(map[string][]string)
	canonicalsByModel := make(map[string][]string)
	for _, op := range p.operators {
		if !p.advertisable(op) {
			continue
		}
		for _, m := range op.Models {
			cap := op.ModelCapacities[m]
			if cap.Coordinates != nil {
				coordsByModel[m] = append(coordsByModel[m], cap.Coordinates)
			}
			if cap.WeightsDigest != "" {
				digestsByModel[m] = append(digestsByModel[m], cap.WeightsDigest)
			}
			if cap.Source != "" {
				sourcesByModel[m] = append(sourcesByModel[m], cap.Source)
			}
			if cap.CanonicalID != "" {
				canonicalsByModel[m] = append(canonicalsByModel[m], cap.CanonicalID)
			}
			if existing, ok := seen[m]; ok {
				existing.InputModalities = unionStrings(existing.InputModalities, cap.InputModalities)
				existing.OutputModalities = unionStrings(existing.OutputModalities, cap.OutputModalities)
				existing.Tags = unionStrings(existing.Tags, cap.Tags)
				existing.ToolUse = aggregateBool(existing.ToolUse, cap.ToolUse)
				existing.Reasoning = aggregateReasoning(existing.Reasoning, cap.Reasoning)
				if cap.ContextWindow > 0 && (existing.ContextWindow == 0 || cap.ContextWindow < existing.ContextWindow) {
					existing.ContextWindow = cap.ContextWindow
				}
				if cap.MaxOutputTokens > 0 && (existing.MaxOutputTokens == 0 || cap.MaxOutputTokens < existing.MaxOutputTokens) {
					existing.MaxOutputTokens = cap.MaxOutputTokens
				}
				if cap.InputUSDPer1M > 0 && (existing.InputRateUSDPer1M == 0 || cap.InputUSDPer1M < existing.InputRateUSDPer1M) {
					existing.InputRateUSDPer1M = cap.InputUSDPer1M
				}
				if cap.OutputUSDPer1M > 0 && (existing.OutputRateUSDPer1M == 0 || cap.OutputUSDPer1M < existing.OutputRateUSDPer1M) {
					existing.OutputRateUSDPer1M = cap.OutputUSDPer1M
				}
				// Cache-read discount: lowest advertised across operators
				// ("from $X"), nil-preserving so a model no operator discounts
				// stays without a cache line.
				existing.CacheReadRateUSDPer1M = minRatePtr(existing.CacheReadRateUSDPer1M, cap.CacheReadUSDPer1M)
				// Long-context (surcharge) tier: display-only cross-operator min,
				// mirroring the token/cache rules — lowest threshold among
				// tier-advertising operators (minNonZero) and lowest of each high
				// rate ("from $X"). The per-operator values on op.ModelCapacities are
				// untouched — THAT is what verifyReservePrice uses; this aggregate is
				// discovery display only, so mixing a low threshold from one operator
				// with a low high-rate from another is acceptable, matching cache-read.
				existing.LongContextThresholdTokens = minNonZero(existing.LongContextThresholdTokens, cap.LongContextThresholdTokens)
				existing.LongContextInputRateUSDPer1M = minRatePtr(existing.LongContextInputRateUSDPer1M, cap.LongContextInputUSDPer1M)
				existing.LongContextOutputRateUSDPer1M = minRatePtr(existing.LongContextOutputRateUSDPer1M, cap.LongContextOutputUSDPer1M)
				existing.LongContextCacheReadRateUSDPer1M = minRatePtr(existing.LongContextCacheReadRateUSDPer1M, cap.LongContextCacheReadUSDPer1M)
				// Image factors: surface the lowest declared (non-zero)
				// value across operators — consistent with the rate
				// fields' "from $X" semantics, since image cost = factor
				// × output_rate. Absence on every operator means the
				// model is not wired for that endpoint at all and clients
				// should treat the missing field as "not served here."
				if cap.ImageToolRateMicroUSDC > 0 && (existing.ImageToolRateMicroUSDC == 0 || cap.ImageToolRateMicroUSDC < existing.ImageToolRateMicroUSDC) {
					existing.ImageToolRateMicroUSDC = cap.ImageToolRateMicroUSDC
				}
				if cap.ImageEditToolRateMicroUSDC > 0 && (existing.ImageEditToolRateMicroUSDC == 0 || cap.ImageEditToolRateMicroUSDC < existing.ImageEditToolRateMicroUSDC) {
					existing.ImageEditToolRateMicroUSDC = cap.ImageEditToolRateMicroUSDC
				}
				if cap.ImageRateMicroUSDC > 0 && (existing.ImageRateMicroUSDC == 0 || cap.ImageRateMicroUSDC < existing.ImageRateMicroUSDC) {
					existing.ImageRateMicroUSDC = cap.ImageRateMicroUSDC
				}
				if cap.ImageEditRateMicroUSDC > 0 && (existing.ImageEditRateMicroUSDC == 0 || cap.ImageEditRateMicroUSDC < existing.ImageEditRateMicroUSDC) {
					existing.ImageEditRateMicroUSDC = cap.ImageEditRateMicroUSDC
				}
				// Display-only companions (representative price at the operator's
				// default size, and its per-image ceiling), same lowest-non-zero
				// rule. The pair stays coherent under it: an operator advertising a
				// cap always advertises a default too, and its default never exceeds
				// its own cap, so min(default) <= min(cap) across the fleet.
				existing.ImageToolBaseMicroUSDC = minNonZero(existing.ImageToolBaseMicroUSDC, cap.ImageToolBaseMicroUSDC)
				existing.ImageEditToolBaseMicroUSDC = minNonZero(existing.ImageEditToolBaseMicroUSDC, cap.ImageEditToolBaseMicroUSDC)
				existing.ImageDefaultMicroUSDC = minNonZero(existing.ImageDefaultMicroUSDC, cap.ImageDefaultMicroUSDC)
				existing.ImageEditDefaultMicroUSDC = minNonZero(existing.ImageEditDefaultMicroUSDC, cap.ImageEditDefaultMicroUSDC)
				existing.ImageCapMicroUSDC = minNonZero(existing.ImageCapMicroUSDC, cap.ImageCapMicroUSDC)
				existing.ImageEditCapMicroUSDC = minNonZero(existing.ImageEditCapMicroUSDC, cap.ImageEditCapMicroUSDC)
				// Eligibility is price-independent (free rate routes advertise a 0
				// rate): any operator serving the route makes the aggregate serve it.
				if cap.ServesImageGen() {
					existing.ServesImageGen = true
				}
				if cap.ServesImageEdit() {
					existing.ServesImageEdit = true
				}
			} else {
				seen[m] = &inject.OperatorDetailsModel{
					ID:                               m,
					ContextWindow:                    cap.ContextWindow,
					MaxOutputTokens:                  cap.MaxOutputTokens,
					InputModalities:                  append([]string(nil), cap.InputModalities...),
					OutputModalities:                 append([]string(nil), cap.OutputModalities...),
					InputRateUSDPer1M:                cap.InputUSDPer1M,
					OutputRateUSDPer1M:               cap.OutputUSDPer1M,
					CacheReadRateUSDPer1M:            minRatePtr(nil, cap.CacheReadUSDPer1M),
					LongContextThresholdTokens:       cap.LongContextThresholdTokens,
					LongContextInputRateUSDPer1M:     minRatePtr(nil, cap.LongContextInputUSDPer1M),
					LongContextOutputRateUSDPer1M:    minRatePtr(nil, cap.LongContextOutputUSDPer1M),
					LongContextCacheReadRateUSDPer1M: minRatePtr(nil, cap.LongContextCacheReadUSDPer1M),
					Reasoning:                        aggregateReasoning(nil, cap.Reasoning),
					ToolUse:                          aggregateBool(nil, cap.ToolUse),
					Tags:                             append([]string(nil), cap.Tags...),
					ImageToolRateMicroUSDC:           cap.ImageToolRateMicroUSDC,
					ImageEditToolRateMicroUSDC:       cap.ImageEditToolRateMicroUSDC,
					ImageToolBaseMicroUSDC:           cap.ImageToolBaseMicroUSDC,
					ImageEditToolBaseMicroUSDC:       cap.ImageEditToolBaseMicroUSDC,
					ImageRateMicroUSDC:               cap.ImageRateMicroUSDC,
					ImageEditRateMicroUSDC:           cap.ImageEditRateMicroUSDC,
					ImageDefaultMicroUSDC:            cap.ImageDefaultMicroUSDC,
					ImageEditDefaultMicroUSDC:        cap.ImageEditDefaultMicroUSDC,
					ImageCapMicroUSDC:                cap.ImageCapMicroUSDC,
					ImageEditCapMicroUSDC:            cap.ImageEditCapMicroUSDC,
					ServesImageGen:                   cap.ServesImageGen(),
					ServesImageEdit:                  cap.ServesImageEdit(),
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	for m, d := range seen {
		d.Coordinates = aggregateCoordinates(coordsByModel[m])
		d.WeightsDigest, d.WeightsMismatch = aggregateDigest(digestsByModel[m])
		d.Source = aggregateSource(sourcesByModel[m])
		// canonical_id only rides when there is no source — mirror the node's
		// per-model rule (inject.OperatorDetailsModel.CanonicalID) so the aggregate
		// keeps the same "present ⇒ sourceless" invariant a consumer relies on.
		if d.Source == "" {
			d.CanonicalID = aggregateIdentity(canonicalsByModel[m])
		}
	}
	out := make([]inject.OperatorDetailsModel, 0, len(seen))
	for _, d := range seen {
		out = append(out, *d)
	}
	return out
}

// AllOperators returns a copy of the registry's operator slice. The copy
// keeps callers from racing the registry's read-only invariants on the
// underlying storage; the per-operator structs themselves are returned
// by value, so any nested slices/maps inside Operator are shared.
// Callers that need to mutate those nested fields must clone them.
//
// Deliberately NOT staging-filtered, unlike the aggregates above — see
// DynamicRegistryProvider.AllOperators for why (the relay pool is built from it).
func (p *StaticRegistryProvider) AllOperators(_ context.Context) []Operator {
	return append([]Operator(nil), p.operators...)
}

// collectNodeVersions returns the sorted, deduplicated list of
// non-empty NodeVersion values across the given reachable, non-held-out
// operators, so the proxy's /v1/zs/details only advertises versions that
// dispatch can currently route to. Shared between the static and dynamic
// registry implementations.
//
// Note the reachability test here is the RAW Reachable bool, where the three
// sibling aggregates ON THE DYNAMIC PROVIDER use the carry-window advertisable
// (the static provider's advertisable is this same condition, so there is no
// asymmetry on that side). Pre-existing and left alone deliberately: under
// bounded probing it makes an un-probed-but-fine node contribute its models to
// /v1/zs/details without its node_version, which is a separate defect from the
// staging gate and not fixed here.
func collectNodeVersions(ops []Operator, allowStaging bool) []string {
	seen := make(map[string]struct{}, len(ops))
	for _, op := range ops {
		if !op.Reachable || HeldOutStaging(op, allowStaging) || wireIncompatible(op) || op.SignerUnderfunded() {
			continue
		}
		if op.NodeVersion == "" {
			continue
		}
		seen[op.NodeVersion] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// aggregateBool ORs an optional capability flag across operators: the
// result is true if either side is a known true, a known false beats nil
// (unknown), and nil + nil stays nil. Always returns a fresh pointer so
// the aggregate never aliases an operator's ModelCapacity. Used so a
// model advertises a capability when ANY reachable operator does.
func aggregateBool(a, b *bool) *bool {
	if a == nil && b == nil {
		return nil
	}
	v := (a != nil && *a) || (b != nil && *b)
	return &v
}

// minNonZero aggregates a microUSDC scalar across operators under the "from $X"
// rule the image fields use: the lowest value any operator declared, with 0
// meaning "not advertised" rather than "free". Both zero ⇒ zero, so a field no
// operator publishes stays absent on the aggregate.
func minNonZero(a, b uint64) uint64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case b < a:
		return b
	}
	return a
}

// minRatePtr aggregates an optional advertised rate across operators: the
// lowest value that any operator declared ("from $X"), treating nil as "no
// value". Returns nil only when both inputs are nil; otherwise a FRESH
// pointer so the aggregate never aliases an operator's ModelCapacity. Used
// for the cache-read discount, whose nil (no discount) must stay distinct
// from a pointed-to 0 (free cached reads).
func minRatePtr(a, b *float64) *float64 {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		v := *b
		return &v
	case b == nil:
		v := *a
		return &v
	}
	v := *a
	if *b < v {
		v = *b
	}
	return &v
}

// aggregateReasoning merges reasoning descriptors across operators: OR
// the Supported flag and union AllowedEfforts. DefaultEffort is dropped
// from the aggregate — a single "default" has no clean cross-operator
// meaning (same rationale as the omitted max_tool_iterations). Returns
// nil only when both inputs are nil; otherwise a fresh descriptor that
// never aliases an operator's ModelCapacity.
func aggregateReasoning(a, b *inject.ModelReasoning) *inject.ModelReasoning {
	if a == nil && b == nil {
		return nil
	}
	out := &inject.ModelReasoning{}
	if a != nil {
		out.Supported = a.Supported
		out.AllowedEfforts = append([]string(nil), a.AllowedEfforts...)
	}
	if b != nil {
		out.Supported = out.Supported || b.Supported
		out.AllowedEfforts = unionStrings(out.AllowedEfforts, b.AllowedEfforts)
	}
	return out
}

// aggregateCoordinates folds the per-operator lean coordinates for one model
// into a single advisory descriptor, surfacing the per-field MAJORITY value
// and omitting a field when operators disagree (no unique mode → "" / 0), so
// the aggregate never invents a false consensus — divergent quant/params
// across operators is real information, not noise. nil when nothing is
// declared. The result never aliases an operator's ModelCoordinates.
func aggregateCoordinates(cs []*inject.ModelCoordinates) *inject.ModelCoordinates {
	var fams, quants, variants []string
	var params, active []uint64
	for _, c := range cs {
		if c == nil {
			continue
		}
		fams = append(fams, c.Family)
		quants = append(quants, c.Quantization)
		variants = append(variants, c.Variant)
		params = append(params, c.Parameters)
		active = append(active, c.ActiveParameters)
	}
	out := inject.ModelCoordinates{
		Family:           modeString(fams),
		Quantization:     modeString(quants),
		Variant:          modeString(variants),
		Parameters:       modeUint64(params),
		ActiveParameters: modeUint64(active),
	}
	if out == (inject.ModelCoordinates{}) {
		return nil
	}
	return &out
}

// aggregateDigest folds the per-operator lean weights_digest values for one
// model into the cross-operator integrity summary: consensus is the single
// digest when every operator that published one agrees (empty on disagreement),
// and mismatch is true when ≥2 DISTINCT non-empty digests appear (operators
// serve different weights for the same id). Unverifiable operators (no digest)
// are ignored for both — they neither establish nor break consensus. Advisory:
// a mismatch is "weights differ" (legitimate for a quant/repack), not fraud.
func aggregateDigest(digests []string) (consensus string, mismatch bool) {
	seen := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		if d == "" {
			continue
		}
		seen[d] = struct{}{}
	}
	switch len(seen) {
	case 0:
		return "", false
	case 1:
		for d := range seen {
			return d, false
		}
	}
	return "", true // ≥2 distinct digests → mismatch, no consensus
}

// aggregateSource folds declared HF source pointers by their model-identity key:
// scheme- and revision-stripped repo, compared case-insensitively. Operators may
// legitimately pin different revisions or spell the repo with different case;
// both still name the same model. The first declared spelling is returned so an
// aggregate preserves a usable, case-correct HF pointer for display/linking.
func aggregateSource(vals []string) string {
	consensus := ""
	consensusKey := ""
	for _, v := range vals {
		if v == "" {
			continue
		}
		key := sourceIdentityKey(v)
		if consensus == "" {
			consensus = v
			consensusKey = key
		} else if consensusKey != key {
			return "" // different repos → no consensus
		}
	}
	return consensus
}

// sourceIdentityKey mirrors the identity normalization used by the node's
// provenance.ParseRef and the client's stripSourceScheme: revisions do not
// participate in model identity, and repo comparison is case-insensitive.
func sourceIdentityKey(source string) string {
	repo := strings.TrimPrefix(source, "hf:")
	if i := strings.IndexByte(repo, '@'); i >= 0 {
		repo = repo[:i]
	}
	return strings.ToLower(repo)
}

// aggregateIdentity folds frontier canonical ids into the one exact non-empty
// value every declaring operator agrees on. Canonicals come from the node's
// curated lowercase whitelist, so unlike source pointers they need no revision
// or case normalization. A disagreement is "can't group", never fraud.
func aggregateIdentity(vals []string) string {
	consensus := ""
	for _, v := range vals {
		if v == "" {
			continue
		}
		if consensus == "" {
			consensus = v
		} else if consensus != v {
			return "" // disagreement → no consensus
		}
	}
	return consensus
}

// modeString returns the single most-common non-empty value, or "" when there
// is none or no unique winner (a tie = operators disagree → omit).
func modeString(vals []string) string {
	counts := make(map[string]int, len(vals))
	for _, v := range vals {
		if v != "" {
			counts[v]++
		}
	}
	return uniqueMode(counts)
}

// modeUint64 is modeString for counts; 0 is treated as "unset".
func modeUint64(vals []uint64) uint64 {
	counts := make(map[uint64]int, len(vals))
	for _, v := range vals {
		if v != 0 {
			counts[v]++
		}
	}
	best := uint64(0)
	maxN, winners := 0, 0
	for v, n := range counts {
		if n > maxN {
			best, maxN, winners = v, n, 1
		} else if n == maxN {
			winners++
		}
	}
	if winners != 1 {
		return 0
	}
	return best
}

// uniqueMode returns the key with the strictly-highest count, or "" on a tie /
// empty.
func uniqueMode(counts map[string]int) string {
	best := ""
	maxN, winners := 0, 0
	for v, n := range counts {
		if n > maxN {
			best, maxN, winners = v, n, 1
		} else if n == maxN {
			winners++
		}
	}
	if winners != 1 {
		return ""
	}
	return best
}

// unionStrings returns a slice containing every element of a plus any
// elements of b not already present. Order of a is preserved; b
// additions are appended. Both nil inputs return nil.
func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	out := append([]string(nil), a...)
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
