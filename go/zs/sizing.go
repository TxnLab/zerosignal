/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"github.com/TxnLab/zerosignal/go/selection"
)

// SizingRequest is what an operator's sizing envelope is compared
// against: the model the request is for, the exact input_tokens the
// tokenizer produced, and the max_output_tokens ceiling the proxy
// intends to pay for (same numbers that land in ReserveRequest).
type SizingRequest struct {
	Model           string
	InputTokens     uint64
	MaxOutputTokens uint64
	// InputTokensV2 is the same body measured with tokenize bound version 2,
	// used for the fit check against operators advertising proto_version >= 9.2
	// (mirrors selection.Constraints.InputTokensV2). Zero means "not supplied"
	// and every operator is filtered on InputTokens.
	//
	// The bounds disagree most on exactly the requests where this filter bites:
	// v1 prices every image at a flat 2048x2048 fallback while v2 reads the real
	// dimensions, so filtering an image request on the v1 number routes it away
	// from small-window operators that would serve it comfortably — while the
	// reserve leg sizes the same request with v2.
	InputTokensV2 uint64
	// DeriveMaxOutput + MaxOutputCeiling mirror selection.Constraints' derive
	// mode: when the caller omitted max_output_tokens (and no per-model default
	// applies), Fits and EffectiveMaxOutput derive the effective max_output
	// PER-OPERATOR from the operator's declared capacity instead of using the
	// flat MaxOutputTokens — so a small-window operator isn't excluded on a
	// guessed ceiling it never has to honor. MaxOutputTokens is ignored while
	// DeriveMaxOutput is set (it survives only as the describeMiss display value).
	DeriveMaxOutput  bool
	MaxOutputCeiling uint64
}

// EffectiveMaxOutput resolves the max_output_tokens req charges THIS operator.
//
// The rule itself is selection.EffectiveMaxOutput — the same function the
// shared filter runs — so the number the sizing filter admits on and the number
// the reserve loop escrows are produced by one piece of code rather than two
// that a comment asserts agree. That invariant has no failover: a disagreement
// is only discovered after escrow.open.
//
// This wrapper is just the adapter from the proxy's own Operator /
// SizingRequest. An operator with no declared capacity for the model passes
// (0, 0), which resolves to the flat ceiling — the "unbounded operator gets the
// flat fallback" behavior from before per-operator derivation.
func EffectiveMaxOutput(op Operator, req SizingRequest) uint64 {
	mc := op.ModelCapacities[req.Model] // zero value on a miss — see above
	return selection.EffectiveMaxOutput(mc.ContextWindow, mc.MaxOutputTokens, selection.MaxOutputSpec{
		Unspecified: req.DeriveMaxOutput,
		Flat:        req.MaxOutputTokens,
		Ceiling:     req.MaxOutputCeiling,
	})
}

// effectiveInputTokens picks the input measurement to filter op on. The rule is
// selection.EffectiveInputTokens — one function, so the shared filter and this
// reserve leg cannot disagree about which bound an operator is measured on.
func (req SizingRequest) effectiveInputTokens(op Operator) uint64 {
	return selection.EffectiveInputTokens(op.ProtoVersion, req.InputTokens, req.InputTokensV2)
}

// Fits reports whether op can serve req under its declared ModelCapacity.
//
// Operators with no declared capacity for req.Model are treated as
// unbounded — Fits returns true. This is the rollout gate: until an
// operator's registry entry carries ModelCapacities, sizing-based
// routing is a no-op for that (operator, model) pair and routing
// behaves exactly as pre-sizing.
//
// Both checks run against the number EffectiveMaxOutput resolves, called rather
// than restated so the value admitted here and the value the reserve loop
// escrows cannot drift apart:
//   - InputTokens+maxOut ≤ ContextWindow (overflow-safe; 0 means unset /
//     unbounded — matches the missing-entry semantics), widened for a node
//     that defers fit to its upstream
//   - maxOut ≤ MaxOutputTokens (skipped when the cap is zero)
//
// The context-window check delegates to selection.FitsContextWindowFor so
// the shared filter and this reserve leg apply one rule. This mirrors
// selection.SelectTargets' sizing step (Fits + effectiveMaxOutput).
func Fits(op Operator, req SizingRequest) bool {
	mc, ok := op.ModelCapacities[req.Model]
	if !ok {
		return true
	}
	maxOut := EffectiveMaxOutput(op, req)
	if !selection.FitsContextWindowFor(op.ProtoVersion, req.effectiveInputTokens(op), maxOut, mc.ContextWindow) {
		return false
	}
	if mc.MaxOutputTokens > 0 && maxOut > mc.MaxOutputTokens {
		return false
	}
	return true
}

// MaxDeclaredOutput reports the largest max_output_tokens any operator in ops
// advertises for model — the biggest completion ceiling the pool can actually
// honor, and therefore the value a caller's own (bigger) ceiling is worth
// lowering to rather than failing the request on.
//
// The MAX, not the min: a caller asking for a large budget should route to the
// operator that can give the most of it. Operators that cap lower still drop out
// of Fits exactly as before — this only stops the pool's most generous operator
// from being filtered out too.
//
// Returns 0 — "don't clamp" — when ops is empty or ANY operator serving the
// model declares no cap. An undeclared cap means unbounded (the same rollout
// gate Fits applies), so that operator can honor whatever the caller asked for
// and shrinking the request would take capability away for nothing.
//
// That last rule is why ops must be the operators the request can actually be
// ROUTED to, not everything in the registry serving the model: one unreachable
// operator declaring no cap disables the clamp for the whole pool. The caller
// (poolMaxOutput) does that filtering.
func MaxDeclaredOutput(ops []Operator, model string) uint64 {
	var maxDeclared uint64
	for _, op := range ops {
		mc, ok := op.ModelCapacities[model]
		if !ok || mc.MaxOutputTokens == 0 {
			return 0
		}
		maxDeclared = max(maxDeclared, mc.MaxOutputTokens)
	}
	return maxDeclared
}
