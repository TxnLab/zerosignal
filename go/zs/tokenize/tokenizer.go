/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package tokenize produces a safe upper bound on input tokens for the
// proxy's reserve call. The proxy is the only component that holds the
// plaintext request, so this work has to live here.
//
// The escrow + signed receipt flow makes the bound (rather than a
// byte-exact count) the right semantic: the operator settles for actual
// usage from its own real tokenizer, refunding the unspent margin out of
// escrow. Underestimates would still cause mid-stream failures (the
// node ceilings against max_price), so the estimator is conservative;
// overestimates only widen the refund.
package tokenize

import "errors"

// Endpoint is a small enum for the upstream shape the request targets.
// It is part of Request for symmetry with the rest of the proxy's
// pipelines and to leave room for endpoint-specific bound tightening
// later; the current SafeEstimator does not branch on it.
type Endpoint string

const (
	EndpointChatCompletions Endpoint = "/v1/chat/completions"
	EndpointResponses       Endpoint = "/v1/responses"
	EndpointCompletions     Endpoint = "/v1/completions"
)

// Request is the input to Estimate: the raw JSON body the proxy is about
// to seal, the model it's headed to, and the upstream endpoint.
type Request struct {
	Model    string
	Body     []byte
	Endpoint Endpoint
}

// Estimate is the output: a safe upper bound on input tokens and a
// concrete max_output_tokens. The latter comes from the request body
// when set, or from a per-model default when absent.
type Estimate struct {
	InputTokens     uint64
	MaxOutputTokens uint64
	// DeriveMaxOutput is set when the caller omitted max_output_tokens AND no
	// per-model default applies — the reserve is sized PER-OPERATOR from each
	// operator's declared capacity (selection.DeriveMaxOutput) rather than a flat
	// number, so a small-window operator isn't blocked by a guessed ceiling. In
	// that mode MaxOutputTokens holds the global fallback ceiling as a display /
	// diagnostic value (== MaxOutputCeiling); the actual per-operator value is
	// computed at reserve time via hayai.EffectiveMaxOutput. Zero value (a
	// caller-specified max, or a per-model default) keeps the flat behavior.
	DeriveMaxOutput  bool
	MaxOutputCeiling uint64
}

// Tokenizer produces an Estimate for a Request. The package ships
// SafeEstimator as the default implementation; tests can register
// alternate implementations per-model on the Registry.
type Tokenizer interface {
	Estimate(Request) (Estimate, error)
}

// ErrMaxOutputRequired is returned when the request omits
// max_tokens / max_completion_tokens / max_output_tokens AND the
// Registry has neither a per-model default nor a global fallback for
// the model. Reserve needs a concrete upper bound to compute max_price,
// so we fail closed in that case. With a fallback configured (the
// production default), an omitting request gets the fallback instead —
// keeping the proxy OpenAI-compatible for clients that don't send the
// field.
var ErrMaxOutputRequired = errors.New("tokenize: max_output_tokens required (body has none and no default configured)")

// Registry holds per-model max_output defaults, a global max_output
// fallback, and (for tests) optional per-model tokenizer overrides.
// Models without an override fall back to the default tokenizer the
// registry was built with — typically SafeEstimator with the package
// defaults.
type Registry struct {
	defaultTokenizer  Tokenizer
	overrides         map[string]Tokenizer
	defaultMaxOutput  map[string]uint64
	fallbackMaxOutput uint64
}

// NewRegistry returns a Registry whose default tokenizer is a zero-
// configured SafeEstimator. Use BuildRegistry when you want to seed
// per-model max_output defaults from config.
func NewRegistry() *Registry {
	return &Registry{
		defaultTokenizer: SafeEstimator{},
		overrides:        make(map[string]Tokenizer),
		defaultMaxOutput: make(map[string]uint64),
	}
}

// SetDefaultTokenizer swaps the fallback Tokenizer used for any model
// that doesn't have a per-model override registered. Pass nil to reset
// to the package default (SafeEstimator{}).
func (r *Registry) SetDefaultTokenizer(t Tokenizer) {
	if t == nil {
		t = SafeEstimator{}
	}
	r.defaultTokenizer = t
}

// Register binds a Tokenizer override to a model name. Used by tests to
// substitute deterministic estimators; production wiring leaves
// overrides empty and lets every model fall through to the default.
func (r *Registry) Register(model string, t Tokenizer) {
	r.overrides[model] = t
}

// SetDefaultMaxOutput configures the per-model fallback used when the
// request body doesn't specify a max output. Zero clears any existing
// entry — the model then falls through to the global fallback (or
// ErrMaxOutputRequired when no fallback is set).
func (r *Registry) SetDefaultMaxOutput(model string, n uint64) {
	if n == 0 {
		delete(r.defaultMaxOutput, model)
		return
	}
	r.defaultMaxOutput[model] = n
}

// SetFallbackMaxOutput configures the global catch-all max output used
// when the request body omits one AND the model has no per-model
// SetDefaultMaxOutput entry. Zero (the default for a bare NewRegistry)
// restores fail-closed behavior: EstimateWithRegistry returns
// ErrMaxOutputRequired rather than guessing a ceiling.
func (r *Registry) SetFallbackMaxOutput(n uint64) {
	r.fallbackMaxOutput = n
}

// Lookup returns the tokenizer registered for model, or the registry's
// default tokenizer when none is registered. Never returns nil.
func (r *Registry) Lookup(model string) Tokenizer {
	if t, ok := r.overrides[model]; ok {
		return t
	}
	return r.defaultTokenizer
}

// DefaultMaxOutput returns the configured per-model default, or (0, false)
// if none is set.
func (r *Registry) DefaultMaxOutput(model string) (uint64, bool) {
	n, ok := r.defaultMaxOutput[model]
	if !ok || n == 0 {
		return 0, false
	}
	return n, true
}

// BuildRegistry returns a Registry with the given per-model max_output
// defaults and global fallback pre-loaded. The default tokenizer is
// SafeEstimator with package defaults — model-specific accuracy isn't
// needed because the node bills against actual usage from the signed
// receipt. A fallback of 0 keeps the registry fail-closed for models
// with no per-model entry.
func BuildRegistry(defaults map[string]uint64, fallback uint64) *Registry {
	reg := NewRegistry()
	for model, n := range defaults {
		reg.SetDefaultMaxOutput(model, n)
	}
	reg.SetFallbackMaxOutput(fallback)
	return reg
}

// EstimateWithRegistry runs the model's tokenizer (default if no override) and
// resolves max_output_tokens when the body omits one, in precedence order:
//
//  1. caller specified it → flat, authoritative;
//  2. per-model default configured → flat (an explicit proxy-admin override);
//  3. else, with a global fallback > 0 → DERIVE mode: the reserve is sized
//     per-operator from each operator's declared capacity against the fallback
//     as the base ceiling (selection.DeriveMaxOutput, applied at reserve time via
//     hayai.EffectiveMaxOutput). MaxOutputTokens carries the ceiling as the
//     display/diagnostic value.
//  4. else (fallback == 0, the fail-closed opt-in) → ErrMaxOutputRequired.
//
// Only case 3 changed from the old flat-fallback behavior: an omitting caller now
// gets a per-operator right-sized reservation (matching the client) instead of a
// single guessed ceiling, keeping the proxy OpenAI-compatible for clients that
// don't send the field while no longer over-reserving on small-window operators.
func EstimateWithRegistry(reg *Registry, req Request) (Estimate, error) {
	t := reg.Lookup(req.Model)
	est, err := t.Estimate(req)
	if err != nil {
		return Estimate{}, err
	}
	if est.MaxOutputTokens > 0 {
		return est, nil // 1. caller specified — flat.
	}
	if n, ok := reg.DefaultMaxOutput(req.Model); ok {
		est.MaxOutputTokens = n // 2. per-model default — flat.
		return est, nil
	}
	if reg.fallbackMaxOutput == 0 {
		return Estimate{}, ErrMaxOutputRequired // 4. fail closed.
	}
	// 3. Derive per-operator against the fallback ceiling.
	est.MaxOutputTokens = reg.fallbackMaxOutput
	est.DeriveMaxOutput = true
	est.MaxOutputCeiling = reg.fallbackMaxOutput
	return est, nil
}
