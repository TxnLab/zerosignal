/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pricing

import (
	"fmt"
	"math"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// Advertised is the operator's published pricing for a model, sourced from
// /v1/zs/details (inject.OperatorDetailsModel plus the operator-level min-charge
// fields). Absent/zero fields are handled per the fail-open rules in
// VerifyTicketPrice.
type Advertised struct {
	// InputUsdPer1M / OutputUsdPer1M are always advertised; 0 means free.
	InputUsdPer1M  float64
	OutputUsdPer1M float64
	// CacheReadRateUsdPer1M is nil when the operator advertises no cache-read
	// discount (cache_read_rate_usd_per_1m omitted); a non-nil 0 means free
	// cached reads.
	CacheReadRateUsdPer1M *float64
	// MinChargeOutputTokens / MinChargeMicroUSDC are the operator-level minimum
	// charge basis. Both zero ⇒ no advertised floor reference (min_charge_bound skipped).
	MinChargeOutputTokens uint64
	MinChargeMicroUSDC    uint64

	// LongContextThresholdTokens is the prompt-token count at/above which the
	// operator's long-context (high) pricing tier applies (xAI's context-size
	// cliff). 0 ⇒ the operator advertises no tier (flat pricing) and the three
	// fields below are ignored. When non-zero, LongContextInputUsdPer1M and
	// LongContextOutputUsdPer1M carry the high-tier rates (>= their base
	// counterparts — a surcharge, enforced by long_context_ordering). The
	// verifier resolves which comparand to bound the signed rates against via
	// IsLongContext(t.InputCount, LongContextThresholdTokens).
	LongContextThresholdTokens uint64
	// LongContextInputUsdPer1M / LongContextOutputUsdPer1M are the high-tier
	// input/output rates. nil is tolerated (a malformed advertisement that omits a
	// required high rate) — the tier resolution then falls back to the base rate,
	// which rate_bound still bounds.
	LongContextInputUsdPer1M  *float64
	LongContextOutputUsdPer1M *float64
	// LongContextCacheReadRateUsdPer1M mirrors the base CacheReadRateUsdPer1M
	// nil-vs-zero semantics for the high tier: nil when the high tier advertises
	// no cache-read discount, a non-nil 0 meaning free cached reads in the high
	// tier. In the high tier this — not the base CacheReadRateUsdPer1M — is the
	// cache_read_bound comparand.
	LongContextCacheReadRateUsdPer1M *float64
}

// Policy tunes the verifier's tolerances and fail-open behavior.
type Policy struct {
	// RateMaxMultiple bounds a signed rate / min-charge against its advertised
	// value: ticket.rate <= ceil(advertisedMicro * RateMaxMultiple). A multiple
	// (not an additive slack) preserves the interim client gate's semantics and
	// absorbs a legitimate reprice between the details snapshot and the reserve.
	// 1.0 = exact-or-cheaper; the interim gate used 2.0.
	RateMaxMultiple float64
	// InputCountTolerance bounds a signed input_count against the caller's own
	// tokenize bound: ticket.input_count <= floor(reserveInputCount*(1+tol)).
	// Reuse the node's input_budget_tolerance (0.10).
	InputCountTolerance float64
	// FailOpen skips checks that lack a usable reference (missing/invalid
	// advertised value, non-recomputable max_price) instead of failing them.
	// Recommended true — an honest send must never be blocked by absent catalog
	// data.
	FailOpen bool
}

// DefaultPolicy preserves the interim client gate's 2x rate ceiling, reuses the
// node's 0.10 input-budget tolerance, and fails open on missing references.
func DefaultPolicy() Policy {
	return Policy{RateMaxMultiple: 2.0, InputCountTolerance: 0.10, FailOpen: true}
}

// Violation is a failed check. Want is the maximum the verifier allowed (or the
// exact value it expected, for the max_price check); Got is the signed value. Both
// are microUSDC except for input_count_bound, where they are token counts.
type Violation struct {
	Check  string // "max_price", "rate_bound", "min_charge_bound", "input_count_bound", "cache_read_discount", "cache_read_bound", "long_context_ordering", "long_context_tier"
	Field  string // the ticket field at fault
	Want   uint64
	Got    uint64
	Detail string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("ticket price %s failed at %s: got %d, allowed %d (%s)",
		v.Check, v.Field, v.Got, v.Want, v.Detail)
}

// VerifyTicketPrice checks a signed ticket's price before a payer escrows against
// it, returning the first violation or nil if the price is acceptable. It runs the
// token-ticket checks below (see proto/SPEC.md §3a "Payer-side price
// verification"); each is named by the Violation.Check it reports:
//
//   - max_price           max_price == ExpectedMaxPrice(...) (exact, from the
//     ticket's own signed numbers + the on-chain feeBps)
//   - rate_bound          input_rate / output_rate <= advertised * RateMaxMultiple
//   - min_charge_bound    min_price <= advertised MinChargeFloor * RateMaxMultiple
//   - input_count_bound   input_count <= reserveInputCount * (1 + InputCountTolerance)
//   - cache_read_discount cache_read_rate <= input_rate (internal invariant, no external ref)
//   - cache_read_bound    cache_read_rate <= advertised cache-read rate * RateMaxMultiple
//   - long_context_ordering advertised high-tier input/output rate >= its base counterpart (surcharge, not discount)
//   - long_context_tier    a tiered input_count needs the caller's own bound to be tiered too
//
// When the operator advertises a long-context tier (adv.LongContextThresholdTokens
// > 0), rate_bound and cache_read_bound resolve the advertised comparand to the
// HIGH-tier rate for a ticket whose signed input_count is at/above the threshold
// (IsLongContext) — the tier is decided by the same signed count the node used at
// reserve, so no separate max() ceiling over base+surcharge is needed. max_price
// stays an exact recompute from the ticket's own signed (already tier-resolved)
// rates. long_context_tier is what makes resolving off the SIGNED count safe: it
// refuses a ticket whose count was raised across the threshold when the caller's
// own bound sits below it, so the input_count tolerance can't be spent buying a
// whole tier.
//
// feeBps is the on-chain protocol fee (pfee), which both proxy and client cache.
// reserveInputCount is the caller's own tokenize.ReserveInputCount value for this
// request (0 ⇒ skip input_count_bound). imageToolBudget is any additive per-request
// budget the caller folded into the reserve (image tools on a /v1/responses ticket;
// 0 for a plain chat/token ticket) so the max_price recompute reproduces it exactly.
//
// Image / character / seconds tickets are priced by a different primitive and are
// skipped (nil) — the caller should verify those with imageprice/videoprice.
func VerifyTicketPrice(t ticket.Ticket, adv Advertised, feeBps, reserveInputCount, imageToolBudget uint64, pol Policy) *Violation {
	switch t.OutputUsageType {
	case ticket.UsageTypeImages, ticket.UsageTypeCharacters, ticket.UsageTypeSeconds:
		return nil // priced per-image / per-char / per-second, not per-token
	}

	// cache_read_discount — a cache read is always a discount. No external reference needed, so
	// this runs unconditionally (a ticket violating it is operator misbehaviour;
	// the node's own startup config rejects it).
	if t.CacheReadRate > t.InputRate {
		return &Violation{Check: "cache_read_discount", Field: "cache_read_rate", Want: t.InputRate, Got: t.CacheReadRate,
			Detail: "cache_read_rate exceeds input_rate; a cache read must be a discount"}
	}

	// max_price — internal consistency (exact). Recompute from the ticket's own
	// signed rates/counts + the on-chain fee; needs no advertised data.
	if want, err := ExpectedMaxPrice(t.InputCount, t.MaxOutputCount, t.InputRate, t.OutputRate, t.MinPrice, imageToolBudget, feeBps); err != nil {
		if !pol.FailOpen {
			return &Violation{Check: "max_price", Field: "max_price", Got: t.MaxPrice,
				Detail: "max_price recompute overflowed: " + err.Error()}
		}
		// fail-open: cannot recompute the ceiling; skip the max_price recompute, still run the rate checks
	} else if t.MaxPrice != want {
		return &Violation{Check: "max_price", Field: "max_price", Want: want, Got: t.MaxPrice,
			Detail: "max_price does not match rates x counts grossed up by the protocol fee"}
	}

	// long_context tier — resolve which advertised rate set the signed rates are
	// bounded against. The tier is decided by the ticket's OWN signed input_count
	// (IsLongContext), the identical value the node used at reserve to pick which
	// rates to sign, so both sides agree deterministically. inputAdv/outputAdv/
	// cacheAdv default to the base tier and are lifted to the high tier below.
	inputAdv, outputAdv := adv.InputUsdPer1M, adv.OutputUsdPer1M
	cacheAdv := adv.CacheReadRateUsdPer1M
	if adv.LongContextThresholdTokens > 0 {
		// long_context_ordering — a tier must be a surcharge, not a discount:
		// advertised high input/output >= their base counterparts. Runs whenever a
		// tier is advertised, independent of this ticket's tier — it validates the
		// advertisement itself, which every ticket against this operator relies on.
		if v := checkLongContextOrdering(adv); v != nil {
			return v
		}
		// long_context_tier — the node may not cross the price cliff on a count
		// the caller doesn't agree crossed it. input_count_bound alone does not
		// cover this: it tolerates a signed count up to reserveInputCount × (1 +
		// InputCountTolerance), and a ≤10% count inflation is enough to jump a
		// whole tier — a 2x multiplier on the entire request, which rate_bound
		// then waves through because an exactly-2x surcharge sits precisely on the
		// base × RateMaxMultiple boundary. So check the TIER, not the count: an
		// honest node only ever clamps input_count DOWN (its own ReserveInputCount
		// call carries no headroom term; the sole raise is the min_input_count
		// floor, orders of magnitude below any real threshold), so a sub-threshold
		// request can never legitimately come back tiered. Skipped when the caller
		// has no bound of its own (reserveInputCount == 0), same as
		// input_count_bound.
		if reserveInputCount > 0 &&
			IsLongContext(t.InputCount, adv.LongContextThresholdTokens) &&
			!IsLongContext(reserveInputCount, adv.LongContextThresholdTokens) {
			return &Violation{Check: "long_context_tier", Field: "input_count",
				Want: reserveInputCount, Got: t.InputCount,
				Detail: "input_count was raised across the long-context threshold; the caller's own bound is below it"}
		}
		if IsLongContext(t.InputCount, adv.LongContextThresholdTokens) {
			if adv.LongContextInputUsdPer1M != nil {
				inputAdv = *adv.LongContextInputUsdPer1M
			}
			if adv.LongContextOutputUsdPer1M != nil {
				outputAdv = *adv.LongContextOutputUsdPer1M
			}
			// In the high tier the base cache-read discount does not apply: the
			// comparand is the high-tier cache-read rate. nil (no high-tier discount
			// advertised) skips cache_read_bound entirely, leaving the signed rate
			// bounded by cache_read_discount (<= the high input_rate) + input rate_bound.
			cacheAdv = adv.LongContextCacheReadRateUsdPer1M
		}
	}

	// rate_bound — signed rates must not exceed the advertised (tier-appropriate) rates (× the multiple).
	if v := checkRateBound("rate_bound", "input_rate", t.InputRate, inputAdv, pol); v != nil {
		return v
	}
	if v := checkRateBound("rate_bound", "output_rate", t.OutputRate, outputAdv, pol); v != nil {
		return v
	}

	// cache_read_bound — the signed cache-read rate must honor the advertised (tier-appropriate)
	// discount, when one is advertised.
	if cacheAdv != nil {
		if v := checkRateBound("cache_read_bound", "cache_read_rate", t.CacheReadRate, *cacheAdv, pol); v != nil {
			return v
		}
	}

	// min_charge_bound — the signed min_price must not exceed the advertised minimum charge,
	// when a floor is advertised.
	if adv.MinChargeOutputTokens > 0 || adv.MinChargeMicroUSDC > 0 {
		floor := MinChargeFloor(adv.MinChargeOutputTokens, t.OutputRate, adv.MinChargeMicroUSDC)
		bound := scaleByMultiple(floor, pol.RateMaxMultiple)
		if t.MinPrice > bound {
			return &Violation{Check: "min_charge_bound", Field: "min_price", Want: bound, Got: t.MinPrice,
				Detail: "min_price exceeds the advertised minimum charge"}
		}
	}

	// input_count_bound — input_count must not exceed the caller's own tokenized reserve bound.
	if reserveInputCount > 0 {
		bound := scaleByTolerance(reserveInputCount, pol.InputCountTolerance)
		if t.InputCount > bound {
			return &Violation{Check: "input_count_bound", Field: "input_count", Want: bound, Got: t.InputCount,
				Detail: "input_count exceeds the reserve's own tokenized bound"}
		}
	}

	return nil
}

// checkRateBound bounds a signed micro rate against an advertised USD/1M rate.
// An advertised rate of 0 (free) enforces a signed rate of 0. An invalid
// advertised rate is skipped under fail-open, else refused.
func checkRateBound(check, field string, ticketRate uint64, advUsdPer1M float64, pol Policy) *Violation {
	advMicro, err := USDRateToMicroUSDCPer1M(advUsdPer1M)
	if err != nil {
		if pol.FailOpen {
			return nil
		}
		return &Violation{Check: check, Field: field, Got: ticketRate,
			Detail: "advertised rate invalid: " + err.Error()}
	}
	bound := scaleByMultiple(advMicro, pol.RateMaxMultiple)
	if ticketRate > bound {
		return &Violation{Check: check, Field: field, Want: bound, Got: ticketRate,
			Detail: "signed rate exceeds the advertised rate"}
	}
	return nil
}

// checkLongContextOrdering enforces that an advertised long-context tier is a
// surcharge, not a discount: the high input/output rates must be >= their base
// counterparts. The caller runs it only when a tier is advertised
// (LongContextThresholdTokens > 0). A nil high rate (a malformed advertisement
// that omits a required high rate) makes no ordering claim and is skipped — the
// tier resolution then falls back to the base rate, which rate_bound still bounds.
// Want/Got stay 0: this is an advertisement-consistency violation, not a
// value-bound, so the detail carries the meaning.
func checkLongContextOrdering(adv Advertised) *Violation {
	if adv.LongContextInputUsdPer1M != nil && *adv.LongContextInputUsdPer1M < adv.InputUsdPer1M {
		return &Violation{Check: "long_context_ordering", Field: "long_context_input_rate",
			Detail: "advertised long-context input rate is below the base input rate; a tier must be a surcharge, not a discount"}
	}
	if adv.LongContextOutputUsdPer1M != nil && *adv.LongContextOutputUsdPer1M < adv.OutputUsdPer1M {
		return &Violation{Check: "long_context_ordering", Field: "long_context_output_rate",
			Detail: "advertised long-context output rate is below the base output rate; a tier must be a surcharge, not a discount"}
	}
	return nil
}

// scaleByMultiple returns ceil(v * mult), saturating at MaxUint64. A multiple <=
// 1 yields v unchanged (exact-or-cheaper bound).
func scaleByMultiple(v uint64, mult float64) uint64 {
	if mult <= 1.0 || v == 0 {
		return v
	}
	scaled := math.Ceil(float64(v) * mult)
	if scaled >= float64(math.MaxUint64) {
		return math.MaxUint64
	}
	return uint64(scaled)
}

// scaleByTolerance returns floor(v * (1+tol)), saturating at MaxUint64. A tol <=
// 0 yields v unchanged.
func scaleByTolerance(v uint64, tol float64) uint64 {
	if tol <= 0 || v == 0 {
		return v
	}
	scaled := math.Floor(float64(v) * (1.0 + tol))
	if scaled >= float64(math.MaxUint64) {
		return math.MaxUint64
	}
	return uint64(scaled)
}
