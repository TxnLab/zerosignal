/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
)

// usageOperator is the serving node as the usage headers and frame name it.
func usageOperator(ev zs.ReceiptVerified) zs.Operator {
	return zs.Operator{ID: ev.Target.Op, NodeID: ev.Target.Node, OwnerAddr: ev.OwnerAddr}
}

// setUsageHeaders renders a verified receipt as the X-Zs-* usage headers.
func setUsageHeaders(h http.Header, ev zs.ReceiptVerified) {
	setReceiptUsageHeaders(h, &ev.Receipt, &ev.Ticket, usageOperator(ev), feesOf(ev), ev.FeeBps, retiredDiscountBps, ev.FeeBpsKnown)
}

// usageFrame renders a verified receipt as the zs.usage stream frame.
func usageFrame(ev zs.ReceiptVerified) zs.Frame {
	return receiptUsageFrame(&ev.Receipt, &ev.Ticket, usageOperator(ev), feesOf(ev), ev.FeeBps, retiredDiscountBps, ev.FeeBpsKnown)
}

// paidFees is what the payer paid the network for a turn: the open's and
// the settle's fees in base units of unit, and the USD price of one coin of
// it, 0 when unknown.
type paidFees struct {
	open, settle uint64
	usdRate      float64
	unit         zs.FeeUnit
}

func feesOf(ev zs.ReceiptVerified) paidFees {
	return paidFees{open: ev.OpenNetworkFees, settle: ev.SettleNetworkFees, usdRate: ev.NativeUSD, unit: ev.FeeUnit}
}

func (f paidFees) total() uint64 { return f.open + f.settle }

func (f paidFees) usd() float64 { return float64(f.total()) / pow10(f.unit.Decimals) * f.usdRate }

// algo reports whether the fees are in ALGO. The names that say ALGO
// (X-Zs-Fees-Microalgos, X-Zs-Algo-Usd-Rate, the frame's algo_* keys) are
// sent only then, never holding another coin's units.
func (f paidFees) algo() bool { return f.unit.Currency == "ALGO" }

// algoRate is the ALGO/USD rate, 0 when the fees are not in ALGO.
func (f paidFees) algoRate() float64 {
	if !f.algo() {
		return 0
	}
	return f.usdRate
}

// inferenceDenom returns the (currency, decimals) tuple the inference
// charge is denominated in for the given ticket. The contract escrows
// USDC (SPEC.md §3.3a), so the ticket's microUSDC amounts are reported
// as ("USDC", 6). Kept as a function (rather than a constant) so a
// future Ticket-level currency field — or a per-operator override —
// can plug in without renaming any header/SSE event field.
func inferenceDenom(_ *ticket.Ticket) (currency string, decimals int) {
	return "USDC", 6
}

// setReceiptUsageHeaders surfaces the node's signed usage receipt plus
// the on-chain network fees the *payer* (this proxy) paid for the
// request as plain response headers, so a non-streaming client can see
// what the request cost in inference + fees. The settle fee is known
// only after the settle submit, which runs after the response is
// written, so the non-streaming caller passes 0 for it: exact on the
// atomic settle path (the payer's fee there is 0), an undercount on the
// standalone-ack fallback. Stream clients don't get these (HTTP headers
// are fixed at stream start) — they get a synthetic `zs.usage` SSE
// frame instead, which does include the settle fee.
//
// Operator-paid fees (the gtxn[1] open over-fee and the gtxn[0]
// settle over-fee that pool the rest of each group via Algorand fee
// pooling) are deliberately excluded — reporting them as the payer's
// fees would mislead the user about what they paid.
//
// Inference is denominated in USDC (the contract escrows USDC, see
// SPEC.md §3.3a); network fees are in the rail's native coin. The two
// USD conversions are independent: inference USD comes straight from the
// USDC amount (1 USDC ≈ $1), fee USD requires the coin's USD rate.
func setReceiptUsageHeaders(h http.Header, r *ticket.UsageReceipt, ticket *ticket.Ticket, op zs.Operator, fees paidFees, feeBps, discountBps uint64, haveFee bool) {
	currency, decimals := inferenceDenom(ticket)
	totalFees := fees.total()

	h.Set("X-Zs-Ticket-Id", r.TicketID)
	if op.ID != 0 {
		h.Set("X-Zs-Operator-Id", strconv.FormatUint(op.ID, 10))
	}
	// Node id within the operator (operator/node split): the (operator, node)
	// pair identifies the serving node. Node ids are 1-based on-chain, so 0 is
	// the unset sentinel and the header is simply omitted then.
	if op.NodeID != 0 {
		h.Set("X-Zs-Node-Id", strconv.FormatUint(op.NodeID, 10))
	}
	if op.OwnerAddr != "" {
		h.Set("X-Zs-Operator-Owner-Addr", op.OwnerAddr)
	}
	h.Set("X-Zs-Actual-Input-Count", strconv.FormatUint(r.ActualInputCount, 10))
	h.Set("X-Zs-Actual-Output-Count", strconv.FormatUint(r.ActualOutputCount, 10))
	// AmountCharged is the operator's BASE (net) take; under the additive fee
	// model the payer's full USDC debit is base + the protocol fee (netFee).
	// The HAY fee discount is RETIRED, so discountBps is always 0 and
	// netFee == grossFee — a pure function of the signed AmountCharged and the
	// live feeBps, no longer gated on the confirmed settle's treasury
	// inner-transfer. The proxy uses its own payer's rate (cached,
	// background-refreshed via a direct protocolFeeBps global read — FeeRate).
	// It equals the
	// per-ticket open-time snapshot the contract charges; the on-chain snapshot
	// stays the settlement authority. The X-Zs-{Platform-Fee,
	// Refund,Total-Debit}-Microusdc headers below carry the decomposition.
	// Max-Price (escrowed, grossed up) still bounds it.
	h.Set("X-Zs-Inference-Amount", strconv.FormatUint(r.AmountCharged, 10))
	h.Set("X-Zs-Inference-Currency", currency)
	h.Set("X-Zs-Inference-Decimals", strconv.Itoa(decimals))
	// Escrowed ceiling. Under the additive fee model this is grossed up to
	// cover the operator's base charge PLUS the worst-case protocol fee, so
	// clients MUST NOT derive the payer refund as (max_price − inference_amount)
	// — that overstates it by the fee. The on-chain settlement refunds
	// max_price − amount_charged − netFee; read the actual refund from chain.
	h.Set("X-Zs-Max-Price-Amount", strconv.FormatUint(ticket.MaxPrice, 10))
	// Symmetric with Max-Price: the operator's per-request minimum-charge
	// floor pinned on the ticket (SPEC.md §3a "Minimum charge"). 0 means
	// no floor for this ticket — always emitted so clients can rely on
	// the header's presence rather than detecting absence.
	h.Set("X-Zs-Min-Price-Amount", strconv.FormatUint(ticket.MinPrice, 10))
	h.Set("X-Zs-Fees-Amount", strconv.FormatUint(totalFees, 10))
	h.Set("X-Zs-Fees-Currency", fees.unit.Currency)
	h.Set("X-Zs-Fees-Decimals", strconv.Itoa(fees.unit.Decimals))
	if fees.algo() {
		h.Set("X-Zs-Fees-Microalgos", strconv.FormatUint(totalFees, 10))
	}
	if r.AmountCharged > 0 {
		h.Set("X-Zs-Inference-Amount-Usd", fmt.Sprintf("$%.6f", inferenceUSD(r.AmountCharged, currency, decimals, fees.algoRate())))
	}
	if fees.usdRate > 0 {
		rate := strconv.FormatFloat(fees.usdRate, 'f', -1, 64)
		h.Set("X-Zs-Fees-Usd", fmt.Sprintf("$%.6f", fees.usd()))
		h.Set("X-Zs-Fees-Usd-Rate", rate)
		if fees.algo() {
			h.Set("X-Zs-Algo-Usd-Rate", rate)
		}
	}
	// Additive-fee breakdown from the open-time snapshot (only when readable).
	// platform_fee is the payer's protocol fee on top of the operator's base;
	// total_debit = inference + platform_fee is the payer's real USDC cost.
	if fb := feeBreakdownFor(r.AmountCharged, ticket.MaxPrice, feeBps, discountBps, haveFee, currency, decimals); fb != nil {
		h.Set("X-Zs-Fee-Bps", strconv.FormatUint(fb.FeeBps, 10))
		h.Set("X-Zs-Discount-Bps", strconv.FormatUint(fb.DiscountBps, 10))
		h.Set("X-Zs-Platform-Fee-Microusdc", strconv.FormatUint(fb.PlatformFeeMicrousdc, 10))
		h.Set("X-Zs-Refund-Microusdc", strconv.FormatUint(fb.RefundMicrousdc, 10))
		h.Set("X-Zs-Total-Debit-Microusdc", strconv.FormatUint(fb.TotalDebitMicrousdc, 10))
		if fb.TotalDebitUsd > 0 {
			h.Set("X-Zs-Total-Debit-Usd", fmt.Sprintf("$%.6f", fb.TotalDebitUsd))
		}
	}
}

// inferenceUSD converts an inference charge to USD. USDC is dollar-
// pegged so the conversion is the straight 1eN unscale; ALGO requires
// the algoUSDPrice oracle reading and is retained for backwards
// compatibility (returns 0 when the rate is missing rather than
// fabricating one). Unknown currencies return 0.
func inferenceUSD(amount uint64, currency string, decimals int, algoUSDPrice float64) float64 {
	switch currency {
	case "USDC":
		return float64(amount) / pow10(decimals)
	case "ALGO":
		if algoUSDPrice <= 0 {
			return 0
		}
		return float64(amount) / pow10(decimals) * algoUSDPrice
	}
	return 0
}

// pow10 returns 10^n as a float64. Small n only (currency decimals).
func pow10(n int) float64 {
	out := 1.0
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}

// usageFrameEvent is the SSE event name the proxy emits in place
// of the swallowed signed receipt so streaming clients can display
// per-request usage + cost. It is OPT-IN (usageFrameHeader): the
// frame's `data:` payload is not a valid OpenAI chat chunk, and strict
// OpenAI clients that parse every `data:` line rather than dispatching
// on the SSE `event:` type (e.g. JetBrains/Koog) throw on it — so the
// proxy stays a clean drop-in OpenAI endpoint by default and only emits
// the frame for zs-aware clients that ask for it.
const usageFrameEvent = "zs.usage"

// usageFrameHeader is the request header a zs-aware streaming
// client sets (any non-empty value) to opt into receiving the
// `event: zs.usage` SSE frame. Absent → the proxy suppresses the
// frame for OpenAI compatibility. Settlement is unaffected either way —
// it runs when the proxy reads the receipt, before this frame is built.
const usageFrameHeader = "X-Zs-Usage-Frame"

// inferenceCost groups the inference charge with its currency
// designator so a future USDC ticket only flips the Currency value
// (and Decimals if needed) — clients keying off the field names don't
// have to change.
type inferenceCost struct {
	Amount    uint64  `json:"amount"`
	Currency  string  `json:"currency"`
	Decimals  int     `json:"decimals"`
	AmountUsd float64 `json:"amount_usd,omitempty"`
}

// usageBody is the unsigned client-facing projection of UsageReceipt
// + the proxy's known on-chain network-fee commitment. Sig + BodyHash
// are deliberately omitted (internal audit fields the client cannot
// verify on its own).
type usageBody struct {
	Type       string `json:"type"`
	TicketID   string `json:"ticket_id"`
	OperatorID uint64 `json:"operator_id,omitempty"`
	// NodeID is the serving node within OperatorID (operator/node split). Omitted
	// when zero — node ids are 1-based on-chain (0 is the unset sentinel) — so the
	// pair reads operator_id+node_id together for the node that actually served.
	NodeID            uint64        `json:"node_id,omitempty"`
	OperatorOwnerAddr string        `json:"operator_owner_addr,omitempty"`
	ActualInputCount  uint64        `json:"actual_input_count"`
	ActualOutputCount uint64        `json:"actual_output_count"`
	Inference         inferenceCost `json:"inference"`
	MaxPriceAmount    uint64        `json:"max_price_amount"`
	// MinPriceAmount mirrors the ticket's min_price (microUSDC) — the
	// per-request floor the operator was committed to (SPEC.md §3a
	// "Minimum charge"). 0 when the floor was disabled at reserve.
	// Omitted when zero so back-compat consumers don't see a new key.
	MinPriceAmount uint64 `json:"min_price_amount,omitempty"`
	// The algo_* keys are sent only when the fees are in ALGO; NetworkFees
	// carries them on every rail.
	AlgoFeesMicroalgos *uint64       `json:"algo_fees_microalgos,omitempty"`
	AlgoFeesUsd        float64       `json:"algo_fees_usd,omitempty"`
	AlgoUsdRate        float64       `json:"algo_usd_rate,omitempty"`
	NetworkFees        networkFeeSum `json:"network_fees"`
	// Fee is the additive-fee breakdown (platform fee, refund, total debit)
	// the proxy derives from the operator-signed amount_charged and the ticket
	// box's open-time fee snapshot. Omitted when the proxy couldn't read the
	// snapshot. See feeBreakdown.
	Fee *feeBreakdown `json:"fee,omitempty"`
}

// networkFeeSum is the payer's network fees for a turn in the rail's coin,
// shaped as inferenceCost is. Not named fees, which would read as the
// protocol-fee breakdown in fee.
type networkFeeSum struct {
	Amount    uint64  `json:"amount"`
	Currency  string  `json:"currency"`
	Decimals  int     `json:"decimals"`
	AmountUsd float64 `json:"amount_usd,omitempty"`
	UsdRate   float64 `json:"usd_rate,omitempty"`
}

// feeBreakdown is the additive-fee decomposition derived from the
// operator-signed amount_charged and the payer's effective fee rate (feeBps;
// the contract snapshots the same rate onto the ticket at open() as the
// settlement authority; see SPEC.md §3a "Open-time fee snapshot").
// amount_charged is the operator's base (net) take; platform_fee rides on top
// and is the payer's; total_debit is what the payer actually pays. The
// discount_bps field is retained for wire-shape stability but is always 0 — the
// HAY fee discount is retired. Present only when the rate was available; the
// whole `fee` object is omitted otherwise (escrow off, or the rate cache hasn't
// warmed). It is a nested object precisely so "rate absent" is distinguishable
// from a genuine 0 platform fee.
type feeBreakdown struct {
	FeeBps               uint64  `json:"fee_bps"`
	DiscountBps          uint64  `json:"discount_bps"`
	PlatformFeeMicrousdc uint64  `json:"platform_fee_microusdc"`
	RefundMicrousdc      uint64  `json:"refund_microusdc"`
	TotalDebitMicrousdc  uint64  `json:"total_debit_microusdc"`
	TotalDebitUsd        float64 `json:"total_debit_usd,omitempty"`
}

// feeBreakdownFor builds the additive-fee breakdown for a settled request, or
// nil when the open-time snapshot wasn't read (haveFee == false). currency /
// decimals come from inferenceDenom; the USD figure is emitted only for USDC.
func feeBreakdownFor(amountCharged, maxPrice, feeBps, discountBps uint64, haveFee bool, currency string, decimals int) *feeBreakdown {
	if !haveFee {
		return nil
	}
	b := escrow.ComputeFeeBreakdown(amountCharged, maxPrice, feeBps, discountBps)
	out := &feeBreakdown{
		FeeBps:               feeBps,
		DiscountBps:          discountBps,
		PlatformFeeMicrousdc: b.NetFee,
		RefundMicrousdc:      b.Refund,
		TotalDebitMicrousdc:  b.TotalDebit,
	}
	if currency == "USDC" {
		out.TotalDebitUsd = float64(b.TotalDebit) / pow10(decimals)
	}
	return out
}

// retiredDiscountBps is the HAY fee discount — retired, so always 0. It is
// threaded into the payer-facing breakdown (the X-Zs-Discount-Bps header and
// the `discount_bps` field of the zs.usage frame) purely for wire-shape
// stability: those fields predate the discount's retirement and clients may
// still read them. There is no longer any source that produces a non-zero
// discount.
const retiredDiscountBps uint64 = 0

// receiptUsageFrame builds the synthetic SSE frame emitted after the
// operator's signed receipt has been verified. fees.open + fees.settle
// are the *payer's* shares of the open and settle groups (operator's
// pool fees are excluded), summed into network_fees.amount so the
// client sees a single "what did the payer pay in network fees"
// number. In the consensus-verified design both shares are 0 on the
// atomic path; only the standalone settle fallback contributes.
// When the payer's fee rate is readable (haveFee), the additive-fee
// breakdown (platform fee, refund, total debit) rides in the frame's
// `fee` object via feeBreakdownFor; it is omitted otherwise.
//
// Marshal cannot fail for this shape; JSON errors here would indicate
// a stdlib bug.
func receiptUsageFrame(r *ticket.UsageReceipt, ticket *ticket.Ticket, op zs.Operator, fees paidFees, feeBps, discountBps uint64, haveFee bool) zs.Frame {
	currency, decimals := inferenceDenom(ticket)
	totalFees := fees.total()
	u := usageBody{
		Type:              usageFrameEvent,
		TicketID:          r.TicketID,
		OperatorID:        op.ID,
		NodeID:            op.NodeID,
		OperatorOwnerAddr: op.OwnerAddr,
		ActualInputCount:  r.ActualInputCount,
		ActualOutputCount: r.ActualOutputCount,
		Inference: inferenceCost{
			Amount:   r.AmountCharged,
			Currency: currency,
			Decimals: decimals,
		},
		MaxPriceAmount: ticket.MaxPrice,
		MinPriceAmount: ticket.MinPrice,
		NetworkFees:    networkFeeSum{Amount: totalFees, Currency: fees.unit.Currency, Decimals: fees.unit.Decimals},
	}
	if fees.algo() {
		u.AlgoFeesMicroalgos = &totalFees
	}
	if r.AmountCharged > 0 {
		u.Inference.AmountUsd = inferenceUSD(r.AmountCharged, currency, decimals, fees.algoRate())
	}
	if fees.usdRate > 0 {
		u.NetworkFees.AmountUsd = fees.usd()
		u.NetworkFees.UsdRate = fees.usdRate
		if fees.algo() {
			u.AlgoFeesUsd = u.NetworkFees.AmountUsd
			u.AlgoUsdRate = fees.usdRate
		}
	}
	u.Fee = feeBreakdownFor(r.AmountCharged, ticket.MaxPrice, feeBps, discountBps, haveFee, currency, decimals)
	payload, _ := json.Marshal(u)
	return zs.Frame{Event: usageFrameEvent, Data: payload}
}
