/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

// Generates / verifies proto/testdata/http_render_vectors.json: how the
// OpenAI-compatible surface renders an error (status, the retry headers and
// the body, byte for byte) and a verified receipt (the X-Zs-* usage headers
// and the zs.usage frame). The SDK's zs.fetch renders from the same rules.
// Every code in errorShapes is an error row, and every Kind renders an
// unlisted code, so a new code or kind lands in the fixture.
//
//	cd proto/go && go test ./zs/handler -run TestRenderVectors -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
)

var updateVectors = flag.Bool("update", false, "regenerate the selected test's proto/testdata vectors")

const renderVectorsPath = "../../../testdata/http_render_vectors.json"

type renderErrorCase struct {
	Kind         zs.Kind `json:"kind"`
	Code         string  `json:"code"`
	Message      string  `json:"message"`
	Retryable    bool    `json:"retryable"`
	Paid         bool    `json:"paid"`
	RetryAfterMs int64   `json:"retry_after_ms"`

	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type renderUsageCase struct {
	Name              string  `json:"name"`
	TicketID          string  `json:"ticket_id"`
	AmountCharged     uint64  `json:"amount_charged"`
	ActualInputCount  uint64  `json:"actual_input_count"`
	ActualOutputCount uint64  `json:"actual_output_count"`
	MaxPrice          uint64  `json:"max_price"`
	MinPrice          uint64  `json:"min_price"`
	Op                uint64  `json:"op"`
	Node              uint64  `json:"node"`
	OwnerAddr         string  `json:"owner_addr"`
	OpenFees          uint64  `json:"open_fees"`
	SettleFees        uint64  `json:"settle_fees"`
	NativeUSD         float64 `json:"native_usd"`
	FeeCurrency       string  `json:"fee_currency"`
	FeeDecimals       int     `json:"fee_decimals"`
	FeeBps            uint64  `json:"fee_bps"`
	FeeBpsKnown       bool    `json:"fee_bps_known"`

	Headers    map[string]string `json:"headers"`
	FrameEvent string            `json:"frame_event"`
	FrameData  string            `json:"frame_data"`
}

type renderVectors struct {
	Errors []renderErrorCase `json:"errors"`
	Usage  []renderUsageCase `json:"usage"`
}

// headerMap is h with lowercase names, as a fetch Headers reports them.
func headerMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[strings.ToLower(k)] = strings.Join(vs, ", ")
	}
	return out
}

func renderErrorInputs() []renderErrorCase {
	var cases []renderErrorCase
	// Retry advice and Retry-After vary by row so each combination is seen.
	retryAfters := []int64{0, 7000, 1500, 999, 86_400_000}
	for i, code := range slices.Sorted(maps.Keys(errorShapes)) {
		cases = append(cases, renderErrorCase{
			Kind: zs.KindInternal, Code: code, Message: "msg for " + code,
			Retryable: i%2 == 0, Paid: i%3 == 0, RetryAfterMs: retryAfters[i%len(retryAfters)],
		})
	}
	for i, k := range []zs.Kind{
		zs.KindInvalidRequest, zs.KindContextExceeded, zs.KindNoRoute, zs.KindBusy,
		zs.KindUnreachable, zs.KindPriceRejected, zs.KindFunds, zs.KindSpendCap,
		zs.KindOperatorFault, zs.KindUpstream, zs.KindInterrupted, zs.KindInternal,
	} {
		cases = append(cases, renderErrorCase{
			Kind: k, Code: "unlisted_" + string(k), Message: "m",
			Retryable: i%2 == 1, RetryAfterMs: retryAfters[i%len(retryAfters)],
		})
	}
	// Go's JSON escapes the HTML characters and the line separators; a code
	// can be empty, which drops it from the body.
	cases = append(cases,
		renderErrorCase{Kind: zs.KindInternal, Code: "registry", Message: "a <b> & c   d   e \"q\" \t\b\f"},
		renderErrorCase{Kind: zs.KindInternal, Code: "", Message: "no code"},
	)
	return cases
}

func runRenderError(c renderErrorCase) renderErrorCase {
	w := httptest.NewRecorder()
	writeError(w, &zs.Error{
		Kind: c.Kind, Code: c.Code, Message: c.Message,
		Retryable: c.Retryable, Paid: c.Paid, RetryAfter: time.Duration(c.RetryAfterMs) * time.Millisecond,
	})
	c.Status = w.Code
	c.Headers = headerMap(w.Header())
	c.Body = w.Body.String()
	return c
}

func renderUsageInputs() []renderUsageCase {
	cases := []renderUsageCase{
		{Name: "full", TicketID: "dGlja2V0LTAwMDAwMDAwMDE=", AmountCharged: 1_000_000, ActualInputCount: 120, ActualOutputCount: 48,
			MaxPrice: 1_100_000, Op: 7, Node: 2, OwnerAddr: "OWNERADDR", OpenFees: 1000, SettleFees: 2000,
			NativeUSD: 0.2134, FeeBps: 1000, FeeBpsKnown: true},
		{Name: "rate unknown", TicketID: "dGlja2V0LTAwMDAwMDAwMDI=", AmountCharged: 500, ActualInputCount: 3, ActualOutputCount: 1,
			MaxPrice: 9000, MinPrice: 100, Op: 1, Node: 1, OwnerAddr: "O"},
		{Name: "nothing charged, ids unset", TicketID: "dGlja2V0LTAwMDAwMDAwMDM=", MaxPrice: 5000, MinPrice: 5000,
			FeeBps: 250, FeeBpsKnown: true},
		{Name: "zero fee rate known", TicketID: "dGlja2V0LTAwMDAwMDAwMDQ=", AmountCharged: 200_000, MaxPrice: 500_000,
			Op: 3, Node: 9, FeeBps: 0, FeeBpsKnown: true, NativeUSD: 1},
		{Name: "tiny rate", TicketID: "dGlja2V0LTAwMDAwMDAwMDU=", AmountCharged: 1, MaxPrice: 10, Op: 4, Node: 1,
			OpenFees: 5, NativeUSD: 0.0000001234, FeeBps: 333, FeeBpsKnown: true},
		{Name: "rounding", TicketID: "dGlja2V0LTAwMDAwMDAwMDY=", AmountCharged: 1_234_567, ActualInputCount: 99_999, ActualOutputCount: 77_777,
			MaxPrice: 2_000_000, MinPrice: 1, Op: 12, Node: 3, OwnerAddr: "OWNER12", OpenFees: 7, SettleFees: 3,
			NativeUSD: 0.123456789, FeeBps: 250, FeeBpsKnown: true},
		{Name: "large rate", TicketID: "dGlja2V0LTAwMDAwMDAwMDc=", AmountCharged: 999_999_999, MaxPrice: 999_999_999,
			Op: 1, Node: 1, OpenFees: 1_000_000, NativeUSD: 12345678.9, FeeBps: 10_000, FeeBpsKnown: true},
		// $%.6f rounds an exact half to even: 15625 µALGO at $0.50 is $0.0078125.
		{Name: "dollar tie down to even", TicketID: "dGlja2V0LTAwMDAwMDAwMDg=", AmountCharged: 1, MaxPrice: 1, Op: 1, Node: 1,
			OpenFees: 15_625, NativeUSD: 0.5},
		{Name: "dollar tie up to even", TicketID: "dGlja2V0LTAwMDAwMDAwMDk=", AmountCharged: 1, MaxPrice: 1, Op: 1, Node: 1,
			OpenFees: 46_875, NativeUSD: 0.5},
		// Past 1e21 $%.6f still prints every digit.
		{Name: "dollars past 1e21", TicketID: "dGlja2V0LTAwMDAwMDAwMTA=", AmountCharged: 1, MaxPrice: 1, Op: 1, Node: 1,
			OpenFees: 3_000_000, NativeUSD: 5.7885281e21},
		// The operator and node ids are rendered each on its own.
		{Name: "operator without node", TicketID: "dGlja2V0LTAwMDAwMDAwMTE=", AmountCharged: 1, MaxPrice: 1, Op: 5},
		{Name: "node without operator", TicketID: "dGlja2V0LTAwMDAwMDAwMTI=", AmountCharged: 1, MaxPrice: 1, Node: 5},
		// Fees in another coin carry none of the names that say ALGO.
		{Name: "fees in SOL", TicketID: "dGlja2V0LTAwMDAwMDAwMTM=", AmountCharged: 1_000, MaxPrice: 2_000, Op: 1, Node: 1,
			OpenFees: 5_000, SettleFees: 5_000, NativeUSD: 150.25, FeeCurrency: "SOL", FeeDecimals: 9, FeeBps: 1000, FeeBpsKnown: true},
		{Name: "fees in SOL, rate unknown", TicketID: "dGlja2V0LTAwMDAwMDAwMTQ=", AmountCharged: 1, MaxPrice: 1, Op: 1, Node: 1,
			OpenFees: 5_000, FeeCurrency: "SOL", FeeDecimals: 9},
	}
	for i := range cases {
		if cases[i].FeeCurrency == "" {
			cases[i].FeeCurrency, cases[i].FeeDecimals = "ALGO", 6
		}
	}
	return cases
}

func runRenderUsage(c renderUsageCase) renderUsageCase {
	ev := zs.ReceiptVerified{
		Receipt: ticket.UsageReceipt{TicketID: c.TicketID, AmountCharged: c.AmountCharged,
			ActualInputCount: c.ActualInputCount, ActualOutputCount: c.ActualOutputCount},
		Ticket:            ticket.Ticket{MaxPrice: c.MaxPrice, MinPrice: c.MinPrice},
		Target:            zs.NodeRef{Op: c.Op, Node: c.Node},
		OwnerAddr:         c.OwnerAddr,
		OpenNetworkFees:   c.OpenFees,
		SettleNetworkFees: c.SettleFees,
		NativeUSD:         c.NativeUSD,
		FeeUnit:           zs.FeeUnit{Currency: c.FeeCurrency, Decimals: c.FeeDecimals},
		FeeBps:            c.FeeBps,
		FeeBpsKnown:       c.FeeBpsKnown,
	}
	h := http.Header{}
	setUsageHeaders(h, ev)
	c.Headers = headerMap(h)
	f := usageFrame(ev)
	c.FrameEvent = f.Event
	c.FrameData = string(f.Data)
	return c
}

func TestRenderVectors(t *testing.T) {
	var got renderVectors
	for _, c := range renderErrorInputs() {
		got.Errors = append(got.Errors, runRenderError(c))
	}
	for _, c := range renderUsageInputs() {
		got.Usage = append(got.Usage, runRenderUsage(c))
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(renderVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(renderVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("rendering differs from %s; if the change is intended, regenerate with -update and review the diff", renderVectorsPath)
	}
}
