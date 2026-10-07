/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/reserve_sizing_vectors.json: the pure
// pieces of dispatch's reserve phase, which the TS SDK mirrors in
// sdk/src/{sizing,estimate,admit,nofit,pacing,request-parse}.ts. Sizing an
// operator, estimating a body and pricing the admission must agree between the
// SDKs, or the same request routes, escrows or refuses differently.
//
//	cd proto/go && go test ./zs -run TestReserveSizingVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

const reserveSizingVectorsPath = "../../testdata/reserve_sizing_vectors.json"

// sizingVecCap and sizingVecOp are the Operator fields sizing reads, named as
// the SDK's Operator names them.
type sizingVecCap struct {
	ContextWindow              uint64   `json:"contextWindow"`
	MaxOutputTokens            uint64   `json:"maxOutputTokens"`
	InputUSDPer1M              float64  `json:"inputUsdPer1m"`
	OutputUSDPer1M             float64  `json:"outputUsdPer1m"`
	LongContextThresholdTokens uint64   `json:"longContextThresholdTokens"`
	LongContextInputUSDPer1M   *float64 `json:"longContextInputUsdPer1m,omitempty"`
	LongContextOutputUSDPer1M  *float64 `json:"longContextOutputUsdPer1m,omitempty"`
}

type sizingVecOp struct {
	ID                       uint64                  `json:"id"`
	ProtoVersion             string                  `json:"protoVersion"`
	MaxToolIters             int                     `json:"maxToolIters"`
	ToolHeadroomPerIteration uint64                  `json:"toolHeadroomPerIteration"`
	ModelCapacities          map[string]sizingVecCap `json:"modelCapacities"`
}

func (v sizingVecOp) operator() Operator {
	op := Operator{
		ID:                       v.ID,
		ProtoVersion:             v.ProtoVersion,
		MaxToolIters:             v.MaxToolIters,
		ToolHeadroomPerIteration: v.ToolHeadroomPerIteration,
		ModelCapacities:          map[string]ModelCapacity{},
	}
	for m, c := range v.ModelCapacities {
		op.ModelCapacities[m] = ModelCapacity{
			ContextWindow:              c.ContextWindow,
			MaxOutputTokens:            c.MaxOutputTokens,
			InputUSDPer1M:              c.InputUSDPer1M,
			OutputUSDPer1M:             c.OutputUSDPer1M,
			LongContextThresholdTokens: c.LongContextThresholdTokens,
			LongContextInputUSDPer1M:   c.LongContextInputUSDPer1M,
			LongContextOutputUSDPer1M:  c.LongContextOutputUSDPer1M,
		}
	}
	return op
}

type sizingVecRequest struct {
	Model            string `json:"model"`
	InputTokens      uint64 `json:"inputTokens"`
	MaxOutputTokens  uint64 `json:"maxOutputTokens"`
	InputTokensV2    uint64 `json:"inputTokensV2"`
	DeriveMaxOutput  bool   `json:"deriveMaxOutput"`
	MaxOutputCeiling uint64 `json:"maxOutputCeiling"`
}

func (r sizingVecRequest) sizing() SizingRequest {
	return SizingRequest{
		Model: r.Model, InputTokens: r.InputTokens, MaxOutputTokens: r.MaxOutputTokens,
		InputTokensV2: r.InputTokensV2, DeriveMaxOutput: r.DeriveMaxOutput, MaxOutputCeiling: r.MaxOutputCeiling,
	}
}

type sizingVecFit struct {
	Name               string           `json:"name"`
	Op                 sizingVecOp      `json:"op"`
	Sizing             sizingVecRequest `json:"sizing"`
	EffectiveMaxOutput uint64           `json:"effective_max_output"`
	Fits               bool             `json:"fits"`
}

type sizingVecMaxDeclared struct {
	Name  string        `json:"name"`
	Ops   []sizingVecOp `json:"ops"`
	Model string        `json:"model"`
	Want  uint64        `json:"want"`
}

type sizingVecReserveInput struct {
	Name         string      `json:"name"`
	Op           sizingVecOp `json:"op"`
	Model        string      `json:"model"`
	Body         string      `json:"body"`
	MaxOutput    uint64      `json:"max_output"`
	Count        uint64      `json:"count"`
	BoundVersion uint8       `json:"bound_version"`
}

// sizingVecExtract's Want is a decimal string, since a uint64 past 2^53 is a
// case; Err is whether Go's decode refused the body.
type sizingVecExtract struct {
	Name string `json:"name"`
	Body string `json:"body"`
	Want string `json:"want"`
	Err  bool   `json:"err"`
}

type sizingVecEstimate struct {
	Name     string            `json:"name"`
	Model    string            `json:"model"`
	Body     string            `json:"body"`
	ByModel  map[string]uint64 `json:"by_model"`
	Fallback uint64            `json:"fallback"`
	// Want is the estimate, or null with Err naming the failure.
	Want *sizingVecEstimated `json:"want"`
	Err  string              `json:"err"`
}

type sizingVecEstimated struct {
	InputTokens      uint64 `json:"inputTokens"`
	MaxOutputTokens  uint64 `json:"maxOutputTokens"`
	DeriveMaxOutput  bool   `json:"deriveMaxOutput"`
	MaxOutputCeiling uint64 `json:"maxOutputCeiling"`
}

type sizingVecStreamable struct {
	Body string `json:"body"`
	Want bool   `json:"want"`
}

type sizingVecImageN struct {
	Body    string `json:"body"`
	N       int    `json:"n"`
	Size    string `json:"size"`
	Quality string `json:"quality"`
	Err     string `json:"err"`
}

type sizingVecRejection struct {
	OperatorID uint64 `json:"operatorId"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type sizingVecMiss struct {
	OperatorID         uint64 `json:"operator_id"`
	ContextWindow      uint64 `json:"context_window"`
	MaxOutputTokens    uint64 `json:"max_output_tokens"`
	EffectiveMaxOutput uint64 `json:"effective_max_output"`
}

type sizingVecMessage struct {
	Name       string               `json:"name"`
	Model      string               `json:"model"`
	Sizing     sizingVecRequest     `json:"sizing"`
	Rejections []sizingVecRejection `json:"rejections"`
	Misses     []sizingVecMiss      `json:"misses"`
	NoFit      string               `json:"no_fit"`
	SizeFail   string               `json:"size_failure"`
}

type sizingVecAdmit struct {
	Name   string           `json:"name"`
	Ops    []sizingVecOp    `json:"ops"`
	Model  string           `json:"model"`
	Body   string           `json:"body"`
	Sizing sizingVecRequest `json:"sizing"`
	// FeeBps is null for a fee not yet read.
	FeeBps *uint64 `json:"fee_bps"`
	// Prices is each op's advertisedMaxPrice, null where it has none.
	Prices []*uint64 `json:"prices"`
	Want   *uint64   `json:"want"`
}

type sizingVecPrivacy struct {
	Config bool   `json:"config"`
	Allow  bool   `json:"allow"`
	Pref   string `json:"pref"`
	Want   bool   `json:"want"`
}

type sizingVecBusyWait struct {
	Sweep       int   `json:"sweep"`
	HintMs      int64 `json:"hint_ms"`
	RemainingMs int64 `json:"remaining_ms"`
	// SweepDelayMs is the configured schedule by sweep, or null for none.
	SweepDelayMs []int64 `json:"sweep_delay_ms"`
	DelayMs      int64   `json:"delay_ms"`
	OK           bool    `json:"ok"`
}

type sizingVectors struct {
	Comment       string                  `json:"comment"`
	Constants     map[string]uint64       `json:"constants"`
	Fits          []sizingVecFit          `json:"fits"`
	MaxDeclared   []sizingVecMaxDeclared  `json:"max_declared"`
	ReserveInput  []sizingVecReserveInput `json:"reserve_input"`
	ExtractMaxOut []sizingVecExtract      `json:"extract_max_output"`
	Estimate      []sizingVecEstimate     `json:"estimate"`
	Streamable    []sizingVecStreamable   `json:"streamable"`
	ImageN        []sizingVecImageN       `json:"image_n"`
	Messages      []sizingVecMessage      `json:"messages"`
	Admit         []sizingVecAdmit        `json:"admit"`
	UsePrivacy    []sizingVecPrivacy      `json:"use_privacy"`
	BusyWait      []sizingVecBusyWait     `json:"busy_wait"`
}

const (
	sizingVecOld   = "9.1" // sized with input bound v1
	sizingVecTight = "9.2" // the first with v2
)

func sizingVecCapOf(window, maxOut uint64) map[string]sizingVecCap {
	return map[string]sizingVecCap{"m": {ContextWindow: window, MaxOutputTokens: maxOut}}
}

func sizingFitCases() []sizingVecFit {
	flat := func(in, out uint64) sizingVecRequest {
		return sizingVecRequest{Model: "m", InputTokens: in, MaxOutputTokens: out}
	}
	derive := func(in uint64) sizingVecRequest {
		return sizingVecRequest{Model: "m", InputTokens: in, MaxOutputTokens: 32768, DeriveMaxOutput: true, MaxOutputCeiling: 32768}
	}
	v2 := func(r sizingVecRequest, in2 uint64) sizingVecRequest { r.InputTokensV2 = in2; return r }
	op := func(pv string, caps map[string]sizingVecCap) sizingVecOp {
		return sizingVecOp{ID: 1, ProtoVersion: pv, ModelCapacities: caps}
	}
	cases := []sizingVecFit{
		{Name: "no capacity for the model is unbounded", Op: op(sizingVecOld, nil), Sizing: flat(1_000_000, 1_000_000)},
		{Name: "a capacity under another model is no capacity", Op: op(sizingVecOld, map[string]sizingVecCap{"other": {ContextWindow: 10}}), Sizing: flat(100, 100)},
		{Name: "fits the window exactly", Op: op(sizingVecOld, sizingVecCapOf(1000, 0)), Sizing: flat(600, 400)},
		{Name: "one token over the window", Op: op(sizingVecOld, sizingVecCapOf(1000, 0)), Sizing: flat(601, 400)},
		{Name: "at the declared output cap", Op: op(sizingVecOld, sizingVecCapOf(0, 400)), Sizing: flat(10, 400)},
		{Name: "over the declared output cap", Op: op(sizingVecOld, sizingVecCapOf(0, 400)), Sizing: flat(10, 401)},
		{Name: "derive takes the declared cap", Op: op(sizingVecOld, sizingVecCapOf(100_000, 8000)), Sizing: derive(1000)},
		{Name: "derive takes a quarter of the window", Op: op(sizingVecOld, sizingVecCapOf(40_000, 0)), Sizing: derive(1000)},
		{Name: "derive floors a tiny window and misses it", Op: op(sizingVecOld, sizingVecCapOf(512, 0)), Sizing: derive(300)},
		{Name: "derive clamps a huge window to the ceiling", Op: op(sizingVecOld, sizingVecCapOf(1_000_000, 0)), Sizing: derive(1000)},
		{Name: "derive with no capacity is the ceiling", Op: op(sizingVecOld, nil), Sizing: derive(1000)},
		{Name: "a pre-9.2 operator is charged v1", Op: op(sizingVecOld, sizingVecCapOf(1000, 0)), Sizing: v2(flat(900, 200), 500)},
		{Name: "a 9.2 operator is charged v2", Op: op(sizingVecTight, sizingVecCapOf(1000, 0)), Sizing: v2(flat(900, 200), 500)},
		{Name: "an unset v2 falls back to v1", Op: op(sizingVecTight, sizingVecCapOf(1000, 0)), Sizing: flat(900, 200)},
		{Name: "an unparseable version is charged v1", Op: op("nine", sizingVecCapOf(1000, 0)), Sizing: v2(flat(900, 200), 500)},
		{Name: "a model named like an Object property", Op: sizingVecOp{ID: 1, ModelCapacities: map[string]sizingVecCap{"m": {ContextWindow: 10}}}, Sizing: sizingVecRequest{Model: "constructor", InputTokens: 100, MaxOutputTokens: 100}},
	}
	for i := range cases {
		o, s := cases[i].Op.operator(), cases[i].Sizing.sizing()
		cases[i].EffectiveMaxOutput = EffectiveMaxOutput(o, s)
		cases[i].Fits = Fits(o, s)
	}
	return cases
}

func sizingMaxDeclaredCases() []sizingVecMaxDeclared {
	capped := func(id, maxOut uint64) sizingVecOp {
		return sizingVecOp{ID: id, ModelCapacities: sizingVecCapOf(0, maxOut)}
	}
	cases := []sizingVecMaxDeclared{
		{Name: "no operators", Ops: []sizingVecOp{}, Model: "m"},
		{Name: "the largest cap", Ops: []sizingVecOp{capped(1, 4000), capped(2, 16000), capped(3, 8000)}, Model: "m"},
		{Name: "one uncapped operator voids the ceiling", Ops: []sizingVecOp{capped(1, 4000), capped(2, 0)}, Model: "m"},
		{Name: "one operator without the model voids it", Ops: []sizingVecOp{capped(1, 4000), {ID: 2}}, Model: "m"},
		{Name: "the uncapped operator is last", Ops: []sizingVecOp{capped(1, 16000), capped(2, 4000), capped(3, 0)}, Model: "m"},
	}
	for i := range cases {
		ops := make([]Operator, len(cases[i].Ops))
		for j, o := range cases[i].Ops {
			ops[j] = o.operator()
		}
		cases[i].Want = MaxDeclaredOutput(ops, cases[i].Model)
	}
	return cases
}

const (
	sizingVecChat       = `{"model":"m","messages":[{"role":"user","content":"hello there, how are you today?"}],"max_tokens":100}`
	sizingVecTools      = `{"model":"m","input":"look it up","tools":[{"type":"web_search"}]}`
	sizingVecFunctions  = `{"model":"m","input":"call it","tools":[{"type":"function","name":"f","parameters":{}}]}`
	sizingVecChained    = `{"model":"m","input":"and then?","previous_response_id":"resp_1"}`
	sizingVecImageInput = `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}}]}]}`
)

func sizingReserveInputCases() []sizingVecReserveInput {
	op := func(pv string, window uint64, iters int, perIter uint64) sizingVecOp {
		return sizingVecOp{ID: 1, ProtoVersion: pv, MaxToolIters: iters, ToolHeadroomPerIteration: perIter, ModelCapacities: sizingVecCapOf(window, 0)}
	}
	cases := []sizingVecReserveInput{
		{Name: "a short body is floored", Op: op(sizingVecOld, 0, 0, 0), Body: sizingVecChat, MaxOutput: 100},
		{Name: "the floor is capped to the window", Op: op(sizingVecOld, 300, 0, 0), Body: sizingVecChat, MaxOutput: 100},
		{Name: "server-side tools add the default headroom", Op: op(sizingVecOld, 0, 3, 0), Body: sizingVecTools, MaxOutput: 100},
		{Name: "server-side tools add the declared headroom", Op: op(sizingVecOld, 0, 3, 500), Body: sizingVecTools, MaxOutput: 100},
		{Name: "a negative iteration count adds none", Op: op(sizingVecOld, 0, -2, 500), Body: sizingVecTools, MaxOutput: 100},
		{Name: "function tools add none", Op: op(sizingVecOld, 0, 3, 500), Body: sizingVecFunctions, MaxOutput: 100},
		{Name: "headroom is capped to the window", Op: op(sizingVecOld, 10_000, 3, 0), Body: sizingVecTools, MaxOutput: 2000},
		{Name: "a chained response reserves the window's rest", Op: op(sizingVecOld, 10_000, 0, 0), Body: sizingVecChained, MaxOutput: 2000},
		{Name: "a chained response without a window is measured", Op: op(sizingVecOld, 0, 0, 0), Body: sizingVecChained, MaxOutput: 2000},
		{Name: "a chained response whose output fills the window is measured", Op: op(sizingVecOld, 2000, 0, 0), Body: sizingVecChained, MaxOutput: 2000},
		{Name: "an image under v1", Op: op(sizingVecOld, 0, 0, 0), Body: sizingVecImageInput, MaxOutput: 100},
		{Name: "an image under v2", Op: op(sizingVecTight, 0, 0, 0), Body: sizingVecImageInput, MaxOutput: 100},
		{Name: "no capacity for the model has no window", Op: sizingVecOp{ID: 1, ModelCapacities: map[string]sizingVecCap{"other": {ContextWindow: 300}}}, Body: sizingVecChat, MaxOutput: 100},
	}
	for i := range cases {
		if cases[i].Model == "" {
			cases[i].Model = "m"
		}
		cases[i].Count, cases[i].BoundVersion = reserveInputCount(cases[i].Op.operator(), cases[i].Model, []byte(cases[i].Body), cases[i].MaxOutput)
	}
	return cases
}

func sizingExtractCases() []sizingVecExtract {
	bodies := []struct{ name, body string }{
		{"empty body", ``},
		{"none set", `{"model":"m"}`},
		{"max_tokens", `{"max_tokens":100}`},
		{"max_output_tokens", `{"max_output_tokens":200}`},
		{"completion beats output beats tokens", `{"max_tokens":1,"max_output_tokens":2,"max_completion_tokens":3}`},
		{"output beats tokens", `{"max_tokens":1,"max_output_tokens":2}`},
		{"a zero falls through", `{"max_completion_tokens":0,"max_tokens":7}`},
		{"null clears an earlier value", `{"max_tokens":5,"max_tokens":null}`},
		{"the last duplicate wins", `{"max_tokens":5,"max_tokens":9}`},
		{"keys match case-insensitively", `{"MAX_TOKENS":11}`},
		{"a folded key after an exact one wins", `{"max_tokens":5,"Max_Tokens":12}`},
		{"an escaped Kelvin sign folds to k", `{"max_toKens":13}`},
		{"an escaped long s folds to s", `{"max_tokenſ":14}`},
		{"a raw Kelvin sign folds to k", "{\"max_toKens\":17}"},
		{"a raw long s folds to s", "{\"max_tokenſ\":18}"},
		{"an escaped key", `{"max_tokens":15}`},
		{"a dotless i does not fold", `{"max_output_tokıns":16,"max_tokens":3}`},
		{"uint64 max", `{"max_tokens":18446744073709551615}`},
		{"past 2^53", `{"max_tokens":9007199254740993}`},
		{"past uint64", `{"max_tokens":18446744073709551616}`},
		{"negative", `{"max_tokens":-1}`},
		{"negative zero", `{"max_tokens":-0}`},
		{"a fraction", `{"max_tokens":1.0}`},
		{"an exponent", `{"max_tokens":1e3}`},
		{"a string", `{"max_tokens":"100"}`},
		{"a bool", `{"max_tokens":true}`},
		{"an object", `{"max_tokens":{}}`},
		{"a bad value after a good one still fails", `{"max_completion_tokens":5,"max_tokens":"x"}`},
		{"a bad value in another field is ignored", `{"max_tokens":5,"temperature":"hot","stream":[1]}`},
		{"top-level null", `null`},
		{"top-level array", `[1]`},
		{"top-level number", `42`},
		{"top-level string", `"x"`},
		{"invalid JSON", `{"max_tokens":5`},
		{"trailing garbage", `{"max_tokens":5} x`},
		{"whitespace around", " \n{\"max_tokens\" : 5 }\t"},
		{"whitespace only", `  `},
		{"nested max_tokens is not read", `{"options":{"max_tokens":5}}`},
	}
	out := make([]sizingVecExtract, len(bodies))
	for i, b := range bodies {
		est, err := tokenize.SafeEstimator{}.Estimate(tokenize.Request{Body: []byte(b.body)})
		out[i] = sizingVecExtract{Name: b.name, Body: b.body, Want: strconv.FormatUint(est.MaxOutputTokens, 10), Err: err != nil}
	}
	return out
}

func sizingEstimateCases() []sizingVecEstimate {
	cases := []sizingVecEstimate{
		{Name: "the caller's value is flat", Model: "m", Body: `{"max_tokens":100,"messages":[]}`, ByModel: map[string]uint64{"m": 500}, Fallback: 32768},
		{Name: "a per-model default is flat", Model: "m", Body: `{"messages":[]}`, ByModel: map[string]uint64{"m": 500}, Fallback: 32768},
		{Name: "a zero per-model default is unset", Model: "m", Body: `{"messages":[]}`, ByModel: map[string]uint64{"m": 0}, Fallback: 32768},
		{Name: "another model's default does not apply", Model: "m", Body: `{"messages":[]}`, ByModel: map[string]uint64{"n": 500}, Fallback: 32768},
		{Name: "a model named like an Object property", Model: "toString", Body: `{"messages":[]}`, ByModel: map[string]uint64{}, Fallback: 32768},
		{Name: "the fallback derives", Model: "m", Body: `{"messages":[]}`, Fallback: 4096},
		{Name: "no fallback refuses", Model: "m", Body: `{"messages":[]}`},
		{Name: "a malformed field refuses before the default", Model: "m", Body: `{"max_tokens":"x"}`, ByModel: map[string]uint64{"m": 500}, Fallback: 32768},
		{Name: "the input bound is v1", Model: "m", Body: sizingVecImageInput, Fallback: 32768},
	}
	for i := range cases {
		reg := tokenize.BuildRegistry(cases[i].ByModel, cases[i].Fallback)
		est, err := tokenize.EstimateWithRegistry(reg, tokenize.Request{Model: cases[i].Model, Body: []byte(cases[i].Body)})
		switch {
		case err == tokenize.ErrMaxOutputRequired:
			cases[i].Err = "max_output_required"
		case err != nil:
			cases[i].Err = "decode"
		default:
			cases[i].Want = &sizingVecEstimated{
				InputTokens: est.InputTokens, MaxOutputTokens: est.MaxOutputTokens,
				DeriveMaxOutput: est.DeriveMaxOutput, MaxOutputCeiling: est.MaxOutputCeiling,
			}
		}
	}
	return cases
}

func sizingStreamableCases() []sizingVecStreamable {
	bodies := []string{
		``, `{}`, `{"stream":true}`, `{"stream":false}`, `{"stream":null}`, `{"stream":"true"}`, `{"stream":1}`,
		`{"STREAM":true}`, `{"ſtream":true}`, `{"stream":true,"stream":false}`, `{"stream":true,"Stream":null}`,
		`{"stream":true,"model":"m"`, `null`, `[true]`, `{"stream":true,"max_tokens":"x"}`,
	}
	out := make([]sizingVecStreamable, len(bodies))
	for i, b := range bodies {
		out[i] = sizingVecStreamable{Body: b, Want: streamableRequest([]byte(b))}
	}
	return out
}

func sizingImageNCases() []sizingVecImageN {
	bodies := []string{
		`{"model":"m","prompt":"p"}`, `{"n":3,"size":"1024x1024","quality":"hd"}`, `{"n":1}`, `{"n":0}`, `{"n":-2}`,
		`{"n":null}`, `{"n":2,"n":null}`, `{"n":1.5}`, `{"n":"2"}`, `{"n":9223372036854775807}`, `{"n":9223372036854775808}`,
		`{"N":4,"SIZE":"256x256"}`, `{"size":"a","size":null}`, `{"size":5}`, `{"quality":true}`, `null`, `[]`, ``, `{`,
		`{"n":-0}`,
	}
	out := make([]sizingVecImageN, len(bodies))
	for i, b := range bodies {
		n, size, quality, err := parseImageRequestN([]byte(b))
		out[i] = sizingVecImageN{Body: b, N: n, Size: size, Quality: quality}
		if err != nil {
			out[i].Err = err.Error()
		}
	}
	return out
}

func sizingMessageCases() []sizingVecMessage {
	flat := sizingVecRequest{Model: "m", InputTokens: 1200, MaxOutputTokens: 4000}
	derive := sizingVecRequest{Model: "m", InputTokens: 1200, MaxOutputTokens: 32768, DeriveMaxOutput: true, MaxOutputCeiling: 32768}
	misses := []sizingVecMiss{
		{OperatorID: 1, ContextWindow: 4096, MaxOutputTokens: 0, EffectiveMaxOutput: 4000},
		{OperatorID: 2, ContextWindow: 0, MaxOutputTokens: 2048, EffectiveMaxOutput: 4000},
		{OperatorID: 3, ContextWindow: 100_000, MaxOutputTokens: 8000, EffectiveMaxOutput: 4000},
		{OperatorID: 4, ContextWindow: 5200, MaxOutputTokens: 3000, EffectiveMaxOutput: 4000},
	}
	rejections := []sizingVecRejection{
		{OperatorID: 5, Code: "context_length_exceeded", Message: "input 1200 + max_output 4000 exceeds 4096"},
		{OperatorID: 6, Code: "context_length_exceeded"},
		{OperatorID: 7},
	}
	cases := []sizingVecMessage{
		{Name: "the head alone", Model: "m", Sizing: flat},
		{Name: "derive mode labels the output", Model: "m", Sizing: derive},
		{Name: "filter misses", Model: "m", Sizing: flat, Misses: misses},
		{Name: "reserve-time rejections", Model: "m", Sizing: flat, Rejections: rejections},
		{Name: "both, rejections first", Model: "m", Sizing: derive, Rejections: rejections[:1], Misses: misses[:1]},
	}
	for i := range cases {
		s := cases[i].Sizing.sizing()
		var ms []sizingMiss
		for _, m := range cases[i].Misses {
			ms = append(ms, sizingMiss(m))
		}
		var rs []reserveSizeRejection
		for _, r := range cases[i].Rejections {
			rs = append(rs, reserveSizeRejection(r))
		}
		cases[i].NoFit = formatNoFitMessage(cases[i].Model, s, ms)
		cases[i].SizeFail = formatReserveSizeFailureMessage(cases[i].Model, s, rs, ms)
		if cases[i].Misses == nil {
			cases[i].Misses = []sizingVecMiss{}
		}
		if cases[i].Rejections == nil {
			cases[i].Rejections = []sizingVecRejection{}
		}
	}
	return cases
}

func sizingAdmitCases() []sizingVecAdmit {
	f64 := func(v float64) *float64 { return &v }
	priced := func(id uint64, in, out float64) sizingVecOp {
		return sizingVecOp{ID: id, ProtoVersion: sizingVecTight, ModelCapacities: map[string]sizingVecCap{
			"m": {ContextWindow: 128_000, InputUSDPer1M: in, OutputUSDPer1M: out},
		}}
	}
	longCtx := func(lcIn, lcOut *float64) sizingVecOp {
		return sizingVecOp{ID: 9, ProtoVersion: sizingVecTight, ModelCapacities: map[string]sizingVecCap{
			"m": {InputUSDPer1M: 1, OutputUSDPer1M: 2, LongContextThresholdTokens: 1000, LongContextInputUSDPer1M: lcIn, LongContextOutputUSDPer1M: lcOut},
		}}
	}
	flat := sizingVecRequest{Model: "m", MaxOutputTokens: 100}
	derive := sizingVecRequest{Model: "m", MaxOutputTokens: 32768, DeriveMaxOutput: true, MaxOutputCeiling: 32768}
	fee := func(v uint64) *uint64 { return &v }
	cases := []sizingVecAdmit{
		{Name: "one operator, no fee", Ops: []sizingVecOp{priced(1, 1, 2)}, FeeBps: fee(0), Sizing: flat},
		{Name: "the fee grosses up", Ops: []sizingVecOp{priced(1, 1, 2)}, FeeBps: fee(250), Sizing: flat},
		{Name: "the cheapest of three", Ops: []sizingVecOp{priced(1, 3, 6), priced(2, 1, 2), priced(3, 2, 4)}, FeeBps: fee(100), Sizing: flat},
		{Name: "a cold fee has no estimate", Ops: []sizingVecOp{priced(1, 1, 2)}, Sizing: flat},
		{Name: "no candidates", Ops: []sizingVecOp{}, FeeBps: fee(0), Sizing: flat},
		{Name: "one unpriced operator voids it", Ops: []sizingVecOp{priced(1, 1, 2), priced(2, 0, 2)}, FeeBps: fee(0), Sizing: flat},
		{Name: "a zero output rate is unpriced", Ops: []sizingVecOp{priced(1, 1, 0)}, FeeBps: fee(0), Sizing: flat},
		{Name: "no capacity for the model is unpriced", Ops: []sizingVecOp{{ID: 1}}, FeeBps: fee(0), Sizing: flat},
		{Name: "derive sizes each operator", Ops: []sizingVecOp{priced(1, 1, 2)}, FeeBps: fee(0), Sizing: derive},
		{Name: "fractional rates round up", Ops: []sizingVecOp{priced(1, 0.15, 0.6)}, FeeBps: fee(33), Sizing: flat},
		{Name: "long context uses its rates", Ops: []sizingVecOp{longCtx(f64(2), f64(4))}, FeeBps: fee(0), Sizing: flat, Body: sizingVecTools},
		{Name: "long context without its rates is unpriced", Ops: []sizingVecOp{longCtx(f64(2), nil)}, FeeBps: fee(0), Sizing: flat, Body: sizingVecTools},
		{Name: "under the threshold the base rates apply", Ops: []sizingVecOp{longCtx(nil, nil)}, FeeBps: fee(0), Sizing: sizingVecRequest{Model: "m", MaxOutputTokens: 100}},
		{Name: "a rate past uint64 is unpriced", Ops: []sizingVecOp{priced(1, 2e13, 1)}, FeeBps: fee(0), Sizing: flat},
		{Name: "a cost past uint64 is unpriced", Ops: []sizingVecOp{priced(1, 1e12, 1)}, FeeBps: fee(0), Sizing: sizingVecRequest{Model: "m", MaxOutputTokens: 100}},
		{Name: "a fee product past uint64 is unpriced", Ops: []sizingVecOp{priced(1, 1, 1.8e12)}, FeeBps: fee(1_000_000_000), Sizing: sizingVecRequest{Model: "m", MaxOutputTokens: 10}},
		{Name: "the same base under a smaller fee", Ops: []sizingVecOp{priced(1, 1, 1.8e12)}, FeeBps: fee(10_000), Sizing: sizingVecRequest{Model: "m", MaxOutputTokens: 10}},
	}
	for i := range cases {
		c := &cases[i]
		c.Model = "m"
		if c.Body == "" {
			c.Body = sizingVecChat
		}
		// The long-context threshold sits between the input floor and the
		// floor plus one iteration's tool headroom.
		if c.Body == sizingVecTools {
			c.Ops[0].MaxToolIters = 1
		}
		ops := make([]Operator, len(c.Ops))
		for j, o := range c.Ops {
			ops[j] = o.operator()
		}
		s := c.Sizing.sizing()
		c.Prices = make([]*uint64, len(ops))
		for j, op := range ops {
			if p, ok := advertisedMaxPrice(op, c.Model, []byte(c.Body), s, feeOr0(c.FeeBps)); ok {
				c.Prices[j] = &p
			}
		}
		feeKnown := c.FeeBps != nil
		if got, ok := newPriceTestServer(feeOr0(c.FeeBps), feeKnown).admitEstimate(ops, c.Model, []byte(c.Body), s); ok {
			c.Want = &got
		}
	}
	return cases
}

func feeOr0(f *uint64) uint64 {
	if f == nil {
		return 0
	}
	return *f
}

func sizingPrivacyCases() []sizingVecPrivacy {
	var out []sizingVecPrivacy
	for _, pref := range []string{"", selection.RelayAuto, selection.RelayOff, selection.RelayRequired} {
		for _, config := range []bool{false, true} {
			for _, allow := range []bool{false, true} {
				out = append(out, sizingVecPrivacy{Config: config, Allow: allow, Pref: pref, Want: resolveUsePrivacy(config, allow, pref)})
			}
		}
	}
	return out
}

func sizingBusyWaitCases() []sizingVecBusyWait {
	cases := []sizingVecBusyWait{
		{Sweep: 1, HintMs: 0, RemainingMs: 8000},
		{Sweep: 1, HintMs: 2000, RemainingMs: 8000},
		{Sweep: 1, HintMs: 3000, RemainingMs: 8000},
		{Sweep: 1, HintMs: 30_000, RemainingMs: 8000},
		{Sweep: 2, HintMs: 500, RemainingMs: 8000},
		{Sweep: 1, HintMs: 0, RemainingMs: 1000},
		{Sweep: 1, HintMs: 0, RemainingMs: 1001},
		{Sweep: 1, HintMs: 2500, RemainingMs: 2500},
		{Sweep: 1, HintMs: 0, RemainingMs: 0},
		{Sweep: 1, HintMs: 0, RemainingMs: -5},
		{Sweep: 1, HintMs: 30_000, RemainingMs: 8000, SweepDelayMs: []int64{0, 250, 500}},
		{Sweep: 2, HintMs: 0, RemainingMs: 400, SweepDelayMs: []int64{0, 250, 500}},
		{Sweep: 1, HintMs: 0, RemainingMs: 0, SweepDelayMs: []int64{0, 250, 500}},
		{Sweep: 1, HintMs: 0, RemainingMs: 1, SweepDelayMs: []int64{0, 0, 0}},
	}
	for i := range cases {
		c := &cases[i]
		s := &Client{}
		if c.SweepDelayMs != nil {
			sched := c.SweepDelayMs
			s.sweepDelayFn = func(sweep int) time.Duration { return time.Duration(sched[sweep]) * time.Millisecond }
		}
		d, ok := s.busyRetryWait(c.Sweep, time.Duration(c.HintMs)*time.Millisecond, time.Duration(c.RemainingMs)*time.Millisecond)
		c.DelayMs, c.OK = d.Milliseconds(), ok
	}
	return cases
}

func TestReserveSizingVectors(t *testing.T) {
	f := sizingVectors{
		Comment: "Generated by proto/go/zs TestReserveSizingVectors. Every field is compared exactly.",
		Constants: map[string]uint64{
			"default_tool_headroom_per_iteration": defaultToolHeadroomPerIteration,
			"reserve_min_input_count":             reserveMinInputCount,
			"busy_retries":                        busyRetries,
			"busy_retry_budget_ms":                uint64(busyRetryBudget.Milliseconds()),
			"busy_retry_delay_ms":                 uint64(busyRetryDelay.Milliseconds()),
			"busy_retry_max_delay_ms":             uint64(busyRetryMaxDelay.Milliseconds()),
			"transient_retry_after_hint_ms":       uint64(transientRetryAfterHint.Milliseconds()),
		},
		Fits:          sizingFitCases(),
		MaxDeclared:   sizingMaxDeclaredCases(),
		ReserveInput:  sizingReserveInputCases(),
		ExtractMaxOut: sizingExtractCases(),
		Estimate:      sizingEstimateCases(),
		Streamable:    sizingStreamableCases(),
		ImageN:        sizingImageNCases(),
		Messages:      sizingMessageCases(),
		Admit:         sizingAdmitCases(),
		UsePrivacy:    sizingPrivacyCases(),
		BusyWait:      sizingBusyWaitCases(),
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(reserveSizingVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(reserveSizingVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("reserve sizing differs from %s; if the change is intended, regenerate with -update and review the diff", reserveSizingVectorsPath)
	}
}
