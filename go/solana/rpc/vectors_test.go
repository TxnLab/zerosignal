/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

// Generates / verifies proto/testdata/solana_rpc_vectors.json: DefaultRetry's
// budget, which outcomes it retries, the wait before each retry, how a
// TransactionError's variant is read, the params each method sends, and what
// a call reads from an answer. The TS SDK's Solana RPC client
// (sdk/src/solana/rpc.ts) replays it.
//
//	cd proto/go && go test ./solana/rpc -run TestSolanaRPCVectors -update

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/solana"
)

var updateVectors = flag.Bool("update", false, "regenerate the selected test's proto/testdata vectors")

const vectorsPath = "../../../testdata/solana_rpc_vectors.json"

type statusCase struct {
	// Status 0 is a transport error: no answer at all.
	Status int  `json:"status"`
	Retry  bool `json:"retry"`
}

type rpcErrorCase struct {
	Method string          `json:"method"`
	Status int             `json:"status"`
	Code   int             `json:"code"`
	Data   json.RawMessage `json:"data"`
	Retry  bool            `json:"retry"`
	// TxErrName is (*Error).TxErrName.
	TxErrName string `json:"tx_err_name"`
	// TxCustom is TxCustomError over (*Error).TxErr, null when it reads none.
	TxCustom *uint32 `json:"tx_custom"`
}

type txErrCase struct {
	Err  json.RawMessage `json:"err"`
	Name string          `json:"name"`
	// Custom is TxCustomError's code, null when it reads none.
	Custom *uint32 `json:"custom"`
}

type backoffCase struct {
	Attempt    int     `json:"attempt"`
	RetryAfter string  `json:"retry_after"`
	WaitMs     float64 `json:"wait_ms"`
}

// requestArgs are a call's inputs in a form both suites can read; the TS
// test makes the same call from them.
type requestArgs struct {
	Key                 string       `json:"key,omitempty"`
	Commitment          Commitment   `json:"commitment,omitempty"`
	Filters             []filterArgs `json:"filters,omitempty"`
	TxHex               string       `json:"tx_hex,omitempty"`
	SkipPreflight       bool         `json:"skip_preflight,omitempty"`
	PreflightCommitment Commitment   `json:"preflight_commitment,omitempty"`
	MaxRetries          *uint64      `json:"max_retries,omitempty"`
	Signatures          []string     `json:"signatures,omitempty"`
	SearchHistory       bool         `json:"search_history,omitempty"`
	DataLen             *uint64      `json:"data_len,omitempty"`
}

type filterArgs struct {
	DataSize *uint64 `json:"data_size,omitempty"`
	Offset   *uint64 `json:"memcmp_offset,omitempty"`
	BytesHex string  `json:"memcmp_bytes_hex,omitempty"`
}

type requestCase struct {
	Method string          `json:"method"`
	Args   requestArgs     `json:"args"`
	Params json.RawMessage `json:"params"`
}

// captureTransport answers every call with a result its method accepts and
// keeps the params it was sent.
type captureTransport struct {
	params []json.RawMessage
}

var cannedResults = map[string]string{
	"getAccountInfo":                    `{"context":{"slot":1},"value":null}`,
	"getProgramAccounts":                `[]`,
	"getBalance":                        `{"context":{"slot":1},"value":0}`,
	"getLatestBlockhash":                `{"context":{"slot":1},"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":0}}`,
	"getBlockHeight":                    `0`,
	"getGenesisHash":                    `"11111111111111111111111111111111"`,
	"getMinimumBalanceForRentExemption": `0`,
	"sendTransaction":                   `"1111111111111111111111111111111111111111111111111111111111111111"`,
	"getSignatureStatuses":              `{"context":{"slot":1},"value":[]}`,
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var r struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	b, _ := io.ReadAll(req.Body)
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	c.params = append(c.params, r.Params)
	result := cannedResults[r.Method]
	if r.Method == "getSignatureStatuses" {
		var p [][]any
		_ = json.Unmarshal(r.Params, &p)
		result = `{"context":{"slot":1},"value":[` + strings.TrimSuffix(strings.Repeat("null,", len(p[0])), ",") + `]}`
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":` + result + `}`)),
	}, nil
}

func u64(v uint64) *uint64 { return &v }

func requestCases(t *testing.T) []requestCase {
	t.Helper()
	key := solana.PublicKey(bytes.Repeat([]byte{0x5a}, 32)).String()
	program := "2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1"
	sig1 := solana.Signature(bytes.Repeat([]byte{0x11}, 64)).String()
	sig2 := solana.Signature(bytes.Repeat([]byte{0xee}, 64)).String()
	// Not a transaction: the params carry the bytes as given.
	tx := []byte{1, 2, 3, 0xfe, 0xff}
	disc := []byte{0x8f, 0x4e, 0x14, 0x75, 0x40, 0xb7, 0x5e, 0x3b}
	return []requestCase{
		{Method: "getAccountInfo", Args: requestArgs{Key: key}},
		{Method: "getAccountInfo", Args: requestArgs{Key: key, Commitment: Confirmed}},
		{Method: "getProgramAccounts", Args: requestArgs{Key: program}},
		{Method: "getProgramAccounts", Args: requestArgs{Key: program, Commitment: Confirmed, Filters: []filterArgs{
			{DataSize: u64(880)}, {Offset: u64(0), BytesHex: hex.EncodeToString(disc)}, {Offset: u64(72), BytesHex: hex.EncodeToString(bytes.Repeat([]byte{7}, 32))},
		}}},
		// One filter is still sent.
		{Method: "getProgramAccounts", Args: requestArgs{Key: program, Filters: []filterArgs{{DataSize: u64(165)}}}},
		{Method: "getProgramAccounts", Args: requestArgs{Key: program, Filters: []filterArgs{{Offset: u64(8), BytesHex: hex.EncodeToString(disc)}}}},
		{Method: "getBalance", Args: requestArgs{Key: key, Commitment: Processed}},
		{Method: "getBalance", Args: requestArgs{Key: key}},
		{Method: "getLatestBlockhash", Args: requestArgs{Commitment: Finalized}},
		{Method: "getLatestBlockhash", Args: requestArgs{}},
		{Method: "getBlockHeight", Args: requestArgs{Commitment: Confirmed}},
		{Method: "getGenesisHash", Args: requestArgs{}},
		{Method: "getMinimumBalanceForRentExemption", Args: requestArgs{DataLen: u64(233)}},
		{Method: "getMinimumBalanceForRentExemption", Args: requestArgs{DataLen: u64(0), Commitment: Confirmed}},
		{Method: "sendTransaction", Args: requestArgs{TxHex: hex.EncodeToString(tx)}},
		{Method: "sendTransaction", Args: requestArgs{TxHex: hex.EncodeToString(tx), PreflightCommitment: Processed, MaxRetries: u64(0)}},
		{Method: "sendTransaction", Args: requestArgs{TxHex: hex.EncodeToString(tx), SkipPreflight: true, MaxRetries: u64(5)}},
		{Method: "getSignatureStatuses", Args: requestArgs{Signatures: []string{sig1, sig2}, SearchHistory: true}},
		{Method: "getSignatureStatuses", Args: requestArgs{Signatures: []string{sig1}}},
	}
}

// answerCase is a result as the RPC sends it and what the call reads from
// it: Want in a form both suites can build, or Refused when the call fails
// on it.
type answerCase struct {
	Method  string          `json:"method"`
	Args    requestArgs     `json:"args"`
	Result  json.RawMessage `json:"result"`
	Refused bool            `json:"refused"`
	Want    json.RawMessage `json:"want"`
}

type wantAccount struct {
	Lamports   uint64 `json:"lamports"`
	Owner      string `json:"owner"`
	DataHex    string `json:"data_hex"`
	Executable bool   `json:"executable"`
}

type wantKeyed struct {
	Pubkey  string      `json:"pubkey"`
	Account wantAccount `json:"account"`
}

type wantStatus struct {
	Slot               uint64          `json:"slot"`
	Confirmations      *uint64         `json:"confirmations"`
	Err                json.RawMessage `json:"err"`
	ConfirmationStatus Commitment      `json:"confirmation_status"`
}

// answerTransport answers every call with one result.
type answerTransport struct{ result string }

func (a answerTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":` + a.result + `}`)),
	}, nil
}

// readAnswer makes the call a case names against its result and renders what
// it decoded.
func readAnswer(ctx context.Context, rc answerCase) (json.RawMessage, error) {
	c, err := NewClient("http://rpc.invalid", WithTransport(answerTransport{string(rc.Result)}))
	if err != nil {
		return nil, err
	}
	a := rc.Args
	render := func(acc Account) wantAccount {
		return wantAccount{acc.Lamports, acc.Owner.String(), hex.EncodeToString(acc.Data), acc.Executable}
	}
	switch rc.Method {
	case "getAccountInfo":
		acc, err := c.GetAccountInfo(ctx, solana.MustPublicKey(a.Key), a.Commitment)
		if errors.Is(err, ErrNotFound) {
			return json.RawMessage(`null`), nil
		}
		if err != nil {
			return nil, err
		}
		return json.Marshal(render(*acc))
	case "getProgramAccounts":
		got, err := c.GetProgramAccounts(ctx, solana.MustPublicKey(a.Key), a.Commitment)
		if err != nil {
			return nil, err
		}
		out := make([]wantKeyed, len(got))
		for i, ka := range got {
			out[i] = wantKeyed{ka.Key.String(), render(ka.Account)}
		}
		return json.Marshal(out)
	case "getSignatureStatuses":
		sigs := make([]solana.Signature, len(a.Signatures))
		for i, s := range a.Signatures {
			if sigs[i], err = solana.ParseSignature(s); err != nil {
				return nil, err
			}
		}
		got, err := c.GetSignatureStatuses(ctx, sigs, a.SearchHistory)
		if err != nil {
			return nil, err
		}
		out := make([]*wantStatus, len(got))
		for i, s := range got {
			if s != nil {
				out[i] = &wantStatus{s.Slot, s.Confirmations, s.Err, s.ConfirmationStatus}
			}
		}
		return json.Marshal(out)
	}
	panic("unknown method " + rc.Method)
}

// answerCases pairs each result with what it must read as, written out here
// rather than taken from the code, so a regeneration cannot carry a changed
// reading into the vectors. want "" is a refusal.
func answerCases(t *testing.T) []answerCase {
	t.Helper()
	key := solana.PublicKey(bytes.Repeat([]byte{0x5a}, 32)).String()
	owner := "2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1"
	sig := solana.Signature(bytes.Repeat([]byte{0x11}, 64)).String()
	// An account's members as the RPC sends them, each one's absence a case.
	const (
		data     = `"data":["AQID","base64"]`
		lamports = `"lamports":5`
	)
	ownerMember := `"owner":"` + owner + `"`
	acct := func(members ...string) string {
		return "{" + strings.Join(slices.Concat(members, []string{`"rentEpoch":0`, `"space":3`}), ",") + "}"
	}
	info := func(value string) string { return `{"context":{"slot":9},"value":` + value + `}` }
	keyed := func(entries ...string) string { return "[" + strings.Join(entries, ",") + "]" }
	entry := func(account string) string { return `{"pubkey":"` + key + `","account":` + account + `}` }
	accountWant := func(executable bool) string {
		return fmt.Sprintf(`{"lamports":5,"owner":"%s","data_hex":"010203","executable":%v}`, owner, executable)
	}
	const refused = ""
	statuses := func(entries ...string) string {
		return `{"context":{"slot":9},"value":[` + strings.Join(entries, ",") + `]}`
	}
	sigs := func(n int) []string {
		s := make([]string, n)
		for i := range s {
			s[i] = sig
		}
		return s
	}
	specs := []struct {
		method string
		args   requestArgs
		result string
		want   string
	}{
		// An account the RPC sends without executable is not a program.
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, lamports, ownerMember)), accountWant(false)},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"executable":false`, lamports, ownerMember)), accountWant(false)},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"executable":true`, lamports, ownerMember)), accountWant(true)},
		// Only a null value is an account that does not exist; a missing one
		// is a malformed answer.
		{"getAccountInfo", requestArgs{Key: key}, info(`null`), `null`},
		{"getAccountInfo", requestArgs{Key: key}, `{"context":{"slot":9}}`, refused},
		{"getAccountInfo", requestArgs{Key: key}, info(`5`), refused},
		// A member the RPC always sends, null, missing or of another type, is
		// a malformed answer rather than its zero value: no lamports, the
		// system program as owner, no data, not a program.
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"executable":null`, lamports, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"executable":"true"`, lamports, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"executable":1`, lamports, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"lamports":null`, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"lamports":"5"`, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, `"lamports":-1`, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, lamports, `"owner":null`)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, lamports)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(data, lamports, `"owner":5`)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(`"data":null`, lamports, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(lamports, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(`"data":[null,"base64"]`, lamports, ownerMember)), refused},
		{"getAccountInfo", requestArgs{Key: key}, info(acct(`"data":["AQID",null]`, lamports, ownerMember)), refused},
		// getProgramAccounts reads its accounts the same way.
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(), `[]`},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(entry(acct(data, lamports, ownerMember))),
			`[{"pubkey":"` + key + `","account":` + accountWant(false) + `}]`},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(`null`), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(`{"pubkey":null,"account":` + acct(data, lamports, ownerMember) + `}`), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(`{"account":` + acct(data, lamports, ownerMember) + `}`), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(entry(`null`)), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(`{"pubkey":"` + key + `"}`), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(entry(acct(data, `"executable":null`, lamports, ownerMember))), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(entry(acct(data, `"lamports":null`, ownerMember))), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(entry(acct(data, lamports, `"owner":null`))), refused},
		{"getProgramAccounts", requestArgs{Key: owner}, keyed(entry(acct(`"data":null`, lamports, ownerMember))), refused},
		// A confirmationStatus that is no commitment is a malformed answer,
		// not a status to read as unconfirmed.
		{"getSignatureStatuses", requestArgs{Signatures: sigs(1)}, statuses(`{"slot":7,"confirmations":null,"err":null,"confirmationStatus":"rooted"}`), ""},
		{"getSignatureStatuses", requestArgs{Signatures: sigs(2)}, statuses(`null`, `{"slot":7,"confirmations":null,"err":null,"confirmationStatus":"Finalized"}`), ""},
		{"getSignatureStatuses", requestArgs{Signatures: sigs(3)}, statuses(
			`{"slot":7,"confirmations":2,"err":null}`,
			`{"slot":8,"confirmations":null,"err":{"InstructionError":[1,{"Custom":6001}]},"confirmationStatus":null}`,
			`{"slot":9,"confirmations":0,"err":null,"confirmationStatus":"processed"}`,
		), `[{"slot":7,"confirmations":2,"err":null,"confirmation_status":""},` +
			`{"slot":8,"confirmations":null,"err":{"InstructionError":[1,{"Custom":6001}]},"confirmation_status":""},` +
			`{"slot":9,"confirmations":0,"err":null,"confirmation_status":"processed"}]`},
	}
	out := make([]answerCase, len(specs))
	for i, s := range specs {
		rc := answerCase{Method: s.method, Args: s.args, Result: json.RawMessage(s.result)}
		got, err := readAnswer(t.Context(), rc)
		switch {
		case s.want == "" && err == nil:
			t.Fatalf("%s %s: read %s, want a refusal", s.method, s.result, got)
		case s.want == "":
			rc.Refused = true
		case err != nil:
			t.Fatalf("%s %s: %v", s.method, s.result, err)
		default:
			var want bytes.Buffer
			if err := json.Compact(&want, []byte(s.want)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want.Bytes()) {
				t.Fatalf("%s %s: read %s, want %s", s.method, s.result, got, want.Bytes())
			}
			rc.Want = got
		}
		out[i] = rc
	}
	return out
}

// issue makes the call a case names on c.
func issue(ctx context.Context, c *HTTPClient, rc requestCase) error {
	a := rc.Args
	switch rc.Method {
	case "getAccountInfo":
		_, err := c.GetAccountInfo(ctx, solana.MustPublicKey(a.Key), a.Commitment)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	case "getProgramAccounts":
		var fs []Filter
		for _, f := range a.Filters {
			if f.DataSize != nil {
				fs = append(fs, DataSize(*f.DataSize))
				continue
			}
			b, err := hex.DecodeString(f.BytesHex)
			if err != nil {
				return err
			}
			fs = append(fs, Memcmp(*f.Offset, b))
		}
		_, err := c.GetProgramAccounts(ctx, solana.MustPublicKey(a.Key), a.Commitment, fs...)
		return err
	case "getBalance":
		_, err := c.GetBalance(ctx, solana.MustPublicKey(a.Key), a.Commitment)
		return err
	case "getLatestBlockhash":
		_, err := c.GetLatestBlockhash(ctx, a.Commitment)
		return err
	case "getBlockHeight":
		_, err := c.GetBlockHeight(ctx, a.Commitment)
		return err
	case "getGenesisHash":
		_, err := c.GetGenesisHash(ctx)
		return err
	case "getMinimumBalanceForRentExemption":
		_, err := c.GetMinimumBalanceForRentExemption(ctx, *a.DataLen, a.Commitment)
		return err
	case "sendTransaction":
		tx, err := hex.DecodeString(a.TxHex)
		if err != nil {
			return err
		}
		_, err = c.SendTransaction(ctx, tx, SendOptions{SkipPreflight: a.SkipPreflight, PreflightCommitment: a.PreflightCommitment, MaxRetries: a.MaxRetries})
		return err
	case "getSignatureStatuses":
		sigs := make([]solana.Signature, len(a.Signatures))
		for i, s := range a.Signatures {
			sig, err := solana.ParseSignature(s)
			if err != nil {
				return err
			}
			sigs[i] = sig
		}
		_, err := c.GetSignatureStatuses(ctx, sigs, a.SearchHistory)
		return err
	}
	panic("unknown method " + rc.Method)
}

func TestSolanaRPCVectors(t *testing.T) {
	p := DefaultRetry()
	now := time.Date(2026, 10, 21, 12, 0, 0, 250_000_000, time.UTC)

	var statuses []statusCase
	for _, s := range []int{0, 100, 200, 201, 204, 299, 301, 304, 400, 401, 403, 404, 405, 408, 413, 425, 429, 430, 499, 500, 501, 502, 503, 504, 520, 524, 599, 600} {
		statuses = append(statuses, statusCase{Status: s, Retry: shouldRetry("getAccountInfo", s, nil)})
	}

	type in struct {
		method string
		status int
		code   int
		data   string
	}
	inputs := []in{
		{"getAccountInfo", 200, CodeNodeUnhealthy, `{"numSlotsBehind":42}`},
		{"getAccountInfo", 200, CodeNodeUnhealthy, ``},
		{"getProgramAccounts", 200, CodeNodeUnhealthy, `{"numSlotsBehind":null}`},
		{"getBalance", 200, CodeNodeUnhealthy, `{"numSlotsBehind":7}`},
		{"getAccountInfo", 201, CodeNodeUnhealthy, ``},
		{"getAccountInfo", 299, CodeNodeUnhealthy, ``},
		{"sendTransaction", 200, CodeNodeUnhealthy, `{"numSlotsBehind":3}`},
		// No method here sends a minContextSlot, so its refusal is not expected
		// weather; a caller that starts sending one decides then.
		{"getBalance", 200, -32016, `{"contextSlot":7}`},
		{"sendTransaction", 200, -32016, ``},
		// A failed simulation: only a missing blockhash is weather.
		{"sendTransaction", 200, CodePreflightFailure, `{"err":"BlockhashNotFound","logs":[],"accounts":null,"unitsConsumed":0}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":{"BlockhashNotFound":null}}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":"AlreadyProcessed","logs":[]}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":"InsufficientFundsForFee"}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":{"InstructionError":[1,{"Custom":6001}]}}`},
		{"sendTransaction", 200, CodeNodeUnhealthy, `{"err":{"InstructionError":[1,{"Custom":6001}]}}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":{"InsufficientFundsForRent":{"account_index":2}}}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":null}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"Err":"BlockhashNotFound"}`},
		{"sendTransaction", 200, CodePreflightFailure, `"BlockhashNotFound"`},
		{"sendTransaction", 200, CodePreflightFailure, `null`},
		{"sendTransaction", 200, CodePreflightFailure, ``},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":"BlockhashNotFound","err":"AccountNotFound"}`},
		{"sendTransaction", 200, CodePreflightFailure, `{"err":"AccountNotFound","err":"BlockhashNotFound"}`},
		// Not sendTransaction, so not a submit's blockhash.
		{"getAccountInfo", 200, CodePreflightFailure, `{"err":"BlockhashNotFound"}`},
		{"getSignatureStatuses", 200, CodePreflightFailure, `{"err":"BlockhashNotFound"}`},
		// The other Agave server codes, and JSON-RPC's own.
		{"sendTransaction", 200, -32003, ``},
		{"sendTransaction", 200, -32006, ``},
		{"sendTransaction", 200, -32013, ``},
		{"sendTransaction", 200, -32015, ``},
		{"getAccountInfo", 200, -32001, ``},
		{"getAccountInfo", 200, -32004, ``},
		{"getAccountInfo", 200, -32007, ``},
		{"getProgramAccounts", 200, -32010, ``},
		{"getProgramAccounts", 200, -32012, ``},
		{"getSignatureStatuses", 200, -32011, ``},
		{"getAccountInfo", 200, -32014, ``},
		{"getAccountInfo", 200, -32017, ``},
		{"getAccountInfo", 200, -32019, ``},
		{"getAccountInfo", 200, -32022, ``},
		{"getAccountInfo", 200, -32000, ``},
		{"getAccountInfo", 200, -32600, ``},
		{"getAccountInfo", 200, -32601, ``},
		{"getAccountInfo", 200, -32602, ``},
		{"getAccountInfo", 200, -32603, ``},
		{"getAccountInfo", 200, -32700, ``},
		{"getAccountInfo", 200, 429, ``},
		{"getAccountInfo", 200, 0, ``},
	}
	var rpcErrors []rpcErrorCase
	for _, c := range inputs {
		var data json.RawMessage
		if c.data != "" {
			data = json.RawMessage(c.data)
		}
		e := &Error{Method: c.method, Code: c.code, Message: "m", Data: data}
		rc := rpcErrorCase{
			Method: c.method, Status: c.status, Code: c.code, Data: data,
			Retry: shouldRetry(c.method, c.status, e), TxErrName: e.TxErrName(),
		}
		if code, ok := TxCustomError(e.TxErr()); ok {
			rc.TxCustom = &code
		}
		rpcErrors = append(rpcErrors, rc)
	}

	var txErrs []txErrCase
	for _, raw := range []string{
		`"BlockhashNotFound"`, `"AlreadyProcessed"`, `""`, "\"\\" + "u0041ccountInUse\"", `null`,
		`{"InstructionError":[0,{"Custom":6001}]}`, `{"InstructionError":[0,"InvalidArgument"]}`,
		`{"DuplicateInstruction":2}`, `{"A":1,"B":2}`, `{"A":1,"A":2}`, `{}`, `[]`, `["BlockhashNotFound"]`,
		`1`, `true`, `{"":1}`,
		`{"InstructionError":[2,{"Custom":6011}]}`, `{"InstructionError":[255,{"Custom":0}]}`,
		`{"InstructionError":[0,{"Custom":4294967295}]}`, `{"InstructionError":[0,{"Custom":4294967296}]}`,
		`{"InstructionError":[0,{"Custom":-1}]}`, `{"InstructionError":[0,{"Custom":1.5}]}`,
		`{"InstructionError":[0,{"Custom":"1"}]}`, `{"InstructionError":[0,{"Custom":null}]}`,
		`{"InstructionError":[256,{"Custom":1}]}`, `{"InstructionError":[-1,{"Custom":1}]}`,
		`{"InstructionError":["0",{"Custom":1}]}`, `{"InstructionError":[null,{"Custom":1}]}`,
		`{"InstructionError":[0,{"Custom":1,"X":2}]}`, `{"InstructionError":[0,{}]}`,
		`{"InstructionError":[0]}`, `{"InstructionError":[0,{"Custom":1},3]}`,
		`{"InstructionError":{"0":{"Custom":1}}}`, `{"InstructionError":[0,{"Custom":1}],"X":1}`,
		`{"InstructionError":[0,[{"Custom":1}]]}`, `{"Custom":1}`,
	} {
		c := txErrCase{Err: json.RawMessage(raw), Name: TxErrName(json.RawMessage(raw))}
		if code, ok := TxCustomError(json.RawMessage(raw)); ok {
			c.Custom = &code
		}
		txErrs = append(txErrs, c)
	}

	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	var schedule []float64
	for attempt := 0; attempt < p.MaxRetries; attempt++ {
		schedule = append(schedule, ms(httpx.LinearBackoff(attempt, "", now, p.WaitMin, p.WaitMax)))
	}
	// The Retry-After parse itself is algod_retry_vectors.json's; these pin
	// that this budget honors it and caps it. Its dates spell GMT, which the
	// layout holds literally, so no zone is looked up in time.Local.
	var backoff []backoffCase
	for _, c := range []struct {
		attempt int
		v       string
	}{
		{0, ""}, {7, ""}, {19, ""}, {0, "1"}, {0, "3"}, {5, "1"}, {0, "10"}, {0, "11"}, {0, "60"}, {0, "abc"},
		{0, "Wed, 21 Oct 2026 12:00:04 GMT"}, {0, "Wed, 21 Oct 2026 12:00:00 GMT"}, {0, "Wed, 21 Oct 2026 12:01:00 GMT"},
	} {
		backoff = append(backoff, backoffCase{Attempt: c.attempt, RetryAfter: c.v, WaitMs: ms(httpx.LinearBackoff(c.attempt, c.v, now, p.WaitMin, p.WaitMax))})
	}

	ct := &captureTransport{}
	client, err := NewClient("http://rpc.invalid", WithTransport(ct))
	if err != nil {
		t.Fatal(err)
	}
	requests := requestCases(t)
	for i := range requests {
		if err := issue(t.Context(), client, requests[i]); err != nil {
			t.Fatalf("%s: %v", requests[i].Method, err)
		}
		requests[i].Params = ct.params[i]
	}

	f := struct {
		Comment      string         `json:"comment"`
		MaxRetries   int            `json:"max_retries"`
		WaitMinMs    float64        `json:"wait_min_ms"`
		WaitMaxMs    float64        `json:"wait_max_ms"`
		Statuses     []statusCase   `json:"statuses"`
		RPCErrors    []rpcErrorCase `json:"rpc_errors"`
		TxErrorNames []txErrCase    `json:"tx_error_names"`
		ScheduleMs   []float64      `json:"schedule_ms"`
		NowUnixMs    int64          `json:"now_unix_ms"`
		Backoff      []backoffCase  `json:"backoff"`
		Requests     []requestCase  `json:"requests"`
		Answers      []answerCase   `json:"answers"`
	}{
		Comment: "Generated by proto/go/solana/rpc TestSolanaRPCVectors. DefaultRetry makes the first attempt and up to max_retries more. " +
			"statuses: whether an answer with no JSON-RPC error is retried (status 0 is a transport error). " +
			"rpc_errors: whether a JSON-RPC error in an answer of that status is retried, and the TransactionError variant and program code read from its data (data null is absent). " +
			"tx_error_names: the variant read from a TransactionError as sent, and custom, the program's code in an InstructionError's Custom (null for none). " +
			"schedule_ms: the wait before retry n+1 with no Retry-After. backoff: the wait after attempt (0-based), with the answer's Retry-After read at now_unix_ms. " +
			"requests: the params each call sends, from args. " +
			"answers: what the call made from args reads from result, as want, or refused when it fails on it as a malformed answer; " +
			"a getAccountInfo want of null is an account that does not exist.",
		MaxRetries:   p.MaxRetries,
		WaitMinMs:    ms(p.WaitMin),
		WaitMaxMs:    ms(p.WaitMax),
		Statuses:     statuses,
		RPCErrors:    rpcErrors,
		TxErrorNames: txErrs,
		ScheduleMs:   schedule,
		NowUnixMs:    now.UnixMilli(),
		Backoff:      backoff,
		Requests:     requests,
		Answers:      answerCases(t),
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(vectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatal("solana_rpc_vectors.json is stale; regenerate with -update")
	}
}
