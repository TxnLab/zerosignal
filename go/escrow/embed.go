/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package escrow wraps the ZeroSignalEscrow smart contract (see
// contracts/contracts/ZeroSignalEscrow.algo.ts) with typed Go helpers used
// by both the proxy and the node. The ARC-56 JSON the puya-ts build
// emits is embedded into the binary so the Go surface can't drift from
// the contract: rebuild the contract → rebuild the Go binary → new
// method selectors.
//
// The wrapper is intentionally thin. Transaction composition goes
// through go-algorand-sdk/v2's AtomicTransactionComposer (see
// client.go); on-the-wire verification goes through VerifyOpenGroup
// (proxy-side, full 2-tx group) and VerifyOpenAppCall (node-side,
// app-call only — see verify.go). Everything else can be built from
// the raw abi.Method objects exposed here.
package escrow

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/abi"
)

// ZeroSignalEscrowARC56 is the ARC-56 JSON spec for the ZeroSignalEscrow
// contract, embedded at build time. The source of truth is
// contracts/contracts/artifacts/ZeroSignalEscrow.arc56.json; to refresh,
// run `pnpm build` in contracts/ and re-copy the file here. A small
// TODO for later: have go generate copy it automatically.
//
//go:embed ZeroSignalEscrow.arc56.json
var ZeroSignalEscrowARC56 []byte

// arc56Method captures the subset of an ARC-56 method entry this
// package needs (name, args, returns). Any other fields are ignored.
type arc56Method struct {
	Name    string         `json:"name"`
	Args    []arc56Arg     `json:"args"`
	Returns arc56ReturnDef `json:"returns"`
}

type arc56Arg struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type arc56ReturnDef struct {
	Type string `json:"type"`
}

type arc56Contract struct {
	Name       string          `json:"name"`
	Methods    []arc56Method   `json:"methods"`
	SourceInfo arc56SourceInfo `json:"sourceInfo"`
}

// arc56SourceInfo mirrors the subset of the ARC-56 `sourceInfo` block
// this package consumes — specifically the approval-program entries
// that map program-counter values to the assert/err message strings
// the contract was compiled from. This is what lets us turn an
// algod "logic eval error: ... pc=NNN" into a typed error: parse the
// PC out of the algod error string, look up the matching message,
// match against a known sentinel.
type arc56SourceInfo struct {
	Approval arc56ProgramSourceInfo `json:"approval"`
}

type arc56ProgramSourceInfo struct {
	SourceInfo []arc56SourceInfoEntry `json:"sourceInfo"`
}

type arc56SourceInfoEntry struct {
	PC           []uint64 `json:"pc"`
	ErrorMessage string   `json:"errorMessage"`
}

// Spec is the in-memory view of the embedded ARC-56 contract. Built
// once via sync.Once and exposed for read-only access.
type Spec struct {
	ContractName string
	Methods      map[string]abi.Method // keyed by method name

	// approvalErrorMessages maps program-counter values inside the
	// approval program to the assert/err message strings the
	// contract was compiled from. Populated from the ARC-56
	// sourceInfo block. Used by submitSingle to convert algod's
	// stringly-typed "logic eval error pc=NNN" responses into
	// typed sentinels (errors.Is-able).
	approvalErrorMessages map[uint64]string
}

// ApprovalErrorMessage returns the source-mapped error message for a
// given program-counter value in the approval program, or ("", false)
// if the PC has no matching sourceInfo entry. Read-only.
func (s *Spec) ApprovalErrorMessage(pc uint64) (string, bool) {
	if s == nil {
		return "", false
	}
	msg, ok := s.approvalErrorMessages[pc]
	return msg, ok
}

// ApprovalErrorMessages returns every distinct source-mapped assert message
// the approval program can emit, sorted. It exists so a caller classifying
// reverts can test its classifier against the WHOLE contract rather than a
// hand-picked sample — the difference between "these strings don't
// over-match" and "nothing else over-matches", which is the only version that
// survives the contract growing a new assert. Order is stable so a failure
// names the same message on every run. Read-only.
func (s *Spec) ApprovalErrorMessages() []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(s.approvalErrorMessages))
	out := make([]string, 0, len(s.approvalErrorMessages))
	for _, msg := range s.approvalErrorMessages {
		if _, dup := seen[msg]; dup {
			continue
		}
		seen[msg] = struct{}{}
		out = append(out, msg)
	}
	slices.Sort(out)
	return out
}

// Cached parse result. sync.Once guards initialization so concurrent
// first-callers (proxy + node both hit GetSpec from goroutines under
// load) don't race on assignment.
var (
	specOnce sync.Once
	spec     *Spec
	specErr  error
)

// loadSpec parses ZeroSignalEscrowARC56 and builds the Methods map.
func loadSpec() (*Spec, error) {
	var raw arc56Contract
	if err := json.Unmarshal(ZeroSignalEscrowARC56, &raw); err != nil {
		return nil, fmt.Errorf("escrow: parse ARC-56 JSON: %w", err)
	}
	s := &Spec{
		ContractName:          raw.Name,
		Methods:               make(map[string]abi.Method, len(raw.Methods)),
		approvalErrorMessages: make(map[uint64]string),
	}
	for _, m := range raw.Methods {
		sig := methodSignature(m)
		method, err := abi.MethodFromSignature(sig)
		if err != nil {
			return nil, fmt.Errorf("escrow: method %q signature %q: %w", m.Name, sig, err)
		}
		s.Methods[m.Name] = method
	}
	// Flatten the approval-program sourceInfo entries into a PC →
	// message map. ARC-56 emits one entry per source assert with all
	// the PCs that share the same message; expand so callers can do
	// O(1) lookups on the PC algod hands them back.
	for _, e := range raw.SourceInfo.Approval.SourceInfo {
		if e.ErrorMessage == "" {
			continue
		}
		for _, pc := range e.PC {
			s.approvalErrorMessages[pc] = e.ErrorMessage
		}
	}
	return s, nil
}

// methodSignature renders an ARC-56 method as its canonical ABI
// signature (e.g. "open(pay,byte[],address,address,uint64,...)"void").
// This is what abi.MethodFromSignature expects.
func methodSignature(m arc56Method) string {
	args := make([]string, 0, len(m.Args))
	for _, a := range m.Args {
		args = append(args, a.Type)
	}
	ret := m.Returns.Type
	if ret == "" {
		ret = "void"
	}
	return m.Name + "(" + strings.Join(args, ",") + ")" + ret
}

// GetSpec returns the parsed spec, initializing it on first call.
// Safe to call from multiple goroutines. Callers should not mutate
// the returned value.
func GetSpec() (*Spec, error) {
	specOnce.Do(func() {
		spec, specErr = loadSpec()
	})
	return spec, specErr
}

// MustSpec is GetSpec that panics on failure. Use only from init()
// contexts where a parse error must abort the binary.
func MustSpec() *Spec {
	s, err := GetSpec()
	if err != nil {
		panic(err)
	}
	return s
}

// MethodByName returns the abi.Method for the given contract method
// name, or an error if the name isn't in the embedded spec.
func MethodByName(name string) (abi.Method, error) {
	s, err := GetSpec()
	if err != nil {
		return abi.Method{}, err
	}
	m, ok := s.Methods[name]
	if !ok {
		return abi.Method{}, fmt.Errorf("escrow: unknown method %q", name)
	}
	return m, nil
}

// MethodSelector returns the 4-byte selector for the named contract
// method — the thing an app call's first ABI argument must equal.
func MethodSelector(name string) ([]byte, error) {
	m, err := MethodByName(name)
	if err != nil {
		return nil, err
	}
	return m.GetSelector(), nil
}
