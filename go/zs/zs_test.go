/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
)

// These strings are shared with the TypeScript SDK, persisted by journals,
// or switched on by callers, so they are pinned as literals: renaming a
// constant's value must fail here.
func TestPublicStrings(t *testing.T) {
	cases := []struct{ got, want string }{
		{string(KindInvalidRequest), "invalid_request"},
		{string(KindContextExceeded), "context_exceeded"},
		{string(KindNoRoute), "no_route"},
		{string(KindBusy), "busy"},
		{string(KindUnreachable), "unreachable"},
		{string(KindPriceRejected), "price_rejected"},
		{string(KindFunds), "funds"},
		{string(KindSpendCap), "spend_cap"},
		{string(KindOperatorFault), "operator_fault"},
		{string(KindUpstream), "upstream"},
		{string(KindInterrupted), "interrupted"},
		{string(KindInternal), "internal"},
		{string(TicketOpen), "open"},
		{string(TicketSettlePending), "settle_pending"},
		{string(RelayHopChosen), "chosen"},
		{string(RelayHopRotated), "rotated"},
		{string(ToolInProgress), "in_progress"},
		{string(ToolCompleted), "completed"},
		{string(PrivacyRelayRequired), "relay_required"},
		{string(PrivacyDirect), "direct"},
		{string(AffinityPrefer), "prefer"},
		{string(AffinityStrict), "strict"},
		{string(AffinityNone), "none"},
		{NodeRef{Op: 3, Node: 7}.String(), "3/7"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// Every type in event.go with an EventType method must appear in
// TestEventTypes, so an event added without a pinned name fails here.
func TestEventTypesCoverEveryEvent(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "event.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := 0
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == "EventType" {
			declared++
		}
	}
	if declared != len(eventTypeCases) {
		t.Errorf("event.go declares %d events, TestEventTypes pins %d", declared, len(eventTypeCases))
	}
}

// The SDK logs through the Logger it was given. A call on the slog package
// itself writes to the host's default logger, which a program that set
// Config.Logger has no reason to watch.
func TestNoPackageLevelSlogCalls(t *testing.T) {
	pkgs, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := filepath.Glob("*/*.go")
	subsub, _ := filepath.Glob("*/*/*.go")
	logging := map[string]bool{"Debug": true, "Info": true, "Warn": true, "Error": true, "Log": true, "LogAttrs": true,
		"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true}
	fset := token.NewFileSet()
	for _, path := range append(append(pkgs, sub...), subsub...) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"log"` {
				t.Errorf("%s: imports the standard log package, which logs past Config.Logger", path)
			}
		}
		isSlog := func(e ast.Expr, name string) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			pkg, ok := sel.X.(*ast.Ident)
			return ok && pkg.Name == "slog" && (name == "" || sel.Sel.Name == name)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !logging[sel.Sel.Name] {
				return true
			}
			// slog.Warn(...), and slog.Default().Warn(...), which is the same
			// call spelled longer. slog.Default() as a nil fallback is fine.
			if isSlog(sel, "") {
				t.Errorf("%s: slog.%s logs past Config.Logger", fset.Position(call.Pos()), sel.Sel.Name)
			} else if inner, ok := sel.X.(*ast.CallExpr); ok && isSlog(inner.Fun, "Default") {
				t.Errorf("%s: slog.Default().%s logs past Config.Logger", fset.Position(call.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

func TestEventTypes(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range eventTypeCases {
		got := c.ev.EventType()
		if got != c.want {
			t.Errorf("%T.EventType() = %q, want %q", c.ev, got, c.want)
		}
		if seen[got] {
			t.Errorf("event type %q used twice", got)
		}
		seen[got] = true
	}
}

var eventTypeCases = []struct {
	ev   Event
	want string
}{
	{MaxOutputClamped{}, "max_output.clamped"},
	{RouteCandidates{}, "route.candidates"},
	{RelayHopChanged{}, "relay.hop"},
	{ReserveStarted{}, "reserve.started"},
	{ReserveRetrying{}, "reserve.retrying"},
	{ReserveSucceeded{}, "reserve.succeeded"},
	{PaymentCommitted{}, "payment.committed"},
	{ResponseStarted{}, "response.started"},
	{Frame{}, "frame"},
	{ItemOpened{}, "item.opened"},
	{ItemClosed{}, "item.closed"},
	{TextDelta{}, "delta.text"},
	{ReasoningDelta{}, "delta.reasoning"},
	{ToolCallDelta{}, "delta.tool_call"},
	{AnnotationAdded{}, "annotation.added"},
	{ToolStatus{}, "tool.status"},
	{ImageProgress{}, "image.progress"},
	{ImagePartial{}, "image.partial"},
	{Usage{}, "usage"},
	{ReceiptVerified{}, "receipt.verified"},
	{ReceiptViolated{}, "receipt.violated"},
	{SettleSubmitted{}, "settle.submitted"},
	{SettleConfirmed{}, "settle.confirmed"},
	{NodeExcluded{}, "node.excluded"},
	{Done{}, "done"},
}

func TestErrorFormatsAndUnwraps(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	var err error = &Error{Kind: KindBusy, Code: "no_capacity", Message: "all slots taken", Err: cause}

	if got, want := err.Error(), "zs: busy (no_capacity): all slots taken: unexpected EOF"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if got, want := (&Error{Kind: KindInternal}).Error(), "zs: internal"; got != want {
		t.Errorf("bare Error() = %q, want %q", got, want)
	}
	var zerr *Error
	if !errors.As(err, &zerr) || zerr.Kind != KindBusy {
		t.Fatalf("errors.As did not recover the Kind: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is does not reach the cause")
	}
}

type fakeSigner struct{ addr string }

func (s fakeSigner) Address() string { return s.addr }
func (fakeSigner) SignBytes(context.Context, string, []byte) ([]byte, error) {
	return nil, nil
}
func (s fakeSigner) HasAccount(a string) bool { return a == s.addr }
func (fakeSigner) SignWithAccount(context.Context, types.Transaction, string) (string, []byte, error) {
	return "", nil, nil
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()

	if c.Privacy != "relay_required" {
		t.Errorf("Privacy = %q, want relay_required", c.Privacy)
	}
	if c.Affinity != (Affinity{Policy: "prefer", TTL: 10 * time.Minute, Max: 1024}) {
		t.Errorf("Affinity = %+v", c.Affinity)
	}
	if c.MaxOutputCeiling != 32768 {
		t.Errorf("MaxOutputCeiling = %d, want 32768", c.MaxOutputCeiling)
	}
	if c.ConcurrentSlots != 10 {
		t.Errorf("ConcurrentSlots = %d, want 10", c.ConcurrentSlots)
	}
	if c.ReserveTimeout != 5*time.Second {
		t.Errorf("ReserveTimeout = %v, want 5s", c.ReserveTimeout)
	}
	wantD := Discovery{
		RefreshInterval:    5 * time.Minute,
		RefreshTimeout:     30 * time.Second,
		ProbeBudget:        96,
		TargetTopK:         8,
		MaxCacheAge:        15 * time.Minute,
		MaxCarryAge:        90 * time.Minute,
		LatencyStateMax:    4096,
		DetailsTimeout:     2 * time.Second,
		DetailsConcurrency: 24,
	}
	if !reflect.DeepEqual(c.Discovery, wantD) {
		t.Errorf("Discovery = %+v\nwant %+v", c.Discovery, wantD)
	}
	if c.Logger == nil || c.Clock == nil || c.HTTPClient == nil {
		t.Error("Logger, Clock and HTTPClient must be filled")
	}
	if c.HTTPClient.Timeout != 0 {
		t.Errorf("HTTPClient.Timeout = %v; a client timeout cuts long streams", c.HTTPClient.Timeout)
	}
	if c.SpendGuard != nil || c.Stores.Journal != nil {
		t.Error("SpendGuard and Journal have no default here")
	}
}

func TestConfigDefaultsKeepExplicitAndReplaceNegative(t *testing.T) {
	c := Config{
		Privacy:         PrivacyDirect,
		Affinity:        Affinity{Policy: AffinityStrict, TTL: time.Minute, Max: 7},
		ConcurrentSlots: 3,
		ReserveTimeout:  -time.Second,
		Discovery:       Discovery{ProbeBudget: -1, TargetTopK: 2},
	}.withDefaults()

	if c.Privacy != PrivacyDirect || c.Affinity != (Affinity{Policy: AffinityStrict, TTL: time.Minute, Max: 7}) {
		t.Errorf("explicit values replaced: %q %+v", c.Privacy, c.Affinity)
	}
	if c.ConcurrentSlots != 3 || c.Discovery.TargetTopK != 2 {
		t.Errorf("explicit counts replaced: %d %d", c.ConcurrentSlots, c.Discovery.TargetTopK)
	}
	if c.ReserveTimeout != 5*time.Second || c.Discovery.ProbeBudget != 96 {
		t.Errorf("negative values kept: %v %d", c.ReserveTimeout, c.Discovery.ProbeBudget)
	}
}

// The environment proxy is consulted only on request. Checked on the Proxy
// func rather than by sending through one: net/http reads the environment
// once per process, so a test cannot set it.
func TestNodeHTTPClientEnvironmentProxy(t *testing.T) {
	for _, use := range []bool{false, true} {
		tr := Config{UseEnvProxy: use}.withDefaults().HTTPClient.Transport.(*http.Transport)
		if (tr.Proxy != nil) != use {
			t.Errorf("UseEnvProxy=%v: transport consults the environment proxy = %v", use, tr.Proxy != nil)
		}
	}
}

// The default client refuses to dial a private address unless the caller
// allows it: an operator's registered BaseURL must not make the payer probe
// its own machine or LAN.
func TestDefaultHTTPClientBlocksPrivateTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	if resp, err := (Config{}).defaultHTTPClient().Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Error("default client reached a loopback server")
	}
	resp, err := Config{AllowPrivateHosts: true}.defaultHTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("AllowPrivateHosts client: %v", err)
	}
	resp.Body.Close()
}

// otherSigner holds a key, but not the one its Address names.
type otherSigner struct{ fakeSigner }

func (otherSigner) HasAccount(string) bool { return false }

// Each refusal names its own message fragment, so deleting one check cannot
// pass on a later check's identical code.
func TestConfigValidate(t *testing.T) {
	signer := fakeSigner{addr: "PAYER"}
	cases := []struct {
		name    string
		cfg     Config
		wantApp uint64
		wantNet algod.Network // checked when set
		wantErr string
	}{
		{name: "testnet preset", cfg: Config{Signer: signer, Network: Testnet()}, wantApp: 765860477},
		{name: "mainnet preset", cfg: Config{Signer: signer, Network: Mainnet()}, wantApp: 3628061142},
		{name: "explicit app id wins", cfg: Config{Signer: signer, Network: Network{Algod: Testnet().Algod, EscrowAppID: 42}}, wantApp: 42},
		{name: "localnet needs an app id", cfg: Config{Signer: signer, Network: Localnet()}, wantErr: "EscrowAppID is required"},
		{name: "localnet with app id", cfg: Config{Signer: signer, Network: Network{Algod: Localnet().Algod, EscrowAppID: 1001}}, wantApp: 1001},
		{name: "custom endpoint needs an app id", cfg: Config{Signer: signer, Network: Network{Algod: algod.Config{Endpoint: "http://algod:4001"}}}, wantErr: "EscrowAppID is required"},
		{name: "zero network is mainnet", cfg: Config{Signer: signer}, wantApp: 3628061142, wantNet: algod.NetworkMainnet},
		{name: "app id alone names no chain", cfg: Config{Signer: signer, Network: Network{EscrowAppID: 1}}, wantErr: "required when Token or EscrowAppID is set"},
		{name: "token alone names no chain", cfg: Config{Signer: signer, Network: Network{Algod: algod.Config{Token: "t"}}}, wantErr: "required when Token or EscrowAppID is set"},
		{name: "unknown network", cfg: Config{Signer: signer, Network: Network{Algod: algod.Config{Network: "devnet"}}}, wantErr: "localnet|testnet|mainnet"},
		{name: "no signer", cfg: Config{Network: Testnet()}, wantErr: "Signer is required"},
		{name: "signer without address", cfg: Config{Signer: fakeSigner{}, Network: Testnet()}, wantErr: "no address"},
		{name: "signer without its key", cfg: Config{Signer: otherSigner{signer}, Network: Testnet()}, wantErr: "cannot sign for its own address"},
		{name: "unknown privacy", cfg: Config{Signer: signer, Network: Testnet(), Privacy: "off"}, wantErr: "unknown Privacy"},
		{name: "unknown affinity", cfg: Config{Signer: signer, Network: Testnet(), Affinity: Affinity{Policy: "sticky"}}, wantErr: "unknown Affinity.Policy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ac, app, _, err := c.cfg.withDefaults().validate()
			if c.wantErr != "" {
				var zerr *Error
				if !errors.As(err, &zerr) || zerr.Kind != KindInvalidRequest || zerr.Code != "invalid_config" {
					t.Fatalf("err = %v, want invalid_request/invalid_config", err)
				}
				if !strings.Contains(zerr.Message, c.wantErr) {
					t.Fatalf("message %q lacks %q", zerr.Message, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if app != c.wantApp {
				t.Errorf("app id = %d, want %d", app, c.wantApp)
			}
			if c.wantNet != "" && ac.ResolvedNetwork != c.wantNet {
				t.Errorf("network = %q, want %q", ac.ResolvedNetwork, c.wantNet)
			}
		})
	}
}

func TestConfigValidateWarnings(t *testing.T) {
	signer := fakeSigner{addr: "PAYER"}
	overridden := Testnet()
	overridden.Algod.Endpoint = "https://mainnet-api.example"
	pinned := overridden
	pinned.EscrowAppID = 42

	cases := []struct {
		name string
		cfg  Config
		want string // "" = no warnings
	}{
		{name: "defaults", cfg: Config{Signer: signer, Network: Testnet()}},
		{name: "endpoint over a preset app id", cfg: Config{Signer: signer, Network: overridden}, want: "still that preset's (765860477)"},
		{name: "endpoint with its own app id", cfg: Config{Signer: signer, Network: pinned}},
		{name: "diverging ceiling", cfg: Config{Signer: signer, Network: Testnet(), MaxOutputCeiling: 8192}, want: "MaxOutputCeiling 8192 differs"},
		{name: "ceiling unused when max output is required", cfg: Config{Signer: signer, Network: Testnet(), MaxOutputCeiling: 8192, RequireMaxOutput: true}},
		{name: "TEE required with verification off", cfg: Config{Signer: signer, Network: Testnet(), RequireTEEModels: []string{"m"}, DisableTEE: true}, want: "[m] have no route"},
		{name: "TEE off, nothing required", cfg: Config{Signer: signer, Network: Testnet(), DisableTEE: true}},
		{name: "TEE required with the default verifier", cfg: Config{Signer: signer, Network: Testnet(), RequireTEEModels: []string{"m"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, warnings, err := c.cfg.withDefaults().validate()
			if err != nil {
				t.Fatal(err)
			}
			if c.want == "" {
				if len(warnings) != 0 {
					t.Errorf("warnings = %q, want none", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], c.want) {
				t.Errorf("warnings = %q, want one containing %q", warnings, c.want)
			}
		})
	}
}
