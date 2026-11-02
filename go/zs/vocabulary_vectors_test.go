/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/sdk_vocabulary_vectors.json: the names
// the Go SDK and @txnlab/zerosignal share. Event types and their fields, the
// Error fields, every enum string, the network presets and the Config
// defaults. Signatures are idiomatic to each language; these names are not,
// so a port reads them from here rather than from Go source.
//
// Field names are the Go names in lower camel case, initialisms lowered as
// words: OpenTxID is openTxId, AlgoUSD is algoUsd.
//
//	cd proto/go && go test ./zs -run TestVocabularyVectors -update

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/transient"
)

const vocabularyVectorsPath = "../../testdata/sdk_vocabulary_vectors.json"

type vocabularyNetwork struct {
	AlgodEndpoint string `json:"algod_endpoint"`
	AlgodToken    string `json:"algod_token"`
	EscrowAppID   uint64 `json:"escrow_app_id"`
	FeeSink       string `json:"fee_sink"`
}

type vocabularySolanaNetwork struct {
	RPCEndpoint       string                   `json:"rpc_endpoint"`
	Program           string                   `json:"program"`
	FreeCreditIssuers []vocabularyCreditIssuer `json:"free_credit_issuers"`
}

type vocabularyCreditIssuer struct {
	Key          string `json:"key"`
	URL          string `json:"url"`
	LoopbackOnly bool   `json:"loopback_only"`
}

type vocabulary struct {
	// Events maps each event type to its fields, in declaration order.
	Events map[string][]string `json:"events"`
	// Records are the value types events and errors carry.
	Records map[string][]string          `json:"records"`
	Enums   map[string][]string          `json:"enums"`
	Network map[string]vocabularyNetwork `json:"networks"`
	// SolanaNetwork are the Solana rail's cluster presets.
	SolanaNetwork map[string]vocabularySolanaNetwork `json:"solana_networks"`
	// Defaults are Config's, durations in milliseconds.
	Defaults map[string]int64 `json:"defaults"`
	// NetworkDefaults are the Config defaults that follow the network: what
	// withDefaults gives Privacy and AllowPrivateHosts for each Network, and
	// whether the deployment is Local.
	NetworkDefaults []vocabularyNetworkDefault `json:"network_defaults"`
	// PublicChains is PublicChain's answer for each genesis, in hex.
	PublicChains []vocabularyPublicChain `json:"public_chains"`
}

type vocabularyPublicChain struct {
	Rail    string `json:"rail"`
	Genesis string `json:"genesis_hex"`
	Want    string `json:"want"`
}

// vocabularyNetworkDefault's network is in the TS Network's terms, which both
// languages can build; Privacy and AllowPrivateHosts are the caller's, and
// absent ones are left unset.
type vocabularyNetworkDefault struct {
	Name              string                  `json:"name"`
	Network           vocabularyNetworkConfig `json:"network"`
	Privacy           Privacy                 `json:"privacy,omitempty"`
	AllowPrivateHosts *bool                   `json:"allow_private_hosts,omitempty"`
	WantLocal         bool                    `json:"want_local"`
	WantPrivacy       Privacy                 `json:"want_privacy"`
	WantPrivateHosts  bool                    `json:"want_allow_private_hosts"`
	// WantCheckGenesis is whether the defaults loosened a setting, so New
	// checks the chain is not a public one.
	WantCheckGenesis bool `json:"want_check_genesis"`
}

type vocabularyNetworkConfig struct {
	Rail          string `json:"rail"`
	Network       string `json:"network,omitempty"`
	AlgodEndpoint string `json:"algod_endpoint,omitempty"`
	EscrowAppID   uint64 `json:"escrow_app_id,omitempty"`
	RPCEndpoint   string `json:"rpc_endpoint,omitempty"`
}

func (n vocabularyNetworkConfig) network() Network {
	if n.Rail == "solana" {
		return Network{Rail: ticket.RailSolana, Solana: SolanaNetwork{Cluster: n.Network, RPCEndpoint: n.RPCEndpoint}}
	}
	return Network{Algod: algod.Config{Network: n.Network, Endpoint: n.AlgodEndpoint}, EscrowAppID: n.EscrowAppID}
}

// networkDefaultCases cover each preset, a localnet named but reached off this
// machine, and a localnet reached at loopback without its name, which is not
// Local either: only the preset says it is a development chain.
var networkDefaultCases = []vocabularyNetworkDefault{
	{Name: "algorand localnet", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet", EscrowAppID: 1006}},
	{Name: "algorand localnet at 127.0.0.1", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet", AlgodEndpoint: "http://127.0.0.1:4001", EscrowAppID: 1006}},
	{Name: "algorand localnet named, another host", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet", AlgodEndpoint: "http://10.0.0.5:4001", EscrowAppID: 1006}},
	{Name: "algorand loopback endpoint alone", Network: vocabularyNetworkConfig{Rail: "algorand", AlgodEndpoint: "http://localhost:4001", EscrowAppID: 1006}},
	{Name: "algorand localnet with no app id", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet"}},
	{Name: "algorand testnet", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "testnet"}},
	{Name: "algorand mainnet", Network: vocabularyNetworkConfig{Rail: "algorand"}},
	{Name: "solana localnet", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet"}},
	{Name: "solana localnet at [::1]", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet", RPCEndpoint: "http://[::1]:8899"}},
	{Name: "solana localnet named, another cluster", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet", RPCEndpoint: "https://api.mainnet-beta.solana.com"}},
	{Name: "solana loopback endpoint alone", Network: vocabularyNetworkConfig{Rail: "solana", RPCEndpoint: "http://127.0.0.1:8899"}},
	{Name: "solana devnet", Network: vocabularyNetworkConfig{Rail: "solana", Network: "devnet"}},
	{Name: "solana localnet, relay asked for", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet"}, Privacy: PrivacyRelayRequired},
	{Name: "solana localnet, private hosts refused", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet"}, AllowPrivateHosts: new(false)},
	{Name: "algorand testnet, private hosts allowed", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "testnet"}, AllowPrivateHosts: new(true)},
	{Name: "solana localnet, both set", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet"}, Privacy: PrivacyDirect, AllowPrivateHosts: new(true)},
	// Host spellings a URL parser may rewrite: Go reads the host as written,
	// lowered, so the TS twin must not take WHATWG's rewrite of it.
	{Name: "algorand localnet at LOCALHOST", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet", AlgodEndpoint: "http://LOCALHOST:4001", EscrowAppID: 1006}},
	{Name: "algorand localnet at 127.1", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet", AlgodEndpoint: "http://127.1:4001", EscrowAppID: 1006}},
	{Name: "algorand localnet at 0x7f000001", Network: vocabularyNetworkConfig{Rail: "algorand", Network: "localnet", AlgodEndpoint: "http://0x7f000001:4001", EscrowAppID: 1006}},
	{Name: "solana localnet at the full ::1", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet", RPCEndpoint: "http://[0:0:0:0:0:0:0:1]:8899"}},
	{Name: "solana localnet at v4-mapped 127.0.0.1", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet", RPCEndpoint: "http://[::ffff:127.0.0.1]:8899"}},
	{Name: "solana localnet with userinfo", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet", RPCEndpoint: "http://user@127.0.0.1:8899"}},
	{Name: "solana localnet at 127.0.0.1.example", Network: vocabularyNetworkConfig{Rail: "solana", Network: "localnet", RPCEndpoint: "http://127.0.0.1.example:8899"}},
}

// publicChainCases are each public chain's genesis, a local validator's, one
// rail's genesis asked of the other, and a Solana hash of the wrong length.
func publicChainCases(t *testing.T) []vocabularyPublicChain {
	b64 := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b58 := func(s string) []byte {
		h, err := solana.ParseHash(s)
		if err != nil {
			t.Fatal(err)
		}
		return h[:]
	}
	local := bytes.Repeat([]byte{7}, 32)
	cases := []struct {
		rail    ticket.Rail
		genesis []byte
	}{
		{ticket.RailAlgorand, b64("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=")},
		{ticket.RailAlgorand, b64("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")},
		{ticket.RailAlgorand, b64("mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=")},
		{ticket.RailAlgorand, local},
		{ticket.RailAlgorand, b58(rpc.DevnetGenesis)},
		{ticket.RailSolana, b58(rpc.MainnetGenesis)},
		{ticket.RailSolana, b58(rpc.TestnetGenesis)},
		{ticket.RailSolana, b58(rpc.DevnetGenesis)},
		{ticket.RailSolana, local},
		{ticket.RailSolana, b64("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")},
		{ticket.RailSolana, b58(rpc.DevnetGenesis)[:31]},
	}
	var out []vocabularyPublicChain
	for _, c := range cases {
		rail := "algorand"
		if c.rail == ticket.RailSolana {
			rail = "solana"
		}
		out = append(out, vocabularyPublicChain{Rail: rail, Genesis: hex.EncodeToString(c.genesis), Want: PublicChain(c.rail, c.genesis)})
	}
	return out
}

// tsName lowers a Go field name to the TypeScript one. A word is an upper-case
// run, or an upper-case letter followed by lower-case ones and digits, so
// FeeBpsKnown is fee/bps/known and OpenTxID is open/tx/id.
func tsName(goName string) string {
	r := []rune(goName)
	var words []string
	for i := 0; i < len(r); {
		j := i + 1
		if unicode.IsUpper(r[i]) {
			for j < len(r) && unicode.IsUpper(r[j]) && !(j+1 < len(r) && unicode.IsLower(r[j+1])) {
				j++
			}
		}
		for j < len(r) && !unicode.IsUpper(r[j]) {
			j++
		}
		words = append(words, string(r[i:j]))
		i = j
	}
	out := ""
	for k, w := range words {
		lw := []rune(strings.ToLower(w))
		if k > 0 {
			lw[0] = unicode.ToUpper(lw[0])
		}
		out += string(lw)
	}
	return out
}

// stringConsts returns the values of the exported string constants of the
// named type declared in dir, in declaration order (files by name). Read from
// source rather than listed, so a constant added in Go reaches the fixture
// without anyone remembering to add it here.
func stringConsts(t *testing.T, dir, typeName string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	var out []string
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				id, ok := vs.Type.(*ast.Ident)
				if !ok || id.Name != typeName {
					continue
				}
				for i, n := range vs.Names {
					if !n.IsExported() {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Fatalf("%s: %s is not a string literal", fset.Position(n.Pos()), n.Name)
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					out = append(out, s)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s constants in %s", typeName, dir)
	}
	return out
}

func fieldNames(v any) []string {
	var names []string
	for f := range reflect.TypeOf(v).Fields() {
		if f.IsExported() {
			names = append(names, tsName(f.Name))
		}
	}
	return names
}

func buildVocabulary(t *testing.T) vocabulary {
	t.Helper()
	v := vocabulary{
		Events: map[string][]string{},
		Records: map[string][]string{
			"Error":      fieldNames(Error{}),
			"NodeRef":    fieldNames(NodeRef{}),
			"Item":       fieldNames(Item{}),
			"Ticket":     fieldNames(Ticket{}),
			"Settlement": fieldNames(Settlement{}),
			"FeeUnit":    fieldNames(FeeUnit{}),
			// The cause a caller reads off an upstream Error.
			"ProviderError": fieldNames(ProviderError{}),
			// What a TicketJournal stores.
			"TicketRecord": fieldNames(TicketRecord{}),
			"SettleArgs":   fieldNames(SettleArgs{}),
		},
		Enums:         map[string][]string{},
		Network:       map[string]vocabularyNetwork{},
		SolanaNetwork: map[string]vocabularySolanaNetwork{},
		Defaults: map[string]int64{
			"reserveTimeoutMs":           DefaultReserveTimeout.Milliseconds(),
			"concurrentSlots":            DefaultDepositSlots,
			"freeCreditBatch":            DefaultFreeCreditBatch,
			"freeCreditFetchTimeoutMs":   freeCreditFetchTimeout.Milliseconds(),
			"freeCreditFailureBackoffMs": freeCreditFailureBackoff.Milliseconds(),
			"affinityTtlMs":              defaultAffinityTTL.Milliseconds(),
			"affinityMax":                defaultAffinityMax,
			"refreshIntervalMs":          DefaultRefreshInterval.Milliseconds(),
			"refreshTimeoutMs":           DefaultRefreshTimeout.Milliseconds(),
			"detailsFetchTimeoutMs":      DefaultDetailsFetchTimeout.Milliseconds(),
			"attestationFetchTimeoutMs":  DefaultAttestationFetchTimeout.Milliseconds(),
			"detailsConcurrency":         DefaultDetailsConcurrency,
			"probeBudget":                DefaultProbeBudget,
			"targetTopK":                 DefaultTargetTopK,
			"maxCacheAgeMs":              DefaultMaxCacheAge.Milliseconds(),
			"maxCarryAgeMs":              DefaultMaxCarryAge.Milliseconds(),
			"latencyStateMax":            DefaultLatencyStateMax,
			"retryBudgetMs":              transient.OverallDeadline.Milliseconds(),
			"maxOutputCeiling":           int64(selection.DefaultMaxOutputCeiling),
			"settlePendingGraceMs":       settlePendingGrace.Milliseconds(),
			"lapseFallbackMs":            defaultLapseFallback.Milliseconds(),
			"feeRateCacheTtlMs":          feeRateCacheTTL.Milliseconds(),
			"feeRateRefreshMs":           feeRateRefreshTimeout.Milliseconds(),
			"escrowConfigTimeoutMs":      escrowConfigTimeout.Milliseconds(),
			// The default inference client's wait for a node's response
			// headers, read off the client so a change there moves it.
			"responseHeaderBackstopMs": Config{}.defaultHTTPClient().Transport.(*http.Transport).ResponseHeaderTimeout.Milliseconds(),
			// Read through withDefaults, so a zero field left unfilled moves it.
			"streamIdlePreStreamMs":  Config{}.withDefaults().StreamIdle.PreStream.Milliseconds(),
			"streamIdleMidStreamMs":  Config{}.withDefaults().StreamIdle.MidStream.Milliseconds(),
			"streamIdleToolActiveMs": Config{}.withDefaults().StreamIdle.ToolActive.Milliseconds(),
			"maxReplyBytes":          int64(maxReplyBytes),
		},
	}
	for _, c := range eventTypeCases {
		v.Events[c.want] = fieldNames(c.ev)
	}
	for _, name := range []string{
		"Kind", "Privacy", "AffinityPolicy", "RelayHopReason", "ToolState", "TicketStatus", "SettleKind", "Endpoint",
	} {
		v.Enums[name] = stringConsts(t, ".", name)
	}
	v.Enums["Attribution"] = stringConsts(t, "../transient", "Attribution")
	// An int enum, so its names come from String(): every value but ReceiptOK.
	for rv := ReceiptViolationSig; rv <= ReceiptViolationBodyHash; rv++ {
		v.Enums["ReceiptViolation"] = append(v.Enums["ReceiptViolation"], rv.String())
	}
	for _, n := range []algod.Network{algod.NetworkLocalnet, algod.NetworkTestnet, algod.NetworkMainnet} {
		ac := algod.Config{Network: string(n)}
		if err := ac.Resolve(); err != nil {
			t.Fatal(err)
		}
		v.Network[string(n)] = vocabularyNetwork{
			AlgodEndpoint: ac.ResolvedEndpoint,
			AlgodToken:    ac.ResolvedToken,
			EscrowAppID:   algod.EscrowAppID(string(n)),
			FeeSink:       algod.FeeSink(string(n)),
		}
	}
	for _, n := range SolanaClusters() {
		rpcEndpoint, program, ok := SolanaClusterPreset(n)
		if !ok {
			t.Fatalf("SolanaClusters lists %q, which has no preset", n)
		}
		issuers, _ := SolanaClusterFreeCreditIssuers(n)
		credit := []vocabularyCreditIssuer{}
		for _, iss := range issuers {
			credit = append(credit, vocabularyCreditIssuer{Key: iss.Key, URL: iss.URL, LoopbackOnly: iss.LoopbackOnly})
		}
		v.SolanaNetwork[n] = vocabularySolanaNetwork{RPCEndpoint: rpcEndpoint, Program: program.String(), FreeCreditIssuers: credit}
	}
	for _, c := range networkDefaultCases {
		cfg := Config{Network: c.Network.network(), Privacy: c.Privacy, AllowPrivateHosts: c.AllowPrivateHosts}.withDefaults()
		d, _, err := ResolveNetwork(cfg.Network)
		c.WantLocal = err == nil && d.Local()
		c.WantPrivacy = cfg.Privacy
		c.WantPrivateHosts = cfg.privateHostsAllowed()
		c.WantCheckGenesis = cfg.localDefaults
		v.NetworkDefaults = append(v.NetworkDefaults, c)
	}
	v.PublicChains = publicChainCases(t)
	return v
}

func TestVocabularyVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildVocabulary(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(vocabularyVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vocabularyVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update to create it)", vocabularyVectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale; run: go test ./zs -run TestVocabularyVectors -update", vocabularyVectorsPath)
	}
}

func TestTSName(t *testing.T) {
	for in, want := range map[string]string{
		"OpenTxID":       "openTxId",
		"AlgoUSD":        "algoUsd",
		"FeeBpsKnown":    "feeBpsKnown",
		"MIME":           "mime",
		"B64":            "b64",
		"ID":             "id",
		"TicketID":       "ticketId",
		"ArgumentsDelta": "argumentsDelta",
		"Op":             "op",
		// An initialism run ends where the next word's capital starts.
		"HTTPServer":  "httpServer",
		"TEEAttested": "teeAttested",
	} {
		if got := tsName(in); got != want {
			t.Errorf("tsName(%q) = %q, want %q", in, got, want)
		}
	}
}
