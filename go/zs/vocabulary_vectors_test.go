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
	"github.com/TxnLab/zerosignal/go/transient"
)

const vocabularyVectorsPath = "../../testdata/sdk_vocabulary_vectors.json"

type vocabularyNetwork struct {
	AlgodEndpoint string `json:"algod_endpoint"`
	AlgodToken    string `json:"algod_token"`
	EscrowAppID   uint64 `json:"escrow_app_id"`
	FeeSink       string `json:"fee_sink"`
}

type vocabulary struct {
	// Events maps each event type to its fields, in declaration order.
	Events map[string][]string `json:"events"`
	// Records are the value types events and errors carry.
	Records map[string][]string          `json:"records"`
	Enums   map[string][]string          `json:"enums"`
	Network map[string]vocabularyNetwork `json:"networks"`
	// Defaults are Config's, durations in milliseconds.
	Defaults map[string]int64 `json:"defaults"`
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
			// The cause a caller reads off an upstream Error.
			"ProviderError": fieldNames(ProviderError{}),
			// What a TicketJournal stores.
			"TicketRecord": fieldNames(TicketRecord{}),
			"SettleArgs":   fieldNames(SettleArgs{}),
		},
		Enums:   map[string][]string{},
		Network: map[string]vocabularyNetwork{},
		Defaults: map[string]int64{
			"reserveTimeoutMs":          DefaultReserveTimeout.Milliseconds(),
			"concurrentSlots":           DefaultDepositSlots,
			"affinityTtlMs":             defaultAffinityTTL.Milliseconds(),
			"affinityMax":               defaultAffinityMax,
			"refreshIntervalMs":         DefaultRefreshInterval.Milliseconds(),
			"refreshTimeoutMs":          DefaultRefreshTimeout.Milliseconds(),
			"detailsFetchTimeoutMs":     DefaultDetailsFetchTimeout.Milliseconds(),
			"attestationFetchTimeoutMs": DefaultAttestationFetchTimeout.Milliseconds(),
			"detailsConcurrency":        DefaultDetailsConcurrency,
			"probeBudget":               DefaultProbeBudget,
			"targetTopK":                DefaultTargetTopK,
			"maxCacheAgeMs":             DefaultMaxCacheAge.Milliseconds(),
			"maxCarryAgeMs":             DefaultMaxCarryAge.Milliseconds(),
			"latencyStateMax":           DefaultLatencyStateMax,
			"retryBudgetMs":             transient.OverallDeadline.Milliseconds(),
			"maxOutputCeiling":          int64(selection.DefaultMaxOutputCeiling),
			"settlePendingGraceMs":      settlePendingGrace.Milliseconds(),
			"lapseFallbackMs":           defaultLapseFallback.Milliseconds(),
			"feeRateCacheTtlMs":         feeRateCacheTTL.Milliseconds(),
			"feeRateRefreshMs":          feeRateRefreshTimeout.Milliseconds(),
			"escrowConfigTimeoutMs":     escrowConfigTimeout.Milliseconds(),
			// The default inference client's wait for a node's response
			// headers, read off the client so a change there moves it.
			"responseHeaderBackstopMs": Config{}.defaultHTTPClient().Transport.(*http.Transport).ResponseHeaderTimeout.Milliseconds(),
			// Read through withDefaults, so a zero field left unfilled moves it.
			"streamIdlePreStreamMs":  Config{}.withDefaults().StreamIdle.PreStream.Milliseconds(),
			"streamIdleMidStreamMs":  Config{}.withDefaults().StreamIdle.MidStream.Milliseconds(),
			"streamIdleToolActiveMs": Config{}.withDefaults().StreamIdle.ToolActive.Milliseconds(),
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
