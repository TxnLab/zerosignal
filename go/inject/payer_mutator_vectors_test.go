/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

// Cross-impl vectors for the four mutators a payer runs before sealing:
// DropRoutingPreferences, DropPromptCacheKey, DropEmptyTools, ClampMaxOutput.
// proto/ts/test/payer-mutator-vectors.test.ts replays them against
// proto/ts/src/inject/mutators.ts.
//
// They pin the decision — which bodies change and what they mean afterwards —
// not the bytes. The payer computes the admission tag over its own output, so
// the two sides only have to agree on the result; Go re-marshals (sorted keys,
// compact) while TS splices the original text, and both are correct.
//
// Regenerate after an intentional change:
//
//	cd proto/go && go test ./inject -run TestPayerMutatorVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

const payerMutatorVectorsPath = "../../testdata/payer_mutator_vectors.json"

// Bodies shared by the drop mutators. Each one is a string, not a json.RawMessage,
// so malformed inputs survive into the fixture verbatim.
var dropBodies = []struct{ name, body string }{
	{"empty_body", ``},
	{"not_json", `{"model":`},
	{"top_level_array", `[{"provider":{}}]`},
	{"top_level_null", `null`},
	{"top_level_string", `"provider"`},
	{"no_target_key", `{"model":"m","messages":[]}`},
	{"provider_object", `{"model":"m","provider":{"order":["a"],"allow_fallbacks":false},"stream":true}`},
	{"provider_null", `{"provider":null,"model":"m"}`},
	{"provider_only_key", `{"provider":{"sort":"price"}}`},
	// The key is spelled with a JSON \u escape for "i". The backslash is built
	// from \x5c so that no editor or tool can turn the escape into a literal.
	{"provider_escaped_key", `{"prov` + "\x5c" + `u0069der":{"sort":"price"},"model":"m"}`},
	{"provider_nested_not_top_level", `{"metadata":{"provider":"x"},"model":"m"}`},
	{"provider_whitespace", "{\n  \"model\" : \"m\" ,\n  \"provider\" : { \"only\" : [ \"x\" ] }\n}\n"},
	{"prompt_cache_key", `{"model":"m","prompt_cache_key":"sess-1234","input":"hi"}`},
	{"prompt_cache_key_and_provider", `{"prompt_cache_key":"k","provider":{},"model":"m"}`},
	{"tools_empty", `{"model":"m","tools":[],"tool_choice":"auto"}`},
	{"tools_empty_spaced", `{"tools":[ ],"model":"m"}`},
	{"tools_empty_no_choice", `{"tools":[],"model":"m"}`},
	{"tools_null", `{"tools":null,"tool_choice":"none","model":"m"}`},
	{"tools_nonempty", `{"tools":[{"type":"function","function":{"name":"f"}}],"tool_choice":"auto"}`},
	{"tools_object", `{"tools":{},"tool_choice":"auto"}`},
	{"tools_string", `{"tools":"[]","tool_choice":"auto"}`},
	{"tool_choice_without_tools", `{"tool_choice":"auto","model":"m"}`},
	{"large_integer_elsewhere", `{"seed":12345678901234567890,"provider":{},"tools":[],"prompt_cache_key":"k","temperature":0.10}`},
	// The other target keys spelled with a \u escape too, built the same way.
	{"escaped_other_keys", `{"prompt_cache_` + "\x5c" + `u006bey":"k","t` + "\x5c" + `u006fols":[],"tool_ch` + "\x5c" + `u006fice":"auto","m":1}`},
	// A repeated key: Go's map keeps the last occurrence and a drop removes
	// them all. RFC 8259 leaves repeated names to the reader.
	{"repeated_keys_last_nonempty", `{"provider":{},"tools":[],"provider":{"sort":"x"},"tools":[{"type":"function"}],"prompt_cache_key":"a","prompt_cache_key":"b"}`},
	{"repeated_keys_last_empty", `{"tools":[{"type":"function"}],"tool_choice":"auto","tools":[]}`},
}

var clampBodies = []struct {
	name    string
	body    string
	ceiling uint64
}{
	{"empty_body", ``, 100},
	{"not_json", `{"max_tokens":`, 100},
	{"top_level_array", `[{"max_tokens":500}]`, 100},
	{"ceiling_zero_is_noop", `{"max_tokens":500}`, 0},
	{"no_ceiling_field", `{"model":"m"}`, 100},
	{"max_tokens_above", `{"model":"m","max_tokens":500}`, 100},
	{"max_tokens_equal", `{"max_tokens":100}`, 100},
	{"max_tokens_below", `{"max_tokens":99}`, 100},
	{"max_completion_tokens_above", `{"max_completion_tokens":65536}`, 32768},
	{"max_output_tokens_above", `{"max_output_tokens":40000,"input":"x"}`, 32768},
	{"all_three_mixed", `{"max_tokens":50,"max_completion_tokens":700,"max_output_tokens":300}`, 100},
	{"string_value_left_alone", `{"max_tokens":"500"}`, 100},
	{"fraction_left_alone", `{"max_tokens":500.5}`, 100},
	{"exponent_left_alone", `{"max_tokens":5e3}`, 100},
	{"negative_left_alone", `{"max_tokens":-5}`, 100},
	{"null_left_alone", `{"max_tokens":null}`, 100},
	{"uint64_max_clamped", `{"max_tokens":18446744073709551615}`, 100},
	{"uint64_overflow_left_alone", `{"max_tokens":18446744073709551616}`, 100},
	{"nested_not_top_level", `{"metadata":{"max_tokens":500}}`, 100},
	{"large_integer_elsewhere", `{"seed":12345678901234567890,"max_tokens":500}`, 100},
	{"ceiling_above_2_53", `{"max_tokens":18446744073709551615}`, 9007199254740993},
	{"repeated_key_last_below", `{"max_tokens":500,"max_tokens":50}`, 100},
	{"repeated_key_last_above", `{"max_tokens":50,"max_tokens":500}`, 100},
	{"repeated_key_both_above", `{"max_tokens":500,"max_tokens":200}`, 100},
	{"escaped_key", `{"max_t` + "\x5c" + `u006fkens":500}`, 100},
}

type dropCase struct {
	Name    string `json:"name"`
	Body    string `json:"body"`
	Changed bool   `json:"changed"`
	Want    string `json:"want"`
}

type clampCase struct {
	Name      string `json:"name"`
	Body      string `json:"body"`
	Ceiling   string `json:"ceiling"`
	Changed   bool   `json:"changed"`
	Want      string `json:"want"`
	Requested string `json:"requested"`
}

type payerMutatorVectorsFile struct {
	Version                int         `json:"version"`
	Comment                string      `json:"comment"`
	MaxOutputFields        []string    `json:"max_output_fields"`
	DropRoutingPreferences []dropCase  `json:"drop_routing_preferences"`
	DropPromptCacheKey     []dropCase  `json:"drop_prompt_cache_key"`
	DropEmptyTools         []dropCase  `json:"drop_empty_tools"`
	ClampMaxOutput         []clampCase `json:"clamp_max_output"`
}

func buildDropCases(t *testing.T, fn func([]byte) ([]byte, error)) []dropCase {
	t.Helper()
	out := make([]dropCase, 0, len(dropBodies))
	var changed int
	for _, b := range dropBodies {
		got, err := fn([]byte(b.body))
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		c := dropCase{Name: b.name, Body: b.body, Changed: !bytes.Equal(got, []byte(b.body)), Want: string(got)}
		if c.Changed {
			changed++
		}
		out = append(out, c)
	}
	if changed == 0 || changed == len(out) {
		t.Fatalf("every drop mutator needs both changed and unchanged cases (changed=%d of %d)", changed, len(out))
	}
	return out
}

func buildPayerMutatorVectors(t *testing.T) payerMutatorVectorsFile {
	t.Helper()
	var clamp []clampCase
	var clampChanged int
	for _, b := range clampBodies {
		got, requested, err := inject.ClampMaxOutput([]byte(b.body), b.ceiling)
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		c := clampCase{
			Name: b.name, Body: b.body, Ceiling: strconv.FormatUint(b.ceiling, 10),
			Changed: !bytes.Equal(got, []byte(b.body)), Want: string(got),
			Requested: strconv.FormatUint(requested, 10),
		}
		if c.Changed {
			clampChanged++
		}
		clamp = append(clamp, c)
	}
	if clampChanged == 0 || clampChanged == len(clamp) {
		t.Fatalf("clamp needs both changed and unchanged cases (changed=%d of %d)", clampChanged, len(clamp))
	}
	return payerMutatorVectorsFile{
		Version: 1,
		Comment: "Cross-impl vectors for the payer's pre-seal mutators. They pin which bodies change and what " +
			"the result means, not its bytes: compare `want` by value. Generated by " +
			"proto/go/inject/payer_mutator_vectors_test.go; regenerate with " +
			"`cd proto/go && go test ./inject -run TestPayerMutatorVectors -update`.",
		MaxOutputFields:        inject.MaxOutputFields(),
		DropRoutingPreferences: buildDropCases(t, inject.DropRoutingPreferences),
		DropPromptCacheKey:     buildDropCases(t, inject.DropPromptCacheKey),
		DropEmptyTools:         buildDropCases(t, inject.DropEmptyTools),
		ClampMaxOutput:         clamp,
	}
}

func TestPayerMutatorVectors(t *testing.T) {
	encoded, err := json.MarshalIndent(buildPayerMutatorVectors(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')
	if *updateToolGrowthVectors {
		if err := os.WriteFile(payerMutatorVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", payerMutatorVectorsPath)
		return
	}
	onDisk, err := os.ReadFile(payerMutatorVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(onDisk, encoded) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./inject -run TestPayerMutatorVectors -update, "+
			"and port the change to proto/ts/src/inject/mutators.ts", payerMutatorVectorsPath)
	}
}
