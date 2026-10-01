/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

// Cross-impl parity vectors for BodyDrivesServerSideToolGrowth — the predicate
// that decides whether a reserve carries tool-loop headroom.
//
// The proxy has always used this narrow predicate; the client used
// tokenize.BodyHasTools ("any tools at all"), so the two sized the same request
// differently — a caller-executed function tool made the client escrow
// max_tool_iterations x tool_headroom_per_iteration (80,000 tokens at the node's
// defaults) for a server-side loop that structurally cannot run. Mirroring the
// predicate into proto/ts fixed that, and this fixture keeps the two in step:
// the classification surface it depends on (normalizeToolName, the not-billed
// table, the shell environment discriminator) is broad enough that a silent
// divergence is otherwise easy.
//
// Regenerate after an intentional change:
//
//	cd proto/go && go test ./inject -run TestToolGrowthVectors -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

var updateToolGrowthVectors = flag.Bool("update", false, "regenerate proto/testdata/tool_growth_vectors.json")

const toolGrowthVectorsPath = "../../testdata/tool_growth_vectors.json"

type toolGrowthVector struct {
	Name     string `json:"name"`
	Body     string `json:"body"`
	Expected bool   `json:"expected"`
	// Why records the reasoning so a future reader can tell an intentional
	// classification from an accident of the table.
	Why string `json:"why"`
}

type toolClassVector struct {
	Name      string `json:"name"`
	Entry     string `json:"entry"`
	WantName  string `json:"want_name"`
	WantClass string `json:"want_class"`
}

type toolGrowthVectorsFile struct {
	Version   int                `json:"version"`
	Comment   string             `json:"comment"`
	Growth    []toolGrowthVector `json:"body_drives_server_side_tool_growth"`
	Classify  []toolClassVector  `json:"classify_tool_entry"`
	Normalize map[string]string  `json:"normalize_tool_name"`
}

// growthBodies are kept as literal JSON so the fixture stays human-auditable.
var growthBodies = []struct{ name, body, why string }{
	{"no_tools", `{"model":"m","messages":[]}`, "no tools field at all"},
	{"empty_tools", `{"model":"m","tools":[]}`, "empty array cannot grow anything"},
	{"malformed", `not json`, "unparseable body reports false; the node's input-budget check backstops"},
	{"tools_not_array", `{"tools":{"type":"web_search"}}`, "non-array tools is not a tools list"},

	{"function_only", `{"tools":[{"type":"function","function":{"name":"get_weather"}}]}`,
		"caller-executed: the harness runs it and re-issues a separately-measured request"},
	{"many_functions", `{"tools":[{"type":"function","function":{"name":"a"}},{"type":"function","function":{"name":"b"}},{"type":"function","function":{"name":"c"}}]}`,
		"the coding-agent case: MCP servers expanded client-side into plain function tools"},
	{"bare_function_no_type", `{"tools":[{"function":{"name":"lookup"}}]}`,
		"no type: a bare function entry is still caller-executed"},
	{"local_shell", `{"tools":[{"type":"local_shell"}]}`, "caller-executed by name"},
	{"apply_patch", `{"tools":[{"type":"apply_patch"}]}`, "caller-executed by name"},
	{"computer_use", `{"tools":[{"type":"computer_use_preview"}]}`,
		"normalizes to computer_use; the caller's harness performs the actions"},
	{"anthropic_bash_dated", `{"tools":[{"type":"bash_20250124"}]}`,
		"the _YYYYMMDD suffix normalizes away to bash, which is caller-executed"},
	{"shell_local_env", `{"tools":[{"type":"shell","environment":{"type":"local"}}]}`,
		"environment.type local folds onto local_shell — runs on the caller's machine"},

	{"zs_builtin", `{"tools":[{"type":"zs_web_search"}]}`,
		"node built-in: the NODE runs the chat->tool->chat loop in-process"},
	{"zs_builtin_among_functions", `{"tools":[{"type":"function","function":{"name":"a"}},{"type":"zs_web_read"}]}`,
		"one growth-driving tool anywhere in the list is enough"},
	{"vendor_web_search", `{"tools":[{"type":"web_search"}]}`,
		"vendor-hosted: the upstream re-prefills results into the context"},
	{"vendor_code_interpreter", `{"tools":[{"type":"code_interpreter"}]}`, "vendor-hosted"},
	{"vendor_mcp", `{"tools":[{"type":"mcp","server_label":"x"}]}`,
		"hosted-but-free still inflates context — the per-call fee is a separate axis"},
	{"moonshot_builtin_function", `{"tools":[{"type":"builtin_function","function":{"name":"$web_search"}}]}`,
		"Moonshot spelling: the identifying name is the $-prefixed function name"},
	{"shell_hosted_env", `{"tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`,
		"vendor-managed container: the upstream executes it"},
	{"unknown_hosted_type", `{"tools":[{"type":"some_new_vendor_tool"}]}`,
		"default-deny: an unrecognized hosted type is assumed to grow context"},
}

var classifyEntries = []struct{ name, entry string }{
	{"function", `{"type":"function","function":{"name":"get_weather"}}`},
	{"zs_builtin", `{"type":"zs_web_search"}`},
	{"builtin_function_moonshot", `{"type":"builtin_function","function":{"name":"$web_search"}}`},
	{"bare_function", `{"function":{"name":"lookup"}}`},
	{"dollar_named_no_type", `{"function":{"name":"$web_search"}}`},
	{"shell_local", `{"type":"shell","environment":{"type":"local"}}`},
	{"shell_hosted", `{"type":"shell","environment":{"type":"container_auto"}}`},
	{"shell_no_env", `{"type":"shell"}`},
	{"mcp", `{"type":"mcp"}`},
	{"web_search_preview", `{"type":"web_search_preview"}`},
	{"unknown", `{"type":"brand_new_tool"}`},
	{"not_an_object", `"just a string"`},
}

var normalizeInputs = []string{
	"$web_search", "web_search_calls", "web_search_call", "web_search_20250305",
	"web_search_preview", "computer", "computer_use_preview", "custom_tool",
	"code_execution", "collections_search", "attachment_search", "  WEB_SEARCH  ",
	"mcp_call", "already_canonical",
}

func classString(c inject.ToolClass) string {
	switch c {
	case inject.ToolClassClient:
		return "client"
	case inject.ToolClassNotBilled:
		return "not_billed"
	case inject.ToolClassVendorBillable:
		return "vendor_billable"
	}
	return "unknown"
}

func buildToolGrowthVectors() *toolGrowthVectorsFile {
	growth := make([]toolGrowthVector, 0, len(growthBodies))
	for _, b := range growthBodies {
		growth = append(growth, toolGrowthVector{
			Name:     b.name,
			Body:     b.body,
			Expected: inject.BodyDrivesServerSideToolGrowth([]byte(b.body)),
			Why:      b.why,
		})
	}
	classify := make([]toolClassVector, 0, len(classifyEntries))
	for _, e := range classifyEntries {
		name, class := inject.ClassifyToolEntry(json.RawMessage(e.entry))
		classify = append(classify, toolClassVector{
			Name: e.name, Entry: e.entry, WantName: name, WantClass: classString(class),
		})
	}
	normalize := make(map[string]string, len(normalizeInputs))
	for _, in := range normalizeInputs {
		normalize[in] = inject.NormalizeToolName(in)
	}
	return &toolGrowthVectorsFile{
		Version: 1,
		Comment: "Cross-impl parity vectors for reserve tool-loop-headroom classification. " +
			"Regenerate via: cd proto/go && go test ./inject -run TestToolGrowthVectors -update. " +
			"Loaded by proto/go/inject/toolgrowth_vectors_test.go and proto/ts/test/tool-growth-vectors.test.ts.",
		Growth:    growth,
		Classify:  classify,
		Normalize: normalize,
	}
}

func TestToolGrowthVectors(t *testing.T) {
	want := buildToolGrowthVectors()
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateToolGrowthVectors {
		if err := os.WriteFile(toolGrowthVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", toolGrowthVectorsPath)
		return
	}

	onDisk, err := os.ReadFile(toolGrowthVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(onDisk, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./inject -run TestToolGrowthVectors -update", toolGrowthVectorsPath)
	}
}

// TestGrowthVectorsCoverBothOutcomes guards against a fixture that silently
// drifts to all-true or all-false and stops discriminating.
func TestGrowthVectorsCoverBothOutcomes(t *testing.T) {
	var yes, no int
	for _, b := range growthBodies {
		if inject.BodyDrivesServerSideToolGrowth([]byte(b.body)) {
			yes++
		} else {
			no++
		}
	}
	if yes == 0 || no == 0 {
		t.Fatalf("vectors must exercise both outcomes: %d growth, %d no-growth", yes, no)
	}
}
