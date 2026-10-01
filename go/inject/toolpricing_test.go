/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestInferDialect(t *testing.T) {
	cases := map[string]Dialect{
		"https://api.x.ai/v1":          DialectXAI,
		"https://api.openai.com/v1":    DialectOpenAI,
		"https://api.moonshot.ai/v1":   DialectMoonshot,
		"https://api.kimi.ai/v1":       DialectMoonshot,
		"https://openrouter.ai/api/v1": DialectOpenRouter,
		"https://api.together.xyz/v1":  DialectGeneric,
		"http://localhost:8000/v1":     DialectGeneric,
		// Negatives that share a substring with the OpenRouter pattern at each
		// length it could be loosened to — "router" and "openrouter". The other
		// negatives here overlap no host pattern at all, so they agree with a
		// widened predicate by coincidence rather than by construction.
		"https://my-router.example.com/v1":  DialectGeneric,
		"https://openrouter.example.com/v1": DialectGeneric,
		"https://OpenRouter.ai/api/v1":      DialectOpenRouter,
		"https://OPENROUTER.AI/api/v1/chat": DialectOpenRouter,
	}
	for url, want := range cases {
		if got := InferDialect(url); got != want {
			t.Errorf("InferDialect(%q) = %q, want %q", url, got, want)
		}
	}
}

// KnownDialects is what every consumer enumerates, and a consumer's own test
// can't pin it: a table-driven test that ranges over it reports PASS with zero
// subtests if it comes back short, so the accessor has to be pinned HERE,
// against the set it wraps.
func TestKnownDialects_ReturnsTheWholeSetAndACopy(t *testing.T) {
	got := KnownDialects()
	if !slices.Equal(got, knownDialects) {
		t.Fatalf("KnownDialects() = %v, want %v", got, knownDialects)
	}
	// The doc promises the slice is the caller's own. A future consumer sorting
	// or truncating the result must not reach the package-level set.
	got[0] = Dialect("mutated")
	if again := KnownDialects(); slices.Contains(again, Dialect("mutated")) {
		t.Errorf("KnownDialects() aliases the package set: %v", again)
	}
}

// IsKnownDialect has no caller inside this module, and proto/go is published
// and CI'd on its own — so without this table the only thing that can catch a
// validator accepting everything (or forking back into a hand-written switch)
// lives in a repo the publish gate never builds.
func TestIsKnownDialect(t *testing.T) {
	known := KnownDialects()
	if len(known) < 6 {
		t.Fatalf("KnownDialects() returned %d dialects; the loop below proves nothing", len(known))
	}
	for _, d := range known {
		if !IsKnownDialect(string(d)) {
			t.Errorf("IsKnownDialect(%q) = false, want true", d)
		}
	}
	// "auto" and "" are a CONSUMER's spellings for "infer it" — this predicate
	// answers only "does the package define this dialect", so a validator that
	// wants to accept them has to say so itself.
	for _, s := range []string{"bogus", "auto", "", "OPENROUTER"} {
		if IsKnownDialect(s) {
			t.Errorf("IsKnownDialect(%q) = true, want false", s)
		}
	}
}

// stringLit unquotes a string-literal expression. strconv.Unquote, not a Trim
// of `"`: a raw backtick literal is the same constant to the compiler, and
// trimming quote characters would leave the backticks on and report a value no
// Dialect ever has.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// knownDialects is hand-maintained, and every consumer that validates an
// operator's dialect override now enumerates it — so a constant declared
// without being added here would be invisible to the validator AND to the
// consumer test that iterates it, which is the same fork one level down. Read
// the constants out of the source instead, where they can't be omitted.
func TestKnownDialects_CoversEveryConstant(t *testing.T) {
	// The whole package, not one file: a constant declared in reasoning.go or a
	// new dialect_openrouter.go is the same fork, and scanning a single file
	// would let file placement route around the check.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}

	// Pass one: every package-scope string constant by name, so a dialect
	// declared through one — `const x = "v"; const D Dialect = x`, the ordinary
	// extract-the-magic-string refactor — resolves instead of vanishing.
	strConsts := map[string]string{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range spec.Names {
				if i >= len(spec.Values) {
					continue
				}
				if s, ok := stringLit(spec.Values[i]); ok {
					strConsts[name.Name] = s
				}
			}
			return true
		})
	}
	resolve := func(e ast.Expr) (string, bool) {
		if s, ok := stringLit(e); ok {
			return s, true
		}
		if id, ok := e.(*ast.Ident); ok {
			s, ok := strConsts[id.Name]
			return s, ok
		}
		return "", false
	}

	declared := map[string]bool{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			// Both spellings: `X Dialect = v` (typed spec) and `X = Dialect(v)`
			// (conversion), which carries no spec.Type.
			typed := false
			if id, ok := spec.Type.(*ast.Ident); ok && id.Name == "Dialect" {
				typed = true
			}
			for _, v := range spec.Values {
				if typed {
					if s, ok := resolve(v); ok {
						declared[s] = true
						continue
					}
				}
				call, ok := v.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					continue
				}
				if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "Dialect" {
					continue
				}
				if s, ok := resolve(call.Args[0]); ok {
					declared[s] = true
				}
			}
			return true
		})
	}
	if len(declared) == 0 {
		t.Fatal("found no Dialect constants in the source; the scan below proves nothing")
	}

	listed := map[string]bool{}
	for _, d := range knownDialects {
		listed[string(d)] = true
	}
	for name := range declared {
		if !listed[name] {
			t.Errorf("Dialect %q is declared but missing from knownDialects — validation will reject it", name)
		}
	}
	for name := range listed {
		if !declared[name] {
			t.Errorf("knownDialects lists %q, which is not a declared Dialect constant", name)
		}
	}
}

// DialectOpenRouter exists for request shaping alone — OpenRouter is a router,
// not a vendor, so every branch that keys off the tool conventions has to treat
// it exactly as DialectGeneric. The per-request cap fields are that branch.
func TestInjectCapFields_OpenRouterMatchesGeneric(t *testing.T) {
	shape := func(d Dialect) string {
		t.Helper()
		obj := map[string]json.RawMessage{"model": json.RawMessage(`"m"`)}
		injectCapFields(obj, d, 8)
		b, err := json.Marshal(obj)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b)
	}
	if got, want := shape(DialectOpenRouter), shape(DialectGeneric); got != want {
		t.Errorf("openrouter cap fields = %s, want the generic ones %s", got, want)
	}
	// Without this the comparison above passes for the wrong reason: if no
	// dialect changed the cap fields, every pair would match.
	if shape(DialectOpenRouter) == shape(DialectXAI) {
		t.Error("no dialect alters the cap fields, so the generic comparison proves nothing")
	}
}

func TestNormalizeToolName(t *testing.T) {
	cases := map[string]string{
		"web_search":            "web_search",
		"web_search_call":       "web_search",
		"web_search_calls":      "web_search",
		"web_search_preview":    "web_search",
		"web_search_20250305":   "web_search",
		"$web_search":           "web_search",
		"x_search":              "x_search",
		"x_search_calls":        "x_search",
		"code_interpreter":      "code_interpreter",
		"code_interpreter_call": "code_interpreter",
		"file_search_call":      "file_search",
		"computer":              "computer_use",
		"computer_use_preview":  "computer_use",
		"computer_call":         "computer_use",
		"custom":                "custom",
		"custom_tool":           "custom",
		"custom_tool_call":      "custom",
		"mcp":                   "mcp",
		"mcp_call":              "mcp",
		"mcp_calls":             "mcp",
		"local_shell":           "local_shell",
		"local_shell_call":      "local_shell",
		"apply_patch":           "apply_patch",
		"apply_patch_call":      "apply_patch",
		"code_execution":        "code_interpreter",
		"code_execution_calls":  "code_interpreter",
		"collections_search":    "file_search",
		"attachment_search":     "attachment_search",
	}
	for in, want := range cases {
		if got := NormalizeToolName(in); got != want {
			t.Errorf("NormalizeToolName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyToolEntry(t *testing.T) {
	cases := []struct {
		name      string
		entry     string
		wantName  string
		wantClass ToolClass
	}{
		{"vendor web_search", `{"type":"web_search"}`, "web_search", ToolClassVendorBillable},
		{"vendor x_search", `{"type":"x_search"}`, "x_search", ToolClassVendorBillable},
		{"vendor code_interpreter", `{"type":"code_interpreter"}`, "code_interpreter", ToolClassVendorBillable},
		{"vendor with config", `{"type":"web_search","search_context_size":"medium"}`, "web_search", ToolClassVendorBillable},
		{"moonshot builtin_function", `{"type":"builtin_function","function":{"name":"$web_search"}}`, "web_search", ToolClassVendorBillable},
		{"client function tool", `{"type":"function","function":{"name":"lookup"}}`, "lookup", ToolClassClient},
		{"node zs_ builtin", `{"type":"zs_web_search"}`, "zs_web_search", ToolClassClient},
		{"node zs_ image", `{"type":"zs_image_generation"}`, "zs_image_generation", ToolClassClient},
		{"anthropic versioned", `{"type":"web_search_20250305","name":"web_search"}`, "web_search", ToolClassVendorBillable},
		// Hosted / caller-executed types no upstream bills per call.
		{"mcp connector", `{"type":"mcp","server_label":"gh","server_url":"https://x"}`, "mcp", ToolClassNotBilled},
		{"freeform custom tool", `{"type":"custom","name":"code_exec"}`, "custom", ToolClassNotBilled},
		{"local shell", `{"type":"local_shell"}`, "local_shell", ToolClassNotBilled},
		{"apply patch", `{"type":"apply_patch"}`, "apply_patch", ToolClassNotBilled},
		{"computer use preview", `{"type":"computer_use_preview","display_width":1024}`, "computer_use", ToolClassNotBilled},
		// OpenAI's hosted shell runs in vendor-managed containers — a different
		// tool from local_shell, and still default-denied.
		{"hosted shell stays billable", `{"type":"shell"}`, "shell", ToolClassVendorBillable},
		{"container shell stays billable", `{"type":"shell","environment":{"type":"container_auto"}}`, "shell", ToolClassVendorBillable},
		{"local shell folds onto local_shell", `{"type":"shell","environment":{"type":"local"}}`, "local_shell", ToolClassNotBilled},
		{"anthropic bash", `{"type":"bash_20250124","name":"bash"}`, "bash", ToolClassNotBilled},
		{"anthropic text editor", `{"type":"text_editor_20250728"}`, "text_editor", ToolClassNotBilled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, class := ClassifyToolEntry(json.RawMessage(c.entry))
			if name != c.wantName || class != c.wantClass {
				t.Errorf("ClassifyToolEntry(%s) = (%q, %v), want (%q, %v)", c.entry, name, class, c.wantName, c.wantClass)
			}
		})
	}
}

func TestNotBilledToolNames(t *testing.T) {
	// Both predicates: hosted-but-free names are not-billed but NOT
	// client-executed, so the response-side counter still counts them.
	cases := []struct {
		name           string
		notBilled      bool
		clientExecuted bool
	}{
		{"function", true, true},
		{"tool", true, true},
		{"custom", true, true},
		{"local_shell", true, true},
		{"apply_patch", true, true},
		{"mcp", true, false},
		{"computer_use", true, true},
		{"bash", true, true},
		{"text_editor", true, true},
		{"str_replace_editor", true, true},
		{"web_search", false, false},
		{"x_search", false, false},
		{"file_search", false, false},
		{"code_interpreter", false, false},
		{"document_search", false, false},
		{"image_generation", false, false},
		{"shell", false, false},
	}
	for _, c := range cases {
		if got := IsNotBilledToolName(c.name); got != c.notBilled {
			t.Errorf("IsNotBilledToolName(%q) = %v, want %v", c.name, got, c.notBilled)
		}
		if got := IsClientExecutedToolName(c.name); got != c.clientExecuted {
			t.Errorf("IsClientExecutedToolName(%q) = %v, want %v", c.name, got, c.clientExecuted)
		}
	}
}

// pricedSet returns a rate func pricing a fixed set of canonical names above zero.
func pricedSet(names ...string) VendorRateFunc {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return func(n string) (uint64, bool) {
		if m[n] {
			return 6000, true
		}
		return 0, false
	}
}

// freeSet returns a rate func pricing a fixed set of canonical names at an
// explicit zero — priced, but costing nothing per call.
func freeSet(names ...string) VendorRateFunc {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return func(n string) (uint64, bool) {
		if m[n] {
			return 0, true
		}
		return 0, false
	}
}

// toolNames returns the canonical names of a body's surviving tools[] entries.
func toolNames(t *testing.T, obj map[string]json.RawMessage) map[string]bool {
	t.Helper()
	var arr []json.RawMessage
	if raw, ok := obj["tools"]; ok {
		if err := json.Unmarshal(raw, &arr); err != nil {
			t.Fatalf("tools not an array: %v", err)
		}
	}
	names := map[string]bool{}
	for _, e := range arr {
		n, _ := ClassifyToolEntry(e)
		names[n] = true
	}
	return names
}

func TestSanitizeToolPricing(t *testing.T) {
	t.Run("strip unpriced vendor, keep function + zs_ + priced", func(t *testing.T) {
		in := `{"model":"grok-4.5","tools":[` +
			`{"type":"web_search"},` +
			`{"type":"x_search"},` +
			`{"type":"function","function":{"name":"lookup"}},` +
			`{"type":"zs_web_search"}` +
			`]}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectXAI, CallCap: 12})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatal(err)
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(obj["tools"], &arr); err != nil {
			t.Fatal(err)
		}
		if len(arr) != 3 {
			t.Fatalf("want 3 tools kept (web_search, function, zs_), got %d: %s", len(arr), obj["tools"])
		}
		// x_search (unpriced vendor) must be gone; the others must remain.
		names := map[string]bool{}
		for _, e := range arr {
			n, _ := ClassifyToolEntry(e)
			names[n] = true
		}
		if names["x_search"] {
			t.Error("unpriced x_search should have been stripped")
		}
		for _, want := range []string{"web_search", "lookup", "zs_web_search"} {
			if !names[want] {
				t.Errorf("expected %q to survive", want)
			}
		}
		// A priced vendor tool survived → cap injected (Responses).
		if string(obj["max_tool_calls"]) != "12" {
			t.Errorf("max_tool_calls = %s, want 12", obj["max_tool_calls"])
		}
		if string(obj["max_turns"]) != "12" {
			t.Errorf("max_turns = %s, want 12 (xai)", obj["max_turns"])
		}
	})

	t.Run("all vendor unpriced empties tools and drops tool_choice", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}],"tool_choice":"auto"}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["tools"]; ok {
			t.Error("tools should have been dropped")
		}
		if _, ok := obj["tool_choice"]; ok {
			t.Error("tool_choice should have been dropped")
		}
		if _, ok := obj["max_tool_calls"]; ok {
			t.Error("no priced vendor tool survived; cap should not be injected")
		}
	})

	t.Run("chat search_parameters neutralized when web_search unpriced", func(t *testing.T) {
		in := `{"model":"grok-4.5","search_parameters":{"mode":"auto"}}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectXAI, IsChat: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["search_parameters"]; ok {
			t.Error("unpriced search_parameters should be removed on chat")
		}
	})

	t.Run("strict chat strips even a priced vendor tool", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"},{"type":"function","function":{"name":"f"}}]}`
		// web_search IS priced, but strict chat (AllowChatServerTools=false) strips it.
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectXAI, IsChat: true, CallCap: 12})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		var arr []json.RawMessage
		_ = json.Unmarshal(obj["tools"], &arr)
		if len(arr) != 1 {
			t.Fatalf("strict chat should strip the priced web_search, got %d tools", len(arr))
		}
		if n, _ := ClassifyToolEntry(arr[0]); n != "f" {
			t.Errorf("only the client function tool should survive, got %q", n)
		}
		if _, ok := obj["max_tool_calls"]; ok {
			t.Error("no vendor tool survived; cap must not be injected")
		}
	})

	t.Run("allow-chat keeps a priced vendor tool on chat", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}]}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectXAI, IsChat: true, AllowChatServerTools: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		var arr []json.RawMessage
		_ = json.Unmarshal(obj["tools"], &arr)
		if len(arr) != 1 {
			t.Errorf("allow-chat should keep the priced web_search, got %d", len(arr))
		}
	})

	t.Run("strict chat strips search_parameters even when web_search priced", func(t *testing.T) {
		in := `{"model":"m","search_parameters":{"mode":"auto"}}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectXAI, IsChat: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["search_parameters"]; ok {
			t.Error("strict chat should strip search_parameters even when web_search is priced")
		}
	})

	t.Run("strict chat strips web_search_options (OpenAI chat search config)", func(t *testing.T) {
		in := `{"model":"gpt-4o-search-preview","web_search_options":{"search_context_size":"high"}}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectOpenAI, IsChat: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["web_search_options"]; ok {
			t.Error("strict chat should strip web_search_options even when web_search is priced")
		}
	})

	t.Run("allow-chat keeps web_search_options when web_search priced", func(t *testing.T) {
		in := `{"model":"gpt-4o-search-preview","web_search_options":{"search_context_size":"low"}}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectOpenAI, IsChat: true, AllowChatServerTools: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["web_search_options"]; !ok {
			t.Error("allow-chat with web_search priced should keep web_search_options")
		}
	})

	t.Run("web_search_options untouched on responses", func(t *testing.T) {
		in := `{"model":"m","web_search_options":{"search_context_size":"low"}}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, IsChat: false})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != in {
			t.Errorf("responses must not touch web_search_options, got %s", out)
		}
	})

	t.Run("responses keeps a priced vendor tool regardless of chat mode", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}]}`
		// IsChat=false → strict-chat flag is irrelevant; the tool survives and is capped.
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectXAI, IsChat: false, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		var arr []json.RawMessage
		_ = json.Unmarshal(obj["tools"], &arr)
		if len(arr) != 1 {
			t.Errorf("responses should keep the priced tool, got %d", len(arr))
		}
		if string(obj["max_tool_calls"]) != "8" {
			t.Errorf("responses should inject the cap, got %s", obj["max_tool_calls"])
		}
	})

	t.Run("no cap injection on chat (even when the tool survives via allow)", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}]}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectOpenAI, IsChat: true, AllowChatServerTools: true, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["max_tool_calls"]; ok {
			t.Error("cap must not be injected on chat")
		}
	})

	t.Run("caller tighter cap preserved", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}],"max_tool_calls":3}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 12})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if string(obj["max_tool_calls"]) != "3" {
			t.Errorf("caller's tighter max_tool_calls=3 should be preserved, got %s", obj["max_tool_calls"])
		}
	})

	t.Run("caller explicit 0 cap preserved (forbids tool calls)", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}],"max_tool_calls":0}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 12})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if string(obj["max_tool_calls"]) != "0" {
			t.Errorf("caller max_tool_calls:0 must not be raised, got %s", obj["max_tool_calls"])
		}
	})

	t.Run("dangling tool_choice for stripped vendor tool dropped", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"},{"type":"function","function":{"name":"f"}}],"tool_choice":{"type":"web_search"}}`
		// web_search unpriced ⇒ stripped; its tool_choice reference must go too.
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["tool_choice"]; ok {
			t.Error("tool_choice referencing a stripped vendor tool should be dropped")
		}
		var arr []json.RawMessage
		_ = json.Unmarshal(obj["tools"], &arr)
		if len(arr) != 1 {
			t.Errorf("the client function tool must survive, got %d tools", len(arr))
		}
	})

	t.Run("tool_choice for a kept priced tool preserved", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}],"tool_choice":{"type":"web_search"}}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("web_search"), SanitizeOpts{Dialect: DialectOpenAI})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["tool_choice"]; !ok {
			t.Error("tool_choice for a kept priced tool must be preserved")
		}
	})

	t.Run("not-billed tools pass through untouched on responses", func(t *testing.T) {
		in := `{"model":"m","tools":[` +
			`{"type":"custom","name":"exec"},` +
			`{"type":"local_shell"},` +
			`{"type":"apply_patch"},` +
			`{"type":"computer_use_preview"},` +
			`{"type":"function","function":{"name":"f"}}` +
			`]}`
		out, stripped, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != in {
			t.Errorf("not-billed tools must pass through byte-identical, got %s", out)
		}
		if len(stripped) != 0 {
			t.Errorf("nothing should be reported stripped, got %v", stripped)
		}
	})

	t.Run("not-billed tools pass through untouched on strict chat", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"mcp"},{"type":"custom","name":"exec"}]}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, IsChat: true, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != in {
			t.Errorf("strict chat must not strip not-billed tools, got %s", out)
		}
	})

	t.Run("billable vendor still stripped alongside a kept not-billed tool", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"x_search"},{"type":"web_search"},{"type":"mcp"}]}`
		out, stripped, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectXAI, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		names := toolNames(t, obj)
		if !names["mcp"] {
			t.Error("mcp is not billed per call and must survive")
		}
		for _, gone := range []string{"web_search", "x_search"} {
			if names[gone] {
				t.Errorf("unpriced billable %q must still be stripped by default", gone)
			}
		}
		if len(stripped) != 2 || stripped[0].Name != "web_search" || stripped[1].Name != "x_search" {
			t.Errorf("stripped = %v, want [web_search x_search]", stripped)
		}
		for _, st := range stripped {
			if st.Reason != StripUnpriced {
				t.Errorf("%s reason = %v, want StripUnpriced", st.Name, st.Reason)
			}
		}
		// mcp is vendor-HOSTED, so it still counts toward the call cap: its
		// results inflate the context even though it costs nothing per call.
		if string(obj["max_tool_calls"]) != "8" {
			t.Errorf("max_tool_calls = %s, want 8 (a surviving hosted tool caps)", obj["max_tool_calls"])
		}
	})

	t.Run("explicit named rate promotes a not-billed tool", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"mcp"}]}`
		out, _, err := SanitizeToolPricing([]byte(in), pricedSet("mcp"), SanitizeOpts{Dialect: DialectXAI, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if !toolNames(t, obj)["mcp"] {
			t.Fatal("an explicitly priced mcp must survive")
		}
		if string(obj["max_tool_calls"]) != "8" {
			t.Errorf("a promoted tool is billable, so the cap applies: got %s", obj["max_tool_calls"])
		}
	})

	t.Run("promoted not-billed tool stripped on strict chat drops its tool_choice", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"mcp"},{"type":"function","function":{"name":"f"}}],"tool_choice":{"type":"mcp"}}`
		out, stripped, err := SanitizeToolPricing([]byte(in), pricedSet("mcp"), SanitizeOpts{Dialect: DialectOpenAI, IsChat: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if toolNames(t, obj)["mcp"] {
			t.Error("a positively-priced mcp is uncappable on chat and must be stripped")
		}
		if _, ok := obj["tool_choice"]; ok {
			t.Error("tool_choice referencing the stripped tool must be dropped")
		}
		if len(stripped) != 1 || stripped[0].Name != "mcp" || stripped[0].Reason != StripStrictChat {
			t.Errorf("stripped = %v, want [{mcp StripStrictChat}]", stripped)
		}
	})

	t.Run("zero rate survives strict chat", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"web_search"}]}`
		out, stripped, err := SanitizeToolPricing([]byte(in), freeSet("web_search"), SanitizeOpts{Dialect: DialectXAI, IsChat: true, CallCap: 8})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if !toolNames(t, obj)["web_search"] {
			t.Error("a tool priced at 0 has no per-call overage, so strict chat must keep it")
		}
		if len(stripped) != 0 {
			t.Errorf("nothing should be reported stripped, got %v", stripped)
		}
	})

	t.Run("zero rate keeps the chat search fields", func(t *testing.T) {
		in := `{"model":"m","search_parameters":{"mode":"auto"},"web_search_options":{"search_context_size":"low"}}`
		out, _, err := SanitizeToolPricing([]byte(in), freeSet("web_search"), SanitizeOpts{Dialect: DialectXAI, IsChat: true})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		for _, f := range []string{"search_parameters", "web_search_options"} {
			if _, ok := obj[f]; !ok {
				t.Errorf("%s must survive when web_search is priced at 0", f)
			}
		}
	})

	t.Run("stripped names include neutralized chat fields, sorted", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"x_search"}],"search_parameters":{"mode":"auto"}}`
		_, stripped, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectXAI, IsChat: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(stripped) != 2 ||
			stripped[0].Name != "search_parameters" || stripped[0].Reason != StripChatSearchField ||
			stripped[1].Name != "x_search" || stripped[1].Reason != StripUnpriced {
			t.Errorf("stripped = %v, want [{search_parameters field} {x_search unpriced}]", stripped)
		}
	})

	t.Run("hosted-free mcp counts toward the cap, client-executed tools do not", func(t *testing.T) {
		// A hosted call re-prefills results into context, so it must stay capped
		// even at no per-call fee. A caller-executed tool costs the operator
		// nothing and the upstream cap knob doesn't govern it.
		hosted := `{"model":"m","tools":[{"type":"mcp"}]}`
		out, _, err := SanitizeToolPricing([]byte(hosted), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 16})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if string(obj["max_tool_calls"]) != "16" {
			t.Errorf("surviving mcp must cap: max_tool_calls = %s, want 16", obj["max_tool_calls"])
		}

		client := `{"model":"m","tools":[{"type":"local_shell"},{"type":"apply_patch"}]}`
		out, _, err = SanitizeToolPricing([]byte(client), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 16})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != client {
			t.Errorf("caller-executed tools must not cap or mutate, got %s", out)
		}
	})

	t.Run("shell passes through only in local mode", func(t *testing.T) {
		// environment.type "local" runs on the caller's machine and is the
		// documented successor to the deprecated local_shell; the container modes
		// bill per session and stay default-denied.
		local := `{"model":"m","tools":[{"type":"shell","environment":{"type":"local"}}]}`
		out, stripped, err := SanitizeToolPricing([]byte(local), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI, CallCap: 16})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != local || len(stripped) != 0 {
			t.Errorf("a local shell must pass through untouched, got %s stripped=%v", out, stripped)
		}
		for _, hosted := range []string{
			`{"model":"m","tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`,
			`{"model":"m","tools":[{"type":"shell"}]}`,
		} {
			_, stripped, err := SanitizeToolPricing([]byte(hosted), pricedSet(), SanitizeOpts{Dialect: DialectOpenAI})
			if err != nil {
				t.Fatal(err)
			}
			if len(stripped) != 1 || stripped[0].Name != "shell" {
				t.Errorf("hosted shell must stay default-denied, stripped = %v for %s", stripped, hosted)
			}
		}
	})

	t.Run("anthropic caller-executed tools pass through", func(t *testing.T) {
		in := `{"model":"m","tools":[{"type":"bash_20250124"},{"type":"text_editor_20250728"},{"type":"str_replace_editor"}]}`
		out, stripped, err := SanitizeToolPricing([]byte(in), pricedSet(), SanitizeOpts{Dialect: DialectGeneric, CallCap: 16})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != in || len(stripped) != 0 {
			t.Errorf("anthropic caller-executed tools must pass through, got %s stripped=%v", out, stripped)
		}
	})

	t.Run("unnameable entry is not rescued by a catch-all", func(t *testing.T) {
		// {"type":"builtin_function"} with no function normalizes to "", which can
		// never be metered — so it must not be kept (and capped) by a catch-all.
		in := `{"model":"m","tools":[{"type":"builtin_function"}]}`
		catchAll := func(string) (uint64, bool) { return 5000, true }
		out, stripped, err := SanitizeToolPricing([]byte(in), catchAll, SanitizeOpts{Dialect: DialectMoonshot, CallCap: 16})
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		_ = json.Unmarshal(out, &obj)
		if _, ok := obj["tools"]; ok {
			t.Errorf("an unnameable vendor entry must be stripped, got %s", out)
		}
		if len(stripped) != 1 || stripped[0].Name != "" {
			t.Errorf("stripped = %v, want one empty-named entry", stripped)
		}
	})

	t.Run("non-object body untouched", func(t *testing.T) {
		in := []byte("not json")
		out, _, err := SanitizeToolPricing(in, pricedSet(), SanitizeOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(in) {
			t.Errorf("non-JSON body mutated: %s", out)
		}
	})
}

func TestCountServerSideToolCalls_XAIStructured(t *testing.T) {
	// Mirrors node/xai.json's usage block: 8 web_search + 9 x_search = 17.
	usage := `{
		"num_server_side_tools_used": 17,
		"server_side_tool_usage_details": {
			"code_interpreter_calls": 0,
			"document_search_calls": 0,
			"file_search_calls": 0,
			"image_generation_calls": 0,
			"mcp_calls": 0,
			"web_search_calls": 8,
			"x_search_calls": 9
		}
	}`
	got := CountServerSideToolCalls(DialectXAI, json.RawMessage(usage), nil)
	if got["web_search"] != 8 || got["x_search"] != 9 {
		t.Fatalf("got %v, want web_search:8 x_search:9", got)
	}
	if _, ok := got["mcp"]; ok {
		t.Error("zero-count tools should be omitted")
	}
	total := 0
	for _, v := range got {
		total += v
	}
	if total != 17 {
		t.Errorf("total = %d, want 17", total)
	}
}

func TestCountServerSideToolCalls_OpenAIOutputItems(t *testing.T) {
	output := []json.RawMessage{
		json.RawMessage(`{"type":"reasoning"}`),
		json.RawMessage(`{"type":"web_search_call","status":"completed"}`),
		json.RawMessage(`{"type":"web_search_call","status":"completed"}`),
		json.RawMessage(`{"type":"web_search_call","status":"completed"}`),
		json.RawMessage(`{"type":"function_call","name":"client_fn"}`),
		json.RawMessage(`{"type":"file_search_call"}`),
		json.RawMessage(`{"type":"message"}`),
		// Hosted but free: really executed upstream, so counting is truthful.
		json.RawMessage(`{"type":"mcp_call"}`),
		// Caller-executed: the harness ran these, not the vendor.
		json.RawMessage(`{"type":"computer_call"}`),
		json.RawMessage(`{"type":"custom_tool_call"}`),
		json.RawMessage(`{"type":"local_shell_call"}`),
		json.RawMessage(`{"type":"apply_patch_call"}`),
	}
	got := CountServerSideToolCalls(DialectOpenAI, nil, output)
	if got["web_search"] != 3 {
		t.Errorf("web_search = %d, want 3", got["web_search"])
	}
	if got["file_search"] != 1 {
		t.Errorf("file_search = %d, want 1", got["file_search"])
	}
	if got["mcp"] != 1 {
		t.Errorf("hosted-but-free mcp calls should still be counted, got %d", got["mcp"])
	}
	for _, name := range []string{"function", "tool", "custom", "local_shell", "apply_patch", "computer_use"} {
		if _, ok := got[name]; ok {
			t.Errorf("caller-executed %q must not be counted as a vendor tool", name)
		}
	}
}

func TestCountServerSideToolCalls_AnthropicServerToolUse(t *testing.T) {
	usage := `{"input_tokens":6039,"output_tokens":931,"server_tool_use":{"web_search_requests":3}}`
	got := CountServerSideToolCalls(DialectGeneric, json.RawMessage(usage), nil)
	if got["web_search"] != 3 {
		t.Errorf("web_search = %d, want 3", got["web_search"])
	}
}
