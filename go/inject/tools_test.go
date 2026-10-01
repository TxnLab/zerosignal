/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"testing"
)

func TestDropEmptyTools(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantTools   bool // expect a "tools" key in the output
		wantChoice  bool // expect a "tool_choice" key in the output
		wantChanged bool // expect the body to differ from input
	}{
		{
			name:        "empty tools dropped",
			in:          `{"model":"m","tools":[]}`,
			wantTools:   false,
			wantChanged: true,
		},
		{
			name:        "empty tools and tool_choice both dropped",
			in:          `{"model":"m","tools":[],"tool_choice":"auto"}`,
			wantTools:   false,
			wantChoice:  false,
			wantChanged: true,
		},
		{
			name:        "non-empty tools preserved",
			in:          `{"model":"m","tools":[{"type":"function","function":{"name":"x"}}],"tool_choice":"auto"}`,
			wantTools:   true,
			wantChoice:  true,
			wantChanged: false,
		},
		{
			name:        "no tools field untouched",
			in:          `{"model":"m"}`,
			wantTools:   false,
			wantChanged: false,
		},
		{
			name:        "tools not an array left alone",
			in:          `{"model":"m","tools":{}}`,
			wantTools:   true,
			wantChanged: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := DropEmptyTools([]byte(c.in))
			if err != nil {
				t.Fatalf("DropEmptyTools: %v", err)
			}
			changed := string(out) != c.in
			if changed != c.wantChanged {
				t.Errorf("changed = %v, want %v (out=%s)", changed, c.wantChanged, out)
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(out, &obj); err != nil {
				t.Fatalf("output not JSON: %v", err)
			}
			if _, ok := obj["tools"]; ok != c.wantTools {
				t.Errorf("tools present = %v, want %v", ok, c.wantTools)
			}
			if _, ok := obj["tool_choice"]; ok != c.wantChoice {
				t.Errorf("tool_choice present = %v, want %v", ok, c.wantChoice)
			}
			// The model field must always survive.
			if _, ok := obj["model"]; !ok {
				t.Errorf("model field was dropped: %s", out)
			}
		})
	}
}

func TestDropEmptyTools_NonJSON(t *testing.T) {
	in := []byte("not json")
	out, err := DropEmptyTools(in)
	if err != nil {
		t.Fatalf("DropEmptyTools: %v", err)
	}
	if string(out) != string(in) {
		t.Errorf("non-JSON body mutated: %s", out)
	}
}

func TestBodyDrivesServerSideToolGrowth(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		// Nothing to grow.
		{"empty body", ``, false},
		{"malformed", `{not json`, false},
		{"no tools field", `{"model":"m","messages":[]}`, false},
		{"empty tools array", `{"model":"m","tools":[]}`, false},

		// Caller-executed: the agent runs the tool and re-issues, and that
		// request is measured on its own. This is the client-side-MCP case.
		{"function tool", `{"tools":[{"type":"function","function":{"name":"x"}}]}`, false},
		{"bare function object", `{"tools":[{"function":{"name":"x"}}]}`, false},
		{"many function tools", `{"tools":[{"type":"function","function":{"name":"a"}},{"type":"function","function":{"name":"b"}},{"type":"function","function":{"name":"c"}}]}`, false},
		{"custom freeform", `{"tools":[{"type":"custom","name":"exec"}]}`, false},
		{"local_shell", `{"tools":[{"type":"local_shell"}]}`, false},
		{"apply_patch", `{"tools":[{"type":"apply_patch"}]}`, false},
		{"computer_use", `{"tools":[{"type":"computer_use"}]}`, false},
		{"anthropic bash dated", `{"tools":[{"type":"bash_20250124"}]}`, false},
		{"anthropic text_editor dated", `{"tools":[{"type":"text_editor_20250124"}]}`, false},
		{"shell local environment", `{"tools":[{"type":"shell","environment":{"type":"local"}}]}`, false},

		// Node zs_ built-ins: the node runs the loop in-process, so the
		// conversation grows inside this one reserve. They classify
		// ToolClassClient, so the signal has to come from the name.
		{"zs_web_search", `{"tools":[{"type":"zs_web_search"}]}`, true},
		{"zs_image_generation", `{"tools":[{"type":"zs_image_generation"}]}`, true},

		// Vendor-hosted: the upstream re-prefills each result into the context.
		{"web_search", `{"tools":[{"type":"web_search"}]}`, true},
		{"code_interpreter", `{"tools":[{"type":"code_interpreter"}]}`, true},
		{"xai code_execution alias", `{"tools":[{"type":"code_execution"}]}`, true},
		{"moonshot builtin_function", `{"tools":[{"type":"builtin_function","function":{"name":"$web_search"}}]}`, true},
		{"shell hosted container", `{"tools":[{"type":"shell","environment":{"type":"container_auto"}}]}`, true},
		// mcp carries no per-call fee but still inflates context — pricing and
		// context growth are separate axes.
		{"mcp connector", `{"tools":[{"type":"mcp","server_label":"gh","server_url":"https://x"}]}`, true},

		// One growth-driving entry among caller-executed ones is enough.
		{"mixed function + zs_", `{"tools":[{"type":"function","function":{"name":"x"}},{"type":"zs_web_search"}]}`, true},
		{"mixed function + mcp", `{"tools":[{"type":"function","function":{"name":"x"}},{"type":"mcp"}]}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := BodyDrivesServerSideToolGrowth([]byte(c.body)); got != c.want {
				t.Errorf("BodyDrivesServerSideToolGrowth(%s) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}
