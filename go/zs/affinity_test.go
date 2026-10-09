/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestAffinity_RecordThenLookup(t *testing.T) {
	c := NewIDAffinity(10, time.Minute, nil)
	// Pin to the exact (operator 1, node 11): Lookup must return both so a
	// continuation routes back to the serving node, not a sibling.
	c.Record(1, 11, []string{"id1", "id2"})
	if op, node, ok := c.Lookup("id1"); !ok || op != 1 || node != 11 {
		t.Errorf("Lookup(id1) = (%d, %d, %v)", op, node, ok)
	}
	if op, node, ok := c.Lookup("id2"); !ok || op != 1 || node != 11 {
		t.Errorf("Lookup(id2) = (%d, %d, %v)", op, node, ok)
	}
	if _, _, ok := c.Lookup("id3"); ok {
		t.Error("Lookup(id3) should miss")
	}
}

func TestAffinity_TTLExpires(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	c := NewIDAffinity(10, 5*time.Second, clk.Now)
	c.Record(1, 11, []string{"id1"})
	clk.Advance(6 * time.Second)
	if _, _, ok := c.Lookup("id1"); ok {
		t.Error("expired entry still returned")
	}
	// And it's been evicted.
	if got := c.Size(); got != 0 {
		t.Errorf("size = %d after expired lookup, want 0", got)
	}
}

func TestAffinity_LRUEviction(t *testing.T) {
	c := NewIDAffinity(2, time.Minute, nil)
	c.Record(1, 11, []string{"id1"})
	c.Record(1, 12, []string{"id2"})
	// Touch id1 so it becomes most-recent.
	if _, _, ok := c.Lookup("id1"); !ok {
		t.Fatal("id1 disappeared unexpectedly")
	}
	c.Record(2, 22, []string{"id3"}) // should evict id2 (least recent)
	if _, _, ok := c.Lookup("id2"); ok {
		t.Error("id2 should have been evicted by LRU")
	}
	if op, node, ok := c.Lookup("id1"); !ok || op != 1 || node != 11 {
		t.Errorf("id1 lost: (%d,%d,%v)", op, node, ok)
	}
	if op, node, ok := c.Lookup("id3"); !ok || op != 2 || node != 22 {
		t.Errorf("id3 lost: (%d,%d,%v)", op, node, ok)
	}
}

func TestAffinity_WriteWinsOnReRecord(t *testing.T) {
	c := NewIDAffinity(4, time.Minute, nil)
	c.Record(1, 11, []string{"id1"})
	c.Record(2, 22, []string{"id1"})
	if op, node, _ := c.Lookup("id1"); op != 2 || node != 22 {
		t.Errorf("Lookup = (%d,%d), want (2,22)", op, node)
	}
}

func TestAffinity_IgnoresEmptyIDs(t *testing.T) {
	c := NewIDAffinity(4, time.Minute, nil)
	c.Record(1, 11, []string{"", ""})
	if got := c.Size(); got != 0 {
		t.Errorf("size = %d, want 0", got)
	}
	if _, _, ok := c.Lookup(""); ok {
		t.Error("empty lookup shouldn't match")
	}
}

func TestAffinity_ValidPolicy(t *testing.T) {
	for _, p := range []AffinityPolicy{AffinityPrefer, AffinityStrict, AffinityNone} {
		if !ValidAffinityPolicy(p) {
			t.Errorf("%q rejected", p)
		}
	}
	if ValidAffinityPolicy("sometimes") {
		t.Error("unknown policy accepted")
	}
}

func TestExtractModel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{"model":"gpt-4o-mini","messages":[]}`, "gpt-4o-mini"},
		{`{}`, ""},
		{`not json`, ""},
	}
	for _, c := range cases {
		if got := ExtractModel([]byte(c.in)); got != c.want {
			t.Errorf("ExtractModel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractInputToolCallIDs(t *testing.T) {
	body := `{
		"messages": [
			{"role":"user","content":"hi"},
			{"role":"tool","tool_call_id":"call-1","content":"a"},
			{"role":"tool","tool_call_id":"call-2","content":"b"},
			{"role":"tool","content":"empty id"}
		]
	}`
	got := ExtractInputToolCallIDs([]byte(body))
	want := []string{"call-1", "call-2"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractRequestedBuiltinTools(t *testing.T) {
	cases := map[string]struct {
		body string
		want []string
	}{
		"none": {
			body: `{"model":"x","messages":[]}`,
			want: nil,
		},
		"only user function": {
			body: `{"tools":[{"type":"function","function":{"name":"f"}}]}`,
			want: nil,
		},
		"single zs tool": {
			body: `{"tools":[{"type":"zs_web_search"}]}`,
			want: []string{"zs_web_search"},
		},
		"mixed": {
			body: `{"tools":[{"type":"function","function":{"name":"f"}},{"type":"zs_web_read"},{"type":"zs_web_search"}]}`,
			want: []string{"zs_web_read", "zs_web_search"},
		},
		"malformed body": {
			body: `not json`,
			want: nil,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := ExtractRequestedBuiltinTools([]byte(c.body))
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (%v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestExtractPreviousResponseID(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"present": {
			body: `{"model":"gpt-4o","previous_response_id":"resp_abc123","input":[]}`,
			want: "resp_abc123",
		},
		"absent": {
			body: `{"model":"gpt-4o","input":[]}`,
			want: "",
		},
		"empty string": {
			body: `{"previous_response_id":""}`,
			want: "",
		},
		"malformed": {
			body: `not json`,
			want: "",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ExtractPreviousResponseID([]byte(c.body)); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractResponseID(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"response object": {
			body: `{"id":"resp_abc","object":"response","model":"gpt-4o"}`,
			want: "resp_abc",
		},
		"object omitted treated as response": {
			// Some upstream variants omit object on the top-level body.
			// Stay tolerant: an id with no object still pinned.
			body: `{"id":"resp_abc","model":"gpt-4o"}`,
			want: "resp_abc",
		},
		"error envelope ignored": {
			// Ensure we don't accidentally record an error's id-like field
			// (e.g. a request_id) as a session pin.
			body: `{"id":"req_abc","object":"error","error":{"message":"..."}}`,
			want: "",
		},
		"no id": {
			body: `{"object":"response"}`,
			want: "",
		},
		"malformed": {
			body: `not json`,
			want: "",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ExtractResponseID([]byte(c.body)); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractResponseIDFromFrame(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"response.created": {
			body: `{"type":"response.created","response":{"id":"resp_xyz","object":"response"}}`,
			want: "resp_xyz",
		},
		"response.completed": {
			body: `{"type":"response.completed","response":{"id":"resp_xyz","usage":{"input_tokens":10}}}`,
			want: "resp_xyz",
		},
		"delta event ignored": {
			body: `{"type":"response.output_text.delta","delta":"hello"}`,
			want: "",
		},
		"unknown type": {
			body: `{"type":"response.in_progress","response":{"id":"resp_xyz"}}`,
			want: "",
		},
		"malformed": {
			body: `not json`,
			want: "",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ExtractResponseIDFromFrame([]byte(c.body)); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractResponseToolCallIDs(t *testing.T) {
	body := `{
		"choices": [
			{"message":{"tool_calls":[{"id":"a"},{"id":"b"}]}},
			{"message":{"tool_calls":[{"id":"c"}]}}
		]
	}`
	got := ExtractResponseToolCallIDs([]byte(body))
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
