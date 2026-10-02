/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// clampModel deliberately isn't "gpt-test": that id is bound to a fake
// estimator returning a fixed 8/128 regardless of the body, which would make a
// caller-supplied max_tokens invisible to these tests. Any other id falls
// through to the real SafeEstimator, which reads the field off the body — the
// path the clamp has to intercept.
const clampModel = "big-out"

// clampNodeBody returns the max-output field the node decrypted, and whether it
// was present at all.
func clampNodeBody(t *testing.T, sealed []byte, field string) (uint64, bool) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(sealed, &obj); err != nil {
		t.Fatalf("node body is not JSON: %s", sealed)
	}
	raw, ok := obj[field]
	if !ok {
		return 0, false
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("%s is not a number: %s", field, raw)
	}
	return n, true
}

// TestDispatchHayai_ClampsCallerMaxOutputToPoolCeiling reproduces the reported
// failure: a third-party chat app whose own model card says 65536 against a pool
// whose only operator advertises 32768. Before the clamp this was a hard 400
// context_length_exceeded ("your conversation is too long") on a request with
// 250k of context headroom — the output ceiling was being treated as an
// eligibility predicate rather than the upper bound it is.
//
// Three things must hold together: the request routes, the ESCROW is sized at
// the clamped number, and the body the node decrypts carries the clamped number
// too. Getting the last one wrong is the quiet failure — the ticket would be
// sized for 32768 while the upstream is still asked for 65536.
func TestDispatchHayai_ClampsCallerMaxOutputToPoolCeiling(t *testing.T) {
	var reserves []ticket.ReserveRequest
	var sealed []byte
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
		onRequest:      func(_ *http.Request, b []byte) { sealed = b },
	})
	node.operator.Models = []string{clampModel}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":65536,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200 (the request should route, not 400)",
			w.Result().StatusCode, w.Body.String())
	}
	if len(reserves) != 1 {
		t.Fatalf("captured %d reserves, want 1", len(reserves))
	}
	if got := reserves[0].MaxOutputCount; got != 32_768 {
		t.Errorf("reserve max_output_count = %d, want 32768 (the pool ceiling)", got)
	}
	if got, ok := clampNodeBody(t, sealed, "max_tokens"); !ok {
		t.Errorf("node body lost max_tokens entirely: %s", sealed)
	} else if got != 32_768 {
		t.Errorf("node saw max_tokens = %d, want 32768 — the sealed body must carry the "+
			"clamped value or the upstream is asked for more than the ticket covers", got)
	}
}

// An operator that declares no max_output_tokens is unbounded (the same rollout
// gate Fits applies), so it can honor whatever the caller asked for. Clamping
// there would take capability away for nothing — the caller's 65536 must reach
// both the escrow and the node untouched.
//
// The pool deliberately holds a second, capped operator: with only the unbounded
// one, "skip the clamp" and "clamp to zero" are indistinguishable and the test
// would pass on a build that ignored the undeclared cap entirely. Here the
// capped operator would supply a 32768 ceiling if it were allowed to, and the
// unbounded one — the only one that survives Fits at 65536 — must still be
// served the caller's own number.
func TestDispatchHayai_UndeclaredCapLeavesCallerMaxOutputAlone(t *testing.T) {
	var reserves []ticket.ReserveRequest
	var sealed []byte
	unbounded := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
		onRequest:      func(_ *http.Request, b []byte) { sealed = b },
	})
	capped := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
	})
	for _, n := range []*fakeNode{unbounded, capped} {
		n.operator.Models = []string{clampModel}
	}
	// ContextWindow only — no declared output cap.
	unbounded.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144},
	}
	capped.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, unbounded, capped))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":65536,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
	}
	if len(reserves) != 1 {
		t.Fatalf("the unbounded operator captured %d reserves, want 1", len(reserves))
	}
	if got := reserves[0].MaxOutputCount; got != 65_536 {
		t.Errorf("reserve max_output_count = %d, want 65536 (unbounded operator, no clamp)", got)
	}
	if got, _ := clampNodeBody(t, sealed, "max_tokens"); got != 65_536 {
		t.Errorf("node saw max_tokens = %d, want 65536", got)
	}
	if capped.callCountValue() != 0 {
		t.Errorf("the 32768 operator can't serve 65536 and should have been filtered, got %d calls",
			capped.callCountValue())
	}
}

// The context window stays a hard filter. Lowering the output ceiling can't
// rescue a request whose input genuinely doesn't fit, and the caller must still
// get context_length_exceeded — now accurate, since a max-output-only miss can
// no longer produce that code.
func TestDispatchHayai_ClampDoesNotRescueAWindowMiss(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{}`),
	})
	node.operator.Models = []string{clampModel}
	// Declares a cap worth clamping to, but a window far too small to hold it.
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 1000, MaxOutputTokens: 32_768},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":65536,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"context_length_exceeded"`) {
		t.Errorf("body missing context_length_exceeded: %s", body)
	}
	// The blamed limit is the window, not the output cap — the clamp already
	// resolved the latter.
	if !strings.Contains(body, "context_window=1000") {
		t.Errorf("body should blame the context window, got: %s", body)
	}
	// The header reports the CLAMPED ceiling: that is the number the request was
	// actually filtered on, and echoing the caller's original 65536 would send
	// them chasing a limit the proxy had already dealt with.
	if !strings.Contains(body, "max_output_tokens=32768") {
		t.Errorf("header should report the clamped ceiling, got: %s", body)
	}
	if node.callCountValue() != 0 {
		t.Errorf("no reserve should have fired, got %d calls", node.callCountValue())
	}
}

// A heterogeneous pool clamps to the MOST generous operator, not the least. The
// caller asked for a big budget, so it should route to whoever can give the most
// of it; the smaller operator drops out through the pre-existing Fits check
// exactly as it did before.
func TestDispatchHayai_ClampsToTheMostGenerousOperator(t *testing.T) {
	var generousReserves []ticket.ReserveRequest
	generous := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		onReserve:      func(req ticket.ReserveRequest) { generousReserves = append(generousReserves, req) },
	})
	stingy := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
	})
	for _, n := range []*fakeNode{generous, stingy} {
		n.operator.Models = []string{clampModel}
	}
	generous.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
	}
	stingy.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 8192},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, generous, stingy))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":65536,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
	}
	if len(generousReserves) != 1 {
		t.Fatalf("the 32768 operator captured %d reserves, want 1", len(generousReserves))
	}
	if got := generousReserves[0].MaxOutputCount; got != 32_768 {
		t.Errorf("reserve max_output_count = %d, want 32768", got)
	}
	if stingy.callCountValue() != 0 {
		t.Errorf("the 8192 operator should have been filtered out, got %d calls", stingy.callCountValue())
	}
}

// A caller already inside the ceiling is untouched — no rewrite, no inflation to
// the pool ceiling. The clamp only ever lowers.
func TestDispatchHayai_CallerUnderCeilingIsUnchanged(t *testing.T) {
	var reserves []ticket.ReserveRequest
	var sealed []byte
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
		onRequest:      func(_ *http.Request, b []byte) { sealed = b },
	})
	node.operator.Models = []string{clampModel}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":512,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
	}
	if len(reserves) != 1 {
		t.Fatalf("captured %d reserves, want 1", len(reserves))
	}
	if got := reserves[0].MaxOutputCount; got != 512 {
		t.Errorf("reserve max_output_count = %d, want 512 (unchanged)", got)
	}
	if got, _ := clampNodeBody(t, sealed, "max_tokens"); got != 512 {
		t.Errorf("node saw max_tokens = %d, want 512", got)
	}
}

// stubExcluder is a NodeExcluder over a fixed set. The production one hangs off
// ChainOperatorSource, which these tests don't build.
type stubExcluder struct{ excluded map[hayai.NodeRef]bool }

func (s stubExcluder) ExcludeNode(target hayai.NodeRef)       { s.excluded[target] = true }
func (s stubExcluder) NodeExcluded(target hayai.NodeRef) bool { return s.excluded[target] }

// routableIgnoringSize decides whose declared ceiling the clamp is allowed to
// read, and every predicate in it must be a HARD exclusion. MaxDeclaredOutput
// treats one undeclared cap as "the whole pool is unbounded", so an operator
// this request can never reach — a staging node, a banned node, one the
// caller's own provider preferences exclude — that answered the setup wizard's
// max_output_tokens prompt with 0 would otherwise switch the clamp off for
// every payer on that model.
//
// The asymmetry matters as much as the predicates: keeping an operator
// selection would later drop only raises the ceiling, which clamps less and
// leaves the request exactly as it behaved before the clamp existed. Dropping
// one selection would have KEPT clamps a caller below what an operator was
// ready to serve. So every false below has to be a rule selection applies
// unconditionally.
func TestRoutableIgnoringSize(t *testing.T) {
	ref := func(id uint64) selection.OperatorRef {
		return selection.OperatorRef{OperatorID: id, MatchAllNodes: true}
	}
	cases := []struct {
		name         string
		mutate       func(*hayai.Operator)
		allowStaging bool
		excluded     bool
		requireTEE   bool
		prefs        selection.RoutingPreferences
		want         bool
	}{
		{
			name: "plain serving operator is routable",
			want: true,
		},
		{
			// The realistic trigger: allow_staging defaults false, and the node
			// wizard documents 0 as a valid answer ("no separate cap beyond
			// context_window"), so a staging node with no ceiling is a shape
			// operators actually produce.
			name:   "staging node is held out by default",
			mutate: func(op *hayai.Operator) { op.Staging = true },
			want:   false,
		},
		{
			name:         "staging node counts once the payer opts in",
			mutate:       func(op *hayai.Operator) { op.Staging = true },
			allowStaging: true,
			want:         true,
		},
		{
			name:     "node proven to have handed a fraudulent settle group",
			excluded: true,
			want:     false,
		},
		{
			name:   "operator speaking a different wire generation",
			mutate: func(op *hayai.Operator) { op.ProtoVersion = "1.0" },
			want:   false,
		},
		{
			name:       "TEE required and the operator is not attested",
			requireTEE: true,
			want:       false,
		},
		{
			name:       "TEE required and the operator is attested",
			mutate:     func(op *hayai.Operator) { op.TEE = attestedTEE },
			requireTEE: true,
			want:       true,
		},
		{
			name: "signing account one microAlgo below the routing floor",
			mutate: func(op *hayai.Operator) {
				v := selection.MinSignerSpendableMicroAlgos - 1
				op.SignerSpendableMicroAlgos = &v
			},
			want: false,
		},
		{
			name: "signing account exactly at the routing floor",
			mutate: func(op *hayai.Operator) {
				v := selection.MinSignerSpendableMicroAlgos
				op.SignerSpendableMicroAlgos = &v
			},
			want: true,
		},
		{
			name:  "caller's provider.ignore excludes it",
			prefs: selection.RoutingPreferences{Ignore: []selection.OperatorRef{ref(7)}},
			want:  false,
		},
		{
			name:  "caller's provider.only names someone else",
			prefs: selection.RoutingPreferences{Only: []selection.OperatorRef{ref(9)}},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := hayai.Operator{
				ID: 7, NodeID: 1,
				Models:       []string{clampModel},
				ProtoVersion: wire.ProtoVersion,
			}
			if tc.mutate != nil {
				tc.mutate(&op)
			}
			cfg := testConfig()
			cfg.AllowStaging = tc.allowStaging
			s := testServer(cfg, Options{})
			if tc.excluded {
				s.nodeExcluder = stubExcluder{excluded: map[hayai.NodeRef]bool{hayai.RefOf(op): true}}
			}
			if got := s.routableIgnoringSize(op, tc.requireTEE, tc.prefs); got != tc.want {
				t.Errorf("routableIgnoringSize = %v, want %v", got, tc.want)
			}
		})
	}
}

// End-to-end proof that the filter is actually wired into the ceiling: a
// staging node declaring no cap sits in the same registry as a production node
// declaring 32768, with allow_staging off. Reading the raw registry would see
// the staging node's undeclared cap, disable the clamp pool-wide, and hand the
// caller back the 400 this whole path exists to prevent.
func TestDispatchHayai_StagingNodeDoesNotDisableTheClamp(t *testing.T) {
	var reserves []ticket.ReserveRequest
	production := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
	})
	staging := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
	})
	for _, n := range []*fakeNode{production, staging} {
		n.operator.Models = []string{clampModel}
	}
	production.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
	}
	// Staging, and no declared output cap — the combination that used to switch
	// the clamp off for everyone.
	staging.operator.Staging = true
	staging.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144},
	}

	cfg := testConfig() // AllowStaging defaults false
	s := testServer(cfg, setupHayai(t, cfg, production, staging))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":65536,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200 — an unroutable staging node must not "+
			"disable the clamp for the production pool", w.Result().StatusCode, w.Body.String())
	}
	if len(reserves) != 1 {
		t.Fatalf("the production node captured %d reserves, want 1", len(reserves))
	}
	if got := reserves[0].MaxOutputCount; got != 32_768 {
		t.Errorf("reserve max_output_count = %d, want 32768", got)
	}
	if staging.callCountValue() != 0 {
		t.Errorf("the staging node should never be reached, got %d calls", staging.callCountValue())
	}
}

// Same shape for the caller's own routing preferences: an operator the request
// excluded by name can't decide the ceiling for the operators it kept.
func TestDispatchHayai_IgnoredOperatorDoesNotDisableTheClamp(t *testing.T) {
	var reserves []ticket.ReserveRequest
	kept := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
	})
	ignored := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
	})
	for _, n := range []*fakeNode{kept, ignored} {
		n.operator.Models = []string{clampModel}
	}
	kept.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
	}
	ignored.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		clampModel: {ContextWindow: 262_144},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, kept, ignored))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		fmt.Sprintf(`{"model":%q,"max_tokens":65536,"provider":{"ignore":["%d"]},`+
			`"messages":[{"role":"user","content":"hi"}]}`, clampModel, ignored.operator.ID)))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
	}
	if len(reserves) != 1 {
		t.Fatalf("the kept operator captured %d reserves, want 1", len(reserves))
	}
	if got := reserves[0].MaxOutputCount; got != 32_768 {
		t.Errorf("reserve max_output_count = %d, want 32768", got)
	}
}

// The clamp is otherwise invisible to the caller: the reply just stops early at
// finish_reason:"length", which looks identical to the model deciding to stop.
// The header is the only thing that tells a tool the proxy moved its ceiling.
func TestDispatchHayai_ClampSetsResponseHeader(t *testing.T) {
	newNode := func() *fakeNode {
		n := newFakeNode(t, &nodeConfig{
			mode:           modeNonStreamEncrypted,
			replyPlaintext: []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
		})
		n.operator.Models = []string{clampModel}
		n.operator.ModelCapacities = map[string]hayai.ModelCapacity{
			clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
		}
		return n
	}

	t.Run("set when the ceiling moved", func(t *testing.T) {
		cfg := testConfig()
		s := testServer(cfg, setupHayai(t, cfg, newNode()))
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
			fmt.Sprintf(`{"model":%q,"max_tokens":65536,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))
		if got := w.Header().Get("X-Zs-Max-Output-Clamped"); got != "32768" {
			t.Errorf("X-Zs-Max-Output-Clamped = %q, want %q", got, "32768")
		}
	})

	// Streaming is where the clamp actually bites — a truncated reply is far
	// more visible mid-stream than in a buffered body — and it takes a
	// completely different write path (an SSE pump, no copyResponseHeaders and
	// no strip). Assert it there too rather than assuming the two agree.
	t.Run("set on the streaming path", func(t *testing.T) {
		n := newFakeNode(t, &nodeConfig{
			mode:         modeStreamEncrypted,
			streamFrames: [][]byte{[]byte(`{"choices":[{"delta":{"content":"hi"}}]}`)},
		})
		n.operator.Models = []string{clampModel}
		n.operator.ModelCapacities = map[string]hayai.ModelCapacity{
			clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
		}
		cfg := testConfig()
		s := testServer(cfg, setupHayai(t, cfg, n))
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
			fmt.Sprintf(`{"model":%q,"max_tokens":65536,"stream":true,`+
				`"messages":[{"role":"user","content":"hi"}]}`, clampModel)))
		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
		}
		if got := w.Header().Get("X-Zs-Max-Output-Clamped"); got != "32768" {
			t.Errorf("X-Zs-Max-Output-Clamped = %q on the streaming path, want %q", got, "32768")
		}
	})

	t.Run("absent when the caller was already under the ceiling", func(t *testing.T) {
		cfg := testConfig()
		s := testServer(cfg, setupHayai(t, cfg, newNode()))
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
			fmt.Sprintf(`{"model":%q,"max_tokens":512,"messages":[{"role":"user","content":"hi"}]}`, clampModel)))
		if got := w.Header().Get("X-Zs-Max-Output-Clamped"); got != "" {
			t.Errorf("X-Zs-Max-Output-Clamped = %q on an unclamped request, want absent", got)
		}
	})

	// The restore this header needs (snapshotHayaiHeaders + stripNodeHayaiHeaders)
	// must not become a hole in the §5.2-step-4 strip. A node answering with its
	// own X-Zs-Max-Output-Clamped is overwriting the proxy's value in w.Header()
	// via copyResponseHeaders, so an allow-list-shaped fix would have forwarded
	// the NODE's number as if the proxy had set it.
	t.Run("a node cannot forge it", func(t *testing.T) {
		forge := func(t *testing.T, callerMaxTokens int, want string) {
			t.Helper()
			n := newFakeNode(t, &nodeConfig{
				mode:             modeNonStreamEncrypted,
				replyPlaintext:   []byte(`{"choices":[{"message":{"content":"hi"}}]}`),
				extraRespHeaders: map[string]string{"X-Zs-Max-Output-Clamped": "999999"},
			})
			n.operator.Models = []string{clampModel}
			n.operator.ModelCapacities = map[string]hayai.ModelCapacity{
				clampModel: {ContextWindow: 262_144, MaxOutputTokens: 32_768},
			}
			cfg := testConfig()
			s := testServer(cfg, setupHayai(t, cfg, n))
			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
				fmt.Sprintf(`{"model":%q,"max_tokens":%d,"messages":[{"role":"user","content":"hi"}]}`,
					clampModel, callerMaxTokens)))
			if got := w.Header().Get("X-Zs-Max-Output-Clamped"); got != want {
				t.Errorf("X-Zs-Max-Output-Clamped = %q, want %q (the node's 999999 must never win)", got, want)
			}
		}
		// Proxy clamped: its own value survives, the node's is discarded.
		t.Run("proxy set one", func(t *testing.T) { forge(t, 65536, "32768") })
		// Proxy clamped nothing: there is no proxy value to restore, so the
		// node's must be stripped and stay stripped.
		t.Run("proxy set none", func(t *testing.T) { forge(t, 512, "") })
	})

	// A cross-origin caller can only read the header if it's on the CORS
	// allow-list — the list writeCORSHeaders builds is explicit, not `*`, so a
	// new X-Zs-* header is unreadable until it's added there.
	t.Run("readable cross-origin", func(t *testing.T) {
		w := httptest.NewRecorder()
		writeCORSHeaders(w, httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil))
		exposed := w.Header().Get("Access-Control-Expose-Headers")
		if !strings.Contains(exposed, "X-Zs-Max-Output-Clamped") {
			t.Errorf("Access-Control-Expose-Headers omits X-Zs-Max-Output-Clamped: %s", exposed)
		}
	})
}
