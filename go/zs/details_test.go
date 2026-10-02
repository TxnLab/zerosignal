/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/wire"
)

func TestDetails_FetchHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/details" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"builtin_tools":[
				{"type":"zs_web_search","name":"zs_web_search","description":"x","parameters":{}},
				{"type":"zs_web_read","name":"zs_web_read","description":"y","parameters":{}}
			],
			"max_tool_iterations":4
		}`))
	}))
	defer srv.Close()

	c := NewDetailsClient(srv.Client(), 2*time.Second)
	got, err := c.Fetch(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got.BuiltinTools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(got.BuiltinTools))
	}
	if got.BuiltinTools[0].Type != "zs_web_search" {
		t.Fatalf("first tool = %q", got.BuiltinTools[0].Type)
	}
	if got.MaxToolIterations != 4 {
		t.Fatalf("MaxToolIterations = %d", got.MaxToolIterations)
	}
}

func TestDetails_FetchTimeout(t *testing.T) {
	blocker := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocker
	}))
	defer func() {
		close(blocker)
		srv.Close()
	}()
	c := NewDetailsClient(nil, 50*time.Millisecond)
	_, err := c.Fetch(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestDetails_Fetch500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewDetailsClient(srv.Client(), 500*time.Millisecond)
	_, err := c.Fetch(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 in error, got %v", err)
	}
}

func TestDetails_FetchMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	c := NewDetailsClient(srv.Client(), 500*time.Millisecond)
	_, err := c.Fetch(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestDetails_FetchFieldsAbsent(t *testing.T) {
	// Older nodes don't advertise builtin_tools; fetch should still
	// succeed and return zero-value capability data.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer srv.Close()
	c := NewDetailsClient(srv.Client(), 500*time.Millisecond)
	got, err := c.Fetch(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got.BuiltinTools) != 0 || got.MaxToolIterations != 0 {
		t.Fatalf("expected zero caps, got %+v", got)
	}
}

// TestDetails_FetchRelayHopTransportError verifies that when a relayed probe
// can't reach the relay host at all (transport error), Fetch returns a
// *RelayHopError naming the relay — so the caller blames the relay, not the
// target. This is the exact symptom from the field report.
func TestDetails_FetchRelayHopTransportError(t *testing.T) {
	// hop.BaseURL points at a port nothing is listening on → dial refused.
	hop := &RelayHop{BaseURL: "http://127.0.0.1:0", TargetID: 3, RelayID: 9}
	c := NewDetailsClient(nil, 500*time.Millisecond)
	_, err := c.Fetch(context.Background(), "https://target.example:9000", hop)
	if err == nil {
		t.Fatalf("expected error")
	}
	var hopErr *RelayHopError
	if !errors.As(err, &hopErr) {
		t.Fatalf("expected *RelayHopError, got %T: %v", err, err)
	}
	if hopErr.RelayID != 9 {
		t.Fatalf("RelayID = %d, want 9", hopErr.RelayID)
	}
}

// TestDetails_FetchRelayHopErrorCodes verifies that relay-generated error
// codes that indicate the relay (outer hop) failed are classified as
// *RelayHopError, while relay_upstream_unreachable (target down) and a target's
// own forwarded error status are NOT — they stay plain target-side failures.
func TestDetails_FetchRelayHopErrorCodes(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		code       string
		relayVer   string // relay's advertised proto_version ("" = unknown, pre-floor)
		setMarker  bool   // relay stamped wire.RelayHopHeader on the response
		wantHopErr bool
	}{
		{"relay_busy", http.StatusServiceUnavailable, protorelay.CodeBusy, "", false, true},
		{"relay_unknown_target", http.StatusNotFound, protorelay.CodeUnknownTarget, "", false, true},
		{"relay_bad_method", http.StatusBadRequest, protorelay.CodeBadMethod, "", false, true},
		{"relay_upstream_unreachable", http.StatusBadGateway, protorelay.CodeUpstreamUnreachable, "", false, false},
		{"target_own_500_no_code", http.StatusInternalServerError, "", "", false, false},

		// The amplifier this fix removes. A code-less transient status from a
		// relay that advertises the hop marker, arriving WITHOUT it, means the
		// relay's own front door answered and the target was never contacted —
		// so it is a hop error, not a target failure. Classifying it as the
		// latter is what let one broken relay bench healthy nodes out of
		// discovery for hours.
		{"relay_front_door_502_unmarked", http.StatusBadGateway, "", "9.1", false, true},
		{"relay_front_door_cloudflare_521_unmarked", 521, "", "9.1", false, true},
		{"relay_front_door_cloudflare_522_unmarked", 522, "", "9.1", false, true},
		// Marker-absence outranks the BODY on this path (unlike NarrowRelayed,
		// which must not flip retryability). A front door that emits its own
		// coded JSON — an Envoy upstream_connect_error, or the node's per-IP
		// throttle which runs AHEAD of the relay handler and answers a coded 429
		// — used to fall through and bench the healthy target.
		{"relay_front_door_coded_429_unmarked", http.StatusTooManyRequests, "rate_limited", "9.1", false, true},
		{"relay_front_door_coded_502_unmarked", http.StatusBadGateway, "upstream_connect_error", "9.1", false, true},
		// A gateway TIMEOUT is not proof: the relay is byte-silent while
		// forwarding, so it may merely have been waiting on a slow target.
		{"relay_front_door_504_timeout_unmarked_is_ambiguous", http.StatusGatewayTimeout, "", "9.1", false, false},
		{"relay_front_door_cloudflare_524_timeout_unmarked_is_ambiguous", 524, "", "9.1", false, false},

		// A MARKED response means the relay forwarded, so the status belongs to
		// the target and this is a genuine target-side failure again. A relay's
		// claim to have forwarded may not be turned into an accusation here.
		{"relay_forwarded_target_502_marked", http.StatusBadGateway, "", "9.1", true, false},

		// The version gate. A pre-floor relay owes no header, so its absence
		// proves nothing — inverting this would reclassify every code-less
		// target error in the current fleet as a relay fault.
		{"pre_floor_relay_502_unmarked", http.StatusBadGateway, "", "9.0", false, false},
		{"unknown_version_relay_502_unmarked", http.StatusBadGateway, "", "", false, false},

		// A code-less status that is NOT transient-shaped is a genuine refusal
		// that reached us through a working relay, marker or no marker.
		{"non_transient_404_unmarked", http.StatusNotFound, "", "9.1", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// ApplyRelay repoints the probe at the relay endpoint and POSTs it.
				if !strings.HasSuffix(r.URL.Path, "/v1/zs/relay") || r.Method != http.MethodPost {
					t.Fatalf("relay request = %s %q", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				if tc.setMarker {
					w.Header().Set(wire.RelayHopHeader, wire.RelayHopHeaderValue)
				}
				w.WriteHeader(tc.status)
				if tc.code != "" {
					_, _ = w.Write([]byte(`{"error":{"type":"x","code":"` + tc.code + `","message":"m"}}`))
				}
			}))
			defer srv.Close()

			hop := &RelayHop{
				BaseURL: srv.URL, TargetID: 3, RelayID: 9, RelayNodeID: 1,
				RelayProtoVersion: tc.relayVer,
			}
			c := NewDetailsClient(srv.Client(), time.Second)
			_, err := c.Fetch(context.Background(), "https://target.example:9000", hop)
			if err == nil {
				t.Fatalf("expected error")
			}
			var hopErr *RelayHopError
			gotHopErr := errors.As(err, &hopErr)
			if gotHopErr != tc.wantHopErr {
				t.Fatalf("RelayHopError = %v, want %v (err: %v)", gotHopErr, tc.wantHopErr, err)
			}
			// The (operator, node) pair is how every downstream reliability
			// store keys — an id-only hop error would let a dead node tar a
			// healthy sibling under the same operator.
			if gotHopErr && (hopErr.RelayID != 9 || hopErr.RelayNodeID != 1) {
				t.Errorf("hop error names relay (%d, %d), want (9, 1)", hopErr.RelayID, hopErr.RelayNodeID)
			}
		})
	}
}

func TestOperator_SupportsBuiltinTool(t *testing.T) {
	op := Operator{
		BuiltinTools: []BuiltinToolDef{
			{Type: "zs_web_search"},
			{Type: "zs_web_read"},
		},
	}
	if !op.SupportsBuiltinTool("zs_web_search") {
		t.Fatalf("expected supports web_search")
	}
	if op.SupportsBuiltinTool("zs_bogus") {
		t.Fatalf("expected !supports bogus")
	}
	if !op.SupportsAllBuiltinTools([]string{"zs_web_search", "zs_web_read"}) {
		t.Fatalf("expected supports all")
	}
	if op.SupportsAllBuiltinTools([]string{"zs_web_search", "zs_image_search"}) {
		t.Fatalf("expected !supports all when one missing")
	}
}
