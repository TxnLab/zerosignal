/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transient_test

// Cross-impl parity test for transient classification and the retry schedule.
// Generates / verifies proto/testdata/transient_vectors.json — a
// language-neutral fixture pinning both the verdict for a battery of
// (status, code) pairs and the exact delay table. proto/ts loads the same file
// and asserts its port agrees, so a proxy and the browser app can never drift
// into retrying a flaky CDN on different schedules.
//
// The schedule is vectored, not just the classifier, because the numbers are
// the user-visible half: a fleet-wide restart is ridden out for the same minute
// either way, or it isn't.
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./transient -run TestTransientVectors -update
//
// Without -update, this asserts the on-disk file matches current Go output.

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/transient_vectors.json")

const vectorsPath = "../../testdata/transient_vectors.json"

type classifyCase struct {
	Name     string            `json:"name"`
	Status   int               `json:"status"`
	Code     string            `json:"code"`
	Expected transient.Verdict `json:"expected"`
}

// narrowCase pins NarrowRelayed: the verdict Classify produced from
// (status, code), plus the route evidence the response body could not carry,
// against the refined verdict. Vectored alongside classify_cases because the
// two halves are one decision — a port that agrees on Classify but disagrees
// here would charge a different hop for the same 504.
type narrowCase struct {
	Name     string                  `json:"name"`
	Status   int                     `json:"status"`
	Code     string                  `json:"code"`
	Evidence transient.RelayEvidence `json:"evidence"`
	Expected transient.Verdict       `json:"expected"`
}

type waitCase struct {
	Name         string `json:"name"`
	ScheduledMs  int64  `json:"scheduled_ms"`
	RetryAfterMs int64  `json:"retry_after_ms"`
	RemainingMs  int64  `json:"remaining_ms"`
	ExpectedMs   int64  `json:"expected_ms"`
	ExpectedOK   bool   `json:"expected_ok"`
}

type scheduleSpec struct {
	InnerAttempts     int     `json:"inner_attempts"`
	Sweeps            int     `json:"sweeps"`
	OverallDeadlineMs int64   `json:"overall_deadline_ms"`
	InnerDelaysMs     []int64 `json:"inner_delays_ms"`
	SweepDelaysMs     []int64 `json:"sweep_delays_ms"`
}

// versionCase pins the minor-gated capability helpers that NarrowRelayed's
// RelayMarksHops input is derived from. These live in package wire, but they
// are vectored HERE because they are only consumed by this decision and because
// leaving them unvectored is what let the two ports drift: Go's strconv.Atoi
// accepted a leading "+" that the TS regex rejected, and JS's parseInt silently
// overflowed a 20-digit segment to a float where Atoi returned ErrRange — the
// JS direction failing OPEN, i.e. an absurd version reading as marker-capable.
type versionCase struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Compatible       bool   `json:"compatible"`
	AtLeastHopMarker bool   `json:"at_least_hop_marker"`
}

// frontDoorCase pins IsRelayFrontDoorStatus per status. NarrowRelayed's rule 4
// already exercises the set indirectly, but the DISCOVERY probes on both sides
// call the predicate directly and status-first (deliberately ignoring the body
// — see the predicate's docs), so membership is a cross-language contract in
// its own right. Vectoring it member-for-member is what makes "the Go and TS
// discovery probes rotate on the same responses" checkable rather than assumed.
type frontDoorCase struct {
	Name      string `json:"name"`
	Status    int    `json:"status"`
	FrontDoor bool   `json:"front_door"`
}

type vectorsFile struct {
	Version        int             `json:"version"`
	Comment        string          `json:"comment"`
	Schedule       scheduleSpec    `json:"schedule"`
	ClassifyCases  []classifyCase  `json:"classify_cases"`
	NarrowCases    []narrowCase    `json:"narrow_cases"`
	VersionCases   []versionCase   `json:"version_cases"`
	FrontDoorCases []frontDoorCase `json:"front_door_cases"`
	WaitCases      []waitCase      `json:"wait_cases"`
}

// classifyInputs are the (status, code) pairs worth pinning. They cover each
// rule in Classify plus the boundaries that have bitten in production: a
// code-less 504 (the CDN case this package exists for), a 503 that DOES carry a
// node code (must stay terminal so the node's own semantics win), and the
// Cloudflare 52x block.
var classifyInputs = []struct {
	name   string
	status int
	code   string
}{
	// Rule 1 — relay-generated hop faults. The target never saw the request.
	{"relay_busy_503", 503, relay.CodeBusy},
	{"relay_unknown_target_404", 404, relay.CodeUnknownTarget},
	{"relay_build_request_502", 502, relay.CodeBuildRequest},
	{"relay_bad_target_400", 400, relay.CodeBadTarget},
	{"relay_bad_path_400", 400, relay.CodeBadPath},
	{"relay_bad_method_400", 400, relay.CodeBadMethod},

	// Rule 2 — the relay's claim ABOUT the target.
	{"relay_upstream_unreachable_502", 502, relay.CodeUpstreamUnreachable},

	// Rule 3 — the zs stack answered; its own per-code semantics own the
	// outcome, so this package declines to classify it as infrastructure.
	{"node_context_length_exceeded_400", 400, "context_length_exceeded"},
	{"node_provider_unavailable_503", 503, "provider_unavailable"},
	{"node_ticket_required_402", 402, "ticket_required"},
	{"node_rate_limited_429", 429, "rate_limited"},
	{"node_draining_503", 503, "node_draining"},

	// Rule 4 — the reason this package exists: a transient-shaped status with
	// no protocol code at all, i.e. a CDN / ingress / LB error page.
	{"bare_504_gateway_timeout", 504, ""},
	{"bare_502_bad_gateway", 502, ""},
	{"bare_503_service_unavailable", 503, ""},
	{"bare_500_internal", 500, ""},
	{"bare_429_no_code", 429, ""},
	{"bare_408_request_timeout", 408, ""},
	{"bare_425_too_early", 425, ""},
	{"cloudflare_520_unknown", 520, ""},
	{"cloudflare_521_origin_down", 521, ""},
	{"cloudflare_522_connect_timeout", 522, ""},
	{"cloudflare_523_origin_unreachable", 523, ""},
	{"cloudflare_524_origin_timeout", 524, ""},
	{"cloudflare_525_tls_handshake", 525, ""},
	{"cloudflare_526_invalid_cert", 526, ""},
	{"cloudflare_527_railgun", 527, ""},
	{"transport_failure_no_response", transient.TransportFailureStatus, ""},

	// Rule 5 — terminal. A 4xx without a code is a genuine refusal, and a 2xx
	// reaching a classifier at all means the caller failed it for its own
	// reasons (bad envelope, unsealed body) that a retry can't fix.
	{"bare_400_bad_request", 400, ""},
	{"bare_401_unauthorized", 401, ""},
	{"bare_403_forbidden", 403, ""},
	{"bare_404_not_found", 404, ""},
	{"bare_422_unprocessable", 422, ""},
	{"bare_200_ok", 200, ""},
}

// narrowInputs pin every rule in NarrowRelayed, plus the two inversions that
// would do real damage if a port got them backwards: charging a target for a
// relay's broken front door, and charging a relay for a header its generation
// was never asked to set.
var narrowInputs = []struct {
	name     string
	status   int
	code     string
	evidence transient.RelayEvidence
}{
	// Rule 1 — passthrough. An attributed verdict already names its hop, and a
	// direct send has no relay to reason about, so evidence changes nothing.
	{"direct_bare_504_unchanged", 504, "", transient.RelayEvidence{}},
	{"direct_transport_failure_unchanged", transient.TransportFailureStatus, "", transient.RelayEvidence{}},
	// The !Relayed guard specifically, with the evidence flags SET. Without
	// these a port that dropped `!e.Relayed` from rules 4/5 passes every other
	// case — and it is reachable: nothing strips X-Zs-Relay-Hop from a target's
	// own DIRECT response, so a target could set it and be read as a relay's
	// claim about itself.
	{"direct_marked_502_unchanged", 502, "",
		transient.RelayEvidence{HopMarker: true}},
	{"direct_marking_relay_502_unchanged", 502, "",
		transient.RelayEvidence{RelayMarksHops: true}},
	{"direct_both_flags_504_unchanged", 504, "",
		transient.RelayEvidence{HopMarker: true, RelayMarksHops: true}},

	// Rule 2 — the caller's own cancel/deadline. A transport failure we caused
	// ourselves says nothing about either hop; without this it reads as rule 3
	// and charges a relay for a socket WE tore down. Reachable on every user
	// "stop" and every client-side reserve timeout.
	{"caller_aborted_transport_failure_unattributed", transient.TransportFailureStatus, "",
		transient.RelayEvidence{Relayed: true, CallerAborted: true}},
	{"caller_aborted_outranks_marker_absence", 502, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true, CallerAborted: true}},
	{"caller_aborted_outranks_marker_presence", 504, "",
		transient.RelayEvidence{Relayed: true, HopMarker: true, RelayMarksHops: true, CallerAborted: true}},
	{"relayed_hop_code_stays_relay", 503, relay.CodeBusy,
		transient.RelayEvidence{Relayed: true, HopMarker: true, RelayMarksHops: true}},
	{"relayed_upstream_unreachable_stays_target", 502, relay.CodeUpstreamUnreachable,
		transient.RelayEvidence{Relayed: true, HopMarker: true, RelayMarksHops: true}},
	{"relayed_terminal_code_unchanged", 400, "context_length_exceeded",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_non_retryable_status_unchanged", 404, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},

	// Rule 3 — no response at all. The socket we opened was the relay's, so
	// this is a relay fault with NO version gate: the case that works against
	// an entirely un-upgraded fleet. (Rule 2 has already excluded the case
	// where WE were the one who hung up.)
	{"relayed_transport_failure_blames_relay", transient.TransportFailureStatus, "",
		transient.RelayEvidence{Relayed: true}},
	{"relayed_transport_failure_blames_relay_even_when_marked", transient.TransportFailureStatus, "",
		transient.RelayEvidence{Relayed: true, HopMarker: true, RelayMarksHops: true}},

	// Rule 5 — the relay ran and forwarded. Its "I got this from the target"
	// is the same shape of claim as relay_upstream_unreachable, so it lands on
	// the same attribution and inherits the caller's existing differential.
	{"relayed_marked_504_blames_target", 504, "",
		transient.RelayEvidence{Relayed: true, HopMarker: true, RelayMarksHops: true}},
	{"relayed_marked_503_blames_target", 503, "",
		transient.RelayEvidence{Relayed: true, HopMarker: true, RelayMarksHops: true}},
	// A marker from a relay we believe predates the header still means the
	// handler ran — presence is self-evident and needs no version gate. Only
	// ABSENCE needs one.
	{"relayed_marked_504_pre_floor_still_blames_target", 504, "",
		transient.RelayEvidence{Relayed: true, HopMarker: true}},

	// Rule 4 — a >= 9.1 relay that ran its handler would have marked. It
	// didn't, and the status says its front door could not get a connection to
	// it, so we were blocked at that door. These are the shapes a relay that is
	// genuinely DOWN produces.
	{"relayed_unmarked_502_blames_relay", 502, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_503_blames_relay", 503, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_cloudflare_521_origin_down_blames_relay", 521, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_cloudflare_522_connect_timeout_blames_relay", 522, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_cloudflare_523_unreachable_blames_relay", 523, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_429_blames_relay", 429, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},

	// Rule 4's timeout carve-out. A relay is byte-silent for the whole forward
	// window (it cannot flush a marker without committing to a status it does
	// not yet know), so a gateway TIMEOUT is indistinguishable between "relay
	// wedged" and "relay waiting on a slow target". Charging here would bench
	// whoever fronts the slowest targets; the rotation differential decides
	// instead. NOTE the contrast with 522 above — that is a CONNECT timeout
	// (TCP never established ⇒ relay down), this is a RESPONSE timeout.
	{"relayed_unmarked_504_gateway_timeout_unattributed", 504, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_cloudflare_524_response_timeout_unattributed", 524, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},
	{"relayed_unmarked_408_unattributed", 408, "",
		transient.RelayEvidence{Relayed: true, RelayMarksHops: true}},

	// Rule 6 — the residue. A pre-floor relay owes us no header, so its
	// absence proves nothing and the verdict stays unattributed exactly as it
	// was before this narrowing existed. Charging here is the inversion that
	// would blame the entire un-upgraded fleet.
	{"relayed_unmarked_504_pre_floor_stays_unknown", 504, "",
		transient.RelayEvidence{Relayed: true}},
	{"relayed_unmarked_transport_status_pre_floor_stays_unknown", 524, "",
		transient.RelayEvidence{Relayed: true}},
}

// versionInputs are the proto_version strings whose parse must be identical in
// both ports. The plain ones document intent; the hostile ones are the actual
// regression pins — every one of the last six diverged before this was vectored.
var versionInputs = []string{
	// Ordinary shapes.
	"9.1", "9.0", "9", "9.2", "9.1.3", "9.0.9", "10.0", "8.9", "1.0", "",
	// Malformed — must fail closed in BOTH ports.
	"garbage", "vNext", "9.x", "x.1", ".1", "9.", ".", "..", "-1.0", "9.-1",
	// The divergences. "+9.1"/"9.+1": Go's Atoi took the sign, the TS regex
	// didn't. The 20-digit forms: JS parseInt overflowed to a float and
	// answered TRUE (fail-open) where Go's Atoi returned ErrRange.
	"+9.1", "9.+1", "+9",
	"99999999999999999999", "99999999999999999999.0", "9.99999999999999999999",
	"9223372036854775808",
	// Whitespace and unicode digits — neither port may accept them.
	" 9.1", "9.1 ", "9 .1", "٩.١",
}

// frontDoorInputs are every status the predicate could plausibly be asked
// about: all of retryableStatuses (so each one's membership is an explicit,
// diffable decision rather than a subtraction), the transport sentinel, and a
// handful of ordinary statuses that must never be front-door shaped.
var frontDoorInputs = []int{
	transient.TransportFailureStatus,
	200, 400, 401, 403, 404, 409, 413, 422,
	408, 425, 429,
	500, 502, 503, 504, 507,
	520, 521, 522, 523, 524, 525, 526, 527,
}

// waitInputs pin the Retry-After / deadline interaction. The load-bearing cases
// are "a server hint longer than the table wins" and "a wait that would eat the
// remaining budget stops the loop instead of sleeping to the deadline".
var waitInputs = []struct {
	name                             string
	scheduled, retryAfter, remaining time.Duration
}{
	{"first_attempt_immediate", 0, 0, 60 * time.Second},
	{"table_wait_within_budget", 1500 * time.Millisecond, 0, 60 * time.Second},
	{"retry_after_longer_wins", 500 * time.Millisecond, 5 * time.Second, 60 * time.Second},
	{"retry_after_shorter_ignored", 4 * time.Second, 250 * time.Millisecond, 60 * time.Second},
	{"wait_exceeds_remaining_stops", 30 * time.Second, 0, 10 * time.Second},
	{"wait_equals_remaining_stops", 10 * time.Second, 0, 10 * time.Second},
	{"no_budget_left_stops", 500 * time.Millisecond, 0, 0},
	{"negative_budget_stops", 500 * time.Millisecond, 0, -1 * time.Second},
	{"retry_after_blows_budget_stops", 0, 90 * time.Second, 60 * time.Second},
}

// versionCaseName turns a (possibly hostile) version string into a stable,
// readable vector name. Empty and whitespace-bearing inputs would otherwise
// produce unnameable or colliding cases.
func versionCaseName(v string) string {
	if v == "" {
		return "empty"
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r == '.':
			b.WriteByte('_')
		case r == ' ':
			b.WriteString("sp")
		case r == '+':
			b.WriteString("plus")
		case r == '-':
			b.WriteString("minus")
		default:
			b.WriteString("x")
		}
	}
	return b.String()
}

func buildVectors() vectorsFile {
	f := vectorsFile{
		Version: 2,
		Comment: "Cross-impl vectors for transient-failure classification, relayed-verdict narrowing, front-door status membership, and the shared retry schedule. " +
			"Generated by proto/go: go test ./transient -run TestTransientVectors -update",
		Schedule: scheduleSpec{
			InnerAttempts:     transient.InnerAttempts,
			Sweeps:            transient.Sweeps,
			OverallDeadlineMs: transient.OverallDeadline.Milliseconds(),
		},
	}
	for i := 0; i < transient.InnerAttempts; i++ {
		f.Schedule.InnerDelaysMs = append(f.Schedule.InnerDelaysMs, transient.InnerDelay(i).Milliseconds())
	}
	for i := 0; i < transient.Sweeps; i++ {
		f.Schedule.SweepDelaysMs = append(f.Schedule.SweepDelaysMs, transient.SweepDelay(i).Milliseconds())
	}
	for _, in := range classifyInputs {
		f.ClassifyCases = append(f.ClassifyCases, classifyCase{
			Name:     in.name,
			Status:   in.status,
			Code:     in.code,
			Expected: transient.Classify(in.status, in.code),
		})
	}
	for _, in := range narrowInputs {
		f.NarrowCases = append(f.NarrowCases, narrowCase{
			Name:     in.name,
			Status:   in.status,
			Code:     in.code,
			Evidence: in.evidence,
			Expected: transient.NarrowRelayed(transient.Classify(in.status, in.code), in.status, in.evidence),
		})
	}
	for _, v := range versionInputs {
		f.VersionCases = append(f.VersionCases, versionCase{
			Name:             "version_" + versionCaseName(v),
			Version:          v,
			Compatible:       wire.ProtoVersionCompatible(v),
			AtLeastHopMarker: wire.SetsRelayHopHeader(v),
		})
	}
	for _, status := range frontDoorInputs {
		f.FrontDoorCases = append(f.FrontDoorCases, frontDoorCase{
			Name:      "front_door_" + strconv.Itoa(status),
			Status:    status,
			FrontDoor: transient.IsRelayFrontDoorStatus(status),
		})
	}
	for _, in := range waitInputs {
		d, ok := transient.Wait(in.scheduled, in.retryAfter, in.remaining)
		f.WaitCases = append(f.WaitCases, waitCase{
			Name:         in.name,
			ScheduledMs:  in.scheduled.Milliseconds(),
			RetryAfterMs: in.retryAfter.Milliseconds(),
			RemainingMs:  in.remaining.Milliseconds(),
			ExpectedMs:   d.Milliseconds(),
			ExpectedOK:   ok,
		})
	}
	return f
}

func TestTransientVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildVectors(), "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	got = append(got, '\n')

	if *updateVectors {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", vectorsPath, err)
		}
		t.Logf("wrote %s", vectorsPath)
		return
	}

	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s (regenerate with -update): %v", vectorsPath, err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Errorf("%s is stale — Go output changed.\n"+
			"If the change was intentional, regenerate with:\n"+
			"  cd proto/go && go test ./transient -run TestTransientVectors -update\n"+
			"and port the same change to proto/ts/src/transient.", vectorsPath)
	}
}
