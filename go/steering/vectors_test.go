/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package steering_test

// Generates / verifies proto/testdata/steering_vectors.json, which
// proto/ts/test/steering-vectors.test.ts replays. Times and durations are
// integer milliseconds, the unit the TS port works in.
//
//	cd proto/go && go test ./steering -run TestSteeringVectors -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/steering"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/steering_vectors.json")

const vectorsPath = "../../testdata/steering_vectors.json"

// t0 is an arbitrary wall-clock instant; vectors are offsets from it so a port
// that confuses "no evidence" with the Unix epoch fails visibly.
var t0 = time.UnixMilli(1_760_000_000_000)

const (
	minute = int64(time.Minute / time.Millisecond)
	second = int64(time.Second / time.Millisecond)
)

type evidenceJSON struct {
	Count int   `json:"count"`
	AtMs  int64 `json:"at_ms"`
}

func evidenceOut(e steering.Evidence) *evidenceJSON {
	if e.At.IsZero() {
		return nil
	}
	return &evidenceJSON{Count: e.Count, AtMs: e.At.UnixMilli()}
}

func evidenceIn(e *evidenceJSON) steering.Evidence {
	if e == nil {
		return steering.Evidence{}
	}
	return steering.Evidence{Count: e.Count, At: time.UnixMilli(e.AtMs)}
}

type decayCase struct {
	Name       string        `json:"name"`
	Evidence   *evidenceJSON `json:"evidence"`
	NowMs      int64         `json:"now_ms"`
	CooldownMs int64         `json:"cooldown_ms"`
	Decayed    *evidenceJSON `json:"decayed"`
	Bumped     evidenceJSON  `json:"bumped"`
}

type backoffJSON struct {
	Failures int   `json:"failures"`
	AtMs     int64 `json:"at_ms"`
	UntilMs  int64 `json:"until_ms"`
}

func backoffOut(b steering.Backoff) *backoffJSON {
	if b.Failures == 0 {
		return nil
	}
	return &backoffJSON{Failures: b.Failures, AtMs: b.At.UnixMilli(), UntilMs: b.Until.UnixMilli()}
}

func backoffIn(b *backoffJSON) steering.Backoff {
	if b == nil {
		return steering.Backoff{}
	}
	return steering.Backoff{Failures: b.Failures, At: time.UnixMilli(b.AtMs), Until: time.UnixMilli(b.UntilMs)}
}

type windowCase struct {
	Failures int   `json:"failures"`
	WindowMs int64 `json:"window_ms"`
}

type backoffCase struct {
	Name        string       `json:"name"`
	Backoff     *backoffJSON `json:"backoff"`
	NowMs       int64        `json:"now_ms"`
	FloorMs     int64        `json:"floor_ms"`
	RemainingMs int64        `json:"remaining_ms"`
	Forget      bool         `json:"forget"`
	// The record after one more failure at now.
	Failed backoffJSON `json:"failed"`
}

type claimJSON struct {
	Owner  string `json:"owner"`
	Digest string `json:"digest"`
}

type consensusCase struct {
	Name      string      `json:"name"`
	Claims    []claimJSON `json:"claims"`
	Consensus string      `json:"consensus"`
	// For each claim in order, whether its digest contradicts the consensus.
	Contradicts []bool `json:"contradicts"`
}

type statusCase struct {
	Status  int  `json:"status"`
	Timeout bool `json:"timeout"`
}

type vectorFile struct {
	Version   int              `json:"version"`
	Constants map[string]int64 `json:"constants"`
	Statuses  []statusCase     `json:"forward_timeout_statuses"`
	Decay     []decayCase      `json:"decay"`
	Windows   []windowCase     `json:"backoff_windows"`
	Backoff   []backoffCase    `json:"backoff"`
	Consensus []consensusCase  `json:"weights_consensus"`
	Downrank  []downrankCase   `json:"relay_downranked"`
}

type downrankCase struct {
	Failures   int  `json:"failures"`
	Stale      int  `json:"stale"`
	Timeouts   int  `json:"timeouts"`
	Downranked bool `json:"downranked"`
}

func buildDownrank() []downrankCase {
	f, tm := steering.RelayDownrankThreshold, steering.RelayTimeoutDownrankThreshold
	out := []downrankCase{}
	for _, c := range [][3]int{
		{0, 0, 0}, {f - 1, 0, 0}, {f, 0, 0}, {0, f - 1, 0}, {0, f, 0},
		{0, 0, tm - 1}, {0, 0, tm}, {f - 1, f - 1, tm - 1}, {f, 0, tm},
		// A timeout count that would cross the failure threshold must not.
		{0, 0, f},
	} {
		out = append(out, downrankCase{c[0], c[1], c[2], steering.RelayDownranked(c[0], c[1], c[2])})
	}
	return out
}

func ms(d time.Duration) int64 { return int64(d / time.Millisecond) }

func buildDecay() []decayCase {
	rep, tmo := ms(steering.RelayReputationCooldown), ms(steering.RelayTimeoutCooldown)
	at := t0.UnixMilli()
	ev := func(n int, offset int64) *evidenceJSON { return &evidenceJSON{Count: n, AtMs: at + offset} }
	inputs := []struct {
		name     string
		e        *evidenceJSON
		nowOff   int64
		cooldown int64
	}{
		{"no evidence", nil, 0, rep},
		{"no time elapsed", ev(2, 0), 0, rep},
		{"just under one cooldown", ev(2, 0), rep - 1, rep},
		{"exactly one cooldown", ev(2, 0), rep, rep},
		{"one cooldown and a residue", ev(3, 0), rep + 7*minute, rep},
		{"two cooldowns", ev(3, 0), 2 * rep, rep},
		{"decays to zero exactly", ev(2, 0), 2 * rep, rep},
		{"decays past zero", ev(2, 0), 9 * rep, rep},
		{"backwards clock by a second", ev(2, 0), -second, rep},
		{"backwards clock by more than a cooldown", ev(2, 0), -3 * rep, rep},
		{"backwards clock by a fraction past one cooldown", ev(2, 0), -rep - 1, rep},
		{"timeout streak under its own cooldown", ev(4, 0), 59 * minute, tmo},
		{"timeout streak one cooldown", ev(4, 0), tmo + 5*minute, tmo},
		{"the short cooldown would have aged it", ev(4, 0), 30 * minute, tmo},
		{"over-threshold evidence", ev(9, 0), 4 * rep, rep},
		{"zero count with a timestamp", ev(0, 0), rep, rep},
		{"zero cooldown ages nothing", ev(2, 0), 9 * rep, 0},
		{"negative cooldown ages nothing", ev(2, 0), 9 * rep, -rep},
	}
	out := make([]decayCase, 0, len(inputs))
	for _, in := range inputs {
		e := evidenceIn(in.e)
		now := time.UnixMilli(at + in.nowOff)
		cd := time.Duration(in.cooldown) * time.Millisecond
		decayed, _ := steering.Decay(e, now, cd)
		out = append(out, decayCase{
			Name: in.name, Evidence: in.e, NowMs: now.UnixMilli(), CooldownMs: in.cooldown,
			Decayed: evidenceOut(decayed),
			Bumped:  *evidenceOut(steering.Bump(e, now, cd)),
		})
	}
	return out
}

func buildWindows() []windowCase {
	out := []windowCase{}
	for _, n := range []int{-1, 0, 1, 2, 3, 4, 5, 6, 64, 1 << 20} {
		out = append(out, windowCase{Failures: n, WindowMs: ms(steering.BackoffWindow(n))})
	}
	return out
}

func buildBackoff() []backoffCase {
	at := t0.UnixMilli()
	capMs := ms(steering.TargetBackoffCap)
	rec := func(failures int) *backoffJSON {
		b := steering.Backoff{}
		for range failures {
			b = steering.RecordFailure(b, t0)
		}
		return backoffOut(b)
	}
	inputs := []struct {
		name    string
		b       *backoffJSON
		nowOff  int64
		floorMs int64
	}{
		{"no record", nil, 0, 0},
		{"inside the first window", rec(1), 10 * second, 0},
		{"first window just lapsed", rec(1), 30 * second, 0},
		{"inside the second window", rec(2), 59 * second, 0},
		{"inside the capped window", rec(9), 4 * minute, 0},
		{"lapsed, inside the grace period", rec(1), 30*second + capMs - 1, 0},
		{"lapsed, grace period over", rec(1), 30*second + capMs, 0},
		{"floor longer than the window", rec(1), 45 * second, 2 * minute},
		{"floor lapsed, inside the grace period", rec(1), 2*minute + capMs - 1, 2 * minute},
		{"floor lapsed, grace period over", rec(1), 2*minute + capMs, 2 * minute},
		{"floor shorter than the window", rec(3), 90 * second, 10 * second},
		{"backwards clock", rec(1), -minute, 0},
	}
	out := make([]backoffCase, 0, len(inputs))
	for _, in := range inputs {
		b := backoffIn(in.b)
		now := time.UnixMilli(at + in.nowOff)
		rem, forget := steering.BackoffRemaining(b, now, time.Duration(in.floorMs)*time.Millisecond)
		out = append(out, backoffCase{
			Name: in.name, Backoff: in.b, NowMs: now.UnixMilli(), FloorMs: in.floorMs,
			RemainingMs: ms(rem), Forget: forget,
			Failed: *backoffOut(steering.RecordFailure(b, now)),
		})
	}
	return out
}

func buildConsensus() []consensusCase {
	const good, fake, other = "sha256:aaaa", "sha256:bbbb", "sha256:cccc"
	c := func(owner, digest string) claimJSON { return claimJSON{owner, digest} }
	inputs := []struct {
		name   string
		claims []claimJSON
	}{
		{"majority of distinct owners", []claimJSON{c("A", good), c("B", good), c("C", fake)}},
		{"one owner each is not a consensus", []claimJSON{c("A", good), c("B", fake)}},
		{"a tie for the lead", []claimJSON{c("A", good), c("B", good), c("C", fake), c("D", fake)}},
		{"a tie behind a clear leader", []claimJSON{c("A", good), c("B", good), c("C", good), c("D", fake), c("E", other)}},
		{"a tie for second does not block the leader", []claimJSON{c("A", good), c("B", good), c("C", good), c("D", fake), c("E", fake), c("F", other), c("G", other)}},
		{"one owner's many nodes count once", []claimJSON{c("A", fake), c("A", fake), c("A", fake), c("A", fake), c("B", good)}},
		{"one owner on both sides", []claimJSON{c("A", good), c("A", fake), c("B", good)}},
		{"a lone publisher", []claimJSON{c("A", good), c("B", ""), c("C", "")}},
		{"nobody publishes", []claimJSON{c("A", ""), c("B", "")}},
		{"case-insensitive", []claimJSON{c("A", "SHA256:AAAA"), c("B", good), c("C", "sha256:BBBB")}},
		// Unicode lowercasing differs between Go and JS (JS writes a final Σ as
		// ς), so only ASCII folds: these two are different digests on both sides.
		{"only ASCII folds: a non-ASCII capital is a different digest", []claimJSON{c("A", "xÉ"), c("B", "xé"), c("C", "xé")}},
		{"only ASCII folds", []claimJSON{c("A", "xΣ"), c("B", "xσ"), c("C", "xσ")}},
		{"claims with no owner are not evidence", []claimJSON{c("", fake), c("", fake), c("C", good)}},
		{"claims with no owner are still judged", []claimJSON{c("", fake), c("A", good), c("B", good)}},
		{"leader found after a larger runner-up was seen", []claimJSON{c("A", fake), c("B", fake), c("C", good), c("D", good), c("E", good)}},
		{"no claims", nil},
	}
	out := make([]consensusCase, 0, len(inputs))
	for _, in := range inputs {
		claims := make([]steering.DigestClaim, len(in.claims))
		for i, cl := range in.claims {
			claims[i] = steering.DigestClaim{Owner: cl.Owner, Digest: cl.Digest}
		}
		cons := steering.WeightsConsensus(claims)
		contra := make([]bool, len(in.claims))
		for i, cl := range in.claims {
			contra[i] = steering.ContradictsWeightsConsensus(cl.Digest, cons)
		}
		out = append(out, consensusCase{Name: in.name, Claims: in.claims, Consensus: cons, Contradicts: contra})
	}
	return out
}

func buildVectors() vectorFile {
	statuses := []statusCase{}
	for _, s := range []int{0, 200, 400, 404, 408, 425, 429, 500, 502, 503, 504, 520, 522, 524, 525} {
		statuses = append(statuses, statusCase{Status: s, Timeout: steering.IsForwardTimeoutStatus(s)})
	}
	return vectorFile{
		Version: 1,
		Constants: map[string]int64{
			"RELAY_DOWNRANK_THRESHOLD":         steering.RelayDownrankThreshold,
			"RELAY_REPUTATION_COOLDOWN_MS":     ms(steering.RelayReputationCooldown),
			"RELAY_TIMEOUT_DOWNRANK_THRESHOLD": steering.RelayTimeoutDownrankThreshold,
			"RELAY_TIMEOUT_COOLDOWN_MS":        ms(steering.RelayTimeoutCooldown),
			"TARGET_BACKOFF_BASE_MS":           ms(steering.TargetBackoffBase),
			"TARGET_BACKOFF_CAP_MS":            ms(steering.TargetBackoffCap),
			"WEIGHTS_CONSENSUS_MIN_OWNERS":     steering.WeightsConsensusMinOwners,
		},
		Statuses:  statuses,
		Decay:     buildDecay(),
		Windows:   buildWindows(),
		Backoff:   buildBackoff(),
		Consensus: buildConsensus(),
		Downrank:  buildDownrank(),
	}
}

func TestSteeringVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildVectors(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update to create it)", vectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; run: cd proto/go && go test ./steering -run TestSteeringVectors -update", vectorsPath)
	}
}
