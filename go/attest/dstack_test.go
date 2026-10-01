/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// The vectors are a real capture from a live Phala tdx.small CVM on
// 2026-08-26: the guest agent's event log and the quote minted in the
// same call. They carry that deployment's app_id and instance_id,
// which is unavoidable — the replay's whole value is that it checks
// against hardware-signed bytes from the SAME capture, and redacting
// an input changes the output. They identify a throwaway probe CVM and
// are not secrets.
//
// THEY LIVE UNDER proto/testdata/, NOT proto/go/attest/testdata/,
// because proto/ts/test/attest-vectors.test.ts runs the same two files
// through the TypeScript implementation. Copying them under ts/ would
// give the two implementations different inputs to agree on, which is
// the one thing a parity fixture must not permit.
const (
	eventLogPath = "../../testdata/attest/ds_event_log.json"
	quotePath    = "../../testdata/attest/ds_quote_hex.txt"

	// The capture has 30 events, only 10 of which are runtime events, so
	// this catches an implementation that replayed all 30.
	//
	// IT DOES NOT PIN THE FILTER. In this capture the 10 runtime events
	// are exactly the 10 with imr==3, so `event_type != DstackRuntimeEventType`
	// and `imr != 3` select the same set and no count can tell them
	// apart. That is a property of the fixture, not of the code, and a
	// CVM that ever extends RTMR3 with a non-runtime event — or emits a
	// runtime event against another register — breaks the coincidence.
	// TestReplayFiltersOnEventTypeNotIMR is what actually holds the
	// filter, using synthetic events chosen so the two predicates
	// disagree.
	wantExtends = 10
)

func loadVectors(t *testing.T) (rawLog string, quote []byte) {
	t.Helper()
	raw, err := os.ReadFile(eventLogPath)
	if err != nil {
		t.Fatalf("read %s: %v", eventLogPath, err)
	}
	qhex, err := os.ReadFile(quotePath)
	if err != nil {
		t.Fatalf("read %s: %v", quotePath, err)
	}
	quote, err = hex.DecodeString(strings.TrimSpace(string(qhex)))
	if err != nil {
		t.Fatalf("decode %s: %v", quotePath, err)
	}
	return string(raw), quote
}

// TestReplayMatchesQuote is the anchor. It deliberately does NOT pin
// the replayed value against a hard-coded constant: that would only
// prove this code still agrees with itself, which is exactly how a
// wrong implementation looks "verified". Comparing against the
// hardware-signed RTMR3 from the same capture is the assertion that
// can actually fail.
func TestReplayMatchesQuote(t *testing.T) {
	rawLog, quote := loadVectors(t)

	events, err := ParseEventLog(rawLog)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replayed, extends, err := ReplayRTMR3(events)
	if err != nil {
		t.Fatalf("ReplayRTMR3: %v", err)
	}
	if extends != wantExtends {
		t.Errorf("extends = %d, want %d — the event-type filter is wrong", extends, wantExtends)
	}
	fromQuote, ok := QuoteRTMR(quote, 3)
	if !ok {
		t.Fatalf("quote is %d bytes — too short for RTMR3", len(quote))
	}
	if !bytesEqual(replayed, fromQuote) {
		t.Errorf("replay does not match the quote\n replayed: %x\n in quote: %x", replayed, fromQuote)
	}
}

// The filter is `event_type`, never `imr`, and on the captured fixture
// the two select the identical set — so the fixture cannot distinguish
// them and every count-based assertion passes either way.
//
// These two events are chosen so the predicates disagree in both
// directions. dstack's own verifier keys on event_type
// (sdk/go/ratls/ratls.go), and the boot events in IMR 0-2 follow a
// different digest convention, so a replay that filtered by register
// would fold in events whose digests it computed the wrong way and
// land on a wrong-but-well-formed 48-byte value.
func TestReplayFiltersOnEventTypeNotIMR(t *testing.T) {
	// imr==3 but NOT a runtime event: an imr-filtering implementation
	// extends this; a correct one skips it and finds nothing to fold.
	onlyIMR3 := []Event{{IMR: 3, EventType: 0x80000001, Event: "boot", EventPayload: "aa"}}
	if _, _, err := ReplayRTMR3(onlyIMR3); err != ErrEmptyReplay {
		t.Errorf("an imr==3 non-runtime event was extended: err = %v, want ErrEmptyReplay", err)
	}

	// A runtime event on another register: an imr-filtering
	// implementation skips this one, a correct one folds it in.
	elsewhere := []Event{{IMR: 1, EventType: DstackRuntimeEventType, Event: "x", EventPayload: "bb"}}
	_, extends, err := ReplayRTMR3(elsewhere)
	if err != nil {
		t.Fatalf("ReplayRTMR3: %v", err)
	}
	if extends != 1 {
		t.Errorf("extends = %d, want 1 — a runtime event was skipped because of its imr", extends)
	}
}

func TestVerifyEventLog_RecoversMeasurements(t *testing.T) {
	rawLog, quote := loadVectors(t)

	m, err := VerifyEventLog(rawLog, quote)
	if err != nil {
		t.Fatalf("VerifyEventLog: %v", err)
	}
	// Both measurements a verifier gates on must be recoverable from
	// the replay alone. os-image-hash being a NAMED event is what
	// settled whether the bundle needed a self-reported field for it
	// (it does not) — so this assertion is load-bearing for the wire
	// shape, not only for the verifier.
	for _, name := range []string{EventComposeHash, EventOSImageHash} {
		v, ok := m[name]
		if !ok {
			t.Errorf("%q missing from the replayed measurements (have %v)", name, keys(m))
			continue
		}
		if len(v) != 64 {
			t.Errorf("%q = %q, want a 32-byte hex digest", name, v)
		}
	}
	// The captured CVM booted the release OS image dstack-0.5.9. Pinned
	// so a vector recaptured on a DEV image — where every other check
	// passes identically — is caught at the fixture rather than in
	// production.
	if got := m[EventOSImageHash]; got != "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033" {
		t.Errorf("os-image-hash = %q; recapture on a release image, not a dev one", got)
	}
}

// TestReplayGuards is the anti-vacuity suite. Each case is a way the
// replay produces a plausible value that compares equal for the wrong
// reason, and each must be an ERROR rather than something a caller
// could compare.
func TestReplayGuards(t *testing.T) {
	rawLog, quote := loadVectors(t)

	t.Run("zero extends", func(t *testing.T) {
		// A log whose events are all non-runtime replays to 48 zero
		// bytes. Against an unmeasured (zero) RTMR3 that compares
		// EQUAL, so returning the value at all is the bug.
		events := []Event{{IMR: 0, EventType: 0x80000001, Event: "boot", EventPayload: "aabb"}}
		if _, _, err := ReplayRTMR3(events); err != ErrEmptyReplay {
			t.Errorf("err = %v, want ErrEmptyReplay", err)
		}
	})

	t.Run("undecodable payload", func(t *testing.T) {
		events, err := ParseEventLog(rawLog)
		if err != nil {
			t.Fatalf("ParseEventLog: %v", err)
		}
		// Corrupt one runtime event's payload. Skipping it silently
		// would yield a partial replay — a wrong 48-byte value
		// indistinguishable from a correct one.
		corrupted := false
		for i := range events {
			if events[i].EventType == DstackRuntimeEventType && events[i].EventPayload != "" {
				events[i].EventPayload = "not-hex"
				corrupted = true
				break
			}
		}
		if !corrupted {
			t.Fatal("no runtime event with a payload to corrupt — the fixture changed shape")
		}
		if _, _, err := ReplayRTMR3(events); !strings.Contains(err.Error(), ErrUndecodablePayload.Error()) {
			t.Errorf("err = %v, want ErrUndecodablePayload", err)
		}
	})

	t.Run("all-zero rtmr3 in quote", func(t *testing.T) {
		// The mirror case: a genuine log against a quote whose RTMR3
		// was never measured. VerifyEventLog must refuse rather than
		// compare, since an empty replay would match it.
		zeroed := make([]byte, len(quote))
		copy(zeroed, quote)
		off := quoteHeaderLen + bodyRTMR0 + 3*rtmrLen
		for i := off; i < off+rtmrLen; i++ {
			zeroed[i] = 0
		}
		if _, err := VerifyEventLog(rawLog, zeroed); err != ErrZeroRTMR {
			t.Errorf("err = %v, want ErrZeroRTMR", err)
		}
	})

	t.Run("quote too short to hold RTMR3", func(t *testing.T) {
		// The branch was unexecuted, and it fails OPEN under one edit:
		// returning the measurements with a nil error hands a verifier
		// a compose-hash and an os-image-hash compared against nothing.
		// The bytes are operator-supplied and reach here after only an
		// 8-byte length check.
		m, err := VerifyEventLog(rawLog, quote[:400])
		if !errors.Is(err, ErrShortQuote) {
			t.Errorf("err = %v, want ErrShortQuote", err)
		}
		if m != nil {
			t.Errorf("measurements returned alongside the error: %v — a caller "+
				"ignoring err would gate on values nothing verified", m)
		}
	})

	t.Run("mismatched log", func(t *testing.T) {
		// An appended runtime event changes the accumulator, so a log
		// that is not the one the hardware measured must not verify.
		tampered := strings.TrimSuffix(strings.TrimSpace(rawLog), "]") +
			`,{"imr":3,"event_type":134217729,"digest":"","event":"extra","event_payload":"00"}]`
		if _, err := VerifyEventLog(tampered, quote); err == nil {
			t.Error("an appended event verified; the replay is not binding the log")
		}
	})

	t.Run("digest field is ignored", func(t *testing.T) {
		// The original bug, pinned: dstack leaves `digest` empty, so an
		// implementation that READS it extends with nothing. Filling
		// the field with garbage must not move the result — if it does,
		// something is reading it.
		events, err := ParseEventLog(rawLog)
		if err != nil {
			t.Fatalf("ParseEventLog: %v", err)
		}
		before, _, err := ReplayRTMR3(events)
		if err != nil {
			t.Fatalf("ReplayRTMR3: %v", err)
		}
		for i := range events {
			events[i].Digest = strings.Repeat("ff", rtmrLen)
		}
		after, _, err := ReplayRTMR3(events)
		if err != nil {
			t.Fatalf("ReplayRTMR3 after: %v", err)
		}
		if !bytesEqual(before, after) {
			t.Error("the log's own digest field changed the replay — it must be computed, not read")
		}
	})
}

func TestQuoteFields(t *testing.T) {
	_, quote := loadVectors(t)

	if got, ok := QuoteTEEType(quote); !ok || got != TEETypeTDX {
		t.Errorf("QuoteTEEType = %#x (ok=%v), want %#x", got, ok, TEETypeTDX)
	}

	// The VALUE, not just ok. bodyRTMR0 and bodyReportData are both
	// anchored indirectly — one by the replay match, the other by the
	// padding check — so MRTD is the only register whose offset nothing
	// else would catch if it moved. Cross-checked against the
	// `tcb_info.mrtd` in the same capture's /Info response, which is an
	// independent source for it rather than this code agreeing with
	// itself.
	const wantMRTD = "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077"
	mrtd, ok := QuoteMRTD(quote)
	if !ok {
		t.Fatal("QuoteMRTD failed on a real quote")
	}
	if got := hex.EncodeToString(mrtd); got != wantMRTD {
		t.Errorf("MRTD\n got: %s\nwant: %s", got, wantMRTD)
	}

	// The FIELD WIDTH, asserted against the hardware rather than against
	// the constant that describes it. ReportDataLen is what the loop
	// below iterates to, so shrinking the constant would shrink the loop
	// with it and the property it proves would narrow silently.
	rd, ok := QuoteReportData(quote)
	if !ok {
		t.Fatal("QuoteReportData failed on a real quote")
	}
	if len(rd) != 64 {
		t.Errorf("REPORTDATA is %d bytes, want 64 — the TDX field width is fixed by hardware", len(rd))
	}

	// THE CAPTURE IS NOW A NEGATIVE FIXTURE, and deliberately so. It was
	// taken from a pre-9.9 node, so its upper half is the zero padding
	// the guest agent wrote — exactly the shape the 9.9 flag day refuses
	// (§3). This is the best possible test of that rule: a real,
	// hardware-signed quote of the kind that must now be turned away,
	// rather than a hand-built approximation of one.
	//
	// It must fail as ErrAuxBindingAbsent and not as a generic malformed
	// quote, because the two send an operator to different remedies:
	// one says upgrade the node, the other says the quote is broken.
	//
	// The lower half comes back with the error, so a verifier can check the
	// key first. Without it the proxy compares a zero key binding and
	// reports every out-of-date node as key_binding_mismatch.
	const wantBinding = "1d2f9ae2df75959798e567366d3412b7bdbc4f24593a46e817a85d954c97aa2d"
	absent, err := SplitReportData(quote)
	if !errors.Is(err, ErrAuxBindingAbsent) {
		t.Errorf("SplitReportData on the pre-9.9 capture returned %v, want ErrAuxBindingAbsent — "+
			"a zero upper half is the flag day's refusal, not an accepted shape", err)
	}
	if got := hex.EncodeToString(absent.KeyBinding[:]); got != wantBinding {
		t.Errorf("KeyBinding returned with ErrAuxBindingAbsent\n got: %s\nwant: %s", got, wantBinding)
	}

	// SYNTHETIC, and the only synthetic quote in this file. Splicing an
	// aux binding into the capture invalidates its signature, so this
	// value is usable ONLY for the byte-level split below and must never
	// reach signature or collateral verification. A genuine 9.9 capture
	// replaces it once a 9.9 node runs on real TDX hardware.
	noPosture, err := HPosture(nil)
	if err != nil {
		t.Fatalf("HPosture(nil): %v", err)
	}
	aux := AuxBinding(42, HAppPending(), noPosture, nil)
	synthetic := withAuxHalf(quote, aux[:])

	halves, err := SplitReportData(synthetic)
	if err != nil {
		t.Fatalf("SplitReportData rejected a well-formed 9.9 quote: %v", err)
	}
	// THE VALUES, not just the widths. Both halves are 32 bytes, so a
	// split that returned them swapped is indistinguishable by length —
	// and a key-binding check comparing the WRONG half would then pass
	// or fail for reasons unrelated to the key. Arity is not identity.
	if got := hex.EncodeToString(halves.KeyBinding[:]); got != wantBinding {
		t.Errorf("KeyBinding\n got: %s\nwant: %s (the low half, from real hardware)", got, wantBinding)
	}
	if halves.AuxBinding != aux {
		t.Errorf("AuxBinding\n got: %x\nwant: %x (the high half, as spliced)", halves.AuxBinding, aux)
	}

	// EVERY byte of the upper half, not just the first — the mirror of
	// the pre-9.9 version of this loop, which asserted the opposite.
	// Narrowing the scan to `allZero(rd[32:36])` would wrongly REFUSE a
	// node whose aux binding happens to start with four zero bytes,
	// which is one catalog in 2^32 and would present as an unroutable
	// node with a crypto error. A single non-zero byte anywhere in the
	// range is a populated upper half.
	//
	// LITERALS, not ReportDataLen — see the width assertion above. A loop
	// bounded by the constant under test walks exactly as far as that
	// constant claims the field is, so shrinking it shrinks the proof.
	for i := 32; i < 64; i++ {
		probe := make([]byte, len(quote))
		copy(probe, quote)
		probe[quoteHeaderLen+bodyReportData+i] = 0x01
		h, err := SplitReportData(probe)
		if err != nil {
			t.Errorf("SplitReportData refused an upper half whose only non-zero byte is %d: %v — "+
				"the all-zero scan must cover the whole range", i, err)
			continue
		}
		if h.AuxBinding[i-32] != 0x01 {
			t.Errorf("AuxBinding lost the byte at offset %d: got %x", i-32, h.AuxBinding)
		}
	}
}

// withAuxHalf returns a copy of quote with the upper 32 bytes of
// report_data replaced. The result is NOT signature-valid — see the
// caller.
func withAuxHalf(quote, aux []byte) []byte {
	out := make([]byte, len(quote))
	copy(out, quote)
	copy(out[quoteHeaderLen+bodyReportData+32:quoteHeaderLen+bodyReportData+64], aux)
	return out
}

func TestQuoteFields_ShortQuote(t *testing.T) {
	// Every accessor must report failure rather than panic on a
	// truncated quote: the bytes are operator-supplied over the network.
	//
	// EACH LENGTH IS ONE BYTE SHORT OF WHAT THAT ACCESSOR NEEDS, not a
	// single tiny buffer. A 100-byte quote sits below every threshold at
	// once, so it exercises no accessor's actual boundary — a guard
	// weakened from `len < off+width` to `len < off` still rejects it,
	// then slices out of range and panics on any input between the two.
	cases := []struct {
		name string
		size int
		call func([]byte) bool // returns ok
	}{
		{"QuoteTEEType", headerTEEType + 4 - 1, func(b []byte) bool { _, ok := QuoteTEEType(b); return ok }},
		{"QuoteMRTD", quoteHeaderLen + bodyMRTD + rtmrLen - 1, func(b []byte) bool { _, ok := QuoteMRTD(b); return ok }},
		{"QuoteRTMR3", quoteHeaderLen + bodyRTMR0 + 3*rtmrLen + rtmrLen - 1, func(b []byte) bool { _, ok := QuoteRTMR(b, 3); return ok }},
		{"QuoteReportData", quoteHeaderLen + bodyReportData + ReportDataLen - 1, func(b []byte) bool { _, ok := QuoteReportData(b); return ok }},
		{"SplitReportData", quoteHeaderLen + bodyReportData + ReportDataLen - 1, func(b []byte) bool { _, err := SplitReportData(b); return err == nil }},
	}
	for _, tc := range cases {
		if tc.call(make([]byte, tc.size)) {
			t.Errorf("%s accepted a %d-byte quote (one short of what it reads)", tc.name, tc.size)
		}
	}

	// WHICH refusal, not merely that it refused. The table above asks only
	// whether err is non-nil, so swapping the two sentinels inside
	// SplitReportData passes it — and the whole point of having two is
	// that they send an operator to different remedies. The boundary is
	// the sharpest place to pin them: one byte short the field is
	// unreadable, and at exactly the width it is readable and the
	// complaint MOVES to the upper half. A guard that lost its width term
	// would report aux_binding_absent on both sides.
	//
	// The TS mirror of this lives in attest-vectors.test.ts; the golden
	// file cannot carry report_data_absent, because it holds one quote and
	// that quote is full-width.
	const rdEnd = quoteHeaderLen + bodyReportData + ReportDataLen
	if _, err := SplitReportData(make([]byte, rdEnd-1)); !errors.Is(err, ErrReportDataAbsent) {
		t.Errorf("one byte short of the field: got %v, want ErrReportDataAbsent", err)
	}
	if _, err := SplitReportData(make([]byte, rdEnd)); !errors.Is(err, ErrAuxBindingAbsent) {
		t.Errorf("exactly at the field width: got %v, want ErrAuxBindingAbsent "+
			"(the field is readable and all zero, so the complaint moves to the upper half)", err)
	}

	if _, ok := QuoteTEEType(nil); ok {
		t.Error("QuoteTEEType accepted a nil quote")
	}
	if _, ok := QuoteRTMR(nil, 0); ok {
		t.Error("QuoteRTMR accepted a nil quote")
	}
}

// The register index is bounds-checked independently of the length, and
// only a FULL-LENGTH quote can show that. Against a short buffer the
// length check rejects every index, so an out-of-range case there
// passes whether or not the range check exists — and with the range
// check gone, n=4 on a real quote returns 48 bytes of report_data as
// "RTMR4" with ok=true, while a negative n reads backwards into the
// header or panics.
func TestQuoteRTMR_RegisterRange(t *testing.T) {
	_, quote := loadVectors(t)

	for _, n := range []int{-1, 4, 99} {
		if v, ok := QuoteRTMR(quote, n); ok {
			t.Errorf("QuoteRTMR(realQuote, %d) = %x (ok), want rejected", n, v)
		}
	}
	// The in-range half, so the test cannot pass by rejecting everything.
	for n := 0; n <= 3; n++ {
		if _, ok := QuoteRTMR(quote, n); !ok {
			t.Errorf("QuoteRTMR(realQuote, %d) was rejected", n)
		}
	}
}

// RuntimeMeasurements must read ONLY runtime events, and this is the
// gap with teeth. Every non-runtime event in the captured log has an
// empty `event` name, so the type check and the name check are
// redundant on real data and dropping the type check breaks nothing
// visible.
//
// It is directly exploitable. A non-runtime event contributes nothing
// to the replay, so an operator can prepend one carrying an
// allowlisted `compose-hash`: RTMR3 still matches the quote, the
// verifier's replay passes, and first-wins then hands it the injected
// value instead of the measured one. The measurement check would be
// reading a field the hardware never covered.
func TestRuntimeMeasurements_IgnoresNonRuntimeEvents(t *testing.T) {
	events := []Event{
		// Not a runtime event, but named and ordered first.
		{IMR: 0, EventType: 0x00000004, Event: EventComposeHash, EventPayload: "dead"},
		// The measured one.
		{IMR: 3, EventType: DstackRuntimeEventType, Event: EventComposeHash, EventPayload: "beef"},
	}
	if got := RuntimeMeasurements(events)[EventComposeHash]; got != "beef" {
		t.Errorf("compose-hash = %q, want %q — a non-runtime event reached the "+
			"measurement map, so an unmeasured value can displace a measured one", got, "beef")
	}
}

func TestRuntimeMeasurements_FirstWins(t *testing.T) {
	// A second event with the same name must not displace the first.
	// Appending is the cheap attack: the replay still matches only if
	// the appended event was measured, but a map that let the last
	// value win would read a friendlier compose-hash than the one the
	// hardware covered.
	events := []Event{
		{EventType: DstackRuntimeEventType, Event: EventComposeHash, EventPayload: "AABB"},
		{EventType: DstackRuntimeEventType, Event: EventComposeHash, EventPayload: "ccdd"},
	}
	if got := RuntimeMeasurements(events)[EventComposeHash]; got != "aabb" {
		t.Errorf("compose-hash = %q, want the first occurrence %q", got, "aabb")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
