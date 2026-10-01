/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package attest holds the measurement arithmetic both sides of a TEE
// verification have to agree on: parsing an Intel TDX quote and
// replaying a dstack runtime event log into RTMR3.
//
// It lives in the protocol module rather than in either consumer
// because BOTH run it, for opposite reasons. The node replays its own
// log at mint time to refuse publishing evidence no verifier could
// accept; the proxy replays it to decide whether to route. Two copies
// would let a node self-certify under arithmetic the verifier does not
// share — the node passes its own check and is silently dropped by
// every relying party, with nothing in either log naming the
// disagreement.
//
// Golden-vectored against a real CVM capture in testdata/ for the same
// reason `proto/testdata/vectors.json` exists: this is derivation
// arithmetic where a wrong implementation produces a well-formed,
// plausible, and entirely incorrect 48-byte value.
//
// See proto/SPEC.md §3e "Measurement replay".
package attest

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// DstackRuntimeEventType is the event type dstack stamps on the
// runtime events it extends into RTMR3.
//
// Matching on it — rather than on `imr == 3` — is what dstack's own
// verifier does (sdk/go/ratls/ratls.go), and the two do NOT select the
// same set. The boot events in IMR 0-2 follow a different digest
// convention entirely, so a replay that filtered by IMR would extend
// events whose digests it computed the wrong way and land on a
// wrong-but-well-formed value.
const DstackRuntimeEventType uint32 = 0x08000001

// rtmrLen is the width of a TDX runtime measurement register: SHA-384.
const rtmrLen = 48

// Named runtime events a verifier gates on. They are read off the
// REPLAYED log, never off any self-reported field — see
// inject.TEEEvidenceBundle.EventLog.
const (
	EventComposeHash = "compose-hash"
	EventOSImageHash = "os-image-hash"
	EventAppID       = "app-id"
	EventInstanceID  = "instance-id"
	EventKeyProvider = "key-provider"
)

// Errors from ReplayRTMR3. Each corresponds to a way the replay can
// produce a plausible-but-meaningless value, and each is returned
// rather than papered over: a caller that compared anyway would be
// comparing two things that agree for the wrong reason.
var (
	// ErrEmptyReplay means the log contained no runtime events at all,
	// so the "replayed" value is 48 zero bytes. Against a quote whose
	// RTMR3 is also zero — an uninitialized or simulated register —
	// that compares EQUAL and reads as a pass.
	ErrEmptyReplay = errors.New("attest: event log extended zero runtime events")

	// ErrUndecodablePayload means at least one runtime event's payload
	// was not hex. Skipping it silently yields a partial replay: a
	// wrong 48-byte value indistinguishable from a correct one.
	ErrUndecodablePayload = errors.New("attest: event log has an undecodable event payload")

	// ErrZeroRTMR means the quote's RTMR3 is all zero, which no
	// genuinely measured CVM produces. Comparing against it would let
	// an all-zero replay pass.
	ErrZeroRTMR = errors.New("attest: quote's RTMR3 is all zero")

	// ErrShortQuote means the quote is too short to hold the register
	// the log would be compared against.
	//
	// A sentinel rather than an inline error because this branch fails
	// OPEN under one plausible edit: returning the measurements with a
	// nil error hands a verifier a compose-hash and an os-image-hash
	// that were compared against nothing at all. The bytes are
	// operator-supplied and reach here after only an 8-byte length
	// check, so the branch is reachable by anyone.
	ErrShortQuote = errors.New("attest: quote is too short to hold RTMR3")
)

// Event is one entry of a dstack runtime event log.
//
// Digest is decoded but deliberately never used. dstack leaves it
// EMPTY on every runtime event, so an implementation that reads it
// extends with nothing — the field is kept here only so its emptiness
// is visible to anyone reading the struct and wondering where it went.
type Event struct {
	IMR          uint32 `json:"imr"`
	EventType    uint32 `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
}

// ParseEventLog decodes the raw JSON array carried as
// inject.TEEEvidenceBundle.EventLog.
func ParseEventLog(raw string) ([]Event, error) {
	var events []Event
	if err := json.Unmarshal([]byte(raw), &events); err != nil {
		return nil, fmt.Errorf("attest: event log is not a JSON array of events: %w", err)
	}
	return events, nil
}

// ReplayRTMR3 recomputes RTMR3 from a dstack event log, following
// dstack's rule exactly (sdk/go/ratls/ratls.go verifyRTMR3, matching
// the Rust cc_eventlog::runtime_events::replay_events::<Sha384>):
//
//	digest = SHA-384( le32(event_type) || ":" || event || ":" || payload )
//	rtmr   = SHA-384( rtmr || digest )       from 48 zero bytes
//
// THE PER-EVENT DIGEST IS COMPUTED, NOT READ. dstack leaves the log's
// own `digest` field empty on every runtime event — measured on a live
// CVM 2026-08-25, where all ten matching entries carried "digest":"".
// An implementation that trusts that field extends with nothing and
// lands on a wrong-but-well-formed 48-byte value: on that capture it
// produced 7e1f442b… where the truth was 1fa4f8ce… — an EARLIER capture
// than the one now in testdata, so don't look for those two values
// there. Nothing errors, the
// value is the right length, and the verifier reports a mismatch it
// will be believed about. That is the failure this comment exists to
// stop recurring, and testdata/ is what makes it detectable.
//
// event_type is little-endian because TDX CVMs are x86_64 and dstack
// packs it with to_ne_bytes(); the payload is hex in the JSON and
// hashed as raw bytes.
//
// Returns ErrUndecodablePayload or ErrEmptyReplay rather than a value a
// caller could compare. extends is the number of events folded in, for
// callers that want to log the shape of what they verified.
func ReplayRTMR3(events []Event) (value []byte, extends int, err error) {
	acc := make([]byte, rtmrLen)
	for i, e := range events {
		if e.EventType != DstackRuntimeEventType {
			continue
		}
		payload, decErr := hex.DecodeString(strings.TrimPrefix(e.EventPayload, "0x"))
		if decErr != nil {
			return nil, extends, fmt.Errorf("%w: event %d (%q): %v",
				ErrUndecodablePayload, i, e.Event, decErr)
		}
		var et [4]byte
		binary.LittleEndian.PutUint32(et[:], e.EventType)

		dh := sha512.New384()
		dh.Write(et[:])
		dh.Write([]byte(":"))
		dh.Write([]byte(e.Event))
		dh.Write([]byte(":"))
		dh.Write(payload)

		h := sha512.New384()
		h.Write(acc)
		h.Write(dh.Sum(nil))
		acc = h.Sum(nil)
		extends++
	}
	if extends == 0 {
		return nil, 0, ErrEmptyReplay
	}
	return acc, extends, nil
}

// VerifyEventLog is the whole check as one call: parse the log, replay
// it, and confirm the result equals the RTMR3 the hardware signed
// inside the quote. On success it returns the named runtime events the
// replay covered, which is the ONLY sanctioned source for compose-hash
// and os-image-hash — reading them from anywhere else skips the step
// that makes them mean anything.
//
// The all-zero RTMR3 guard is here rather than at the call site
// because that is where it is load-bearing: an empty replay and an
// unmeasured register agree, and a caller doing `bytes.Equal(replayed,
// fromQuote)` has no way to notice.
func VerifyEventLog(rawLog string, quote []byte) (map[string]string, error) {
	events, err := ParseEventLog(rawLog)
	if err != nil {
		return nil, err
	}
	replayed, _, err := ReplayRTMR3(events)
	if err != nil {
		return nil, err
	}
	fromQuote, ok := QuoteRTMR(quote, 3)
	if !ok {
		return nil, fmt.Errorf("%w: got %d bytes", ErrShortQuote, len(quote))
	}
	if allZero(fromQuote) {
		return nil, ErrZeroRTMR
	}
	if !bytesEqual(replayed, fromQuote) {
		return nil, fmt.Errorf("attest: RTMR3 replay does not match the quote (replayed %x, quote %x)",
			replayed, fromQuote)
	}
	return RuntimeMeasurements(events), nil
}

// RuntimeMeasurements collects the named runtime events into a map
// keyed by event name, with hex payloads lowercased and unprefixed.
//
// A duplicate name keeps the FIRST occurrence. dstack emits each once,
// so a second is either a platform change worth noticing or an attempt
// to have a later, friendlier value win a lookup; keeping the first
// means an appended event cannot displace a measured one.
func RuntimeMeasurements(events []Event) map[string]string {
	out := make(map[string]string)
	for _, e := range events {
		if e.EventType != DstackRuntimeEventType || e.Event == "" {
			continue
		}
		if _, seen := out[e.Event]; seen {
			continue
		}
		out[e.Event] = strings.ToLower(strings.TrimPrefix(e.EventPayload, "0x"))
	}
	return out
}

// ---------------------------------------------------------------------------
// TDX v4 quote field access
// ---------------------------------------------------------------------------

// TDX v4 quote layout: a 48-byte header followed by the TD report
// body. Offsets are into the body.
const (
	quoteHeaderLen = 48

	bodyMRTD       = 136
	bodyRTMR0      = 328
	bodyReportData = 520

	// headerTEEType is the offset of the 4-byte TEE type in the quote
	// HEADER (not the body). 0x81 is TDX; 0x00 is SGX.
	headerTEEType = 4

	// TEETypeTDX is the header's tee_type value for Intel TDX.
	TEETypeTDX uint32 = 0x81

	// ReportDataLen is the width of the hardware REPORTDATA field. Each
	// of the two bindings it carries is 32 bytes — see SplitReportData.
	ReportDataLen = 64
)

// QuoteTEEType reads the TEE type from the quote header.
//
// This is how a verifier decides which vendor chain to check the quote
// against. It must never be decided by the bundle's `mode` string: that
// is node-authored, so reading it would hand the operator the choice of
// which chain their evidence is judged against.
func QuoteTEEType(quote []byte) (uint32, bool) {
	if len(quote) < headerTEEType+4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(quote[headerTEEType : headerTEEType+4]), true
}

// QuoteRTMR extracts RTMR[n] (n in 0..3) from a TDX v4 quote.
func QuoteRTMR(quote []byte, n int) ([]byte, bool) {
	if n < 0 || n > 3 {
		return nil, false
	}
	off := quoteHeaderLen + bodyRTMR0 + n*rtmrLen
	if len(quote) < off+rtmrLen {
		return nil, false
	}
	return quote[off : off+rtmrLen], true
}

// QuoteMRTD extracts MRTD, the CVM's initial-measurement register.
func QuoteMRTD(quote []byte) ([]byte, bool) {
	off := quoteHeaderLen + bodyMRTD
	if len(quote) < off+rtmrLen {
		return nil, false
	}
	return quote[off : off+rtmrLen], true
}

// QuoteReportData extracts the full 64-byte REPORTDATA field.
func QuoteReportData(quote []byte) ([]byte, bool) {
	off := quoteHeaderLen + bodyReportData
	if len(quote) < off+ReportDataLen {
		return nil, false
	}
	return quote[off : off+ReportDataLen], true
}

// TDX v4 ECDSA signature-data layout, walked by QuotePCKCertChain.
// Everything past the TD report body is variable-length, so these are
// sizes and tags rather than absolute offsets.
const (
	// bodyLen is the TD report body: the quote's only other
	// fixed-width region, sitting between the header and the
	// signature data.
	//
	// DERIVED, not restated as 584. The body's geometry is already
	// pinned by the offsets above, and REPORTDATA is its last field,
	// so writing the total independently would be a second copy of the
	// same fact in a second const block — free to drift, and drifting
	// silently, since a wrong total just moves the walk onto bytes
	// that fail to parse.
	bodyLen = bodyReportData + ReportDataLen

	// The signature data opens with a 64-byte ECDSA signature over the
	// quote and the 64-byte attestation public key, then the QE
	// certification data.
	sigECDSALen  = 64
	sigPubKeyLen = 64

	// certTypeQEReport is the outer certification-data tag on every
	// TDX v4 quote: the payload is a QE report plus a nested
	// certification-data blob.
	certTypeQEReport = 6
	// certTypePCKChain marks a nested payload that IS the PEM chain.
	certTypePCKChain = 5

	// Fixed-width prefix of a type-6 payload: the QE report and the
	// signature over it, before the variable-length QE auth data.
	qeReportLen    = 384
	qeReportSigLen = 64
)

// QuotePCKCertChain returns the PEM certificate chain the platform's
// PCK key is issued under, carried inside the quote's certification
// data. It is the input to an FMSPC lookup — which collateral set this
// quote must be judged against.
//
// ok is false for anything this walk does not recognize: a quote that
// is not TDX, a truncated quote, a length field that overruns, a
// certification-data type other than the PEM-chain form (Intel defines
// encrypted-PPID variants whose chain must be fetched from a PCCS
// instead; dstack CVMs do not produce them), or a chain of zero length.
// When ok is true the result is non-empty — callers test the boolean,
// so an empty-but-ok chain would reach a PEM parser as a silent
// nothing.
//
// The returned slice is a COPY. It would otherwise alias the caller's
// quote buffer with spare capacity behind it, so an append by any
// downstream holder would write into the quote the signature covers.
//
// Two shape notes for consumers, both live on real hardware: the chain
// is leaf-first (only the leaf PCK certificate carries an FMSPC), and
// it is NUL-TERMINATED — the declared length includes the trailing
// 0x00. Go's pem.Decode tolerates the trailing byte; a consumer
// splitting on "END CERTIFICATE" may not.
//
// GO ONLY, and deliberately not mirrored in proto/ts. The browser
// verifier gets the equivalent from @phala/dcap-qvl's own quote
// parser, so a TS twin here would be a second implementation of
// somebody else's parser rather than a parity requirement — the
// package doc's "both sides run this" is about the replay arithmetic,
// not about this accessor.
//
// NOTHING HERE IS TRUSTED, and that is what keeps a hand-rolled walk
// appropriate for a security-adjacent path. The bytes decide which
// documents a caller goes on to FETCH; they are not evidence and are
// never verified against. A wrong answer yields collateral that does
// not match, so the quote fails to verify — closed, never open — and
// on the node it degrades to publishing no collateral at all, which is
// the pre-feature state. Contrast SplitReportData, where the bytes are
// the claim.
func QuotePCKCertChain(quote []byte) ([]byte, bool) {
	// STRUCTURAL, not probabilistic. Everything below is the TDX v4
	// ECDSA-P256 layout; an SGX v3 or a future v5 quote has a different
	// one. Without this gate such a quote is rejected only by luck —
	// whichever byte happens to sit where the type-6 tag is read — so
	// the refusal would be correct today and unexplained tomorrow.
	if t, ok := QuoteTEEType(quote); !ok || t != TEETypeTDX {
		return nil, false
	}
	// Cursor past header + body + the 4-byte signature-data length.
	off := quoteHeaderLen + bodyLen
	sig, ok := lenPrefixed(quote, off, 4)
	if !ok {
		return nil, false
	}
	// Past the ECDSA signature and attestation key sits the outer
	// certification data: a 2-byte type and a 4-byte length.
	inner, ok := certData(sig, sigECDSALen+sigPubKeyLen, certTypeQEReport)
	if !ok {
		return nil, false
	}
	// The type-6 payload: QE report, its signature, then a 2-byte
	// length-prefixed auth data, then the nested certification data.
	auth, ok := lenPrefixed(inner, qeReportLen+qeReportSigLen, 2)
	if !ok {
		return nil, false
	}
	// lenPrefixed returned the auth data itself; the nested block
	// starts immediately after it.
	nested := qeReportLen + qeReportSigLen + 2 + len(auth)
	chain, ok := certData(inner, nested, certTypePCKChain)
	if !ok || len(chain) == 0 {
		return nil, false
	}
	// Copied rather than returned as a sub-slice of the caller's quote:
	// see the godoc. A zero-length declared chain is already refused
	// above, so this never returns an empty non-nil slice.
	return append([]byte(nil), chain...), true
}

// certData reads a (uint16 type, uint32 length, bytes) block at off
// and returns its payload, requiring the type to be wantType.
func certData(b []byte, off int, wantType uint16) ([]byte, bool) {
	if off < 0 || off+6 > len(b) {
		return nil, false
	}
	if binary.LittleEndian.Uint16(b[off:off+2]) != wantType {
		return nil, false
	}
	return lenPrefixed(b, off+2, 4)
}

// lenPrefixed reads a little-endian length of width bytes at off and
// returns exactly that many bytes following it.
//
// The length is attacker-controlled, so it is checked against the
// remaining input before it is used to slice — an overrun must be a
// false, never a panic on a path that runs inside a request handler.
func lenPrefixed(b []byte, off, width int) ([]byte, bool) {
	if off < 0 || off+width > len(b) {
		return nil, false
	}
	var n uint64
	switch width {
	case 2:
		n = uint64(binary.LittleEndian.Uint16(b[off : off+2]))
	case 4:
		n = uint64(binary.LittleEndian.Uint32(b[off : off+4]))
	default:
		return nil, false
	}
	start := off + width
	// Compared in uint64 so a length near 2^32 cannot wrap when added
	// to start on a 32-bit build.
	if uint64(len(b)-start) < n {
		return nil, false
	}
	return b[start : start+int(n)], true
}

// ReportDataHalves is the 64-byte hardware field split into the two
// independent commitments it carries.
//
// Both are [32]byte rather than []byte so that comparing one against a
// freshly computed binding is `==` on a fixed width — a slice compare is
// where a truncated or empty candidate passes a length nobody checked.
// Named fields rather than two positional returns because both are
// [32]byte: a caller that swapped them would still compile.
type ReportDataHalves struct {
	// KeyBinding is the lower 32 bytes: SHA-256(ephemeral age pubkey ||
	// be64(operator_id)). Compare against ReportData, recomputed from a
	// key and an id the verifier resolved INDEPENDENTLY of the bundle.
	KeyBinding [32]byte

	// AuxBinding is the upper 32 bytes: SHA-256 over the node id, H_app
	// and the nonce. SplitReportData checks only that it is not all zero;
	// ReportDataHalves.VerifyAux checks its value against the bundle.
	AuxBinding [32]byte
}

// Refusals from SplitReportData. Verifiers report them under different
// tags: a truncated quote is malformed evidence, and an all-zero upper
// half is a node that needs upgrading.
var (
	// ErrReportDataAbsent: the quote is too short to hold report_data.
	ErrReportDataAbsent = errors.New("attest: quote carries no report_data field")

	// ErrAuxBindingAbsent: the upper 32 bytes are all zero, which is what
	// a pre-9.9 node mints. Verifiers report it as aux_binding_absent so
	// the operator sees that the node needs an upgrade.
	ErrAuxBindingAbsent = errors.New("attest: report_data upper half is all zero — node predates proto 9.9")
)

// SplitReportData returns both halves of report_data.
//
// It refuses a quote too short to hold the field (ErrReportDataAbsent) and
// an all-zero upper half (ErrAuxBindingAbsent). There is no option to
// accept a zero upper half, so no input can select pre-9.9 behaviour.
//
// With ErrAuxBindingAbsent it still returns KeyBinding, so a verifier checks
// the lower half first; a quote whose key binding is also wrong is reported
// as key_binding_mismatch.
//
// A non-zero upper half is only known to be populated. Before 9.9 the upper
// half had to be zero, because the quote signature covers all 64 bytes and
// an unchecked half would let a node get 32 bytes of its choice signed by
// real hardware. That protection now depends on the caller calling
// ReportDataHalves.VerifyAux.
func SplitReportData(quote []byte) (ReportDataHalves, error) {
	rd, present := QuoteReportData(quote)
	if !present {
		return ReportDataHalves{}, ErrReportDataAbsent
	}
	if allZero(rd[32:]) {
		var h ReportDataHalves
		copy(h.KeyBinding[:], rd[:32])
		return h, ErrAuxBindingAbsent
	}
	var h ReportDataHalves
	copy(h.KeyBinding[:], rd[:32])
	copy(h.AuxBinding[:], rd[32:])
	return h, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// bytesEqual avoids importing bytes for one call.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
