/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Cross-implementation vectors for the measurement arithmetic, written
// to proto/testdata/attest_vectors.json and read by BOTH this file and
// proto/ts/test/attest-vectors.test.ts.
//
// Regenerate: cd proto/go && go test ./attest -run TestVectors -update
//
// WHY THIS FILE EXISTS SEPARATELY FROM dstack_test.go, which already
// verifies the replay against a real quote: that test proves the Go
// implementation is right. It cannot prove the TypeScript one agrees,
// and the client is about to make routing decisions on the same bytes.
// Every value here is one an incorrect implementation reproduces as a
// well-formed, plausible, entirely wrong 48 or 32 bytes — SHA-384 of
// the wrong preimage is still 48 bytes, and a report_data hash over
// little-endian operator ids is still 32.
//
// The INPUTS are not in this file. They are the same two capture files
// dstack_test.go reads, referenced by path, so the two implementations
// cannot end up agreeing about different bytes.
var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/attest_vectors.json")

const vectorsPath = "../../testdata/attest_vectors.json"

// The (pubkey, operator_id) the captured quote's report_data was minted
// over — the dstackprobe deployment's placeholder recipient and its
// operator id. Mirrored by proxy/internal/hayai's capturedKey /
// capturedOperatorID, which is exactly why they are published into the
// vectors: a constant that lives only in two Go test files is not
// available to a third implementation reading this capture.
//
// TestQuoteBindingIsSelfDescribing asserts they reproduce the quote's
// own lower 32 bytes, so a wrong value here fails rather than shipping a
// self-description that describes nothing.
const (
	captureBindingPubkey     = "age1probeplaceholderrecipientvalue000000000000000000"
	captureBindingOperatorID = uint64(42)
)

type replayVector struct {
	Extends  int    `json:"extends"`
	RTMR3Hex string `json:"rtmr3_hex"`
}

type quoteVector struct {
	Len           int    `json:"len"`
	TEEType       uint32 `json:"tee_type"`
	MRTDHex       string `json:"mrtd_hex"`
	RTMR0Hex      string `json:"rtmr0_hex"`
	RTMR1Hex      string `json:"rtmr1_hex"`
	RTMR2Hex      string `json:"rtmr2_hex"`
	RTMR3Hex      string `json:"rtmr3_hex"`
	ReportDataHex string `json:"report_data_hex"`
	BindingHex    string `json:"binding_hash_hex"`

	// SplitError is the refusal SplitReportData returns for this quote,
	// as a stable code both languages map to, or "" when it is accepted.
	// The capture predates 9.9, so its upper half is zero padding and the
	// code is aux_binding_absent.
	SplitError string `json:"split_error"`

	// The inputs that produced BindingHex, so a third implementation
	// reading only this file can recompute the capture's lower half.
	// Recomputing SHA-256(pubkey || be64(id)) to the quote's lower 32
	// bytes also shows that Phala hardware placed the requested value in
	// REPORTDATA as given, without hashing it.
	BindingNodePubkey string `json:"binding_node_pubkey"`
	BindingOperatorID string `json:"binding_operator_id"` // decimal string, per reportDataVector
}

// reportDataVector pins the key-binding hash. operator_id 0 and the
// 64-bit boundary are both present deliberately: a little-endian
// implementation agrees with a big-endian one on id 0 and on nothing
// else, so a single mid-range case cannot tell them apart, and an id
// above 2^32 catches a 32-bit truncation that every small id hides.
type reportDataVector struct {
	Name       string `json:"name"`
	NodePubkey string `json:"node_pubkey"`

	// A DECIMAL STRING, not a JSON number, and the max-uint64 case is
	// what forces it: JSON.parse gives JavaScript a float64, so
	// 18446744073709551615 comes back as …616 and the mirror hashes a
	// value Go never produced. Encoding it as a number made this
	// vector assert that the two implementations agree while handing
	// them different inputs — the exact failure the file exists to
	// catch, inverted.
	OperatorID string `json:"operator_id"`

	ExpectedHex string `json:"expected_hex"`
	ExpectedB64 string `json:"expected_b64"`
}

// hostileCase pins the two implementations against an event log an
// OPERATOR wrote, rather than against the one well-formed capture.
//
// This exists because a mutation pass found the gap and a live
// divergence inside it: TypeScript stripped a `0X` prefix that Go does
// not, so the same operator-authored payload decoded in the browser and
// failed in the node — two relying parties reaching opposite verdicts
// on identical evidence, which is the failure the shared module exists
// to prevent. Nothing observable was wrong, because real dstack emits
// no prefix; that is exactly what let it ship.
//
// Every case below is a shape an operator can put on the wire for free,
// and the ones that pass are as load-bearing as the ones that fail: a
// leniency added to EITHER side now turns both suites red.
//
// Go is the reference. These fields record what Go does, including its
// errors — ReplayError carries the TypeScript AttestErrorCode spelling
// so one taxonomy describes both.
type hostileCase struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	Log  string `json:"log"`

	// Empty when the replay succeeded.
	ReplayError string `json:"replay_error"`

	RTMR3Hex string `json:"rtmr3_hex"`
	Extends  int    `json:"extends"`

	// RuntimeMeasurements is pinned even for a case whose replay fails:
	// it is separately exported, and a caller that read it without
	// replaying is the mistake the whole package is arranged against.
	Measurements map[string]string `json:"measurements"`
}

// Entries are carried as the WIRE type itself rather than a vector-local
// struct. A third near-identical shape with its own field names is the
// same drift risk the alias in binding.go exists to remove: this file's
// purpose is to prove that hashing the entries a bundle actually carries
// gives this digest, and it can only do that if these ARE those entries.
//
// It also keeps weights_state a NUMBER rather than a name, so the vectors
// pin the DISCRIMINATOR BYTE that enters the digest — a mirror mapping
// names to different numbers would agree with this file and disagree with
// Go.

// hAppVector pins the model-set measurement, including the inputs Go
// REFUSES. The refusals are as load-bearing as the successes: a mirror
// that accepts a duplicate model id computes a digest for a catalog Go
// would not sign, and the divergence surfaces as a verifier rejecting a
// node its own operator can verify.
type hAppVector struct {
	Name    string       `json:"name"`
	Why     string       `json:"why"`
	Entries []ModelEntry `json:"entries"`

	// Error carries the TypeScript AttestErrorCode spelling, empty on
	// success — the same one-taxonomy rule hostileCase.ReplayError follows.
	Error string `json:"error"`
	// ExpectedHex is empty when Error is set.
	ExpectedHex string `json:"expected_hex"`
}

// auxBindingVector pins the upper 32 bytes of report_data.
type auxBindingVector struct {
	Name string `json:"name"`
	Why  string `json:"why"`

	// A DECIMAL STRING for the same reason reportDataVector.OperatorID is
	// one: node ids are uint64, JSON.parse hands JavaScript a float64, and
	// a max-uint64 case encoded as a number would feed the two
	// implementations different inputs while claiming they agree.
	NodeID string `json:"node_id"`

	HAppHex     string `json:"h_app_hex"`
	HPostureHex string `json:"h_posture_hex"`
	// NonceHex empty means ABSENT (Go nil, TS null) — distinct from the
	// all-zero nonce case below it, which is spelled out in full and must
	// produce the identical digest.
	NonceHex    string `json:"nonce_hex"`
	ExpectedHex string `json:"expected_hex"`
}

// hAppJSONVector pins H_app over entry lists given as raw JSON text, which
// each implementation decodes with its own parser. hAppVector's entries are
// marshalled from Go structs and so always carry all four keys; these cases
// cover the JSON a hostile node can send instead (missing keys, nulls, wrong
// types, lone surrogates), where Go's decoder and JSON.parse differ.
type hAppJSONVector struct {
	Name        string `json:"name"`
	Why         string `json:"why"`
	EntriesJSON string `json:"entries_json"`
	Error       string `json:"error"`
	ExpectedHex string `json:"expected_hex"`
}

// auxVerifyVector pins VerifyAux's decision: the nonce rules, the
// empty-list rule and the failure tag, which no byte-level vector reaches.
type auxVerifyVector struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// NodeID is the verifier's chain-resolved id, as a decimal string.
	NodeID string `json:"node_id"`
	// EntriesJSON is the bundle's app_models as JSON text; "" means the
	// field is absent.
	EntriesJSON string `json:"entries_json"`
	// PostureJSON is the bundle's posture as JSON text; "" means the field
	// is absent.
	PostureJSON string `json:"posture_json"`
	// EchoedNonce is the bundle's nonce field; "" means absent.
	EchoedNonce string `json:"echoed_nonce"`
	// ChallengeHex is the nonce the verifier sent; "" means it sent none.
	ChallengeHex string `json:"challenge_hex"`
	// AuxHex is the signed upper half of report_data.
	AuxHex string `json:"aux_hex"`
	Error  string `json:"error"`
	Tag    string `json:"tag"`
}

type vectorsFile struct {
	Version           int                `json:"version"`
	Comment           string             `json:"comment"`
	EventLogPath      string             `json:"event_log_path"`
	QuotePath         string             `json:"quote_path"`
	RuntimeEventType  uint32             `json:"runtime_event_type"`
	Replay            replayVector       `json:"replay"`
	Measurements      map[string]string  `json:"measurements"`
	Quote             quoteVector        `json:"quote"`
	ReportDataVectors []reportDataVector `json:"report_data"`
	HAppVectors       []hAppVector       `json:"h_app"`
	AuxBindingVectors []auxBindingVector `json:"aux_binding"`
	HAppJSONVectors   []hAppJSONVector   `json:"h_app_json"`
	AuxVerifyVectors  []auxVerifyVector  `json:"aux_verify"`
	HPostureVectors   []hPostureVector   `json:"h_posture"`
	Hostile           []hostileCase      `json:"hostile"`
}

// hPostureVector pins H_posture over a posture given as raw JSON text, which
// each implementation decodes with its own parser — the bundle field is what
// a verifier hashes, so the decode is part of what must agree.
type hPostureVector struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	// PostureJSON "" means the field is absent from the bundle.
	PostureJSON string `json:"posture_json"`
	ExpectedHex string `json:"expected_hex"`
}

// hAppErrorCode maps a Go sentinel onto the TypeScript AttestErrorCode
// string. Same purpose as replayErrorCode: one taxonomy in the file
// rather than two kept in step by eye.
func hAppErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrMalformedModelEntry):
		return "malformed_model_entry"
	case errors.Is(err, ErrDuplicateModelID):
		return "duplicate_model_id"
	case errors.Is(err, ErrEmptyModelID):
		return "empty_model_id"
	case errors.Is(err, ErrStateDigestDisagree):
		return "state_digest_disagree"
	case errors.Is(err, ErrUnknownWeightsState):
		return "unknown_weights_state"
	default:
		return "unmapped"
	}
}

// splitReportDataErrorCode maps SplitReportData's refusals to the stable
// strings the vectors carry, so TypeScript reproduces WHICH refusal rather
// than merely refusing. The two are different accusations — see the
// sentinels' godoc.
func splitReportDataErrorCode(quote []byte) string {
	_, err := SplitReportData(quote)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrReportDataAbsent):
		return "report_data_absent"
	case errors.Is(err, ErrAuxBindingAbsent):
		return "aux_binding_absent"
	default:
		// Caught by the generator, as in hAppErrorCode: a sentinel added
		// later would otherwise be written into the golden file as the
		// literal "unmapped" and only surface when TypeScript eventually
		// disagreed with it.
		return "unmapped"
	}
}

// buildHAppVectors records what Go does for each catalog shape. Go is the
// expectation; the value of the file is that TypeScript must reproduce it,
// errors included.
func buildHAppVectors(t *testing.T) []hAppVector {
	t.Helper()

	const dg = "sha256:" + "ab12" // short on purpose: the format is unvalidated
	measured := func(id string) ModelEntry {
		return ModelEntry{ModelID: id, Source: "hf/" + id, WeightsDigest: dg, State: WeightsMeasured}
	}

	cases := []struct {
		name, why string
		entries   []ModelEntry
	}{
		{
			"empty catalog is the pending value",
			"Must equal HAppPending. Neither may be 32 zero bytes, or a booting node is indistinguishable from a pre-9.9 one and the check is skipped exactly when it is least earned.",
			nil,
		},
		{
			"one measured model",
			"The ordinary case.",
			[]ModelEntry{measured("a-model")},
		},
		{
			"one declared model",
			"THE PAIR for 'one measured model': byte-identical to it except the state, so the digests differ ONLY because the state byte does. A mirror collapsing the two states produces one digest for two different claims, and this is the case that catches it — which it cannot do if any other field also moves.",
			[]ModelEntry{{ModelID: "a-model", Source: "hf/a-model", WeightsDigest: dg, State: WeightsDeclared}},
		},
		{
			"one unverifiable model carries no digest",
			"Hosted passthrough. The empty digest is the point: absence is a VALUE here, so this must not collide with a model omitted from the catalog entirely.",
			[]ModelEntry{{ModelID: "gpt-ish", Source: "", WeightsDigest: "", State: WeightsUnverifiable}},
		},
		{
			"three models, given sorted",
			"Paired with the next case: both must produce the SAME digest, which is what pins that sorting happens inside HApp rather than being the caller's duty.",
			[]ModelEntry{measured("aaa"), measured("bbb"), measured("ccc")},
		},
		{
			"three models, given unsorted",
			"THE PAIR. A node builds its catalog from maps and discovery order; if input order changed the digest, a node and a verifier holding identical sets would disagree with nothing to diagnose it.",
			[]ModelEntry{measured("ccc"), measured("aaa"), measured("bbb")},
		},
		{
			"model ids sort by BYTES, not by case",
			"'Z' (0x5a) sorts BELOW 'a' (0x61). A mirror using localeCompare or a case-insensitive sort orders these the other way and digests a different preimage.",
			[]ModelEntry{measured("a-model"), measured("Z-model")},
		},
		{
			"non-ASCII model id is length-prefixed in BYTES",
			"lenStr counts UTF-8 bytes; JavaScript's String.length counts UTF-16 units, and they differ here. A mirror using .length writes a short length and every following field slides.",
			[]ModelEntry{measured("modèl-π")},
		},
		{
			"sort order is UTF-8 BYTES, not UTF-16 code units",
			"THE ONLY CASE THAT CAN CATCH A PLAIN `a < b` IN THE MIRROR. Go compares strings bytewise, JavaScript's < compares UTF-16 code units, and these two ids order OPPOSITELY under the two rules: U+FFFD is EF BF BD in UTF-8 and 0xFFFD in UTF-16, while U+1F600 is F0 9F 98 80 in UTF-8 and the surrogate pair 0xD83D 0xDE00 in UTF-16 — so UTF-8 puts U+FFFD first and UTF-16 puts the emoji first. Every other multi-entry case here is ASCII, where the two rules agree, so deleting the TS compareUtf8 helper passes the whole suite without this one. Unreachable over the wire today; it is here because the divergence it pins is silent and the vector is free.",
			[]ModelEntry{measured("�"), measured("\U0001F600")},
		},
		{
			"empty source is allowed",
			"A model whose provenance the node resolved to nothing is legitimate, and its empty lenStr must still occupy four bytes.",
			[]ModelEntry{{ModelID: "m", Source: "", WeightsDigest: dg, State: WeightsMeasured}},
		},
		{
			"duplicate model ids are REFUSED even when nothing else matches",
			"They cannot both answer 'what is this node serving as m', and a minter and a verifier breaking the tie differently compute different digests from identical input. The two entries agree on the ID AND NOTHING ELSE on purpose: a check that also compared source or state would still refuse two exact clones, so only a pair like this one — the shape an operator would actually build to slip a substituted model past an id-matching verifier — pins that the ID ALONE is the key.",
			[]ModelEntry{
				{ModelID: "m", Source: "hf/m", WeightsDigest: dg, State: WeightsMeasured},
				{ModelID: "m", Source: "hosted/elsewhere", WeightsDigest: "", State: WeightsUnverifiable},
			},
		},
		{
			"duplicate detected across an unsorted input",
			"The dedup runs after the sort, so an adjacent-pair check must still catch a pair the caller separated. These two ARE exact clones, which is what keeps that easier case covered once the vector above stopped being one.",
			[]ModelEntry{measured("m"), measured("z"), measured("m")},
		},
		{
			"model ids that are PREFIXES of one another",
			"Sorting falls through to the length tiebreak only when one id is a prefix of the other, and every other multi-entry case here differs at some byte or has equal lengths — so this is the only case that pins the tail of the comparison. Unlike the surrogate-pair case above, this shape is not exotic: 'llama-3' and 'llama-3-instruct' is what a real catalog looks like, so a mirror reversing the tiebreak diverges on ordinary input.",
			[]ModelEntry{measured("llama-3-instruct"), measured("llama-3")},
		},
		{
			"empty model id is REFUSED",
			"Nothing can match it against a request, so it can only pad the count.",
			[]ModelEntry{{ModelID: "", Source: "s", WeightsDigest: dg, State: WeightsMeasured}},
		},
		{
			"measured with no digest is REFUSED",
			"The state claims the node hashed something and the entry shows nothing.",
			[]ModelEntry{{ModelID: "m", Source: "s", WeightsDigest: "", State: WeightsMeasured}},
		},
		{
			"DECLARED with no digest is REFUSED",
			"THE THIRD CORNER of the state/digest matrix, and the one a mirror is likeliest to drop: measured and declared share a branch here, so splitting them and letting declared through refuses nothing the other two cases test. Declared is a weaker claim than measured but it is still a claim, and an entry asserting it while showing no digest would otherwise fold into an attested catalog with nothing behind it.",
			[]ModelEntry{{ModelID: "m", Source: "s", WeightsDigest: "", State: WeightsDeclared}},
		},
		{
			"unverifiable WITH a digest is REFUSED",
			"The other direction, and the one a lenient mirror is likelier to allow: it looks like extra information rather than a contradiction.",
			[]ModelEntry{{ModelID: "m", Source: "s", WeightsDigest: dg, State: WeightsUnverifiable}},
		},
		{
			"an unknown state byte is REFUSED",
			"Fail closed. A newer node's state would otherwise be hashed as one this verifier thinks it understands.",
			[]ModelEntry{{ModelID: "m", Source: "s", WeightsDigest: dg, State: WeightsState(4)}},
		},
		{
			"state zero is REFUSED",
			"0 is the Go zero value and what a lenient JSON decoder yields for a missing weights_state. It must not mean measured, the strongest claim.",
			[]ModelEntry{{ModelID: "m", Source: "s", WeightsDigest: dg, State: WeightsState(0)}},
		},
		{
			"an entry breaking TWO rules reports the FIRST one",
			"Pins the check order, so Go and TypeScript report the same code for one input. The empty id is checked before the state.",
			[]ModelEntry{{ModelID: "", Source: "s", WeightsDigest: "", State: WeightsState(4)}},
		},
	}

	out := make([]hAppVector, 0, len(cases))
	for _, c := range cases {
		// Non-nil even when empty, so the pending case serializes as []
		// rather than null and a mirror reading it gets a list to iterate.
		entries := make([]ModelEntry, 0, len(c.entries))
		entries = append(entries, c.entries...)
		digest, err := HApp(c.entries)
		v := hAppVector{Name: c.name, Why: c.why, Entries: entries, Error: hAppErrorCode(err)}
		if v.Error == "unmapped" {
			t.Fatalf("case %q returned an unmapped error: %v", c.name, err)
		}
		if err == nil {
			v.ExpectedHex = hex.EncodeToString(digest[:])
		}
		out = append(out, v)
	}
	return out
}

// buildAuxBindingVectors pins the upper half across the id encodings and
// the nonce-presence distinction.
func buildAuxBindingVectors(t *testing.T) []auxBindingVector {
	t.Helper()

	pending := HAppPending()
	populated, err := HApp([]ModelEntry{
		{ModelID: "m", Source: "hf/m", WeightsDigest: "sha256:ab12", State: WeightsMeasured},
	})
	if err != nil {
		t.Fatalf("build populated H_app: %v", err)
	}
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1) // non-zero in every byte, and not all equal
	}
	var zeroNonce [32]byte
	noPosture := mustHPosture(t, nil)
	xaiPosture := mustHPosture(t, &TEEPosture{
		PlaintextTerminates: "named_upstream",
		UpstreamBaseURL:     "https://api.x.ai/v1",
		ZeroRetention:       true,
	})

	cases := []struct {
		name, why string
		nodeID    uint64
		hApp      [32]byte
		hPosture  [32]byte
		nonce     *[32]byte
	}{
		{"node id zero, pending catalog", "A little-endian implementation agrees with a big-endian one on id 0 and on nothing else, so this case alone cannot tell them apart — it is here to pair with the ones below.", 0, pending, noPosture, nil},
		{"small node id", "The ordinary case.", 42, populated, noPosture, nil},
		{"node id above 32 bits", "Catches a 32-bit truncation that every small id hides.", 1 << 33, populated, noPosture, nil},
		{"max uint64 node id", "The boundary that forces node_id to ride as a decimal string rather than a JSON number.", ^uint64(0), populated, noPosture, nil},
		{"absent nonce", "Paired with the next case.", 7, populated, noPosture, nil},
		{"explicit all-zero nonce", "THE PAIR: it must produce the IDENTICAL digest to an absent nonce, because absent IS 32 zero bytes. That is why 'I supplied a nonce and got zeros back' cannot be detected here and must be a verifier-side failure — this function cannot see what was asked for.", 7, populated, noPosture, &zeroNonce},
		{"a real nonce", "The on-demand ?nonce= path. Different digest for the same catalog and node, which is the whole point of liveness.", 7, populated, noPosture, &nonce},
		{"a named-upstream posture", "H_posture sits between H_app and the nonce; swapping the two 32-byte fields must change the digest, which only a case with both non-trivial can show.", 7, populated, xaiPosture, &nonce},
	}

	out := make([]auxBindingVector, 0, len(cases))
	for _, c := range cases {
		got := AuxBinding(c.nodeID, c.hApp, c.hPosture, c.nonce)
		v := auxBindingVector{
			Name:        c.name,
			Why:         c.why,
			NodeID:      strconv.FormatUint(c.nodeID, 10),
			HAppHex:     hex.EncodeToString(c.hApp[:]),
			HPostureHex: hex.EncodeToString(c.hPosture[:]),
			ExpectedHex: hex.EncodeToString(got[:]),
		}
		if c.nonce != nil {
			v.NonceHex = hex.EncodeToString(c.nonce[:])
		}
		out = append(out, v)
	}
	return out
}

func mustHPosture(t *testing.T, p *TEEPosture) [32]byte {
	t.Helper()
	h, err := HPosture(p)
	if err != nil {
		t.Fatalf("HPosture(%+v): %v", p, err)
	}
	return h
}

// decodePostureJSON decodes a posture the way a verifier decoding a bundle
// does: through the bundle's own field, so a JSON null and an absent key both
// land as nil. An undecodable posture is a generator bug, not a vector.
func decodePostureJSON(t *testing.T, s string) *TEEPosture {
	t.Helper()
	if s == "" {
		return nil
	}
	var b struct {
		Posture *TEEPosture `json:"posture"`
	}
	if err := json.Unmarshal([]byte(`{"posture":`+s+`}`), &b); err != nil {
		t.Fatalf("posture %s does not decode: %v", s, err)
	}
	return b.Posture
}

// buildHPostureVectors records what Go does for each posture shape.
func buildHPostureVectors(t *testing.T) []hPostureVector {
	t.Helper()
	cases := []struct{ name, why, posture string }{
		{"absent", "No posture field. Committed as absent, so a relay cannot add one.", ""},
		{"null", "Go decodes null into a nil pointer: the same claim as absent, and the same digest.", "null"},
		{"in_enclave", "The sealed_local posture: no upstream, no zero-retention flag.",
			`{"plaintext_terminates":"in_enclave"}`},
		{"named upstream, xAI", "The attested_passthrough case this binding exists for.",
			`{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1","zero_retention":true}`},
		{"named upstream, zero_retention false", "Paired with the previous case: the flag alone must move the digest.",
			`{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1","zero_retention":false}`},
		{"named upstream, lookalike host", "One changed host: a different digest, so a relay cannot swap the URL a verifier judges.",
			`{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai.attacker.example/v1","zero_retention":true}`},
		{"explicit nulls inside", "Go leaves a string or bool field at its zero value on null; TypeScript must read null as '' and false, or the two hash different postures.",
			`{"plaintext_terminates":"in_enclave","upstream_base_url":null,"zero_retention":null}`},
		{"empty object", "Present but empty is NOT absent: the presence byte differs.", `{}`},
		{"unknown key", "An unrecognised key is ignored by both decoders and does not enter the preimage.",
			`{"plaintext_terminates":"in_enclave","future_field":"x"}`},
		{"non-ASCII URL", "Lengths are UTF-8 byte counts, not UTF-16 code units.",
			`{"plaintext_terminates":"named_upstream","upstream_base_url":"https://exämple.test/v1"}`},
		{"field boundary", "lenStr framing: moving bytes between two adjacent strings must change the digest.",
			`{"plaintext_terminates":"named_upstreamh","upstream_base_url":"ttps://x"}`},
		{"named upstream, attested gateway", "The ACI gateway posture: the bound upstream_attested bit, which a relay cannot set.",
			`{"plaintext_terminates":"named_upstream","upstream_base_url":"https://gateway.example/v1","upstream_attested":true}`},
		{"bool order", "zero_retention and upstream_attested swapped: the two flag bytes are positional.",
			`{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1","upstream_attested":true}`},
	}
	out := make([]hPostureVector, 0, len(cases))
	for _, c := range cases {
		h := mustHPosture(t, decodePostureJSON(t, c.posture))
		out = append(out, hPostureVector{
			Name:        c.name,
			Why:         c.why,
			PostureJSON: c.posture,
			ExpectedHex: hex.EncodeToString(h[:]),
		})
	}
	// The vectors only prove Go and TypeScript agree; these pin what the
	// `why` texts claim. Exactly these groups share a digest, and every other
	// pair differs.
	same := map[string]string{"null": "absent", "explicit nulls inside": "in_enclave", "unknown key": "in_enclave"}
	for _, a := range out {
		for _, b := range out {
			if a.Name >= b.Name {
				continue
			}
			wantEqual := same[a.Name] == b.Name || same[b.Name] == a.Name ||
				(same[a.Name] != "" && same[a.Name] == same[b.Name])
			if got := a.ExpectedHex == b.ExpectedHex; got != wantEqual {
				t.Errorf("h_posture %q vs %q: equal=%v, want %v", a.Name, b.Name, got, wantEqual)
			}
		}
	}
	return out
}

// auxVerifyErrorCode extends hAppErrorCode with VerifyAux's own errors.
func auxVerifyErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNonceMismatch):
		return "nonce_mismatch"
	case errors.Is(err, ErrMalformedNonce):
		return "malformed_nonce"
	case errors.Is(err, ErrZeroChallenge):
		return "zero_challenge"
	case errors.Is(err, ErrHAppPreimageMissing):
		return "happ_preimage_missing"
	case errors.Is(err, ErrAuxBindingMismatch):
		return "aux_binding_mismatch"
	default:
		return hAppErrorCode(err)
	}
}

// decodeEntriesJSON decodes app_models the way a verifier decoding a bundle
// does. An undecodable list is a generator bug, not a vector.
func decodeEntriesJSON(t *testing.T, s string) []ModelEntry {
	t.Helper()
	if s == "" {
		return nil
	}
	var entries []ModelEntry
	if err := json.Unmarshal([]byte(s), &entries); err != nil {
		t.Fatalf("entries %s do not decode: %v", s, err)
	}
	return entries
}

// buildHAppJSONVectors records what Go does for each raw JSON entry list.
func buildHAppJSONVectors(t *testing.T) []hAppJSONVector {
	t.Helper()

	cases := []struct{ name, why, json string }{
		{
			"well-formed entry",
			"The control for the cases below.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":1}]`,
		},
		{
			"measured entry with weights_digest missing",
			"A lenient decoder reads the missing digest as \"\" and refuses measured-without-digest; JavaScript reads undefined, which is not \"\", and used to hash it as a measured claim with no digest. Both must refuse it as malformed.",
			`[{"model_id":"m","source":"hf/m","weights_state":1}]`,
		},
		{
			"measured entry with a null weights_digest",
			"JavaScript's TextEncoder encodes null as the four bytes \"null\".",
			`[{"model_id":"m","source":"hf/m","weights_digest":null,"weights_state":1}]`,
		},
		{
			"null source",
			"Go decodes null into a string as \"\"; JavaScript keeps null.",
			`[{"model_id":"m","source":null,"weights_digest":"","weights_state":3}]`,
		},
		{
			"model_id missing",
			"Go decodes it as \"\" and reports an empty id; JavaScript used to hash undefined as an empty string without the empty-id check firing.",
			`[{"source":"hf/m","weights_digest":"sha256:ab12","weights_state":1}]`,
		},
		{
			"weights_state missing",
			"A lenient Go decoder reads 0.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12"}]`,
		},
		{
			"weights_state zero",
			"A present 0 is well-formed JSON and an unknown state.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":0}]`,
		},
		{
			"weights_state above 255",
			"Go cannot store 300 in a uint8. It must be an unknown state in both implementations, not a decode failure in one.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":300}]`,
		},
		{
			"weights_state 257",
			"257 truncates to 1 in a uint8, so a decoder missing the upper bound reads it as measured. 300 truncates to 44, still unknown, and cannot tell.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":257}]`,
		},
		{
			"weights_state -255",
			"-255 wraps to 1 in a uint8, so a decoder missing the lower bound reads it as measured.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":-255}]`,
		},
		{
			"weights_state null",
			"Malformed, not unknown: null into a Go float64 is a silent 0.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":null}]`,
		},
		{
			"weights_state 1.0",
			"JSON.parse yields 1, so Go accepts it too. Same digest as the well-formed entry.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":1.0}]`,
		},
		{
			"weights_state 1.5",
			"Not an integer.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":1.5}]`,
		},
		{
			"weights_state as a string",
			"Wrong type.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":"1"}]`,
		},
		{
			"model_id as a number",
			"Wrong type.",
			`[{"model_id":7,"source":"hf/m","weights_digest":"sha256:ab12","weights_state":1}]`,
		},
		{
			"key in the wrong case",
			"Go's default struct decoding matches keys case-insensitively; JavaScript does not. The strict decoder matches exactly.",
			`[{"Model_ID":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":1}]`,
		},
		{
			"an extra key is ignored",
			"Both implementations ignore unknown keys. Same digest as the well-formed entry.",
			`[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":1,"note":"x"}]`,
		},
		{
			"a null entry",
			"Not an object.",
			`[null]`,
		},
		{
			"a number entry",
			"Not an object.",
			`[7]`,
		},
		{
			"lone surrogates decode to one id",
			"Go's decoder turns an unpaired surrogate escape into U+FFFD, so these are duplicates in Go. JavaScript keeps the lone surrogates as distinct strings; its verifier must compare UTF-8 bytes, where TextEncoder also writes U+FFFD.",
			`[{"model_id":"\ud800","source":"","weights_digest":"","weights_state":3},{"model_id":"\udc00","source":"","weights_digest":"","weights_state":3}]`,
		},
		{
			"malformed is checked before the per-entry rules",
			"The empty-id entry sorts first, but the malformed-entry pass runs over the whole list before sorting, so the code is malformed_model_entry.",
			`[{"model_id":"","source":"s","weights_digest":"sha256:ab12","weights_state":1},{"model_id":"b"}]`,
		},
		{
			"duplicate ids keep their input order",
			"The sort is stable, so the valid \"dup\" stays first and the second is reported as a duplicate. An unstable sort (Go's pdqsort above 12 elements) can put the bad-state copy first and report unknown_weights_state instead.",
			stableSortCase(),
		},
	}

	out := make([]hAppJSONVector, 0, len(cases))
	for _, c := range cases {
		digest, err := HApp(decodeEntriesJSON(t, c.json))
		v := hAppJSONVector{Name: c.name, Why: c.why, EntriesJSON: c.json, Error: hAppErrorCode(err)}
		if v.Error == "unmapped" {
			t.Fatalf("case %q returned an unmapped error: %v", c.name, err)
		}
		if err == nil {
			v.ExpectedHex = hex.EncodeToString(digest[:])
		}
		out = append(out, v)
	}
	return out
}

// stableSortCase is 20 distinct unverifiable ids followed by two "dup"
// entries, the first valid and the second with an unknown state.
func stableSortCase() string {
	var b strings.Builder
	b.WriteString("[")
	for i := range 20 {
		fmt.Fprintf(&b, `{"model_id":"m%02d","source":"","weights_digest":"","weights_state":3},`, 19-i)
	}
	b.WriteString(`{"model_id":"dup","source":"","weights_digest":"sha256:ab12","weights_state":1},`)
	b.WriteString(`{"model_id":"dup","source":"","weights_digest":"sha256:ab12","weights_state":9}]`)
	return b.String()
}

// buildAuxVerifyVectors records VerifyAux's verdict for each bundle shape.
func buildAuxVerifyVectors(t *testing.T) []auxVerifyVector {
	t.Helper()

	const node = uint64(7)
	const catalog = `[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ab12","weights_state":1}]`
	const edited = `[{"model_id":"m","source":"hf/m","weights_digest":"sha256:ff99","weights_state":1}]`
	const malformed = `[{"model_id":"m","source":"hf/m","weights_state":1}]`

	var n, m [32]byte
	for i := range n {
		n[i] = byte(i + 1)
		m[i] = byte(0xf0 - i)
	}
	nHex, mHex := hex.EncodeToString(n[:]), hex.EncodeToString(m[:])
	z := n
	z[0] = 0
	zHex := hex.EncodeToString(z[:])

	const xai = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1","zero_retention":true}`
	const lookalike = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai.attacker.example/v1","zero_retention":true}`
	const noRetention = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://api.x.ai/v1","zero_retention":false}`
	const gateway = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://gateway.example/v1"}`
	const gatewayAttested = `{"plaintext_terminates":"named_upstream","upstream_base_url":"https://gateway.example/v1","upstream_attested":true}`

	mintP := func(id uint64, entries, posture string, nonce *[32]byte) string {
		h, err := HApp(decodeEntriesJSON(t, entries))
		if err != nil {
			t.Fatalf("mint over %s: %v", entries, err)
		}
		aux := AuxBinding(id, h, mustHPosture(t, decodePostureJSON(t, posture)), nonce)
		return hex.EncodeToString(aux[:])
	}
	mint := func(id uint64, entries string, nonce *[32]byte) string {
		return mintP(id, entries, "", nonce)
	}

	// The pre-posture cases carry no posture field and mint over an absent
	// one; the posture cases below add the seventh field.
	type auxCase struct {
		name, why, entries, echoed, challenge, aux, posture string
	}
	base := []struct {
		name, why                       string
		entries, echoed, challenge, aux string
	}{
		{"unchallenged cached bundle", "The ordinary case.",
			catalog, "", "", mint(node, catalog, nil)},
		{"challenged, echo matches", "The ?nonce= path.",
			catalog, nHex, nHex, mint(node, catalog, &n)},
		{"challenged, echo in upper case", "Both implementations decode hex case-insensitively and compare bytes.",
			catalog, strings.ToUpper(nHex), nHex, mint(node, catalog, &n)},
		{"challenged, echo absent", "A replayed cached bundle. Hashing 32 zero bytes would verify it; the verifier must refuse because it asked for a nonce.",
			catalog, "", nHex, mint(node, catalog, nil)},
		{"challenged, echo is another caller's nonce", "A replayed bundle minted for someone else's challenge. Its binding is valid for the nonce it carries, so hashing the echo would verify it.",
			catalog, mHex, nHex, mint(node, catalog, &m)},
		{"challenged, echo malformed", "Refused as a nonce mismatch, not a malformed nonce: the verifier asked for a specific value.",
			catalog, "zz", nHex, mint(node, catalog, &n)},
		{"unchallenged, bundle carries a nonce", "A bundle minted for another caller's challenge still verifies for a verifier that sent none.",
			catalog, mHex, "", mint(node, catalog, &m)},
		{"unchallenged, nonce not hex", "Refused rather than read as absent.",
			catalog, strings.Repeat("z", 64), "", mint(node, catalog, nil)},
		{"unchallenged, nonce too short", "Exactly 64 hex characters or refused.",
			catalog, nHex[:62], "", mint(node, catalog, nil)},
		{"sibling node's bundle", "Minted by node 8, checked against node 7's chain-resolved id.",
			catalog, "", "", mint(node+1, catalog, nil)},
		{"empty catalog, honest", "A node serving nothing, or still booting. Verifies.",
			"", "", "", mint(node, "", nil)},
		{"catalog withheld", "The quote commits to a catalog the bundle does not publish.",
			"", "", "", mint(node, catalog, nil)},
		{"sibling node's empty-catalog bundle", "Also happ_preimage_missing: with no entries, a node-id mismatch and a withheld catalog cannot be told apart.",
			"", "", "", mint(node+1, "", nil)},
		{"catalog edited in transit", "A relay changed a digest.",
			edited, "", "", mint(node, catalog, nil)},
		{"malformed catalog", "Refused before the comparison.",
			malformed, "", "", mint(node, catalog, nil)},
		{"nonce is checked before the catalog", "Pins the order: a nonce mismatch is reported even when the catalog is also malformed.",
			malformed, "", nHex, mint(node, catalog, nil)},
		{"challenge is all zero", "Zeros hash the same as no nonce, so a cached bundle with a 64-zero nonce field would pass as fresh. The verifier's own challenge is refused.",
			catalog, strings.Repeat("0", 64), strings.Repeat("0", 64), mint(node, catalog, nil)},
		{"challenge starts with a zero byte", "Only an all-zero challenge is refused. A check on the first byte would refuse one honest random challenge in 256.",
			catalog, zHex, zHex, mint(node, catalog, &z)},
		{"app_models is null", "Go decodes null as an absent list; TypeScript must treat it the same, not as a malformed list.",
			"null", "", "", mint(node, "", nil)},
		{"app_models is null, catalog withheld", "null must reach the missing-catalog check, not fail on reading the list.",
			"null", "", "", mint(node, catalog, nil)},
		{"app_models is [], catalog withheld", "An explicit empty list is the same claim as an absent one.",
			"[]", "", "", mint(node, catalog, nil)},
		{"unchallenged, nonce too long", "The echo is node-controlled; 66 hex characters must be refused, not decoded into 32 bytes past the end.",
			catalog, nHex + "00", "", mint(node, catalog, nil)},
		{"catalog with a duplicate id", "Each HApp refusal is happ_preimage_invalid, not a disagreement.",
			`[{"model_id":"m","source":"","weights_digest":"","weights_state":3},{"model_id":"m","source":"","weights_digest":"","weights_state":3}]`,
			"", "", mint(node, catalog, nil)},
		{"catalog with an empty id", "As above.",
			`[{"model_id":"","source":"","weights_digest":"","weights_state":3}]`,
			"", "", mint(node, catalog, nil)},
		{"catalog whose state contradicts its digest", "As above.",
			`[{"model_id":"m","source":"","weights_digest":"","weights_state":1}]`,
			"", "", mint(node, catalog, nil)},
		{"catalog with an unknown state", "As above.",
			`[{"model_id":"m","source":"","weights_digest":"sha256:ab12","weights_state":9}]`,
			"", "", mint(node, catalog, nil)},
	}
	cases := make([]auxCase, 0, len(base)+8)
	for _, c := range base {
		cases = append(cases, auxCase{c.name, c.why, c.entries, c.echoed, c.challenge, c.aux, ""})
	}
	cases = append(cases, []auxCase{
		// Posture. The hardware signs what the measured binary derived; a
		// bundle whose posture differs from it in any field must not verify.
		{"posture honest", "The attested_passthrough case: the published posture is the one the quote commits to.",
			catalog, "", "", mintP(node, catalog, xai, nil), xai},
		{"posture URL rewritten in transit", "The lookalike attack against an honest node: the binary signed api.x.ai, a relay publishes an attacker host. Refused.",
			catalog, "", "", mintP(node, catalog, xai, nil), lookalike},
		{"posture signed with the lookalike", "The binding verifies — it proves only what the binary derived. Judging the URL is the verifier's next step, not this one.",
			catalog, "", "", mintP(node, catalog, lookalike, nil), lookalike},
		{"zero_retention flipped on", "A relay upgrading the flag.",
			catalog, "", "", mintP(node, catalog, noRetention, nil), xai},
		{"posture stripped", "The quote commits to a posture the bundle no longer carries.",
			catalog, "", "", mintP(node, catalog, xai, nil), ""},
		{"posture added", "The quote commits to no posture; the bundle carries one.",
			catalog, "", "", mint(node, catalog, nil), xai},
		{"posture null", "null is absent: the same digest, so it verifies against an absent-posture quote.",
			catalog, "", "", mint(node, catalog, nil), "null"},
		{"posture stripped, empty catalog", "With no entries every mismatch reads happ_preimage_missing — the digest cannot say which input moved.",
			"", "", "", mintP(node, "", xai, nil), ""},
		{"upstream_attested set in transit", "A relay claiming the node appraises its upstream, to pair with an injected upstream_attestation block. Refused.",
			catalog, "", "", mintP(node, catalog, gateway, nil), gatewayAttested},
	}...)

	out := make([]auxVerifyVector, 0, len(cases))
	for _, c := range cases {
		var aux [32]byte
		if _, err := hex.Decode(aux[:], []byte(c.aux)); err != nil {
			t.Fatalf("%s: aux: %v", c.name, err)
		}
		var challenge *[32]byte
		if c.challenge != "" {
			var ch [32]byte
			if _, err := hex.Decode(ch[:], []byte(c.challenge)); err != nil {
				t.Fatalf("%s: challenge: %v", c.name, err)
			}
			challenge = &ch
		}
		err := ReportDataHalves{AuxBinding: aux}.VerifyAux(node, decodeEntriesJSON(t, c.entries), decodePostureJSON(t, c.posture), c.echoed, challenge)
		v := auxVerifyVector{
			Name:         c.name,
			Why:          c.why,
			NodeID:       strconv.FormatUint(node, 10),
			EntriesJSON:  c.entries,
			PostureJSON:  c.posture,
			EchoedNonce:  c.echoed,
			ChallengeHex: c.challenge,
			AuxHex:       c.aux,
			Error:        auxVerifyErrorCode(err),
			Tag:          AuxFailureTag(err),
		}
		if v.Error == "unmapped" {
			t.Fatalf("case %q returned an unmapped error: %v", c.name, err)
		}
		out = append(out, v)
	}
	return out
}

// replayErrorCode maps a Go sentinel onto the TypeScript
// AttestErrorCode string, so the vectors carry one taxonomy rather than
// two that have to be kept in step by eye.
func replayErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUndecodablePayload):
		return "undecodable_payload"
	case errors.Is(err, ErrEmptyReplay):
		return "empty_replay"
	default:
		return "unmapped"
	}
}

// buildHostileCases runs each operator-authored log through Go and
// records what Go did. Nothing here is asserted against a hand-written
// expectation — Go IS the expectation, and the value of the file is
// that TypeScript has to reproduce it.
func buildHostileCases(t *testing.T) []hostileCase {
	t.Helper()

	const rt = 0x08000001
	cases := []struct{ name, why, log string }{
		{
			"uppercase hex payload",
			"Go's hex.DecodeString takes either case; a mirror that lowercased its charset would reject a log Go accepts.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"AABBCC"}]`,
		},
		{
			"lowercase 0x prefix",
			"Trimmed by both, so this is the case that keeps the next one from being read as 'prefixes are rejected'.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"0xaabbcc"}]`,
		},
		{
			"uppercase 0X prefix",
			"THE DIVERGENCE. Go trims only lowercase, so 0X reaches hex.DecodeString and fails; a mirror accepting 0X decodes and routes on evidence Go refuses.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"0Xaabbcc"}]`,
		},
		{
			"null event name",
			"JSON null lands as the empty string in Go. A mirror using a non-nullish coalesce hashes the four bytes 'null' and gets a different RTMR3 from the same log.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":null,"event_payload":"aa"}]`,
		},
		{
			"absent event_payload",
			"Absent decodes to the empty payload and still extends. A mirror that treated undefined as undecodable would refuse a log Go accepts.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash"}]`,
		},
		{
			"empty event name is measured by nobody",
			"RuntimeMeasurements skips it; a mirror dropping that guard mints an empty-string key.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"","event_payload":"aa"},` +
				`{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"bb"}]`,
		},
		{
			"a later duplicate cannot displace a measured value",
			"First occurrence wins, so an appended event cannot overwrite one the hardware measured.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"AA"},` +
				`{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"bb"}]`,
		},
		{
			"a non-empty digest field is still ignored",
			"dstack leaves digest empty; a mirror that trusted a populated one would extend with attacker-chosen bytes.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"` + strings.Repeat("de", 48) + `","event":"compose-hash","event_payload":"aa"}]`,
		},
		{
			"imr 3 but not a runtime event",
			"Filtering on imr rather than event_type selects this; the two predicates disagree here and agree on the real capture.",
			`[{"imr":3,"event_type":4,"digest":"","event":"boot-ish","event_payload":"aa"}]`,
		},
		{
			"runtime event outside imr 3",
			"The converse: an imr filter would MISS this one.",
			`[{"imr":1,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"aa"}]`,
		},
		{
			"odd-length payload",
			"Not decodable as bytes; skipping it silently would yield a partial replay indistinguishable from a whole one.",
			`[{"imr":3,"event_type":` + strconv.Itoa(rt) + `,"digest":"","event":"compose-hash","event_payload":"abc"}]`,
		},
	}

	out := make([]hostileCase, 0, len(cases))
	for _, c := range cases {
		events, err := ParseEventLog(c.log)
		if err != nil {
			t.Fatalf("%s: ParseEventLog: %v", c.name, err)
		}
		value, extends, replayErr := ReplayRTMR3(events)
		code := replayErrorCode(replayErr)
		if code == "unmapped" {
			t.Fatalf("%s: ReplayRTMR3 returned an error with no TS code mapping: %v", c.name, replayErr)
		}
		hc := hostileCase{
			Name:         c.name,
			Why:          c.why,
			Log:          c.log,
			ReplayError:  code,
			Extends:      extends,
			Measurements: RuntimeMeasurements(events),
		}
		if replayErr == nil {
			hc.RTMR3Hex = hex.EncodeToString(value)
		}
		out = append(out, hc)
	}
	return out
}

func buildVectors(t *testing.T) *vectorsFile {
	t.Helper()
	rawLog, quote := loadVectors(t)

	events, err := ParseEventLog(rawLog)
	if err != nil {
		t.Fatalf("ParseEventLog: %v", err)
	}
	replayed, extends, err := ReplayRTMR3(events)
	if err != nil {
		t.Fatalf("ReplayRTMR3: %v", err)
	}

	rtmr := make([]string, 4)
	for n := range rtmr {
		v, ok := QuoteRTMR(quote, n)
		if !ok {
			t.Fatalf("QuoteRTMR(%d) not present", n)
		}
		rtmr[n] = hex.EncodeToString(v)
	}
	mrtd, ok := QuoteMRTD(quote)
	if !ok {
		t.Fatal("QuoteMRTD not present")
	}
	rd, ok := QuoteReportData(quote)
	if !ok {
		t.Fatal("QuoteReportData not present")
	}
	teeType, ok := QuoteTEEType(quote)
	if !ok {
		t.Fatal("QuoteTEEType not present")
	}
	// The capture's key binding is read straight off the field: the
	// capture is a pre-9.9 node, so SplitReportData refuses it, and
	// splitError records that refusal.
	splitError := splitReportDataErrorCode(quote)
	if splitError == "unmapped" {
		t.Fatal("SplitReportData returned a sentinel splitReportDataErrorCode does not map")
	}

	// A fixed, obviously-synthetic recipient. It is not the capture's
	// real node key: the quote's own report_data is pinned above, and
	// these cases exist to pin the HASH function across id encodings,
	// which no live value exercises better than the boundaries below.
	const pubkey = "age1ysu8p4akgwu3rj8h5hcqntxmmhum9rxuy5mz9xsxgkju5q42sd4sswf5t2"

	rdCases := []struct {
		name   string
		pubkey string
		id     uint64
	}{
		{"operator id zero", pubkey, 0},
		{"small id", pubkey, 42},
		{"above 32 bits", pubkey, 1 << 33},
		{"max uint64", pubkey, ^uint64(0)},
		{"empty pubkey", "", 42},

		// The pubkey dimension, which had exactly two shapes while the
		// id dimension had five — and a mutation adding TrimSpace to
		// the pubkey write survived the whole suite. A node that
		// normalizes its own key hashes a preimage no relying party
		// reproduces, and the verdict is key_binding_mismatch against
		// evidence that is fine. The bytes go in verbatim; these pin
		// that there is no normalization of any kind.
		{"pubkey with surrounding whitespace", "  " + pubkey + "\n", 42},
		{"pubkey with an interior space", "age1ysu8 p4akgwu3rj8h5hcqntxmmhum9rxuy5mz9xsxgkju5q42sd4sswf5t2", 42},
		{"pubkey case is significant", strings.ToUpper(pubkey), 42},
		{"pubkey with a NUL byte", "abc\x00def", 42},
		{"non-ASCII pubkey is hashed as UTF-8", "kéy-π", 42},
	}
	rdVectors := make([]reportDataVector, 0, len(rdCases))
	for _, c := range rdCases {
		rdVectors = append(rdVectors, reportDataVector{
			Name:        c.name,
			NodePubkey:  c.pubkey,
			OperatorID:  strconv.FormatUint(c.id, 10),
			ExpectedHex: hex.EncodeToString(ReportData(c.pubkey, c.id)),
			ExpectedB64: ReportDataB64(c.pubkey, c.id),
		})
	}

	return &vectorsFile{
		Version: 1,
		Comment: "Cross-impl vectors for TEE measurement arithmetic. " +
			"Regenerate via: cd proto/go && go test ./attest -run TestVectors -update. " +
			"Loaded by proto/go/attest/vectors_test.go and proto/ts/test/attest-vectors.test.ts. " +
			"Inputs are the capture files named below, not inlined here.",
		EventLogPath:     "attest/ds_event_log.json",
		QuotePath:        "attest/ds_quote_hex.txt",
		RuntimeEventType: DstackRuntimeEventType,
		Replay: replayVector{
			Extends:  extends,
			RTMR3Hex: hex.EncodeToString(replayed),
		},
		Measurements: RuntimeMeasurements(events),
		Quote: quoteVector{
			Len:               len(quote),
			TEEType:           teeType,
			MRTDHex:           hex.EncodeToString(mrtd),
			RTMR0Hex:          rtmr[0],
			RTMR1Hex:          rtmr[1],
			RTMR2Hex:          rtmr[2],
			RTMR3Hex:          rtmr[3],
			ReportDataHex:     hex.EncodeToString(rd),
			BindingHex:        hex.EncodeToString(rd[:32]),
			SplitError:        splitError,
			BindingNodePubkey: captureBindingPubkey,
			BindingOperatorID: strconv.FormatUint(captureBindingOperatorID, 10),
		},
		ReportDataVectors: rdVectors,
		HAppVectors:       buildHAppVectors(t),
		AuxBindingVectors: buildAuxBindingVectors(t),
		HAppJSONVectors:   buildHAppJSONVectors(t),
		AuxVerifyVectors:  buildAuxVerifyVectors(t),
		HPostureVectors:   buildHPostureVectors(t),
		Hostile:           buildHostileCases(t),
	}
}

func TestVectors(t *testing.T) {
	v := buildVectors(t)

	// The replayed value and the quote's own RTMR3 must be the same
	// string in the file. Pinning them separately is what makes the
	// vectors self-checking: a TS implementation that reproduces the
	// quote field by reading it and the replay by computing it agrees
	// with Go only if the computation is right.
	if v.Replay.RTMR3Hex != v.Quote.RTMR3Hex {
		t.Fatalf("replayed RTMR3 %s != quote RTMR3 %s", v.Replay.RTMR3Hex, v.Quote.RTMR3Hex)
	}

	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	if *updateVectors {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", vectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", vectorsPath, len(got))
		return
	}

	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v\n(run `cd proto/go && go test ./attest -run TestVectors -update` to generate)", vectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s drifted from current Go output\n(run `cd proto/go && go test ./attest -run TestVectors -update` to regenerate)", vectorsPath)
	}
}

// The binding is the one place an id-encoding bug is invisible to every
// other test in the package: the quote's report_data is a fixed capture,
// so nothing else in here ever calls ReportData with an id it could get
// backwards. Asserted against a hand-written expectation rather than
// against ReportData's own output, which would agree with itself.
func TestReportDataIsBigEndian(t *testing.T) {
	// Two ids that are byte-reverses of each other. Under
	// little-endian encoding each produces the OTHER's big-endian
	// digest, so a swapped implementation makes these two equal.
	const a uint64 = 0x0102030405060708
	const b uint64 = 0x0807060504030201

	da := ReportData("k", a)
	db := ReportData("k", b)
	if bytes.Equal(da, db) {
		t.Fatal("byte-reversed operator ids hash the same — the id encoding is not endian-sensitive")
	}

	// And pin the actual layout, so "sensitive to endianness" cannot
	// pass while being sensitive in the WRONG direction. The constant
	// is derived outside Go — `printf 'k'; printf '\x00'x7 '\x01' |
	// shasum -a 256` — because an expectation computed by the function
	// under test agrees with any encoding it happens to use.
	const wantHex = "bb5098ab9baf09f4138439a6ce2991b82388005ecf32a36281a2400bcd115136"
	if got := hex.EncodeToString(ReportData("k", 1)); got != wantHex {
		t.Errorf("ReportData(\"k\", 1) = %s, want %s", got, wantHex)
	}
}

// TestQuoteBindingIsSelfDescribing is what makes the two new quote fields
// worth carrying. Publishing a (pubkey, operator_id) pair beside the
// captured binding hash is only useful if the pair actually produces that
// hash — otherwise the file gains a self-description that describes
// nothing, and a third implementation calibrating against it concludes its
// own correct arithmetic is wrong.
func TestQuoteBindingIsSelfDescribing(t *testing.T) {
	_, quote := loadVectors(t)
	// Read the field directly rather than through SplitReportData, which
	// refuses this pre-9.9 capture. The evidence here is about the LOWER
	// half — that real hardware embedded a caller-chosen value verbatim —
	// and that half is unaffected by the flag day.
	rd, present := QuoteReportData(quote)
	if !present {
		t.Fatal("the captured quote carries no report_data")
	}
	want := ReportData(captureBindingPubkey, captureBindingOperatorID)
	if !bytes.Equal(rd[:32], want) {
		t.Errorf("the published binding inputs do not reproduce the captured quote's binding:\n"+
			"  quote      %x\n  recomputed %x\n"+
			"  (pubkey %q, operator_id %d)",
			rd[:32], want, captureBindingPubkey, captureBindingOperatorID)
	}
}

// TestAuxPreimagesArePinnedFromOutside checks the Go digests against
// constants computed without Go or TypeScript. The golden vectors compare Go
// with a TypeScript mirror written from the same doc comment, so a misread
// preimage would appear in both and the vectors would still pass.
//
// Derived in Python from proto/SPEC.md's stated preimages (WeightsMeasured
// is the byte 1):
//
//	H_app       = SHA-256("zs-happ-v1\0" || be32(n) || lenStr(id) || lenStr(src) || lenStr(digest) || u8(state))
//	H_posture   = SHA-256("zs-posture-v1\0" || u8(0))   absent, or
//	            = SHA-256("zs-posture-v1\0" || u8(1) || lenStr(terminates) || lenStr(url) || u8(zero_retention) || u8(upstream_attested))
//	aux_binding = SHA-256("zs-aux-v2\0"  || be64(node_id) || H_app || H_posture || nonce)
//
// If one fails, re-derive it by hand to find which side moved. Copying the
// new value from Go makes the test check nothing.
func TestAuxPreimagesArePinnedFromOutside(t *testing.T) {
	h, err := HApp([]ModelEntry{
		{ModelID: "m", Source: "s", WeightsDigest: "sha256:ab", State: WeightsMeasured},
	})
	if err != nil {
		t.Fatalf("HApp: %v", err)
	}
	const wantHApp = "adb19a536ebe4ff7be8b2b356a5d59b53d15e60705f07280c5eecc8fd304e3b3"
	if got := hex.EncodeToString(h[:]); got != wantHApp {
		t.Errorf("HApp(one measured entry) = %s, want %s", got, wantHApp)
	}

	const wantPending = "86097ce8ac700d38448258745c15beca14c43ecff86f94ec1dce3f1767be0e8b"
	pending := HAppPending()
	if got := hex.EncodeToString(pending[:]); got != wantPending {
		t.Errorf("HAppPending() = %s, want %s", got, wantPending)
	}

	const wantNoPosture = "f60e38bb5e542d1c5f6af42de0784e8ddb9ba689b881e80c3b60731954affd32"
	noPosture := mustHPosture(t, nil)
	if got := hex.EncodeToString(noPosture[:]); got != wantNoPosture {
		t.Errorf("HPosture(nil) = %s, want %s", got, wantNoPosture)
	}

	const wantXAIPosture = "dc63cd7878a74bb255c412a3546d96fa4eb4e78db6e974cf57afd0ab234281cf"
	xai := mustHPosture(t, &TEEPosture{
		PlaintextTerminates: "named_upstream",
		UpstreamBaseURL:     "https://api.x.ai/v1",
		ZeroRetention:       true,
	})
	if got := hex.EncodeToString(xai[:]); got != wantXAIPosture {
		t.Errorf("HPosture(named_upstream xAI) = %s, want %s", got, wantXAIPosture)
	}

	const wantGatewayPosture = "2b38a4eed61958279fbf96a6c6d5e4ca2a362293bc0f87538432c1ce5a2323e9"
	gw := mustHPosture(t, &TEEPosture{
		PlaintextTerminates: "named_upstream",
		UpstreamBaseURL:     "https://gateway.example/v1",
		UpstreamAttested:    true,
	})
	if got := hex.EncodeToString(gw[:]); got != wantGatewayPosture {
		t.Errorf("HPosture(named_upstream attested gateway) = %s, want %s", got, wantGatewayPosture)
	}

	const wantAux = "86647ca311415a2c6e9f2346ef0f93b50d02a226861b62cb169d0b621a7bbf7d"
	aux := AuxBinding(1, pending, noPosture, nil)
	if got := hex.EncodeToString(aux[:]); got != wantAux {
		t.Errorf("AuxBinding(1, HAppPending(), HPosture(nil), nil) = %s, want %s", got, wantAux)
	}

	const wantAuxXAI = "9247f69124626755ebdc86e3cb5fae4aaf179193b5650cac5d64cb99704806c0"
	auxXAI := AuxBinding(1, pending, xai, nil)
	if got := hex.EncodeToString(auxXAI[:]); got != wantAuxXAI {
		t.Errorf("AuxBinding(1, HAppPending(), HPosture(xAI), nil) = %s, want %s", got, wantAuxXAI)
	}
}

// TestHPostureCoversEveryField is the tripwire for a field added to
// TEEPosture without a preimage change. An unhashed field is an unbound one:
// a relay could rewrite it and the aux binding would still verify, which is
// exactly the gap H_posture was added to close.
func TestHPostureCoversEveryField(t *testing.T) {
	// Wire fields only: the unexported malformed mark never travels.
	const hashed = 4 // plaintext_terminates, upstream_base_url, zero_retention, upstream_attested
	n := 0
	for f := range reflect.TypeFor[TEEPosture]().Fields() {
		if f.Tag.Get("json") != "" {
			n++
		}
	}
	if n != hashed {
		t.Fatalf("TEEPosture has %d wire fields but HPosture hashes %d — add the new field to the "+
			"preimage (and bump the zs-posture tag), in Go, TypeScript and proto/SPEC.md", n, hashed)
	}
	base := TEEPosture{PlaintextTerminates: "named_upstream", UpstreamBaseURL: "https://api.x.ai/v1", ZeroRetention: true}
	h0 := mustHPosture(t, &base)
	for name, mut := range map[string]func(*TEEPosture){
		"plaintext_terminates": func(p *TEEPosture) { p.PlaintextTerminates = "in_enclave" },
		"upstream_base_url":    func(p *TEEPosture) { p.UpstreamBaseURL = "https://api.x.ai.attacker.example/v1" },
		"zero_retention":       func(p *TEEPosture) { p.ZeroRetention = false },
		"upstream_attested":    func(p *TEEPosture) { p.UpstreamAttested = true },
	} {
		p := base
		mut(&p)
		if mustHPosture(t, &p) == h0 {
			t.Errorf("changing %s left H_posture unchanged", name)
		}
	}
	if mustHPosture(t, &TEEPosture{}) == mustHPosture(t, nil) {
		t.Error("an empty posture and an absent one hash the same — the presence byte is not in the preimage")
	}
	if _, err := HPosture(&TEEPosture{UpstreamBaseURL: "https://\xff/v1"}); !errors.Is(err, ErrMalformedPosture) {
		t.Errorf("invalid UTF-8 in the URL returned %v, want ErrMalformedPosture", err)
	}
	if got := AuxFailureTag(ErrMalformedPosture); got != TagPosturePreimageInvalid {
		t.Errorf("AuxFailureTag(ErrMalformedPosture) = %q, want %q", got, TagPosturePreimageInvalid)
	}
}

// TestHAppPendingIsNotZero pins the one property the pending value exists
// for. A zero H_app would make a booting node's upper half indistinguishable
// from a pre-9.9 node's all-zero padding, so the aux-binding check would be
// skipped exactly in the window it is least earned.
//
// It is asserted here rather than only in the vectors because the vectors
// compare Go against TypeScript: both could agree on zero and both be wrong.
func TestHAppPendingIsNotZero(t *testing.T) {
	pending := HAppPending()
	var zero [32]byte
	if pending == zero {
		t.Fatal("HAppPending is 32 zero bytes, which a pre-9.9 node's padding is indistinguishable from")
	}

	empty, err := HApp(nil)
	if err != nil {
		t.Fatalf("HApp(nil): %v", err)
	}
	if empty != pending {
		t.Errorf("an empty catalog and the pending value differ (%x vs %x) — both mean "+
			"'this node has attested no models' and must be one digest", empty, pending)
	}

	// The aux binding built over it must not be zero either. A verifier
	// checking only H_app would miss a tag or node-id change collapsing the
	// outer digest.
	if AuxBinding(0, pending, mustHPosture(t, nil), nil) == zero {
		t.Fatal("AuxBinding over the pending value is 32 zero bytes")
	}
}

// TestHAppDoesNotMutateCaller pins a Go-specific hazard with no TypeScript
// twin, which is why it is a Go test and not a vector: TS's [...entries]
// copies before sorting as a matter of syntax, while Go's slices.SortFunc
// sorts IN PLACE and would reorder the caller's slice.
//
// The node builds its entry list from its live catalog, so an in-place sort
// silently reorders state the node keeps using — and every digest would
// still be correct, which is what makes it invisible.
func TestHAppDoesNotMutateCaller(t *testing.T) {
	entries := []ModelEntry{
		{ModelID: "ccc", Source: "s", WeightsDigest: "sha256:ab", State: WeightsMeasured},
		{ModelID: "aaa", Source: "s", WeightsDigest: "sha256:ab", State: WeightsMeasured},
	}
	if _, err := HApp(entries); err != nil {
		t.Fatalf("HApp: %v", err)
	}
	if entries[0].ModelID != "ccc" || entries[1].ModelID != "aaa" {
		t.Errorf("HApp reordered the caller's slice: got %q, %q",
			entries[0].ModelID, entries[1].ModelID)
	}
}

// AuxFailureTag's two mappings no vector reaches. The default is the
// fail-closed one: "" is a consumer's pass value, so a future VerifyAux
// error nobody mapped must still refuse.
func TestAuxFailureTagUnvectoredMappings(t *testing.T) {
	if got := AuxFailureTag(errors.New("some future error")); got != TagAuxBindingMismatch {
		t.Errorf("unmapped error -> %q, want %q", got, TagAuxBindingMismatch)
	}
	if got := AuxFailureTag(ErrAuxBindingAbsent); got != TagAuxBindingAbsent {
		t.Errorf("ErrAuxBindingAbsent -> %q, want %q", got, TagAuxBindingAbsent)
	}
}

// Invalid UTF-8 in any string field is refused before hashing. Go's JSON
// decoder never produces it, so only a node minting from its own config
// could; its hash would be one no TypeScript verifier can reproduce.
func TestHAppRefusesInvalidUTF8(t *testing.T) {
	for _, e := range []ModelEntry{
		{ModelID: "a\xff", State: WeightsUnverifiable},
		{ModelID: "a", Source: "s\xff", State: WeightsUnverifiable},
		{ModelID: "a", WeightsDigest: "sha256:\xff", State: WeightsMeasured},
	} {
		if _, err := HApp([]ModelEntry{e}); !errors.Is(err, ErrMalformedModelEntry) {
			t.Errorf("HApp(%+v) err = %v, want ErrMalformedModelEntry", e, err)
		}
	}
}

// TestVerifyAuxIsTheGate moves one input at a time away from a binding that
// verifies, and checks each is refused. SplitReportData checks only that the
// upper half is non-zero, so without VerifyAux the upper half would be 32
// bytes of the node's choice signed by real hardware.
func TestVerifyAuxIsTheGate(t *testing.T) {
	const nodeID = uint64(7)
	entries := []ModelEntry{
		{ModelID: "m", Source: "hf/m", WeightsDigest: "sha256:ab12", State: WeightsMeasured},
	}
	hApp, err := HApp(entries)
	if err != nil {
		t.Fatalf("HApp: %v", err)
	}
	nonce := [32]byte{1, 2, 3}
	nonceHex := hex.EncodeToString(nonce[:])
	posture := &TEEPosture{PlaintextTerminates: "named_upstream", UpstreamBaseURL: "https://api.x.ai/v1", ZeroRetention: true}
	good := ReportDataHalves{AuxBinding: AuxBinding(nodeID, hApp, mustHPosture(t, posture), &nonce)}

	if err := good.VerifyAux(nodeID, entries, posture, nonceHex, &nonce); err != nil {
		t.Fatalf("VerifyAux rejected the binding its own inputs produce: %v", err)
	}
	lookalike := *posture
	lookalike.UpstreamBaseURL = "https://api.x.ai.attacker.example/v1"

	other := []ModelEntry{
		{ModelID: "m", Source: "hf/m", WeightsDigest: "sha256:ff99", State: WeightsMeasured},
	}
	var otherNonce [32]byte
	otherNonce[31] = 9

	for _, tc := range []struct {
		name    string
		nodeID  uint64
		entries []ModelEntry
		posture *TEEPosture
		echoed  string
		want    error
	}{
		{"a different node id", nodeID + 1, entries, posture, nonceHex, ErrAuxBindingMismatch},
		{"a substituted weights digest", nodeID, other, posture, nonceHex, ErrAuxBindingMismatch},
		{"a substituted upstream", nodeID, entries, &lookalike, nonceHex, ErrAuxBindingMismatch},
		{"the posture dropped", nodeID, entries, nil, nonceHex, ErrAuxBindingMismatch},
		{"a different echoed nonce", nodeID, entries, posture, hex.EncodeToString(otherNonce[:]), ErrNonceMismatch},
		{"the echo dropped", nodeID, entries, posture, "", ErrNonceMismatch},
		{"the catalog dropped", nodeID, nil, posture, nonceHex, ErrHAppPreimageMissing},
	} {
		if err := good.VerifyAux(tc.nodeID, tc.entries, tc.posture, tc.echoed, &nonce); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	// An HApp error reaches the caller unchanged, so it is tagged
	// happ_preimage_invalid rather than aux_binding_mismatch.
	dup := []ModelEntry{entries[0], entries[0]}
	if err := good.VerifyAux(nodeID, dup, posture, nonceHex, &nonce); !errors.Is(err, ErrDuplicateModelID) {
		t.Errorf("a duplicate-id catalog returned %v, want ErrDuplicateModelID", err)
	}
}

// TestAuxBindingNilAndZeroNonceAgree pins that an absent nonce hashes as
// 32 zero bytes. That is why the digest alone cannot show a dropped nonce,
// and why VerifyAux compares the echo with the challenge before hashing.
func TestAuxBindingNilAndZeroNonceAgree(t *testing.T) {
	h := HAppPending()
	p := mustHPosture(t, nil)
	var zero [32]byte
	if AuxBinding(7, h, p, nil) != AuxBinding(7, h, p, &zero) {
		t.Fatal("an absent nonce and an all-zero nonce produce different bindings — " +
			"absent IS 32 zero bytes, and a verifier recomputing the zero case would " +
			"reject a cached bundle")
	}
}

// TestHAppSeparatesItsInputs is the cheap guard against a preimage whose
// fields can slide into each other. Every field is length-prefixed, so this
// should hold by construction — it is asserted because "by construction"
// stops being true the moment someone appends a bare string.
//
// It is H_app's guard and not AuxBinding's: AuxBinding's fields are all
// fixed-width (be64, 32, 32), so nothing there can slide and there is no
// equivalent test to write.
func TestHAppSeparatesItsInputs(t *testing.T) {
	a, err := HApp([]ModelEntry{{ModelID: "ab", Source: "c", WeightsDigest: "sha256:1", State: WeightsMeasured}})
	if err != nil {
		t.Fatalf("HApp: %v", err)
	}
	b, err := HApp([]ModelEntry{{ModelID: "a", Source: "bc", WeightsDigest: "sha256:1", State: WeightsMeasured}})
	if err != nil {
		t.Fatalf("HApp: %v", err)
	}
	if a == b {
		t.Fatal("moving a byte from model_id into source produced the same H_app — " +
			"the length prefixes are not separating the fields")
	}
}
