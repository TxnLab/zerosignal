/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/TxnLab/zerosignal/go/inject"
)

// ReportData computes the binding nonce a TEE embeds in its report's
// report_data / REPORT_DATA / nonce field:
//
//	report_data = SHA-256(node_pubkey_bytes || operator_id_be64)
//
// The operator id is big-endian so the digest input has one canonical
// form across implementations. See proto/SPEC.md §3e; a mismatch is the
// `key_binding_mismatch` failure tag in proto/TEE.md §4.3.
//
// nodePubkey is the node's current **ephemeral age recipient** — the key
// requests are actually sealed to. It is deliberately NOT the on-chain
// signing address: attesting the identity key would prove only that the
// enclave controls the operator identity, leaving the hop from that key
// to the sealing key operator-attested (an Ed25519 advertisement
// signature nothing proves was produced inside the CVM). An operator
// holding a copy of the signing key outside the enclave could then point
// traffic at an ephemeral whose private half lives on the plain host and
// still pass every check. Because the sealing key rotates, callers pass
// it per mint rather than capturing it once.
//
// NODE ID IS NOT IN THIS HASH. The verifier's nodePubkey argument is the
// ephemeral it verified for this node, and that verification
// (ticket.EphemeralAdvertisement.Verify) already covers the chain-resolved
// node id. operatorID is here for what the advertisement cannot cover: a
// different owner replaying a bundle, whose chain-resolved id then gives a
// different digest.
//
// Within one operator, the owner can sign an advertisement naming a sibling
// node's ephemeral, so this half alone lets a node present a sibling's
// bundle. The upper half closes that: AuxBinding hashes be64(node_id).
//
// One function, because the node, the proxy and client/ (in TypeScript)
// must compute identical bytes. A divergent copy produces a
// key_binding_mismatch on valid evidence, and nothing in either log names
// the disagreement.
func ReportData(nodePubkey string, operatorID uint64) []byte {
	var idBytes [8]byte
	binary.BigEndian.PutUint64(idBytes[:], operatorID)
	h := sha256.New()
	h.Write([]byte(nodePubkey))
	h.Write(idBytes[:])
	return h.Sum(nil)
}

// ReportDataB64 is ReportData in the standard-base64 form the bundle's
// `report_data` JSON field carries.
func ReportDataB64(nodePubkey string, operatorID uint64) string {
	return base64.StdEncoding.EncodeToString(ReportData(nodePubkey, operatorID))
}

// ---------------------------------------------------------------------------
// Aux binding — the UPPER 32 bytes of report_data (proto 9.9, posture 9.10)
//
// ReportData above is the lower half. The upper half commits to the node id,
// the model catalog the node advertises, the node's dataflow posture, and an
// optional caller nonce.
// ---------------------------------------------------------------------------

// Domain tags for the digests. Each ends in NUL and contains no other NUL, so
// no tag is a prefix of another. The aux tag moved to v2 when H_posture joined
// the preimage: a v1 binding is then a mismatch rather than a digest that
// happens to verify over a shorter input.
const (
	auxBindingTag = "zs-aux-v2\x00"
	hAppTag       = "zs-happ-v1\x00"
	hPostureTag   = "zs-posture-v1\x00"
)

// TEEPosture aliases the wire type for the same reason ModelEntry does.
type TEEPosture = inject.TEEPosture

// ErrMalformedPosture: a posture string is not valid UTF-8. A node holding one
// would mint a digest no verifier reproduces (JSON encoding replaces the bad
// bytes), so HPosture refuses it and the node refuses to mint.
var ErrMalformedPosture = errors.New("attest: malformed posture")

// HPosture is the measurement of the node's dataflow posture:
//
//	H_posture = SHA-256( "zs-posture-v1\x00" || u8(0) )                   absent
//	H_posture = SHA-256( "zs-posture-v1\x00" || u8(1) ||
//	                     lenStr(plaintext_terminates) ||
//	                     lenStr(upstream_base_url) || u8(zero_retention) ||
//	                     u8(upstream_attested) )                            present
//
// Before 9.10 the posture block was a self-report bound to nothing: the
// measured image computed it honestly, but anything between the enclave and
// the verifier could rewrite it, and verifiers could only check it for
// internal coherence. Hashing it into report_data means the upstream a payer
// judges is the upstream the measured binary derived from its EFFECTIVE
// config — after env overrides and after dstack's ${VAR} substitution, which
// happens outside the compose hash. The literal NODE_CONFIG_YAML text cannot
// give that, which is why the verifier does not parse it.
//
// An absent posture is committed as absent rather than refused: the field is
// optional on the wire and a node publishing none makes no claim. Committing
// the absence means a relay can neither strip a posture nor add one.
//
// Every TEEPosture field is in the preimage; TestHPostureCoversEveryField
// fails when a field is added without a matching preimage change.
func HPosture(p *TEEPosture) ([32]byte, error) {
	b := make([]byte, 0, 64)
	b = append(b, hPostureTag...)
	if p == nil {
		b = append(b, 0)
		return sha256.Sum256(b), nil
	}
	if p.Malformed() || !utf8.ValidString(p.PlaintextTerminates) || !utf8.ValidString(p.UpstreamBaseURL) {
		return [32]byte{}, ErrMalformedPosture
	}
	b = append(b, 1)
	b = appendLenStr(b, p.PlaintextTerminates)
	b = appendLenStr(b, p.UpstreamBaseURL)
	b = append(b, boolByte(p.ZeroRetention), boolByte(p.UpstreamAttested))
	return sha256.Sum256(b), nil
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// Aliases of the wire types in inject, which defines them with the rest of
// the bundle (attest already imports inject, so the reverse would be a
// cycle). One type means a verifier hashes exactly the struct it decoded.
type (
	WeightsState = inject.WeightsState
	ModelEntry   = inject.ModelEntry
)

const (
	WeightsMeasured     = inject.WeightsMeasured
	WeightsDeclared     = inject.WeightsDeclared
	WeightsUnverifiable = inject.WeightsUnverifiable
)

var (
	// ErrMalformedModelEntry: the entry's JSON lacked a key, carried a null,
	// or had a value of the wrong type. See inject.ModelEntry.UnmarshalJSON.
	ErrMalformedModelEntry = errors.New("attest: malformed model entry")
	// ErrDuplicateModelID: two entries name one model. A minter and a
	// verifier that kept different ones would compute different digests.
	ErrDuplicateModelID = errors.New("attest: duplicate model id in the entry list")
	// ErrEmptyModelID: an entry with no id cannot match any request.
	ErrEmptyModelID = errors.New("attest: entry has an empty model id")
	// ErrStateDigestDisagree: an unverifiable entry carries a digest, or a
	// measured or declared entry carries none.
	ErrStateDigestDisagree = errors.New("attest: entry state disagrees with its weights digest")
	// ErrUnknownWeightsState: a state this build does not know, including 0.
	// Refused so a newer node's state is never hashed as one this verifier
	// thinks it understands.
	ErrUnknownWeightsState = errors.New("attest: unknown weights state")
)

// HApp is the measurement of the model set:
//
//	H_app = SHA-256( "zs-happ-v1\x00" || be32(len(entries)) || entry... )
//	entry = lenStr(model_id) || lenStr(source) || lenStr(weights_digest) || u8(state)
//
// A node MUST list its complete advertised catalog: a node that listed only
// the models it could hash could serve an unlisted one and still verify. The
// list can lag /v1/zs/details by about 75 s after a catalog change, so the
// reference verifiers report it and do not route on it.
//
// HApp first rejects any malformed entry, scanning in the caller's order,
// then stable-sorts by ModelID bytes, then checks each sorted entry for an
// empty id, a duplicate id, and a state/digest disagreement. The TypeScript
// hApp does the same, so both return the same error for the same list.
// Sorting inside HApp means a node and a verifier holding the same set in
// different orders agree. The caller's slice is not mutated.
//
// A string that is not valid UTF-8 counts as malformed. Encoding it to JSON
// replaces the bad bytes with U+FFFD, so a node whose catalog held one would
// mint a hash no verifier reproduces; refusing it here makes the node refuse
// to mint instead.
//
// An empty list is valid; see HAppPending.
//
// On error HApp returns the zero [32]byte. A caller that ignores the error
// builds an AuxBinding over it that no verifier reproduces, so the mistake
// fails closed. Check the error anyway.
func HApp(entries []ModelEntry) ([32]byte, error) {
	for _, e := range entries {
		if e.Malformed() || !utf8.ValidString(e.ModelID) ||
			!utf8.ValidString(e.Source) || !utf8.ValidString(e.WeightsDigest) {
			return [32]byte{}, ErrMalformedModelEntry
		}
	}

	sorted := make([]ModelEntry, len(entries))
	copy(sorted, entries)
	slices.SortStableFunc(sorted, func(a, b ModelEntry) int {
		return strings.Compare(a.ModelID, b.ModelID)
	})

	b := make([]byte, 0, 64+len(sorted)*96)
	b = append(b, hAppTag...)
	b = appendU32(b, uint32(len(sorted)))

	for i, e := range sorted {
		if e.ModelID == "" {
			return [32]byte{}, ErrEmptyModelID
		}
		// Duplicates are adjacent after the sort.
		if i > 0 && e.ModelID == sorted[i-1].ModelID {
			return [32]byte{}, fmt.Errorf("%w: %q", ErrDuplicateModelID, e.ModelID)
		}
		switch e.State {
		case WeightsMeasured, WeightsDeclared:
			if e.WeightsDigest == "" {
				return [32]byte{}, fmt.Errorf("%w: %q is %s with no digest",
					ErrStateDigestDisagree, e.ModelID, e.State)
			}
		case WeightsUnverifiable:
			if e.WeightsDigest != "" {
				return [32]byte{}, fmt.Errorf("%w: %q is unverifiable yet carries a digest",
					ErrStateDigestDisagree, e.ModelID)
			}
		default:
			return [32]byte{}, fmt.Errorf("%w: %q has state %d",
				ErrUnknownWeightsState, e.ModelID, uint8(e.State))
		}
		b = appendLenStr(b, e.ModelID)
		b = appendLenStr(b, e.Source)
		b = appendLenStr(b, e.WeightsDigest)
		b = append(b, byte(e.State))
	}
	return sha256.Sum256(b), nil
}

// HAppPending is the H_app of an empty entry list. A node publishes it until
// its catalog is available to the minter.
//
// It is not zero, so AuxBinding over it is not zero either, and
// SplitReportData does not mistake a booting node for a pre-9.9 one. A
// bundle carrying it verifies and lists no models.
func HAppPending() [32]byte {
	h, err := HApp(nil)
	if err != nil {
		panic("attest: HApp(nil) must not fail: " + err.Error())
	}
	return h
}

// AuxBinding is the upper 32 bytes of report_data:
//
//	aux_binding = SHA-256( "zs-aux-v2\x00" || be64(node_id) || H_app || H_posture || nonce )
//
// node_id is here so a node cannot present a sibling node's bundle; see
// ReportData. It is be64, like operator_id in ReportData: a decimal string
// would give "0042" and "42" different preimages.
//
// A nil nonce hashes as 32 zero bytes, as does an explicit all-zero nonce.
// The type is *[32]byte, so a wrong-length nonce does not compile.
func AuxBinding(nodeID uint64, hApp, hPosture [32]byte, nonce *[32]byte) [32]byte {
	b := make([]byte, 0, len(auxBindingTag)+8+32+32+32)
	b = append(b, auxBindingTag...)
	b = appendU64(b, nodeID)
	b = append(b, hApp[:]...)
	b = append(b, hPosture[:]...)
	if nonce != nil {
		b = append(b, nonce[:]...)
	} else {
		var zero [32]byte
		b = append(b, zero[:]...)
	}
	return sha256.Sum256(b)
}

var (
	// ErrAuxBindingMismatch: the signed aux binding is not
	// AuxBinding(nodeID, HApp(entries), HPosture(posture), nonce). The
	// catalog, the posture, the node id or the nonce differs from what the
	// hardware signed; the digest cannot say which.
	ErrAuxBindingMismatch = errors.New("attest: aux binding does not match node id, catalog, posture and nonce")
	// ErrHAppPreimageMissing: the bundle lists no models, and the signed aux
	// binding is not the empty-catalog value for this node, posture and
	// nonce. The node signed some other catalog without publishing it, or
	// the node id, posture or nonce differs.
	ErrHAppPreimageMissing = errors.New("attest: bundle lists no models but the quote does not commit to an empty catalog")
	// ErrNonceMismatch: the verifier sent a challenge and the bundle's
	// nonce is absent, malformed, or a different value. The bundle was not
	// minted for this challenge.
	ErrNonceMismatch = errors.New("attest: bundle nonce does not echo the challenge")
	// ErrMalformedNonce: the verifier sent no challenge and the bundle's
	// nonce is present but is not 64 hex characters.
	ErrMalformedNonce = errors.New("attest: bundle nonce is not 64 hex characters")
	// ErrZeroChallenge: the verifier's own challenge is all zero, which
	// hashes the same as no challenge. A cached bundle with "nonce" set to
	// 64 zeros would then pass as fresh. Seen only from a verifier bug,
	// such as an unchecked random read into a zeroed array.
	ErrZeroChallenge = errors.New("attest: challenge is all zero")
)

// VerifyAux recomputes the aux binding from a bundle and compares it with
// the upper half the hardware signed. SplitReportData checks only that the
// upper half is non-zero; this is the check of its value.
//
// VerifyAux holds the nonce, empty-list and comparison rules, so each
// verifier calls one function instead of reimplementing them. The
// aux_verify vectors pin that it and the TypeScript verifyAux decide each
// case the same way.
//
// nodeID MUST be the chain-resolved id. The bundle does not carry one.
//
// entries is the bundle's app_models as decoded (nil if the field was
// absent). posture is the bundle's posture as decoded (nil if absent). A
// verifier MUST judge the same posture value it passed here — a copy read
// from anywhere else is unbound again.
//
// echoed is the bundle's nonce field ("" if absent). challenge is the nonce
// this verifier sent with ?nonce=, or nil if it sent none:
//
//   - challenge set: it must not be all zero (ErrZeroChallenge), and echoed
//     must decode to it (ErrNonceMismatch otherwise). challenge is hashed.
//   - challenge nil, echoed empty: 32 zero bytes are hashed.
//   - challenge nil, echoed set: echoed must be 64 hex characters
//     (ErrMalformedNonce otherwise), and its bytes are hashed. A bundle
//     minted for someone else's challenge therefore still verifies; a
//     verifier that wants freshness has to send its own.
//
// Errors, in the order they are checked:
//
//  1. ErrZeroChallenge, then ErrNonceMismatch or ErrMalformedNonce.
//  2. An error from HApp.
//  3. ErrMalformedPosture.
//  4. ErrHAppPreimageMissing if entries is empty and the binding differs,
//     otherwise ErrAuxBindingMismatch.
func (h ReportDataHalves) VerifyAux(nodeID uint64, entries []ModelEntry, posture *TEEPosture, echoed string, challenge *[32]byte) error {
	nonce, err := resolveNonce(echoed, challenge)
	if err != nil {
		return err
	}
	hApp, err := HApp(entries)
	if err != nil {
		return err
	}
	hPosture, err := HPosture(posture)
	if err != nil {
		return err
	}
	if h.AuxBinding != AuxBinding(nodeID, hApp, hPosture, nonce) {
		if len(entries) == 0 {
			return ErrHAppPreimageMissing
		}
		return ErrAuxBindingMismatch
	}
	return nil
}

func resolveNonce(echoed string, challenge *[32]byte) (*[32]byte, error) {
	if challenge != nil {
		if *challenge == ([32]byte{}) {
			return nil, ErrZeroChallenge
		}
		got, ok := decodeNonce(echoed)
		if !ok || got != *challenge {
			return nil, ErrNonceMismatch
		}
		return challenge, nil
	}
	if echoed == "" {
		return nil, nil
	}
	got, ok := decodeNonce(echoed)
	if !ok {
		return nil, ErrMalformedNonce
	}
	return &got, nil
}

// decodeNonce accepts exactly 64 hex characters, either case, matching
// the TypeScript verifier's /^[0-9a-fA-F]{64}$/.
func decodeNonce(s string) ([32]byte, bool) {
	var n [32]byte
	if len(s) != 64 {
		return n, false
	}
	if _, err := hex.Decode(n[:], []byte(s)); err != nil {
		return n, false
	}
	return n, true
}

// Failure tags for the aux binding (proto/SPEC.md §3e, verifier step 6).
const (
	TagAuxBindingAbsent       = "aux_binding_absent"
	TagAuxBindingMismatch     = "aux_binding_mismatch"
	TagHAppPreimageMissing    = "happ_preimage_missing"
	TagHAppPreimageInvalid    = "happ_preimage_invalid"
	TagPosturePreimageInvalid = "posture_preimage_invalid"
)

// TagPostureUpstreamUnverifiable is verifier step 7's refusal of a bound
// named_upstream posture that inject.NamedUpstreamAdmissible rejects. It is
// not an aux-binding failure (the binding verified), so AuxFailureTag never
// returns it.
const TagPostureUpstreamUnverifiable = "posture_upstream_unverifiable"

// AuxFailureTag maps an error from SplitReportData's aux check or from
// VerifyAux to its SPEC failure tag. It returns "" for nil, and
// TagAuxBindingMismatch for any error it does not recognise, so an
// unmapped error still refuses. The TypeScript auxFailureTag mirrors it,
// and the aux_verify vectors pin both.
//
// Handle ErrReportDataAbsent before calling it: SPEC tags a quote too short
// to hold report_data key_binding_mismatch, which is not an aux tag.
func AuxFailureTag(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAuxBindingAbsent):
		return TagAuxBindingAbsent
	case errors.Is(err, ErrHAppPreimageMissing):
		return TagHAppPreimageMissing
	case errors.Is(err, ErrMalformedModelEntry),
		errors.Is(err, ErrDuplicateModelID),
		errors.Is(err, ErrEmptyModelID),
		errors.Is(err, ErrStateDigestDisagree),
		errors.Is(err, ErrUnknownWeightsState):
		return TagHAppPreimageInvalid
	case errors.Is(err, ErrMalformedPosture):
		return TagPosturePreimageInvalid
	default:
		// ErrAuxBindingMismatch, ErrNonceMismatch and ErrMalformedNonce land
		// here. ErrZeroChallenge does too, although the verifier is at fault,
		// not the node. Only a broken verifier sends an all-zero challenge, so
		// it gets no tag of its own.
		return TagAuxBindingMismatch
	}
}

// Canonical-bytes helpers, matching the encoding rules in proto/go/ticket.
// Duplicated because ticket's copies are unexported and attest does not
// import ticket. These bytes only have to equal their TypeScript twin, which
// the golden vectors pin.
func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendLenStr(b []byte, s string) []byte {
	b = appendU32(b, uint32(len(s)))
	return append(b, s...)
}
