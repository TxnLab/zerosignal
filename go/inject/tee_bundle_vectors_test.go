/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

// Cross-impl vectors for decoding a /v1/zs/attestation body, and for the
// RFC 3339 parse both the decode and attest's collateral dating rest on.
// proto/ts/test/tee-bundle-vectors.test.ts replays them against
// decodeEvidenceBundle and parseRFC3339.
//
// A body one verifier decodes and the other refuses is a node one payer can
// route to and the other cannot, so every outcome is Go's: whether the decode
// fails, and what the fields outside the aux binding decode to. The aux fields
// (nonce, app_models, posture) are left out on purpose. Go coerces a wrongly
// typed one into a value VerifyAux refuses, TypeScript keeps it raw and
// verifyAux refuses that, and attest's aux_verify vectors pin the refusals.
//
// Inputs Go and TypeScript cannot be made to agree on are left out too; the
// TypeScript decoder's comment lists them.
//
// Regenerate after an intentional change:
//
//	cd proto/go && go test ./inject -run TestTEEBundleVectors -update

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
)

const teeBundleVectorsPath = "../../testdata/tee_bundle_vectors.json"

type teeTimeVector struct {
	UnixSec int64 `json:"unix_sec"`
	Nanos   int   `json:"nanos"`
}

func teeTime(t time.Time) *teeTimeVector {
	if t.IsZero() {
		return nil
	}
	return &teeTimeVector{UnixSec: t.Unix(), Nanos: t.Nanosecond()}
}

type rfc3339Vector struct {
	Input string         `json:"input"`
	Time  *teeTimeVector `json:"time"` // null when Go refuses the input
}

type decodedUpstream struct {
	Protocol       string         `json:"protocol"`
	BaseURL        string         `json:"base_url"`
	ReportURL      string         `json:"report_url"`
	KeysetDigest   string         `json:"keyset_digest"`
	VerifiedAt     *teeTimeVector `json:"verified_at"`
	LeaseExpiresAt *teeTimeVector `json:"lease_expires_at"`
	CarveOuts      []string       `json:"carve_outs"`
}

// decodedBundle is every field of a decoded bundle outside the aux binding,
// with times as instants so the TypeScript side compares what it parsed
// rather than the string it kept.
type decodedBundle struct {
	Mode           string                `json:"mode"`
	CPUReport      string                `json:"cpu_report"`
	GPUEAT         string                `json:"gpu_eat"`
	EventLog       string                `json:"event_log"`
	AppCompose     string                `json:"app_compose"`
	NodePubkey     string                `json:"node_pubkey"`
	OperatorID     uint64                `json:"operator_id"`
	ReportData     string                `json:"report_data"`
	GeneratedAt    *teeTimeVector        `json:"generated_at"`
	RefreshSeconds int                   `json:"refresh_seconds"`
	Stub           bool                  `json:"stub"`
	Collateral     *inject.TEECollateral `json:"collateral"`
	Upstream       *decodedUpstream      `json:"upstream_attestation"`
}

type bundleDecodeVector struct {
	Name string `json:"name"`
	Why  string `json:"why,omitempty"`
	// Body is the response body, or BodyHex when it is not valid UTF-8 and
	// so cannot ride a JSON string.
	Body    string         `json:"body,omitempty"`
	BodyHex string         `json:"body_hex,omitempty"`
	Decoded *decodedBundle `json:"decoded"` // null when Go refuses the body
}

type teeBundleVectorsFile struct {
	Version      int                  `json:"version"`
	Comment      string               `json:"comment"`
	RFC3339      []rfc3339Vector      `json:"rfc3339"`
	BundleDecode []bundleDecodeVector `json:"bundle_decode"`
}

// rfc3339Inputs covers what Go's time.Parse(time.RFC3339, …) accepts beyond the
// canonical form, because that is what the TypeScript parser has to match:
// time.Time's UnmarshalJSON goes through the same parse.
var rfc3339Inputs = []string{
	"2026-10-09T12:34:56Z",
	"2026-10-09T12:34:56.5Z",
	"2026-10-09T12:34:56.000Z",
	"2026-10-09T12:34:56.123456789Z",
	"2026-10-09T12:34:56.1234567891234Z", // digits past the ninth are dropped, not rounded
	"2026-10-09T12:34:56,5Z",             // a comma separator, accepted by Parse's fallback
	"2026-10-09T12:34:56.Z",
	"2026-10-09T12:34:56.5,5Z",
	"2026-10-09T12:34:56.-5Z",
	"2026-10-09T1:34:56Z", // a one-digit hour, accepted by the fallback
	"2026-10-09T12:3:56Z",
	"2026-10-09T12:34:5Z",
	"2026-10-9T12:34:56Z",
	"2026-1-09T12:34:56Z",
	"2026-10-09t12:34:56Z",
	"2026-10-09T12:34:56z",
	"2026-10-09 12:34:56Z",
	"2026-10-09T12:34:56+05:30",
	"2026-10-09T12:34:56.5+05:30",
	"2026-10-09T12:34:56-07:00",
	"2026-10-09T12:34:56+00:00",
	"2026-10-09T12:34:56-00:00",
	"2026-10-09T12:34:56+24:00", // offsets up to 24h and 60m are accepted
	"2026-10-09T12:34:56+23:60",
	"2026-10-09T12:34:56+25:00",
	"2026-10-09T12:34:56+00:61",
	"2026-10-09T12:34:56+0530",
	"2026-10-09T12:34:56+5:30",
	"2026-10-09T12:34:56+05:3",
	"2026-10-09T12:34:56",
	"2026-10-09T12:34Z",
	"2026-10-09T23:59:59Z",
	"2026-10-09T24:00:00Z",
	"2026-10-09T12:60:00Z",
	"2026-10-09T12:34:60Z",
	"2026-02-29T00:00:00Z",
	"2024-02-29T00:00:00Z",
	"2000-02-29T00:00:00Z",
	"1900-02-29T00:00:00Z",
	"2026-04-31T00:00:00Z",
	"2026-12-31T00:00:00Z",
	"2026-00-09T12:34:56Z",
	"2026-13-09T12:34:56Z",
	"2026-10-00T12:34:56Z",
	"0000-01-01T00:00:00Z",
	"0001-01-01T00:00:00Z",
	"1969-12-31T23:59:59.999999999Z",
	"9999-12-31T23:59:59Z",
	"10000-01-01T00:00:00Z",
	" 2026-10-09T12:34:56Z",
	"2026-10-09T12:34:56Z ",
	"2026-10-09T12:34:56ZZ",
	"+2026-10-09T12:34:56Z",
	"２026-10-09T12:34:56Z",
	"2026-10-09T12:34:56.５Z",
	"",
}

// A complete, well-formed bundle; the cases below are edits of it.
const baseBundle = `{"mode":"dstack-tdx","cpu_report":"AAEC","event_log":"[]","app_compose":"{}",` +
	`"posture":{"plaintext_terminates":"in_enclave"},"node_pubkey":"age1k","operator_id":42,` +
	`"report_data":"AAAA","app_models":[],"generated_at":"2026-10-09T12:34:56.123456789Z",` +
	`"refresh_seconds":600,` +
	`"upstream_attestation":{"protocol":"aci/1","base_url":"https://u.example","report_url":"https://u.example/r",` +
	`"keyset_digest":"sha256:00","verified_at":"2026-10-09T12:00:00Z","lease_expires_at":"2026-10-10T12:00:00+02:00",` +
	`"carve_outs":["root_backdoor_env:X"]},` +
	`"collateral":{"pck_crl_issuer_chain":"a","root_ca_crl":"b","pck_crl":"c","tcb_info_issuer_chain":"d",` +
	`"tcb_info":"{\"issueDate\":\"x\"}","tcb_info_signature":"e","qe_identity_issuer_chain":"f",` +
	`"qe_identity":"{}","qe_identity_signature":"g"}}`

// edit replaces one top-level key's value in baseBundle (or removes it when
// value is empty), so each case reads as the one thing it changes.
func edit(key, value string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(baseBundle), &m); err != nil {
		panic(err)
	}
	if value == "" {
		delete(m, key)
	} else {
		m[key] = json.RawMessage(value)
	}
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// deepBundle nests key's value in n arrays inside the outer object.
func deepBundle(key string, n int) string {
	return `{"mode":"stub","` + key + `":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
}

var bundleDecodeCases = []struct{ name, why, body string }{
	{"base", "every field present and well typed", baseBundle},
	{"empty_object", "every field takes its zero value", `{}`},
	{"top_level_null", "Go calls UnmarshalJSON with null, which decodes to a zero bundle", `null`},
	{"top_level_array", "", `[1,2]`},
	{"top_level_string", "", `"bundle"`},
	{"top_level_number", "", `5`},
	{"not_json", "", `{"mode":`},
	{"trailing_data", "", `{} {}`},
	{"leading_bom", "both decoders refuse a byte-order mark", string([]byte{0xef, 0xbb, 0xbf}) + "{}"},
	{"surrounding_whitespace", "", " \n\t{\"mode\":\"stub\"}\r\n"},
	{"unknown_keys_ignored", "", `{"mode":"stub","extra":{"x":[1,2]},"other":5}`},
	{"case_variant_only", "a case-variant key is not the field", `{"MODE":"stub","Operator_ID":"x","Stub":"yes"}`},
	{"case_variant_beside_exact", "the exact key wins whichever comes last", `{"mode":"a","Mode":"b","cpu_report":"A","CPU_REPORT":"B"}`},
	{"unicode_folded_key", "ſ folds to s in Go's default decoding", `{"app_compoſe":"C","node_pubkey":"k"}`},
	{"duplicate_key_last_wins", "", `{"mode":"a","mode":"b"}`},
	{"duplicate_key_type_then_string", "only the last duplicate is decoded", `{"mode":5,"mode":"b"}`},
	{"depth_10000", "encoding/json's limit, counting the outer object", deepBundle("extra", 9999)},
	{"depth_10001", "one past it fails the whole body, even in an unknown field", deepBundle("extra", 10000)},
	{"depth_10001_under_nonce", "the depth check runs before any aux coercion", deepBundle("nonce", 10000)},
	{"brackets_in_string", "brackets inside a string are not nesting", `{"mode":"\"` + strings.Repeat("[", 10001) + `"}`},

	{"mode_number", "", edit("mode", `5`)},
	{"mode_null", "null leaves a string empty", edit("mode", `null`)},
	{"node_pubkey_object", "", edit("node_pubkey", `{}`)},
	{"report_data_array", "", edit("report_data", `["AAAA"]`)},
	{"cpu_report_bool", "", edit("cpu_report", `true`)},
	{"event_log_number", "", edit("event_log", `0`)},
	{"app_compose_object", "app_compose is the document as a string, never the object", edit("app_compose", `{"runner":"x"}`)},
	{"gpu_eat_present", "", edit("gpu_eat", `"a.b.c"`)},

	{"operator_id_string", "", edit("operator_id", `"42"`)},
	{"operator_id_negative", "", edit("operator_id", `-1`)},
	{"operator_id_negative_zero", "ParseUint refuses -0", edit("operator_id", `-0`)},
	{"operator_id_fraction", "", edit("operator_id", `42.5`)},
	{"operator_id_null", "", edit("operator_id", `null`)},
	{"operator_id_zero", "", edit("operator_id", `0`)},
	{"operator_id_max_safe", "", edit("operator_id", `9007199254740991`)},
	{"operator_id_overflow", "2^64 does not fit a uint64", edit("operator_id", `18446744073709551616`)},
	{"operator_id_bool", "", edit("operator_id", `true`)},

	{"refresh_seconds_negative", "", edit("refresh_seconds", `-60`)},
	{"refresh_seconds_negative_zero", "ParseInt accepts -0 as 0", edit("refresh_seconds", `-0`)},
	{"refresh_seconds_string", "", edit("refresh_seconds", `"600"`)},
	{"refresh_seconds_fraction", "", edit("refresh_seconds", `1.5`)},
	{"refresh_seconds_null", "", edit("refresh_seconds", `null`)},
	{"refresh_seconds_absent", "", edit("refresh_seconds", ``)},

	{"stub_true", "", edit("stub", `true`)},
	{"stub_string", "", edit("stub", `"true"`)},
	{"stub_number", "", edit("stub", `1`)},
	{"stub_null", "", edit("stub", `null`)},

	{"generated_at_offset", "", edit("generated_at", `"2026-10-09T14:34:56+02:00"`)},
	{"generated_at_one_digit_hour", "accepted by Go's fallback parse", edit("generated_at", `"2026-10-09T1:34:56Z"`)},
	{"generated_at_comma_fraction", "", edit("generated_at", `"2026-10-09T12:34:56,25Z"`)},
	{"generated_at_offset_24h", "", edit("generated_at", `"2026-10-09T12:34:56+24:00"`)},
	{"generated_at_offset_60m", "", edit("generated_at", `"2026-10-09T12:34:56+23:60"`)},
	{"generated_at_empty", "an empty string is not a time", edit("generated_at", `""`)},
	{"generated_at_garbage", "", edit("generated_at", `"yesterday"`)},
	{"generated_at_date_only", "", edit("generated_at", `"2026-10-09"`)},
	{"generated_at_lowercase", "", edit("generated_at", `"2026-10-09t12:34:56z"`)},
	{"generated_at_number", "", edit("generated_at", `1791549296`)},
	{"generated_at_null", "null leaves the zero time", edit("generated_at", `null`)},
	{"generated_at_absent", "", edit("generated_at", ``)},
	{"generated_at_feb_30", "", edit("generated_at", `"2026-02-30T00:00:00Z"`)},

	{"aux_nonce_number", "a wrongly typed aux field does not fail the decode", edit("nonce", `5`)},
	{"aux_app_models_string", "", edit("app_models", `"x"`)},
	{"aux_app_models_bad_entry", "", edit("app_models", `[{"model_id":5}]`)},
	{"aux_posture_number", "", edit("posture", `5`)},
	{"aux_posture_bad_field", "", edit("posture", `{"zero_retention":"yes"}`)},

	{"collateral_null", "", edit("collateral", `null`)},
	{"collateral_string", "", edit("collateral", `"x"`)},
	{"collateral_array", "", edit("collateral", `[]`)},
	{"collateral_number_field", "", edit("collateral", `{"tcb_info":5}`)},
	{"collateral_null_field", "null leaves a member empty", edit("collateral", `{"tcb_info":null,"pck_crl":"c"}`)},
	{"collateral_partial", "the decode does not check completeness; Complete does", edit("collateral", `{"pck_crl":"c"}`)},
	{"collateral_empty_object", "", edit("collateral", `{}`)},
	{"collateral_case_variants", "", edit("collateral", `{"tcb_info":"A","TCB_INFO":"B","PCK_CRL":"C"}`)},

	{"upstream_null", "", edit("upstream_attestation", `null`)},
	{"upstream_array", "", edit("upstream_attestation", `[]`)},
	{"upstream_string", "", edit("upstream_attestation", `"aci/1"`)},
	{"upstream_protocol_number", "", edit("upstream_attestation", `{"protocol":1}`)},
	{"upstream_verified_at_bad", "a bad time inside the block fails the whole decode", edit("upstream_attestation", `{"protocol":"aci/1","verified_at":"soon"}`)},
	{"upstream_lease_null", "", edit("upstream_attestation", `{"protocol":"aci/1","lease_expires_at":null}`)},
	{"upstream_carve_outs_null_entry", "a null entry decodes to an empty string", edit("upstream_attestation", `{"carve_outs":["a",null]}`)},
	{"upstream_carve_outs_number_entry", "", edit("upstream_attestation", `{"carve_outs":[1]}`)},
	{"upstream_carve_outs_string", "", edit("upstream_attestation", `{"carve_outs":"a"}`)},
	{"upstream_carve_outs_null", "", edit("upstream_attestation", `{"carve_outs":null}`)},
	{"upstream_case_variants", "", edit("upstream_attestation", `{"protocol":"aci/1","CARVE_OUTS":["y"],"Protocol":"x"}`)},
}

func decodeForVector(body []byte) *decodedBundle {
	var b inject.TEEEvidenceBundle
	if err := json.Unmarshal(body, &b); err != nil {
		return nil
	}
	d := &decodedBundle{
		Mode:           b.Mode,
		CPUReport:      b.CPUReport,
		GPUEAT:         b.GPUEAT,
		EventLog:       b.EventLog,
		AppCompose:     b.AppCompose,
		NodePubkey:     b.NodePubkey,
		OperatorID:     b.OperatorID,
		ReportData:     b.ReportData,
		GeneratedAt:    teeTime(b.GeneratedAt),
		RefreshSeconds: b.RefreshSeconds,
		Stub:           b.Stub,
		Collateral:     b.Collateral,
	}
	if u := b.UpstreamAttestation; u != nil {
		d.Upstream = &decodedUpstream{
			Protocol:       u.Protocol,
			BaseURL:        u.BaseURL,
			ReportURL:      u.ReportURL,
			KeysetDigest:   u.KeysetDigest,
			VerifiedAt:     teeTime(u.VerifiedAt),
			LeaseExpiresAt: teeTime(u.LeaseExpiresAt),
			CarveOuts:      u.CarveOuts,
		}
		if d.Upstream.CarveOuts == nil {
			// Go cannot tell absent from null here; TypeScript reads both as [].
			d.Upstream.CarveOuts = []string{}
		}
	}
	return d
}

func buildTEEBundleVectors(t *testing.T) teeBundleVectorsFile {
	t.Helper()
	f := teeBundleVectorsFile{
		Version: 1,
		Comment: "Generated by proto/go/inject/tee_bundle_vectors_test.go. Do not hand-edit; " +
			"regenerate with `cd proto/go && go test ./inject -run TestTEEBundleVectors -update`.",
	}
	for _, in := range rfc3339Inputs {
		v := rfc3339Vector{Input: in}
		if tm, err := time.Parse(time.RFC3339, in); err == nil {
			v.Time = &teeTimeVector{UnixSec: tm.Unix(), Nanos: tm.Nanosecond()}
		}
		f.RFC3339 = append(f.RFC3339, v)
	}
	for _, c := range bundleDecodeCases {
		f.BundleDecode = append(f.BundleDecode, bundleDecodeVector{
			Name: c.name, Why: c.why, Body: c.body, Decoded: decodeForVector([]byte(c.body)),
		})
	}
	// Not valid UTF-8: a truncated three-byte sequence inside a model id.
	bad := []byte(`{"mode":"dstack-tdx","app_models":[{"model_id":"x` + "\xe2\x82" + `A"}]}`)
	f.BundleDecode = append(f.BundleDecode, bundleDecodeVector{
		Name:    "invalid_utf8",
		Why:     "the two decoders replace bad bytes differently, so both refuse the body",
		BodyHex: hex.EncodeToString(bad),
		Decoded: decodeForVector(bad),
	})
	return f
}

func TestTEEBundleVectors(t *testing.T) {
	f := buildTEEBundleVectors(t)

	// Every case must decode to what its name says, or the fixture pins an
	// accident. Spot-check the ones whose outcome is the point.
	byName := map[string]*decodedBundle{}
	for _, v := range f.BundleDecode {
		byName[v.Name] = v.Decoded
	}
	for _, name := range []string{"base", "top_level_null", "aux_nonce_number", "aux_posture_number", "collateral_partial", "depth_10000", "brackets_in_string"} {
		if byName[name] == nil {
			t.Fatalf("%s: Go refused it, the fixture expects a decode", name)
		}
	}
	for _, name := range []string{"top_level_array", "operator_id_negative_zero", "generated_at_empty", "invalid_utf8", "upstream_verified_at_bad", "depth_10001", "depth_10001_under_nonce"} {
		if byName[name] != nil {
			t.Fatalf("%s: Go decoded it, the fixture expects a refusal", name)
		}
	}

	got, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	if *updateToolGrowthVectors {
		if err := os.WriteFile(teeBundleVectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", teeBundleVectorsPath, err)
		}
		return
	}
	want, err := os.ReadFile(teeBundleVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", teeBundleVectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; regenerate with:\n  cd proto/go && go test ./inject -run TestTEEBundleVectors -update",
			teeBundleVectorsPath)
	}
}

// The inputs listed as Parse-fallback forms must actually be accepted, or the
// TypeScript parser is being held to a rule Go does not have.
func TestTEEBundleVectors_FallbackFormsAreAccepted(t *testing.T) {
	for _, in := range []string{
		"2026-10-09T1:34:56Z", "2026-10-09T12:34:56,5Z", "2026-10-09T12:34:56+24:00", "2026-10-09T12:34:56+23:60",
	} {
		if _, err := time.Parse(time.RFC3339, in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}
