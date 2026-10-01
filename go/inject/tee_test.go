/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOperatorDetails_TEEOmitWhenAbsent(t *testing.T) {
	// Pre-TEE consumers must see no `tee` key when a non-TEE node
	// returns details. This is what keeps the existing wire shape
	// byte-for-byte stable.
	d := OperatorDetails{
		Models: []OperatorDetailsModel{},
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), `"tee"`) {
		t.Fatalf("non-TEE OperatorDetails serialized with tee field: %s", out)
	}
}

func TestOperatorDetails_TEEPresent(t *testing.T) {
	when := time.Unix(1_750_000_000, 0).UTC()
	d := OperatorDetails{
		Models: []OperatorDetailsModel{},
		TEE: &TEEAdvertisement{
			Mode:        "nvidia-cc-tdx",
			AttestedAt:  when,
			EvidenceURL: "/v1/zs/attestation",
		},
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		`"tee":{`,
		`"mode":"nvidia-cc-tdx"`,
		`"evidence_url":"/v1/zs/attestation"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %s in output, got %s", want, got)
		}
	}
	var rt OperatorDetails
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt.TEE == nil {
		t.Fatalf("TEE field lost in round-trip")
	}
	if rt.TEE.Mode != "nvidia-cc-tdx" || !rt.TEE.AttestedAt.Equal(when) || rt.TEE.EvidenceURL != "/v1/zs/attestation" {
		t.Fatalf("TEE round-trip mismatch: %+v", rt.TEE)
	}
}

func TestTEEEvidenceBundle_RoundTrip(t *testing.T) {
	when := time.Unix(1_750_000_000, 0).UTC()
	in := TEEEvidenceBundle{
		Mode:           "nvidia-cc-tdx",
		CPUReport:      "BASE64REPORT==",
		GPUEAT:         "eyJ.JWT.SIG",
		NodePubkey:     "age1xyz",
		OperatorID:     42,
		ReportData:     "BASE64HASH==",
		GeneratedAt:    when,
		RefreshSeconds: 3600,
	}
	wire, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out TEEEvidenceBundle
	if err := json.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Mode != in.Mode ||
		out.CPUReport != in.CPUReport ||
		out.GPUEAT != in.GPUEAT ||
		out.NodePubkey != in.NodePubkey ||
		out.OperatorID != in.OperatorID ||
		out.ReportData != in.ReportData ||
		out.RefreshSeconds != in.RefreshSeconds ||
		!out.GeneratedAt.Equal(in.GeneratedAt) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.Stub {
		t.Fatalf("Stub should default to false")
	}
}

func TestTEEEvidenceBundle_StubOmitsCPUAndGPU(t *testing.T) {
	in := TEEEvidenceBundle{
		Mode:           "stub",
		NodePubkey:     "age1xyz",
		OperatorID:     1,
		ReportData:     "BASE64HASH==",
		GeneratedAt:    time.Unix(0, 0).UTC(),
		RefreshSeconds: 60,
		Stub:           true,
	}
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	if strings.Contains(got, `"cpu_report"`) {
		t.Errorf("stub bundle leaked cpu_report: %s", got)
	}
	if strings.Contains(got, `"gpu_eat"`) {
		t.Errorf("stub bundle leaked gpu_eat: %s", got)
	}
	if !strings.Contains(got, `"stub":true`) {
		t.Errorf("stub flag missing: %s", got)
	}
	// The dstack-only fields have no business on a stub bundle either.
	// Same reason as cpu_report: a payer reading the JSON must not see
	// a shape that suggests evidence exists to check.
	if strings.Contains(got, `"event_log"`) {
		t.Errorf("stub bundle leaked event_log: %s", got)
	}
	if strings.Contains(got, `"posture"`) {
		t.Errorf("stub bundle leaked posture: %s", got)
	}
}

func TestTEEEvidenceBundle_DstackRoundTrip(t *testing.T) {
	when := time.Unix(1_750_000_000, 0).UTC()
	in := TEEEvidenceBundle{
		Mode:       TEEModeDstackTDX,
		CPUReport:  "BASE64QUOTE==",
		EventLog:   `[{"imr":3,"event_type":134217729,"event":"compose-hash","event_payload":"6e6f"}]`,
		NodePubkey: "age1xyz",
		OperatorID: 42,
		ReportData: "BASE64HASH==",
		Posture: &TEEPosture{
			PlaintextTerminates: PlaintextNamedUpstream,
			UpstreamBaseURL:     "https://api.x.ai/v1",
			ZeroRetention:       true,
		},
		GeneratedAt:    when,
		RefreshSeconds: 1200,
	}
	wire, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Wire keys, pinned literally: a rename here is a breaking change
	// between proxy and node that no Go-side round-trip would notice,
	// because both ends move together with the struct.
	for _, want := range []string{
		`"mode":"dstack-tdx"`,
		`"event_log":"`,
		`"posture":{`,
		`"plaintext_terminates":"named_upstream"`,
		`"upstream_base_url":"https://api.x.ai/v1"`,
		`"zero_retention":true`,
	} {
		if !strings.Contains(string(wire), want) {
			t.Errorf("missing %s in %s", want, wire)
		}
	}
	var out TEEEvidenceBundle
	if err := json.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.EventLog != in.EventLog {
		t.Errorf("event_log round-trip: got %q, want %q", out.EventLog, in.EventLog)
	}
	if out.Posture == nil {
		t.Fatalf("posture lost in round-trip")
	}
	if *out.Posture != *in.Posture {
		t.Errorf("posture round-trip: got %+v, want %+v", *out.Posture, *in.Posture)
	}
	// GPUEAT is meaningless on a CPU-only mode; assert the zero value
	// survives as an absent key rather than an empty string, so a
	// verifier's "is there GPU evidence" test is a presence test.
	if strings.Contains(string(wire), `"gpu_eat"`) {
		t.Errorf("dstack bundle carried gpu_eat: %s", wire)
	}
}

func TestTEEEvidenceBundle_NvidiaShapeUnchanged(t *testing.T) {
	// The additive property, stated as a test: adding EventLog and
	// Posture must not have moved a byte for the modes that set
	// neither. A round-trip cannot see this — both ends of a
	// round-trip carry the new fields — so compare the serialized
	// form against the exact pre-change bytes.
	in := TEEEvidenceBundle{
		Mode:           TEEModeNvidiaCCTDX,
		CPUReport:      "BASE64REPORT==",
		GPUEAT:         "eyJ.JWT.SIG",
		NodePubkey:     "age1xyz",
		OperatorID:     42,
		ReportData:     "BASE64HASH==",
		GeneratedAt:    time.Unix(1_750_000_000, 0).UTC(),
		RefreshSeconds: 3600,
	}
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"mode":"nvidia-cc-tdx","cpu_report":"BASE64REPORT==","gpu_eat":"eyJ.JWT.SIG",` +
		`"node_pubkey":"age1xyz","operator_id":42,"report_data":"BASE64HASH==",` +
		`"generated_at":"2025-06-15T15:06:40Z","refresh_seconds":3600}`
	if string(out) != want {
		t.Errorf("nvidia bundle wire shape moved\n got: %s\nwant: %s", out, want)
	}
}

// BOTH posture values, pinned as wire literals. Only named_upstream was
// — and every Go consumer compares symbolically, so changing
// PlaintextInEnclave's value is invisible to all of them at once.
//
// It bites across the publish gate: with node on an older proto and the
// proxy on a newer one, the proxy's switch falls through to default for
// a genuinely in-enclave node, and default means "unknown — never the
// stronger of the two". A correct node is silently downgraded.
func TestTEEPosture_WireValues(t *testing.T) {
	cases := []struct {
		constant string
		wire     string
	}{
		{PlaintextInEnclave, `"plaintext_terminates":"in_enclave"`},
		{PlaintextNamedUpstream, `"plaintext_terminates":"named_upstream"`},
	}
	for _, tc := range cases {
		out, err := json.Marshal(TEEPosture{PlaintextTerminates: tc.constant})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(out), tc.wire) {
			t.Errorf("posture %q serialized as %s, want it to contain %s",
				tc.constant, out, tc.wire)
		}
	}
	// They must also stay distinct — collapsing them would make every
	// comparison in every consumer answer the same way.
	if PlaintextInEnclave == PlaintextNamedUpstream {
		t.Error("the two posture values are identical")
	}
}

// Complete is the executable form of the "a partial set is an absent
// set" MUST, so the thing that can break it is not a wrong comparison
// — it is a TENTH field added to the struct and not added to the list,
// which leaves the MUST quietly false for that member while every
// existing test stays green.
//
// So this drives the check by REFLECTION rather than by name: fill
// every string field, then blank each one in turn and require a false.
// A new field is covered the moment it exists.
func TestTEECollateral_CompleteCoversEveryField(t *testing.T) {
	if (&TEECollateral{}).Complete() {
		t.Error("an empty set reported complete")
	}
	if (*TEECollateral)(nil).Complete() {
		t.Error("a nil set reported complete")
	}

	full := func() *TEECollateral {
		c := &TEECollateral{}
		v := reflect.ValueOf(c).Elem()
		for i := range v.NumField() {
			if v.Field(i).Kind() != reflect.String {
				t.Fatalf("%s is not a string; this test only reasons about string members",
					v.Type().Field(i).Name)
			}
			v.Field(i).SetString("x")
		}
		return c
	}

	if !full().Complete() {
		t.Fatal("a fully populated set reported incomplete")
	}

	n := reflect.TypeOf(TEECollateral{}).NumField()
	if n != 9 {
		t.Errorf("TEECollateral has %d fields, want 9 — SPEC.md §3e and both "+
			"verifiers enumerate them; update all of them together", n)
	}
	for i := range n {
		c := full()
		name := reflect.TypeOf(*c).Field(i).Name
		reflect.ValueOf(c).Elem().Field(i).SetString("")
		if c.Complete() {
			t.Errorf("a set missing %s reported complete — that field is not in Complete's list", name)
		}
	}
}

func TestTEEEvidenceBundle_NoSelfReportedMeasurements(t *testing.T) {
	// A tripwire, not a correctness check. compose_hash and
	// os_image_hash are deliberately absent from this bundle: both are
	// recoverable by replaying EventLog against the quote's RTMR3, and
	// carrying them as fields would invite a verifier to read the
	// self-report instead of replaying. That cheap wrong verifier is
	// indistinguishable from the correct one on every honest node, so
	// the design decision gets a test rather than only a comment.
	//
	// If you are here because you added the field: read
	// TEEEvidenceBundle.EventLog's godoc first, then delete this.
	//
	// IT IS THE FIELD NAMES THAT ARE BANNED, NOT THE BYTES. This used
	// to search the whole marshalled document for those substrings,
	// which worked only while every field was a short opaque token. It
	// stops working the moment a field carries a real document:
	// AppCompose is a dstack app-compose.json whose embedded compose
	// file legitimately contains the string `compose_hash` in comments
	// (verified against the captured document in proto/testdata), so
	// the old form would fail on an honest node's payload while
	// proving nothing about the bundle's shape.
	//
	// WALKING THE TYPE, NOT A MARSHALLED FIXTURE, and both halves of
	// that matter:
	//
	//   - RECURSIVE. The bundle has a nested object — Posture — and a
	//     map[string]json.RawMessage over the marshalled form
	//     enumerates only depth one. TEEPosture is already the
	//     self-reported hint block, so "record which build this
	//     posture describes" is the natural next request and would
	//     land a compose_hash field the shallow check cannot see.
	//   - FIXTURE-INDEPENDENT. A hand-built literal only exercises the
	//     fields its author remembered; a new `omitempty` field left
	//     out of it marshals to nothing and is never examined. The
	//     type always has every field.
	//
	// If you are here because you added the field: read
	// TEEEvidenceBundle.EventLog's godoc first, then delete this.
	for _, f := range jsonFieldNames(t, reflect.TypeOf(TEEEvidenceBundle{})) {
		// Lowercased before comparing, because the ban list is
		// lowercase and Go field names are not: an UNTAGGED field
		// `RTMR3 string` marshals under its Go name and would sail
		// past a case-sensitive Contains.
		lower := strings.ToLower(f.name)
		for _, banned := range []string{"compose_hash", "os_image_hash", "mrtd", "rtmr"} {
			// Substring, not equality: `rtmr` must also catch `rtmr3`
			// and `quote_rtmr`, which are the shapes someone would
			// actually add.
			if strings.Contains(lower, banned) {
				t.Errorf("%s carries a self-reported measurement field %q (banned: %q)",
					f.owner, f.name, banned)
			}
		}
	}

	// The counterpart the walk cannot make: prove a banned word really
	// does appear inside a VALUE on an honest bundle. Without it,
	// nothing distinguishes this check from the whole-document one it
	// replaced, and a revert to Contains-over-the-document would look
	// fine here while failing in production.
	full := TEEEvidenceBundle{
		Mode:      TEEModeDstackTDX,
		CPUReport: "BASE64QUOTE==",
		EventLog:  `[]`,
		AppCompose: `{"manifest_version":2,` +
			`"docker_compose_file":"# a comment naming compose_hash\n"}`,
		NodePubkey: "age1xyz",
		OperatorID: 42,
		ReportData: "BASE64HASH==",
		Posture:    &TEEPosture{PlaintextTerminates: PlaintextInEnclave},
	}
	out, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), "compose_hash") {
		t.Fatal("the fixture no longer carries a banned word inside a VALUE, so this " +
			"test can no longer tell a field-name check from a whole-document one")
	}
}

// jsonFieldNames returns every JSON key t serializes, including those
// of nested structs, so a tripwire over field names cannot be defeated
// by nesting.
func jsonFieldNames(t *testing.T, typ reflect.Type) []struct{ owner, name string } {
	t.Helper()
	var out []struct{ owner, name string }
	seen := map[reflect.Type]bool{}

	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Ptr || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := range rt.NumField() {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if tag == "-" {
				continue
			}
			// An absent tag means the Go field name IS the JSON key.
			// Defaulting to "" instead would make every untagged field
			// invisible to the caller's ban list.
			if tag == "" {
				tag = f.Name
			}
			out = append(out, struct{ owner, name string }{rt.Name(), tag})
			walk(f.Type)
		}
	}
	walk(typ)

	if len(out) == 0 {
		t.Fatalf("walked %s and found no JSON fields — the walk is broken, and a "+
			"tripwire over zero fields passes for anything", typ)
	}
	return out
}

// TestHAppPreimage_WireValues pins the SPELLINGS of the 9.9 preimage
// fields, for the reason TestTEEPosture_WireValues names: every Go
// consumer compares symbolically, so renaming a JSON tag is invisible to
// all of them at once — while the browser verifier in client/ reads these
// strings out of parsed JSON and would simply stop finding them.
//
// ModelEntry's four names matter more than most: they are the preimage a
// verifier hashes, so a rename does not merely lose a field, it changes
// H_app for a catalog both sides believe they agree on.
func TestHAppPreimage_WireValues(t *testing.T) {
	out, err := json.Marshal(TEEEvidenceBundle{
		AppModels: []ModelEntry{{
			ModelID:       "m",
			Source:        "hf/m",
			WeightsDigest: "sha256:ab12",
			State:         WeightsMeasured,
		}},
		Nonce: "ff00",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"app_models":[`,
		`"model_id":"m"`,
		`"source":"hf/m"`,
		`"weights_digest":"sha256:ab12"`,
		`"weights_state":1`,
		`"nonce":"ff00"`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("serialized bundle is missing %s\n got: %s", want, out)
		}
	}

	// Every entry field serializes even when empty. The strict decoder
	// marks an entry with a missing key malformed, so a producer that
	// omitted an empty Source would publish a catalog every verifier
	// refuses.
	out, err = json.Marshal([]ModelEntry{{ModelID: "m", State: WeightsUnverifiable}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"source":""`, `"weights_digest":""`, `"weights_state":3`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("an empty entry field vanished: want %s\n got: %s", want, out)
		}
	}
}

// A wrongly typed app_models or nonce decodes to a value VerifyAux refuses,
// never to an absent field (which would hash an empty catalog or 32 zero
// bytes) and never to a decode error (which the proxy files as fetch_failed,
// where TypeScript names the node). attest's
// TestVerifyAux_WrongTypesMatchTypeScript checks the resulting tags.
func TestTEEEvidenceBundle_WrongAuxTypesAreCoerced(t *testing.T) {
	for _, doc := range []string{
		`{"app_models":{}}`, `{"app_models":"x"}`, `{"app_models":1}`, `{"app_models":true}`,
	} {
		var b TEEEvidenceBundle
		if err := json.Unmarshal([]byte(doc), &b); err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		if len(b.AppModels) != 1 || !b.AppModels[0].Malformed() {
			t.Errorf("%s: AppModels = %+v, want one malformed entry", doc, b.AppModels)
		}
	}
	for _, doc := range []string{
		`{"nonce":5}`, `{"nonce":["` + strings.Repeat("ab", 32) + `"]}`, `{"nonce":{}}`, `{"nonce":true}`,
		`{"nonce":"` + strings.Repeat("ab", 32) + `","nonce":5}`,
	} {
		var b TEEEvidenceBundle
		if err := json.Unmarshal([]byte(doc), &b); err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		if b.Nonce == "" || len(b.Nonce) == 64 {
			t.Errorf("%s: Nonce = %q, want a present value that is not 64 hex characters", doc, b.Nonce)
		}
	}
	// null stays absent in both languages.
	var n TEEEvidenceBundle
	if err := json.Unmarshal([]byte(`{"nonce":null,"app_models":null}`), &n); err != nil {
		t.Fatal(err)
	}
	if n.Nonce != "" || n.AppModels != nil {
		t.Errorf("null fields decoded as %q / %+v, want absent", n.Nonce, n.AppModels)
	}
}

// Nested objects match keys exactly too. collateral's documents are
// signature-checked, so a case variant carrying a second, older signed
// document would otherwise give the two verifiers different TCB verdicts.
func TestTEEEvidenceBundle_NestedExactKeys(t *testing.T) {
	const doc = `{"collateral":{"tcb_info":"A","TCB_INFO":"B"},` +
		`"posture":{"plaintext_terminates":"in_enclave","Plaintext_Terminates":"upstream"},` +
		`"upstream_attestation":{"protocol":"aci/1","carve_outs":["x"],"CARVE_OUTS":["y","z"]}}`
	var b TEEEvidenceBundle
	if err := json.Unmarshal([]byte(doc), &b); err != nil {
		t.Fatal(err)
	}
	if b.Collateral == nil || b.Collateral.TCBInfo != "A" {
		t.Errorf("Collateral = %+v, want tcb_info A", b.Collateral)
	}
	if b.Posture == nil || b.Posture.PlaintextTerminates != "in_enclave" {
		t.Errorf("Posture = %+v, want in_enclave", b.Posture)
	}
	if b.UpstreamAttestation == nil || !reflect.DeepEqual(b.UpstreamAttestation.CarveOuts, []string{"x"}) {
		t.Errorf("UpstreamAttestation = %+v, want carve_outs [x]", b.UpstreamAttestation)
	}

	// A variant with no exact key beside it. The pair above passes even
	// without the filter, because re-encoding sorts keys and the exact
	// lower-case key lands last and wins.
	const variantOnly = `{"collateral":{"TCB_INFO":"B"},"posture":{"Plaintext_Terminates":"upstream"},` +
		`"upstream_attestation":{"CARVE_OUTS":["y"]}}`
	var v TEEEvidenceBundle
	if err := json.Unmarshal([]byte(variantOnly), &v); err != nil {
		t.Fatal(err)
	}
	if v.Collateral.TCBInfo != "" || v.Posture.PlaintextTerminates != "" || v.UpstreamAttestation.CarveOuts != nil {
		t.Errorf("a variant-only key was read: collateral %+v, posture %+v, upstream %+v",
			v.Collateral, v.Posture, v.UpstreamAttestation)
	}
}

// Outside the aux binding, a value of the wrong JSON type still fails the
// whole decode, including an object field that is not an object.
func TestTEEEvidenceBundle_NonObjectsAreErrors(t *testing.T) {
	for _, doc := range []string{
		`{"collateral":"x"}`, `{"upstream_attestation":[]}`, `[1,2]`,
	} {
		var b TEEEvidenceBundle
		if err := json.Unmarshal([]byte(doc), &b); err == nil {
			t.Errorf("%s decoded without error: %+v", doc, b)
		}
	}
}

// The posture is inside the aux binding, so a wrongly typed one decodes to a
// marked posture that attest.HPosture refuses (the tag parity is pinned in
// attest's TestVerifyAux_WrongTypesMatchTypeScript). Nothing else about the
// bundle may be lost, and a well-typed posture must never be marked.
func TestTEEEvidenceBundle_WrongTypedPostureIsMarked(t *testing.T) {
	for _, doc := range []string{`{"posture":5,"node_pubkey":"k"}`, `{"posture":{"zero_retention":"yes"},"node_pubkey":"k"}`} {
		var b TEEEvidenceBundle
		if err := json.Unmarshal([]byte(doc), &b); err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		if !b.Posture.Malformed() || b.NodePubkey != "k" {
			t.Errorf("%s: posture %+v (malformed=%v), node_pubkey %q", doc, b.Posture, b.Posture.Malformed(), b.NodePubkey)
		}
		if NamedUpstreamAdmissible(b.Posture, true) {
			t.Errorf("%s: a malformed posture is admissible", doc)
		}
	}
	for _, doc := range []string{`{"posture":null}`, `{"posture":{"plaintext_terminates":"in_enclave","zero_retention":false}}`} {
		var b TEEEvidenceBundle
		if err := json.Unmarshal([]byte(doc), &b); err != nil || b.Posture.Malformed() {
			t.Errorf("%s: err %v, malformed %v", doc, err, b.Posture.Malformed())
		}
	}
}

// A field without a json tag would decode under its Go name with case
// folding, so jsonKeys refuses to build a key set for it.
func TestJSONKeys_PanicsOnUntaggedField(t *testing.T) {
	type untagged struct {
		Tagged string `json:"tagged"`
		Loose  string
	}
	defer func() {
		if recover() == nil {
			t.Error("jsonKeys accepted an untagged exported field")
		}
	}()
	jsonKeys[untagged]()
}

// A bundle with invalid UTF-8 is refused. Go and TextDecoder replace the bad
// bytes with different numbers of U+FFFD, so the two verifiers would hash
// different model ids from one body.
func TestTEEEvidenceBundle_RefusesInvalidUTF8(t *testing.T) {
	doc := []byte(`{"mode":"dstack-tdx","app_models":[{"model_id":"x` + "\xe2\x82" +
		`A","source":"","weights_digest":"","weights_state":3}]}`)
	var b TEEEvidenceBundle
	err := json.Unmarshal(doc, &b)
	if err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Errorf("err = %v, want the UTF-8 refusal", err)
	}
}

// TestTEEEvidenceBundle_ExactKeys pins that top-level keys are read exactly,
// as JavaScript reads them. Go's default decoding would take the
// case-variant keys here, giving the Go and TypeScript verifiers different
// inputs from one bundle.
func TestTEEEvidenceBundle_ExactKeys(t *testing.T) {
	// A wrongly typed variant is ignored, as JavaScript ignores it, rather
	// than failing the whole bundle.
	for _, doc := range []string{
		`{"mode":"dstack-tdx","APP_MODELS":1}`,
		`{"mode":"dstack-tdx","Nonce":5}`,
	} {
		var b TEEEvidenceBundle
		if err := json.Unmarshal([]byte(doc), &b); err != nil {
			t.Errorf("%s: %v, want the variant ignored", doc, err)
		}
	}

	// Fields outside the aux binding: the exact key wins, whichever comes
	// last, and a Unicode-folded key ("ſ" folds to "s") is not a match.
	var q TEEEvidenceBundle
	if err := json.Unmarshal([]byte(`{"cpu_report":"A","CPU_REPORT":"B","app_compoſe":"C"}`), &q); err != nil {
		t.Fatal(err)
	}
	if q.CPUReport != "A" || q.AppCompose != "" {
		t.Errorf("CPUReport = %q, AppCompose = %q; want \"A\" and empty", q.CPUReport, q.AppCompose)
	}

	const doc = `{"mode":"dstack-tdx",` +
		`"app_models":[{"model_id":"a","source":"","weights_digest":"","weights_state":3}],` +
		`"APP_MODELS":[{"model_id":"b","source":"","weights_digest":"","weights_state":3}],` +
		`"Nonce":"ab"}`
	var b TEEEvidenceBundle
	if err := json.Unmarshal([]byte(doc), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.AppModels) != 1 || b.AppModels[0].ModelID != "a" {
		t.Errorf("AppModels = %+v, want the exact-key list [a]", b.AppModels)
	}
	if b.Nonce != "" {
		t.Errorf("Nonce = %q, want empty: only \"nonce\" counts", b.Nonce)
	}
	if b.Mode != TEEModeDstackTDX {
		t.Errorf("Mode = %q: the other fields must still decode", b.Mode)
	}

	// Only a case variant present: the field is absent, not the variant.
	var v TEEEvidenceBundle
	if err := json.Unmarshal([]byte(`{"App_Models":[{"model_id":"b","source":"","weights_digest":"","weights_state":3}]}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.AppModels != nil {
		t.Errorf("AppModels = %+v from a case-variant key", v.AppModels)
	}

	// The node's own output round-trips.
	orig := TEEEvidenceBundle{Mode: TEEModeDstackTDX, Nonce: strings.Repeat("ab", 32),
		AppModels: []ModelEntry{{ModelID: "m", WeightsDigest: "sha256:aa", State: WeightsMeasured}}}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var back TEEEvidenceBundle
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.AppModels, orig.AppModels) || back.Nonce != orig.Nonce {
		t.Errorf("round trip lost fields: %+v", back)
	}
}

// TestModelEntry_RoundTrip pins that what a node marshals, a verifier
// decodes as a well-formed entry equal to the original. The strict decoder
// would otherwise refuse the node's own output.
func TestModelEntry_RoundTrip(t *testing.T) {
	in := []ModelEntry{
		{ModelID: "m", Source: "hf/m", WeightsDigest: "sha256:ab12", State: WeightsMeasured},
		{ModelID: "p", Source: "hf/p", WeightsDigest: "sha256:cd34", State: WeightsDeclared},
		{ModelID: "grok", State: WeightsUnverifiable},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out []ModelEntry
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the entries:\n in: %+v\nout: %+v", in, out)
	}
	for _, e := range out {
		if e.Malformed() {
			t.Errorf("%s decoded as malformed", e.ModelID)
		}
	}
}

// TestModelEntry_MalformedIsReset pins that decoding into a reused value
// clears the previous state. A decoder that set the flag only on failure
// would leave a stale "malformed" on a good entry, or drop it on a bad one.
func TestModelEntry_MalformedIsReset(t *testing.T) {
	var e ModelEntry
	if err := json.Unmarshal([]byte(`{"model_id":"m"}`), &e); err != nil || !e.Malformed() {
		t.Fatalf("an entry missing three keys: err=%v malformed=%v", err, e.Malformed())
	}
	good := `{"model_id":"m","source":"","weights_digest":"","weights_state":3}`
	if err := json.Unmarshal([]byte(good), &e); err != nil || e.Malformed() {
		t.Fatalf("a good entry decoded over a malformed one: err=%v malformed=%v", err, e.Malformed())
	}
	bad := `{"model_id":"x","source":null,"weights_digest":"","weights_state":3}`
	if err := json.Unmarshal([]byte(bad), &e); err != nil || !e.Malformed() || e.ModelID != "" {
		t.Fatalf("a bad entry decoded over a good one kept its fields: %+v malformed=%v", e, e.Malformed())
	}
}

func TestWeightsState_String(t *testing.T) {
	for s, want := range map[WeightsState]string{
		WeightsMeasured:     "measured",
		WeightsDeclared:     "declared",
		WeightsUnverifiable: "unverifiable",
		0:                   "unknown(0)",
		9:                   "unknown(9)",
	} {
		if got := s.String(); got != want {
			t.Errorf("WeightsState(%d).String() = %q, want %q", uint8(s), got, want)
		}
	}
}
