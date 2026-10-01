/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
)

func providerOf(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	p, ok := obj["provider"].(map[string]any)
	if !ok {
		t.Fatalf("no provider object in %s", body)
	}
	return p
}

func TestPinACIVerified(t *testing.T) {
	t.Run("sets the constraint on a body that has no provider object", func(t *testing.T) {
		out, err := inject.PinACIVerified([]byte(`{"model":"m","messages":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := providerOf(t, out)["aci_verified"]; got != true {
			t.Errorf("aci_verified = %v, want true", got)
		}
	})

	t.Run("routing keys survive untouched", func(t *testing.T) {
		// Everything in `provider` other than the ACI constraints is
		// the caller's routing, and rewriting it would silently change
		// where a request goes.
		out, err := inject.PinACIVerified([]byte(`{"provider":{"order":["a"],"sort":"price"}}`))
		if err != nil {
			t.Fatal(err)
		}
		p := providerOf(t, out)
		if p["sort"] != "price" {
			t.Errorf("sort = %v, want it preserved", p["sort"])
		}
		if len(p["order"].([]any)) != 1 {
			t.Errorf("order = %v, want it preserved", p["order"])
		}
	})

	t.Run("a null provider is annotated, not a panic", func(t *testing.T) {
		// `{"provider":null}` is legal JSON a client can send. Unmarshalling
		// null into a *map sets the map to NIL with a nil error, and the next
		// line assigns into it — so without the null guard this is a panic on
		// an egress path, which on a server is a dropped connection rather
		// than a refusal. The pre-existing EnforceUpstreamPrivacy has this
		// exact fixture; this function did not.
		out, err := inject.PinACIVerified([]byte(`{"model":"m","provider":null}`))
		if err != nil {
			t.Fatalf("a null provider must be replaced, not refused: %v", err)
		}
		if got := providerOf(t, out)["aci_verified"]; got != true {
			t.Errorf("aci_verified = %v, want true", got)
		}
	})

	t.Run("a caller cannot turn it off", func(t *testing.T) {
		// The constraint only tightens. A client speaking straight to a
		// node does not have its `provider` object stripped pre-seal,
		// so a caller-supplied false has to lose.
		out, err := inject.PinACIVerified([]byte(`{"provider":{"aci_verified":false}}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := providerOf(t, out)["aci_verified"]; got != true {
			t.Errorf("aci_verified = %v — a caller overrode the constraint", got)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		once, err := inject.PinACIVerified([]byte(`{"model":"m"}`))
		if err != nil {
			t.Fatal(err)
		}
		twice, err := inject.PinACIVerified(once)
		if err != nil {
			t.Fatal(err)
		}
		if string(once) != string(twice) {
			t.Errorf("second pass changed the body:\n%s\n%s", once, twice)
		}
	})

	t.Run("fails closed on a body it cannot annotate", func(t *testing.T) {
		// Forwarding an un-annotated body is exactly the outcome this
		// exists to prevent, so — unlike the best-effort mutators — it
		// must error rather than return the input.
		//
		// Each case runs under its own recover, because the two ways this can
		// go wrong are not the same defect and a bare call conflates them: a
		// nil error means the body was forwarded unannotated, while a PANIC
		// means the process died on client-supplied JSON. Without the recover
		// the second aborts the remaining subtests, so the run reports the
		// panic's stack instead of which inputs are unprotected.
		for _, body := range []string{`not json`, `null`, `[1,2]`, `{"provider":"nope"}`} {
			t.Run(body, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked on %s instead of refusing it — on an egress "+
							"path that is a dropped connection, not a refusal: %v", body, r)
					}
				}()
				if _, err := inject.PinACIVerified([]byte(body)); err == nil {
					t.Errorf("%s was forwarded unannotated", body)
				}
			})
		}
	})

	t.Run("an empty body is the one pass-through", func(t *testing.T) {
		// There is no prompt in it to protect.
		out, err := inject.PinACIVerified(nil)
		if err != nil || len(out) != 0 {
			t.Errorf("out = %q, err = %v", out, err)
		}
	})

	t.Run("the wire key is spelled exactly as the spec names it", func(t *testing.T) {
		// The aggregator rejects any unrecognized aci_-prefixed field
		// with invalid_request_error, so a typo fails every request
		// rather than degrading quietly — but only once it reaches a
		// live gateway, which no other test here can reach.
		out, err := inject.PinACIVerified([]byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), `"aci_verified":true`) {
			t.Errorf("body = %s", out)
		}
	})
}

// TestUpstreamAttestation_WireShape pins the published JSON of the block, which
// no Go test read at all.
//
// It is the only shape a payer's verifier parses, both verifiers are hand-written
// against SPEC § 3e rather than generated from this struct, and neither lives in
// this module — so a renamed tag or an `omitempty` added to the wrong field is a
// silent break of every consumer with this whole suite green.
func TestUpstreamAttestation_WireShape(t *testing.T) {
	if inject.UpstreamProtocolACI1 != "aci/1" {
		t.Errorf("UpstreamProtocolACI1 = %q — SPEC § 3e names the value, and a verifier "+
			"that does not recognize it must treat the block as unverifiable",
			inject.UpstreamProtocolACI1)
	}

	full := inject.UpstreamAttestation{
		Protocol:       inject.UpstreamProtocolACI1,
		BaseURL:        "https://inference.phala.com/v1",
		ReportURL:      "https://inference.phala.com/v1/aci/attestation",
		KeysetDigest:   "sha256:ef8a",
		VerifiedAt:     time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
		LeaseExpiresAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		CarveOuts:      []string{"root_backdoor_env:DSTACK_ROOT_PUBLIC_KEY"},
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"protocol", "base_url", "report_url", "keyset_digest",
		"verified_at", "lease_expires_at", "carve_outs",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("a fully populated block has no %q; keys = %v", k, keysOf(got))
		}
	}
	if len(got) != 7 {
		t.Errorf("keys = %v, want exactly the seven SPEC § 3e names — an added field is a "+
			"wire change and an extra one here is published to every payer", keysOf(got))
	}

	// CARVE_OUTS MUST SURVIVE. `omitempty` on a non-empty slice does not drop
	// it, but the tag sits one word away from being wrong and this field is the
	// one the spec calls normative: omitting it publishes a clean appraisal the
	// node did not get.
	if string(got["carve_outs"]) != `["root_backdoor_env:DSTACK_ROOT_PUBLIC_KEY"]` {
		t.Errorf("carve_outs = %s", got["carve_outs"])
	}

	t.Run("the minimal block still names its protocol", func(t *testing.T) {
		// protocol and base_url carry NO omitempty on purpose. An absent
		// `protocol` is easy for a verifier to skip past; an empty one is an
		// unrecognized one, which SPEC § 3e rule 4 requires it to treat as
		// unverifiable. verified_at is unconditional for the same reason — a
		// missing timestamp reads as "no claim" rather than as a stale verdict.
		raw, err := json.Marshal(inject.UpstreamAttestation{})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"protocol", "base_url", "verified_at"} {
			if _, ok := got[k]; !ok {
				t.Errorf("an empty block omits %q; keys = %v", k, keysOf(got))
			}
		}
		// omitzero, not omitempty: omitempty has no effect on a struct and
		// would have published a zero timestamp reading as a real expiry —
		// i.e. a lease that expired in year 1, which a verifier would reject
		// as stale rather than as absent.
		if _, ok := got["lease_expires_at"]; ok {
			t.Errorf("a zero lease expiry was published as %s; omitzero must drop it",
				got["lease_expires_at"])
		}
		if _, ok := got["carve_outs"]; ok {
			t.Error("an empty carve_outs was published; absent is the encoding for " +
				"\"enforced every rule\"")
		}
	})

	t.Run("the bundle omits the block entirely when there is no upstream", func(t *testing.T) {
		// Every sealed_local node takes this path, so an `omitempty` lost here
		// would publish `"upstream_attestation":null` on the whole fleet.
		raw, err := json.Marshal(inject.TEEEvidenceBundle{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "upstream_attestation") {
			t.Errorf("bundle = %s", raw)
		}
	})
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
