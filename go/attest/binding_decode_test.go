/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

// A wrongly typed nonce or app_models must reach the tag the TypeScript
// verifyAux gives for the same body: malformed_nonce / nonce_mismatch map to
// aux_binding_mismatch, and a catalog that is not a list to
// happ_preimage_invalid. A decode error instead would be filed as
// fetch_failed, which names our side rather than the node.
func TestVerifyAux_WrongTypesMatchTypeScript(t *testing.T) {
	hex := strings.Repeat("11", 32)
	var challenge [32]byte
	for i := range challenge {
		challenge[i] = 0x11
	}
	entry := `[{"model_id":"m","source":"","weights_digest":"","weights_state":3}]`
	for _, tc := range []struct {
		name, doc string
		want      string
	}{
		{"nonce number", `{"app_models":` + entry + `,"nonce":5}`, TagAuxBindingMismatch},
		{"nonce array of hex", `{"app_models":` + entry + `,"nonce":["` + hex + `"]}`, TagAuxBindingMismatch},
		{"nonce later duplicate wins", `{"app_models":` + entry + `,"nonce":"` + hex + `","nonce":5}`, TagAuxBindingMismatch},
		// The nonce echoes the challenge so the challenged pass reaches H_app;
		// both languages check the nonce first.
		{"app_models object", `{"app_models":{},"nonce":"` + hex + `"}`, TagHAppPreimageInvalid},
		{"app_models string", `{"app_models":"x","nonce":"` + hex + `"}`, TagHAppPreimageInvalid},
		// Posture is hashed after H_app in both languages.
		{"posture array", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":[]}`, TagPosturePreimageInvalid},
		{"posture string", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":"named_upstream"}`, TagPosturePreimageInvalid},
		{"posture zero_retention string", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":{"zero_retention":"true"}}`, TagPosturePreimageInvalid},
		{"posture url number", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":{"upstream_base_url":1}}`, TagPosturePreimageInvalid},
		{"posture upstream_attested string", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":{"upstream_attested":"true"}}`, TagPosturePreimageInvalid},
		{"posture later duplicate wins", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":{"zero_retention":true,"zero_retention":1}}`, TagPosturePreimageInvalid},
		// Both faults: H_app is checked first in both languages, so the tag
		// names the catalog.
		{"app_models and posture both bad", `{"app_models":"x","nonce":"` + hex + `","posture":[]}`, TagHAppPreimageInvalid},
		// Controls: shapes both languages hash, so they reach the comparison.
		{"posture unknown key ignored", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":{"Zero_Retention":"x"}}`, TagAuxBindingMismatch},
		{"posture null fields", `{"app_models":` + entry + `,"nonce":"` + hex + `","posture":{"plaintext_terminates":null,"zero_retention":null}}`, TagAuxBindingMismatch},
	} {
		var b inject.TEEEvidenceBundle
		if err := json.Unmarshal([]byte(tc.doc), &b); err != nil {
			t.Errorf("%s: decode failed (%v); TypeScript decodes it and refuses it with a tag", tc.name, err)
			continue
		}
		var h ReportDataHalves
		for _, ch := range []*[32]byte{nil, &challenge} {
			if got := AuxFailureTag(h.VerifyAux(7, b.AppModels, b.Posture, b.Nonce, ch)); got != tc.want {
				t.Errorf("%s (challenged=%v): tag %q, want %q", tc.name, ch != nil, got, tc.want)
			}
		}
	}
}
