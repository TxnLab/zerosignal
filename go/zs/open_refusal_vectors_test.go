/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/open_refusal_vectors.json: a node's
// refusal body in, the refusal category the payer reads from it and whether
// that is the prepaid pool out. The TS twin replays it through
// openRefusalCategory and poolRefusal (sdk/src/sealed.ts).
//
//	cd proto/go && go test ./zs -run TestOpenRefusalVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

const openRefusalVectorsPath = "../../testdata/open_refusal_vectors.json"

type openRefusalVector struct {
	Name     string `json:"name"`
	Body     string `json:"body"`
	Category string `json:"category"`
	Pool     bool   `json:"pool"`
}

func openRefusalVectorInputs() []openRefusalVector {
	refusal := func(message, reason string) string {
		e := map[string]string{"code": "payment_verification_failed", "message": message, "type": "invalid_request_error"}
		if reason != "" {
			e["reason"] = reason
		}
		b, _ := json.Marshal(map[string]any{"error": e})
		return string(b)
	}
	algod := func(c string) string { return "payment verification failed: open group rejected by algod (" + c + ")" }
	cluster := func(c string) string { return "payment verification failed: open rejected by the cluster (" + c + ")" }
	return []openRefusalVector{
		{Name: "reason mbr_pool", Body: refusal(algod("mbr_pool"), "mbr_pool")},
		{Name: "reason rent_pool", Body: refusal(cluster("rent_pool"), "rent_pool")},
		{Name: "reason contract", Body: refusal(algod("contract"), "contract")},
		{Name: "reason overspend", Body: refusal(algod("overspend"), "overspend")},
		// The reason is the node's word; a message that disagrees is ignored.
		{Name: "reason wins over the message", Body: refusal(algod("mbr_pool"), "contract")},
		{Name: "legacy algod mbr_pool", Body: refusal(algod("mbr_pool"), "")},
		{Name: "legacy cluster rent_pool", Body: refusal(cluster("rent_pool"), "")},
		{Name: "legacy algod contract", Body: refusal(algod("contract"), "")},
		{Name: "legacy cluster usdc_insufficient", Body: refusal(cluster("usdc_insufficient"), "")},
		{Name: "legacy without the closing parenthesis", Body: refusal("payment verification failed: open group rejected by algod (mbr_pool", "")},
		{Name: "legacy with text after the category", Body: refusal(algod("mbr_pool")+" later", "")},
		{Name: "the open watchdog's refusal", Body: refusal("payment verification failed: open_unconfirmed: the open did not confirm", "")},
		{Name: "bare refusal", Body: refusal("payment verification failed", "")},
		{Name: "category only in another field", Body: `{"error":{"code":"payment_verification_failed","message":"payment verification failed","param":"mbr_pool"}}`},
		{Name: "reason not a string", Body: `{"error":{"code":"payment_verification_failed","message":"x","reason":7}}`},
		{Name: "message not a string", Body: `{"error":{"code":"payment_verification_failed","message":7,"reason":"mbr_pool"}}`},
		// Keys are read exactly: Go's struct decoding would fold the case.
		{Name: "reason key capitalised", Body: `{"error":{"code":"payment_verification_failed","message":"payment verification failed","Reason":"mbr_pool"}}`},
		{Name: "error key capitalised", Body: `{"Error":{"code":"payment_verification_failed","message":"x","reason":"mbr_pool"}}`},
		{Name: "error is null", Body: `{"error":null}`},
		{Name: "error is an array", Body: `{"error":["mbr_pool"]}`},
		{Name: "reason is null", Body: `{"error":{"code":"payment_verification_failed","message":"payment verification failed: open group rejected by algod (mbr_pool)","reason":null}}`},
		{Name: "not JSON", Body: "payment verification failed: open group rejected by algod (mbr_pool)"},
		{Name: "empty", Body: ""},
	}
}

func TestOpenRefusalVectors(t *testing.T) {
	cases := openRefusalVectorInputs()
	for i := range cases {
		cases[i].Category = openRefusalCategory([]byte(cases[i].Body))
		cases[i].Pool = poolRefusal(cases[i].Category)
	}
	out, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *updateVectors {
		if err := os.WriteFile(openRefusalVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(openRefusalVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("openRefusalCategory differs from %s; if the change is intended, regenerate with -update and review the diff", openRefusalVectorsPath)
	}
}
