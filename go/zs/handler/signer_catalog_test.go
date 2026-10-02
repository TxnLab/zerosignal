/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// The discovery surface must agree with routing for the signer-funding gate
// too — and, unlike staging, /v1/zs/operators keeps listing the node with its
// balance, because that is the only place a payer can see why a model left.

func fundedCatalogOp(id uint64, model string, spendable *uint64) hayai.Operator {
	op := catalogOp(id, model, false)
	op.SignerSpendableMicroAlgos = spendable
	return op
}

func TestSignerCatalogAndDispatchAgree(t *testing.T) {
	ops := []hayai.Operator{
		fundedCatalogOp(1, "funded-model", nil),
		fundedCatalogOp(2, "broke-only", new(selection.MinSignerSpendableMicroAlgos-1)),
	}

	for name, s := range map[string]*Server{
		"static":  catalogServer(t, false, ops...),
		"dynamic": dynamicCatalogServer(t, false, ops...),
	} {
		t.Run(name, func(t *testing.T) {
			ids := listedModelIDs(t, s)
			if !ids["funded-model"] || ids["broke-only"] {
				t.Errorf("/v1/models = %v, want funded-model only", ids)
			}
			if got := getModelStatus(t, s, "broke-only"); got != http.StatusNotFound {
				t.Errorf("GET /v1/models/broke-only = %d, want 404 (must match the list)", got)
			}
			if names := detailsModelIDs(t, s); names["broke-only"] {
				t.Errorf("/v1/zs/details listed broke-only: %v", names)
			}
			if code, body := postChat(t, s, "broke-only"); code != http.StatusServiceUnavailable ||
				!strings.Contains(body, `"no_funded_operator"`) {
				t.Errorf("POST broke-only = %d %s, want 503 no_funded_operator", code, body)
			}

			dirs := operatorsPayload(t, s)
			if len(dirs) != 2 {
				t.Fatalf("/v1/zs/operators = %d entries, want 2 (an underfunded node stays listed)", len(dirs))
			}
			for _, d := range dirs {
				switch id, _ := d["operator_id"].(float64); id {
				case 1:
					if _, present := d["signer_spendable_microalgos"]; present {
						t.Errorf("never-read node carries a balance: %v", d)
					}
					if _, present := d["signer_underfunded"]; present {
						t.Errorf("never-read node marked underfunded: %v", d)
					}
				case 2:
					if v, _ := d["signer_spendable_microalgos"].(float64); v != float64(selection.MinSignerSpendableMicroAlgos-1) {
						t.Errorf("node 2 signer_spendable_microalgos = %v, want %d", d["signer_spendable_microalgos"], selection.MinSignerSpendableMicroAlgos-1)
					}
					if u, _ := d["signer_underfunded"].(bool); !u {
						t.Errorf("node 2 not marked signer_underfunded: %v", d)
					}
				}
			}
		})
	}
}
