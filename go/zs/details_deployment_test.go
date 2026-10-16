/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// The vectors pin checkDetailsDeployment; this pins that probeOne consults it,
// and that a refused node is left as a failed probe leaves it.
func TestProbeOne_RefusesAnotherDeployment(t *testing.T) {
	depOf := func(fill byte) ticket.DeploymentID {
		d, err := ticket.AlgorandDeploymentID(bytes.Repeat([]byte{fill}, 32), 1001)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	mine := depOf(1)
	for _, tc := range []struct {
		name       string
		advertised string
		admitted   bool
	}{
		{"another deployment", depOf(2).String(), false},
		{"none from a 9.13 node", "", false},
		{"this deployment", mine.String(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"models":        []map[string]any{{"id": "fresh", "context_window": 8192}},
					"proto_version": wire.ProtoVersion,
					"deployment":    tc.advertised,
				})
			}))
			defer node.Close()

			source := &ChainOperatorSource{
				Details:        NewDetailsClient(nil, 2*time.Second),
				DetailsTimeout: 2 * time.Second,
				Deployment:     mine,
				Log:            discardLogger(),
			}
			earlier := time.Now().Add(-time.Minute)
			op := Operator{
				ID: 1, NodeID: 1, OwnerAddr: "A", BaseURL: node.URL,
				ProtoVersion: wire.ProtoVersion, Reachable: true,
				Models: []string{"carried"}, ReachableAsOf: earlier,
			}
			source.recordReachable(RefOf(op), true)
			selAll := []selection.Operator{op.Selection()}
			source.probeOne(context.Background(), source.Details, nil, selAll, &op, time.Now(), discardLogger())

			if op.Reachable != tc.admitted || source.recallReachable(RefOf(op)) != tc.admitted {
				t.Fatalf("reachable = %v, remembered = %v; want %v", op.Reachable, source.recallReachable(RefOf(op)), tc.admitted)
			}
			wantModel := "carried"
			if tc.admitted {
				wantModel = "fresh"
			}
			if len(op.Models) != 1 || op.Models[0] != wantModel {
				t.Fatalf("models = %v, want [%s]", op.Models, wantModel)
			}
			if tc.admitted == op.ReachableAsOf.Equal(earlier) {
				t.Fatalf("reachable_as_of = %v; it moves only on an admitted probe", op.ReachableAsOf)
			}
		})
	}
}
