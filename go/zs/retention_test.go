/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

// The retention tier has to survive the details → ModelCapacity hop. It is
// written on the node side and read on the proxy side, and until this existed
// neither end was pinned — the classic asymmetric round trip, where the copy can
// be deleted and both suites stay green.
func TestProbeOne_CarriesRetention(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Two models with DIFFERENT tiers: a node can point text and image at
		// separate upstreams, and a per-model copy that collapsed to one value
		// would pass a single-model fixture.
		_, _ = fmt.Fprintf(w, `{"deployment":%q,"models":[
			{"id":"chat","context_window":8192,"retention":"upstream_confirmed"},
			{"id":"pic","context_window":8192,"retention":"upstream_enforced"},
			{"id":"plain","context_window":8192},
			{"id":"bold","context_window":8192,"retention":"mathematically_impossible_to_retain"}
		]}`, harnessDeployment.String())
	}))
	defer node.Close()

	source := &ChainOperatorSource{
		Deployment:     harnessDeployment,
		Details:        NewDetailsClient(nil, 2*time.Second),
		DetailsTimeout: 2 * time.Second,
		Log:            discardLogger(),
	}
	op := Operator{
		ID: 1, NodeID: 1, OwnerAddr: "A", BaseURL: node.URL,
		ProtoVersion: wire.ProtoVersion, Reachable: true,
	}
	source.recordReachable(RefOf(op), true)
	selAll := []selection.Operator{op.Selection()}
	source.probeOne(context.Background(), source.Details, nil, selAll, &op, time.Now(), discardLogger())

	for id, want := range map[string]string{
		"chat": inject.RetentionUpstreamConfirmed,
		"pic":  inject.RetentionUpstreamEnforced,
		// Absent on the wire stays absent here — it means unknown, and
		// substituting any placeholder would make the proxy assert something
		// the node did not.
		"plain": "",
		// A tier this build does not know is dropped to unknown rather than
		// carried through. The field is node-authored and reaches a dashboard,
		// so a verbatim copy lets a node mint its own reassuring label and have
		// the proxy render it — inject.IsKnownRetention exists for exactly this
		// and, until this case, had no production caller anywhere.
		"bold": "",
	} {
		got, ok := op.ModelCapacities[id]
		if !ok {
			t.Fatalf("model %q missing from ModelCapacities", id)
		}
		if got.Retention != want {
			t.Errorf("%s: Retention = %q, want %q", id, got.Retention, want)
		}
	}
}
