/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
)

// boxListPageLimit is the `limit` query param: how many boxes algod returns per
// page, alongside a next-token to page through the rest.
//
// It is `limit`, not `max` — a distinct param. `max` is algod's legacy
// all-in-one-response cap, checked against the app's TOTAL box count before any
// prefix filter and failing the whole call with "Result limit exceeded" rather
// than paginating. Don't reach for it here.
const boxListPageLimit = 1000

// ErrBoxValuesUnsupported is returned by ListApplicationBoxes when algod
// returns box names without values despite `include=values` — an older node
// that doesn't implement the bulk values read. Callers can treat it as a signal
// to fall back to per-box reads rather than a hard failure.
var ErrBoxValuesUnsupported = errors.New("algod: node did not return box values for include=values")

// Box is one application box: its full name and value, both already
// base64-decoded from the algod response.
type Box struct {
	Name  []byte
	Value []byte
}

// BoxLister is the optional capability the escrow bulk fetchers probe for
// (production *sdkClient implements it; in-memory test fakes do not, and fall
// back to per-id box reads). It lists every box whose name starts with prefix,
// with values, paginating internally.
type BoxLister interface {
	ListApplicationBoxes(ctx context.Context, appID uint64, prefix []byte) ([]Box, error)
}

var _ BoxLister = (*sdkClient)(nil)

// ListApplicationBoxes returns every box of appID whose name starts with prefix,
// name AND value, in a single paginated sweep — the Go analogue of the client's
// getApplicationBoxes(...).prefix(...).include('values').next(...) loop.
//
// The SDK's `Round` param (pin page 1's round on every later page) is
// deliberately NOT used: box data is only readable for the rounds still in the
// node's lookback range, so pinning turns a slow sweep into a hard failure,
// while the next-token cursor is a box NAME in sorted order — a box written or
// deleted mid-sweep shifts no other box across the cursor, so an unpinned sweep
// can only miss or include that one box, never skip or duplicate the rest.
func (s *sdkClient) ListApplicationBoxes(ctx context.Context, appID uint64, prefix []byte) ([]Box, error) {
	prefixParam := "b64:" + base64.StdEncoding.EncodeToString(prefix)

	var out []Box
	next := ""
	for {
		req := s.c.GetApplicationBoxes(appID).
			Prefix(prefixParam).
			Include([]string{"values"}).
			Limit(boxListPageLimit)
		if next != "" {
			req = req.Next(next)
		}

		page, err := req.Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("algod: box-list for app %d: %w", appID, err)
		}

		for i := range page.Boxes {
			// include=values must yield a value; a name-only entry means the node
			// ignored the parameter — fail with a sentinel so the caller can fall
			// back to per-box reads. (Escrow boxes are never legitimately empty.)
			if page.Boxes[i].Value == nil {
				return nil, ErrBoxValuesUnsupported
			}
			out = append(out, Box{Name: page.Boxes[i].Name, Value: page.Boxes[i].Value})
		}
		if page.NextToken == "" {
			break
		}
		next = page.NextToken
	}
	return out, nil
}
