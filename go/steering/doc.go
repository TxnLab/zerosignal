/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package steering holds the pure arithmetic behind a payer's app-side routing
// signals: how relay-failure evidence ages (Decay, Bump), how long a failing
// target is demoted (BackoffWindow, BackoffRemaining), and which weights digest
// a model's operators agree on (WeightsConsensus). Mirrored in
// proto/ts/src/steering and golden-vectored in proto/testdata/steering_vectors.json.
//
// The stores these feed stay with each payer: the maps keyed by node, the
// reachability a differential claim is checked against, and the set of details
// envelopes a consensus is taken over are all per-process and vantage-specific,
// so two payers legitimately hold different state. What this package fixes is
// that the same state yields the same verdict in Go and TS: one implementation
// of the arithmetic per language, held together by the vectors rather than by
// hand-kept copies.
//
// Deliberately NOT part of selection: that package is the eligibility and
// price policy over a candidate set, and these are inputs a caller folds in
// around it, demoting and never excluding.
//
// Latency is not here either. Its EWMAs are floats with a browser-vantage
// sample the proxy doesn't have, so it is property-tested in each SDK instead.
package steering
