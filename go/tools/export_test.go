/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

// Unexported limits the cross-impl vectors pin, so the TS port enforces the
// same budget the node does without widening this package's API.
const (
	MaxIconsTotalB64BytesForTest = maxIconsTotalB64Bytes
	MaxActionSourcesForTest      = maxActionSources
	MaxActionQueryBytesForTest   = maxActionQueryBytes
	MaxActionURLBytesForTest     = maxActionURLBytes
)

// LinkableURLForTest exposes the link rule so the TS port's is pinned to it.
var LinkableURLForTest = linkableURL
