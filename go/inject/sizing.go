/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

// FitsContextWindow reports whether input+maxOutput is within window
// without uint64 overflow. A window of 0 means "no cap declared" and
// returns true.
//
// Both the proxy's candidate filter and the node's reserve gatekeeper
// call this so the two layers agree byte-for-byte on what "fits" means.
// Keeping the check in the protocol module prevents silent drift if one
// side adds an adjustment (e.g. a safety margin) that the other
// forgets.
func FitsContextWindow(input, maxOutput, window uint64) bool {
	if window == 0 {
		return true
	}
	if input > ^uint64(0)-maxOutput {
		return false
	}
	return input+maxOutput <= window
}
