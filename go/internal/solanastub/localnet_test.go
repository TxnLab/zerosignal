/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solanastub

import "testing"

// The localnet's keypair is also devnet's admin, so StartLocalnet must refuse
// before it writes the Config anywhere but this machine.
func TestCheckLoopback(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"http://127.0.0.1:8899":         true,
		"http://localhost:8899":         true,
		"http://[::1]:8899":             true,
		"http://127.0.0.2:8899":         true,
		"https://api.devnet.solana.com": false,
		"http://10.0.0.5:8899":          false,
		"http://localhost.example.com":  false,
		"http://0.0.0.0:8899":           false,
		"":                              false,
	} {
		if err := checkLoopback(endpoint); (err == nil) != ok {
			t.Errorf("checkLoopback(%q) = %v, want ok %v", endpoint, err, ok)
		}
	}
}
