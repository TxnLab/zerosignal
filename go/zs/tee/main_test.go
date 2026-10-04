/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tee

import (
	"os"
	"testing"
	"time"
)

// testStateDir is where TestMain persists the collateral cache's process
// singleton.
var testStateDir string

// TestMain points the collateral cache's process singleton at a temporary
// directory before any test can use it, so no test reads or writes a
// developer's real tee-collateral.json.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "zs-tee-test-state-")
	if err != nil {
		panic(err)
	}
	testStateDir = dir
	if err := PersistCollateral(dir); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
