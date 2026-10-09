//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly || windows)

/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"errors"
	"os"
)

var errLocked = errors.New("locked")

// lockFile takes no lock here; see FileJournal.
func lockFile(*os.File) error { return nil }
