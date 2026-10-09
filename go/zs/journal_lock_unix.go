//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"errors"
	"os"
	"syscall"
)

var errLocked = errors.New("locked")

// lockFile takes an exclusive lock on f without waiting. Closing f releases
// it, and so does the process exiting.
func lockFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return errLocked
	}
	return err
}
