/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wallet

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// The environment the zerosignal CLIs read. The package reads neither unless
// a caller passes OverrideFromEnv or EnvOrPromptPassphrase, or calls
// LoadPayer, so an app that embeds it chooses its own sources.
const (
	// EnvBackend is a KeyringOptions.Override: BackendOS, BackendFile, or a
	// 99designs/keyring backend name.
	EnvBackend = "ZEROSIGNAL_KEYRING_BACKEND"
	// EnvPassphrase unlocks the encrypted file without a prompt, for a
	// service or a detached daemon with no terminal.
	EnvPassphrase = "ZEROSIGNAL_KEYSTORE_PASSPHRASE"
)

// OverrideFromEnv returns EnvBackend, "" when unset: a KeyringOptions.Override.
func OverrideFromEnv() string { return os.Getenv(EnvBackend) }

// EnvOrPromptPassphrase returns EnvPassphrase when it is set, else prompts on
// the terminal without echo. It is a KeyringOptions.Passphrase.
func EnvOrPromptPassphrase(prompt string) (string, error) {
	if v, ok := os.LookupEnv(EnvPassphrase); ok {
		return v, nil
	}
	if prompt == RepeatPassphrasePrompt {
		fmt.Fprint(os.Stderr, RepeatPassphrasePrompt+" to confirm it: ")
	} else {
		fmt.Fprint(os.Stderr, "Enter a passphrase to unlock your zerosignal wallet "+
			"(encrypts it at rest; set "+EnvPassphrase+" to skip this prompt): ")
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// NeedsPassphrasePrompt reports whether reading a wallet on backend with
// EnvOrPromptPassphrase will prompt: the encrypted file without EnvPassphrase
// set. A daemon asks this, with its opened Wallet's Backend, before it
// detaches from the terminal it would prompt on.
func NeedsPassphrasePrompt(backend string) bool {
	if _, ok := os.LookupEnv(EnvPassphrase); ok {
		return false
	}
	return UsesFileBackend(backend)
}
