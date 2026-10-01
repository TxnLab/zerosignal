/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"os"
	"time"
)

// LoadTimeout is the deadline binaries should apply when calling New
// with the default provider chain. Long enough to tolerate a single
// slow cloud backend round-trip; short enough to keep startup snappy
// and surface misconfigured credentials quickly.
const LoadTimeout = 30 * time.Second

// MnemonicURLsEnv is the env var both the node and the proxy consult
// for cloud-backed mnemonic URLs. Format:
//
//	name1=awssecretsmanager://...,name2=gcpsecretmanager://...,name3=azurekeyvault://VAULT/SECRET
//
// Empty or unset means "no cloud secrets configured" — env-only mode.
const MnemonicURLsEnv = "ZS_MNEMONIC_URLS"

// ProvidersFromEnv returns the standard provider chain a binary should
// hand to New: the OS-environment scanner first (cheapest, always
// safe), then the URL-backed cloud provider that dispatches per URL
// scheme to the right backend (AWS / GCP / Azure / file).
//
// Nil providers in the slice are tolerated by New, so binaries can
// pass the result directly without filtering.
func ProvidersFromEnv() []SecretProvider {
	return []SecretProvider{
		EnvProvider{},
		NewURLProviderFromEnv(os.Getenv(MnemonicURLsEnv)),
	}
}

// LoadFromEnv is the one-line equivalent of "build the standard
// provider chain, build a keystore from it, with the standard
// timeout." Binaries that don't need to inject extra providers can
// skip the boilerplate.
func LoadFromEnv(parent context.Context) (*KeyStore, error) {
	ctx, cancel := context.WithTimeout(parent, LoadTimeout)
	defer cancel()
	return New(ctx, ProvidersFromEnv()...)
}
