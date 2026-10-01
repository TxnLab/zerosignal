/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"filippo.io/age"
)

// LoadIdentityFromFile reads an age identity file (the output of `age-keygen
// -o <path>`) and returns the parsed identity. Accepts files with comment
// lines prefixed with "#" and the standard AGE-SECRET-KEY-1... line.
func LoadIdentityFromFile(path string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("parse identity in %s: %w", path, err)
		}
		return id, nil
	}
	return nil, fmt.Errorf("no age identity found in %s", path)
}

// ZeroEphemeralIdentity is a best-effort wipe of the private scalar held
// inside an age.X25519Identity. The library stores the key in an unexported
// `secretKey []byte` field, so we reach it with reflect + unsafe. If a
// future age release renames or restructures the field this silently
// becomes a no-op — the identity is still collected by GC, the key just
// lingers in the heap until then.
func ZeroEphemeralIdentity(id *age.X25519Identity) {
	if id == nil {
		return
	}
	v := reflect.ValueOf(id).Elem().FieldByName("secretKey")
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return
	}
	sk := (*[]byte)(unsafe.Pointer(v.UnsafeAddr()))
	for i := range *sk {
		(*sk)[i] = 0
	}
}
