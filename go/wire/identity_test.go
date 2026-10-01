/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestLoadIdentityFromFile_RoundTrip(t *testing.T) {
	id := newTestIdentity(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	content := "# created by age-keygen\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadIdentityFromFile(path)
	if err != nil {
		t.Fatalf("LoadIdentityFromFile: %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Errorf("loaded identity recipient = %s, want %s",
			got.Recipient(), id.Recipient())
	}
}

func TestLoadIdentityFromFile_Missing(t *testing.T) {
	_, err := LoadIdentityFromFile(filepath.Join(t.TempDir(), "nope.key"))
	if err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestLoadIdentityFromFile_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("not-an-age-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentityFromFile(path)
	if err == nil {
		t.Fatal("want parse error")
	}
}

func TestLoadIdentityFromFile_OnlyComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(path, []byte("# just a comment\n# another\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentityFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "no age identity") {
		t.Errorf("want no-identity error, got %v", err)
	}
}

// secretBytes returns a copy of the age identity's secretKey via reflect +
// unsafe. Fails the test if the field layout has drifted.
func secretBytes(t *testing.T, id any) []byte {
	t.Helper()
	v := reflect.ValueOf(id).Elem().FieldByName("secretKey")
	if !v.IsValid() {
		t.Fatal("age.X25519Identity has no `secretKey` field — zero helper will silently no-op")
	}
	if v.Kind() != reflect.Slice {
		t.Fatalf("secretKey kind = %v, want slice", v.Kind())
	}
	sk := (*[]byte)(unsafe.Pointer(v.UnsafeAddr()))
	out := make([]byte, len(*sk))
	copy(out, *sk)
	return out
}

func TestZeroEphemeralIdentity_WipesSecret(t *testing.T) {
	id := newTestIdentity(t)

	before := secretBytes(t, id)
	if len(before) == 0 {
		t.Fatal("secretKey empty before wipe")
	}
	allZero := true
	for _, b := range before {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("secretKey was already all-zero before wipe")
	}

	ZeroEphemeralIdentity(id)

	after := secretBytes(t, id)
	for i, b := range after {
		if b != 0 {
			t.Errorf("secretKey[%d] = %x, want 0", i, b)
		}
	}
}

func TestZeroEphemeralIdentity_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic on nil: %v", r)
		}
	}()
	ZeroEphemeralIdentity(nil)
}

// TestZeroEphemeralIdentity_FieldNameAssumption ensures a future age release
// that renames `secretKey` is loud, not silent — if this test fails the
// zero helper has become a no-op.
func TestZeroEphemeralIdentity_FieldNameAssumption(t *testing.T) {
	id := newTestIdentity(t)
	v := reflect.ValueOf(id).Elem().FieldByName("secretKey")
	if !v.IsValid() {
		t.Fatal("age.X25519Identity.secretKey no longer exists — update identity.go")
	}
}
