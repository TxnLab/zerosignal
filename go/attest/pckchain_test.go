/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// These live HERE, beside the parser, rather than in the one consumer
// that happens to call it. The node's copy could not run on a `proto`
// clone — i.e. not on the side of the publish gate where the parser is
// edited — which for the newest and most attacker-exposed quote
// accessor in the package is the wrong half of the tree to be covered
// on.
func pckCapture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/attest/ds_quote_hex.txt")
	if err != nil {
		t.Fatalf("read quote capture: %v", err)
	}
	q, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if err != nil {
		t.Fatalf("capture is not hex: %v", err)
	}
	return q
}

// Runs on a real Phala CVM quote, never a synthetic one: a quote built
// from these same constants would agree with the walk by construction,
// and "the layout is not what we believe it is" is the only real risk
// this parser carries.
func TestQuotePCKCertChain_RealCapture(t *testing.T) {
	chain, ok := QuotePCKCertChain(pckCapture(t))
	if !ok {
		t.Fatal("no PCK certificate chain in the captured quote")
	}
	// Leaf, intermediate CA, root. A walk that landed one length field
	// early or late still returns SOMETHING, so the count is part of
	// the assertion rather than a nicety.
	if n := strings.Count(string(chain), "BEGIN CERTIFICATE"); n != 3 {
		t.Errorf("chain carries %d certificates, want 3", n)
	}
	if !strings.HasPrefix(string(chain), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("chain does not start at a PEM header: %.40q", chain)
	}
	// Documented on the accessor because a consumer splitting on the
	// END marker trips over it. Pinned so the doc cannot quietly
	// become false.
	if !strings.HasSuffix(string(chain), "\x00") {
		t.Error("expected the NUL terminator the declared length includes")
	}
}

// The returned slice must not alias the caller's quote. It used to,
// with ~70 bytes of spare capacity behind it, so an append by any
// downstream holder wrote into the buffer whose signature covers those
// bytes.
func TestQuotePCKCertChain_DoesNotAliasTheQuote(t *testing.T) {
	quote := pckCapture(t)
	before := append([]byte(nil), quote...)

	chain, ok := QuotePCKCertChain(quote)
	if !ok {
		t.Fatal("no chain")
	}
	_ = append(chain, "APPENDED"...) //nolint:gocritic // the point is the side effect
	for i := range quote {
		if quote[i] != before[i] {
			t.Fatalf("appending to the returned chain mutated the quote at offset %d", i)
		}
	}
}

// Every length field in this walk is attacker-supplied — the bytes
// arrive from a guest agent — so an overrun must be a false, never a
// panic on a path that runs inside a request handler.
func TestQuotePCKCertChain_RefusesMalformedQuotes(t *testing.T) {
	full := pckCapture(t)

	t.Run("truncated", func(t *testing.T) {
		// Exhaustive over every prefix, not a hand-picked few: the
		// interesting boundaries are interior length fields and nobody
		// can name them by eye.
		//
		// The threshold is DERIVED rather than asserted. This capture
		// carries ~70 bytes past the end of the declared chain, so the
		// walk legitimately succeeds on prefixes shorter than the whole
		// quote — the property under test is that it is all-or-nothing,
		// never a partial read. So: find the shortest prefix that
		// parses, require it to yield the same chain as the full quote,
		// and require every shorter prefix to refuse.
		want, ok := QuotePCKCertChain(full)
		if !ok {
			t.Fatal("the full quote does not parse")
		}
		shortest := -1
		for n := range len(full) + 1 {
			var got []byte
			var parsed bool
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panic on a %d-byte prefix: %v", n, r)
					}
				}()
				got, parsed = QuotePCKCertChain(full[:n])
			}()
			switch {
			case !parsed:
				if shortest >= 0 {
					t.Fatalf("a %d-byte prefix refused after a %d-byte one succeeded", n, shortest)
				}
			case shortest < 0:
				shortest = n
				fallthrough
			default:
				// A short read must never look like a good one.
				if string(got) != string(want) {
					t.Fatalf("a %d-byte prefix yielded a DIFFERENT %d-byte chain (full: %d)",
						n, len(got), len(want))
				}
			}
		}
		if shortest < 0 {
			t.Fatal("no prefix parsed at all")
		}
		t.Logf("chain is complete from %d bytes; the capture is %d (%d bytes of slack)",
			shortest, len(full), len(full)-shortest)
	})

	t.Run("length fields at their extremes", func(t *testing.T) {
		// The four little-endian length fields the walk reads, at the
		// offsets it reads them: signed-data (u32), outer cert-data
		// (u32, past its 2-byte type), QE auth (u16), nested cert-data
		// (u32, past its type). Each is overwritten with values that
		// would overrun, wrap, or read as negative.
		//
		// The nested one is the only field that can produce a
		// zero-length chain with the walk otherwise intact, so it is
		// the only one the `ok && len(chain) == 0` assertion below can
		// actually fire on — and it was the one missing from this list
		// while the comment above enumerated all four.
		sigLenOff := quoteHeaderLen + bodyLen
		outerLenOff := sigLenOff + 4 + sigECDSALen + sigPubKeyLen + 2
		authLenOff := outerLenOff + 4 + qeReportLen + qeReportSigLen
		authLen := int(binary.LittleEndian.Uint16(full[authLenOff : authLenOff+2]))
		nestedLenOff := authLenOff + 2 + authLen + 2
		for _, off := range []int{sigLenOff, outerLenOff, authLenOff, nestedLenOff} {
			for _, v := range []uint32{0, 1, 0x7fffffff, 0x80000000, 0xffffffff} {
				mutated := append([]byte(nil), full...)
				binary.LittleEndian.PutUint32(mutated[off:off+4], v)
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("panic with length %#x at offset %d: %v", v, off, r)
						}
					}()
					if chain, ok := QuotePCKCertChain(mutated); ok && len(chain) == 0 {
						t.Errorf("ok with an empty chain (length %#x at %d)", v, off)
					}
				}()
			}
		}
	})

	t.Run("wrong certification-data types", func(t *testing.T) {
		// Type 5 where 6 belongs and vice versa: the encrypted-PPID
		// variants are real Intel types this walk deliberately does not
		// handle, and reading one anyway would hand a caller the wrong
		// bytes rather than nothing.
		outerTypeOff := quoteHeaderLen + bodyLen + 4 + sigECDSALen + sigPubKeyLen
		for _, v := range []uint16{0, 1, 2, 3, 4, 5, 7} {
			mutated := append([]byte(nil), full...)
			binary.LittleEndian.PutUint16(mutated[outerTypeOff:outerTypeOff+2], v)
			if _, ok := QuotePCKCertChain(mutated); ok {
				t.Errorf("outer certification-data type %d was accepted", v)
			}
		}

		// The NESTED tag, which is the one that says these bytes are a
		// PEM chain at all. Checking only the outer tag leaves types
		// 1-3 — Intel's encrypted-PPID variants, whose chain must be
		// fetched from a PCCS instead — handed back as if they were
		// certificates.
		authLenOff := outerTypeOff + 2 + 4 + qeReportLen + qeReportSigLen
		authLen := int(binary.LittleEndian.Uint16(full[authLenOff : authLenOff+2]))
		nestedTypeOff := authLenOff + 2 + authLen
		for _, v := range []uint16{0, 1, 2, 3, 4, 6, 7} {
			mutated := append([]byte(nil), full...)
			binary.LittleEndian.PutUint16(mutated[nestedTypeOff:nestedTypeOff+2], v)
			if _, ok := QuotePCKCertChain(mutated); ok {
				t.Errorf("nested certification-data type %d was accepted", v)
			}
		}
	})

	t.Run("non-TDX quotes are refused structurally", func(t *testing.T) {
		// Not probabilistically. The whole layout below the header is
		// TDX v4's; an SGX quote that happened to carry a 6 where the
		// tag is read would otherwise walk on into unrelated bytes.
		mutated := append([]byte(nil), full...)
		binary.LittleEndian.PutUint32(mutated[headerTEEType:headerTEEType+4], 0)
		if _, ok := QuotePCKCertChain(mutated); ok {
			t.Error("an SGX tee_type was accepted by a TDX-only walk")
		}
	})
}

// The trailing slack is real on this capture — the declared lengths end
// before the quote does — so a caller must not read "refuses a
// truncation" as "requires exact consumption".
func TestQuotePCKCertChain_ToleratesTrailingBytes(t *testing.T) {
	if _, ok := QuotePCKCertChain(append(pckCapture(t), 0xff, 0xff)); !ok {
		t.Error("trailing bytes made the chain unreadable")
	}
}
