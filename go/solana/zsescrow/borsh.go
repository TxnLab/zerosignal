/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The Borsh subset the program's instructions, accounts and events use:
// little-endian integers, a bool as one byte, an Option as a 0/1 tag, and a
// string or byte vector as a u32 length and its bytes.

type writer struct{ b []byte }

func (w *writer) u8(v uint8)   { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }
func (w *writer) i64(v int64)  { w.u64(uint64(v)) }
func (w *writer) bytes(b []byte) {
	w.b = append(w.b, b...)
}
func (w *writer) key(k solana.PublicKey) { w.bytes(k[:]) }
func (w *writer) bool(v bool) {
	if v {
		w.u8(1)
	} else {
		w.u8(0)
	}
}
func (w *writer) vec(b []byte) {
	w.u32(uint32(len(b)))
	w.bytes(b)
}

// option writes Some(v) or None.
func option[T any](w *writer, v *T, put func(T)) {
	if v == nil {
		w.u8(0)
		return
	}
	w.u8(1)
	put(*v)
}

var ErrDecode = errors.New("zsescrow: malformed data")

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return make([]byte, n)
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = fmt.Errorf("%w: short read at %d", ErrDecode, r.off)
		return make([]byte, n)
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *reader) u8() uint8   { return r.take(1)[0] }
func (r *reader) u16() uint16 { return binary.LittleEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.LittleEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.LittleEndian.Uint64(r.take(8)) }
func (r *reader) i64() int64  { return int64(r.u64()) }
func (r *reader) key() (k solana.PublicKey) {
	copy(k[:], r.take(32))
	return k
}

// bool refuses a byte other than 0 or 1, as Borsh does.
func (r *reader) bool() bool {
	v := r.u8()
	if v > 1 && r.err == nil {
		r.err = fmt.Errorf("%w: bool %d at %d", ErrDecode, v, r.off-1)
	}
	return v == 1
}

func (r *reader) vec() []byte {
	n := r.u32()
	if r.err == nil && int(n) > len(r.b)-r.off {
		r.err = fmt.Errorf("%w: length %d at %d", ErrDecode, n, r.off-4)
		return nil
	}
	return append([]byte(nil), r.take(int(n))...)
}

func (r *reader) array(dst []byte) { copy(dst, r.take(len(dst))) }

// claim reads ClaimFields in their Borsh order, ClaimFields.put's.
func (r *reader) claim() (f ClaimFields) {
	f.Amount = r.u64()
	r.array(f.ReceiptDigest[:])
	f.TTFTMs, f.DecodeMs, f.InputUnits, f.OutputUnits = r.u64(), r.u64(), r.u64(), r.u64()
	f.OutputUsageType, f.AuxUsageType, f.AuxCount = r.u8(), r.u8(), r.u64()
	return f
}
