/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import (
	"errors"
	"math/big"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Index = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	for i := range len(base58Alphabet) {
		t[base58Alphabet[i]] = int8(i)
	}
	return t
}()

var errBase58 = errors.New("solana: invalid base58")

// maxBase58Len is the longest spelling of size bytes: all zeros, one '1'
// each, or ceil(size·log 256 / log 58) digits, whichever is longer.
func maxBase58Len(size int) int {
	return max(size, (size*1366+999)/1000)
}

// encodeBase58 is the Bitcoin alphabet, each leading zero byte written as '1'.
// Keys and signatures are 32 and 64 bytes, so big.Int is fast enough and
// keeps the code obviously right.
func encodeBase58(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b[zeros:])
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for range zeros {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// decodeBase58 decodes s into exactly size bytes. A string that decodes to
// any other length is refused rather than padded or truncated, so two
// spellings never name one key.
//
// A string longer than any spelling of size bytes is refused before
// decoding, which is quadratic in its length: keys arrive from RPC answers
// and node JSON, and a long one would otherwise stall the reader.
func decodeBase58(s string, size int) ([]byte, error) {
	if s == "" || len(s) > maxBase58Len(size) {
		return nil, errBase58
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for i := zeros; i < len(s); i++ {
		d := base58Index[s[i]]
		if d < 0 {
			return nil, errBase58
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(d)))
	}
	body := n.Bytes()
	if zeros+len(body) != size {
		return nil, errBase58
	}
	out := make([]byte, size)
	copy(out[zeros:], body)
	return out, nil
}
