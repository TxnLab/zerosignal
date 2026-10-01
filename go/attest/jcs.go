/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// JCS — RFC 8785 JSON Canonicalization Scheme.
//
// Needed because ACI/1 binds its whole trust chain to sha256(JCS(document)):
// the workload keyset's digest is what the hardware quote commits to in
// report_data, and a receipt's signature is over the JCS form of the receipt
// minus its signature. A canonicalizer that is merely close produces a
// well-formed digest that is simply wrong — and from outside, a verifier
// computing the wrong digest is INDISTINGUISHABLE FROM AN HONEST VERIFIER
// CATCHING A LIAR. That asymmetry is why everything below refuses by name
// rather than guessing.
//
// THIS IMPLEMENTATION IS DELIBERATELY PARTIAL, and the partiality is the
// feature. It handles the subset RFC 8785 shares with a plain sorted-key
// encoder and refuses the rest. The alternative — implementing ECMAScript
// Number::toString and UTF-16 code-unit collation to serve documents nobody
// sends — is a large amount of subtle code whose failures are silent.
//
// WHY THE REFUSALS NEED THEIR OWN TESTS rather than a comment. The live ACI
// documents are all-ASCII strings and small integers, so the live path
// exercises only the easy half of the spec: an earlier revision of this code
// asserted its refusal discipline in a comment and was wrong in four ways
// while running green against a real gateway. See
// TestJCS_RefusesWhatItCannotCanonicalize, whose cases are deliberately ones
// no live document contains.
//
// ONE CONFORMANCE GAP IS KNOWINGLY LEFT OPEN: a DUPLICATE object key in the
// input collapses last-wins, silently, because encoding/json does. Closing it
// needs a token-level decoder, and it is left open rather than refused
// because the reference implementations we interoperate with resolve it the
// same way — `@phala/dcap-qvl` and the ACI gateway both round-trip through
// JSON.parse, which is also last-wins. So both sides compute the same digest
// over the same duplicate-keyed document, and a refusal here would break
// agreement rather than protect it. That reasoning is what makes it a gap
// rather than a bug; it stops holding the moment a peer canonicalizes from
// raw tokens.

// jcsSafeIntBound is 2^53 — above it, an integer's own decimal literal and
// its ECMAScript Number::toString form can differ.
const jcsSafeIntBound = 1 << 53

// jcsLineSeparators are U+2028 and U+2029, which Go's encoder escapes
// unconditionally and RFC 8785 §3.2.2.1 requires literal.
var jcsLineSeparators = string(rune(0x2028)) + string(rune(0x2029))

// ErrJCSUnsupported is returned for any input this canonicalizer declines to
// serialize. Callers MUST treat it as "cannot verify", never as "does not
// match" — the two lead to opposite conclusions about the peer.
var ErrJCSUnsupported = errors.New("attest: value is outside this JCS subset")

// JCSCanonicalize returns the RFC 8785 canonical form of raw.
//
// Errors wrap ErrJCSUnsupported when the input is outside the supported
// subset, and are plain decode errors when the input is not JSON.
func JCSCanonicalize(raw json.RawMessage) ([]byte, error) {
	// THE RAW BYTES ARE CHECKED FIRST, BEFORE ANY DECODE, AND THAT ORDERING IS
	// THE WHOLE POINT. encoding/json substitutes U+FFFD for invalid UTF-8 and
	// for an unpaired surrogate escape during DECODING, so a guard downstream
	// of Decode can never see either one — it inspects a string the decoder has
	// already repaired. That was the bug: `{"s":"\ud800"}`, `{"s":"\udead"}` and
	// a raw 0xFF byte all canonicalized to the same U+FFFD output with no error,
	// so sha256(JCS(doc)) was not injective over exactly the inputs the
	// canonicalizer was written to refuse.
	//
	// Both failure directions are bad and the second is worse. A conformant peer
	// either refuses an unpaired surrogate or emits `\ud800` (ES2019
	// well-formed JSON.stringify), so we would disagree with it and read the
	// disagreement as "the gateway is lying". And one signature or one
	// report_data commitment would cover several documents this verifier
	// considers identical.
	if err := jcsCheckRaw(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber, so a number's original literal survives to be checked.
	// Decoding into float64 would silently resolve the exact cases the
	// number rule exists to refuse.
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("attest: JCS input is not valid JSON: %w", err)
	}
	// Refuse trailing content rather than canonicalizing a prefix: two
	// documents differing only after the first value would otherwise
	// share a digest.
	//
	// dec.More() ALONE IS NOT ENOUGH, and the gap is exactly two bytes. It is
	// defined as `err == nil && c != ']' && c != '}'`, so a stray closing
	// bracket is invisible to it — `{"a":1}}` and `{"a":1}]` both canonicalized
	// to `{"a":1}` with no error, which is the digest collision this guard
	// exists to prevent. Reading one more token and requiring io.EOF closes it.
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing content after the first JSON value", ErrJCSUnsupported)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content after the first JSON value "+
			"(a stray closing bracket, which json.Decoder.More reports as end of input)",
			ErrJCSUnsupported)
	}
	var buf bytes.Buffer
	if err := jcsWrite(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jcsCheckRaw refuses the two input classes encoding/json silently repairs
// during decoding, so they cannot reach a downstream guard already looking at
// repaired text.
//
//  1. Invalid UTF-8 anywhere in the document.
//  2. A `\uD800`–`\uDFFF` escape that is not part of a high-then-low pair.
//
// It works on bytes rather than on a parse because that is the only place the
// information still exists. It is deliberately NOT a JSON parser: it scans for
// the escape form and for encoding validity, and leaves every syntactic
// judgment to the decoder that runs next. A `\u` sequence outside a string
// literal is not valid JSON, so the decoder refuses it regardless of what this
// pass concluded, and the cost of scanning it here is a spurious refusal on a
// document that was going to be refused anyway.
func jcsCheckRaw(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: input is not valid UTF-8, and encoding/json would silently "+
			"substitute U+FFFD while decoding — hashing bytes the peer never sent",
			ErrJCSUnsupported)
	}
	for i := 0; i+5 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		// A backslash-escaped backslash is not an escape introducer. Count the
		// run so `\\uD800` (a literal backslash then the text "uD800") is not
		// read as an escape.
		if raw[i+1] == '\\' {
			i++
			continue
		}
		if raw[i+1] != 'u' && raw[i+1] != 'U' {
			continue
		}
		cp, ok := jcsParseHex4(raw[i+2:])
		if !ok || cp < 0xD800 || cp > 0xDFFF {
			continue
		}
		if cp >= 0xDC00 {
			return fmt.Errorf("%w: input carries a low surrogate escape \\u%04X with no "+
				"preceding high surrogate; encoding/json decodes it to U+FFFD, so the digest "+
				"would cover bytes the peer never sent", ErrJCSUnsupported, cp)
		}
		// A high surrogate must be followed immediately by a low one.
		lo, lok := jcsParseHex4Escape(raw[i+6:])
		if !lok || lo < 0xDC00 || lo > 0xDFFF {
			return fmt.Errorf("%w: input carries a high surrogate escape \\u%04X that is not "+
				"followed by a low surrogate; encoding/json decodes it to U+FFFD, so the digest "+
				"would cover bytes the peer never sent", ErrJCSUnsupported, cp)
		}
		i += 11 // past both escapes
	}
	return nil
}

// jcsParseHex4 reads exactly four hex digits.
func jcsParseHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var v rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

// jcsParseHex4Escape reads a `\uXXXX` escape at the start of b.
func jcsParseHex4Escape(b []byte) (rune, bool) {
	if len(b) < 6 || b[0] != '\\' || (b[1] != 'u' && b[1] != 'U') {
		return 0, false
	}
	return jcsParseHex4(b[2:])
}

func jcsWrite(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return jcsWriteString(buf, t)
	case json.Number:
		// RFC 8785 §3.2.2.2 defers to ECMAScript Number::toString.
		// "Fits in an int64" is NOT the safe predicate, and assuming it
		// was is the mistake this guard exists to prevent — two int64
		// values serialize differently under the spec than as their own
		// literal, and both survive json.Number.Int64 without error
		// (measured, go1.26):
		//
		//	-0                 -> spec says "0",   literal is "-0"
		//	9007199254740993   -> spec says …992,  literal is …993
		//
		// So the predicate is "the literal is the canonical decimal form
		// of an integer a double represents exactly".
		i, err := t.Int64()
		if err != nil || strconv.FormatInt(i, 10) != t.String() ||
			i > jcsSafeIntBound || i < -jcsSafeIntBound {
			return fmt.Errorf("%w: number %q needs full RFC 8785 §3.2.2.2 "+
				"(ECMAScript Number::toString) serialization", ErrJCSUnsupported, t.String())
		}
		buf.WriteString(t.String())
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsWrite(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			// Sorting is by UTF-16 code unit (§3.2.3). Byte order and
			// UTF-16 order agree for everything below U+10000 that is
			// not a surrogate-pair boundary case; a non-ASCII key means
			// that agreement has to be argued rather than assumed.
			for _, r := range k {
				if r > 0x7f {
					return fmt.Errorf("%w: non-ASCII object key %q — sorting is by "+
						"UTF-16 code unit (§3.2.3) and this implementation only claims "+
						"byte-order equivalence for ASCII", ErrJCSUnsupported, k)
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := jcsWriteString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := jcsWrite(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrJCSUnsupported, v)
	}
	return nil
}

// jcsWriteString emits §3.2.2.1 string serialization, which is
// JSON.stringify: escape only the quote, the backslash and C0, and emit every
// other code point literally.
//
// Go's encoder is close to that but not equal to it, in THREE ways — all
// measured on go1.26, and only the first is the one people remember:
//
//   - The HTML trio is escaped. SetEscapeHTML(false) fixes it.
//   - U+2028 and U+2029 are escaped UNCONDITIONALLY, and SetEscapeHTML(false)
//     does NOT disable that. The spec requires them literal.
//   - Invalid UTF-8, including a lone surrogate, is silently replaced with
//     U+FFFD — by the decoder and the encoder both.
//
// The last two are refused rather than worked around. Emitting a digest over
// bytes that are not the input is the precise failure this canonicalizer
// exists to avoid.
//
// NOTE WHERE THE THIRD ONE IS ACTUALLY ENFORCED: jcsCheckRaw, on the raw input,
// before any decode. It has to be there — "by the decoder AND the encoder" is
// not a stylistic pairing, it means the string this function receives has
// already been repaired, so the check below cannot fire through
// JCSCanonicalize. It is kept as a belt for a future caller that reaches
// jcsWrite with a string from somewhere else.
func jcsWriteString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: string is not valid UTF-8, and Go would silently "+
			"substitute U+FFFD — hashing bytes the peer never sent", ErrJCSUnsupported)
	}
	if strings.ContainsAny(s, jcsLineSeparators) {
		return fmt.Errorf("%w: string contains U+2028/U+2029, which Go escapes "+
			"unconditionally (SetEscapeHTML(false) does not disable it) while RFC 8785 "+
			"§3.2.2.1 requires them literal", ErrJCSUnsupported)
	}
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
	return nil
}
