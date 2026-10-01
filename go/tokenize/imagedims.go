/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import (
	"encoding/base64"
	"strings"
)

// True pixel dimensions for the v2 bound's image term.
//
// v1 prices every image the caller didn't annotate at the 2048x2048 high-detail
// fallback — 2805 tokens — because no client sets width/height on an image part
// (and none should: they aren't standard fields, and a strict upstream rejects
// unknown keys). Measured against the corpus that is 3.7x-11x the true cost.
//
// The bytes are already in the body, though: a pasted image rides as a
// `data:image/...;base64,...` URL. So the bound reads the dimensions out of the
// image HEADER, and the caller, the proxy and the node all derive the identical
// number from the identical body with no wire change.
//
// Two hard rules, because this parses attacker-controlled input inside the node:
//
//   - HEADER ONLY, NEVER DECODE. Nothing here inflates, allocates per-pixel, or
//     walks image data. A decoder would be a decompression-bomb vector.
//   - BOUNDED READ. At most imageHeaderScanBytes of the base64 payload is
//     decoded, so a 50 MB data URL costs the same as a 50 KB one.
//
// Anything unrecognised — a remote URL, a truncated or malformed header, an
// unknown format, a SOF marker past the scan window — falls through to the
// 2048x2048 fallback. The failure direction is always "charge more".
const (
	// Decoded bytes examined. A JPEG can carry a large EXIF or ICC block ahead
	// of its SOF marker, so this is well past the ~30 bytes the other formats
	// need. Still a hard ceiling: past it, the fallback applies.
	imageHeaderScanBytes = 64 * 1024

	// base64 encodes 3 bytes per 4 characters.
	base64CharsPerScan = (imageHeaderScanBytes/3 + 1) * 4
)

// imageDimsFromURL returns the pixel dimensions encoded in a data: URL's image
// header, or ok=false when they can't be established.
func imageDimsFromURL(url string) (width, height int, ok bool) {
	raw, ok := decodeImageHeader(url)
	if !ok {
		return 0, 0, false
	}
	return sniffImageDims(raw)
}

// decodeImageHeader extracts and base64-decodes the leading bytes of a data:
// URL's payload. Returns ok=false for any non-base64 data URL or other scheme.
func decodeImageHeader(url string) ([]byte, bool) {
	if !strings.HasPrefix(url, "data:") {
		return nil, false
	}
	idx := strings.Index(url, ";base64,")
	if idx < 0 {
		return nil, false
	}
	payload := stripASCIIWhitespace(url[idx+len(";base64,"):])
	if len(payload) > base64CharsPerScan {
		payload = payload[:base64CharsPerScan]
	}
	// Truncating mid-quantum leaves a length that isn't a multiple of 4;
	// dropping the partial group keeps the decode strict and cheap.
	payload = payload[:len(payload)-len(payload)%4]
	if payload == "" {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		// A truncated payload can still yield a usable prefix; retry on the
		// largest clean quantum boundary before giving up.
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(payload, "="))
		if err != nil {
			return nil, false
		}
	}
	return raw, len(raw) > 0
}

// stripASCIIWhitespace removes the whitespace a line-wrapping base64 encoder
// inserts. Go's encoding/base64 silently skips \r and \n; the TS mirror's
// decoder rejects them outright, so without this a MIME-wrapped data URL — what
// Java's Base64.getMimeEncoder, Python's base64.encodebytes and the openssl
// base64 CLI all emit by default — reads its true dimensions on one side and
// the 2048x2048 fallback on the other, and the node rejects an honest request.
func stripASCIIWhitespace(s string) string {
	if !strings.ContainsAny(s, " \t\r\n\v\f") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\r', '\n', '\v', '\f':
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// sniffImageDims dispatches on the format's magic bytes.
//
// GIF is deliberately ABSENT. Its Logical Screen Descriptor — the only size
// field in the header — is not the size a decoder reports: PIL, and therefore
// the transformers/vLLM image path, use the per-frame Image Descriptor. The two
// may legally disagree, and the LSD is four payer-controlled bytes, so patching
// them to 1x1 dropped a real 4096x4096 GIF from 11012 tokens to 302 — a 36x
// under-reserve that the node cannot detect, because it re-measures with this
// same function. Every other format's header IS authoritative for real decoders
// (a lie there makes the decoder see the same small image), so only GIF has the
// gap. Falling through to the 2048x2048 default costs an honest small GIF some
// over-reservation and closes the hole.
func sniffImageDims(b []byte) (width, height int, ok bool) {
	switch {
	case len(b) >= 24 && string(b[:8]) == "\x89PNG\r\n\x1a\n" && string(b[12:16]) == "IHDR":
		return be32(b[16:]), be32(b[20:]), true
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return webpDims(b)
	case len(b) >= 4 && b[0] == 0xFF && b[1] == 0xD8:
		return jpegDims(b)
	}
	return 0, 0, false
}

// webpDims handles all three WebP chunk layouts: extended (VP8X), lossy (VP8 )
// and lossless (VP8L).
func webpDims(b []byte) (width, height int, ok bool) {
	if len(b) < 16 {
		return 0, 0, false
	}
	switch string(b[12:16]) {
	case "VP8X":
		// 24-bit little-endian (canvas width - 1, canvas height - 1) at +24.
		if len(b) < 30 {
			return 0, 0, false
		}
		return le24(b[24:]) + 1, le24(b[27:]) + 1, true
	case "VP8 ":
		// Keyframe header: 3-byte frame tag, the 3-byte start code, then
		// 14-bit width and height.
		if len(b) < 30 || b[23] != 0x9D || b[24] != 0x01 || b[25] != 0x2A {
			return 0, 0, false
		}
		return le16(b[26:]) & 0x3FFF, le16(b[28:]) & 0x3FFF, true
	case "VP8L":
		// Signature byte 0x2F, then 14 bits of (width - 1) and 14 of (height - 1).
		if len(b) < 25 || b[20] != 0x2F {
			return 0, 0, false
		}
		bits := uint32(b[21]) | uint32(b[22])<<8 | uint32(b[23])<<16 | uint32(b[24])<<24
		return int(bits&0x3FFF) + 1, int((bits>>14)&0x3FFF) + 1, true
	}
	return 0, 0, false
}

// jpegDims scans the marker chain for a start-of-frame segment. JPEG puts no
// dimensions in a fixed position — they live in whichever SOFn arrives after an
// arbitrary run of application and quantisation segments.
func jpegDims(b []byte) (width, height int, ok bool) {
	i := 2
	for i+3 < len(b) {
		if b[i] != 0xFF {
			// Not at a marker boundary: resynchronise rather than trusting a
			// length field we may have mis-read.
			i++
			continue
		}
		marker := b[i+1]
		switch {
		case marker == 0xFF:
			// Fill byte; markers may be padded with any number of 0xFF.
			i++
			continue
		case marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7):
			// Standalone markers carry no length field.
			i += 2
			continue
		case marker == 0xDA || marker == 0xD9:
			// Start of scan / end of image: entropy-coded data follows and no
			// SOF can appear after it in a baseline file.
			return 0, 0, false
		}
		segLen := be16(b[i+2:])
		if segLen < 2 {
			return 0, 0, false
		}
		// SOF0..SOF15, excluding DHT (0xC4), JPG (0xC8) and DAC (0xCC).
		if marker >= 0xC0 && marker <= 0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
			if i+9 > len(b) {
				return 0, 0, false
			}
			// Segment layout: length(2) precision(1) height(2) width(2).
			return be16(b[i+7:]), be16(b[i+5:]), true
		}
		i += 2 + segLen
	}
	return 0, 0, false
}

func be16(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

func be32(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

func le16(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	return int(b[0]) | int(b[1])<<8
}

func le24(b []byte) int {
	if len(b) < 3 {
		return 0
	}
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16
}
