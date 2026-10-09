/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"bytes"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Canonical mime strings for the icon formats a ZeroSignal node may put on
// the wire. This set IS the allowlist: IconMimeFromBytes returns one of
// these or the empty string, and nothing else may appear in
// ToolAction.Icons.
//
// image/svg+xml is deliberately absent and must stay absent. SVG is an
// active document format, and these are third-party bytes a node fetched
// from a site it does not control, relayed to a consumer that will inline
// them into its own page. Raster only.
const (
	IconMimeICO  = "image/x-icon"
	IconMimePNG  = "image/png"
	IconMimeGIF  = "image/gif"
	IconMimeJPEG = "image/jpeg"
	IconMimeWebP = "image/webp"
)

const (
	// MaxIconRawBytes bounds ONE icon's decoded bytes. Exported because the
	// node's fetcher enforces it at download time (io.LimitReader) and this
	// package enforces it again on the way onto the wire — one number, one
	// contract, checked at both ends.
	MaxIconRawBytes = 16 << 10

	// maxIconsTotalB64Bytes bounds ALL icons on a single action, measured on
	// the base64 payload rather than the decoded bytes because that is what
	// actually rides the sealed frame and lands in the receipt body_hash.
	maxIconsTotalB64Bytes = 96 << 10

	// MaxIconHosts bounds how many distinct hosts one action may carry an
	// icon for. Independent of maxActionSources: several sources routinely
	// share a host, and the icons map is keyed by host precisely so they
	// collapse. Exported so a fetcher can bound its fan-out to the same
	// number rather than fetching icons this package would then discard.
	MaxIconHosts = 12
)

// SourceIcon is a site's own favicon, fetched by the node and inlined so the
// consumer never contacts the site itself.
//
// That indirection is the entire point of carrying bytes rather than a URL.
// A consumer rendering <img src="https://thatsite.com/favicon.ico"> would
// leak its IP and a render timestamp to every host in a search result — hosts
// chosen by a third-party search backend steered by a model-chosen query,
// which makes it a beacon channel rather than a decoration. The bytes ride
// the sealed frame instead, so a relay learns nothing and the consumer
// contacts nobody.
//
// Mime is always one of the Icon*Mime constants above, derived from the
// bytes themselves (IconMimeFromBytes) and never from the serving site's
// Content-Type header.
type SourceIcon struct {
	Mime    string `json:"mime"`
	DataB64 string `json:"data_b64"`
}

// IconHostKey normalizes a source URL to the key used in ToolAction.Icons.
//
// The key is defined as the URL's WHATWG `URL.hostname`: lowercased, port
// dropped, IDN in punycode, an IPv6 literal in brackets and canonically
// compressed. "www." is NOT stripped.
//
// Pinning it to WHATWG rather than "whatever each side's URL parser returns"
// is the whole point. A consumer's display layer trims "www." for readability
// (the reference client does, in linkableSourceHost), so the key cannot be the
// display form — but "each side re-derives it from the URL" is not on its own
// enough to prevent drift, because the parsers genuinely disagree. Go's
// url.Hostname() does no IDNA and strips IPv6 brackets, where the browser's
// URL.hostname applies IDNA ToASCII and keeps them, so `https://münchen.de/`
// and `https://[2001:db8::1]/` key differently on the two sides unless this
// function does the extra work. Naming one external standard gives both sides
// a target instead of two hand-rolled normalizers to keep identical forever.
//
// Verified against the browser by TestIconHostKey_MatchesWHATWG, and pinned to
// the TS port by testdata/tools_vectors.json, whose host-key table the reference
// client's favicon-store.test.ts also duplicates — edit one, edit the others.
//
// Known divergences, all URLs WHATWG refuses outright and Go's parser takes, so
// the consumer has no key to look the icon up by anyway: a port above 65535, a
// host whose last label is numeric but not a valid IPv4 address (`256.1.1.1`,
// `example.123`), and `<` / `>` in the host. WHATWG also canonicalizes IPv4
// shorthand and integer forms (`127.1`, `16843009` = 1.1.1.1) where Go keys the
// literal text; the SSRF guard refuses the private ones, not all of them.
func IconHostKey(rawURL string) (string, bool) {
	if !linkableURL(rawURL) {
		return "", false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	h := parsed.Hostname()
	// A zone identifier (`fe80::1%eth0`) has no WHATWG form: the browser
	// refuses the URL, so no consumer could ever look its icon up.
	if h == "" || strings.Contains(h, "%") {
		return "", false
	}
	// An IPv6 literal keeps its brackets and takes WHATWG's serialization,
	// which matches RFC 5952 except that an embedded IPv4 is written in hex.
	if addr, err := netip.ParseAddr(h); err == nil && addr.Is6() {
		return "[" + whatwgIPv6(addr) + "]", true
	}
	if isASCII(h) {
		// Already the ToASCII fixed point. Taken as-is rather than through
		// idna, whose Lookup profile rejects runes WHATWG allows in an ASCII
		// host (an underscore, most notably) — rejecting those here would
		// drop icons for hosts the consumer keys perfectly well.
		return strings.ToLower(h), true
	}
	a, err := idna.Lookup.ToASCII(h)
	if err != nil || a == "" {
		return "", false
	}
	return strings.ToLower(a), true
}

// whatwgIPv6 serializes an IPv6 address as the URL Standard does: eight
// lowercase hex groups with the first longest run of two or more zero groups
// compressed. That is netip's RFC 5952 form except for an IPv4-mapped address,
// which RFC 5952 writes dotted (`::ffff:1.2.3.4`) and WHATWG in hex
// (`::ffff:102:304`).
func whatwgIPv6(addr netip.Addr) string {
	if !addr.Is4In6() {
		return addr.String()
	}
	b := addr.As16()
	var groups [8]uint16
	for i := range groups {
		groups[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	runStart, runLen := -1, 1
	for i := 0; i < len(groups); {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(groups) && groups[j] == 0 {
			j++
		}
		if j-i > runLen {
			runStart, runLen = i, j-i
		}
		i = j
	}
	var sb strings.Builder
	for i := 0; i < len(groups); i++ {
		if i == runStart {
			sb.WriteString("::")
			i += runLen - 1
			continue
		}
		if i > 0 && i != runStart+runLen {
			sb.WriteByte(':')
		}
		sb.WriteString(strconv.FormatUint(uint64(groups[i]), 16))
	}
	return sb.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// IconMimeFromBytes reports the canonical mime for raw icon bytes by
// inspecting their magic number, or "" if they are not a format this
// protocol carries.
//
// Sniffing rather than trusting the response's Content-Type is deliberate:
// the header is set by a site the node does not control, so a server could
// otherwise label an SVG (or anything else) as image/png and have it inlined
// into a consumer's page. The bytes decide.
func IconMimeFromBytes(b []byte) string {
	switch {
	// PNG: \x89PNG\r\n\x1a\n
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		return IconMimePNG
	// JPEG: FF D8 FF
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return IconMimeJPEG
	// GIF87a / GIF89a
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return IconMimeGIF
	// RIFF....WEBP
	case len(b) >= 12 && bytes.HasPrefix(b, []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return IconMimeWebP
	// ICO: 00 00 01 00. The neighbouring 00 00 02 00 is a CUR (cursor)
	// resource, which shares the container but is not an image a consumer
	// should render — match the icon type exactly, not the container.
	case bytes.HasPrefix(b, []byte{0x00, 0x00, 0x01, 0x00}):
		return IconMimeICO
	default:
		return ""
	}
}

// iconMimeAllowed guards AttachIcons against a hand-built SourceIcon whose
// Mime never came from IconMimeFromBytes.
func iconMimeAllowed(mime string) bool {
	switch mime {
	case IconMimeICO, IconMimePNG, IconMimeGIF, IconMimeJPEG, IconMimeWebP:
		return true
	default:
		return false
	}
}

// AttachIcons sets a.Icons from the fetched icons, walking hosts in the
// given order and stopping at the host-count cap or the total byte budget.
//
// Order is a parameter rather than being read off the map because Go
// randomizes map iteration: budget-driven dropping would otherwise discard a
// different arbitrary icon on every request. Callers pass hosts in the order
// their sources appear, so a tight budget favours the top of the list — the
// chips a reader looks at first.
//
// The two caps deliberately behave differently, and the difference is easy to
// "tidy" away. The host COUNT cap yields a true prefix — the first
// MaxIconHosts entries, nothing after. The BYTE budget is first-fit: an icon
// too large for the remaining room is skipped and later smaller ones still
// fit. Turning that into a prefix would mean one large icon near the head
// blanks every chip behind it. Both are pinned by tests, and SPEC § 5.3.1
// describes the distinction.
//
// Entries whose mime is outside the allowlist, whose payload is empty, or
// which exceed MaxIconRawBytes are skipped. Nothing is truncated: half an
// icon is not a smaller icon.
func (a *ToolAction) AttachIcons(hosts []string, icons map[string]*SourceIcon) {
	if a == nil || len(hosts) == 0 || len(icons) == 0 {
		return
	}
	out := make(map[string]*SourceIcon, len(hosts))
	total := 0
	for _, h := range hosts {
		if len(out) == MaxIconHosts {
			break
		}
		ic := icons[h]
		if ic == nil || !iconMimeAllowed(ic.Mime) {
			continue
		}
		if _, dup := out[h]; dup {
			continue
		}
		if raw := rawB64Len(ic.DataB64); raw < 0 || raw > MaxIconRawBytes {
			continue
		}
		if total+len(ic.DataB64) > maxIconsTotalB64Bytes {
			continue
		}
		total += len(ic.DataB64)
		out[h] = ic
	}
	if len(out) == 0 {
		return
	}
	a.Icons = out
}

// rawB64Len is the exact decoded size of a standard padded base64 string, or
// -1 if s is not one.
//
// Exact rather than the obvious len(s)/4*3 approximation because the cap it
// feeds is a documented contract: base64 rounds 3 raw bytes up to 4, so
// comparing encoded lengths would admit an icon up to two bytes past
// MaxIconRawBytes, and "bounded at 16 KiB, give or take" is not a bound.
// Rejecting a length that is not a multiple of four also rejects an empty
// payload and anything whose length was never legal for standard base64. It
// does NOT validate the alphabet — "@@@@" measures as three bytes here. The
// consumer re-checks the alphabet before building a data: URI, which is where
// that matters; this is a size bound, not a decoder.
func rawB64Len(s string) int {
	n := len(s)
	if n == 0 || n%4 != 0 {
		return -1
	}
	pad := 0
	if s[n-1] == '=' {
		pad++
		if s[n-2] == '=' {
			pad++
		}
	}
	return n/4*3 - pad
}
