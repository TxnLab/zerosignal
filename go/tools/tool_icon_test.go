/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Real magic-number prefixes, padded out so the length checks pass.
func pngBytes() []byte {
	return append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, 0, 1, 2, 3)
}
func jpegBytes() []byte { return append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, 0, 1, 2, 3) }
func gif89Bytes() []byte {
	return append([]byte("GIF89a"), 0, 1, 2, 3)
}
func gif87Bytes() []byte {
	return append([]byte("GIF87a"), 0, 1, 2, 3)
}
func webpBytes() []byte {
	b := []byte("RIFF")
	b = append(b, 0x1A, 0x00, 0x00, 0x00)
	b = append(b, []byte("WEBPVP8 ")...)
	return b
}
func icoBytes() []byte { return append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00}, 0, 1, 2, 3) }

func TestIconMimeFromBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"png", pngBytes(), IconMimePNG},
		{"jpeg", jpegBytes(), IconMimeJPEG},
		{"gif89a", gif89Bytes(), IconMimeGIF},
		{"gif87a", gif87Bytes(), IconMimeGIF},
		{"webp", webpBytes(), IconMimeWebP},
		{"ico", icoBytes(), IconMimeICO},
		{"empty", nil, ""},
		{"html error page", []byte("<!DOCTYPE html><html><body>404"), ""},
		{"pdf", []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3"), ""},
		{"truncated png signature", []byte{0x89, 'P', 'N'}, ""},
		{"riff that is not webp", append([]byte("RIFF"), append([]byte{0, 0, 0, 0}, []byte("WAVEfmt ")...)...), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IconMimeFromBytes(tc.in); got != tc.want {
				t.Fatalf("IconMimeFromBytes = %q, want %q", got, tc.want)
			}
		})
	}
}

// SVG is the one exclusion that is a security property rather than a format
// choice: it is an active document, and these bytes come from a site the node
// does not control and get inlined into the consumer's page.
func TestIconMimeFromBytes_RejectsSVG(t *testing.T) {
	svgs := [][]byte{
		[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		[]byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>`),
		[]byte("\xef\xbb\xbf<svg/>"), // BOM-prefixed
	}
	for _, b := range svgs {
		if got := IconMimeFromBytes(b); got != "" {
			t.Fatalf("SVG sniffed as %q, want it rejected", got)
		}
	}
}

// A CUR shares the ICO container but is a cursor resource, not an icon.
func TestIconMimeFromBytes_RejectsCursor(t *testing.T) {
	cur := []byte{0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0, 1, 2, 3}
	if got := IconMimeFromBytes(cur); got != "" {
		t.Fatalf("CUR sniffed as %q, want it rejected", got)
	}
}

func TestIconHostKey(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"lowercases", "https://Algorand.CO/path", "algorand.co", true},
		{"keeps www", "https://www.example.com/x", "www.example.com", true},
		{"drops port", "https://example.com:8443/x", "example.com", true},
		{"drops default port", "https://example.com:443/x", "example.com", true},
		{"http is fine", "http://example.com/", "example.com", true},
		{"ipv6 keeps brackets, as URL.hostname does", "https://[2606:4700::1111]/x", "[2606:4700::1111]", true},
		{"javascript rejected", "javascript:alert(1)", "", false},
		{"data rejected", "data:text/html,<script>", "", false},
		{"no host", "https:///path", "", false},
		{"garbage", "not a url", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := IconHostKey(tc.in)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("IconHostKey(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// The key a node writes and the key a consumer derives must be the same
// string for the same URL, and "both sides read it off the URL" is NOT enough
// on its own — Go's url.Hostname() and the browser's URL.hostname genuinely
// disagree. Every `want` below was produced by running
// `new URL(<url>).hostname` in a browser-equivalent runtime; IconHostKey has
// to reproduce it.
//
// THIS TABLE IS DUPLICATED in the reference client's
// src/chat/favicon-store.test.ts. Edit one, edit the other — there is no
// shared vector file, because the client consumes proto as a published npm
// package and cannot read proto/testdata.
func TestIconHostKey_MatchesWHATWG(t *testing.T) {
	cases := []struct{ url, want string }{
		// The plain cases both parsers already agreed on.
		{"https://Algorand.CO/path", "algorand.co"},
		{"https://www.example.com/x", "www.example.com"},
		{"https://example.com:8443/x", "example.com"},
		{"https://example.com:443/x", "example.com"},
		{"http://example.com/", "example.com"},
		{"https://example.com./x", "example.com."},
		{"https://my_host.example.com/x", "my_host.example.com"},
		// IDN: the browser applies IDNA ToASCII, so we must too.
		{"https://münchen.de/x", "xn--mnchen-3ya.de"},
		{"https://例え.jp/x", "xn--r8jz45g.jp"},
		{"https://xn--mnchen-3ya.de/x", "xn--mnchen-3ya.de"},
		// IPv6: the browser keeps the brackets AND compresses.
		{"https://[2001:db8::1]:8443/x", "[2001:db8::1]"},
		{"https://[2001:db8:0:0:0:0:0:1]/x", "[2001:db8::1]"},
		{"https://[::1]/x", "[::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			got, ok := IconHostKey(tc.url)
			if !ok {
				t.Fatalf("IconHostKey(%q) refused a URL the consumer keys as %q", tc.url, tc.want)
			}
			if got != tc.want {
				t.Fatalf("IconHostKey(%q) = %q, want %q — the node would key an icon the "+
					"consumer never looks up", tc.url, got, tc.want)
			}
		})
	}
}

func icon(mime string, raw int) *SourceIcon {
	return &SourceIcon{Mime: mime, DataB64: base64.StdEncoding.EncodeToString(make([]byte, raw))}
}

func TestAttachIcons_HappyPath(t *testing.T) {
	a := &ToolAction{Type: ActionTypeSearch, Query: "x"}
	a.AttachIcons([]string{"a.com", "b.com"}, map[string]*SourceIcon{
		"a.com": icon(IconMimePNG, 100),
		"b.com": icon(IconMimeICO, 200),
	})
	if len(a.Icons) != 2 {
		t.Fatalf("Icons = %d entries, want 2", len(a.Icons))
	}
	if a.Icons["a.com"].Mime != IconMimePNG {
		t.Fatalf("a.com mime = %q", a.Icons["a.com"].Mime)
	}
}

func TestAttachIcons_RejectsDisallowedMime(t *testing.T) {
	a := &ToolAction{Type: ActionTypeSearch, Query: "x"}
	a.AttachIcons([]string{"evil.com", "ok.com"}, map[string]*SourceIcon{
		"evil.com": icon("image/svg+xml", 100),
		"ok.com":   icon(IconMimePNG, 100),
	})
	if _, ok := a.Icons["evil.com"]; ok {
		t.Fatal("an image/svg+xml icon was attached")
	}
	if _, ok := a.Icons["ok.com"]; !ok {
		t.Fatal("the allowed icon was dropped too — the filter is not selective")
	}
}

func TestAttachIcons_SkipsEmptyPayload(t *testing.T) {
	a := &ToolAction{Type: ActionTypeSearch, Query: "x"}
	a.AttachIcons([]string{"a.com"}, map[string]*SourceIcon{
		"a.com": {Mime: IconMimePNG, DataB64: ""},
	})
	if a.Icons != nil {
		t.Fatalf("Icons = %v, want nil (an empty payload is not an icon)", a.Icons)
	}
}

func TestAttachIcons_OversizeIconDroppedNotTruncated(t *testing.T) {
	a := &ToolAction{Type: ActionTypeSearch, Query: "x"}
	big := icon(IconMimePNG, MaxIconRawBytes+1)
	a.AttachIcons([]string{"big.com", "small.com"}, map[string]*SourceIcon{
		"big.com":   big,
		"small.com": icon(IconMimePNG, 64),
	})
	if _, ok := a.Icons["big.com"]; ok {
		t.Fatal("an over-cap icon was attached")
	}
	if got, ok := a.Icons["small.com"]; !ok || got.DataB64 == "" {
		t.Fatal("the in-budget icon was dropped alongside it")
	}
	// Nothing shortened: a truncated icon is a broken image, not a small one.
	for h, ic := range a.Icons {
		if rawB64Len(ic.DataB64) > MaxIconRawBytes {
			t.Fatalf("%s survived over-cap at %d raw bytes", h, rawB64Len(ic.DataB64))
		}
	}
}

// The cap is on decoded bytes, so it must not drift with base64's 4:3
// rounding: exactly MaxIconRawBytes is admitted and one byte more is not.
func TestAttachIcons_ByteCapIsExact(t *testing.T) {
	at := func(raw int) map[string]*SourceIcon {
		return map[string]*SourceIcon{"a.com": icon(IconMimePNG, raw)}
	}
	ok := &ToolAction{Type: ActionTypeSearch}
	ok.AttachIcons([]string{"a.com"}, at(MaxIconRawBytes))
	if len(ok.Icons) != 1 {
		t.Fatalf("an icon of exactly MaxIconRawBytes was rejected")
	}
	over := &ToolAction{Type: ActionTypeSearch}
	over.AttachIcons([]string{"a.com"}, at(MaxIconRawBytes+1))
	if len(over.Icons) != 0 {
		t.Fatalf("an icon one byte over MaxIconRawBytes was admitted")
	}
}

func TestRawB64Len(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{base64.StdEncoding.EncodeToString([]byte{}), -1},       // empty
		{base64.StdEncoding.EncodeToString([]byte{1}), 1},       // "AQ=="
		{base64.StdEncoding.EncodeToString([]byte{1, 2}), 2},    // "AQI="
		{base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), 3}, // "AQID"
		{base64.StdEncoding.EncodeToString(make([]byte, 99)), 99},
		{"AQI", -1},   // not a multiple of 4
		{"AQIDA", -1}, // not a multiple of 4
	}
	for _, tc := range cases {
		if got := rawB64Len(tc.in); got != tc.want {
			t.Fatalf("rawB64Len(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestAttachIcons_HostCountCapped(t *testing.T) {
	hosts := make([]string, 0, MaxIconHosts+5)
	icons := map[string]*SourceIcon{}
	for i := 0; i < MaxIconHosts+5; i++ {
		h := string(rune('a'+i)) + ".com"
		hosts = append(hosts, h)
		icons[h] = icon(IconMimePNG, 32)
	}
	a := &ToolAction{Type: ActionTypeSearch, Query: "x"}
	a.AttachIcons(hosts, icons)
	if len(a.Icons) != MaxIconHosts {
		t.Fatalf("Icons = %d entries, want the cap of %d", len(a.Icons), MaxIconHosts)
	}
	// The cap keeps the head of the list, so what a reader sees first wins.
	if _, ok := a.Icons[hosts[0]]; !ok {
		t.Fatal("the first host was dropped — the cap is not order-preserving")
	}
}

func TestAttachIcons_TotalByteBudget(t *testing.T) {
	// Each icon must be under the PER-ICON cap so this exercises the total
	// budget and not that one. 12288 raw encodes to exactly 16384 b64 bytes,
	// so the budget binds after maxIconsTotalB64Bytes/16384 of them.
	const perRaw = 12288
	wantFit := maxIconsTotalB64Bytes / 16384
	if perRaw > MaxIconRawBytes {
		t.Fatalf("test icon of %d raw exceeds the per-icon cap; this would test the wrong thing", perRaw)
	}
	hosts := []string{}
	icons := map[string]*SourceIcon{}
	for i := 0; i < wantFit+3; i++ {
		h := string(rune('a'+i)) + ".com"
		hosts = append(hosts, h)
		icons[h] = icon(IconMimePNG, perRaw)
	}
	a := &ToolAction{Type: ActionTypeSearch, Query: "x"}
	a.AttachIcons(hosts, icons)

	total := 0
	for _, ic := range a.Icons {
		total += len(ic.DataB64)
	}
	if total > maxIconsTotalB64Bytes {
		t.Fatalf("attached %d b64 bytes, over the %d budget", total, maxIconsTotalB64Bytes)
	}
	if len(a.Icons) == len(hosts) {
		t.Fatal("every icon fit — the budget did not bind, so this test proves nothing")
	}
	if len(a.Icons) != wantFit {
		t.Fatalf("attached %d icons, want exactly %d to fit the budget", len(a.Icons), wantFit)
	}
	if len(hosts) > MaxIconHosts {
		t.Fatalf("test uses %d hosts; the host cap would bind before the budget", len(hosts))
	}
	if _, ok := a.Icons[hosts[0]]; !ok {
		t.Fatal("the first host was dropped — the budget is not order-preserving")
	}
}

func TestAttachIcons_NoIconsLeavesFieldAbsent(t *testing.T) {
	a := &ToolAction{Type: ActionTypeSearch, Query: "algorand"}
	a.AttachIcons(nil, nil)
	a.AttachIcons([]string{"a.com"}, nil)
	a.AttachIcons(nil, map[string]*SourceIcon{"a.com": icon(IconMimePNG, 10)})
	if a.Icons != nil {
		t.Fatalf("Icons = %v, want nil", a.Icons)
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "icons") {
		t.Fatalf("marshalled %s — the field must be omitted, never null", b)
	}
}

func TestAttachIcons_NilReceiverIsSafe(t *testing.T) {
	var a *ToolAction
	a.AttachIcons([]string{"a.com"}, map[string]*SourceIcon{"a.com": icon(IconMimePNG, 10)})
}

// The byte budget is first-fit and the host-count cap is a prefix. Both
// behaviours are deliberate and neither was pinned before: swapping either
// `continue`/`break` left the suite green.
func TestAttachIcons_ByteBudgetIsFirstFitNotPrefix(t *testing.T) {
	// Fill most of the budget, then offer one icon too large for the gap
	// followed by one small enough to fit it.
	hosts := []string{}
	icons := map[string]*SourceIcon{}
	for i := 0; i < 4; i++ {
		h := "fill" + string(rune('a'+i)) + ".example"
		hosts = append(hosts, h)
		icons[h] = icon(IconMimePNG, MaxIconRawBytes)
	}
	hosts = append(hosts, "big.example", "small.example")
	icons["big.example"] = icon(IconMimePNG, MaxIconRawBytes)
	icons["small.example"] = icon(IconMimePNG, 128)

	a := &ToolAction{Type: ActionTypeSearch}
	a.AttachIcons(hosts, icons)

	if _, ok := a.Icons["big.example"]; ok {
		t.Fatal("setup failed: the large icon fit, so the budget never bound and this proves nothing")
	}
	if _, ok := a.Icons["small.example"]; !ok {
		t.Fatal("a small icon AFTER an over-budget one was dropped — the budget is behaving " +
			"as a prefix, so one large icon near the head blanks every chip behind it")
	}
}

func TestAttachIcons_HostCapIsAPrefix(t *testing.T) {
	hosts := []string{}
	icons := map[string]*SourceIcon{}
	for i := 0; i < MaxIconHosts+3; i++ {
		h := "h" + string(rune('a'+i)) + ".example"
		hosts = append(hosts, h)
		icons[h] = icon(IconMimePNG, 64)
	}
	a := &ToolAction{Type: ActionTypeSearch}
	a.AttachIcons(hosts, icons)
	for i, h := range hosts {
		_, ok := a.Icons[h]
		if i < MaxIconHosts && !ok {
			t.Fatalf("%s (position %d) missing — the host cap is not a prefix", h, i)
		}
		if i >= MaxIconHosts && ok {
			t.Fatalf("%s (position %d) present — past the host cap", h, i)
		}
	}
}
