/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
)

// Cross-implementation vectors for CollateralFreshEnough and the two readers
// under it, written to proto/testdata/collateral_vectors.json and replayed by
// proto/ts/test/collateral-vectors.test.ts.
//
// Regenerate: cd proto/go && go test ./attest -run TestCollateralVectors -update
//
// The readers are pinned on their own as well as through the floor, because
// the floor only says yes or no: a TypeScript reader that dated a CRL Go
// refuses would agree with every fresh/stale case here and still accept a set
// Go falls back from. So each refusal Go makes in crlThisUpdate and issuedAt
// has a case.
//
// The CRLs are assembled by hand rather than by x509.CreateRevocationList,
// which writes only canonical encodings; the point of most cases is a
// non-canonical one. Every CRL is unsigned (a zero signature), which
// ParseRevocationList does not check and the freshness floor never asks about.
//
// Cases where the TypeScript reader is known to differ are left out; its file
// header names them (a malformed algorithm identifier, issuer name, or
// anything after thisUpdate, all of which Go refuses).

const collateralVectorsPath = "../../testdata/collateral_vectors.json"

type collateralTime struct {
	UnixSec int64 `json:"unix_sec"`
	Nanos   int   `json:"nanos"`
}

func collTime(t time.Time, ok bool) *collateralTime {
	if !ok {
		return nil
	}
	return &collateralTime{UnixSec: t.Unix(), Nanos: t.Nanosecond()}
}

type crlVector struct {
	Name   string          `json:"name"`
	CRLHex string          `json:"crl_hex"`
	Time   *collateralTime `json:"time"` // null when Go refuses to date it
	// Null when Go refuses to date the CRL or it carries no nextUpdate.
	NextUpdate *collateralTime `json:"next_update"`
}

type issuedAtVector struct {
	Name    string          `json:"name"`
	Doc     string          `json:"doc"`
	Wrapper string          `json:"wrapper"`
	Time    *collateralTime `json:"time"`
}

type freshVector struct {
	Name       string                `json:"name"`
	Collateral *inject.TEECollateral `json:"collateral"`
	NowUnixMs  int64                 `json:"now_unix_ms"`
	MaxAgeMs   int64                 `json:"max_age_ms"`
	Fresh      bool                  `json:"fresh"`
}

type collateralVectorsFile struct {
	Version          int              `json:"version"`
	Comment          string           `json:"comment"`
	EmbeddedMaxAgeMs int64            `json:"embedded_collateral_max_age_ms"`
	MinRootCACRLMs   int64            `json:"min_root_ca_crl_this_update_unix_ms"`
	CRLThisUpdate    []crlVector      `json:"crl_this_update"`
	IssuedAt         []issuedAtVector `json:"issued_at"`
	CollateralFresh  []freshVector    `json:"collateral_fresh"`
}

// tlv encodes one DER element with a minimal length.
func tlv(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	n := len(body)
	var head []byte
	switch {
	case n < 0x80:
		head = []byte{tag, byte(n)}
	case n < 0x100:
		head = []byte{tag, 0x81, byte(n)}
	default:
		head = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	return append(head, body...)
}

var (
	crlAlg    = tlv(0x30, tlv(0x06, []byte{0x2b, 0x65, 0x70})) // id-Ed25519
	crlIssuer = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, []byte{0x55, 0x04, 0x03}), tlv(0x0c, []byte("Test CRL CA")))))
	crlNext   = tlv(0x17, []byte("491231235959Z"))
	crlSig    = tlv(0x03, append([]byte{0}, make([]byte, 64)...))
	crlV2     = tlv(0x02, []byte{0x01})
)

type crlParts struct {
	version, tbsAlg, issuer, thisUpdate, nextUpdate, outerAlg, sig []byte
}

func defaultCRLParts(thisUpdate []byte) crlParts {
	return crlParts{version: crlV2, tbsAlg: crlAlg, issuer: crlIssuer, thisUpdate: thisUpdate,
		nextUpdate: crlNext, outerAlg: crlAlg, sig: crlSig}
}

func (p crlParts) der() []byte {
	tbs := tlv(0x30, p.version, p.tbsAlg, p.issuer, p.thisUpdate, p.nextUpdate)
	return tlv(0x30, tbs, p.outerAlg, p.sig)
}

func utcCRL(s string) string { return hex.EncodeToString(defaultCRLParts(tlv(0x17, []byte(s))).der()) }
func genCRL(s string) string { return hex.EncodeToString(defaultCRLParts(tlv(0x18, []byte(s))).der()) }

func genTime(t time.Time) []byte {
	if t.Nanosecond() != 0 {
		panic("a CRL cannot carry " + t.String())
	}
	return tlv(0x18, []byte(t.UTC().Format("20060102150405Z0700")))
}

// crlAt is a CRL whose thisUpdate is t. A CRL time has whole seconds only, so
// the sub-second boundary cases below move a JSON document instead.
func crlAt(t time.Time) string {
	return hex.EncodeToString(defaultCRLParts(genTime(t)).der())
}

// crlWindowAt is a CRL valid from this to next; a nil next omits nextUpdate.
func crlWindowAt(this time.Time, next *time.Time) string {
	p := defaultCRLParts(genTime(this))
	p.nextUpdate = nil
	if next != nil {
		p.nextUpdate = genTime(*next)
	}
	return hex.EncodeToString(p.der())
}

func docAt(t time.Time) string {
	return `{"version":3,"issueDate":"` + t.UTC().Format(time.RFC3339Nano) + `","id":"TDX"}`
}

func buildCRLVectors() []crlVector {
	partsHex := func(f func(*crlParts)) string {
		p := defaultCRLParts(tlv(0x17, []byte("261009123456Z")))
		f(&p)
		return hex.EncodeToString(p.der())
	}
	base := utcCRL("261009123456Z")

	// A long-form length octet where the short form fits.
	nonMinimal := func() string {
		p := defaultCRLParts(tlv(0x17, []byte("261009123456Z")))
		issuer := append([]byte{0x30, 0x81}, p.issuer[1:]...)
		p.issuer = issuer
		return hex.EncodeToString(p.der())
	}()

	// An issuer whose content (132 bytes) needs the long form, with the
	// length header supplied by the case: minimal is 30 81 84.
	longCN := tlv(0x31, tlv(0x30, tlv(0x06, []byte{0x55, 0x04, 0x03}), tlv(0x0c, bytes.Repeat([]byte("A"), 120))))
	longIssuer := func(header ...byte) string {
		return partsHex(func(p *crlParts) { p.issuer = append(append([]byte{}, header...), longCN...) })
	}

	cases := []struct{ name, hex string }{
		{"utc_canonical", base},
		{"utc_uppercase_hex", strings.ToUpper(base)},
		{"utc_surrounding_go_space", string(rune(0x85)) + "\t " + base + "\n" + string(rune(0x3000))},
		{"utc_leading_bom", string(rune(0xfeff)) + base},
		{"utc_minutes_only", utcCRL("2610091234Z")},
		{"utc_offset", utcCRL("261009123456+0130")},
		{"utc_offset_minutes_only", utcCRL("2610091234-0700")},
		{"utc_offset_24h", utcCRL("261009123456+2400")},
		{"utc_offset_24h59m", utcCRL("261009123456+2459")},
		{"utc_offset_25h", utcCRL("261009123456+2500")},
		{"utc_offset_60m", utcCRL("261009123456+0060")},
		{"utc_offset_plus_zero", utcCRL("261009123456+0000")},
		{"utc_offset_minus_zero", utcCRL("261009123456-0000")},
		{"utc_lowercase_z", utcCRL("261009123456z")},
		{"utc_no_zone", utcCRL("261009123456")},
		{"utc_fraction", utcCRL("261009123456.5Z")},
		{"utc_year_49", utcCRL("491231235959Z")},
		{"utc_year_50", utcCRL("500101000000Z")},
		{"utc_year_00_leap", utcCRL("000229000000Z")},
		{"utc_feb_29_leap", utcCRL("240229000000Z")},
		{"utc_feb_29_common", utcCRL("250229000000Z")},
		{"utc_hour_24", utcCRL("261009240000Z")},
		{"utc_second_60", utcCRL("261009123460Z")},
		{"utc_month_13", utcCRL("261309123456Z")},
		{"utc_day_0", utcCRL("261000123456Z")},
		{"utc_short", utcCRL("2610091Z")},
		{"gen_canonical", genCRL("20261009123456Z")},
		{"gen_fraction", genCRL("20261009123456.5Z")},
		{"gen_fraction_nine", genCRL("20261009123456.123456789Z")},
		{"gen_fraction_trailing_zero", genCRL("20261009123456.50Z")},
		{"gen_fraction_ten", genCRL("20261009123456.1234567891Z")},
		{"gen_fraction_comma", genCRL("20261009123456,5Z")},
		{"gen_fraction_empty", genCRL("20261009123456.Z")},
		{"gen_fraction_zero", genCRL("20261009123456.0Z")},
		{"gen_offset", genCRL("20261009123456-0130")},
		{"gen_minutes_only", genCRL("202610091234Z")},
		{"gen_year_0", genCRL("00000101000000Z")},
		{"gen_go_zero_time", genCRL("00010101000000Z")},
		{"gen_go_zero_instant_offset", genCRL("00010101013000+0130")},
		{"gen_year_9999", genCRL("99991231235959Z")},
		{"this_update_integer", hex.EncodeToString(defaultCRLParts(tlv(0x02, []byte{1})).der())},
		{"version_0", partsHex(func(p *crlParts) { p.version = tlv(0x02, []byte{0x00}) })},
		{"version_2", partsHex(func(p *crlParts) { p.version = tlv(0x02, []byte{0x02}) })},
		{"version_non_minimal", partsHex(func(p *crlParts) { p.version = tlv(0x02, []byte{0x00, 0x01}) })},
		{"version_absent", partsHex(func(p *crlParts) { p.version = nil })},
		{"outer_alg_differs", partsHex(func(p *crlParts) {
			p.outerAlg = tlv(0x30, tlv(0x06, []byte{0x2b, 0x65, 0x71})) // id-Ed448
		})},
		{"sig_padding_8", partsHex(func(p *crlParts) { p.sig = tlv(0x03, []byte{8, 0}) })},
		{"sig_padding_bits_set", partsHex(func(p *crlParts) { p.sig = tlv(0x03, []byte{1, 0x01}) })},
		{"sig_padding_bits_clear", partsHex(func(p *crlParts) { p.sig = tlv(0x03, []byte{1, 0x02}) })},
		{"sig_empty", partsHex(func(p *crlParts) { p.sig = tlv(0x03) })},
		{"sig_only_padding", partsHex(func(p *crlParts) { p.sig = tlv(0x03, []byte{1}) })},
		{"sig_absent", partsHex(func(p *crlParts) { p.sig = nil })},
		{"sig_wrong_tag", partsHex(func(p *crlParts) { p.sig = tlv(0x04, []byte{0, 0}) })},
		{"next_update_absent", partsHex(func(p *crlParts) { p.nextUpdate = nil })},
		{"next_update_absent_revoked_list_follows", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x30) })},
		{"next_update_utc", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x17, []byte("270226130400Z")) })},
		{"next_update_utc_offset", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x17, []byte("270226130400+0130")) })},
		{"next_update_generalized", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x18, []byte("20270226130400Z")) })},
		{"next_update_go_zero_time", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x18, []byte("00010101000000Z")) })},
		{"next_update_malformed", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x17, []byte("2702261Z")) })},
		{"next_update_generalized_fraction", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0x18, []byte("20270226130400.5Z")) })},
		{"next_update_overlong", partsHex(func(p *crlParts) { p.nextUpdate = []byte{0x17, 0x05, '2'} })},
		{"next_update_absent_extensions_follow", partsHex(func(p *crlParts) { p.nextUpdate = tlv(0xa0, tlv(0x30)) })},
		{"issuer_non_minimal_length", nonMinimal},
		{"issuer_long_form", longIssuer(0x30, 0x81, 0x84)},
		{"issuer_long_form_leading_zero", longIssuer(0x30, 0x82, 0x00, 0x84)},
		{"issuer_indefinite_length", longIssuer(0x30, 0x80)},
		{"issuer_five_length_octets", longIssuer(0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x84)},
		// Pins the outcome only: every element read here is also checked
		// against an expected tag, which a high-tag form never equals.
		{"high_tag_number", partsHex(func(p *crlParts) { p.issuer = []byte{0x3f, 0x01, 0x00} })},
		{"trailing_data", base + "0000"},
		{"truncated", base[:len(base)-4]},
		{"odd_length", base[:len(base)-1]},
		{"not_hex", "zz" + base[2:]},
		{"empty", ""},
		{"whitespace_only", " \t\n"},
		{"not_a_sequence", "0400"},
	}
	out := make([]crlVector, 0, len(cases))
	for _, c := range cases {
		this, next, ok := crlWindow(c.hex)
		out = append(out, crlVector{Name: c.name, CRLHex: c.hex, Time: collTime(this, ok),
			NextUpdate: collTime(next, ok && !next.IsZero())})
	}
	return out
}

func buildIssuedAtVectors() []issuedAtVector {
	cases := []struct{ name, doc, wrapper string }{
		{"bare", `{"version":3,"issueDate":"2026-10-09T12:34:56Z","id":"TDX"}`, "tcbInfo"},
		{"bare_fraction_offset", `{"issueDate":"2026-10-09T12:34:56.123456789+02:00"}`, "tcbInfo"},
		{"bare_go_fallback_form", `{"issueDate":"2026-10-09T1:34:56,5Z"}`, "enclaveIdentity"},
		// JSON's escape for the leading "2", split so no tool decodes it here.
		{"escaped_digits", `{"issueDate":"\` + `u0032026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"surrounding_whitespace", " \n{\"issueDate\":\"2026-10-09T12:34:56Z\"}\t", "tcbInfo"},
		{"duplicate_key_last_wins", `{"issueDate":"2026-01-01T00:00:00Z","issueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"wrapped", `{"tcbInfo":{"issueDate":"2026-10-09T12:34:56Z"}}`, "tcbInfo"},
		{"wrapped_qe", `{"enclaveIdentity":{"issueDate":"2026-10-09T12:34:56Z"}}`, "enclaveIdentity"},
		{"wrapper_beside_issue_date", `{"tcbInfo":{},"issueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"other_wrapper_beside_issue_date", `{"enclaveIdentity":{},"issueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"wrapper_null", `{"tcbInfo":null,"issueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"case_variant_key", `{"IssueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"issue_date_number", `{"issueDate":1791549296}`, "tcbInfo"},
		{"issue_date_null", `{"issueDate":null}`, "tcbInfo"},
		{"issue_date_missing", `{"nextUpdate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"issue_date_date_only", `{"issueDate":"2026-10-09"}`, "tcbInfo"},
		{"issue_date_prose", `{"issueDate":"Oct 9 2026"}`, "tcbInfo"},
		{"issue_date_lowercase", `{"issueDate":"2026-10-09t12:34:56z"}`, "tcbInfo"},
		{"not_json", `{"issueDate":`, "tcbInfo"},
		{"array", `[{"issueDate":"2026-10-09T12:34:56Z"}]`, "tcbInfo"},
		{"null", `null`, "tcbInfo"},
		{"string", `"2026-10-09T12:34:56Z"`, "tcbInfo"},
		{"empty", ``, "tcbInfo"},
		{"depth_10000", `{"x":` + strings.Repeat("[", 9999) + strings.Repeat("]", 9999) +
			`,"issueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
		{"depth_10001", `{"x":` + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) +
			`,"issueDate":"2026-10-09T12:34:56Z"}`, "tcbInfo"},
	}
	out := make([]issuedAtVector, 0, len(cases))
	for _, c := range cases {
		t, ok := issuedAt(c.doc, c.wrapper)
		out = append(out, issuedAtVector{Name: c.name, Doc: c.doc, Wrapper: c.wrapper, Time: collTime(t, ok)})
	}
	return out
}

func buildFreshVectors() []freshVector {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	maxAge := EmbeddedCollateralMaxAge

	// set builds a complete collateral set whose four documents are dated
	// tcb, qe, pck and root.
	set := func(tcb, qe, pck, root time.Time) *inject.TEECollateral {
		return &inject.TEECollateral{
			PCKCRLIssuerChain:     "chain",
			RootCACRL:             crlAt(root),
			PCKCRL:                crlAt(pck),
			TCBInfoIssuerChain:    "chain",
			TCBInfo:               docAt(tcb),
			TCBInfoSignature:      "00",
			QEIdentityIssuerChain: "chain",
			QEIdentity:            docAt(qe),
			QEIdentitySignature:   "00",
		}
	}
	all := func(t time.Time) *inject.TEECollateral { return set(t, t, t, t) }
	edge := now.Add(-maxAge)

	type c struct {
		name   string
		coll   *inject.TEECollateral
		maxAge time.Duration
	}
	cases := []c{
		{"all_now", all(now), maxAge},
		{"all_an_hour_old", all(now.Add(-time.Hour)), maxAge},
		{"all_at_the_floor", all(edge), maxAge},
		{"all_a_second_past_the_floor", all(edge.Add(-time.Second)), maxAge},
		{"tcb_info_a_nanosecond_past_the_floor", set(edge.Add(-time.Nanosecond), now, now, now), maxAge},
		{"qe_identity_a_nanosecond_past_the_floor", set(now, edge.Add(-time.Nanosecond), now, now), maxAge},
		{"pck_crl_a_second_past_the_floor", set(now, now, edge.Add(-time.Second), now), maxAge},
		{"tcb_info_a_nanosecond_ahead", set(now.Add(time.Nanosecond), now, now, now), maxAge},
		{"qe_identity_a_nanosecond_ahead", set(now, now.Add(time.Nanosecond), now, now), maxAge},
		{"pck_crl_a_second_ahead", set(now, now, now.Add(time.Second), now), maxAge},
		{"root_ca_crl_a_second_ahead", set(now, now, now, now.Add(time.Second)), maxAge},
		{"tcb_info_a_year_ahead", set(now.AddDate(1, 0, 0), now, now, now), maxAge},
		{"zero_max_age_at_now", all(now), 0},
		{"zero_max_age_a_nanosecond_old", set(now.Add(-time.Nanosecond), now, now, now), 0},
		{"absent", nil, maxAge},
	}
	for _, name := range []string{"pck_crl_issuer_chain", "tcb_info_signature", "root_ca_crl", "qe_identity"} {
		coll := all(now)
		switch name {
		case "pck_crl_issuer_chain":
			coll.PCKCRLIssuerChain = ""
		case "tcb_info_signature":
			coll.TCBInfoSignature = ""
		case "root_ca_crl":
			coll.RootCACRL = ""
		case "qe_identity":
			coll.QEIdentity = ""
		}
		cases = append(cases, c{"missing_" + name, coll, maxAge})
	}
	wrapped := all(now)
	wrapped.TCBInfo = `{"tcbInfo":` + docAt(now) + `}`
	cases = append(cases, c{"tcb_info_wrapped", wrapped, maxAge})
	undated := all(now)
	undated.PCKCRL = "00"
	cases = append(cases, c{"pck_crl_undatable", undated, maxAge})

	// The root CA CRL is judged by its own window and the pinned minimum,
	// not by maxAge.
	day := 24 * time.Hour
	pin := MinRootCACRLThisUpdate()
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	yearAfterPin := pin.AddDate(1, 0, 0)
	for _, w := range []struct {
		name  string
		this  time.Time
		next  *time.Time
		limit time.Duration
	}{
		{"root_ca_crl_at_the_pinned_minimum", pin, &yearAfterPin, maxAge},
		{"root_ca_crl_a_second_before_the_pinned_minimum", pin.Add(-time.Second), &yearAfterPin, maxAge},
		{"root_ca_crl_a_second_past_the_floor", edge.Add(-time.Second), at(day), maxAge},
		{"root_ca_crl_at_its_next_update", pin, at(0), maxAge},
		{"root_ca_crl_a_second_past_its_next_update", pin, at(-time.Second), maxAge},
		{"root_ca_crl_next_update_before_this_update", now.Add(-time.Hour), at(-2 * time.Hour), maxAge},
		{"root_ca_crl_no_next_update", now.Add(-time.Hour), nil, maxAge},
		{"root_ca_crl_at_the_pinned_minimum_with_zero_max_age", pin, &yearAfterPin, 0},
	} {
		coll := all(now)
		coll.RootCACRL = crlWindowAt(w.this, w.next)
		cases = append(cases, c{w.name, coll, w.limit})
	}

	out := make([]freshVector, 0, len(cases))
	for _, tc := range cases {
		out = append(out, freshVector{
			Name:       tc.name,
			Collateral: tc.coll,
			NowUnixMs:  now.UnixMilli(),
			MaxAgeMs:   tc.maxAge.Milliseconds(),
			Fresh:      CollateralFreshEnough(tc.coll, now, tc.maxAge),
		})
	}
	return out
}

func TestCollateralVectors(t *testing.T) {
	f := collateralVectorsFile{
		Version: 1,
		Comment: "Generated by proto/go/attest/collateral_vectors_test.go. Do not hand-edit; " +
			"regenerate with `cd proto/go && go test ./attest -run TestCollateralVectors -update`.",
		EmbeddedMaxAgeMs: EmbeddedCollateralMaxAge.Milliseconds(),
		MinRootCACRLMs:   MinRootCACRLThisUpdate().UnixMilli(),
		CRLThisUpdate:    buildCRLVectors(),
		IssuedAt:         buildIssuedAtVectors(),
		CollateralFresh:  buildFreshVectors(),
	}

	// The cases are only worth replaying if they reach both outcomes the names
	// claim; a builder bug that made every CRL unparseable would otherwise pin
	// a file of refusals.
	want := map[string]bool{
		"utc_canonical": true, "utc_offset_24h": true, "gen_canonical": true,
		"utc_offset_plus_zero": false, "gen_fraction": false, "version_0": false,
		"issuer_long_form": true, "issuer_long_form_leading_zero": false,
		"next_update_absent": true, "next_update_malformed": false, "next_update_overlong": false,
	}
	for _, v := range f.CRLThisUpdate {
		if ok, listed := want[v.Name]; listed && (v.Time != nil) != ok {
			t.Fatalf("crl %s: dated = %v, want %v", v.Name, v.Time != nil, ok)
		}
	}
	hasNext := map[string]bool{
		"utc_canonical": true, "next_update_absent": false, "next_update_absent_revoked_list_follows": false,
		"next_update_utc_offset": true, "next_update_go_zero_time": false, "next_update_absent_extensions_follow": false,
	}
	for _, v := range f.CRLThisUpdate {
		if ok, listed := hasNext[v.Name]; listed && (v.NextUpdate != nil) != ok {
			t.Fatalf("crl %s: has nextUpdate = %v, want %v", v.Name, v.NextUpdate != nil, ok)
		}
	}
	fresh := map[string]bool{
		"all_at_the_floor": true, "tcb_info_a_nanosecond_past_the_floor": false, "pck_crl_a_second_ahead": false,
		"root_ca_crl_at_the_pinned_minimum": true, "root_ca_crl_a_second_before_the_pinned_minimum": false,
		"root_ca_crl_at_its_next_update": true, "root_ca_crl_a_second_past_its_next_update": false,
		"root_ca_crl_no_next_update": false,
		"root_ca_crl_a_second_ahead": false, "root_ca_crl_a_second_past_the_floor": true,
	}
	for _, v := range f.CollateralFresh {
		if ok, listed := fresh[v.Name]; listed && v.Fresh != ok {
			t.Fatalf("fresh %s = %v, want %v", v.Name, v.Fresh, ok)
		}
	}

	got, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(collateralVectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", collateralVectorsPath, err)
		}
		return
	}
	prev, err := os.ReadFile(collateralVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", collateralVectorsPath, err)
	}
	if !bytes.Equal(got, prev) {
		t.Fatalf("%s is stale; regenerate with:\n  cd proto/go && go test ./attest -run TestCollateralVectors -update",
			collateralVectorsPath)
	}
}
