/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestInnerRequest_RoundTrip(t *testing.T) {
	header := innerRequestHeader{
		ReplyToPublicKey: "age1qqq",
		AlgorandTxID:     "TXABC",
		TicketID:         "dGlja2V0",
		AdmissionTag:     "dGFn",
	}
	body := []byte(`{"model":"gpt-4","messages":[]}`)

	frame, err := encodeInnerRequest(header, body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	gotHeader, gotBody, err := decodeInnerRequest(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotHeader != header {
		t.Errorf("header = %+v, want %+v", gotHeader, header)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
}

// The node reads the tx id and open group under either set of names, and
// refuses a header that names one of them twice with different values: the
// admission tag binds the tx id, so admitting on the other would check a
// payment the tag never named.
func TestPaymentFields(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h         innerRequestHeader
		ref, open string
		ok        bool
	}{
		{"legacy", innerRequestHeader{AlgorandTxID: "TX", OpenGroup: "G"}, "TX", "G", true},
		{"neutral", innerRequestHeader{PaymentRef: "TX", PaymentOpen: "G"}, "TX", "G", true},
		{"both agreeing", innerRequestHeader{AlgorandTxID: "TX", PaymentRef: "TX", OpenGroup: "G", PaymentOpen: "G"}, "TX", "G", true},
		{"mixed", innerRequestHeader{PaymentRef: "TX", OpenGroup: "G"}, "TX", "G", true},
		{"refs disagree", innerRequestHeader{AlgorandTxID: "TX", PaymentRef: "OTHER"}, "", "", false},
		{"opens disagree", innerRequestHeader{AlgorandTxID: "TX", OpenGroup: "G", PaymentOpen: "H"}, "", "", false},
		{"neither", innerRequestHeader{}, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, open, err := tc.h.paymentFields()
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if ref != tc.ref || open != tc.open {
				t.Fatalf("(ref, open) = (%q, %q), want (%q, %q)", ref, open, tc.ref, tc.open)
			}
		})
	}
}

// The refusal must hold at the node's entry point, not only in the helper: a
// DecryptRequest that dropped paymentFields' error would take one of two
// values from a header that names both.
func TestDecryptRequest_RefusesDisagreeingNames(t *testing.T) {
	node, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]innerRequestHeader{
		"refs":  {AlgorandTxID: "TX", PaymentRef: "OTHER"},
		"opens": {AlgorandTxID: "TX", OpenGroup: "G", PaymentOpen: "H"},
	} {
		t.Run(name, func(t *testing.T) {
			h.ReplyToPublicKey = node.Recipient().String()
			inner, err := encodeInnerRequest(h, []byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			ct, err := ageSeal(inner, node.Recipient())
			if err != nil {
				t.Fatal(err)
			}
			env, err := json.Marshal(RequestEnvelope{Ciphertext: base64.StdEncoding.EncodeToString(ct)})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := DecryptRequest(env, node); err == nil || !strings.Contains(err.Error(), "disagree") {
				t.Fatalf("DecryptRequest = %+v, %v; want a disagreement refusal", got, err)
			}
		})
	}
}

// RequestBinding.NeutralNames picks which names reach the node, and only
// those: an older node reads an absent algorand_tx_id as "" and admits nothing.
func TestWrapRequestBound_WritesTheChosenNames(t *testing.T) {
	node, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, neutral := range []bool{false, true} {
		env, err := WrapRequestBound([]byte("{}"), RequestBinding{TxID: "TX", TicketID: "T", OpenGroup: "G", NeutralNames: neutral}, reply, node.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		var outer RequestEnvelope
		if err := json.Unmarshal(env, &outer); err != nil {
			t.Fatal(err)
		}
		ct, err := base64.StdEncoding.DecodeString(outer.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := ageOpen(ct, node)
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := decodeInnerRequest(inner)
		if err != nil {
			t.Fatal(err)
		}
		want := innerRequestHeader{ReplyToPublicKey: reply.Recipient().String(), TicketID: "T", AlgorandTxID: "TX", OpenGroup: "G"}
		if neutral {
			want.AlgorandTxID, want.OpenGroup, want.PaymentRef, want.PaymentOpen = "", "", "TX", "G"
		}
		if h != want {
			t.Fatalf("neutral=%v: header %+v, want %+v", neutral, h, want)
		}
		got, err := DecryptRequest(env, node)
		if err != nil {
			t.Fatal(err)
		}
		if got.AlgorandTxID != "TX" || got.OpenGroup != "G" || got.NeutralNames != neutral {
			t.Fatalf("neutral=%v: decrypted %q %q %v", neutral, got.AlgorandTxID, got.OpenGroup, got.NeutralNames)
		}
	}

	// A payer-submitted open carries no group, so payment_ref alone must
	// still read as the neutral names.
	env, err := WrapRequestBound([]byte("{}"), RequestBinding{TxID: "TX", TicketID: "T", NeutralNames: true}, reply, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptRequest(env, node); err != nil || !got.NeutralNames || got.AlgorandTxID != "TX" {
		t.Fatalf("payment_ref alone: %+v, %v", got, err)
	}
}

// The admission tag and the receipt's body_hash both commit to sha256(body),
// so the framing must return the body's exact bytes — including whitespace a
// JSON re-marshal would drop.
func TestInnerRequest_BodyBytesPreservedExactly(t *testing.T) {
	body := []byte("{\n  \"model\" : \"gpt-4\",\n  \"n\":\t1\n}\n")
	frame, err := encodeInnerRequest(innerRequestHeader{ReplyToPublicKey: "age1"}, body)
	if err != nil {
		t.Fatal(err)
	}
	_, gotBody, err := decodeInnerRequest(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body not byte-preserved:\n got %q\nwant %q", gotBody, body)
	}
}

func TestInnerRequest_EmptyBody(t *testing.T) {
	frame, err := encodeInnerRequest(innerRequestHeader{ReplyToPublicKey: "age1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := decodeInnerRequest(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want empty", body)
	}
}

func TestDecodeInnerRequest_Malformed(t *testing.T) {
	good, err := encodeInnerRequest(innerRequestHeader{ReplyToPublicKey: "age1"}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}

	truncatedHeader := bytes.Clone(good)
	binary.BigEndian.PutUint32(truncatedHeader[5:innerPrefixLen], uint32(len(good)))

	oversizedHeader := bytes.Clone(good)
	binary.BigEndian.PutUint32(oversizedHeader[5:innerPrefixLen], innerHeaderMaxLen+1)

	badMagic := bytes.Clone(good)
	badMagic[0] = 'x'

	badVersion := bytes.Clone(good)
	badVersion[4] = innerRequestVersion + 1

	badJSON := bytes.Clone(good)
	badJSON[innerPrefixLen] = '['

	for _, tc := range []struct {
		name  string
		frame []byte
		want  string
	}{
		{"truncated", good[:innerPrefixLen-1], "truncated"},
		{"bad magic", badMagic, "bad magic"},
		{"bad version", badVersion, "version"},
		{"header past end", truncatedHeader, "past end"},
		{"header too large", oversizedHeader, "exceeds max"},
		{"bad header json", badJSON, "parse inner request header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decodeInnerRequest(tc.frame)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// The proxy (Go) and the client (TS) both ENCODE inner-request frames; only the
// node (Go) decodes them. Nothing else in the test suite crosses that seam, so
// these fixtures are real bytes emitted by proto/ts's encodeInnerRequest,
// captured once and pinned here. Regenerate by encoding the same inputs in TS
// and hex-dumping the result.
//
// The multibyte case is the one that matters: a TS implementation that measured
// headerLen in UTF-16 code units rather than bytes would produce a frame Go
// truncates mid-header, and every non-ASCII age recipient would break.
func TestGoDecodesTypeScriptEncodedFrames(t *testing.T) {
	for _, tc := range []struct {
		name       string
		frameHex   string
		wantHeader innerRequestHeader
		wantBody   string
	}{
		{
			name:     "all fields",
			frameHex: "7a73727101000000617b227265706c795f746f5f7075626c69635f6b6579223a226167653178797a222c22616c676f72616e645f74785f6964223a225458222c227469636b65745f6964223a2264477430222c2261646d697373696f6e5f746167223a226447466e227d7b226d6f64656c223a226d227d",
			wantHeader: innerRequestHeader{
				ReplyToPublicKey: "age1xyz", AlgorandTxID: "TX", TicketID: "dGt0", AdmissionTag: "dGFn",
			},
			wantBody: `{"model":"m"}`,
		},
		{
			name:       "multibyte header and body, optional fields omitted",
			frameHex:   "7a73727101000000397b227265706c795f746f5f7075626c69635f6b6579223a2261676531c3a9e29883222c22616c676f72616e645f74785f6964223a225458227dc3bc6e69636f646520e2988320626f6479",
			wantHeader: innerRequestHeader{ReplyToPublicKey: "age1é☃", AlgorandTxID: "TX"},
			wantBody:   "ünicode ☃ body",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := hex.DecodeString(tc.frameHex)
			if err != nil {
				t.Fatal(err)
			}
			gotHeader, gotBody, err := decodeInnerRequest(frame)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotHeader != tc.wantHeader {
				t.Errorf("header = %+v, want %+v", gotHeader, tc.wantHeader)
			}
			if string(gotBody) != tc.wantBody {
				t.Errorf("body = %q, want %q", gotBody, tc.wantBody)
			}
		})
	}
}
