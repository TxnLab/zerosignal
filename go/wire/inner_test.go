/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
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
