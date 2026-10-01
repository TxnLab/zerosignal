/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
)

func encB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestListApplicationBoxes_PaginatesAndDecodesValues(t *testing.T) {
	var prefixes, includes, nexts, limits, maxes []string
	page := 0
	c, srv := newFakeAlgod(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		prefixes = append(prefixes, q.Get("prefix"))
		includes = append(includes, q.Get("include"))
		nexts = append(nexts, q.Get("next"))
		limits = append(limits, q.Get("limit"))
		maxes = append(maxes, q.Get("max"))
		w.Header().Set("Content-Type", "application/json")
		if page == 0 {
			page++
			_, _ = w.Write([]byte(`{"boxes":[{"name":"` + encB64("o:box1") + `","value":"` + encB64("val1") + `"}],"next-token":"TOK"}`))
			return
		}
		_, _ = w.Write([]byte(`{"boxes":[{"name":"` + encB64("o:box2") + `","value":"` + encB64("val2") + `"}]}`))
	})
	defer srv.Close()

	boxes, err := c.(BoxLister).ListApplicationBoxes(context.Background(), 123, []byte("o:"))
	if err != nil {
		t.Fatalf("ListApplicationBoxes: %v", err)
	}
	if len(boxes) != 2 {
		t.Fatalf("got %d boxes across pages, want 2", len(boxes))
	}
	if string(boxes[0].Name) != "o:box1" || string(boxes[0].Value) != "val1" {
		t.Fatalf("box[0] = %q/%q", boxes[0].Name, boxes[0].Value)
	}
	if string(boxes[1].Name) != "o:box2" || string(boxes[1].Value) != "val2" {
		t.Fatalf("box[1] = %q/%q", boxes[1].Name, boxes[1].Value)
	}

	// Query params: prefix is b64-encoded, include=values, and the second page
	// carries the first page's next-token.
	if want := "b64:" + base64.StdEncoding.EncodeToString([]byte("o:")); prefixes[0] != want {
		t.Fatalf("prefix param = %q, want %q", prefixes[0], want)
	}
	if includes[0] != "values" {
		t.Fatalf("include param = %q, want values", includes[0])
	}
	if nexts[0] != "" || nexts[1] != "TOK" {
		t.Fatalf("next params = %q, %q; want \"\", \"TOK\"", nexts[0], nexts[1])
	}
	// Page size rides `limit`, never `max`. They are different params: `max` is
	// algod's legacy all-in-one cap, checked against the app's TOTAL box count
	// before any prefix filter, and it fails the call rather than paginating.
	// This runs on the live operator/node discovery path, so pin it.
	for i, got := range limits {
		if got != "1000" {
			t.Fatalf("page %d: limit param = %q, want 1000", i, got)
		}
	}
	for i, got := range maxes {
		if got != "" {
			t.Fatalf("page %d: max param = %q, want it unset (see boxListPageLimit)", i, got)
		}
	}
}

func TestListApplicationBoxes_ValuesUnsupported(t *testing.T) {
	c, srv := newFakeAlgod(t, func(w http.ResponseWriter, _ *http.Request) {
		// A name with no value = the node ignored include=values.
		_, _ = w.Write([]byte(`{"boxes":[{"name":"` + encB64("o:box1") + `"}]}`))
	})
	defer srv.Close()

	_, err := c.(BoxLister).ListApplicationBoxes(context.Background(), 1, []byte("o:"))
	if !errors.Is(err, ErrBoxValuesUnsupported) {
		t.Fatalf("err = %v, want ErrBoxValuesUnsupported", err)
	}
}

func TestListApplicationBoxes_HTTPError(t *testing.T) {
	// 400 (not 5xx) so DefaultTransport's transient-5xx retry loop doesn't fire —
	// we're asserting the non-200 error path, not retry behavior.
	c, srv := newFakeAlgod(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("boom"))
	})
	defer srv.Close()

	if _, err := c.(BoxLister).ListApplicationBoxes(context.Background(), 1, []byte("o:")); err == nil {
		t.Fatal("want an error on a non-200 box-list response")
	}
}
