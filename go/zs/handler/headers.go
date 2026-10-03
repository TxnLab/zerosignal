/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"maps"
	"net/http"
	"slices"
	"strings"
)

// hopByHopHeaders are per-hop headers that MUST NOT be forwarded end-to-end.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// stripZsHeaders deletes every X-Zs-* header. Run on the client-bound
// header set after every copyResponseHeaders — the sealed-response success
// path AND the pre-envelope error passthrough. SPEC.md §5.2 step 4: the client
// sees no X-Zs-Response-Key, no X-Zs-Receipt, no X-Zs-Settle-Group (the settle
// group carries the operator's pre-signed first half; nothing node-set should
// leak through). zs already removes them from the header sets it reports; this
// is the HTTP surface's own guarantee, not a reliance on that. The proxy's own
// X-Zs-* usage headers are re-added afterwards by setReceiptUsageHeaders —
// proxy-owned metadata, not upstream passthrough.
func stripZsHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Zs-") {
			delete(h, k)
		}
	}
}

// snapshotZsHeaders copies the X-Zs-* headers already on the client-bound
// writer: the ones the PROXY set before the operator was ever called, such as
// the max_output clamp marker. copyResponseHeaders followed by
// stripZsHeaders clears every X-Zs-* on that writer — the node's and the
// proxy's alike — so anything set ahead of the response has to be re-asserted
// after the strip, which is what stripNodeZsHeaders does.
//
// Snapshot-and-restore rather than an allow-list inside the strip, because the
// strip is a security control and an allow-list would defeat it: the copy runs
// first, so a node answering with the same header name has already overwritten
// the proxy's value by the time the strip sees it, and exempting the name would
// hand the node's value straight to the client. A value captured before the
// operator was contacted can't be spoofed.
func snapshotZsHeaders(h http.Header) http.Header {
	var saved http.Header
	for k, vs := range h {
		if !strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Zs-") {
			continue
		}
		if saved == nil {
			saved = make(http.Header, 1)
		}
		saved[k] = slices.Clone(vs)
	}
	return saved
}

// stripNodeZsHeaders drops every node-set X-Zs-* from the client-bound
// header set (see stripZsHeaders) and puts the proxy's own back.
func stripNodeZsHeaders(h, saved http.Header) {
	stripZsHeaders(h)
	maps.Copy(h, saved)
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if _, hop := hopByHopHeaders[ck]; hop {
			continue
		}
		// Access-Control-* headers describe the CORS contract between the
		// browser and whoever it's talking to directly — which is the proxy,
		// not the upstream node. The node sets its own CORS headers for
		// development setups that hit it directly, but those values would
		// overwrite the proxy's (set in writeCORSHeaders before the handler
		// ran) and the node's Expose-Headers omits the X-Zs-* cost
		// metadata the proxy attaches in setReceiptUsageHeaders — so the
		// browser ends up blocking JS access to the very headers the proxy
		// is trying to expose.
		if strings.HasPrefix(ck, "Access-Control-") {
			continue
		}
		dst[ck] = append([]string(nil), vs...)
	}
}
