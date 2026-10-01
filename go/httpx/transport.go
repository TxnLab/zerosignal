/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package httpx provides a shared, tuned http.Transport for hayai's
// node↔node and proxy↔node calls. Go's http.DefaultTransport is wrong in
// two ways for a service that fans many concurrent requests at a small,
// changing set of operator hosts:
//
//   - It caps idle (keep-alive) connections per host at 2, so every
//     concurrent caller past the second re-dials and re-runs the TLS
//     handshake the moment its request completes — connection churn that
//     shows up as latency and CPU under load.
//   - It dials for 30s before giving up. Against an unreachable operator
//     that stalls the request (and, on the relay, pins a circuit slot)
//     for half a minute when the dispatcher could have failed over in
//     well under a second.
//
// Transport fixes both: a short dial timeout so an unreachable operator
// fails fast, and a generous per-host idle pool so warm connections are
// reused. It is the operator-host analogue of algod.DefaultTransport,
// which makes the same choices for the single algod host.
package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

const (
	// DefaultDialTimeout bounds TCP connection establishment. A reachable
	// operator completes the handshake in well under a second even across
	// the public internet, so a short ceiling lets the dispatcher fail
	// over to the next candidate — and frees a relay circuit slot —
	// quickly when a node is unreachable, instead of stalling for Go's
	// 30s default.
	DefaultDialTimeout = 5 * time.Second

	// DefaultTLSHandshakeTimeout bounds the TLS handshake after the TCP
	// connect succeeds. Like the dial, a live node completes this fast.
	DefaultTLSHandshakeTimeout = 5 * time.Second

	// DefaultKeepAlive is the TCP keep-alive probe interval. Mirrors Go's
	// default; set explicitly because overriding DialContext discards the
	// dialer the cloned DefaultTransport shipped with.
	DefaultKeepAlive = 30 * time.Second

	// DefaultMaxIdleConnsPerHost keeps connections warm to a single
	// operator host under concurrent load. Go's default (2) closes every
	// connection past the second as soon as its request finishes, forcing
	// the next concurrent caller to re-dial + re-handshake. 100 matches
	// the algod transport's per-host pool.
	DefaultMaxIdleConnsPerHost = 100

	// ForwardHeaderBackstop is the recommended ResponseHeaderTimeout for the
	// forwarding clients — the relay forwarder and the proxy→node client —
	// whose own overall Client.Timeout must stay 0. It exists only to bound a
	// connected-but-silent peer; it must never clip a slow-but-valid response.
	//
	// For STREAMING endpoints (/v1/chat/completions, /v1/responses) the node
	// writes its response headers right after admission — before the first
	// upstream token (see node runStream/runStreamWithTools, which call
	// writeHeaders at stream start) — so headers arrive within admission
	// latency (decrypt + ticket consume + on-chain payment verify), far under
	// any value here.
	//
	// But these same clients also forward NON-streaming endpoints — most
	// notably /v1/images/generations and /v1/images/edits — where the node
	// cannot write response headers until the full upstream image call has
	// completed and the result is sealed (there is no early header to send: a
	// sealed JSON body is all-or-nothing). Image generation/editing routinely
	// runs tens of seconds and can reach a couple of minutes, so the backstop
	// has to outlast the slowest legal non-streaming op, not just admission. A
	// tight value (this was 30s) clips slow-but-valid image forwards with a
	// spurious 502 relay_upstream_unreachable / operator_unreachable. Keep it
	// generous — it only ever fires for a genuinely silent peer, and the dial
	// (DefaultDialTimeout) and TLS (DefaultTLSHandshakeTimeout) timeouts
	// already bound the connect phase.
	ForwardHeaderBackstop = 5 * time.Minute

	// DefaultH2ReadIdleTimeout arms an HTTP/2 keepalive PING: after this much
	// time with no frame read on an h2 connection, the transport sends a PING.
	// This keeps a warm connection (and any intermediary NAT/idle mapping)
	// alive and, paired with the ping timeout below, lets a caller detect a
	// silently-dropped peer quickly instead of hanging on a dead connection.
	//
	// NOTE: h2 PINGs are CONNECTION-level, not stream-level. They do NOT keep an
	// individual response stream alive through an L7 reverse proxy / LB that
	// times out on response-body idleness — that idle-stream reset is defended
	// against by the node emitting periodic SSE keepalive comment frames on the
	// response body itself (node server.sse_keepalive_interval). These pings are
	// the transport-side complement: fast dead-peer detection + warm pools.
	DefaultH2ReadIdleTimeout = 30 * time.Second

	// DefaultH2PingTimeout bounds how long to wait for the PING ack before
	// treating the h2 connection as dead and closing it, so the next request
	// re-dials (or the dispatcher fails over) instead of stalling.
	DefaultH2PingTimeout = 15 * time.Second
)

// Options tunes Transport. The zero value yields the package defaults
// (short dial, large per-host pool, no response-header timeout), which
// suit the streaming proxy↔node and relay clients.
type Options struct {
	// DialTimeout bounds TCP connect; 0 uses DefaultDialTimeout.
	DialTimeout time.Duration
	// TLSHandshakeTimeout bounds the TLS handshake; 0 uses DefaultTLSHandshakeTimeout.
	TLSHandshakeTimeout time.Duration
	// MaxIdleConnsPerHost caps warm idle conns per host; 0 uses DefaultMaxIdleConnsPerHost.
	MaxIdleConnsPerHost int
	// ResponseHeaderTimeout bounds the wait for response headers after the
	// request is fully written; 0 means no bound. Set it to
	// ForwardHeaderBackstop on the relay/proxy forwarding clients. Do NOT set
	// it tight: for streaming endpoints the upstream's time-to-first-token is
	// in the response body (not the headers), and for non-streaming endpoints
	// (e.g. image generations/edits) the peer writes no headers at all until
	// the full upstream call completes.
	ResponseHeaderTimeout time.Duration

	// H2ReadIdleTimeout / H2PingTimeout tune the HTTP/2 keepalive PING on the
	// transport; 0 uses DefaultH2ReadIdleTimeout / DefaultH2PingTimeout. They
	// engage only when HTTP/2 is actually negotiated (an https operator/relay);
	// a plaintext http/1.1 dev target is unaffected. See the constants: these
	// are connection-level health pings, NOT a substitute for the node's
	// stream-body SSE keepalive.
	H2ReadIdleTimeout time.Duration
	H2PingTimeout     time.Duration

	// BlockPrivateTargets, when true, installs a dialer Control hook that
	// refuses to connect to a resolved IP in a private / loopback / link-local
	// / CGNAT / ULA range (see IsPrivateIP). This is the SSRF guard for clients
	// that dial attacker-controllable, operator-registered BaseURLs — the node
	// relay forwarder and the proxy→operator client. Because the hook inspects
	// the address Go is *about to dial* (post-DNS-resolution), it catches
	// literal private IPs, hostnames that resolve into private space, and
	// DNS-rebinding alike. Leave it false for clients dialing trusted infra
	// (algod / oracle / NFD), and false-it on localnet via the per-component
	// dev opt-out (operators legitimately run on 127.0.0.1 / 10.x there).
	BlockPrivateTargets bool
}

// Transport returns a tuned *http.Transport. Each call yields a fresh
// transport with its own connection pool, so give one transport (one
// pool) to each long-lived client rather than sharing it across unrelated
// clients.
func Transport(opts Options) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()

	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	tlsTimeout := opts.TLSHandshakeTimeout
	if tlsTimeout <= 0 {
		tlsTimeout = DefaultTLSHandshakeTimeout
	}
	perHost := opts.MaxIdleConnsPerHost
	if perHost <= 0 {
		perHost = DefaultMaxIdleConnsPerHost
	}

	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: DefaultKeepAlive,
	}
	if opts.BlockPrivateTargets {
		dialer.Control = blockPrivateControl
	}
	t.DialContext = dialer.DialContext
	t.TLSHandshakeTimeout = tlsTimeout
	t.ResponseHeaderTimeout = opts.ResponseHeaderTimeout
	t.MaxIdleConnsPerHost = perHost
	// MaxIdleConns (total, across all hosts) stays unlimited: the proxy
	// keeps warm pools to many operator hosts at once, and a small total
	// cap (the cloned default is 100) would starve the per-host pools when
	// several operators are busy. Idle conns are still reaped after
	// IdleConnTimeout (90s, inherited from DefaultTransport).
	t.MaxIdleConns = 0

	// Enable HTTP/2 keepalive PINGs. ConfigureTransports switches this transport
	// from the stdlib-bundled http2 (which exposes no ping knobs) to
	// golang.org/x/net/http2 and returns the *http2.Transport so we can set
	// them. It only affects connections where h2 is negotiated via ALPN over
	// TLS; a plaintext http/1.1 target keeps using HTTP/1. A configure error is
	// non-fatal — the transport still works over h2 (bundled) / h1, just
	// without tuned pings.
	h2ReadIdle := opts.H2ReadIdleTimeout
	if h2ReadIdle <= 0 {
		h2ReadIdle = DefaultH2ReadIdleTimeout
	}
	h2Ping := opts.H2PingTimeout
	if h2Ping <= 0 {
		h2Ping = DefaultH2PingTimeout
	}
	if h2t, err := http2.ConfigureTransports(t); err == nil && h2t != nil {
		h2t.ReadIdleTimeout = h2ReadIdle
		h2t.PingTimeout = h2Ping
	}

	return t
}

// Client returns an *http.Client with a tuned transport. timeout is the
// client's overall deadline: 0 means none, which is required for
// long-lived SSE streams — per-request cancellation then comes from the
// request context.
func Client(timeout time.Duration, opts Options) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(opts),
	}
}

// ErrPrivateTarget is the error a BlockPrivateTargets dial fails with when the
// resolved address falls in a private / loopback / link-local range. It wraps
// the offending IP, so callers can errors.Is it while still logging the value.
var ErrPrivateTarget = errors.New("httpx: refusing to dial private/loopback/link-local address")

// cgnat is the RFC 6598 carrier-grade-NAT range (100.64.0.0/10). Go's
// net.IP.IsPrivate covers RFC1918 and IPv6 ULA (fc00::/7) but NOT CGNAT, so it
// is checked explicitly in IsPrivateIP.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsPrivateIP reports whether ip is in a range a client must not be tricked
// into dialing on an attacker-controlled BaseURL: loopback, RFC1918 / IPv6 ULA
// (net.IP.IsPrivate), link-local (unicast + multicast), unspecified, multicast,
// or RFC 6598 CGNAT (100.64.0.0/10). Family-agnostic — the net.IP.Is* methods
// classify v4 and v6 alike. A nil ip reports true (fail closed). This is the
// SSRF predicate; it is intentionally separate from the IPv4-only,
// golden-vectored selection.isPublicIPv4 used for relay /16 diversity.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	return cgnat.Contains(ip)
}

// blockPrivateControl is a net.Dialer.Control hook that fails the dial when the
// resolved address is a private/loopback target. address is the concrete
// ip:port the dialer is about to connect to (post-resolution), which is what
// makes the guard DNS-rebinding-proof. A non-IP or unparseable address fails
// closed.
func blockPrivateControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unresolved address %q", ErrPrivateTarget, address)
	}
	if IsPrivateIP(ip) {
		return fmt.Errorf("%w: %s", ErrPrivateTarget, ip)
	}
	return nil
}
