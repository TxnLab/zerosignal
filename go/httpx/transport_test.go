/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTransportDefaults(t *testing.T) {
	tr := Transport(Options{})

	if tr.TLSHandshakeTimeout != DefaultTLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", tr.TLSHandshakeTimeout, DefaultTLSHandshakeTimeout)
	}
	if tr.MaxIdleConnsPerHost != DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}
	// Total idle pool must be unlimited (0), not the cloned DefaultTransport
	// value of 100 — a small total cap starves per-host pools across many
	// operator hosts.
	if tr.MaxIdleConns != 0 {
		t.Errorf("MaxIdleConns = %d, want 0 (unlimited)", tr.MaxIdleConns)
	}
	// No header timeout unless asked for, so a slow-but-valid admission is
	// never clipped.
	if tr.ResponseHeaderTimeout != 0 {
		t.Errorf("ResponseHeaderTimeout = %v, want 0", tr.ResponseHeaderTimeout)
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil; dial timeout would fall back to the OS default")
	}
	// Inherited from the cloned DefaultTransport.
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s (inherited)", tr.IdleConnTimeout)
	}
}

func TestTransportHTTP2PingsConfigured(t *testing.T) {
	// ConfigureTransports installs the "h2" ALPN handler on TLSNextProto (and
	// switches the transport to golang.org/x/net/http2 so the ping knobs take
	// effect). Its presence is the observable signal that h2 keepalive pings
	// were wired; the ReadIdleTimeout/PingTimeout live on the returned
	// *http2.Transport, which isn't reachable from *http.Transport.
	tr := Transport(Options{})
	if tr.TLSNextProto == nil || tr.TLSNextProto["h2"] == nil {
		t.Fatal("expected HTTP/2 to be configured (TLSNextProto[\"h2\"] set)")
	}

	// Custom (and non-default) ping values must not error out the configure
	// path — the transport still comes back h2-configured.
	tr2 := Transport(Options{H2ReadIdleTimeout: 7 * time.Second, H2PingTimeout: 3 * time.Second})
	if tr2.TLSNextProto == nil || tr2.TLSNextProto["h2"] == nil {
		t.Fatal("expected HTTP/2 configured with custom ping values")
	}
}

func TestTransportOptionsOverride(t *testing.T) {
	tr := Transport(Options{
		DialTimeout:           1 * time.Second,
		TLSHandshakeTimeout:   2 * time.Second,
		MaxIdleConnsPerHost:   7,
		ResponseHeaderTimeout: ForwardHeaderBackstop,
	})

	if tr.TLSHandshakeTimeout != 2*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 2s", tr.TLSHandshakeTimeout)
	}
	if tr.MaxIdleConnsPerHost != 7 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 7", tr.MaxIdleConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != ForwardHeaderBackstop {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, ForwardHeaderBackstop)
	}
}

func TestClient(t *testing.T) {
	c := Client(0, Options{})
	if c.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0 (streaming)", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.MaxIdleConnsPerHost != DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}

	withTimeout := Client(5*time.Second, Options{})
	if withTimeout.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", withTimeout.Timeout)
	}
}

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// blocked
		{"127.0.0.1", true},       // loopback v4
		{"::1", true},             // loopback v6
		{"10.0.0.5", true},        // RFC1918
		{"172.16.3.4", true},      // RFC1918
		{"192.168.1.1", true},     // RFC1918
		{"169.254.1.1", true},     // link-local v4
		{"fe80::1", true},         // link-local v6
		{"fc00::1", true},         // ULA v6
		{"fd12:3456::1", true},    // ULA v6
		{"100.64.0.1", true},      // CGNAT (not covered by IsPrivate)
		{"100.127.255.254", true}, // CGNAT upper edge
		{"0.0.0.0", true},         // unspecified v4
		{"::", true},              // unspecified v6
		{"224.0.0.1", true},       // multicast v4
		{"ff02::1", true},         // multicast v6
		// allowed (globally routable)
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.5", false},          // TEST-NET-3, but routable as far as Is* is concerned
		{"100.63.255.255", false},       // just below CGNAT
		{"100.128.0.0", false},          // just above CGNAT
		{"2606:4700:4700::1111", false}, // public v6
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("ParseIP(%q) returned nil", c.ip)
		}
		if got := IsPrivateIP(ip); got != c.want {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if !IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) = false, want true (fail closed)")
	}
}

// TestBlockPrivateTargetsDial proves the dial guard refuses a loopback target
// when BlockPrivateTargets is set, and dials it normally when it isn't — the
// localnet dev opt-out. httptest listens on 127.0.0.1, so the guarded client
// must fail with ErrPrivateTarget while the unguarded one gets a 200.
func TestBlockPrivateTargetsDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	get := func(c *http.Client) error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}

	blocked := Client(2*time.Second, Options{BlockPrivateTargets: true})
	if err := get(blocked); err == nil {
		t.Fatal("guarded client dialed a loopback target; want ErrPrivateTarget")
	} else if !errors.Is(err, ErrPrivateTarget) {
		t.Fatalf("guarded client error = %v, want ErrPrivateTarget", err)
	}

	allowed := Client(2*time.Second, Options{}) // opt-out: default, no guard
	if err := get(allowed); err != nil {
		t.Fatalf("unguarded client failed to dial loopback target: %v", err)
	}
}
