/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
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

func TestTransportSendsHTTP2Pings(t *testing.T) {
	// Asserted on the wire, not on the transport's fields: how
	// ConfigureTransports wires h2 differs by Go release (1.26 fills
	// TLSNextProto; 1.27 hands it to the stdlib's own HTTP/2 and leaves
	// TLSNextProto empty), and the ping knobs aren't readable from
	// *http.Transport either way. The server answers the handshake and never
	// the request, so only a keepalive PING can arrive.
	cert := httptest.NewTLSServer(nil) // for its certificate
	cert.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pinged := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := io.ReadFull(c, make([]byte, len(http2.ClientPreface))); err != nil {
			return
		}
		fr := http2.NewFramer(c, c)
		if fr.WriteSettings() != nil {
			return
		}
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() && fr.WriteSettingsAck() != nil {
					return
				}
			case *http2.PingFrame:
				if !f.IsAck() {
					pinged <- struct{}{}
					return
				}
			}
		}
	}()

	tr := Transport(Options{H2ReadIdleTimeout: 100 * time.Millisecond, H2PingTimeout: time.Second})
	// Amended, not replaced: the transport's TLS config carries the h2 ALPN
	// entry on the releases that put it there.
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.InsecureSkipVerify = true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
		if resp, err := tr.RoundTrip(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-pinged:
	case <-time.After(5 * time.Second):
		t.Fatal("no HTTP/2 PING with a 100ms read-idle timeout")
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
