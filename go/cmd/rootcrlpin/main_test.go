/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
	"time"
)

func TestVerdict(t *testing.T) {
	pin := time.Date(2026, 2, 26, 13, 4, 0, 0, time.UTC)
	next := pin.AddDate(1, 0, 0)
	now := pin.AddDate(0, 8, 0)
	newer := pin.AddDate(1, 0, 0)
	older := pin.Add(-time.Hour)
	at := func(t time.Time) *time.Time { return &t }

	cases := []struct {
		name   string
		intel  time.Time
		mirror *time.Time
		now    time.Time
		code   int
		prefix string
	}{
		{"current", pin, at(pin), now, 0, "ok"},
		{"current, mirror unreadable", pin, nil, now, 0, "ok"},
		// Intel unchanged and the pin current, yet every carried set is refused.
		{"mirror behind the pin", pin, at(older), now, 1, "the mirror serves"},
		{"pin ahead of Intel", older, at(older), now, 1, "fix the pin"},
		{"inside the expiry warning", pin, at(pin), next.Add(-expiryWarning + time.Hour), 1, "Intel's root CA CRL reaches"},
		{"just outside the expiry warning", pin, at(pin), next.Add(-expiryWarning - time.Hour), 0, "ok"},
		{"Intel reissued, mirror serves it", newer, at(newer), now, 1, "bump:"},
		{"Intel reissued, mirror behind", newer, at(pin), now, 1, "bump pending"},
		{"Intel reissued, mirror unreadable", newer, nil, now, 1, "bump pending"},
	}
	for _, c := range cases {
		msg, code := verdict(pin, c.intel, next, c.mirror, c.now)
		if code != c.code || !strings.HasPrefix(msg, c.prefix) {
			t.Errorf("%s: got (%d, %q), want (%d, %q…)", c.name, code, msg, c.code, c.prefix)
		}
	}
}
