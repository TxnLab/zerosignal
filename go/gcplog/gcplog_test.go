/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package gcplog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestSeverity(t *testing.T) {
	cases := []struct {
		name string
		lvl  slog.Level
		want string
	}{
		{"debug", slog.LevelDebug, "DEBUG"},
		{"info", slog.LevelInfo, "INFO"},
		{"warn", slog.LevelWarn, "WARNING"},
		{"error", slog.LevelError, "ERROR"},
		// Below info but above debug -> still DEBUG bucket.
		{"between debug and info", slog.LevelDebug + 1, "DEBUG"},
		// Custom level above error stays ERROR.
		{"above error", slog.LevelError + 4, "ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Severity(tc.lvl); got != tc.want {
				t.Fatalf("Severity(%v) = %q, want %q", tc.lvl, got, tc.want)
			}
		})
	}
}

func TestReplaceAttrJSONHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: ReplaceAttr,
	}))

	log.Warn("hello world", slog.String("operator_id", "op-123"))

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log line: %v\nline: %s", err, buf.String())
	}

	// GCP-recognized keys present with mapped values.
	if got := entry["severity"]; got != "WARNING" {
		t.Errorf("severity = %v, want WARNING", got)
	}
	if got := entry["message"]; got != "hello world" {
		t.Errorf("message = %v, want %q", got, "hello world")
	}
	// time is left as slog's default key (already GCP-compatible).
	if _, ok := entry["time"]; !ok {
		t.Errorf("expected time key to be present")
	}
	// slog's default keys must be gone after remapping.
	if _, ok := entry["level"]; ok {
		t.Errorf("level key should have been renamed to severity")
	}
	if _, ok := entry["msg"]; ok {
		t.Errorf("msg key should have been renamed to message")
	}
	// User attrs pass through untouched.
	if got := entry["operator_id"]; got != "op-123" {
		t.Errorf("operator_id = %v, want op-123", got)
	}
}

func TestReplaceAttrLeavesGroupedAttrsAlone(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: ReplaceAttr,
	}))

	// A user attr literally named "msg" nested inside a group must not be
	// renamed to "message".
	log.Info("grouped", slog.Group("g", slog.String("msg", "inner")))

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("unmarshal log line: %v\nline: %s", err, buf.String())
	}
	g, ok := entry["g"].(map[string]any)
	if !ok {
		t.Fatalf("expected group object under key g, got %v", entry["g"])
	}
	if got := g["msg"]; got != "inner" {
		t.Errorf("grouped msg = %v, want inner (should not be renamed)", got)
	}
}
