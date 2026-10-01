/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"testing"
)

func TestEnvelopeConstants(t *testing.T) {
	if EncryptedContentType != "application/vnd.zs+json" {
		t.Errorf("EncryptedContentType changed — wire-breaking")
	}
	if ResponseKeyHeader != "X-Zs-Response-Key" {
		t.Errorf("ResponseKeyHeader changed — wire-breaking")
	}
	if StreamEventMarker != "zs" {
		t.Errorf("StreamEventMarker changed — wire-breaking")
	}
	if ResponseKeySize != 32 {
		t.Errorf("ResponseKeySize = %d, want 32", ResponseKeySize)
	}
	if NonceSize != 12 {
		t.Errorf("NonceSize = %d, want 12", NonceSize)
	}
}

func TestBodyAndFrameAADAreDisjoint(t *testing.T) {
	// Body AAD and frame AAD with frameIndex=0 must differ so a body
	// ciphertext cannot be replayed as frame 0 or vice versa.
	if bytes.Equal(BuildBodyAAD("TX", ""), BuildFrameAAD("TX", "", 0)) {
		t.Error("body and frame AAD collide; domain separation broken")
	}
}

func TestBuildFrameAAD_IndexAffectsOutput(t *testing.T) {
	// Monotonic frame counter: different indices must produce different AAD.
	a := BuildFrameAAD("TX", "", 0)
	b := BuildFrameAAD("TX", "", 1)
	if bytes.Equal(a, b) {
		t.Error("frame AAD does not depend on frameIndex")
	}
}

func TestBuildBodyAAD_TxIDAffectsOutput(t *testing.T) {
	if bytes.Equal(BuildBodyAAD("A", ""), BuildBodyAAD("B", "")) {
		t.Error("body AAD does not depend on txID")
	}
}

func TestBuildBodyAAD_TicketIDAffectsOutput(t *testing.T) {
	// Different ticket IDs must produce different AAD so a response sealed
	// for one ticket cannot be replayed against another ticket's request.
	if bytes.Equal(BuildBodyAAD("TX", "T1"), BuildBodyAAD("TX", "T2")) {
		t.Error("body AAD does not depend on ticketID")
	}
}

func TestBuildFrameAAD_TicketIDAffectsOutput(t *testing.T) {
	if bytes.Equal(BuildFrameAAD("TX", "T1", 0), BuildFrameAAD("TX", "T2", 0)) {
		t.Error("frame AAD does not depend on ticketID")
	}
}

func TestBuildBodyAAD_EmptyVsNonEmptyTicket(t *testing.T) {
	// The trailing separator is always present so empty vs non-empty ticket
	// produce different AAD.
	if bytes.Equal(BuildBodyAAD("TX", ""), BuildBodyAAD("TX", "T")) {
		t.Error("empty-ticket and present-ticket AAD collide")
	}
}
