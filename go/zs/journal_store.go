/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// memJournal is the default TicketJournal: it outlives a request but not the
// process.
type memJournal struct {
	mu   sync.Mutex
	recs map[string]TicketRecord
}

func newMemJournal() *memJournal { return &memJournal{recs: map[string]TicketRecord{}} }

func (j *memJournal) Put(_ context.Context, rec TicketRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.recs[rec.TicketID] = rec
	return nil
}

func (j *memJournal) Delete(_ context.Context, ticketID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.recs, ticketID)
	return nil
}

func (j *memJournal) List(_ context.Context, payer string, escrowAppID uint64) ([]TicketRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return listRecords(j.recs, payer, escrowAppID), nil
}

// listRecords is List over an in-memory map, oldest first so a sweep finishes
// the longest-stranded ticket first.
func listRecords(recs map[string]TicketRecord, payer string, escrowAppID uint64) []TicketRecord {
	var out []TicketRecord
	for _, r := range recs {
		if r.Payer == payer && r.EscrowAppID == escrowAppID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].CreatedAt.Equal(out[b].CreatedAt) {
			return out[a].CreatedAt.Before(out[b].CreatedAt)
		}
		return out[a].TicketID < out[b].TicketID
	})
	return out
}

// FileJournal is a TicketJournal kept in one JSON file, rewritten whole and
// synced on each change, twice per paid request. Rows stay until the reconciler
// sees their box gone, so the file holds every ticket from roughly the last
// ticket lifetime; writing it whole keeps it one valid document after a crash.
//
// One process owns the file: OpenFileJournal takes an exclusive lock on a
// sibling ".lock" file and Close releases it. Each process rewrites the whole
// file from its own copy, so two sharing one would drop each other's rows. On
// platforms other than Unix and Windows the lock is not taken.
type FileJournal struct {
	path string
	mu   sync.Mutex
	recs map[string]TicketRecord
	lock *os.File // nil once closed
}

// ErrJournalInUse is returned by OpenFileJournal when another FileJournal,
// in this process or another, holds the file.
var ErrJournalInUse = errors.New("zs: ticket journal is in use by another process")

// fileJournalDoc is the file's format. Its rows are their own type so that
// renaming a field of TicketRecord cannot silently drop data from a file
// written before.
type fileJournalDoc struct {
	Version int              `json:"version"`
	Tickets []fileJournalRow `json:"tickets"`
}

type fileJournalRow struct {
	TicketID    string          `json:"ticket_id"`
	OpenTxID    string          `json:"open_tx_id"`
	EscrowAppID uint64          `json:"escrow_app_id"`
	OperatorID  uint64          `json:"operator_id"`
	NodeID      uint64          `json:"node_id"`
	Payer       string          `json:"payer"`
	MaxPrice    uint64          `json:"max_price"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Status      TicketStatus    `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Settle      *fileSettleArgs `json:"settle,omitempty"`
}

type fileSettleArgs struct {
	AmountCharged      uint64           `json:"amount_charged"`
	ReceiptDigest      string           `json:"receipt_digest"`
	TtftMs             uint64           `json:"ttft_ms"`
	DecodeMs           uint64           `json:"decode_ms"`
	InputTokens        uint64           `json:"input_tokens"`
	OutputTokens       uint64           `json:"output_tokens"`
	OutputUsageType    ticket.UsageType `json:"output_usage_type"`
	AuxOutputUsageType ticket.UsageType `json:"aux_output_usage_type"`
	AuxOutputCount     uint64           `json:"aux_output_count"`
}

func rowOf(r TicketRecord) fileJournalRow {
	row := fileJournalRow{
		TicketID: r.TicketID, OpenTxID: r.OpenTxID, EscrowAppID: r.EscrowAppID,
		OperatorID: r.Target.Op, NodeID: r.Target.Node, Payer: r.Payer, MaxPrice: r.MaxPrice,
		ExpiresAt: r.ExpiresAt, Status: r.Status, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if a := r.Settle; a != nil {
		row.Settle = &fileSettleArgs{
			AmountCharged: a.AmountCharged, ReceiptDigest: hex.EncodeToString(a.ReceiptDigest[:]),
			TtftMs: a.TtftMs, DecodeMs: a.DecodeMs, InputTokens: a.InputTokens, OutputTokens: a.OutputTokens,
			OutputUsageType: a.OutputUsageType, AuxOutputUsageType: a.AuxOutputUsageType, AuxOutputCount: a.AuxOutputCount,
		}
	}
	return row
}

func (row fileJournalRow) record() (TicketRecord, error) {
	r := TicketRecord{
		TicketID: row.TicketID, OpenTxID: row.OpenTxID, EscrowAppID: row.EscrowAppID,
		Target: NodeRef{Op: row.OperatorID, Node: row.NodeID}, Payer: row.Payer, MaxPrice: row.MaxPrice,
		ExpiresAt: row.ExpiresAt, Status: row.Status, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	if s := row.Settle; s != nil {
		a := SettleArgs{
			AmountCharged: s.AmountCharged, TtftMs: s.TtftMs, DecodeMs: s.DecodeMs,
			InputTokens: s.InputTokens, OutputTokens: s.OutputTokens,
			OutputUsageType: s.OutputUsageType, AuxOutputUsageType: s.AuxOutputUsageType, AuxOutputCount: s.AuxOutputCount,
		}
		d, err := hex.DecodeString(s.ReceiptDigest)
		if err != nil || len(d) != len(a.ReceiptDigest) {
			return r, fmt.Errorf("ticket %s: bad receipt_digest %q", row.TicketID, s.ReceiptDigest)
		}
		copy(a.ReceiptDigest[:], d)
		r.Settle = &a
	}
	return r, nil
}

const fileJournalVersion = 1

// OpenFileJournal locks and loads the journal at path, or starts an empty one
// when the file does not exist. A file it cannot read is an error rather than
// an empty journal: starting empty would forget tickets that still hold the
// payer's USDC. A journal another FileJournal holds is ErrJournalInUse.
func OpenFileJournal(path string) (*FileJournal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("zs: ticket journal dir: %w", err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("zs: open ticket journal lock: %w", err)
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		if errors.Is(err, errLocked) {
			return nil, fmt.Errorf("%w: %s", ErrJournalInUse, path)
		}
		return nil, fmt.Errorf("zs: lock ticket journal: %w", err)
	}
	recs, err := readJournal(path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &FileJournal{path: path, recs: recs, lock: lock}, nil
}

func readJournal(path string) (map[string]TicketRecord, error) {
	recs := map[string]TicketRecord{}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return recs, nil
	case err != nil:
		return nil, fmt.Errorf("zs: read ticket journal: %w", err)
	}
	var doc fileJournalDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("zs: parse ticket journal %s: %w", path, err)
	}
	if doc.Version != fileJournalVersion {
		return nil, fmt.Errorf("zs: ticket journal %s has version %d, want %d", path, doc.Version, fileJournalVersion)
	}
	for _, row := range doc.Tickets {
		r, err := row.record()
		if err != nil {
			return nil, fmt.Errorf("zs: parse ticket journal %s: %w", path, err)
		}
		recs[r.TicketID] = r
	}
	return recs, nil
}

// Close releases the lock. The journal accepts no writes after it.
func (j *FileJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	err := j.lock.Close()
	j.lock = nil
	return err
}

func (j *FileJournal) Put(_ context.Context, rec TicketRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	prev, had := j.recs[rec.TicketID]
	j.recs[rec.TicketID] = rec
	if err := j.save(); err != nil {
		if had {
			j.recs[rec.TicketID] = prev
		} else {
			delete(j.recs, rec.TicketID)
		}
		return err
	}
	return nil
}

func (j *FileJournal) Delete(_ context.Context, ticketID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	prev, had := j.recs[ticketID]
	if !had {
		return nil
	}
	delete(j.recs, ticketID)
	if err := j.save(); err != nil {
		j.recs[ticketID] = prev
		return err
	}
	return nil
}

func (j *FileJournal) List(_ context.Context, payer string, escrowAppID uint64) ([]TicketRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return listRecords(j.recs, payer, escrowAppID), nil
}

// save writes the journal to a temporary file and renames it over the old
// one, so a crash leaves either the old document or the new one. Runs under
// j.mu.
func (j *FileJournal) save() error {
	if j.lock == nil {
		return errors.New("zs: ticket journal is closed")
	}
	doc := fileJournalDoc{Version: fileJournalVersion, Tickets: make([]fileJournalRow, 0, len(j.recs))}
	for _, r := range j.recs {
		doc.Tickets = append(doc.Tickets, rowOf(r))
	}
	sort.Slice(doc.Tickets, func(a, b int) bool { return doc.Tickets[a].TicketID < doc.Tickets[b].TicketID })
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("zs: encode ticket journal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return fmt.Errorf("zs: ticket journal dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(j.path), filepath.Base(j.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("zs: write ticket journal: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("zs: write ticket journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("zs: sync ticket journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("zs: write ticket journal: %w", err)
	}
	if err := os.Rename(tmp.Name(), j.path); err != nil {
		return fmt.Errorf("zs: replace ticket journal: %w", err)
	}
	return nil
}
