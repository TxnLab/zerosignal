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
	"maps"
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

func (j *memJournal) List(_ context.Context, payer string, d Deployment) ([]TicketRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return listRecords(j.recs, payer, d), nil
}

// listRecords is List over an in-memory map, oldest first so a sweep finishes
// the longest-stranded ticket first.
func listRecords(recs map[string]TicketRecord, payer string, d Deployment) []TicketRecord {
	var out []TicketRecord
	for _, r := range recs {
		if r.Payer == payer && d.Owns(r) {
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
// synced on each change, twice per paid request. A row goes when its atomic
// settle is seen confirmed, or else when the reconciler sees its box gone, so
// the file holds the tickets still open plus those from roughly the last
// ticket lifetime that settled another way; writing it whole keeps it one
// valid document after a crash.
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
	// skipped is written only while OpenFileJournal runs.
	skipped []JournalMergeSkip
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
	Deployment  string          `json:"deployment,omitempty"`
	OperatorID  uint64          `json:"operator_id"`
	NodeID      uint64          `json:"node_id"`
	Payer       string          `json:"payer"`
	MaxPrice    uint64          `json:"max_price"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Status      TicketStatus    `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Settle      *fileSettleArgs `json:"settle,omitempty"`
	// Signed is new in the same file version: a binary from before it
	// ignores the field, and only loses the over-claim check it feeds.
	Signed *fileSettleArgs `json:"signed,omitempty"`
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
		TicketID: r.TicketID, OpenTxID: r.OpenTxID, EscrowAppID: r.EscrowAppID, Deployment: r.Deployment,
		OperatorID: r.Target.Op, NodeID: r.Target.Node, Payer: r.Payer, MaxPrice: r.MaxPrice,
		ExpiresAt: r.ExpiresAt, Status: r.Status, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	row.Settle = fileSettleArgsOf(r.Settle)
	row.Signed = fileSettleArgsOf(r.Signed)
	return row
}

func fileSettleArgsOf(a *SettleArgs) *fileSettleArgs {
	if a == nil {
		return nil
	}
	return &fileSettleArgs{
		AmountCharged: a.AmountCharged, ReceiptDigest: hex.EncodeToString(a.ReceiptDigest[:]),
		TtftMs: a.TtftMs, DecodeMs: a.DecodeMs, InputTokens: a.InputTokens, OutputTokens: a.OutputTokens,
		OutputUsageType: a.OutputUsageType, AuxOutputUsageType: a.AuxOutputUsageType, AuxOutputCount: a.AuxOutputCount,
	}
}

func (row fileJournalRow) record() (TicketRecord, error) {
	r := TicketRecord{
		TicketID: row.TicketID, OpenTxID: row.OpenTxID, EscrowAppID: row.EscrowAppID, Deployment: row.Deployment,
		Target: NodeRef{Op: row.OperatorID, Node: row.NodeID}, Payer: row.Payer, MaxPrice: row.MaxPrice,
		ExpiresAt: row.ExpiresAt, Status: row.Status, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	var err error
	if r.Settle, err = row.Settle.args(row.TicketID); err != nil {
		return r, err
	}
	if r.Signed, err = row.Signed.args(row.TicketID); err != nil {
		return r, err
	}
	return r, nil
}

// args is s decoded, nil for none.
func (s *fileSettleArgs) args(ticketID string) (*SettleArgs, error) {
	if s == nil {
		return nil, nil
	}
	a := SettleArgs{
		AmountCharged: s.AmountCharged, TtftMs: s.TtftMs, DecodeMs: s.DecodeMs,
		InputTokens: s.InputTokens, OutputTokens: s.OutputTokens,
		OutputUsageType: s.OutputUsageType, AuxOutputUsageType: s.AuxOutputUsageType, AuxOutputCount: s.AuxOutputCount,
	}
	d, err := hex.DecodeString(s.ReceiptDigest)
	if err != nil || len(d) != len(a.ReceiptDigest) {
		return nil, fmt.Errorf("ticket %s: bad receipt_digest %q", ticketID, s.ReceiptDigest)
	}
	copy(a.ReceiptDigest[:], d)
	return &a, nil
}

// Version 1 still, though rows gained deployment: a rolled-back binary refuses
// any other version, and it ignores the field.
const fileJournalVersion = 1

// OpenFileJournal locks and loads the journal at path, or starts an empty one
// when the file does not exist. A file it cannot read is an error rather than
// an empty journal: starting empty would forget tickets that still hold the
// payer's USDC. A journal another FileJournal holds is ErrJournalInUse.
//
// Each legacy file, the journal under an earlier name, is merged in and then
// removed, unless another process holds it or it will not read: it is then
// left as it is, and a later open merges it. Its lock file stays.
func OpenFileJournal(path string, legacy ...string) (*FileJournal, error) {
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
	j := &FileJournal{path: path, recs: recs, lock: lock}
	for _, l := range legacy {
		if l != "" && journalPathKey(l) != journalPathKey(path) {
			j.mergeLegacy(l)
		}
	}
	return j, nil
}

// JournalMergeSkip is a legacy file OpenFileJournal left in place, and why.
type JournalMergeSkip struct {
	Path string
	Err  error
}

// MergeSkipped lists the legacy files the open left in place. OpenFileJournal
// has no logger, so the caller reports them.
func (j *FileJournal) MergeSkipped() []JournalMergeSkip { return j.skipped }

// mergeLegacy folds the journal at l into j, the newer UpdatedAt winning a
// ticket both hold, then removes l once j's file holds its rows. A crash
// between the two leaves both, and the next open merges again to the same
// result.
func (j *FileJournal) mergeLegacy(l string) {
	if _, err := os.Stat(l); errors.Is(err, os.ErrNotExist) {
		return
	}
	skip := func(err error) { j.skipped = append(j.skipped, JournalMergeSkip{Path: l, Err: err}) }
	lock, err := os.OpenFile(l+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		skip(err)
		return
	}
	// An older process still journaling there would go on writing rows this
	// merge never sees, and its next save would bring the file back.
	if err := lockFile(lock); err != nil {
		lock.Close()
		if errors.Is(err, errLocked) {
			err = fmt.Errorf("%w: %s", ErrJournalInUse, l)
		}
		skip(err)
		return
	}
	defer lock.Close()
	if err := j.mergeFrom(l); err != nil {
		skip(err)
		return
	}
	// A file left behind is merged again on every open, bringing back rows
	// this journal has since finished, so its staying is reported. The lock
	// file stays, as the journal's own does: removing it would let two
	// processes from before this release each lock a fresh one.
	if err := os.Remove(l); err != nil {
		skip(fmt.Errorf("merged but not removed: %w", err))
	}
}

// mergeFrom reads the journal at l into j and saves j. A file that will not
// read is never removed: its rows may still hold the payer's USDC, and a
// reader that knows the old name can still find them.
func (j *FileJournal) mergeFrom(l string) error {
	old, err := readJournal(l)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	prev := maps.Clone(j.recs)
	for id, r := range old {
		if cur, ok := j.recs[id]; !ok || r.UpdatedAt.After(cur.UpdatedAt) {
			j.recs[id] = r
		}
	}
	if err := j.save(); err != nil {
		j.recs = prev
		return err
	}
	return nil
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

func (j *FileJournal) List(_ context.Context, payer string, d Deployment) ([]TicketRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return listRecords(j.recs, payer, d), nil
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
