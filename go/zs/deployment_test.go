/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

func depRec(id string, updated time.Time) TicketRecord {
	return TicketRecord{
		TicketID: id, EscrowAppID: 7, Payer: "PAYER", Status: TicketOpen,
		CreatedAt: reconcileNow, UpdatedAt: updated, ExpiresAt: reconcileNow.Add(time.Hour),
	}
}

func writeJournal(t *testing.T, path string, recs ...TicketRecord) {
	t.Helper()
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if err := j.Put(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
}

func listed(t *testing.T, j TicketJournal) map[string]TicketRecord {
	t.Helper()
	recs, err := j.List(context.Background(), "PAYER", journalDeployment)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]TicketRecord{}
	for _, r := range recs {
		out[r.TicketID] = r
	}
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// A legacy journal's rows join the new file, the later write of a ticket both
// hold wins whichever file it is in, and the legacy file goes only once the
// new file holds the rows. Its lock file stays, so a process from before this
// release still contends for the same lock.
func TestOpenFileJournal_MergesLegacy(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "new.json"), filepath.Join(dir, "old.json")
	early, late := reconcileNow, reconcileNow.Add(time.Minute)

	oldA, oldB, oldC := depRec("A", late), depRec("B", early), depRec("C", early)
	oldA.MaxPrice, oldC.MaxPrice = 1, 1
	writeJournal(t, legacy, oldA, oldB, oldC)
	newA, newC, newD := depRec("A", early), depRec("C", late), depRec("D", early)
	newA.MaxPrice, newC.MaxPrice = 2, 2
	writeJournal(t, path, newA, newC, newD)

	j, err := OpenFileJournal(path, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if s := j.MergeSkipped(); len(s) != 0 {
		t.Fatalf("skipped %v", s)
	}
	got := listed(t, j)
	if ids := slices.Sorted(maps.Keys(got)); !slices.Equal(ids, []string{"A", "B", "C", "D"}) {
		t.Fatalf("merged %v, want A B C D", ids)
	}
	if got["A"].MaxPrice != 1 || got["C"].MaxPrice != 2 {
		t.Errorf("A from %d and C from %d, want each from the file that wrote it later (1, 2)", got["A"].MaxPrice, got["C"].MaxPrice)
	}
	if exists(legacy) || !exists(legacy+".lock") {
		t.Errorf("after the merge the legacy journal exists %v and its lock %v, want only the lock", exists(legacy), exists(legacy+".lock"))
	}
	j.Close()

	reopened, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if n := len(listed(t, reopened)); n != 4 {
		t.Errorf("the new file holds %d rows after the merge, want 4", n)
	}
}

// A legacy journal another process still writes is left to it: merging rows
// it goes on changing would lose its later writes, and its next save would
// bring the file back. A later open, once it lets go, merges it.
func TestOpenFileJournal_SkipsAHeldLegacy(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "new.json"), filepath.Join(dir, "old.json")
	writeJournal(t, legacy, depRec("OLD", reconcileNow))
	holder, err := OpenFileJournal(legacy)
	if err != nil {
		t.Fatal(err)
	}

	j, err := OpenFileJournal(path, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if s := j.MergeSkipped(); len(s) != 1 || s[0].Path != legacy || !errors.Is(s[0].Err, ErrJournalInUse) {
		t.Fatalf("skipped %+v, want the held legacy file with ErrJournalInUse", s)
	}
	if _, ok := listed(t, j)["OLD"]; ok {
		t.Error("a held legacy journal was merged")
	}
	if !exists(legacy) {
		t.Fatal("a held legacy journal was removed")
	}
	j.Close()
	holder.Close()

	j2, err := OpenFileJournal(path, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer j2.Close()
	if _, ok := listed(t, j2)["OLD"]; !ok || exists(legacy) {
		t.Error("once released, the legacy journal was not merged")
	}
}

// A legacy file that will not read is kept, rows that may hold the payer's
// USDC and all, and does not stop the new journal from opening.
func TestOpenFileJournal_KeepsAnUnreadableLegacy(t *testing.T) {
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "new.json"), filepath.Join(dir, "old.json")
	if err := os.WriteFile(legacy, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenFileJournal(path, legacy)
	if err != nil {
		t.Fatalf("an unreadable legacy file failed the open: %v", err)
	}
	defer j.Close()
	if s := j.MergeSkipped(); len(s) != 1 || s[0].Path != legacy || s[0].Err == nil {
		t.Errorf("skipped %+v, want the unreadable legacy file", s)
	}
	if b, err := os.ReadFile(legacy); err != nil || string(b) != "{not json" {
		t.Errorf("the unreadable legacy file is gone or changed: %q, %v", b, err)
	}
}

// Naming the journal itself, an absent file or nothing as a legacy path is a
// no-op, not a self-merge that removes the journal.
func TestOpenFileJournal_LegacyNoOps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "j.json")
	writeJournal(t, path, depRec("A", reconcileNow))
	j, err := OpenFileJournal(path, path, dir+"/./"+filepath.Base(path), "", filepath.Join(dir, "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if s := j.MergeSkipped(); len(s) != 0 {
		t.Errorf("skipped %v", s)
	}
	if _, ok := listed(t, j)["A"]; !ok || !exists(path) {
		t.Error("the journal lost its row or its file")
	}
}

// A merge whose save fails keeps the legacy file and leaves the journal as
// it was, rather than holding rows in memory that no file has.
func TestOpenFileJournal_FailedMergeSaveKeepsBoth(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	newDir, oldDir := filepath.Join(t.TempDir(), "new"), t.TempDir()
	path, legacy := filepath.Join(newDir, "j.json"), filepath.Join(oldDir, "old.json")
	writeJournal(t, path, depRec("NEW", reconcileNow))
	writeJournal(t, legacy, depRec("OLD", reconcileNow))
	if err := os.Chmod(newDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(newDir, 0o700) })

	j, err := OpenFileJournal(path, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if s := j.MergeSkipped(); len(s) != 1 || s[0].Path != legacy {
		t.Fatalf("skipped %+v, want the legacy file whose merge could not save", s)
	}
	if got := listed(t, j); len(got) != 1 || got["NEW"].TicketID == "" {
		t.Errorf("journal holds %v after the failed merge, want only NEW", got)
	}
	if !exists(legacy) {
		t.Error("the legacy file was removed though its rows were never saved")
	}
}

// A legacy file that merges but will not go is reported: left in place, it is
// merged again on every open and brings back rows this journal has finished.
func TestOpenFileJournal_ReportsALegacyItCannotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes from a read-only directory")
	}
	oldDir := t.TempDir()
	path, legacy := filepath.Join(t.TempDir(), "new.json"), filepath.Join(oldDir, "old.json")
	writeJournal(t, legacy, depRec("OLD", reconcileNow))
	if err := os.Chmod(oldDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(oldDir, 0o700) })

	j, err := OpenFileJournal(path, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if s := j.MergeSkipped(); len(s) != 1 || s[0].Path != legacy || s[0].Err == nil || !strings.Contains(s[0].Err.Error(), "not removed") {
		t.Fatalf("skipped %+v, want the legacy file reported as merged but not removed", s)
	}
	if _, ok := listed(t, j)["OLD"]; !ok || !exists(legacy) {
		t.Error("want the legacy rows merged and the file it could not remove still there")
	}
}

// Solana has no journals from before deployment keys, so a deployment on
// another rail never claims an unnamed row by its app id.
func TestDeployment_OnlyAlgorandOwnsUnnamedRows(t *testing.T) {
	d := Deployment{Rail: ticket.RailSolana, Network: "mainnet", EscrowAppID: 7}
	if d.Owns(TicketRecord{EscrowAppID: 7}) {
		t.Error("a Solana deployment owns an unnamed row by its app id")
	}
	if d.LegacyKey() != "" {
		t.Errorf("a Solana deployment has legacy key %q", d.LegacyKey())
	}
}

// deployment is written beside escrow_app_id, so an SDK from before it still
// finds the row, and comes back from the file.
func TestFileJournal_DeploymentRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.json")
	r := depRec("A", reconcileNow)
	r.Deployment = "algorand-custom-7"
	writeJournal(t, path, r)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, `"escrow_app_id": 7`) || !strings.Contains(s, `"deployment": "algorand-custom-7"`) || !strings.Contains(s, `"version": 1`) {
		t.Errorf("file %s lacks the version-1 row with both scopes", b)
	}
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if got := listed(t, j)["A"].Deployment; got != r.Deployment {
		t.Errorf("deployment came back as %q", got)
	}
}

func TestStateFile(t *testing.T) {
	path, legacy := StateFile("/d", "ticket-journal", journalDeployment)
	if path != filepath.Join("/d", "ticket-journal-algorand-custom-7.json") || legacy != filepath.Join("/d", "ticket-journal-7.json") {
		t.Errorf("StateFile = %q, %q", path, legacy)
	}
}

func TestAdoptLegacyFile(t *testing.T) {
	dir := t.TempDir()
	legacy, current := filepath.Join(dir, "old"), filepath.Join(dir, "new")
	if err := AdoptLegacyFile(legacy, current); err != nil || exists(current) {
		t.Fatalf("neither file: err %v, current exists %v", err, exists(current))
	}
	if err := os.WriteFile(legacy, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AdoptLegacyFile(legacy, current); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(current); string(b) != "old" || exists(legacy) {
		t.Fatalf("legacy only: current %q, legacy still there %v", b, exists(legacy))
	}
	if err := os.WriteFile(legacy, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AdoptLegacyFile(legacy, current); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(current); string(b) != "old" || !exists(legacy) {
		t.Errorf("both: current %q (want kept), legacy kept %v", b, exists(legacy))
	}
}

// New merges Stores.JournalLegacyPaths into the journal it opens, and adopts
// Discovery.CatalogLegacyPath before discovery reads the catalog.
func TestNew_AdoptsLegacyState(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "new.json"), filepath.Join(dir, "old.json")
	writeJournal(t, legacy, depRec("OLD", reconcileNow))
	catalog, oldCatalog := filepath.Join(dir, "catalog-new.json"), filepath.Join(dir, "catalog-old.json")
	if err := os.WriteFile(oldCatalog, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := pathConfig(t, url, path)
	cfg.Stores.JournalLegacyPaths = []string{legacy}
	cfg.Discovery.CatalogPath, cfg.Discovery.CatalogLegacyPath = catalog, oldCatalog
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.ownJournal.recs["OLD"]; !ok || exists(legacy) {
		t.Error("New did not merge the legacy journal")
	}
	if !exists(catalog) || exists(oldCatalog) {
		t.Error("New did not adopt the legacy catalog")
	}
	if got := c.Deployment().Key(); got != "algorand-testnet-1" {
		t.Errorf("Deployment().Key() = %q", got)
	}
}

// A legacy journal New leaves unmerged is logged, so the host learns that
// rows it may need are still under the old name.
func TestNew_WarnsOfAnUnmergedLegacyJournal(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	dir := t.TempDir()
	path, legacy := filepath.Join(dir, "new.json"), filepath.Join(dir, "old.json")
	if err := os.WriteFile(legacy, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cfg := pathConfig(t, url, path)
	cfg.Stores.JournalLegacyPaths = []string{legacy}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s := logs.String(); !strings.Contains(s, "not merged yet") || !strings.Contains(s, legacy) {
		t.Errorf("no warning naming the unmerged legacy journal:\n%s", s)
	}
}
