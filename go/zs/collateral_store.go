/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CollateralStateDir is the directory the TEE collateral cache persists to.
// Empty disables persistence. It is read once, at the first attestation
// check, so a process must set it before then.
var CollateralStateDir string

// Intel PCS collateral, kept across restarts.
//
// WITHOUT IT THE IN-MEMORY CACHE DIES WITH THE PROCESS, and that is the
// failure mode a long-lived agent session actually hits: an upgrade, a
// service restart, or a laptop waking up discards every artifact this
// proxy verified from Intel, so the next probe starts cold. If it starts
// cold during a PCS outage, stale-while-revalidate has nothing to serve
// and every TEE operator leaves routing — the exact outcome the stale
// path exists to prevent, reintroduced by a restart.
//
// Nothing here is secret or payer-identifying: it is a few hundred KB of
// Intel-signed certificates, revocation lists, and TCB documents, all of
// which are public and served to anyone who asks Intel. So this adds no
// privacy surface, and specifically none of the ticket/operator/address
// data the retention rules cover.

// collateralStoreFile is the basename under the state directory.
//
// STATE, NOT CACHE. A directory under os.UserCacheDir is swept routinely,
// by the OS or the user, which would silently re-open the restart hole
// this file exists to close; CollateralStateDir should be a state
// directory for that reason.
const collateralStoreFile = "tee-collateral.json"

// collateralPersistDebounce coalesces writes after a successful fetch.
//
// Fetches are already rare (one per artifact per collateralTTL, over a
// handful of URLs), so this is a few writes an hour rather than a hot
// path. It is deliberately a write-behind with no shutdown hook: the
// store is an optimization, so losing the tail of it costs one cold
// fetch, while a shutdown hook would be a new ordering dependency in
// app.Run for no better guarantee.
//
// WHAT THAT MEANS FOR THE CLI, which is not the "kill -9" case it looks
// like: `zs-proxy tee inspect --chain` verifies one quote in about a
// second and then exits NORMALLY, well inside this window, so it
// persists nothing it fetched. Only the daemon ever warms the file. That
// is the intended split — a diagnostic run should not reshape the state
// the daemon routes on — but it does mean an operator cannot warm the
// cache by running the CLI, and a `tee inspect` during an Intel outage
// therefore falls to the node's own collateral where the daemon would
// have had a cached copy.
const collateralPersistDebounce = 5 * time.Second

// persistedEntry is one artifact on disk.
//
// Body and header travel as-is under encoding/json, which base64s the
// []byte. Deliberately not gob: this file is worth being able to read
// with jq when a payer reports that attestation went strange, and the
// size difference is irrelevant at a few hundred KB.
type persistedEntry struct {
	URL     string              `json:"url"`
	Header  map[string][]string `json:"header,omitempty"`
	Body    []byte              `json:"body"`
	Fetched time.Time           `json:"fetched"`
}

type persistedCollateral struct {
	Version int              `json:"version"`
	Entries []persistedEntry `json:"entries"`
}

// collateralStoreVersion guards the on-disk shape. A file written by a
// newer proxy is IGNORED rather than guessed at — starting cold costs
// one round of fetches, while misreading an entry's Fetched time would
// silently widen collateralStaleMax.
const collateralStoreVersion = 1

// collateralStoreMaxBytes bounds the whole file at load.
//
// Sized off the fetch path rather than off an observation:
// maxCollateralBytes (4 MiB) caps a single artifact, and a DCAP
// verification consults four of them per platform. 32 MiB is generous
// for the handful of platforms one proxy sees while still being a cap.
const collateralStoreMaxBytes = 32 << 20

type collateralStore struct {
	path string

	mu    sync.Mutex
	timer *time.Timer
}

// newCollateralStore resolves the state path. A nil store means "no
// persistence" and every method tolerates it, so a process with no state
// directory degrades to the in-memory cache rather than failing to start.
func newCollateralStore() *collateralStore {
	if CollateralStateDir == "" {
		slog.Debug("attestation: no state directory, collateral cache will not persist")
		return nil
	}
	return newCollateralStoreAt(filepath.Join(CollateralStateDir, collateralStoreFile))
}

// newCollateralStoreAt is newCollateralStore against an explicit path,
// so a test that builds its own cachingGetter can exercise the real
// persistence wiring against a temp directory.
//
// The process singleton reads CollateralStateDir instead, which this
// package's TestMain points at a temporary directory, so tests never touch
// a real tee-collateral.json.
func newCollateralStoreAt(path string) *collateralStore {
	return &collateralStore{path: path}
}

// load reads the persisted entries.
//
// BEST-EFFORT BY CONTRACT. Absent, unreadable, corrupt, or written by a
// newer version all mean "start cold", never an error the caller has to
// handle — the alternative is a proxy that refuses to start because a
// cache file it does not need got truncated.
func (s *collateralStore) load() map[string]collateralEntry {
	if s == nil {
		return nil
	}
	// BOUNDED, because the fetch path is. maxCollateralBytes caps each
	// artifact off the wire, and a file this process wrote can hold only
	// a handful of them — so anything past the cap is a file we did not
	// write, and the comment on collateralStaleMax is explicit that once
	// persisted, provenance rests on the filesystem. Reading it anyway
	// would be the one part of that boundary left unbounded.
	f, err := os.Open(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Debug("attestation: could not read persisted collateral",
				slog.String("path", s.path), slog.Any("err", err))
		}
		return nil
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, collateralStoreMaxBytes+1))
	if err != nil {
		slog.Debug("attestation: could not read persisted collateral",
			slog.String("path", s.path), slog.Any("err", err))
		return nil
	}
	if len(raw) > collateralStoreMaxBytes {
		slog.Debug("attestation: persisted collateral is larger than this proxy could have written it, starting cold",
			slog.String("path", s.path), slog.Int("bytes", len(raw)))
		return nil
	}
	var doc persistedCollateral
	if err := json.Unmarshal(raw, &doc); err != nil {
		slog.Debug("attestation: persisted collateral is unreadable, starting cold",
			slog.String("path", s.path), slog.Any("err", err))
		return nil
	}
	if doc.Version != collateralStoreVersion {
		return nil
	}
	now := time.Now()
	out := make(map[string]collateralEntry, len(doc.Entries))
	for _, e := range doc.Entries {
		// A zero Fetched would read as infinitely old and be refused by
		// collateralStaleMax anyway, but dropping it here keeps the
		// in-memory map's invariants the same whether it was loaded or
		// fetched.
		//
		// A FUTURE Fetched is the dangerous direction and is dropped for
		// a different reason: it makes the age negative, which reads as
		// fresher than fresh and short-circuits both bounds at once (see
		// cachingGetter.getWithContext). A host with a fast RTC —
		// snapshot restore, unsynced boot — writes exactly that, and
		// persisting it is what would carry the condition past the
		// restart that used to clear it. Dropping costs one fetch.
		if e.URL == "" || e.Fetched.IsZero() || e.Fetched.After(now) || len(e.Body) == 0 {
			continue
		}
		// PAST collateralStaleMax IS ALREADY UNSERVABLE — the stale arm
		// refuses it — so dropping it here changes no verdict. It is here
		// so the file cannot grow without bound: save re-serializes
		// whatever the map holds, so an artifact for a platform this proxy
		// last saw years ago would otherwise be loaded and rewritten
		// forever, outliving its own usefulness with nothing to trim it.
		if now.Sub(e.Fetched) >= collateralStaleMax {
			continue
		}
		out[e.URL] = collateralEntry{header: e.Header, body: e.Body, fetched: e.Fetched}
	}
	return out
}

// save writes the snapshot atomically.
//
// Temp-then-rename rather than internal/connect's atomicWriteWithBackup:
// that helper is unexported with nine call sites there, and hayai
// importing connect inverts the layering the same way config importing
// it would. There is deliberately no .bak — the file is reconstructible
// from Intel by definition.
//
// AND DELIBERATELY NO fsync BEFORE THE RENAME. A power loss can install
// a truncated file; load's unreadable-JSON branch treats that as a cold
// start, which is the same outcome as the missing file this store is an
// optimization over. Paying an fsync on a background write to protect a
// cache that is free to rebuild would be the wrong trade.
func (s *collateralStore) save(entries map[string]collateralEntry) {
	if s == nil {
		return
	}
	doc := persistedCollateral{Version: collateralStoreVersion, Entries: make([]persistedEntry, 0, len(entries))}
	for url, e := range entries {
		doc.Entries = append(doc.Entries, persistedEntry{
			URL: url, Header: e.header, Body: e.body, Fetched: e.fetched,
		})
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		slog.Debug("attestation: could not encode collateral for persistence", slog.Any("err", err))
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		slog.Debug("attestation: could not create state directory", slog.Any("err", err))
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), collateralStoreFile+".*")
	if err != nil {
		slog.Debug("attestation: could not open temp file for collateral", slog.Any("err", err))
		return
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		slog.Debug("attestation: could not write collateral", slog.Any("err", err))
		return
	}
	if err := tmp.Close(); err != nil {
		slog.Debug("attestation: could not close collateral temp file", slog.Any("err", err))
		return
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		slog.Debug("attestation: could not install collateral file", slog.Any("err", err))
	}
}

// persistSoon schedules a debounced save of the cache's current entries.
func (g *cachingGetter) persistSoon() {
	if g.store == nil {
		return
	}
	debounce := g.persistDebounce
	if debounce <= 0 {
		debounce = collateralPersistDebounce
	}
	g.store.mu.Lock()
	defer g.store.mu.Unlock()
	if g.store.timer != nil {
		g.store.timer.Reset(debounce)
		return
	}
	g.store.timer = time.AfterFunc(debounce, func() {
		g.mu.Lock()
		snapshot := make(map[string]collateralEntry, len(g.entries))
		for k, v := range g.entries {
			snapshot[k] = v
		}
		g.mu.Unlock()
		g.store.save(snapshot)
	})
}
